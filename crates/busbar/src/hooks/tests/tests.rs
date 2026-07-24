use super::*;
use std::collections::HashSet;

#[test]
fn from_ranked_drops_unknown_and_dedups() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    // 9 is unknown (dropped); 1 is duplicated (deduped); order preserved.
    let d = RoutingDecision::from_ranked([2usize, 9, 1, 1, 0], &valid);
    assert_eq!(d, RoutingDecision::Prefer(vec![2, 1, 0]));
}

use crate::config::{HookCfg, HookKind, PolicyOnError, PoolPolicy, PromptAccess, UserAccess};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Hook plugin test env ──────────────────────────────────────────────────────────────────────────
// The 1.5.0 hooks-as-plugins world: a hook resolves its `plugin:` ref against a validated plugin
// registry into a `DlopenPolicy`. These resolution tests build a real registry from the hermetic
// `busbar-hook-test-plugin` cdylib (aliased `test-hook`), so `resolve_*` exercises the true
// registry-resolution path — the same seam the request path uses. A gate whose `plugin:` names a
// missing plugin resolves to `None` (gate-absent), exactly as before.

/// Locate the hermetic hook-test plugin cdylib in the build's target dir (like the store/auth tests).
/// Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure; locally a
/// missing cdylib returns `None` and the caller skips cleanly.
fn hook_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the hook-test plugin cdylib is not built under CI; refusing to silently skip the \
             hook-plugin resolution coverage"
        );
    }
    candidate
}

/// Build a validated [`HookEnv`] whose registry loads the hook-test cdylib under the given alias and
/// declared manifest `needs`. `None` when the cdylib is not built (the caller skips). Uses the
/// unsigned + `allow_unsigned` path (the test can't sign with the embedded first-party key), which
/// still exercises the full scan/trust/load pipeline.
fn test_env_needs(alias: &str, needs: busbar_plugin_sign::HookNeeds) -> Option<HookEnv> {
    let lib = std::fs::read(hook_cdylib()?).expect("read hook cdylib");
    let dir = crate::tests::tmp_plugin_dir(&format!("hook-env-{alias}"));
    let mut m = crate::tests::plugin_manifest("busbar-hook-test-plugin", alias, "acme");
    m.kind = "hook".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("hook")
        .iter()
        .max()
        .expect("hook abi");
    m.needs = needs;
    let tarball = crate::tests::unsigned_tarball(m, &lib);
    std::fs::write(dir.join("hook.tar.gz"), tarball).unwrap();
    let mut policy = busbar_plugin_sign::TrustPolicy {
        binary_version: "1.5.0".into(),
        ..Default::default()
    };
    policy.allow_unsigned = true;
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    Some(HookEnv::new(std::sync::Arc::new(registry)))
}

/// A [`HookEnv`] that resolves `test-hook` (declaring rw prompt + ro user intent, so the projection
/// matrix's operator grants are not clamped by the manifest in the general resolution tests).
fn test_env() -> Option<HookEnv> {
    test_env_needs(
        "test-hook",
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
}

/// An empty env (no plugins loaded) — a hook ref resolves to `None` (gate-absent).
fn empty_env() -> HookEnv {
    HookEnv::new(std::sync::Arc::new(
        busbar_plugin_loader::PluginRegistry::empty(),
    ))
}

/// A pool with a native ranking strategy and no gate.
fn pool_policy(policy: PoolPolicy) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        module_hooks: Vec::new(),
        policy,
        gates: Vec::new(),
        base_named: true,
    }
}

/// A pool referencing a gate hook by name (native strategy defaults to weighted).
fn pool_with_hook(name: &str) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        module_hooks: Vec::new(),
        policy: PoolPolicy::Weighted,
        gates: vec![name.to_string()],
        base_named: false,
    }
}

/// A minimal gate hook backed by the `test-hook` plugin; grants filled by the caller.
fn base_gate() -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: crate::config::DEFAULT_POLICY_TIMEOUT_MS,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    }
}

/// A one-entry hooks registry.
fn registry(name: &str, hook: HookCfg) -> HashMap<String, HookCfg> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), hook);
    m
}

/// Each native `policy:` strategy resolves to a constructed `Policy` whose name round-trips the
/// native registry name. (No gate; empty hook registry.) Requires the removable `hooks-ranking`
/// plugin — under `--no-default-features` a non-weighted native policy is a boot error, not a
/// resolvable policy, so this behavior test only applies when the plugin is compiled in.
#[cfg(feature = "hooks-ranking")]
#[test]
fn native_policy_resolves_constructed_policy() {
    for (policy, name) in [
        (PoolPolicy::Cheapest, "cheapest"),
        (PoolPolicy::Fastest, "fastest"),
        (PoolPolicy::LeastBusy, "least_busy"),
        (PoolPolicy::Usage, "usage"),
    ] {
        let cfg = pool_policy(policy);
        match resolve_policy(&cfg) {
            Some(ResolvedPolicy::Policy { policy, .. }) => {
                assert_eq!(
                    policy.name(),
                    name,
                    "resolved native policy name must round-trip"
                );
            }
            other => panic!(
                "policy: {name} must resolve to a Policy, got none={}",
                other.is_none()
            ),
        }
    }
}

/// The `default:` hook becomes the base ordering for a pool that named NO base (base_named=false)
/// and has no gate of its own — but NOT for a pool that named a base or brought its own gate.
#[test]
fn default_hook_resolves_as_base_for_unnamed_pools() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut def = base_gate();
    def.default = true;
    let mut hooks = registry("def", def);
    // also register the own-gate hook "h"
    hooks.insert("h".to_string(), base_gate());

    assert_eq!(default_hook_name(&hooks), Some("def"));

    // base_named=false + no gate ⇒ inherits the default gate as its base ordering.
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear(); // base_named is already false from pool_with_hook
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool inherits the default hook as its ordering"
    );

    // base_named=true (explicit weighted) ⇒ default does NOT override; weighted ⇒ None.
    assert!(
        resolve_pool_ordering(
            &pool_policy(PoolPolicy::Weighted),
            &hooks,
            &env,
            Some("def"),
            0
        )
        .is_none(),
        "a pool that named its base keeps it; the default does not override"
    );

    // base_named=false with its OWN gate ⇒ STILL inherits the default as its base — gates are
    // orthogonal to the base ordering (they fire in the phase-2 reconcile on top of it), and
    // its own gate resolves separately via resolve_pool_gates.
    let gated = pool_with_hook("h");
    assert!(
        resolve_pool_ordering(&gated, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool with its own gate still inherits the default as base"
    );
    assert_eq!(
        resolve_pool_gates(&gated, &hooks, &env, 0).len(),
        1,
        "the pool's own gate resolves separately, on top of the inherited base"
    );

    // No default registered ⇒ identical to resolve_policy (backstop): unnamed pool ⇒ None.
    assert!(
        resolve_pool_ordering(&unnamed, &HashMap::new(), &env, None, 0).is_none(),
        "no default hook ⇒ the compiled-in weighted backstop (None)"
    );
}

/// `policy: weighted` (default / absent) collapses to the zero-cost default (`None`).
#[test]
fn weighted_policy_resolves_none_zero_cost() {
    assert!(
        resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none(),
        "the weighted native must collapse to the zero-cost default path"
    );
}

/// A pool gate referencing an UNKNOWN registry entry is skipped at resolution (gate absent) —
/// routing never strands a request; config_validate/pre-flight is the loud gate at boot.
#[test]
fn unknown_hook_ref_falls_back_to_none() {
    let hooks = HashMap::new();
    assert!(resolve_pool_gates(&pool_with_hook("nonexistent"), &hooks, &empty_env(), 0).is_empty());
}

/// A pool `hook:` naming a plugin-backed gate resolves to a constructed `DlopenPolicy` whose name is
/// the hook's registry name; a gate whose plugin is missing (empty registry) degrades to gate-absent.
#[test]
fn plugin_gate_resolves_constructed_policy() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry("h", base_gate());
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                policy, timeout, ..
            },
        )) => {
            assert_eq!(
                policy.name(),
                "h",
                "the DlopenPolicy carries the hook's registry name"
            );
            assert_eq!(
                timeout,
                std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                "a gate with the default timeout resolves to the documented deadline, not 0ms",
            );
        }
        None => panic!("plugin gate must resolve to a Policy"),
    }
    // A missing plugin (empty registry) → gate absent (the pre-flight is the loud gate at boot).
    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

/// The plain default (`policy: weighted`, no hook) stays the zero-cost `None` path.
#[test]
fn weighted_default_resolves_none() {
    assert!(resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none());
}

/// `on_error` resolution: a reserved terminal yields an EMPTY chain + that terminal; a gate
/// name appends its transport and follows ITS on_error; a ranking strategy appends one
/// infallible link and terminates.
#[test]
fn on_error_chain_resolves_gates_and_terminals() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // a (plugin, on_error: b) -> b (plugin, on_error: reject)
    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);

    let resolved = resolve_pool_gates(&pool_with_hook("a"), &hooks, &env, 0);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolved.into_iter().next()
    else {
        panic!("gate a must resolve");
    };
    assert_eq!(on_error_chain.len(), 1, "one fallback link (gate b)");
    assert_eq!(on_error_chain[0].policy.name(), "b");
    assert_eq!(
        on_error,
        PolicyOnError::Reject,
        "the chain bottoms out on b's reject terminal"
    );

    // `on_error: nothing` — the explicit do-not-participate terminal — resolves to the same
    // no-op machinery as weighted (an empty chain + the Weighted terminal, which every
    // reconcile pass skips): a failing gate with `nothing` can never displace another gate.
    let mut n = base_gate();
    n.on_error = "nothing".to_string();
    let hooks_n = registry("n", n);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("n"), &hooks_n, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate n must resolve");
    };
    assert!(on_error_chain.is_empty());
    assert_eq!(
        on_error,
        PolicyOnError::Weighted,
        "nothing = the non-participating terminal"
    );

    // A direct terminal ⇒ empty chain.
    let mut c = base_gate();
    c.on_error = "first".to_string();
    let hooks = registry("c", c);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("c"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate c must resolve");
    };
    assert!(on_error_chain.is_empty(), "a terminal name has no chain");
    assert_eq!(on_error, PolicyOnError::First);
}

/// `on_error: <ranking strategy>` appends one infallible link and terminates at weighted.
#[cfg(feature = "hooks-ranking")]
#[test]
fn on_error_chain_strategy_terminates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut g = base_gate();
    g.on_error = "cheapest".to_string();
    let hooks = registry("g", g);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("g"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate g must resolve");
    };
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(on_error_chain[0].policy.name(), "cheapest");
    assert_eq!(on_error, PolicyOnError::Weighted);
}

/// A pool's `prompt: rw` gate is a PHASE-1 rewrite, not a phase-2 decision gate: it is
/// EXCLUDED from `resolve_pool_gates` and resolved by `resolve_pool_rewrites` instead — so it
/// never pays a decision deadline for a reply arm it cannot return.
#[test]
fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    let hooks = registry("rw", rw);
    let pool = pool_with_hook("rw");
    assert!(
        resolve_pool_gates(&pool, &hooks, &env, 0).is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        resolve_pool_rewrites(&pool, &hooks, &env, 0).len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );
    // And the inverse: a plain (non-rw) gate stays a decision gate, no rewrite entry.
    let hooks = registry("plain", base_gate());
    let pool = pool_with_hook("plain");
    assert_eq!(resolve_pool_gates(&pool, &hooks, &env, 0).len(), 1);
    assert!(resolve_pool_rewrites(&pool, &hooks, &env, 0).is_empty());
}

/// A gate hook with `on_error: nothing`/loop but a MISSING plugin resolves cleanly to gate-absent
/// (never a stranded request), independent of the plugin registry contents.
#[test]
fn missing_plugin_gate_is_absent_not_stranded() {
    let hooks = registry("h", base_gate());
    // With an empty registry the plugin doesn't resolve → gate absent.
    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

/// SECURITY INVARIANT: `resolve_rewrite_hooks` admits ONLY `prompt: rw` GATES as rewrite hooks.
/// A `ro`/`no` gate and a tap (even one that claims `prompt: rw`) are excluded — the rw grant is
/// enforced at RESOLUTION, so a hook without the grant can NEVER reach the rewrite/transform path,
/// independent of what it tries to return (the bidirectional grant holds by construction).
#[test]
fn resolve_rewrite_hooks_admits_only_prompt_rw_gates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));
    // A tap that (nonsensically) claims prompt: rw — still NEVER a rewrite hook (a tap can't reply).
    hooks.insert("rw-tap".to_string(), mk(HookKind::Tap, PromptAccess::Rw));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "rw-tap".to_string(),
    ];
    let resolved = resolve_rewrite_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        1,
        "only the prompt:rw GATE is a rewrite hook; ro/no gates + the tap are excluded"
    );
}

/// `resolve_gate_hooks` admits the GLOBAL DECISION gates: `kind: gate` that is NOT a rewrite
/// (`prompt: rw`) gate. A rewrite gate fires in the phase-1 transform pass (excluded here); a tap
/// never decides (excluded). So from {rw-gate, ro-gate, no-gate, rw-tap} exactly the ro + no gates
/// resolve as decision gates.
#[test]
fn resolve_gate_hooks_admits_only_decision_gates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));
    hooks.insert("a-tap".to_string(), mk(HookKind::Tap, PromptAccess::Ro));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "a-tap".to_string(),
    ];
    let resolved = resolve_gate_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        2,
        "decision gates = the ro + no gates; the rw (rewrite) gate and the tap are excluded"
    );
}

/// `resolve_tap_hooks` admits ONLY `kind: tap` hooks observing at the REQUESTED stage (unset
/// `at:` defaults to request). A gate is excluded (it fires on the gate seam, not the tap
/// fan-out).
#[test]
fn resolve_tap_hooks_admits_only_request_stage_taps() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, at: Option<crate::config::HookStage>| HookCfg {
        kind,
        at,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert(
        "tap-req".to_string(),
        mk(HookKind::Tap, Some(crate::config::HookStage::Request)),
    );
    hooks.insert("tap-unset".to_string(), mk(HookKind::Tap, None));
    hooks.insert(
        "tap-completion".to_string(),
        mk(HookKind::Tap, Some(crate::config::HookStage::Completion)),
    );
    hooks.insert("a-gate".to_string(), mk(HookKind::Gate, None));
    let global = vec![
        "tap-req".to_string(),
        "tap-unset".to_string(),
        "tap-completion".to_string(),
        "a-gate".to_string(),
    ];
    let resolved = resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Request);
    assert_eq!(
        resolved.len(),
        2,
        "only the two REQUEST-stage taps resolve; the gate and the completion-stage tap are excluded"
    );
    // The same registry resolved for the COMPLETION stage admits exactly the completion tap.
    let completion = resolve_tap_hooks(
        &hooks,
        &global,
        &env,
        0,
        crate::config::HookStage::Completion,
    );
    assert_eq!(completion.len(), 1, "one completion-stage tap");
    // And a stage nothing observes resolves empty (the zero-cost skip).
    assert!(
        resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Attempt).is_empty(),
        "no attempt-stage tap is configured"
    );
    // Every resolved tap here is `prompt: no`, so `send_prompt` (the middle tuple element) is false.
    assert!(
        resolved.iter().all(|(_, send_prompt, _)| !*send_prompt),
        "a prompt:no tap must not carry the prompt-content grant"
    );
}

/// A tap's `prompt: ro` grant flows through `resolve_tap_hooks` as `send_prompt = true` (the plugin
/// also declares the prompt need), so the firing site can hand it the prompt-content projection; a
/// `prompt: no` tap stays `false` (shape-only). This is the per-grant projection contract for taps.
#[test]
fn resolve_tap_hooks_carries_prompt_grant() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |prompt: PromptAccess| HookCfg {
        kind: HookKind::Tap,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("ro-tap".to_string(), mk(PromptAccess::Ro));
    hooks.insert("no-tap".to_string(), mk(PromptAccess::No));
    let resolved = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string(), "no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert_eq!(resolved.len(), 2);
    // Both taps share priority 0; identify each by re-resolving individually to assert the flag.
    let ro = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    let no = resolve_tap_hooks(
        &hooks,
        &["no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert!(ro[0].1, "prompt:ro tap carries send_prompt = true");
    assert!(!no[0].1, "prompt:no tap carries send_prompt = false");
}

/// The `timeout_ms == 0` → default guard in `policy_timeout` (belt-and-suspenders for any
/// code-built `PolicyCfg` that slips a 0 through).
#[test]
fn policy_timeout_treats_zero_as_default() {
    assert_eq!(
        policy_timeout(0),
        std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
        "0ms must be coerced to the documented default policy timeout, never 0"
    );
    assert_eq!(
        policy_timeout(42),
        std::time::Duration::from_millis(42),
        "a non-zero timeout must be honored verbatim"
    );
}

#[test]
fn from_ranked_empty_is_abstain() {
    let valid: HashSet<usize> = [0usize].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked([7usize, 8], &valid),
        RoutingDecision::Abstain,
        "all-unknown ranked list collapses to Abstain"
    );
    assert_eq!(
        RoutingDecision::from_ranked(std::iter::empty(), &valid),
        RoutingDecision::Abstain,
    );
}

/// A native `policy:` FORCES the payload projections off at resolve (no native policy reads them).
/// Requires the `hooks-ranking` plugin (a native non-weighted policy exists only when compiled in).
#[cfg(feature = "hooks-ranking")]
#[test]
fn native_resolve_forces_opt_in_flags_off() {
    match resolve_policy(&pool_policy(PoolPolicy::Cheapest)) {
        Some(ResolvedPolicy::Policy {
            send_prompt,
            send_user,
            ..
        }) => {
            assert!(!send_prompt, "native must force send_prompt off");
            assert!(!send_user, "native must force send_user off");
        }
        None => panic!("native pool must resolve to a policy"),
    }
}

/// A gate hook's `prompt: ro` / `user: ro` grants PASS THROUGH to the resolved policy as
/// send_prompt / send_user — the mirror image of the native force-off: an accidental hardcoded
/// `false` would silently strip content from every opted-in hook. (The plugin manifest here declares
/// the matching intent, so BOTH agree and the projection is on.)
#[test]
fn gate_grants_pass_through_as_projection_flags() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry(
        "h",
        HookCfg {
            prompt: PromptAccess::Ro,
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                send_prompt,
                send_user,
                ..
            },
        )) => {
            assert!(
                send_prompt,
                "prompt:ro grant + manifest need must pass send_prompt through"
            );
            assert!(
                send_user,
                "user:ro grant + manifest need must pass send_user through"
            );
        }
        None => panic!("gate must resolve to a policy"),
    }
}

/// THE MANIFEST-INTENT × OPERATOR-GRANT PROJECTION MATRIX (the belt-and-suspenders rule): the core
/// projects prompt/user content ONLY when BOTH the operator grants it AND the signed manifest
/// declares the need. A grant above the declared need is a no-op; a manifest need above the grant is
/// a no-op. Prompt content flows only when both are ≥ read; rewrite-power (rw) requires both rw.
#[test]
fn manifest_intent_and_grant_projection_matrix() {
    use busbar_plugin_sign::NeedLevel;
    // (manifest prompt need, operator prompt grant) -> expected send_prompt
    let prompt_cases = [
        (NeedLevel::No, PromptAccess::No, false),
        (NeedLevel::No, PromptAccess::Ro, false), // grant above declared need = no-op
        (NeedLevel::No, PromptAccess::Rw, false),
        (NeedLevel::Ro, PromptAccess::No, false), // declared above grant = no-op
        (NeedLevel::Ro, PromptAccess::Ro, true),
        (NeedLevel::Ro, PromptAccess::Rw, true), // both ≥ read → content flows
        (NeedLevel::Rw, PromptAccess::No, false),
        (NeedLevel::Rw, PromptAccess::Ro, true),
        (NeedLevel::Rw, PromptAccess::Rw, true),
    ];
    for (idx, (need, grant, want_prompt)) in prompt_cases.into_iter().enumerate() {
        let alias = format!("mtx-{idx}");
        let Some(env) = test_env_needs(
            &alias,
            busbar_plugin_sign::HookNeeds {
                prompt: need,
                user: NeedLevel::No,
            },
        ) else {
            eprintln!("skip: hook cdylib not built (run under --workspace)");
            return;
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                prompt: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_prompt, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for case {idx}");
        };
        assert_eq!(
            send_prompt, want_prompt,
            "case {idx}: manifest {need:?} × grant {grant:?} → send_prompt {want_prompt}"
        );
    }

    // The user axis: send_user only when BOTH manifest declares (ro) AND operator grants (ro).
    let user_cases = [
        (NeedLevel::No, UserAccess::No, false),
        (NeedLevel::No, UserAccess::Ro, false),
        (NeedLevel::Ro, UserAccess::No, false),
        (NeedLevel::Ro, UserAccess::Ro, true),
    ];
    for (idx, (need, grant, want_user)) in user_cases.into_iter().enumerate() {
        let alias = format!("mtx-user-{idx}");
        let Some(env) = test_env_needs(
            &alias,
            busbar_plugin_sign::HookNeeds {
                prompt: NeedLevel::No,
                user: need,
            },
        ) else {
            return;
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                user: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_user, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for user case {idx}");
        };
        assert_eq!(
            send_user, want_user,
            "user case {idx}: manifest {need:?} × grant {grant:?} → send_user {want_user}"
        );
    }
}

/// LOCKS the invariant behind `forward`'s `unreachable!("from_ranked never rejects")` arm:
/// `from_ranked` is a pure order-normalizer and must only ever produce Prefer/Abstain. If a
/// future change makes it emit Reject, that unreachable arm panics on a live request — this
/// test is the tripwire that fails FIRST.
#[test]
fn from_ranked_never_produces_reject() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    for ranked in [
        vec![0usize, 1, 2],
        vec![2, 2, 2],
        vec![9, 8, 7],
        vec![],
        vec![1],
        vec![0, 9, 1, 0, 2, 2],
    ] {
        let d = RoutingDecision::from_ranked(ranked.clone(), &valid);
        assert!(
            !matches!(d, RoutingDecision::Reject { .. }),
            "from_ranked({ranked:?}) must never yield Reject"
        );
    }
}

/// The opt-in projections REDACT their content in Debug: a stray `{{:?}}` debug log on the
/// routing path must never fan operator-opted-in prompt text or end-user PII into the log
/// stream (the VirtualKey key-hash precedent).
#[test]
fn opt_in_projections_redact_debug() {
    let p = PromptProjection {
        system: Some("SECRET-SYSTEM-PROMPT".into()),
        messages: vec![("user".into(), "SECRET-MESSAGE-TEXT".into())],
    };
    let dbg = format!("{p:?}");
    assert!(
        !dbg.contains("SECRET-SYSTEM-PROMPT"),
        "leaked system: {dbg}"
    );
    assert!(
        !dbg.contains("SECRET-MESSAGE-TEXT"),
        "leaked message: {dbg}"
    );

    let i = CallerIdentity {
        key_id: Some("k-1".into()),
        key_name: Some("sales-team".into()),
        user: Some("alice@example.com".into()),
    };
    let dbg = format!("{i:?}");
    assert!(
        !dbg.contains("alice@example.com"),
        "leaked end-user id: {dbg}"
    );
    // The operator-facing key labels stay visible — they are the operator's own config values,
    // and losing them would make the struct undiagnosable.
    assert!(dbg.contains("sales-team"));
}

// ── DlopenPolicy behavior over the REAL projectors (ported socket/webhook transport coverage) ──────
// These drive a LOADED test-hook plugin through the resolved `DlopenPolicy` using the engine's REAL
// `hooks::plugin::projectors()` (the wire.rs fail-closed parsers), porting the retired socket/webhook
// transport tests (reject-precedence, order, abstain, rewrite, notify delivery) onto the dlopen seam.

/// Resolve the single gate `h` from a one-hook registry backed by the test-hook plugin (settings
/// carry the plugin's behavior config), returning the constructed `Arc<dyn RoutingPolicy>`.
fn resolve_one(env: &HookEnv, settings: serde_json::Value) -> Option<Arc<dyn RoutingPolicy>> {
    let mut hook = base_gate();
    hook.prompt = PromptAccess::Ro; // so the opt-in prompt projection is sent (matches manifest rw need)
    hook.settings = settings.as_object().cloned().unwrap_or_default();
    let hooks = registry("h", hook);
    match resolve_gate_transport("h", &hooks["h"], &hooks, env, 0)? {
        ResolvedPolicy::Policy { policy, .. } => Some(policy),
    }
}

fn dreq(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
    }
}

fn dcand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
    }
}

fn dctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// `decide` over the dlopen seam: the plugin's configured order is echoed and normalized by the REAL
/// `wire::normalize` (unknown idxs dropped); an empty order abstains.
#[tokio::test]
async fn dlopen_decide_order_and_abstain() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    let policy = resolve_one(&env, serde_json::json!({"order": [9, 1, 0]})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![1, 0]),
        "unknown idx 9 dropped by the real normalizer"
    );

    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// `decide` REJECT over the dlopen seam: the opt-in prompt projection reaches the in-process gate
/// (proving content delivery under the grant + manifest need), and the plugin's `{"reject":{...}}`
/// surfaces as a `RoutingDecision::Reject` through the REAL fail-closed normalizer (status/message).
#[tokio::test]
async fn dlopen_decide_reject_from_opt_in_prompt() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"}),
    )
    .expect("resolve");

    // Prompt WITHOUT the token → the gate ranks (no reject).
    let d = policy
        .decide(&dreq("clean prompt"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Prefer(vec![0]));

    // Prompt WITH the token → the gate rejects (content reached it over the ABI).
    let d = policy
        .decide(&dreq("please BLOCKME"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Reject {
            status: 403,
            message: "blocked by test gate".to_string()
        }
    );
}

/// `transform` over the dlopen seam: the plugin rewrites the body (a rw gate), and rejects on the
/// screen token — reject > rewrite precedence, through the REAL `wire::transform_outcome`.
#[tokio::test]
async fn dlopen_transform_rewrite_and_reject() {
    use busbar_api::TransformOutcome;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let policy =
        resolve_one(&env, serde_json::json!({"reject_if_contains": "BLOCKME"})).expect("resolve");

    match policy.transform(&dreq("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
    match policy.transform(&dreq("BLOCKME"), budget).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// A `notify` tap over the dlopen seam is fire-and-forget: it never blocks, never panics, and
/// tolerates a malformed projection (swallowed).
#[tokio::test]
async fn dlopen_notify_is_fire_and_forget() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");
    let projection = serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
    policy.notify(&projection, budget).await; // completes without error
    policy.notify(b"not json", budget).await; // malformed projection swallowed
}

/// `status` + `describe` over the dlopen seam: the plugin reports a metric (via `fetch_status`) and a
/// schema envelope (via `fetch_schema`, single-nest extracted), using the REAL projectors.
#[tokio::test]
async fn dlopen_status_and_schema_reads() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hook = {
        let mut h = base_gate();
        h.settings = serde_json::json!({"order": [0]})
            .as_object()
            .cloned()
            .unwrap();
        h
    };
    // Drive a decide first so the plugin's decide counter is non-zero, then read status.
    let hooks = registry("h", hook.clone());
    let ResolvedPolicy::Policy { policy, .. } =
        resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    let _ = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await;

    let status = fetch_status("h", &hook, 0, &env).await.expect("status");
    let metrics = status.metrics.expect("metrics");
    assert_eq!(metrics[0]["name"], "test_decides_total");

    let schema = fetch_schema("h", &hook, 0, &env).await.expect("schema");
    // fetch_schema returns the schema member ALREADY EXTRACTED (single nest).
    assert_eq!(schema["type"], "object");
}

/// `configure` push over the dlopen seam: the test-hook plugin acks the EXACT pushed version → Ok.
/// (A wrong-version ack rejecting the commit is covered at the DlopenPolicy configure unit level.)
#[tokio::test]
async fn dlopen_configure_acks_exact_version() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hook = base_gate();
    push_configure(&hook, "h", 7, &env)
        .await
        .expect("the plugin acks the pushed version");
}

/// The on_error CHAIN fires through LOADED plugins: gate `a` (on_error → gate `b`) resolves a
/// one-link fallback chain whose link is a live `DlopenPolicy` (name `b`), bottoming out on `b`'s
/// `reject` terminal. Ported from the socket on_error-chain test onto the dlopen seam.
#[tokio::test]
async fn dlopen_on_error_chain_link_is_live_plugin() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = resolve_gate_transport("a", &hooks["a"], &hooks, &env, 0).expect("gate a resolves");
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(
        on_error_chain[0].policy.name(),
        "b",
        "the fallback link is a live DlopenPolicy"
    );
    assert_eq!(on_error, PolicyOnError::Reject);
    // And the live fallback link actually decides over the ABI.
    let cands = [dcand(0)];
    let d = on_error_chain[0]
        .policy
        .decide(
            &dreq("x"),
            &cands,
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the fallback link decides");
    assert!(matches!(
        d,
        RoutingDecision::Abstain | RoutingDecision::Prefer(_)
    ));
}

/// A `prompt: no` gate (default) sends NO prompt content even though the plugin declares an rw need:
/// the belt-and-suspenders rule requires BOTH — the operator grant of `no` wins. So the gate cannot
/// reject on prompt content it never received.
#[tokio::test]
async fn dlopen_prompt_no_grant_withholds_content() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // A gate with the DEFAULT prompt: no grant, but a plugin that WOULD reject on the token.
    let mut hook = base_gate(); // prompt defaults to No
    hook.settings = serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"})
        .as_object()
        .cloned()
        .unwrap();
    let hooks = registry("h", hook);
    let ResolvedPolicy::Policy {
        policy,
        send_prompt,
        ..
    } = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    assert!(
        !send_prompt,
        "prompt:no grant → no content projected, regardless of manifest intent"
    );
    // The prompt carries the token, but with send_prompt=false the CORE would not project it. Here we
    // simulate the firing site: a `prompt: no` gate gets a request with NO prompt projection.
    let mut req = dreq("please BLOCKME");
    req.prompt = None; // the core withholds content for a no-grant hook
    let d = policy
        .decide(
            &req,
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![0]),
        "no content reached the gate → it ranks, never rejects"
    );
}

/// REJECT-STATUS CLAMP over the dlopen seam (ported from the socket reject-status test): a hook may
/// only speak client errors. Whatever status the plugin returns, the REAL `wire::normalize` clamps
/// anything outside 400..=499 to 403 — a hook cannot mint a success/redirect/5xx through the ABI.
#[tokio::test]
async fn dlopen_decide_reject_status_is_clamped() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    for (sent, want) in [
        (400, 400),
        (451, 451),
        (499, 499),
        (200, 403),
        (302, 403),
        (500, 403),
        (0, 403),
        (70000, 403),
    ] {
        let policy = resolve_one(
            &env,
            serde_json::json!({"reject_if_contains": "X", "reject_status": sent}),
        )
        .expect("resolve");
        match policy
            .decide(&dreq("X please"), &cands, &dctx(), budget)
            .await
            .expect("decide")
        {
            RoutingDecision::Reject { status, .. } => {
                assert_eq!(status, want, "sent {sent} must clamp to {want}")
            }
            other => panic!("expected Reject for sent {sent}, got {other:?}"),
        }
    }
}

/// RESTRICT over the dlopen seam (ported from the socket restrict coverage): a compliance gate's
/// `{"restrict":{"tags_any":[...]}}` reply surfaces as a `RoutingDecision::Restrict` through the REAL
/// `wire::normalize` — restrict wins over `order`, and a malformed/empty restrict is fail-closed to an
/// EMPTY tag set (resolved downstream by `on_empty`, never allow-all).
#[tokio::test]
async fn dlopen_decide_restrict_and_fail_closed() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    // Well-formed restrict → Restrict{tags_any}; restrict wins even though `order` is also set.
    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [1, 0], "restrict_tags": ["baa"]}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
        other => panic!("expected Restrict, got {other:?}"),
    }

    // A malformed restrict (empty tags) is fail-closed to an EMPTY tag set — never allow-all/order.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"restrict": {"tags_any": []}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert!(
            tags_any.is_empty(),
            "malformed restrict stays Restrict (fail-closed → on_empty), got {tags_any:?}"
        ),
        other => panic!("malformed restrict must stay Restrict, got {other:?}"),
    }
}

/// FAIL-CLOSED reply parsing over the dlopen seam (ported from the socket malformed-reply coverage):
/// the REAL `wire::normalize` degrades a mis-typed `reject` detail to a full-strength 403 rejection
/// (never a silent route), while a non-verb reply object abstains — a hook that tried to stop a
/// request can never have it routed because a detail was malformed.
#[tokio::test]
async fn dlopen_decide_raw_reply_is_fail_closed() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];

    // A `reject` with a bogus (string) status degrades to the default 403 — still a rejection.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": {"status": "451"}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Reject { status, .. } => assert_eq!(status, 403),
        other => panic!("malformed reject must stay a 403 Reject, got {other:?}"),
    }

    // A non-verb reply object → Abstain (no opinion), never an error.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"unknown_field": true}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Abstain
    );

    // `reject: false` is the explicit opt-out — defers to `order`.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": false, "order": [0]}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![0])
    );
}

/// The USER-identity opt-in projection rides the dlopen seam when BOTH the grant and manifest agree:
/// a `user: ro` gate (manifest declares the user need) gets the caller identity in the projection.
/// This is the identity analogue of the prompt opt-in delivery test.
#[tokio::test]
async fn dlopen_user_identity_projection_rides_the_wire() {
    use busbar_plugin_sign::{HookNeeds, NeedLevel};
    let Some(env) = test_env_needs(
        "user-hook",
        HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry(
        "h",
        HookCfg {
            plugin: "user-hook".to_string(),
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    let Some(ResolvedPolicy::Policy {
        send_user,
        send_prompt,
        ..
    }) = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
    else {
        panic!("gate must resolve");
    };
    assert!(send_user, "user:ro grant + manifest user need → send_user");
    assert!(
        !send_prompt,
        "no prompt grant/need → prompt content stays withheld"
    );
}

/// A SLOW gate is cut off by the wall-clock `budget` over the dlopen seam (ported from the socket
/// silent-hook timeout test): a decide that overruns the deadline surfaces as `Err` (→ the caller's
/// `on_error`), promptly — never a hang. The blocking call runs on `spawn_blocking`, so a sleeping
/// plugin never stalls the runtime.
#[tokio::test]
async fn dlopen_decide_deadline_cuts_off_a_slow_gate() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let policy =
        resolve_one(&env, serde_json::json!({"order": [0], "sleep_ms": 2000})).expect("resolve");
    let started = std::time::Instant::now();
    let r = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_millis(100),
        )
        .await;
    assert!(r.is_err(), "a slow gate must exceed the deadline → Err");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the deadline must cut the exchange off promptly, not wait out the sleep"
    );
}

/// FAIL-OPEN management reads over the dlopen seam (ported from the socket status/describe
/// "unsupported" coverage): a hook that replies `{}` to `status`/`describe` is treated as
/// "doesn't speak it" — `fetch_status`/`fetch_schema` return `None`, never affecting a request.
#[tokio::test]
async fn dlopen_empty_management_reads_are_fail_open_none() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"empty_management": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        fetch_status("h", &hook, 0, &env).await.is_none(),
        "an empty status reply is fail-open None"
    );
    assert!(
        fetch_schema("h", &hook, 0, &env).await.is_none(),
        "an empty describe reply is fail-open None"
    );
}

/// A NACK'd `configure` push over the dlopen seam does NOT commit (ported from the socket
/// wrong-version-ack coverage): the plugin refuses to ack, so `push_configure` returns `Err` and the
/// settings PATCH would not commit — the exact-version ack rule holds over the ABI.
#[tokio::test]
async fn dlopen_configure_nack_does_not_commit() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"nack_configure": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        push_configure(&hook, "h", 7, &env).await.is_err(),
        "a hook that refuses to ack must fail the configure push (no commit)"
    );
}
