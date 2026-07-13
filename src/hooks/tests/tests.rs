
use super::*;
use std::collections::HashSet;

#[test]
fn from_ranked_drops_unknown_and_dedups() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    // 9 is unknown (dropped); 1 is duplicated (deduped); order preserved.
    let d = RoutingDecision::from_ranked([2usize, 9, 1, 1, 0], &valid);
    assert_eq!(d, RoutingDecision::Prefer(vec![2, 1, 0]));
}

/// Build a minimal `PoolCfg` with the given `route`/`policy` for resolve_policy tests.
use crate::config::{HookCfg, HookKind, PolicyOnError, PoolPolicy, PromptAccess, UserAccess};
use std::collections::HashMap;

/// A pool with a native ranking strategy and no gate.
fn pool_policy(policy: PoolPolicy) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
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
        policy: PoolPolicy::Weighted,
        gates: vec![name.to_string()],
        base_named: false,
    }
}

/// A minimal gate hook; transport/grants filled by the caller.
fn base_gate() -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        socket: None,
        webhook: None,
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
#[cfg(unix)]
#[test]
fn default_hook_resolves_as_base_for_unnamed_pools() {
    let client = reqwest::Client::new();
    let mut def = base_gate();
    def.socket = Some("/run/busbar/def.sock".to_string());
    def.default = true;
    let mut hooks = registry("def", def);
    // also register the own-gate hook "h"
    let mut h = base_gate();
    h.socket = Some("/run/busbar/h.sock".to_string());
    hooks.insert("h".to_string(), h);

    assert_eq!(default_hook_name(&hooks), Some("def"));

    // base_named=false + no gate ⇒ inherits the default gate as its base ordering.
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear(); // base_named is already false from pool_with_hook
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &client, Some("def"), 0).is_some(),
        "an unnamed-base pool inherits the default hook as its ordering"
    );

    // base_named=true (explicit weighted) ⇒ default does NOT override; weighted ⇒ None.
    assert!(
        resolve_pool_ordering(
            &pool_policy(PoolPolicy::Weighted),
            &hooks,
            &client,
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
        resolve_pool_ordering(&gated, &hooks, &client, Some("def"), 0).is_some(),
        "an unnamed-base pool with its own gate still inherits the default as base"
    );
    assert_eq!(
        resolve_pool_gates(&gated, &hooks, &client, 0).len(),
        1,
        "the pool's own gate resolves separately, on top of the inherited base"
    );

    // No default registered ⇒ identical to resolve_policy (backstop): unnamed pool ⇒ None.
    assert!(
        resolve_pool_ordering(&unnamed, &HashMap::new(), &client, None, 0).is_none(),
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
/// routing never strands a request; config_validate is the loud gate that rejects the dangling
/// ref at boot.
#[test]
fn unknown_hook_ref_falls_back_to_none() {
    let client = reqwest::Client::new();
    let hooks = HashMap::new();
    assert!(resolve_pool_gates(&pool_with_hook("nonexistent"), &hooks, &client, 0).is_empty());
}

/// A pool `hook:` naming a socket gate resolves to a constructed socket gate policy (unix); an
/// empty socket path degrades to gate-absent.
#[cfg(unix)]
#[test]
fn socket_gate_resolves_constructed_policy() {
    let client = reqwest::Client::new();
    let hooks = registry(
        "h",
        HookCfg {
            socket: Some("/run/busbar/hook.sock".to_string()),
            ..base_gate()
        },
    );
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &client, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                policy, timeout, ..
            },
        )) => {
            assert_eq!(policy.name(), "socket");
            assert_eq!(
                timeout,
                std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                "a gate with the default timeout resolves to the documented deadline, not 0ms",
            );
        }
        None => panic!("socket gate must resolve to a Policy"),
    }
    // Empty socket path → gate absent (validation is the loud gate).
    let empty = registry(
        "h",
        HookCfg {
            socket: Some(String::new()),
            ..base_gate()
        },
    );
    assert!(resolve_pool_gates(&pool_with_hook("h"), &empty, &client, 0).is_empty());
}

/// The plain default (`policy: weighted`, no hook) stays the zero-cost `None` path.
#[test]
fn weighted_default_resolves_none() {
    assert!(resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none());
}

/// `on_error` resolution: a reserved terminal yields an EMPTY chain + that terminal; a gate
/// name appends its transport and follows ITS on_error; a ranking strategy appends one
/// infallible link and terminates.
#[cfg(unix)]
#[test]
fn on_error_chain_resolves_gates_and_terminals() {
    let client = reqwest::Client::new();
    // a (socket, on_error: b) -> b (socket, on_error: reject)
    let mut a = base_gate();
    a.socket = Some("/run/busbar/a.sock".to_string());
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.socket = Some("/run/busbar/b.sock".to_string());
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);

    let resolved = resolve_pool_gates(&pool_with_hook("a"), &hooks, &client, 0);
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
    assert_eq!(on_error_chain[0].policy.name(), "socket");
    assert_eq!(
        on_error,
        PolicyOnError::Reject,
        "the chain bottoms out on b's reject terminal"
    );

    // `on_error: nothing` — the explicit do-not-participate terminal — resolves to the same
    // no-op machinery as weighted (an empty chain + the Weighted terminal, which every
    // reconcile pass skips): a failing gate with `nothing` can never displace another gate.
    let mut n = base_gate();
    n.socket = Some("/run/busbar/n.sock".to_string());
    n.on_error = "nothing".to_string();
    let hooks_n = registry("n", n);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("n"), &hooks_n, &client, 0)
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
    c.socket = Some("/run/busbar/c.sock".to_string());
    c.on_error = "first".to_string();
    let hooks = registry("c", c);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("c"), &hooks, &client, 0)
        .into_iter()
        .next()
    else {
        panic!("gate c must resolve");
    };
    assert!(on_error_chain.is_empty(), "a terminal name has no chain");
    assert_eq!(on_error, PolicyOnError::First);
}

/// `on_error: <ranking strategy>` appends one infallible link and terminates at weighted.
#[cfg(all(unix, feature = "hooks-ranking"))]
#[test]
fn on_error_chain_strategy_terminates() {
    let client = reqwest::Client::new();
    let mut g = base_gate();
    g.socket = Some("/run/busbar/g.sock".to_string());
    g.on_error = "cheapest".to_string();
    let hooks = registry("g", g);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("g"), &hooks, &client, 0)
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
#[cfg(unix)]
#[test]
fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    let client = reqwest::Client::new();
    let mut rw = base_gate();
    rw.socket = Some("/run/busbar/rw.sock".to_string());
    rw.prompt = PromptAccess::Rw;
    let hooks = registry("rw", rw);
    let pool = pool_with_hook("rw");
    assert!(
        resolve_pool_gates(&pool, &hooks, &client, 0).is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        resolve_pool_rewrites(&pool, &hooks, &client, 0).len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );
    // And the inverse: a plain (non-rw) gate stays a decision gate, no rewrite entry.
    let mut plain = base_gate();
    plain.socket = Some("/run/busbar/plain.sock".to_string());
    let hooks = registry("plain", plain);
    let pool = pool_with_hook("plain");
    assert_eq!(resolve_pool_gates(&pool, &hooks, &client, 0).len(), 1);
    assert!(resolve_pool_rewrites(&pool, &hooks, &client, 0).is_empty());
}

/// SECURITY INVARIANT: `resolve_rewrite_hooks` admits ONLY `prompt: rw` GATES as rewrite hooks.
/// A `ro`/`no` gate and a tap (even one that claims `prompt: rw`) are excluded — the rw grant is
/// enforced at RESOLUTION, so a hook without the grant can NEVER reach the rewrite/transform path,
/// independent of what it tries to return (the bidirectional grant holds by construction).
#[test]
fn resolve_rewrite_hooks_admits_only_prompt_rw_gates() {
    let client = reqwest::Client::new();
    // Loopback webhook so the transport resolves on every platform (unlike unix-only sockets).
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        socket: None,
        webhook: Some("http://127.0.0.1:9931/".to_string()),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: true,
        default: false,
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
    let resolved = resolve_rewrite_hooks(&hooks, &global, &client, 0);
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
    let client = reqwest::Client::new();
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        socket: None,
        webhook: Some("http://127.0.0.1:9933/".to_string()),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: true,
        default: false,
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
    let resolved = resolve_gate_hooks(&hooks, &global, &client, 0);
    assert_eq!(
        resolved.len(),
        2,
        "decision gates = the ro + no gates; the rw (rewrite) gate and the tap are excluded"
    );
}

/// `resolve_tap_hooks` admits ONLY `kind: tap` hooks observing at the REQUESTED stage (unset
/// `at:` defaults to request). A gate is excluded (it fires on the gate seam, not the tap
/// fan-out). The two request-stage taps below (one explicit `at: request`, one unset) resolve
/// for the request stage; the completion tap resolves for the completion stage only.
#[test]
fn resolve_tap_hooks_admits_only_request_stage_taps() {
    let client = reqwest::Client::new();
    let mk = |kind: HookKind, at: Option<crate::config::HookStage>| HookCfg {
        kind,
        socket: None,
        webhook: Some("http://127.0.0.1:9932/".to_string()),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        at,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: true,
        default: false,
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
    let resolved = resolve_tap_hooks(
        &hooks,
        &global,
        &client,
        0,
        crate::config::HookStage::Request,
    );
    assert_eq!(
            resolved.len(),
            2,
            "only the two REQUEST-stage taps resolve; the gate and the completion-stage tap are excluded"
        );
    // The same registry resolved for the COMPLETION stage admits exactly the completion tap.
    let completion = resolve_tap_hooks(
        &hooks,
        &global,
        &client,
        0,
        crate::config::HookStage::Completion,
    );
    assert_eq!(completion.len(), 1, "one completion-stage tap");
    // And a stage nothing observes resolves empty (the zero-cost skip).
    assert!(
        resolve_tap_hooks(
            &hooks,
            &global,
            &client,
            0,
            crate::config::HookStage::Attempt
        )
        .is_empty(),
        "no attempt-stage tap is configured"
    );
    // Every resolved tap here is `prompt: no`, so `send_prompt` (the middle tuple element) is false.
    assert!(
        resolved.iter().all(|(_, send_prompt, _)| !*send_prompt),
        "a prompt:no tap must not carry the prompt-content grant"
    );
}

/// A tap's `prompt: ro` grant flows through `resolve_tap_hooks` as `send_prompt = true`, so the
/// firing site can hand it the prompt-content projection; a `prompt: no` tap stays `false`
/// (shape-only). This is the per-grant projection contract for taps.
#[test]
fn resolve_tap_hooks_carries_prompt_grant() {
    let client = reqwest::Client::new();
    let mk = |prompt: PromptAccess| HookCfg {
        kind: HookKind::Tap,
        socket: None,
        webhook: Some("http://127.0.0.1:9933/".to_string()),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: true,
        default: false,
    };
    let mut hooks = HashMap::new();
    hooks.insert("ro-tap".to_string(), mk(PromptAccess::Ro));
    hooks.insert("no-tap".to_string(), mk(PromptAccess::No));
    let resolved = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string(), "no-tap".to_string()],
        &client,
        0,
        crate::config::HookStage::Request,
    );
    assert_eq!(resolved.len(), 2);
    // Both taps share priority 0; identify each by re-resolving individually to assert the flag.
    let ro = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string()],
        &client,
        0,
        crate::config::HookStage::Request,
    );
    let no = resolve_tap_hooks(
        &hooks,
        &["no-tap".to_string()],
        &client,
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
/// `false` in the webhook or socket arm would silently strip content from every opted-in hook.
/// The socket half runs on unix only (elsewhere a socket gate resolves to `None`).
#[test]
fn gate_grants_pass_through_as_projection_flags() {
    let client = reqwest::Client::new();
    // On non-unix the socket push below is compiled out and `mut` would be unused.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases = vec![(
        "webhook",
        registry(
            "h",
            HookCfg {
                webhook: Some("http://127.0.0.1:8787/".to_string()),
                prompt: PromptAccess::Ro,
                user: UserAccess::Ro,
                ..base_gate()
            },
        ),
    )];
    #[cfg(unix)]
    cases.push((
        "socket",
        registry(
            "h",
            HookCfg {
                socket: Some("/run/busbar/hook.sock".to_string()),
                prompt: PromptAccess::Ro,
                user: UserAccess::Ro,
                ..base_gate()
            },
        ),
    ));
    for (label, hooks) in cases {
        match resolve_pool_gates(&pool_with_hook("h"), &hooks, &client, 0)
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
                    "{label} must pass prompt:ro through as send_prompt"
                );
                assert!(send_user, "{label} must pass user:ro through as send_user");
            }
            None => panic!("{label} gate must resolve to a policy"),
        }
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
