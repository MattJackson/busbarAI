// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pluggable routing policies.
//!
//! A pool may declare a routing **policy** that, given a cheap projection of the request, returns an
//! ordered **preference** of members — not a single pick. The ordered list feeds the failover loop
//! Busbar already has (`forward::pick_among`): if the policy's #1 is tripped / excluded / at
//! capacity, Busbar walks to #2 using the existing breaker machinery. One transport-agnostic trait
//! (`RoutingPolicy`); webhook / socket are the out-of-process implementations, and the built-in
//! ranking hooks (the `hooks/ranking/` workspace crate) are the in-process ones.
//!
//! ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool resolves to `ResolvedPolicy::None`
//! at config load and NEVER constructs any of the projection types or enters this module's async
//! path. The hot path stays today's inline SWRR.
//!
//! This surface is PRODUCTION-WIRED: `forward::decide_policy_order` builds the `RoutingRequest` +
//! `Candidate` projections from the live store signals and invokes the resolved policy on every
//! non-default request; `forward::pick_among` walks the ranked order through the existing failover
//! loop. `resolve_policy` (below) constructs the ranking-hook / webhook / socket transports once
//! at config load.

use std::sync::Arc;

/// Resolve a configured `timeout_ms` into a `Duration`, treating `0` as "use the default". A code-built
/// `PolicyCfg` (e.g. a native shorthand) can carry `timeout_ms == 0` because serde's field default only
/// fires on the deserialize path; a literal `0ms` deadline would make every policy decision instantly
/// time out. This belt-and-suspenders guard pairs with the desugar-site stamp in `config.rs`.
fn policy_timeout(timeout_ms: u64) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        crate::limits::default_policy_timeout_ms()
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms)
}

pub(crate) mod socket;
pub(crate) mod webhook;
pub(crate) mod wire;

// The HOOK CONTRACT — the `RoutingPolicy` trait and the read-only projections it is invoked with
// (`RoutingRequest`, `Candidate`, `RoutingContext`, `RoutingDecision`, …) — lives in the
// `busbar-api` crate (the one crate both the engine and every plugin build against). Re-exported
// here so engine-internal paths are unchanged.
pub(crate) use busbar_api::{
    CallerIdentity, Candidate, PolicyError, PolicyResult, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub(crate) enum ResolvedPolicy {
    /// A constructed policy object (webhook / socket / native non-weighted) plus its fallback config.
    /// The default SWRR / weighted path is represented as `None` by `resolve_policy` (it constructs no
    /// policy object), so there is no `Weighted` variant — a weighted pool simply has no resolved
    /// policy and takes the inline SWRR branch.
    Policy {
        policy: Arc<dyn RoutingPolicy>,
        /// The TERMINAL the on_error chain bottoms out on (weighted/reject/first) — applied when
        /// the policy fails and every chain link (below) also fails.
        on_error: crate::config::PolicyOnError,
        /// The resolved on_error FALLBACK CHAIN: hooks/strategies fired IN ORDER when the policy
        /// errors or times out; the first that answers decides. Empty (the common case — a
        /// terminal was named directly) costs nothing. Resolved once at config load; boot
        /// validation proves termination (cycles/unknowns/taps never reach here).
        on_error_chain: Vec<FallbackHook>,
        timeout: std::time::Duration,
        /// Derived from the hook's `prompt` grant (`ro`/`rw`) — build + send the prompt content
        /// projection (default false, i.e. `prompt: no`).
        send_prompt: bool,
        /// Derived from the hook's `user` grant (`ro`) — build + send the caller identity projection
        /// (default false, i.e. `user: no`).
        send_user: bool,
        /// Gate `on_empty` — behavior when a `restrict` reply leaves an EMPTY candidate intersection.
        /// Default `Reject` (fail-closed; the spec default for a compliance restrict); `Weighted`
        /// is the advisory escape (fall back to SWRR over the FULL pool). Inert for non-restricting
        /// policies (native/order-only), which never produce an empty intersection.
        on_empty: crate::config::PolicyOnError,
    },
}

/// One link in a gate's resolved `on_error` fallback chain: the fallback hook's transport plus
/// the per-hook config the firing site needs (its own deadline, ITS grants — a fallback never
/// sees a projection its own grants don't allow — and its own `on_empty`).
#[derive(Clone)]
pub(crate) struct FallbackHook {
    pub(crate) policy: Arc<dyn RoutingPolicy>,
    pub(crate) timeout: std::time::Duration,
    pub(crate) send_prompt: bool,
    pub(crate) send_user: bool,
    pub(crate) on_empty: crate::config::PolicyOnError,
}

/// Resolve a pool's routing config into a runtime policy ONCE at config load. Returns `None` for the
/// ZERO-COST default path: `route: weighted` (the default / absent case) AND the explicit
/// `route: native, policy.name: weighted` form both resolve to `None`, because `weighted` Abstains
/// and thus converges with today's inline SWRR — so the hot path constructs no policy object, builds
/// no projections, and takes the unchanged `select_weighted_in` branch.
///
/// This resolves the BASE only. A pool's GATES are resolved separately (`resolve_pool_gates`) and
/// fire in the phase-2 decision reconcile — a gate's `order` overrides the base; its abstain falls
/// through to the base. The resolved base is stored on `PoolRuntime::policy` and consumed
/// per-request by `forward::decide_policy_order`.
pub(crate) fn resolve_policy(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    // `weighted` ⇒ the zero-cost default path (no policy object, inline SWRR) — byte-identical to
    // 1.2.1's `route: weighted` — so `native_name()` returns `None` here and we take the `?`
    // short-circuit BELOW regardless of the ranking feature.
    let name = cfg.policy.native_name()?;
    // The non-weighted ranking strategies are the `hooks-ranking` plugin. When it's compiled OUT, a
    // `policy: cheapest` (etc.) is a config_validate BOOT ERROR, so this arm is unreachable in a
    // running server; degrade to None (SWRR) as belt-and-suspenders.
    #[cfg(feature = "hooks-ranking")]
    {
        let policy = busbar_hooks_ranking::native_policy(name)?;
        Some(ResolvedPolicy::Policy {
            policy,
            on_error: crate::config::PolicyOnError::default(),
            on_error_chain: Vec::new(),
            timeout: policy_timeout(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
            // Native policies rank on live signals and have no reader for prompt/identity.
            send_prompt: false,
            send_user: false,
            // A native ordering policy never restricts, so on_empty is inert; keep the fail-closed default.
            on_empty: crate::config::PolicyOnError::Reject,
        })
    }
    #[cfg(not(feature = "hooks-ranking"))]
    {
        let _ = name;
        None
    }
}

/// The name of the registered `default: true` hook, if any — the base ordering that pools which named
/// none inherit. At most one exists (config_validate enforces it), so `find` is unambiguous.
pub(crate) fn default_hook_name(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> Option<&str> {
    hooks
        .iter()
        .find(|(_, h)| h.default)
        .map(|(name, _)| name.as_str())
}

/// Resolve a pool's base ordering, honoring the `default:` hook. A pool that named NO base ordering
/// (`base_named == false`) INHERITS the `default:` hook as its base (the default gate orders it) —
/// the REPLACEMENT of the compiled-in `weighted` backstop, per the everything-is-a-hook model. A pool
/// that explicitly named a base keeps its choice (the default does NOT override it); a pool's own
/// GATES are orthogonal — they fire in the phase-2 reconcile ON TOP of whatever base resolves here.
/// When no `default:` hook is registered, this is exactly `resolve_policy` (the compiled-in
/// backstop). Called once per pool at startup.
pub(crate) fn resolve_pool_ordering(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    client: &reqwest::Client,
    default_hook: Option<&str>,
) -> Option<ResolvedPolicy> {
    if !cfg.base_named {
        if let Some(name) = default_hook {
            if let Some(hook) = hooks.get(name) {
                // The default gate becomes this pool's base ordering.
                return resolve_gate_transport(hook, hooks, client);
            }
        }
    }
    resolve_policy(cfg)
}

/// Resolve a pool's GATES (`hook:` / the non-strategy names in `hooks: [...]`) into their transports,
/// preserving CONFIG ORDER and carrying each hook's `priority` — the firing site merges these with
/// the global decision gates into one priority-sorted phase-2 chain (stable: ties keep globals-first,
/// then config order). Unresolvable / dangling / wrong-kind refs are skipped here (config_validate
/// surfaces them loudly at boot); a skip degrades to "gate absent", never a stranded request.
pub(crate) fn resolve_pool_gates(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    client: &reqwest::Client,
) -> Vec<(u16, ResolvedPolicy)> {
    cfg.gates
        .iter()
        .filter_map(|name| {
            let hook = hooks.get(name)?;
            if hook.kind != crate::config::HookKind::Gate {
                return None;
            }
            // A `prompt: rw` gate is a phase-1 REWRITE (resolved by `resolve_pool_rewrites`), not
            // a phase-2 decision gate — including it here would fire it for a decision it never
            // returns (its rewrite reply normalizes to Abstain), paying its deadline for nothing.
            if hook.prompt.can_rewrite() {
                return None;
            }
            resolve_gate_transport(hook, hooks, client).map(|rp| (hook.priority, rp))
        })
        .collect()
}

/// Resolve a pool's REWRITE gates — the `prompt: rw` gates in its `hooks: [...]` list — into the
/// pool's phase-1 transform chain, sorted by ascending `priority` (stable: config order breaks
/// ties). Fired AFTER the global rewrite chain for requests routed to this pool (each chain is
/// internally priority-ordered; globals always precede pool rewrites). The rw GRANT is the
/// admission ticket, enforced here at resolution exactly as in `resolve_rewrite_hooks`.
pub(crate) fn resolve_pool_rewrites(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    client: &reqwest::Client,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for name in &cfg.gates {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        if hook.kind != crate::config::HookKind::Gate || !hook.prompt.can_rewrite() {
            continue;
        }
        if let Some(ResolvedPolicy::Policy {
            policy, timeout, ..
        }) = resolve_gate_transport(hook, hooks, client)
        {
            ranked.push((hook.priority, timeout, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

/// Resolve a GATE hook's transport (socket or webhook) into a [`ResolvedPolicy`]. The prompt/identity
/// projections are gated by the hook's `prompt:`/`user:` grants (`ro`/`rw` send the prompt; `ro` sends
/// identity). A missing/invalid transport degrades to `None` — config_validate surfaces it loudly.
fn resolve_gate_transport(
    hook: &crate::config::HookCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    client: &reqwest::Client,
) -> Option<ResolvedPolicy> {
    let policy = gate_transport_only(hook, client)?;
    let (on_error_chain, on_error) = resolve_on_error_chain(hook, hooks, client);
    Some(ResolvedPolicy::Policy {
        policy,
        on_error,
        on_error_chain,
        timeout: policy_timeout(hook.timeout_ms),
        send_prompt: hook.prompt.sends_prompt(),
        send_user: hook.user.sends_user(),
        on_empty: gate_on_empty(hook),
    })
}

/// The bare transport of a gate — webhook (SSRF-validated at load) or Unix socket (lazy connect) —
/// without the surrounding policy config. Shared by the primary resolution and the on_error chain.
fn gate_transport_only(
    hook: &crate::config::HookCfg,
    client: &reqwest::Client,
) -> Option<Arc<dyn RoutingPolicy>> {
    if let Some(url) = hook.webhook.as_deref() {
        let url = crate::observability::validate_routing_webhook_url(Some(url)).ok()?;
        return Some(Arc::new(webhook::WebhookPolicy::new(url, client.clone())));
    }
    gate_socket_transport(hook)
}

/// Wrap a gate's Unix domain socket path as a [`socket::SocketPolicy`], carrying the configure
/// preamble (D2) when the hook declares settings — sent first on every fresh connection so a
/// restarted hook always holds current settings.
#[cfg(unix)]
fn gate_socket_transport(hook: &crate::config::HookCfg) -> Option<Arc<dyn RoutingPolicy>> {
    let path = hook.socket.as_deref()?;
    if path.is_empty() {
        return None;
    }
    if hook.settings.is_empty() {
        Some(Arc::new(socket::SocketPolicy::new(path.to_string())))
    } else {
        Some(Arc::new(socket::SocketPolicy::with_configure(
            path.to_string(),
            // The registry NAME isn't threaded to this seam; the hook's own name is echoed in the
            // configure context for multi-hook binaries. Absent a name here, the socket path is
            // the stable identity the hook can key on.
            path,
            &hook.settings,
            0,
        )))
    }
}

/// The configure-push deadline (spec `configure_timeout_ms` default): distinct from the
/// per-request gate deadline — configure may do real work (reload a model, open files).
const CONFIGURE_TIMEOUT_MS: u64 = 5000;

/// PUSH a settings map to a hook over its transport and wait for the ack (D2, the
/// `PATCH /api/v1/admin/hooks/{name}/settings` core). `Ok` = acked (commit); `Err` = NOT committed.
pub(crate) async fn push_configure(
    hook: &crate::config::HookCfg,
    name: &str,
    settings_version: u64,
    client: &reqwest::Client,
) -> Result<(), String> {
    let Some(transport) = gate_transport_only(hook, client) else {
        return Err("hook transport unresolvable".to_string());
    };
    transport
        .configure(
            name,
            &hook.settings,
            settings_version,
            std::time::Duration::from_millis(CONFIGURE_TIMEOUT_MS),
        )
        .await
        .map_err(|e| e.to_string())
}

/// Fetch a hook's self-described settings schema over its transport (D2,
/// `GET /api/v1/admin/hooks/{name}/schema`). `None` = the hook/transport doesn't answer describe.
pub(crate) async fn fetch_schema(
    hook: &crate::config::HookCfg,
    client: &reqwest::Client,
) -> Option<serde_json::Value> {
    let transport = gate_transport_only(hook, client)?;
    transport
        .describe(std::time::Duration::from_millis(CONFIGURE_TIMEOUT_MS))
        .await
}

/// Resolve a hook's `on_error` NAME into its runtime fallback chain + terminal, following the
/// registry: a reserved terminal stops immediately (the common, zero-cost case); a built-in ranking
/// strategy appends one infallible link and terminates (its abstain converges with weighted);
/// another GATE appends its transport and the walk continues through ITS `on_error`. Boot
/// validation is the loud gate for unknown names / taps / cycles — here they degrade safely to the
/// weighted terminal (never a stranded request), with a visited guard so a cycle cannot loop.
fn resolve_on_error_chain<'a>(
    hook: &'a crate::config::HookCfg,
    hooks: &'a std::collections::HashMap<String, crate::config::HookCfg>,
    client: &reqwest::Client,
) -> (Vec<FallbackHook>, crate::config::PolicyOnError) {
    let mut chain: Vec<FallbackHook> = Vec::new();
    let mut visited: Vec<&str> = Vec::new();
    let mut current: &'a str = hook.on_error.as_str();
    loop {
        if let Some(terminal) = crate::config::on_error_terminal(current) {
            return (chain, terminal);
        }
        // A built-in ranking strategy: sync, no I/O, cannot fail — one link, then done. Compiled
        // out, the name falls through to the registry lookup below (and validation errored at boot).
        #[cfg(feature = "hooks-ranking")]
        if let Some(policy) = busbar_hooks_ranking::native_policy(current) {
            chain.push(FallbackHook {
                policy,
                timeout: policy_timeout(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                send_prompt: false,
                send_user: false,
                on_empty: crate::config::PolicyOnError::Reject,
            });
            return (chain, crate::config::PolicyOnError::Weighted);
        }
        if visited.contains(&current) {
            return (chain, crate::config::PolicyOnError::default());
        }
        let Some(h) = hooks.get(current) else {
            return (chain, crate::config::PolicyOnError::default());
        };
        if h.kind != crate::config::HookKind::Gate {
            return (chain, crate::config::PolicyOnError::default());
        }
        if let Some(policy) = gate_transport_only(h, client) {
            chain.push(FallbackHook {
                policy,
                timeout: policy_timeout(h.timeout_ms),
                send_prompt: h.prompt.sends_prompt(),
                send_user: h.user.sends_user(),
                on_empty: gate_on_empty(h),
            });
        }
        visited.push(current);
        current = h.on_error.as_str();
    }
}

/// A gate's `on_empty` behavior (empty restrict intersection): the configured value, or the
/// FAIL-CLOSED default `Reject` — the spec default for a compliance restrict, never allow-all.
fn gate_on_empty(hook: &crate::config::HookCfg) -> crate::config::PolicyOnError {
    hook.on_empty
        .clone()
        .unwrap_or(crate::config::PolicyOnError::Reject)
}

/// Resolve the GLOBAL rewrite hooks — the `global_hooks` names whose registry entry is a `kind: gate`
/// with a `prompt: rw` grant — into their transports, sorted by ASCENDING `priority` (the transform
/// chain order; `weighted`-tie-break by config order is preserved by the stable sort). Returns
/// `(per-hook transform deadline, transport)` pairs. The `rw` GRANT IS ENFORCED HERE: a `ro`/`no`
/// gate (or a tap, or a non-rewrite gate) is skipped, so it can never rewrite — the bidirectional
/// grant holds by construction, independent of what a hook tries to return. Unresolvable transports
/// (bad socket/webhook) are skipped; config_validate surfaces those loudly at boot.
pub(crate) fn resolve_rewrite_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    client: &reqwest::Client,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        // ONLY a gate with prompt: rw is a rewrite hook — the grant enforcement point.
        if hook.kind != crate::config::HookKind::Gate || !hook.prompt.can_rewrite() {
            continue;
        }
        if let Some(ResolvedPolicy::Policy {
            policy, timeout, ..
        }) = resolve_gate_transport(hook, hooks, client)
        {
            ranked.push((hook.priority, timeout, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

/// Resolve the GLOBAL TAP hooks observing at ONE stage — the `global_hooks` names whose registry
/// entry is a `kind: tap` with `at: <stage>` (an unset `at:` defaults to `request`) — into their
/// transports. Returns `(per-hook deadline, prompt-grant, transport)` triples. Taps are
/// fire-and-forget so order is irrelevant, but a stable priority sort keeps startup deterministic.
/// Unresolvable transports are skipped (config_validate surfaces them at boot).
pub(crate) fn resolve_tap_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    client: &reqwest::Client,
    stage: crate::config::HookStage,
) -> Vec<(std::time::Duration, bool, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, bool, Arc<dyn RoutingPolicy>)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        if hook.kind != crate::config::HookKind::Tap {
            continue;
        }
        // An unset `at:` defaults to the request stage.
        if hook.at.unwrap_or(crate::config::HookStage::Request) != stage {
            continue;
        }
        // `send_prompt` carries the tap's `prompt: ro` grant through to the firing site, so a granted
        // tap gets the prompt content projection and a `prompt: no` (default) tap gets shape-only.
        if let Some(ResolvedPolicy::Policy {
            policy,
            timeout,
            send_prompt,
            ..
        }) = resolve_gate_transport(hook, hooks, client)
        {
            ranked.push((hook.priority, timeout, send_prompt, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _, _)| *p);
    ranked.into_iter().map(|(_, t, sp, p)| (t, sp, p)).collect()
}

/// Resolve the GLOBAL DECISION gates — the `global_hooks` names whose registry entry is a `kind: gate`
/// that is NOT a rewrite gate (`prompt: rw` gates fire in the phase-1 transform pass via
/// `resolve_rewrite_hooks`; taps observe, they don't decide). These fire on EVERY request to reach a
/// verdict (reject / restrict / order) alongside a pool's own `hook:` gate. Returns the full
/// `ResolvedPolicy` for each (carrying `on_error`/`on_empty`/grants) so the firing site can run it
/// through the same `decide_policy_order` machinery as a pool gate, PLUS the hook's `priority` so
/// the firing site can merge globals with a pool's own gates into one phase-2 chain. Sorted by
/// ascending `priority` (the chain tie-break, e.g. which reject message surfaces). Unresolvable
/// transports are skipped (config_validate surfaces them at boot).
pub(crate) fn resolve_gate_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    client: &reqwest::Client,
) -> Vec<(u16, ResolvedPolicy)> {
    let mut ranked: Vec<(u16, ResolvedPolicy)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        // Decision gates only: a gate that does not rewrite. `rw` gates are phase-1 rewrites; taps
        // never decide. (A gate may still return nothing/reject/restrict/order.)
        if hook.kind != crate::config::HookKind::Gate || hook.prompt.can_rewrite() {
            continue;
        }
        if let Some(rp) = resolve_gate_transport(hook, hooks, client) {
            ranked.push((hook.priority, rp));
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

/// Non-unix fallback: `tokio::net::UnixStream` is unix-only, so a socket gate degrades to the default
/// SWRR with a loud pointer at the webhook transport. The request is never stranded.
#[cfg(not(unix))]
fn gate_socket_transport(_hook: &crate::config::HookCfg) -> Option<Arc<dyn RoutingPolicy>> {
    tracing::warn!(
        "a socket gate (Unix-domain-socket hook) is not available on this platform; falling back to \
         weighted. Use a `webhook:` hook for an out-of-process gate here."
    );
    None
}

#[cfg(test)]
mod tests {
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
            resolve_pool_ordering(&unnamed, &hooks, &client, Some("def")).is_some(),
            "an unnamed-base pool inherits the default hook as its ordering"
        );

        // base_named=true (explicit weighted) ⇒ default does NOT override; weighted ⇒ None.
        assert!(
            resolve_pool_ordering(
                &pool_policy(PoolPolicy::Weighted),
                &hooks,
                &client,
                Some("def")
            )
            .is_none(),
            "a pool that named its base keeps it; the default does not override"
        );

        // base_named=false with its OWN gate ⇒ STILL inherits the default as its base — gates are
        // orthogonal to the base ordering (they fire in the phase-2 reconcile on top of it), and
        // its own gate resolves separately via resolve_pool_gates.
        let gated = pool_with_hook("h");
        assert!(
            resolve_pool_ordering(&gated, &hooks, &client, Some("def")).is_some(),
            "an unnamed-base pool with its own gate still inherits the default as base"
        );
        assert_eq!(
            resolve_pool_gates(&gated, &hooks, &client).len(),
            1,
            "the pool's own gate resolves separately, on top of the inherited base"
        );

        // No default registered ⇒ identical to resolve_policy (backstop): unnamed pool ⇒ None.
        assert!(
            resolve_pool_ordering(&unnamed, &HashMap::new(), &client, None).is_none(),
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
        assert!(resolve_pool_gates(&pool_with_hook("nonexistent"), &hooks, &client).is_empty());
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
        match resolve_pool_gates(&pool_with_hook("h"), &hooks, &client)
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
        assert!(resolve_pool_gates(&pool_with_hook("h"), &empty, &client).is_empty());
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

        let resolved = resolve_pool_gates(&pool_with_hook("a"), &hooks, &client);
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
        )) = resolve_pool_gates(&pool_with_hook("n"), &hooks_n, &client)
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
        )) = resolve_pool_gates(&pool_with_hook("c"), &hooks, &client)
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
        )) = resolve_pool_gates(&pool_with_hook("g"), &hooks, &client)
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
            resolve_pool_gates(&pool, &hooks, &client).is_empty(),
            "an rw gate must not resolve as a decision gate"
        );
        assert_eq!(
            resolve_pool_rewrites(&pool, &hooks, &client).len(),
            1,
            "an rw gate must resolve into the pool rewrite chain"
        );
        // And the inverse: a plain (non-rw) gate stays a decision gate, no rewrite entry.
        let mut plain = base_gate();
        plain.socket = Some("/run/busbar/plain.sock".to_string());
        let hooks = registry("plain", plain);
        let pool = pool_with_hook("plain");
        assert_eq!(resolve_pool_gates(&pool, &hooks, &client).len(), 1);
        assert!(resolve_pool_rewrites(&pool, &hooks, &client).is_empty());
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
        let resolved = resolve_rewrite_hooks(&hooks, &global, &client);
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
        let resolved = resolve_gate_hooks(&hooks, &global, &client);
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
        let resolved =
            resolve_tap_hooks(&hooks, &global, &client, crate::config::HookStage::Request);
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
            crate::config::HookStage::Completion,
        );
        assert_eq!(completion.len(), 1, "one completion-stage tap");
        // And a stage nothing observes resolves empty (the zero-cost skip).
        assert!(
            resolve_tap_hooks(&hooks, &global, &client, crate::config::HookStage::Attempt)
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
            crate::config::HookStage::Request,
        );
        assert_eq!(resolved.len(), 2);
        // Both taps share priority 0; identify each by re-resolving individually to assert the flag.
        let ro = resolve_tap_hooks(
            &hooks,
            &["ro-tap".to_string()],
            &client,
            crate::config::HookStage::Request,
        );
        let no = resolve_tap_hooks(
            &hooks,
            &["no-tap".to_string()],
            &client,
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
            match resolve_pool_gates(&pool_with_hook("h"), &hooks, &client)
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
}
