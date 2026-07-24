// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pluggable routing policies.
//!
//! A pool may declare a routing **policy** that, given a cheap projection of the request, returns an
//! ordered **preference** of members — not a single pick. The ordered list feeds the failover loop
//! Busbar already has (`proxy::pick_among`): if the policy's #1 is tripped / excluded / at
//! capacity, Busbar walks to #2 using the existing breaker machinery. One transport-agnostic trait
//! (`RoutingPolicy`); a `kind: hook` dlopen PLUGIN (loaded over the hybrid ABI as a `DlopenPolicy`)
//! is the general out-of-core implementation, and the built-in ranking hooks (the `hooks/ranking/`
//! workspace crate) are the compiled-in ones. (1.5.0 retired the out-of-process socket/webhook
//! transports — a hook is now a signed, trusted, in-process plugin.)
//!
//! ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool resolves to `ResolvedPolicy::None`
//! at config load and NEVER constructs any of the projection types or enters this module's async
//! path. The hot path stays today's inline SWRR.
//!
//! This surface is PRODUCTION-WIRED: `proxy::decide_policy_order` builds the `RoutingRequest` +
//! `Candidate` projections from the live store signals and invokes the resolved policy on every
//! non-default request; `proxy::pick_among` walks the ranked order through the existing failover
//! loop. `resolve_policy` (below) constructs the ranking-hook / dlopen-plugin transports once at
//! config load.

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

pub(crate) mod plugin;
pub(crate) mod scrape;
pub(crate) mod wire;

// The HOOK CONTRACT — the `RoutingPolicy` trait and the read-only projections it is invoked with
// (`RoutingRequest`, `Candidate`, `RoutingContext`, `RoutingDecision`, …) — lives in the
// `busbar-api` crate (the one crate both the engine and every plugin build against). Re-exported
// here so engine-internal paths are unchanged.
// `PolicyError`/`PolicyResult` are re-exported for the `#[cfg(test)]` hook-seam tests (which
// implement `RoutingPolicy` against the engine's types); allow the unused-in-non-test warning.
#[allow(unused_imports)]
pub(crate) use busbar_api::{
    CallerIdentity, Candidate, PolicyError, PolicyResult, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};

/// The plugin-resolution environment threaded through every hook-transport builder: the validated
/// plugin registry (the ONLY resolution surface — a hook's `plugin:` ref opens a `DlopenPolicy`
/// through it) and the shared [`HookProjectors`] every `DlopenPolicy` uses to project the request and
/// parse the reply through the engine's own fail-closed `wire` normalizers. Cheap to clone (both are
/// `Arc`-backed); replaces the old `&reqwest::Client` the retired webhook transport needed.
#[derive(Clone)]
pub(crate) struct HookEnv {
    pub(crate) registry: std::sync::Arc<busbar_plugin_loader::PluginRegistry>,
    pub(crate) projectors: std::sync::Arc<busbar_plugin_loader::hook::HookProjectors>,
    /// The secret resolver used to turn any SecretRef-typed hook setting (e.g. a `licenseKey`) into
    /// its raw value BEFORE the settings cross the ABI at open/configure (ADR-0007). Shared with the
    /// store/auth open paths; the same fail-closed resolver.
    pub(crate) secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
}

impl HookEnv {
    /// Bundle a registry + the shared projectors + the secret resolver into the resolution
    /// environment.
    pub(crate) fn new(
        registry: std::sync::Arc<busbar_plugin_loader::PluginRegistry>,
        secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
    ) -> Self {
        HookEnv {
            registry,
            projectors: plugin::projectors(),
            secret_resolver,
        }
    }

    /// Resolve a hook's opaque `settings:` map — substituting any SecretRef-typed value (e.g. a
    /// `licenseKey`) with its resolved secret — before the JSON crosses the ABI at open/configure.
    /// FAIL-CLOSED: an unresolvable ref is an `Err`, never a dangling reference handed to the plugin.
    fn resolve_hook_settings(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        crate::config::secret::resolve_settings(settings, &self.secret_resolver)
    }
}

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub(crate) enum ResolvedPolicy {
    /// A constructed policy object (a dlopen hook plugin / native non-weighted) plus its fallback config.
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
/// per-request by `proxy::decide_policy_order`.
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
    env: &HookEnv,
    default_hook: Option<&str>,
    settings_version: u64,
) -> Option<ResolvedPolicy> {
    if !cfg.base_named {
        if let Some(name) = default_hook {
            if let Some(hook) = hooks.get(name) {
                // The default gate becomes this pool's base ordering.
                return resolve_gate_transport(name, hook, hooks, env, settings_version);
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
    env: &HookEnv,
    settings_version: u64,
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
            resolve_gate_transport(name, hook, hooks, env, settings_version)
                .map(|rp| (hook.priority, rp))
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
    env: &HookEnv,
    settings_version: u64,
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
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((hook.priority, timeout, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

/// Resolve a GATE hook into a [`ResolvedPolicy`]. The prompt/identity projections are gated by BOTH
/// the operator's `prompt:`/`user:` grant AND the plugin's signed-manifest declared intent (`needs:`)
/// — the belt-and-suspenders projection rule: the core sends content ONLY when both agree
/// ([`projection_grants`]). A missing/unresolvable plugin degrades to `None` — the plugin pre-flight
/// surfaces it loudly at boot.
fn resolve_gate_transport(
    name: &str,
    hook: &crate::config::HookCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> Option<ResolvedPolicy> {
    let policy = gate_transport_named(name, hook, env, settings_version)?;
    let (on_error_chain, on_error) = resolve_on_error_chain(hook, hooks, env, settings_version);
    let (send_prompt, send_user) = projection_grants(name, hook, env);
    Some(ResolvedPolicy::Policy {
        policy,
        on_error,
        on_error_chain,
        timeout: policy_timeout(hook.timeout_ms),
        send_prompt,
        send_user,
        on_empty: gate_on_empty(hook),
    })
}

/// The BELT-AND-SUSPENDERS projection rule: the core projects `prompt`/`user` content into a hook's
/// wire payload ONLY when BOTH the operator's config grant AND the plugin's signed-manifest declared
/// intent (`needs:`) allow it. A fat-fingered grant to a plugin that never asked for content is a
/// no-op (advisory warn); a plugin that asks can still be denied by the operator. Returns
/// `(send_prompt, send_user)`. When the plugin manifest can't be resolved (validated elsewhere), we
/// fall back to the operator grant alone — the pre-flight already fails boot on an unresolvable ref,
/// so this branch is a safety net, never the live path.
fn projection_grants(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> (bool, bool) {
    let grant_prompt = hook.prompt.sends_prompt();
    let grant_user = hook.user.sends_user();
    let Some(p) = env.registry.resolve(&hook.plugin) else {
        return (grant_prompt, grant_user);
    };
    let needs = &p.manifest.needs;
    let send_prompt = grant_prompt && needs.prompt.wants_read();
    let send_user = grant_user && needs.user.wants_read();
    // Surface a fat-fingered grant that the manifest never declared: the projection is a no-op, but
    // the operator should know the grant is inert (they may have the wrong plugin).
    if grant_prompt && !needs.prompt.wants_read() {
        tracing::warn!(
            hook = %name, plugin = %hook.plugin,
            "hook grants `prompt` but the plugin manifest declares no prompt need — no prompt \
             content will be sent (grant is inert)"
        );
    }
    if grant_user && !needs.user.wants_read() {
        tracing::warn!(
            hook = %name, plugin = %hook.plugin,
            "hook grants `user` but the plugin manifest declares no user need — no identity will \
             be sent (grant is inert)"
        );
    }
    // Surface the declared intent at resolution (register/load visibility).
    if needs.declares_any() {
        tracing::info!(
            hook = %name, plugin = %hook.plugin,
            needs_prompt = ?needs.prompt, needs_user = ?needs.user,
            send_prompt, send_user,
            "hook plugin declared content intent"
        );
    }
    (send_prompt, send_user)
}

/// Open the `kind: hook` PLUGIN backing this hook as a [`busbar_plugin_loader::DlopenPolicy`] — the
/// in-process replacement for the retired socket/webhook transports. The plugin's opaque `settings:`
/// map is its `open` config (verbatim JSON). `name` + `settings_version` are carried for diagnostics
/// and the configure ack. `None` when the reference doesn't resolve to a loadable `kind: hook`
/// plugin (the plugin pre-flight already fails boot on that, so a `None` here is a safety net that
/// degrades to "gate absent", never a stranded request).
fn gate_transport_named(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    _settings_version: u64,
) -> Option<Arc<dyn RoutingPolicy>> {
    // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret store BEFORE the
    // settings cross the ABI (ADR-0007). A resolution failure is treated exactly like a failed load:
    // the gate degrades to absent (the existing fail-open-to-the-request posture of this runtime
    // safety net). The FAIL-CLOSED guarantee lives in the plugin pre-flight, which refuses boot/reload
    // on an unresolvable hook secret before this path is ever taken.
    let resolved = match env.resolve_hook_settings(&hook.settings) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                hook = %name, plugin = %hook.plugin, error = %e,
                "hook settings did not resolve; gate treated as absent (fail-open to the request)"
            );
            return None;
        }
    };
    let cfg_json = serde_json::Value::Object(resolved).to_string();
    match env
        .registry
        .open_hook(&hook.plugin, &cfg_json, name, env.projectors.clone())
    {
        Ok(policy) => Some(policy),
        Err(e) => {
            tracing::warn!(
                hook = %name, plugin = %hook.plugin, error = %e,
                "hook plugin failed to load; gate treated as absent (fail-open to the request)"
            );
            None
        }
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
    env: &HookEnv,
) -> Result<(), String> {
    // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) before the settings cross the ABI
    // (ADR-0007). FAIL-CLOSED: an unresolvable ref is NOT committed — the plugin never receives a
    // dangling reference on a settings push.
    let resolved = env
        .resolve_hook_settings(&hook.settings)
        .map_err(|e| format!("hook '{name}' settings: {e}"))?;
    let Some(transport) = gate_transport_named(name, hook, env, settings_version) else {
        return Err("hook plugin unresolvable".to_string());
    };
    transport
        .configure(
            name,
            &resolved,
            settings_version,
            std::time::Duration::from_millis(CONFIGURE_TIMEOUT_MS),
        )
        .await
        .map_err(|e| e.to_string())
}

/// Fetch a hook's self-reported STATUS (observed settings + metrics) over its transport — the
/// control-plane read behind `GET /api/v1/admin/hooks/{name}/status`. Fresh transport per call
/// (never contends the hot request connection); `None` = unsupported/unreachable (fail-open).
pub(crate) async fn fetch_status(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<busbar_api::HookStatus> {
    let transport = gate_transport_named(name, hook, env, settings_version)?;
    transport
        .status(std::time::Duration::from_millis(CONFIGURE_TIMEOUT_MS))
        .await
}

/// Fetch a hook's self-described settings schema over its transport (D2,
/// `GET /api/v1/admin/hooks/{name}/schema`). `None` = the hook/transport doesn't answer describe.
pub(crate) async fn fetch_schema(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<serde_json::Value> {
    let transport = gate_transport_named(name, hook, env, settings_version)?;
    // `DlopenPolicy::describe` returns the schema member ALREADY EXTRACTED from the plugin's
    // self-description envelope (via the `describe_schema` projector), so the /schema read serves a
    // SINGLE nest (the endpoint adds its own {name, schema} wrapper). No schema member (incl. the
    // `{}` unsupported reply) = no schema (the endpoint reports null).
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
    env: &HookEnv,
    settings_version: u64,
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
        if let Some(policy) = gate_transport_named(current, h, env, settings_version) {
            let (send_prompt, send_user) = projection_grants(current, h, env);
            chain.push(FallbackHook {
                policy,
                timeout: policy_timeout(h.timeout_ms),
                send_prompt,
                send_user,
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
/// (unresolvable plugin refs) are skipped; the plugin pre-flight surfaces those loudly at boot.
pub(crate) fn resolve_rewrite_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
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
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
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
    env: &HookEnv,
    settings_version: u64,
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
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
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
    env: &HookEnv,
    settings_version: u64,
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
        if let Some(rp) = resolve_gate_transport(name, hook, hooks, env, settings_version) {
            ranked.push((hook.priority, rp));
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
