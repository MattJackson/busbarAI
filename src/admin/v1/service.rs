// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Admin API v1 SERVICE — the application core (the "port").
//!
//! `AdminService` owns every admin OPERATION as a typed async method returning `Result<View,
//! AdminError>`. It holds the shared `App` and knows nothing about HTTP/JSON/MCP: a transport adapter
//! (`super::transport`) drives it and projects the result onto a wire. This is where scope checks,
//! atomicity, and audit live as the surface grows — one place, reused by every transport (REST now;
//! GraphQL/MCP/gRPC later, unchanged).

use std::sync::Arc;

use crate::state::App;

use super::contract::{
    AdminAuthView, AdminError, AuthView, BuildInfo, ConfigValidateView, EffectiveConfigView,
    HookHealthView, HookTransportView, HookView, InfoView, KeyUsageView, ModelView, Page,
    PluginView, PoolDetailView, PoolMemberStatusView, PoolMemberView, PoolView, ProviderView,
    TopologyInfo, UsageTotals, UsageView,
};
use crate::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

/// Process start instant, for the `info` uptime read. Stamped ONCE at startup by `mark_start()`.
/// A missing value (never stamped — e.g. a unit test that skips `main`) yields a `None` uptime
/// rather than a panic.
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Stamp the process start instant for the `info` uptime read. Idempotent (first `set` wins), so it
/// is safe to call unconditionally at startup.
pub(crate) fn mark_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
}

/// The auth modules COMPILED INTO this binary (feature-gated at compile time — real `#[cfg]` on each
/// array element, so this reflects the ACTUAL binary and empties under `--no-default-features`). The
/// single source for both `info`'s build proof and the `plugins?type=auth` catalog.
fn auth_modules_compiled_in() -> Vec<&'static str> {
    [
        #[cfg(feature = "auth-tokens")]
        "tokens",
    ]
    .to_vec()
}

/// The removable hook plugins COMPILED INTO this binary (feature-gated). Excludes the always-present,
/// non-removable weighted SWRR floor, which is reported separately (as `weighted_floor` / the
/// `weighted` compiled-in entry).
fn hook_plugins_compiled_in() -> Vec<&'static str> {
    [
        #[cfg(feature = "hooks-ranking")]
        "ranking",
    ]
    .to_vec()
}

/// Best-effort reachability probe for a hook's transport, for the health read. NEVER sends a hook
/// request — it only checks whether the endpoint accepts a connection. A socket gets a short-timeout
/// `connect` (unix only); a webhook is not probed here (returns `None` with a note — webhooks lazy-
/// connect per request, and a blind GET/HEAD could have side effects). Returns `(reachable, detail)`.
async fn probe_transport(cfg: &HookCfg) -> (Option<bool>, Option<String>) {
    // Cap the probe so an unresponsive socket can never stall the admin read.
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
    match (&cfg.socket, &cfg.webhook) {
        (Some(path), _) => {
            #[cfg(unix)]
            {
                match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::UnixStream::connect(path))
                    .await
                {
                    Ok(Ok(_stream)) => (Some(true), None),
                    Ok(Err(e)) => (Some(false), Some(format!("connect failed: {}", e.kind()))),
                    Err(_) => (Some(false), Some("connect timed out".to_string())),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                (
                    None,
                    Some("socket transport is unix-only; not probed on this host".to_string()),
                )
            }
        }
        (None, Some(_url)) => (
            None,
            Some("webhook is probed on demand at request time, not here".to_string()),
        ),
        (None, None) => (
            Some(false),
            Some("hook defines no transport (socket or webhook)".to_string()),
        ),
    }
}

/// Build the next `App` snapshot with `name` registered/updated to `cfg` in the hook registry — the
/// PURE core of `POST /admin/v1/hooks` (runtime hook registration). Validates the definition, clones
/// the current snapshot (sharing the live-state `Arc`s), inserts the hook, updates the global-hook
/// wiring, and RE-RESOLVES the rewrite/tap transports so a `global` hook takes effect immediately on
/// swap. Lanes/store/pools/auth are UNTOUCHED, so the store's per-lane breaker state is preserved (no
/// re-index — the safe, store-constraint-free subset of config apply). The caller `AppHandle::swap`s
/// the returned snapshot. Pure + `Result` → unit-testable without the transport.
/// The `settings` map is persisted VERBATIM into the state file and re-sent to the hook binary on
/// every reconnect, so an unbounded map bloats the durable state and amplifies the reconnect path.
/// These caps are far past any real hook's settings; a compromised `hooks-register` token must not
/// be able to blow them out. Shared by `build_with_hook` (register / PUT) and `patch_hook_settings`
/// (PATCH) so all three write paths enforce ONE limit with no drift.
pub(crate) const MAX_SETTINGS_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SETTINGS_KEYS: usize = 256;
/// Upper bound on a hook name (a registry key persisted to the state file + every audit row).
/// Generous headroom over any real hook name; guards the durable-state/audit/reconnect path.
pub(crate) const MAX_HOOK_NAME_LEN: usize = 256;

/// Fail-closed size check for a hook's `settings` map — see the cap rationale above.
pub(crate) fn validate_hook_settings_size(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AdminError> {
    if settings.len() > MAX_SETTINGS_KEYS {
        return Err(AdminError::Validation(format!(
            "settings has too many keys ({}, max {MAX_SETTINGS_KEYS})",
            settings.len()
        )));
    }
    if let Ok(bytes) = serde_json::to_vec(settings) {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(AdminError::Validation(format!(
                "settings too large ({} bytes, max {MAX_SETTINGS_BYTES})",
                bytes.len()
            )));
        }
    }
    Ok(())
}

pub(crate) fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
    // ── validate the definition (fail-closed, before any mutation) ──
    if name.trim().is_empty() {
        return Err(AdminError::Validation("hook name must not be empty".into()));
    }
    // Cap the name length. The name is a registry key that gets written VERBATIM into the overlay
    // state file and every audit row (and echoed on the wire); without a bound a `hooks-register`
    // token could POST a name up to the body-size cap (~MB), bloating the durable state / audit /
    // reconnect path — the same defensive posture as the key-id / settings caps. (found: audit c2r4.)
    if name.len() > MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "hook name is {} chars; must be <= {MAX_HOOK_NAME_LEN}",
            name.len()
        )));
    }
    // The `settings` map rides register/PUT too — cap it here so it is bounded on EVERY write path,
    // not just PATCH (found: audit c1r12 — register/PUT were missing the cap PATCH already had).
    validate_hook_settings_size(&cfg.settings)?;
    // Exactly one transport: socket XOR webhook.
    if cfg.socket.is_none() == cfg.webhook.is_none() {
        return Err(AdminError::Validation(
            "a hook must set exactly one transport: `socket` or `webhook`".into(),
        ));
    }
    // `prompt: rw` is a rewrite grant, meaningless (and unsafe) on a fire-and-forget tap.
    if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
        return Err(AdminError::Validation(
            "`prompt: rw` is invalid on a `kind: tap` hook (a tap cannot rewrite)".into(),
        ));
    }
    // GRANT IMMUTABILITY (§6.4): `kind`/`prompt`/`user` are definition-only and FROZEN after first
    // registration. Re-registering a name with different grants is a `conflict` — delete and
    // re-register to change them. This closes the "register `prompt: no`, wire it in, then escalate to
    // `rw`" exfiltration path: a grant can never widen in place. Re-registering with the SAME grants is
    // allowed (an idempotent re-register / settings refresh).
    if let Some(existing) = current.hook_registry.get(name) {
        if existing.kind != cfg.kind || existing.prompt != cfg.prompt || existing.user != cfg.user {
            return Err(AdminError::Conflict(format!(
                "hook `{name}` already exists with different kind/prompt/user grants; grants are \
                 immutable — delete and re-register to change them"
            )));
        }
    }

    // ── build the next snapshot (clone shares live state; only config-derived fields change) ──
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    let is_global = cfg.global;
    next.hook_registry.insert(name.to_string(), cfg);
    if is_global {
        if !next.global_hooks.iter().any(|n| n == name) {
            next.global_hooks.push(name.to_string());
        }
    } else {
        // A PUT that REPLACES a prior `global: true` hook with `global: false` must DE-WIRE it from
        // the global fan-out — otherwise the stale membership keeps it firing on every request and
        // `hook_view` keeps reporting `global: true`, so the operator's 200 OK silently no-ops the
        // demotion. Mirrors `build_without_hook`'s DELETE cleanup.
        next.global_hooks.retain(|n| n != name);
    }
    // Re-resolve the FIRED transports from the new registry so a global hook is live after the swap.
    next.rewrite_hooks = crate::routing::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
    );
    next.tap_hooks = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Completion,
    );
    next.global_gates =
        crate::routing::resolve_gate_hooks(&next.hook_registry, &next.global_hooks, &next.client);
    Ok(next)
}

/// Build the next `App` snapshot with `name` REMOVED from the hook registry — the pure core of
/// `DELETE /admin/v1/hooks/{name}`. `not_found` if the name is unregistered. Clones the current
/// snapshot (sharing live state), drops the hook from the registry + global wiring, and re-resolves
/// the rewrite/tap transports. Lanes/store untouched (breaker state preserved). Same GLOBAL scope as
/// `build_with_hook`: pool-`hook:` references are resolved into `pool_runtime` at startup and are NOT
/// re-resolved here — that (plus the dangling-ref 409) lands with the broader config/apply.
pub(crate) fn build_without_hook(current: &App, name: &str) -> Result<App, AdminError> {
    if !current.hook_registry.contains_key(name) {
        return Err(AdminError::NotFound(format!("hook `{name}`")));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry.remove(name);
    next.global_hooks.retain(|n| n != name);
    next.rewrite_hooks = crate::routing::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
    );
    next.tap_hooks = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Completion,
    );
    next.global_gates =
        crate::routing::resolve_gate_hooks(&next.hook_registry, &next.global_hooks, &next.client);
    Ok(next)
}

/// Build the next `App` snapshot with the whole HOOK SURFACE replaced by a version snapshot — the
/// pure core of `POST /admin/v1/config/rollback`. RE-VALIDATES the snapshot against CURRENT reality
/// before any mutation (a snapshot that was valid when recorded may violate an invariant now):
/// per-hook transport XOR + rw-on-tap, at-most-one-default, and no dangling global refs. Clones the
/// current snapshot (sharing live state — lanes/store untouched, breaker state preserved) and
/// re-resolves every global transport. Same restrict-scope as the other builders: pool-resolved
/// hook references are startup-resolved and not re-resolved here.
pub(crate) fn build_with_registry(
    current: &App,
    registry: std::collections::HashMap<String, HookCfg>,
    global_hooks: Vec<String>,
) -> Result<App, AdminError> {
    for (name, cfg) in &registry {
        if cfg.socket.is_none() == cfg.webhook.is_none() {
            return Err(AdminError::Validation(format!(
                "hook `{name}` must set exactly one transport: `socket` or `webhook`"
            )));
        }
        if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
            return Err(AdminError::Validation(format!(
                "hook `{name}` sets `prompt: rw` on a `kind: tap` (a tap cannot rewrite)"
            )));
        }
    }
    let defaults: Vec<&str> = registry
        .iter()
        .filter(|(_, h)| h.default)
        .map(|(n, _)| n.as_str())
        .collect();
    if defaults.len() > 1 {
        return Err(AdminError::Validation(format!(
            "snapshot has more than one `default: true` hook: {}",
            defaults.join(", ")
        )));
    }
    for g in &global_hooks {
        if !registry.contains_key(g) {
            return Err(AdminError::Validation(format!(
                "snapshot wires unknown global hook `{g}`"
            )));
        }
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry = registry;
    next.global_hooks = global_hooks;
    next.rewrite_hooks = crate::routing::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
    );
    next.tap_hooks = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::routing::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        crate::config::HookStage::Completion,
    );
    next.global_gates =
        crate::routing::resolve_gate_hooks(&next.hook_registry, &next.global_hooks, &next.client);
    Ok(next)
}

/// The admin application core. Cheap to construct and clone-free to share (`Arc<App>` inside); a
/// transport builds ONE and hands `Arc<AdminService>` to its routes.
pub(crate) struct AdminService {
    app: Arc<App>,
}

impl AdminService {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self { app }
    }

    /// `GET /admin/v1/info` — version, the COMPILED-IN plugin sets (compliance-by-compilation proof),
    /// uptime, and pool/model/provider topology. Read scope. Infallible today, but returns `Result`
    /// for a uniform transport contract (every op is `Result<View, AdminError>`).
    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
        // The compiled-in plugin sets reflect the ACTUAL binary (feature-gated). `default auth =
        // tokens` + `default hook = weighted` are the two OEM-default plugins; weighted is the one
        // baked in (non-removable), so it appears as `weighted_floor` below, not in `hook_plugins`.
        let auth_modules = auth_modules_compiled_in();
        let hook_plugins = hook_plugins_compiled_in();

        let providers: std::collections::BTreeSet<&str> =
            self.app.lanes.iter().map(|l| l.provider.as_str()).collect();

        Ok(InfoView {
            version: env!("CARGO_PKG_VERSION"),
            build: BuildInfo {
                auth_modules,
                hook_plugins,
                weighted_floor: true,
            },
            uptime_seconds: PROCESS_START.get().map(|s| s.elapsed().as_secs()),
            topology: TopologyInfo {
                pools: self.app.pools.len(),
                models: self.app.by_model.len(),
                providers: providers.len(),
            },
            config_persistence: self.app.overlay_path.is_some(),
            config_version: self.app.config_version,
        })
    }

    /// `GET /admin/v1/pools` — the pool topology (name + member models/weights). Read scope. Sorted
    /// by name for a stable, diff-friendly listing. Live per-member
    /// status is an additive follow-up (§6.9).
    pub(crate) async fn list_pools(&self) -> Result<Page<PoolView>, AdminError> {
        let mut pools: Vec<PoolView> = self
            .app
            .pools
            .iter()
            .map(|(name, members)| PoolView {
                name: name.clone(),
                members: members
                    .iter()
                    .map(|m| PoolMemberView {
                        // `idx` is the stable lane handle; project the lane's model name.
                        model: self.app.lanes[m.idx].model.clone(),
                        weight: m.weight,
                    })
                    .collect(),
            })
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pools))
    }

    /// `GET /admin/v1/pools/{name}` — the LIVE per-member status of one pool (breaker/concurrency/
    /// latency/tallies), from the same store signals the routing seam ranks on. Read scope.
    /// `not_found` if the pool is unknown.
    pub(crate) async fn get_pool(&self, name: &str) -> Result<PoolDetailView, AdminError> {
        let members = self
            .app
            .pools
            .get(name)
            .ok_or_else(|| AdminError::NotFound(format!("pool `{name}`")))?;
        let now = crate::store::now();
        let members = members
            .iter()
            .map(|m| {
                // `snapshot` is the same release-exposed live summary `/stats` reads (usable / cooldown
                // / inflight / tallies / dead); `available_permits` + `lane_latency_ms` round it out.
                let snap = self.app.store.snapshot(m.idx, now);
                PoolMemberStatusView {
                    model: self.app.lanes[m.idx].model.clone(),
                    weight: m.weight,
                    usable: snap.usable,
                    cooldown_remaining_s: snap.cooldown_remaining_s,
                    available_concurrency: self.app.store.available_permits(m.idx),
                    inflight: snap.inflight,
                    latency_ms: self.app.store.lane_latency_ms(m.idx),
                    ok: snap.ok,
                    err: snap.err,
                    dead: snap.dead,
                }
            })
            .collect();
        Ok(PoolDetailView {
            name: name.to_string(),
            members,
        })
    }

    /// `GET /admin/v1/models` — every model lane + its upstream provider. Read scope. Sorted by
    /// model name. No credentials.
    pub(crate) async fn list_models(&self) -> Result<Page<ModelView>, AdminError> {
        let mut models: Vec<ModelView> = self
            .app
            .lanes
            .iter()
            .map(|l| ModelView {
                model: l.model.clone(),
                provider: l.provider.clone(),
            })
            .collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(Page::single(models))
    }

    /// `GET /admin/v1/providers` — distinct upstream providers + the count of model lanes routing
    /// through each. Read scope. Sorted by provider name.
    pub(crate) async fn list_providers(&self) -> Result<Page<ProviderView>, AdminError> {
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for lane in &self.app.lanes {
            *counts.entry(lane.provider.as_str()).or_insert(0) += 1;
        }
        let providers = counts
            .into_iter()
            .map(|(provider, model_count)| ProviderView {
                provider: provider.to_string(),
                model_count,
            })
            .collect();
        Ok(Page::single(providers))
    }

    /// `GET /admin/v1/hooks` — the hook registry read. Read scope. Each entry
    /// is the DEFINITION (kind/transport/grants/ordering/stage), never a secret. Sorted by name.
    pub(crate) async fn list_hooks(&self) -> Result<Page<HookView>, AdminError> {
        let mut hooks: Vec<HookView> = self
            .app
            .hook_registry
            .iter()
            .map(|(name, cfg)| self.hook_view(name, cfg))
            .collect();
        hooks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(hooks))
    }

    /// `GET /admin/v1/hooks/{name}` — one hook definition, or `not_found` if the name is unregistered.
    pub(crate) async fn get_hook(&self, name: &str) -> Result<HookView, AdminError> {
        self.app
            .hook_registry
            .get(name)
            .map(|cfg| self.hook_view(name, cfg))
            .ok_or_else(|| AdminError::NotFound(format!("hook `{name}`")))
    }

    /// `GET /admin/v1/plugins?type=auth|hooks` — the plugin catalog for one TYPE. Read
    /// scope. Lists COMPILED-IN plugins (feature-gated, from the binary — the same source as `info`'s
    /// build proof) and EXTERNAL plugins (registered over socket/webhook). An unknown/absent `type` is
    /// an `invalid_request` (the two types are distinct engine contracts; a caller must pick one).
    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                // Compiled-in auth modules (feature-gated). Active = present in the auth chain.
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    plugins.push(PluginView {
                        name: name.to_string(),
                        r#type: "auth",
                        loader: "compiled-in",
                        active: Some(chain.contains(&name)),
                        target: None,
                    });
                }
                // External auth modules (runtime-registered) — none until the auth-module registration
                // endpoint lands (#56); the catalog shape is ready for them.
            }
            "hooks" => {
                // The weighted SWRR floor is compiled in unconditionally (the non-removable default
                // hook); activation is the per-pool default, not summarized here.
                plugins.push(PluginView {
                    name: "weighted".to_string(),
                    r#type: "hooks",
                    loader: "compiled-in",
                    active: None,
                    target: None,
                });
                for name in hook_plugins_compiled_in() {
                    plugins.push(PluginView {
                        name: name.to_string(),
                        r#type: "hooks",
                        loader: "compiled-in",
                        active: None,
                        target: None,
                    });
                }
                // External hooks = the configured registry entries (socket/webhook). Configured ⇒
                // active; the transport target is projected (operator config, not a secret).
                let mut externals: Vec<PluginView> = self
                    .app
                    .hook_registry
                    .iter()
                    .map(|(name, cfg)| {
                        let target = cfg.socket.clone().or_else(|| cfg.webhook.clone());
                        PluginView {
                            name: name.clone(),
                            r#type: "hooks",
                            loader: "external",
                            active: Some(true),
                            target,
                        }
                    })
                    .collect();
                externals.sort_by(|a, b| a.name.cmp(&b.name));
                plugins.append(&mut externals);
            }
            other => {
                return Err(AdminError::Validation(format!(
                    "unknown plugin type `{other}`: expected `auth` or `hooks`"
                )));
            }
        }
        Ok(Page::single(plugins))
    }

    /// `GET /admin/v1/config` — the EFFECTIVE running config, composed from the same redacted reads as
    /// the individual endpoints (auth/pools/models/providers/hooks/global-hooks). Read scope. Carries
    /// no secret. For drift detection + one-shot inspection; the base-vs-overlay source annotation
    /// lands with the overlay substrate.
    pub(crate) async fn get_config(&self) -> Result<EffectiveConfigView, AdminError> {
        Ok(EffectiveConfigView {
            version: self.app.config_version,
            auth: self.get_auth().await?,
            pools: self.list_pools().await?.items,
            models: self.list_models().await?.items,
            providers: self.list_providers().await?.items,
            hooks: self.list_hooks().await?.items,
            global_hooks: self.app.global_hooks.clone(),
        })
    }

    /// `POST /admin/v1/config/validate` — DRY-RUN a proposed config: resolve (`config.yaml` deploy +
    /// `providers.yaml` defs) then run the full boot-time `config_validate`, collecting every error at
    /// once, WITHOUT applying anything. Always succeeds as an operation (`Result::Ok`) — the verdict is
    /// in the view's `ok`/`errors`; a valid request describing an invalid config is `ok: false`, not an
    /// error. Read scope (no mutation). Env interpolation is out of scope (structure + resolution only).
    pub(crate) async fn validate_config(
        &self,
        deploy: DeployCfg,
        defs: std::collections::HashMap<String, ProviderDef>,
    ) -> Result<ConfigValidateView, AdminError> {
        // Resolve first (cross-references config.yaml providers against providers.yaml defs); if that
        // fails there is no RootCfg to hand to the semantic validator, so return the resolve errors.
        match crate::config::resolve(&deploy, &defs) {
            Err(errors) => Ok(ConfigValidateView { ok: false, errors }),
            Ok(root) => match crate::config_validate::validate(&root) {
                Ok(()) => Ok(ConfigValidateView {
                    ok: true,
                    errors: Vec::new(),
                }),
                Err(errors) => Ok(ConfigValidateView { ok: false, errors }),
            },
        }
    }

    /// `GET /admin/v1/admin-auth` — the ADMIN-plane auth config (distinct from the ingress chain).
    /// Read scope. Today reports the built-in admin-token gate; when the pluggable `admin_auth` chain
    /// lands it reports that chain. Never a secret.
    pub(crate) async fn get_admin_auth(&self) -> Result<AdminAuthView, AdminError> {
        // The admin plane is guarded by the governance admin token today.
        let configured = self
            .app
            .governance
            .as_ref()
            .map(|g| g.admin_token_hash().is_some())
            .unwrap_or(false);
        let modules = if configured {
            vec!["admin-token"]
        } else {
            Vec::new()
        };
        Ok(AdminAuthView {
            configured,
            modules,
        })
    }

    /// `GET /admin/v1/usage` — fleet usage aggregation (spend/tokens/requests totals + per-key
    /// breakdown) from governance's counters. Read scope. Empty when governance is disabled. The
    /// per-key store reads run on a blocking thread (the SQLite store is synchronous), so the async
    /// runtime is never blocked. Never returns a secret — ids/names only.
    pub(crate) async fn get_usage(&self) -> Result<UsageView, AdminError> {
        let Some(gov) = self.app.governance.clone() else {
            return Ok(UsageView {
                total: UsageTotals::default(),
                keys: Vec::new(),
            });
        };
        let now = crate::store::now();
        let joined = tokio::task::spawn_blocking(move || -> Result<UsageView, ()> {
            let keys = gov.all_keys().map_err(|_| ())?;
            let mut total = UsageTotals::default();
            let mut per_key = Vec::with_capacity(keys.len());
            for k in keys {
                let u = gov.usage_for(&k.id, now).map_err(|_| ())?.unwrap_or(
                    crate::governance::Usage {
                        spend_cents: 0,
                        tokens: 0,
                        requests: 0,
                    },
                );
                total.spend_cents = total.spend_cents.saturating_add(u.spend_cents);
                total.tokens = total.tokens.saturating_add(u.tokens);
                total.requests = total.requests.saturating_add(u.requests);
                per_key.push(KeyUsageView {
                    id: k.id,
                    name: k.name,
                    spend_cents: u.spend_cents,
                    tokens: u.tokens,
                    requests: u.requests,
                });
            }
            per_key.sort_by(|a, b| a.id.cmp(&b.id));
            Ok(UsageView {
                total,
                keys: per_key,
            })
        })
        .await;
        match joined {
            Ok(Ok(view)) => Ok(view),
            // A store failure or a blocking-join failure is an internal error (details logged upstream
            // in the store layer); the caller never sees store internals.
            Ok(Err(())) | Err(_) => Err(AdminError::Internal),
        }
    }

    /// `GET /admin/v1/auth` — the ingress auth chain + upstream-credential mode. Read scope. Never a
    /// secret: only module names and the mode. The mutation half (`PUT /admin/v1/auth`, with the
    /// anti-self-lockout guard) lands with the config-plane write path.
    pub(crate) async fn get_auth(&self) -> Result<AuthView, AdminError> {
        Ok(AuthView {
            chain: self.app.auth.chain_names(),
            upstream_credentials: match self.app.upstream_creds() {
                crate::auth::UpstreamCreds::Own => "own",
                crate::auth::UpstreamCreds::Passthrough => "passthrough",
            },
            open: self.app.auth.is_open(),
        })
    }

    /// `GET /admin/v1/hooks/{name}/health` — best-effort transport reachability for one hook. Read
    /// scope. `not_found` if the name is unregistered. NEVER fires the hook: for a socket it does a
    /// short-timeout connect probe (`reachable = Some(_)`); for a webhook (or on non-unix) it reports
    /// `reachable = None` with a note (webhooks are probed on demand at request time, not here).
    pub(crate) async fn hook_health(&self, name: &str) -> Result<HookHealthView, AdminError> {
        let cfg = self
            .app
            .hook_registry
            .get(name)
            .ok_or_else(|| AdminError::NotFound(format!("hook `{name}`")))?;
        let view = self.hook_view(name, cfg);
        let (reachable, detail) = probe_transport(cfg).await;
        Ok(HookHealthView {
            name: name.to_string(),
            transport: view.transport,
            reachable,
            detail,
        })
    }

    /// Project a registry `HookCfg` into the wire `HookView`. `global` is true when the hook is named
    /// in `global_hooks:` OR declares inline `global: true` — the two ways a hook is globally wired.
    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        let (transport_kind, target) = match (&cfg.socket, &cfg.webhook) {
            (Some(path), _) => ("socket", Some(path.clone())),
            (None, Some(url)) => ("webhook", Some(url.clone())),
            (None, None) => ("none", None),
        };
        HookView {
            name: name.to_string(),
            kind: match cfg.kind {
                HookKind::Tap => "tap",
                HookKind::Gate => "gate",
            },
            transport: HookTransportView {
                kind: transport_kind,
                target,
            },
            prompt: match cfg.prompt {
                PromptAccess::No => "no",
                PromptAccess::Ro => "ro",
                PromptAccess::Rw => "rw",
            },
            user: match cfg.user {
                UserAccess::No => "no",
                UserAccess::Ro => "ro",
            },
            priority: cfg.priority,
            at: cfg.at.map(|s| match s {
                HookStage::Request => "request",
                HookStage::Route => "route",
                HookStage::Attempt => "attempt",
                HookStage::Completion => "completion",
            }),
            on_error: cfg.on_error.clone(),
            timeout_ms: cfg.timeout_ms,
            settings: cfg.settings.clone(),
            global: cfg.global || self.app.global_hooks.iter().any(|n| n == name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};
    use crate::test_support::TestApp;

    fn hook(kind: HookKind, global: bool) -> HookCfg {
        HookCfg {
            kind,
            socket: None,
            webhook: Some("http://127.0.0.1:9971/".to_string()),
            timeout_ms: 5,
            on_error: "weighted".to_string(),
            prompt: PromptAccess::No,
            user: UserAccess::No,
            priority: 0,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global,
            default: false,
        }
    }

    /// `build_with_hook` registers a GLOBAL tap into the registry + global wiring AND re-resolves it
    /// into the fired tap transports — so after the caller swaps the returned snapshot, the tap is live.
    /// Lanes/store are shared (unchanged), proving the store-constraint-free subset.
    #[test]
    fn build_with_hook_registers_and_wires_global_tap() {
        let app = TestApp::new().build();
        assert_eq!(app.tap_hooks.len(), 0, "fixture starts with no taps");
        let next = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
            .expect("a valid global tap registers");
        assert!(next.hook_registry.contains_key("logger"));
        assert!(
            next.global_hooks.iter().any(|n| n == "logger"),
            "global tap wired into global_hooks"
        );
        assert_eq!(
            next.tap_hooks.len(),
            1,
            "the global tap re-resolved into the fired tap transports (live after swap)"
        );
        // Live state is shared, not rebuilt: the store Arc is the SAME instance.
        assert!(
            std::sync::Arc::ptr_eq(&app.store, &next.store),
            "the store (live breaker state) is preserved across the apply, not re-indexed"
        );
    }

    /// REGRESSION (audit c1r8): a PUT that REPLACES a `global: true` hook with `global: false` must
    /// DE-WIRE it from the global fan-out — remove it from `global_hooks` AND drop it from the fired
    /// transports — so the demotion actually takes effect. The prior code only ever APPENDED on
    /// `global: true` and never removed, so a demoted hook kept firing on every request and still
    /// reported `global: true`.
    #[test]
    fn build_with_hook_demotes_global_false_removes_wiring() {
        let app = TestApp::new().build();
        // Register a GLOBAL tap, then PUT the same name with global: false.
        let promoted = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
            .expect("global tap registers");
        assert!(promoted.global_hooks.iter().any(|n| n == "logger"));
        assert_eq!(promoted.tap_hooks.len(), 1, "global tap is live");

        let demoted = build_with_hook(&promoted, "logger", hook(HookKind::Tap, false))
            .expect("demotion to global: false is a valid same-grant replace");
        assert!(
            !demoted.global_hooks.iter().any(|n| n == "logger"),
            "a global: false PUT must REMOVE the hook from global_hooks, not leave it firing"
        );
        assert_eq!(
            demoted.tap_hooks.len(),
            0,
            "the demoted hook must drop out of the fired global tap transports"
        );
        assert!(
            demoted.hook_registry.contains_key("logger"),
            "the hook definition itself survives — only its global membership is dropped"
        );
    }

    /// REGRESSION (audit c1r12): the `settings` map size cap enforced by PATCH must ALSO gate
    /// register/PUT (both funnel through `build_with_hook`) — else an unbounded map could be
    /// registered/replaced, bloating the durable state and the reconnect path the cap protects.
    #[test]
    fn build_with_hook_caps_oversized_settings() {
        let app = TestApp::new().build();
        // Just over the key cap.
        let mut too_many = hook(HookKind::Tap, false);
        for i in 0..=MAX_SETTINGS_KEYS {
            too_many
                .settings
                .insert(format!("k{i}"), serde_json::json!(1));
        }
        assert!(
            matches!(
                build_with_hook(&app, "big", too_many),
                Err(AdminError::Validation(_))
            ),
            "a settings map over the key cap must reject at register/PUT, not just PATCH"
        );

        // Just over the byte cap (few keys, huge value).
        let mut too_big = hook(HookKind::Tap, false);
        too_big.settings.insert(
            "blob".to_string(),
            serde_json::json!("x".repeat(MAX_SETTINGS_BYTES + 1)),
        );
        assert!(matches!(
            build_with_hook(&app, "big", too_big),
            Err(AdminError::Validation(_))
        ));

        // A modest settings map still registers.
        let mut ok = hook(HookKind::Tap, false);
        ok.settings
            .insert("level".to_string(), serde_json::json!("info"));
        assert!(build_with_hook(&app, "fine", ok).is_ok());
    }

    /// REGRESSION (audit c2r4): the hook NAME (a registry key persisted to the state file + every
    /// audit row) must be length-capped, like the key id / settings map — else a `hooks-register`
    /// token could POST a megabyte-long name and bloat the durable state / audit / reconnect path.
    #[test]
    fn build_with_hook_caps_oversized_name() {
        let app = TestApp::new().build();
        let huge = "n".repeat(MAX_HOOK_NAME_LEN + 1);
        assert!(
            matches!(
                build_with_hook(&app, &huge, hook(HookKind::Tap, false)),
                Err(AdminError::Validation(_))
            ),
            "a name over the cap must reject"
        );
        // A name AT the cap is fine.
        let at_cap = "n".repeat(MAX_HOOK_NAME_LEN);
        assert!(build_with_hook(&app, &at_cap, hook(HookKind::Tap, false)).is_ok());
    }

    /// Validation is fail-closed BEFORE any mutation: `prompt: rw` on a tap and a missing transport
    /// both reject with `invalid_request`.
    #[test]
    fn build_with_hook_rejects_invalid_definitions() {
        let app = TestApp::new().build();
        let mut rw_tap = hook(HookKind::Tap, false);
        rw_tap.prompt = PromptAccess::Rw;
        assert!(matches!(
            build_with_hook(&app, "t", rw_tap),
            Err(AdminError::Validation(_))
        ));

        let mut no_transport = hook(HookKind::Gate, false);
        no_transport.webhook = None;
        assert!(matches!(
            build_with_hook(&app, "x", no_transport),
            Err(AdminError::Validation(_))
        ));

        let empty_name = hook(HookKind::Gate, false);
        assert!(matches!(
            build_with_hook(&app, "  ", empty_name),
            Err(AdminError::Validation(_))
        ));
    }

    /// GRANT IMMUTABILITY (§6.4): re-registering an existing hook with DIFFERENT kind/prompt/user is a
    /// `conflict`; re-registering with the SAME grants is allowed (idempotent). Closes the escalation
    /// path (register `prompt: no`, then widen to `rw`).
    #[test]
    fn build_with_hook_enforces_grant_immutability() {
        let app = TestApp::new().build();
        // First registration: a gate with prompt: no.
        let after_first = build_with_hook(&app, "g", hook(HookKind::Gate, false)).unwrap();

        // Re-register the SAME name with a WIDENED grant (prompt: rw) → conflict.
        let mut escalated = hook(HookKind::Gate, false);
        escalated.prompt = PromptAccess::Rw;
        assert!(
            matches!(
                build_with_hook(&after_first, "g", escalated),
                Err(AdminError::Conflict(_))
            ),
            "widening a grant in place must be a conflict"
        );

        // Re-register with the SAME grants → allowed (idempotent).
        assert!(
            build_with_hook(&after_first, "g", hook(HookKind::Gate, false)).is_ok(),
            "re-registering with identical grants is allowed"
        );
    }
}
