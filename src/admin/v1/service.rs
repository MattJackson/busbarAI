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
    DeployCfg, HookCfg, HookKind, HookStage, PolicyOnError, PromptAccess, ProviderDef, UserAccess,
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
#[allow(dead_code)] // wired by the POST /admin/v1/hooks endpoint (next increment).
pub(crate) fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
    // ── validate the definition (fail-closed, before any mutation) ──
    if name.trim().is_empty() {
        return Err(AdminError::Validation("hook name must not be empty".into()));
    }
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

    // ── build the next snapshot (clone shares live state; only config-derived fields change) ──
    let mut next = current.clone();
    let is_global = cfg.global;
    next.hook_registry.insert(name.to_string(), cfg);
    if is_global && !next.global_hooks.iter().any(|n| n == name) {
        next.global_hooks.push(name.to_string());
    }
    // Re-resolve the FIRED transports from the new registry so a global hook is live after the swap.
    next.rewrite_hooks = crate::routing::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
    );
    next.tap_hooks =
        crate::routing::resolve_tap_hooks(&next.hook_registry, &next.global_hooks, &next.client);
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
            on_error: match cfg.on_error {
                PolicyOnError::Weighted => "weighted",
                PolicyOnError::Reject => "reject",
                PolicyOnError::First => "first",
            },
            timeout_ms: cfg.timeout_ms,
            global: cfg.global || self.app.global_hooks.iter().any(|n| n == name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HookCfg, HookKind, PolicyOnError, PromptAccess, UserAccess};
    use crate::test_support::TestApp;

    fn hook(kind: HookKind, global: bool) -> HookCfg {
        HookCfg {
            kind,
            socket: None,
            webhook: Some("http://127.0.0.1:9971/".to_string()),
            timeout_ms: 5,
            on_error: PolicyOnError::default(),
            prompt: PromptAccess::No,
            user: UserAccess::No,
            priority: 0,
            at: None,
            on_empty: None,
            global,
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
}
