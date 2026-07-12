// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

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
    AdminError, BuildInfo, HookTransportView, HookView, InfoView, ModelView, Page, PoolMemberView,
    PoolView, ProviderView, TopologyInfo,
};
use crate::config::{HookCfg, HookKind, HookStage, PolicyOnError, PromptAccess, UserAccess};

/// Process start instant, for the `info` uptime read. Stamped ONCE at startup by `mark_start()`.
/// A missing value (never stamped — e.g. a unit test that skips `main`) yields a `None` uptime
/// rather than a panic.
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Stamp the process start instant for the `info` uptime read. Idempotent (first `set` wins), so it
/// is safe to call unconditionally at startup.
pub(crate) fn mark_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
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
        // The compiled-in plugin catalog, by type. Feature-gated at COMPILE time (real `#[cfg]` on
        // each array element), so this reflects the ACTUAL binary — the weighted SWRR floor is always
        // present; `tokens`/`ranking` vanish under `--no-default-features`, giving a provably smaller
        // surface. `default auth = tokens` + `default hook = weighted` are the two OEM-default plugins;
        // weighted is the one baked in (non-removable), so it appears as `weighted_floor` below, not here.
        let auth_modules: Vec<&'static str> = [
            #[cfg(feature = "auth-tokens")]
            "tokens",
        ]
        .to_vec();
        let hook_plugins: Vec<&'static str> = [
            #[cfg(feature = "hooks-ranking")]
            "ranking",
        ]
        .to_vec();

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

    /// `GET /admin/v1/pools` — the pool topology (name + member models/weights) for the fleet
    /// dashboard. Read scope. Sorted by name for a stable, diff-friendly listing. Live per-member
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

    /// `GET /admin/v1/hooks` — the hook registry (the CP plugin-store view). Read scope. Each entry
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
