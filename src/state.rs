// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::Arc;

pub(crate) use crate::proto::Protocol;
pub(crate) use crate::store::now;
pub(crate) use crate::store::StateStore;

use reqwest::Client;

// ---------- lane (one per model) ----------
#[derive(Clone)]
pub(crate) struct Lane {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) protocol: Arc<Protocol>,
    pub(crate) max: usize,
    // error_map cloned into each lane at startup for Stage 1b normalization
    pub(crate) error_map: Arc<std::collections::HashMap<String, String>>,
    /// Optional maximum context window size for this lane's model.
    pub(crate) context_max: Option<usize>,
    /// Optional upstream request-path override. When set, used verbatim instead of the protocol's
    /// default path (for providers that embed the API version in base_url and serve /chat/completions).
    pub(crate) path: Option<String>,
    /// Optional auth-style override. `Some("api-key")` sends an `api-key: <key>` header instead of
    /// the protocol's native auth (used by Azure OpenAI). `None` / `Some("bearer")` use the
    /// protocol's `sign_request` (bearer, x-goog-api-key, or SigV4).
    pub(crate) auth: Option<String>,
    /// Optional active health-probe settings (from the provider's `health:` block). `None` or
    /// `mode: none` means no background probing for this lane.
    pub(crate) health: Option<crate::config::HealthCfg>,
    /// Optional default max output tokens, injected at the cross-protocol translation seam when the
    /// source request omitted `max_tokens` (legal for OpenAI) but this lane's protocol REQUIRES it
    /// (Anthropic Messages — see `ProtocolWriter::requires_max_tokens`). Falls back to
    /// `crate::proto::DEFAULT_MAX_TOKENS` when unset.
    pub(crate) default_max_tokens: Option<u32>,
}

/// A pool lane with its associated weight.
#[derive(Clone)]
pub(crate) struct WeightedLane {
    pub(crate) idx: usize,  // index into lanes array
    pub(crate) weight: u32, // member weight from config
}

/// Per-pool runtime config resolved from config.yaml. Keyed by pool name so the re-entrant
/// `forward_with_pool` (which knows its pool name) can look up the right failover/breaker/affinity
/// settings — pools are first-class, but lanes are shared, so this config lives per pool.
#[derive(Clone, Default)]
pub(crate) struct PoolRuntime {
    /// Per-pool failover settings (deadline, cap, and member exclusions).
    pub(crate) failover: Option<crate::config::FailoverCfg>,
    /// Per-pool session-affinity settings (which request header pins a session to a lane).
    pub(crate) affinity: Option<crate::config::AffinityCfg>,
    /// Per-pool breaker settings (trip mode/thresholds + cooldown backoff), resolved into the
    /// runtime `store::BreakerCfg` the FSM evaluates. `None` falls back to ADR-0002 defaults.
    pub(crate) breaker: Option<crate::store::BreakerCfg>,
}

pub(crate) struct App {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) store: Arc<dyn StateStore>,
    pub(crate) by_model: HashMap<String, usize>,
    /// Pools now carry weights alongside lane indices.
    pub(crate) pools: HashMap<String, Vec<WeightedLane>>,
    pub(crate) client: Client,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    /// Default failover config (deadline_s and max_failover cap) when a pool has no override.
    pub(crate) failover_cfg: Option<crate::config::FailoverCfg>,
    /// Per-pool runtime config (failover/exclusions today; breaker/affinity as they're wired).
    pub(crate) pool_runtime: HashMap<String, PoolRuntime>,
    /// Fallback pools mapping (pool name -> WeightedLane vec) for fallback mode.
    pub(crate) fallback_pools: HashMap<String, Vec<WeightedLane>>,
    /// OnExhausted config per pool name.
    pub(crate) on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
    /// governance runtime (virtual keys + budgets/limits store). `None` = disabled.
    pub(crate) governance: Option<std::sync::Arc<crate::governance::GovState>>,
}

impl App {
    /// The configured auth mode — SINGLE SOURCE OF TRUTH. The `AuthMiddleware` owns it (set once at
    /// construction from `auth.mode`, never mutated), and ingress token-gating reads it there; this
    /// accessor lets the EGRESS credential-selection path read the same value without a denormalized
    /// copy on `App` that could (in principle) drift. Cheap: `AuthMode` is `Copy`.
    pub(crate) fn auth_mode(&self) -> crate::auth::AuthMode {
        self.auth.mode
    }
}
