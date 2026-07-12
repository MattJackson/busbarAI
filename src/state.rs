// SPDX-License-Identifier: Apache-2.0
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
    /// Optional auth-style override. `Some(ProviderAuth::ApiKey)` sends an `api-key: <key>` header
    /// instead of the protocol's native auth (used by Azure OpenAI). `None` / `Some(Bearer)` use the
    /// protocol's `sign_request` (bearer, x-goog-api-key, or SigV4).
    pub(crate) auth: Option<crate::config::ProviderAuth>,
    /// Optional active health-probe settings (from the provider's `health:` block). `None` or
    /// `mode: none` means no background probing for this lane.
    pub(crate) health: Option<crate::config::HealthCfg>,
    /// Model-level per-ATTEMPT time-to-response-headers cap (ms) — the hang detector. A pool
    /// member's `attempt_timeout_ms` overrides it per workload; see `ModelCfg::attempt_timeout_ms`.
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator-declared: this model accepts reasoning/thinking request params (the cross-protocol
    /// reasoning-carry gate). A pool member's `reasoning` overrides it. See `ModelCfg::reasoning`.
    pub(crate) reasoning: bool,
    /// Optional default max output tokens, injected at the cross-protocol translation seam when the
    /// source request omitted `max_tokens` (legal for OpenAI) but this lane's protocol REQUIRES it
    /// (Anthropic Messages — see `ProtocolWriter::requires_max_tokens`). Falls back to
    /// `crate::proto::DEFAULT_MAX_TOKENS` when unset.
    pub(crate) default_max_tokens: Option<u32>,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of `self.model` (the config key).
    /// Useful when the provider expects a different model string (e.g. Bedrock model IDs).
    pub(crate) upstream_model: Option<String>,
}

impl Lane {
    /// The model name to send on the wire. Returns `upstream_model` when set,
    /// otherwise falls back to the config key (`self.model`).
    pub(crate) fn wire_model(&self) -> &str {
        self.upstream_model.as_deref().unwrap_or(&self.model)
    }
}

/// A pool lane with its associated weight.
#[derive(Clone)]
pub(crate) struct WeightedLane {
    pub(crate) idx: usize,  // index into lanes array
    pub(crate) weight: u32, // member weight from config
    /// Pool-member override of the lane's `reasoning` capability flag (member wins). `None` =
    /// inherit the model-level flag. See `ModelCfg::reasoning`.
    pub(crate) reasoning: Option<bool>,
    /// Pool-member override of the lane's `attempt_timeout_ms` (one model, different budgets per
    /// workload/pool). `None` = inherit the model-level value.
    pub(crate) attempt_timeout_ms: Option<u64>,
}

/// Operator-declared per-member routing metadata (config), projected into the routing `Candidate`
/// at the seam. Lives on `PoolRuntime` keyed by lane idx (NOT on the shared `Lane`, since the same
/// lane can be a member of several pools with different tier/cost/tags). Building this ONLY for pools
/// that declare a non-default `route:` is NOT required — it is cheap to populate for every pool, but it is
/// READ only inside the policy arm of the seam, so the zero-cost default path never touches it.
#[derive(Clone, Default)]
pub(crate) struct MemberMeta {
    pub(crate) tier: Option<String>,
    pub(crate) cost_per_mtok: Option<f64>,
    pub(crate) tags: Vec<String>,
}

/// Per-pool runtime config resolved from config.yaml. Keyed by pool name so the re-entrant
/// `forward_with_pool` (which knows its pool name) can look up the right failover/breaker/affinity
/// settings — pools are first-class, but lanes are shared, so this config lives per pool.
#[derive(Clone, Default)]
pub(crate) struct PoolRuntime {
    /// Operator-declared member metadata (tier / cost / tags) keyed by lane idx, for the routing
    /// `Candidate` projection. Read ONLY inside the policy arm of the seam; the default SWRR path
    /// never touches it. Empty for a pool with no members declaring metadata.
    pub(crate) members: std::collections::HashMap<usize, MemberMeta>,
    /// Per-pool failover settings (deadline, cap, and member exclusions).
    pub(crate) failover: Option<crate::config::FailoverCfg>,
    /// Per-pool session-affinity settings (which request header pins a session to a lane).
    pub(crate) affinity: Option<crate::config::AffinityCfg>,
    /// Per-pool breaker settings (trip mode/thresholds + cooldown backoff), resolved into the
    /// runtime `store::BreakerCfg` the FSM evaluates. `None` falls back to ADR-0002 defaults.
    pub(crate) breaker: Option<crate::store::BreakerCfg>,
    /// Per-pool routing policy, resolved ONCE at config load. `None` is the ZERO-COST default
    /// (`route: weighted` / absent / explicit-native-weighted): no policy object, no projection, the
    /// unchanged inline SWRR hot path. `Some(_)` is a non-default policy whose ranked order feeds the
    /// failover loop: `forward::decide_policy_order` invokes it per request and `pick_among` walks the
    /// resulting order.
    pub(crate) policy: Option<crate::routing::ResolvedPolicy>,
}

pub(crate) struct App {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) store: Arc<dyn StateStore>,
    pub(crate) by_model: HashMap<String, usize>,
    /// Pool members, each carrying a lane index and its configured weight.
    pub(crate) pools: HashMap<String, Vec<WeightedLane>>,
    pub(crate) client: Client,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    /// GLOBAL rewrite hooks — the `prompt: rw` gates named in `global_hooks`, resolved to their
    /// transports and sorted by ascending `priority` (the transform-chain order). Fired before
    /// dispatch to mutate the request body (compression/redaction). Empty (the default) = no rewrite
    /// pass, zero cost. Only `rw` gates land here — the grant is enforced at RESOLUTION, so a
    /// `ro`/`no` hook can never rewrite (the bidirectional grant holds by construction). Each entry is
    /// `(per-hook transform deadline, transport)`.
    pub(crate) rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::routing::RoutingPolicy>)>,
    /// GLOBAL request-stage TAP hooks — the `kind: tap` hooks in `global_hooks` observing at the
    /// `request` stage, resolved to their transports. Fired FIRE-AND-FORGET (spawned off the request
    /// path) before dispatch — a tap can never delay or fail the request. Empty (the default) = no
    /// taps, zero cost. Each entry is `(per-hook deadline, transport)`. Other stages
    /// (route/attempt/completion + synthetic rejected-completion) are follow-ups.
    pub(crate) tap_hooks: Vec<(std::time::Duration, Arc<dyn crate::routing::RoutingPolicy>)>,
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
    /// Global fallback for the translation-injected `max_tokens` (`limits.default_max_tokens`), used
    /// at the cross-protocol seam when a lane has no per-lane `default_max_tokens`. Defaults to
    /// `proto::DEFAULT_MAX_TOKENS` (4096). Read by `IrReq::prepare_for_egress` at the cross-protocol seam.
    pub(crate) default_max_tokens: u32,
    /// Resolved effort-word → thinking-budget table for the cross-protocol reasoning carry
    /// (`limits.reasoning_effort_budgets`, defaults 1024/4096/8192/16384), ordered
    /// [minimal, low, medium, high]. Stamped onto the IR at the egress seam so writers project
    /// effort words and numeric budgets with the operator's numbers.
    pub(crate) reasoning_effort_budgets: [u32; 4],
}

impl App {
    /// The UPSTREAM-credential mode — whether the egress path signs with busbar's configured lane key
    /// (`Own`) or forwards the caller's credential (`Passthrough`). Read off the `AuthMiddleware`
    /// (set once at construction from `upstream_credentials:`, never mutated). Cheap: `Copy`.
    pub(crate) fn upstream_creds(&self) -> crate::auth::UpstreamCreds {
        self.auth.upstream_creds
    }
}
