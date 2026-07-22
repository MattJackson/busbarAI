// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    /// The SigV4 signed-`host` header value, derived ONCE at boot from `base_url` (scheme + userinfo
    /// stripped, authority only — see `proxy::host_from_base`). Precomputed so the request path borrows
    /// it into `SigningContext` instead of re-running the parse + `String` allocation on every
    /// forwarded request (it is a pure function of the immutable `base_url`). Only the Bedrock SigV4
    /// writer reads it; other protocols ignore `SigningContext::host`.
    pub(crate) signing_host: String,
    pub(crate) api_key: String,
    pub(crate) protocol: Arc<Protocol>,
    /// Outbound credential — how this lane presents Busbar's identity to the upstream. Resolved once
    /// at boot from (protocol, auth). See `crate::egress_auth`; the request path calls `headers_for`.
    pub(crate) credential: Arc<dyn crate::egress_auth::CredentialProvider>,
    pub(crate) max: usize,
    // error_map cloned into each lane at startup for Stage 1b normalization
    pub(crate) error_map: Arc<std::collections::HashMap<String, String>>,
    /// Optional maximum context window size for this lane's model.
    pub(crate) context_max: Option<usize>,
    /// Optional upstream request-path override. When set, used verbatim instead of the protocol's
    /// default path (for providers that embed the API version in base_url and serve /chat/completions).
    pub(crate) path: Option<String>,
    /// Optional path-BASE override for URL-model protocols (Gemini): replaces the hardcoded base
    /// segment while keeping the per-request `/{model}:verb` suffix (Vertex AI). See `EgressCtx`.
    pub(crate) path_base: Option<String>,
    /// Optional active health-probe settings (from the provider's `health:` block). `None` or
    /// `mode: none` means no background probing for this lane.
    pub(crate) health: Option<crate::config::HealthCfg>,
    /// Model-level per-ATTEMPT time-to-response-headers cap (ms) — the hang detector. A pool
    /// member's `attempt_timeout_ms` overrides it per workload; see `ModelCfg::attempt_timeout_ms`.
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator-declared: this model accepts reasoning/thinking request params (the cross-protocol
    /// reasoning-carry gate). A pool member's `reasoning` overrides it. See `ModelCfg::reasoning`.
    pub(crate) reasoning: bool,
    /// Operator-declared: this model accepts prompt-cache markers on model-gated dialects
    /// (Bedrock `cachePoint`). Gates the cross-protocol cache-breakpoint carry; see
    /// `ModelCfg::prompt_caching`.
    pub(crate) prompt_caching: bool,
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
    /// failover loop: `proxy::decide_policy_order` invokes it per request and `pick_among` walks the
    /// resulting order.
    pub(crate) policy: Option<crate::hooks::ResolvedPolicy>,
    /// This pool's DECISION GATES (`hook:` / the non-strategy names in `hooks: [...]`), resolved once
    /// at config load, each with its `priority`, in config order. Fired in the phase-2 decision
    /// reconcile alongside the global gates (one priority-sorted chain; stable sort keeps
    /// globals-before-pool on ties, then config order). Empty (the default) = no pool gates — the
    /// phase-2 pass is skipped entirely when this and `global_gates` are both empty.
    pub(crate) gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// This pool's REWRITE chain — the `prompt: rw` gates in its `hooks: [...]` list, resolved once
    /// at config load, ascending-priority order. Fired in the phase-1 transform pass AFTER the
    /// global rewrite chain, only for requests routed to this pool. Empty (the default) = no pool
    /// rewrites, zero cost.
    pub(crate) rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
}

/// `Clone` is the config-apply enabler: cloning an `App` shares the live-state `Arc`s (store, auth,
/// governance, client — the things that must SURVIVE a config change) and deep-copies the
/// config-derived collections (lanes, pools, hooks, …). So `apply` builds the next snapshot as
/// `let mut next = (*current).clone(); /* mutate config-derived fields */` and `AppHandle::swap`s it,
/// while in-flight requests keep serving on the old snapshot and the SAME breaker/latency state.
#[derive(Clone)]
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
    pub(crate) rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
    /// GLOBAL request-stage TAP hooks — the `kind: tap` hooks in `global_hooks` observing at the
    /// `request` stage, resolved to their transports. Fired FIRE-AND-FORGET (spawned off the request
    /// path) before dispatch — a tap can never delay or fail the request. Empty (the default) = no
    /// taps, zero cost. Each entry is `(per-hook deadline, send_prompt, transport)`: `send_prompt`
    /// carries the tap's `prompt: ro` grant so a granted tap receives the prompt-content projection and
    /// a `prompt: no` tap receives shape-only. Other stages (route/attempt/completion + synthetic
    /// rejected-completion) are follow-ups.
    pub(crate) tap_hooks: Vec<(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )>,
    /// GLOBAL taps observing at the ROUTE stage (`at: route`) — fired once per request when the
    /// decision reconcile has produced the final candidate set. Same triple shape as `tap_hooks`.
    pub(crate) tap_hooks_route: Vec<(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )>,
    /// GLOBAL taps observing at the ATTEMPT stage (`at: attempt`) — fired per failover attempt with
    /// the attempt number / dispatched target / remaining candidates / previous failure.
    pub(crate) tap_hooks_attempt: Vec<(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )>,
    /// GLOBAL taps observing at the COMPLETION stage (`at: completion`) — fired once per request
    /// with the outcome (`ok`/`failed`/`rejected_by_gate` — the SYNTHETIC completion, so audit taps
    /// see gate denials too) and response status.
    pub(crate) tap_hooks_completion: Vec<(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )>,
    /// GLOBAL DECISION gates — the non-rewrite `kind: gate` hooks in `global_hooks`, resolved to
    /// their full `ResolvedPolicy` (transport + on_error/on_empty/grants), each with its `priority`.
    /// Fired CONCURRENTLY on every request in the phase-2 decision reconcile, merged with the pool's
    /// own gates into one priority-sorted chain (reject wins / restricts intersect / order
    /// last-wins). Empty (the default) = no global gates, zero cost. Pre-sorted ascending by
    /// priority so the merge's stable sort keeps globals-first on ties.
    pub(crate) global_gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// The raw `hooks:` registry (name → definition) as configured, for the Admin API v1 hooks READ
    /// surface (`GET /api/v1/admin/hooks`). This is the DEFINITION set, distinct
    /// from the RESOLVED transports in `rewrite_hooks`/`tap_hooks` (which the request path fires). Empty
    /// when no hooks are configured. Read-only after construction; the config-plane mutation surface
    /// swaps a new `App` snapshot rather than mutating this in place.
    pub(crate) hook_registry: HashMap<String, crate::config::HookCfg>,
    /// The `global_hooks:` list — names fired on every request (plus any hook with inline `global:
    /// true`). Carried for the hooks read surface so a definition can report whether it is globally
    /// wired. Read-only after construction.
    pub(crate) global_hooks: Vec<String>,
    /// Hook names defined in the BASE config file (pre-overlay). `PUT /api/v1/admin/hooks/{name}` on a
    /// base hook is a 409 (edit the file, don't shadow it); API-registered (overlay) hooks replace
    /// freely. Immutable after boot.
    pub(crate) base_hook_names: std::collections::HashSet<String>,
    /// Per-principal ADMIN MUTATION rate limiter (§6.6). Arc-shared across apply snapshots so the
    /// windows survive every swap.
    pub(crate) mutation_limiter: Arc<crate::admin::rate::MutationLimiter>,
    /// Idempotency-Key replay cache for key minting (bounded, ~10min TTL): a retried POST with the
    /// same key returns the FIRST response verbatim instead of double-creating. Arc-shared across
    /// swaps. Maps (principal id, Idempotency-Key) → (created_at, cached 201 body). The key is
    /// SCOPED TO THE PRINCIPAL: a different admin presenting the same Idempotency-Key value must
    /// NOT replay another principal's response (which carries a once-shown secret) — the header is
    /// a client-chosen string, not a cross-principal handle.
    #[allow(clippy::type_complexity)]
    pub(crate) idempotency_cache: Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), (u64, serde_json::Value)>>,
    >,
    /// Config VERSION HISTORY — every successful config-plane mutation records its snapshot here.
    /// Arc-shared across apply snapshots (survives every swap); bounded ring (see
    /// `admin::versions`).
    pub(crate) versions: Arc<crate::admin::versions::VersionLog>,
    /// The ADMIN auth chain (`admin_auth:` module names, default `[admin-tokens]`) — executed by
    /// the auth middleware for `/admin` paths. Empty = the explicit OPEN admin posture (dev).
    pub(crate) admin_chain: Vec<String>,
    /// The credential cache (design-hooks-v2 §2.5) — Arc-shared ACROSS config swaps (like the
    /// mutation limiter): an apply/reload must not silently re-open every cached-allow window.
    pub(crate) credential_cache: Arc<crate::auth_cache::CredentialCache>,
    /// Per-module trust-boundary caps (`auth.modules:`) — consulted by BOTH chains at Identify
    /// time (allowed_groups intersection) and at admin scope resolution (max_admin_scope ceiling).
    pub(crate) auth_modules: std::collections::HashMap<String, crate::config::AuthModuleCfg>,
    /// `group_map:` — principal groups → operator policy (admin scope today). Read by the admin
    /// authorization resolution; unmapped groups grant nothing (fail closed).
    pub(crate) group_map: HashMap<String, crate::config::GroupMapEntry>,
    /// The config.yaml path busbar booted from — `POST /api/v1/admin/config/reload` re-runs the boot
    /// disk-load pipeline against it. `None` (tests / ephemeral) ⇒ reload is `invalid_request`.
    pub(crate) config_path: Option<std::path::PathBuf>,
    /// The providers.yaml path (same role as `config_path`).
    pub(crate) providers_path: Option<std::path::PathBuf>,
    /// The config-overlay path (`BUSBAR_CONFIG_OVERLAY`), if persistence is enabled. `Some` = an
    /// API-applied hook change is written here so it survives a restart (re-merged onto base config at
    /// boot); `None` (the default) = runtime changes are live but not persisted. Carried on `App` (not
    /// a global) so it is testable + survives config swaps (`App::clone` copies it).
    pub(crate) overlay_path: Option<std::path::PathBuf>,
    /// Monotonic config version — `0` at boot, incremented by each API config apply (the swap builds
    /// the next snapshot with `config_version + 1`). Exposed on `GET /api/v1/admin/info` so drift-detection
    /// tooling can tell whether the running config changed since a prior read. Process-local (resets on
    /// restart); durable version history + rollback is a follow-up.
    pub(crate) config_version: u64,
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
    /// The resolved COST MODEL (rate card + budget groups + flat fee), rebuilt with the config on
    /// every apply/reload while `governance` (the token ledger) survives the swap - which is what
    /// makes a rate-card correction reprice every past and future derived figure on the next read.
    pub(crate) cost: std::sync::Arc<crate::cost::CostModel>,
    /// The directory the signed plugin tarballs live in (`plugins.dir`, default `plugins`). Carried
    /// on the snapshot so the Admin API plugin catalog (`GET /api/v1/admin/plugins?type=store`) and
    /// the install/remove/reload endpoints operate on the SAME directory the boot store-load
    /// resolves against — one source of truth, and it survives config swaps (`App::clone` copies it).
    pub(crate) plugins_dir: std::path::PathBuf,
    /// The whole `plugins.*` block (master switch + trust + floors) — re-used at admin-install to
    /// RE-VERIFY an uploaded plugin server-side (the client is never trusted) and to project each
    /// catalog entry's trust verdict. Carried on the snapshot (not a global) so it is testable and
    /// survives swaps.
    pub(crate) plugins_cfg: crate::config::PluginsCfg,
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

/// A swappable handle to the current `App` snapshot — the seam that lets an admin config `apply`
/// replace the running configuration atomically WITHOUT restarting or blocking in-flight requests.
///
/// The router's state is `Arc<AppHandle>`. Every handler and the auth middleware call `load()` to get
/// the CURRENT snapshot at that instant (an owned `Arc<App>`, no lock held across any `.await`).
/// In-flight requests keep the snapshot they already loaded (the old `Arc<App>` stays alive until its
/// last reference drops); new requests see the new one. `swap()` replaces the pointer under a brief
/// write lock — the only writer is the admin apply path, so the read side is effectively uncontended
/// (a `RwLock` read + `Arc` clone, ~tens of nanoseconds). Behaviorally identical to a fixed
/// `Arc<App>` until something calls `swap()`.
pub(crate) struct AppHandle {
    current: std::sync::RwLock<Arc<App>>,
}

impl AppHandle {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self {
            current: std::sync::RwLock::new(app),
        }
    }

    /// The current `App` snapshot. Clones the `Arc` (cheap) and releases the read lock immediately.
    /// A poisoned lock (a panic in a prior holder) still guards a valid `Arc<App>` — recover it rather
    /// than propagate, since the guarded value is a single pointer with no inconsistent state to fear.
    pub(crate) fn load(&self) -> Arc<App> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Atomically replace the current snapshot (the admin config-mutation seam: reload, apply, and every
    /// hook/auth mutation). Re-spawns the health probers against `next`: probers hold a `Weak<App>` and
    /// exit once the App they were spawned against drops (audit H2), so EVERY swap must re-attach them —
    /// otherwise the first admin mutation replaces the boot App, the boot App drops as in-flight requests
    /// drain, its probers exit, and active/dead health probing silently STOPS even though lanes/health are
    /// unchanged (audit 1.4.0: only reload/apply re-spawned; the six hook/auth-mutation swaps did not).
    /// Doing it in `swap` itself makes it impossible for a future swap site to forget.
    pub(crate) fn swap(&self, next: Arc<App>) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = next.clone();
        crate::health::spawn_probers(&next);
    }
}

/// An axum extractor that yields the CURRENT `App` snapshot from the router's `Arc<AppHandle>` state.
/// This is what lets every handler keep working with an `Arc<App>` while transparently reading the
/// post-apply configuration: a handler takes `CurrentApp(app): CurrentApp` instead of
/// `State(app): State<Arc<App>>`, and the rest of its body is unchanged (`app` is still `Arc<App>`).
/// A local newtype is required because the orphan rule forbids `impl FromRef<_> for Arc<App>`.
pub(crate) struct CurrentApp(pub(crate) Arc<App>);

impl<S> axum::extract::FromRequestParts<S> for CurrentApp
where
    Arc<AppHandle>: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // `State` extraction of the handle is Infallible (the handle is always present in state).
        let axum::extract::State(handle) =
            axum::extract::State::<Arc<AppHandle>>::from_request_parts(parts, state).await?;
        Ok(CurrentApp(handle.load()))
    }
}
