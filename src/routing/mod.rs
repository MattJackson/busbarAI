// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Pluggable routing policies.
//!
//! A pool may declare a routing **policy** that, given a cheap projection of the request, returns an
//! ordered **preference** of members — not a single pick. The ordered list feeds the failover loop
//! Busbar already has (`forward::pick_among`): if the policy's #1 is tripped / excluded / at
//! capacity, Busbar walks to #2 using the existing breaker machinery. One transport-agnostic trait
//! (`RoutingPolicy`); webhook / socket / script / native are implementations.
//!
//! ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool resolves to `ResolvedPolicy::None`
//! at config load and NEVER constructs any of the projection types or enters this module's async
//! path. The hot path stays today's inline SWRR.
//!
//! This surface is PRODUCTION-WIRED: `forward::decide_policy_order` builds the `RoutingRequest` +
//! `Candidate` projections from the live store signals and invokes the resolved policy on every
//! non-default request; `forward::pick_among` walks the ranked order through the existing failover
//! loop. `resolve_policy` (below) constructs the native / webhook / socket / script transports once
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

pub(crate) mod native;
#[cfg(feature = "script-policy")]
pub(crate) mod script;
pub(crate) mod socket;
pub(crate) mod webhook;
pub(crate) mod wire;

/// A read-only, cheaply-constructed projection of the request for routing decisions. Built ONCE per
/// request from the pristine ingress `serde_json::Value` BEFORE the failover loop, and ONLY for
/// non-default pools. Borrows where possible; owns only small derived scalars. A policy never
/// touches the mutable IR or `App`.
#[derive(Debug, Clone)]
pub(crate) struct RoutingRequest<'a> {
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    /// The model the caller asked for (may be a pool name or a member model), if any. Projected to
    /// the SCRIPT policy only — the shared webhook/socket wire (`wire::HookReqProjection`)
    /// deliberately omits it. The script projection is the only reader in the default build, so it
    /// is gated on `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) requested_model: Option<&'a str>,
    pub(crate) message_count: usize,
    /// Number of tool definitions on the request. Projected to the script policy (the only reader),
    /// so it is gated on `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) tool_count: usize,
    pub(crate) has_tools: bool,
    /// Sum of all text-block chars across system + messages. A v1 SIZE signal (NOT a token count).
    pub(crate) total_chars: usize,
    /// System-prompt text chars only. Projected to the script policy (the only reader), so it is
    /// gated on `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) system_chars: usize,
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// The request's prompt content — `Some` ONLY when the pool opted in via `policy.send_prompt`
    /// (default off). The default projection is shape-only; this is the operator-gated exception
    /// that lets a trusted hook screen content (PII, guardrails, audit). Owned: flattening the
    /// ingress body allocates, and that cost is paid only behind the opt-in.
    pub(crate) prompt: Option<PromptProjection>,
    /// Caller identity — `Some` ONLY when the pool opted in via `policy.send_user` (default off).
    /// Carries the governance virtual-key `id`/`name` and the body's end-user field. NEVER the
    /// caller's secret/token, regardless of configuration.
    pub(crate) identity: Option<CallerIdentity>,
}

/// The opt-in prompt content projection (`policy.send_prompt: true`). Text only: string content and
/// `{type:"text"}` blocks are flattened; non-text blocks (images, tool results) are skipped, so the
/// payload carries words, not binary blobs.
#[derive(Debug, Clone)]
pub(crate) struct PromptProjection {
    /// The system prompt's text, flattened (bare string, or text blocks concatenated).
    pub(crate) system: Option<String>,
    /// Every message as `(role, flattened text)`, in request order.
    pub(crate) messages: Vec<(String, String)>,
}

/// The opt-in caller identity projection (`policy.send_user: true`). By construction this can never
/// carry a secret: the governance lookup resolves the token to its key record and only the record's
/// `id`/`name` are projected.
#[derive(Debug, Clone)]
pub(crate) struct CallerIdentity {
    /// Governance virtual-key id (stable handle), if the caller authenticated with a virtual key.
    pub(crate) key_id: Option<String>,
    /// Governance virtual-key display name.
    pub(crate) key_name: Option<String>,
    /// The request body's end-user identifier (`user` in OpenAI dialect, `metadata.user_id` in
    /// Anthropic dialect), if the caller supplied one.
    pub(crate) user: Option<String>,
}

/// One routable member, with the metadata + live signals a policy ranks on. Projected from
/// `app.lanes[idx]` + the pool member config + the store. `idx` is the stable handle the failover
/// loop already speaks.
#[derive(Debug, Clone)]
pub(crate) struct Candidate<'a> {
    /// Index into `app.lanes` — the failover loop's lingua franca.
    pub(crate) idx: usize,
    pub(crate) model: &'a str,
    /// Upstream provider name. Projected to the script policy (its only reader), so it is gated on
    /// `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) provider: &'a str,
    /// The existing SWRR weight (so a policy can fall back to it). Projected to the script policy (its
    /// only reader), so it is gated on `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) weight: u32,
    /// Member context-window ceiling. Projected to the script policy (its only reader), so it is
    /// gated on `script-policy`.
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) context_max: Option<usize>,
    // ── operator-declared member metadata (config) ───────────────────────────────────────────────
    pub(crate) tier: Option<&'a str>,
    pub(crate) cost_per_mtok: Option<f64>,
    /// Free-form operator tags. Projected to the hook wire (`wire::HookCandidate.tags`, omitted
    /// when empty) and to the script policy.
    pub(crate) tags: &'a [String],
    // ── live signals (read per-request from the store at the seam) ───────────────────────────────
    /// Rolling EWMA of recent end-to-end latency for this lane, in milliseconds. `None` until the
    /// lane has served at least one request.
    pub(crate) latency_ms: Option<f64>,
    /// Currently-available concurrency permits on this lane's semaphore (free slots). A `least_busy`
    /// policy prefers the lane with the most headroom.
    pub(crate) available_concurrency: usize,
    /// Per-lane lifetime request budget remaining (`None` = unlimited). The `usage` policy prefers
    /// the lane with the most budget left; cheap (read from the store).
    pub(crate) budget_remaining: Option<i64>,
    /// Rate-limit HEADROOM as a fraction in `[0.0, 1.0]`: how much of the request's governance
    /// rate budget (the tighter of the caller key's RPM / TPM limit) is still available this window —
    /// `1.0` is fully-unused, `0.0` is at the cap. `None` when no rate limit applies (governance
    /// disabled, or the key has neither RPM nor TPM set). Populated at the seam from
    /// `governance::GovState::rate_headroom`. The `usage` policy prefers the candidate with the MOST
    /// headroom (furthest from a provider 429). Rate limits are per-KEY in Busbar today, so this value
    /// is currently the same across a request's candidates — `usage` then ranks deterministically by
    /// `idx` — but the field is per-candidate so a future per-lane rate signal drops in without a
    /// contract change.
    pub(crate) rate_headroom: Option<f64>,
}

/// Read-only context a policy may consult beyond the request + candidates themselves.
#[derive(Debug, Clone)]
pub(crate) struct RoutingContext<'a> {
    pub(crate) pool: &'a str,
    /// Per-KEY governance budget remaining for this request, when known/plumbed. `None` when
    /// governance is disabled or per-key budget is not visible at the seam (v1 default).
    pub(crate) budget_remaining: Option<i64>,
}

/// A boxed, thread-safe policy error. Kept dependency-free (no `anyhow`/`thiserror`) so the routing
/// contract adds no new crate. A transport surfaces transient failures (a webhook 500, a script
/// panic, a marshaling error) as this; the caller coerces any `Err` to the pool's `on_error` fallback,
/// so an error NEVER propagates to the client — it degrades to weighted/reject/first.
pub(crate) type PolicyError = Box<dyn std::error::Error + Send + Sync>;

/// The result of a policy decision. `Ok(Abstain)` is the clean "no opinion" path; `Err` is coerced
/// to `on_error` by the caller (never surfaced to the client).
pub(crate) type PolicyResult = Result<RoutingDecision, PolicyError>;

/// The decision: an ordered preference, or an explicit abstention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoutingDecision {
    /// Ranked preference, most-preferred first. Entries are candidate `idx` values. The list MAY be
    /// a subset (a policy can drop a candidate); any omitted candidate is treated as LOWEST priority,
    /// NOT excluded — the failover loop can still reach it after the ranked ones are exhausted, so a
    /// broken policy never strands a healthy lane. Duplicates and unknown idxs are ignored.
    Prefer(Vec<usize>),
    /// "No preference" — fall back to the pool's default (weighted/SWRR). Identical to the policy not
    /// being configured. A timeout / error / malformed response is coerced to this (per `on_error`).
    Abstain,
    /// REJECT the request: no upstream is dispatched and the caller receives a dialect-native error.
    /// The verb that makes content-seeing hooks (`policy.send_prompt`) useful — a PII screen or
    /// guardrail can stop a request before it leaves the network. `status` is already clamped to
    /// 4xx and `message` sanitized by `wire::normalize` (the only producer): a hook can never mint a
    /// 5xx, a success, or a header-injecting message through this path.
    Reject { status: u16, message: String },
}

/// THE transport-agnostic contract. webhook / socket / script / native all implement this.
#[async_trait::async_trait]
pub(crate) trait RoutingPolicy: Send + Sync + 'static {
    /// Rank candidates for this request. MUST be cancel-safe and SHOULD respect `budget` (a
    /// wall-clock deadline; the caller also wraps the call in a hard `timeout`). Returning `Err` or
    /// exceeding the deadline is handled by the caller per `on_error`; an impl SHOULD prefer
    /// `Ok(Abstain)` over erroring when it simply has no opinion.
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: std::time::Duration,
    ) -> PolicyResult;

    /// Stable transport/policy name for metrics + the `x-busbar-route` header
    /// (e.g. `"webhook"`, `"script"`, `"weighted"`, `"cheapest"`).
    fn name(&self) -> &'static str;
}

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub(crate) enum ResolvedPolicy {
    /// A constructed policy object (webhook / script / native non-weighted) plus its fallback config.
    /// The default SWRR / weighted path is represented as `None` by `resolve_policy` (it constructs no
    /// policy object), so there is no `Weighted` variant — a weighted pool simply has no resolved
    /// policy and takes the inline SWRR branch.
    Policy {
        policy: Arc<dyn RoutingPolicy>,
        on_error: crate::config::PolicyOnError,
        timeout: std::time::Duration,
        /// `policy.send_prompt` — build + send the prompt content projection (default false).
        send_prompt: bool,
        /// `policy.send_user` — build + send the caller identity projection (default false).
        send_user: bool,
    },
}

/// Resolve a pool's routing config into a runtime policy ONCE at config load. Returns `None` for the
/// ZERO-COST default path: `route: weighted` (the default / absent case) AND the explicit
/// `route: native, policy.name: weighted` form both resolve to `None`, because `weighted` Abstains
/// and thus converges with today's inline SWRR — so the hot path constructs no policy object, builds
/// no projections, and takes the unchanged `select_weighted_in` branch.
///
/// Every non-default transport is resolved here: a non-weighted native is looked up in the registry,
/// a webhook is constructed over its validated URL + the shared client, and a script is compiled once.
/// A missing / invalid / unknown transport degrades to `None` (the default SWRR) so routing never
/// strands a request — startup validation is what surfaces the misconfiguration. The resolved policy
/// is stored on `PoolRuntime::policy` and consumed per-request by `forward::decide_policy_order`.
pub(crate) fn resolve_policy(
    cfg: &crate::config::PoolCfg,
    client: &reqwest::Client,
) -> Option<ResolvedPolicy> {
    use crate::config::RouteKind;
    match cfg.route {
        // Default / absent: today's inline SWRR. No policy object — the zero-cost fast path.
        RouteKind::Weighted => None,
        // The native form (`route: native` + `policy.name`, OR a native shorthand desugared to the
        // same shape by `PoolCfg`'s deserializer). Look the name up in the native registry and wrap
        // it as a `Policy`. The `weighted` native resolves to `None` (the zero-cost default): it would
        // only ever `Abstain`, so constructing a policy object + projection for it is pure waste —
        // collapsing it to `None` keeps `route: native, policy.name: weighted` byte-identical to the
        // default SWRR hot path. A missing `policy`/`name`, or an unknown name, falls back to `None`
        // (default SWRR) — startup validation surfaces the misconfiguration; routing never strands.
        RouteKind::Native => {
            let policy_cfg = cfg.policy.as_ref()?;
            let name = policy_cfg.name.as_deref()?;
            // `weighted` ⇒ the zero-cost default path (no policy object, inline SWRR).
            if name == native::POLICY_NAME_WEIGHTED {
                return None;
            }
            let policy = native::native_policy(name)?;
            Some(ResolvedPolicy::Policy {
                policy,
                on_error: policy_cfg.on_error.clone(),
                timeout: policy_timeout(policy_cfg.timeout_ms),
                send_prompt: policy_cfg.send_prompt,
                send_user: policy_cfg.send_user,
            })
        }
        // The operator-sidecar HTTP transport. The URL is validated at config load
        // (`observability::validate_routing_webhook_url`, the OTLP loopback carve-out); here we
        // construct the `WebhookPolicy` over that URL and a clone of the SHARED upstream client. A
        // missing/invalid URL falls back to `None` (the default SWRR path) — startup validation is
        // what surfaces the misconfiguration; routing must never strand a request.
        RouteKind::Webhook => {
            let policy_cfg = cfg.policy.as_ref()?;
            let url = policy_cfg.url.as_deref()?;
            let url = crate::observability::validate_routing_webhook_url(Some(url)).ok()?;
            Some(ResolvedPolicy::Policy {
                policy: Arc::new(webhook::WebhookPolicy::new(url, client.clone())),
                on_error: policy_cfg.on_error.clone(),
                timeout: policy_timeout(policy_cfg.timeout_ms),
                send_prompt: policy_cfg.send_prompt,
                send_user: policy_cfg.send_user,
            })
        }
        // SCRIPT (Rhai) transport. Behind the `script-policy` feature so the default build pulls no
        // Rhai. The script is compiled ONCE here at config load; a compile error degrades to the
        // default SWRR (`None`) with a loud warning — never strands a request. When the feature is
        // absent, `route: script` likewise degrades to default with a clear "feature not enabled"
        // warning, so a misconfigured pool is loud, not silent. DEPRECATED in favor of the socket
        // hook (`resolve_script` warns).
        RouteKind::Script => resolve_script(cfg),
        // The Unix-socket BINARY hook: an operator-run compiled hook on a local Unix domain socket,
        // same wire contract as the webhook, microseconds instead of a network hop. Unix-only; the
        // non-unix arm degrades loudly to the default (use `route: webhook` there). A missing socket
        // path falls back to `None` — startup validation surfaces the misconfiguration.
        RouteKind::Socket => resolve_socket(cfg),
    }
}

/// Resolve a `route: socket` pool: wrap the configured socket path as a [`socket::SocketPolicy`].
/// The connection is LAZY (the hook binary may start after busbar), so only the path's presence is
/// checked here; `config_validate` enforces it loudly at startup.
#[cfg(unix)]
fn resolve_socket(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    let policy_cfg = cfg.policy.as_ref()?;
    let path = policy_cfg.socket.as_deref()?;
    if path.is_empty() {
        return None;
    }
    Some(ResolvedPolicy::Policy {
        policy: Arc::new(socket::SocketPolicy::new(path.to_string())),
        on_error: policy_cfg.on_error.clone(),
        timeout: policy_timeout(policy_cfg.timeout_ms),
        send_prompt: policy_cfg.send_prompt,
        send_user: policy_cfg.send_user,
    })
}

/// Non-unix fallback: `tokio::net::UnixStream` is unix-only, so `route: socket` degrades to the
/// default SWRR with a loud pointer at the webhook transport. The request is never stranded.
#[cfg(not(unix))]
fn resolve_socket(_cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    tracing::warn!(
        "route: socket (the Unix-socket hook) is not available on this platform; falling back to \
         weighted. Use `route: webhook` for an out-of-process routing hook here."
    );
    None
}

/// Resolve a `route: script` pool. Feature-gated body: with `script-policy` it compiles the operator
/// script once and wraps it as a `Policy`; without the feature it warns and falls to the default.
#[cfg(feature = "script-policy")]
fn resolve_script(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    tracing::warn!(
        "route: script (Rhai) is DEPRECATED and will be removed in a future release: the \
         interpreter adds ~100us per decision where the socket hook (`route: socket`, a compiled \
         binary on a Unix socket, same wire contract) answers in single-digit microseconds. \
         Migrate to `route: socket` or `route: webhook`."
    );
    let policy_cfg = cfg.policy.as_ref();
    let source = match policy_cfg.map_or(Ok(None), script_source) {
        Ok(Some(src)) => src,
        Ok(None) => {
            tracing::warn!(
                "route: script pool has no `script`/`script_file`; falling back to weighted"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!("route: script source error: {e}; falling back to weighted");
            return None;
        }
    };
    match script::ScriptPolicy::compile(&source) {
        Ok(policy) => Some(ResolvedPolicy::Policy {
            policy: std::sync::Arc::new(policy),
            on_error: policy_cfg.map(|p| p.on_error.clone()).unwrap_or_default(),
            timeout: policy_timeout(
                policy_cfg
                    .map(|p| p.timeout_ms)
                    .unwrap_or(crate::limits::default_policy_timeout_ms()),
            ),
            // The deprecated script transport never receives the opt-in projections (its Rhai env
            // predates them and is frozen); the flags are still honored at the seam if set, the
            // script just has no bindings to read them.
            send_prompt: policy_cfg.map(|p| p.send_prompt).unwrap_or(false),
            send_user: policy_cfg.map(|p| p.send_user).unwrap_or(false),
        }),
        Err(e) => {
            tracing::warn!("route: script failed to compile: {e}; falling back to weighted");
            None
        }
    }
}

/// Read the inline `script` or `script_file` source for a `route: script` pool. Exactly one is
/// expected; `script_file` is read from disk at config load. `Ok(None)` = neither was set.
#[cfg(feature = "script-policy")]
fn script_source(p: &crate::config::PolicyCfg) -> Result<Option<String>, PolicyError> {
    if let Some(src) = &p.script {
        return Ok(Some(src.clone()));
    }
    if let Some(path) = &p.script_file {
        let src = std::fs::read_to_string(path)
            .map_err(|e| -> PolicyError { format!("reading script_file {path}: {e}").into() })?;
        return Ok(Some(src));
    }
    Ok(None)
}

/// Feature-OFF fallback: a `route: script` pool without the `script-policy` feature can't construct a
/// Rhai policy, so it degrades to the default SWRR with a clear "feature not enabled" warning. The
/// request is never stranded; the operator sees that the build lacks the feature they configured.
#[cfg(not(feature = "script-policy"))]
fn resolve_script(_cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    tracing::warn!(
        "route: script configured but this binary was built WITHOUT the `script-policy` feature; \
         falling back to weighted. Rebuild with `--features script-policy` to enable Rhai routing."
    );
    None
}

impl RoutingDecision {
    /// Normalize a raw ranked list into a clean `Prefer`/`Abstain`: drop unknown idxs (not in
    /// `valid`), dedup while preserving first-seen order, and coerce an empty result to `Abstain`.
    /// Shared by every transport so the same liberal-in-what-you-accept rules hold everywhere.
    pub(crate) fn from_ranked(
        raw: impl IntoIterator<Item = usize>,
        valid: &std::collections::HashSet<usize>,
    ) -> RoutingDecision {
        let mut seen = std::collections::HashSet::new();
        let mut order = Vec::new();
        for idx in raw {
            if valid.contains(&idx) && seen.insert(idx) {
                order.push(idx);
            }
        }
        if order.is_empty() {
            RoutingDecision::Abstain
        } else {
            RoutingDecision::Prefer(order)
        }
    }
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
    fn pool_cfg(
        route: crate::config::RouteKind,
        policy: Option<crate::config::PolicyCfg>,
    ) -> crate::config::PoolCfg {
        crate::config::PoolCfg {
            members: vec![],
            breaker: None,
            failover: None,
            on_exhausted: None,
            affinity: None,
            route,
            policy,
        }
    }

    /// `route: native` + a non-weighted `policy.name` must resolve to a constructed `Policy`.
    /// The resolved policy's name must round-trip the native registry name.
    #[test]
    fn native_arm_resolves_constructed_policy() {
        use crate::config::{PolicyCfg, RouteKind};
        let client = reqwest::Client::new();
        for name in ["cheapest", "fastest", "least_busy", "usage"] {
            let cfg = pool_cfg(
                RouteKind::Native,
                Some(PolicyCfg {
                    name: Some(name.to_string()),
                    ..Default::default()
                }),
            );
            match resolve_policy(&cfg, &client) {
                Some(ResolvedPolicy::Policy { policy, .. }) => {
                    assert_eq!(policy.name(), name, "resolved native policy name must round-trip");
                }
                other => panic!("route: native, policy.name: {name} must resolve to a Policy, got a non-Policy resolution: {}", other.is_none()),
            }
        }
    }

    /// `route: native, policy.name: weighted` collapses to the zero-cost default (`None`): the
    /// weighted native only ever Abstains, so building a policy object for it is pure waste.
    #[test]
    fn native_weighted_resolves_none_zero_cost() {
        use crate::config::{PolicyCfg, RouteKind};
        let client = reqwest::Client::new();
        let cfg = pool_cfg(
            RouteKind::Native,
            Some(PolicyCfg {
                name: Some("weighted".to_string()),
                ..Default::default()
            }),
        );
        assert!(
            resolve_policy(&cfg, &client).is_none(),
            "the weighted native must collapse to the zero-cost default path"
        );
    }

    /// A `route: native` with a missing `policy`/`name`, or an unknown name, falls back to `None`
    /// (default SWRR) — routing must never strand a request; startup validation surfaces the misconfig.
    #[test]
    fn native_missing_or_unknown_name_falls_back_to_none() {
        use crate::config::{PolicyCfg, RouteKind};
        let client = reqwest::Client::new();
        // No policy at all.
        assert!(resolve_policy(&pool_cfg(RouteKind::Native, None), &client).is_none());
        // Policy present but no name.
        assert!(resolve_policy(
            &pool_cfg(RouteKind::Native, Some(PolicyCfg::default())),
            &client
        )
        .is_none());
        // Unknown name.
        assert!(resolve_policy(
            &pool_cfg(
                RouteKind::Native,
                Some(PolicyCfg {
                    name: Some("nonexistent".to_string()),
                    ..Default::default()
                }),
            ),
            &client
        )
        .is_none());
    }

    /// `route: socket` + a `policy.socket` path resolves to a constructed socket policy (unix);
    /// a missing/empty path falls back to `None` (startup validation surfaces the misconfig).
    #[cfg(unix)]
    #[test]
    fn socket_arm_resolves_constructed_policy() {
        use crate::config::{PolicyCfg, RouteKind};
        let client = reqwest::Client::new();
        let cfg = pool_cfg(
            RouteKind::Socket,
            Some(PolicyCfg {
                socket: Some("/run/busbar/hook.sock".to_string()),
                ..Default::default()
            }),
        );
        match resolve_policy(&cfg, &client) {
            Some(ResolvedPolicy::Policy { policy, .. }) => assert_eq!(policy.name(), "socket"),
            other => panic!(
                "route: socket must resolve to a Policy, got none={}",
                other.is_none()
            ),
        }
        // Missing / empty socket path → None (default SWRR; validation is the loud gate).
        assert!(resolve_policy(&pool_cfg(RouteKind::Socket, None), &client).is_none());
        assert!(resolve_policy(
            &pool_cfg(
                RouteKind::Socket,
                Some(PolicyCfg {
                    socket: Some(String::new()),
                    ..Default::default()
                }),
            ),
            &client
        )
        .is_none());
    }

    /// The `route: socket` YAML shorthand desugars to `RouteKind::Socket` and resolves with the
    /// documented default deadline (not 0ms) — same guarantee as the native shorthands.
    #[cfg(unix)]
    #[test]
    fn socket_route_parses_and_gets_default_timeout() {
        let client = reqwest::Client::new();
        let yaml = "route: socket\nmembers: []\npolicy:\n  socket: /run/busbar/hook.sock\n";
        let cfg: crate::config::PoolCfg = serde_yaml::from_str(yaml).expect("socket route parses");
        assert_eq!(cfg.route, crate::config::RouteKind::Socket);
        match resolve_policy(&cfg, &client) {
            Some(ResolvedPolicy::Policy { timeout, .. }) => assert_eq!(
                timeout,
                std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
            ),
            other => panic!("must resolve, got none={}", other.is_none()),
        }
    }

    /// The plain default (`route: weighted`) stays the zero-cost `None` path.
    #[test]
    fn weighted_route_resolves_none() {
        let client = reqwest::Client::new();
        assert!(
            resolve_policy(&pool_cfg(crate::config::RouteKind::Weighted, None), &client).is_none()
        );
    }

    /// A native shorthand (`route: cheapest`, etc.) must resolve to a `Policy` whose hard deadline
    /// is the documented default — NOT the 0ms a `PolicyCfg::default()`-built struct would carry.
    /// Drives the desugar through serde (as a real config would) and then `resolve_policy`.
    #[test]
    fn shorthand_route_resolves_default_timeout_not_zero() {
        let client = reqwest::Client::new();
        for name in ["cheapest", "fastest", "least_busy", "usage"] {
            let yaml = format!("route: {name}\nmembers: []\n");
            let cfg: crate::config::PoolCfg =
                serde_yaml::from_str(&yaml).expect("shorthand must parse");
            match resolve_policy(&cfg, &client) {
                Some(ResolvedPolicy::Policy { timeout, .. }) => {
                    assert_eq!(
                        timeout,
                        std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                        "shorthand `route: {name}` must resolve to the documented \
                         {default}ms deadline, not 0ms",
                        default = crate::config::DEFAULT_POLICY_TIMEOUT_MS,
                    );
                }
                other => panic!(
                    "shorthand `route: {name}` must resolve to a Policy, got none={}",
                    other.is_none()
                ),
            }
        }
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
}
