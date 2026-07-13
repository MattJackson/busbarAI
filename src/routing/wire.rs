// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE hook wire contract — shared by every out-of-process routing transport (HTTP webhook,
//! Unix-socket binary). A policy hook receives this exact JSON projection and returns this exact
//! reply shape, whatever the transport, so a hook graduates between transports (webhook prototype →
//! socket binary) without changing its logic. Versioned by shape, not a field, in v1: the schema is
//! append-only.

use super::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use serde::{Deserialize, Serialize};

/// PER-REQUEST message kinds — the explicit `op` discriminator every per-request payload carries
/// (contract audit #5: the three kinds were wire-indistinguishable; a hook binary receiving bytes
/// had to infer the kind from field presence/endpoint, and two registrations sharing one socket
/// provably could not tell them apart). MANAGEMENT messages stay key-discriminated (a top-level
/// `configure` / `describe` / `status` key); everything else is a per-request message and `op`
/// says which. The vocabulary is append-only — hooks MUST ignore unknown ops per the contract.
pub(crate) const OP_DECIDE: &str = "decide";
pub(crate) const OP_TRANSFORM: &str = "transform";
pub(crate) const OP_NOTIFY: &str = "notify";

/// The stable request schema sent to a hook: the request projection, every candidate, and context.
/// The request-side wire structs deliberately do NOT derive `Debug`: behind the opt-ins they
/// borrow prompt text and end-user identity, and a derived Debug would bypass the redacting
/// impls on `PromptProjection`/`CallerIdentity`.
#[derive(Serialize)]
pub(crate) struct HookRequest<'a> {
    /// The message kind: `decide` (a gate's blocking decision), `transform` (a rewrite pass), or
    /// `notify` (a fire-and-forget tap — never answer it). See [`OP_DECIDE`].
    pub(crate) op: &'static str,
    pub(crate) request: HookReqProjection<'a>,
    pub(crate) candidates: Vec<HookCandidate<'a>>,
    pub(crate) context: HookContext,
    /// TAP observation-stage payload — present ONLY on stage taps (`at: route|attempt|completion`);
    /// absent on request-stage taps and every gate, so the pre-stages wire is byte-identical
    /// (append-only schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stage: Option<HookStageProjection<'a>>,
}

/// The tap OBSERVATION-STAGE payload. Which fields are present depends on `at`:
/// `route` carries the surviving candidate count after the decision reconcile;
/// `attempt` carries the full failover story (attempt number, dispatched target, remaining
/// candidates, and — from attempt 2 — why the previous attempt failed);
/// `completion` carries the outcome (`ok` | `failed` | `rejected_by_gate` — the SYNTHETIC
/// completion that lets an audit tap see denials) and the response status.
#[derive(Serialize)]
pub(crate) struct HookStageProjection<'a> {
    pub(crate) at: &'static str,
    /// The dispatched candidate's model name (ONE name for one concept across the wire — the
    /// same string `candidates[].model` carries on decide payloads).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attempt_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) remaining_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous_failure: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
}

/// The request projection sent to a hook. THE CONTRACT: a **default bucket** of shape/metadata
/// signals is ALWAYS present (pool, protocol, counts, sizes, stream, max_tokens; plus every
/// candidate's metadata + live signals in `HookCandidate`) — nothing sensitive. On top of that, at
/// most **two access-gated SECURITY fields** ride the projection, each opted in per hook by an
/// explicit grant:
///   - `prompt` grant (`no|ro|rw`): `system` + `messages` (flattened text) — present when the grant
///     is `ro` OR `rw`. The REQUEST wire is IDENTICAL for `ro` and `rw` (a hook must SEE the prompt to
///     screen it or to rewrite it); the extra power of `rw` is on the REPLY only — a `rw` hook's
///     `rewrite` arm is applied, a `ro` hook's is dropped (enforced at the rewrite seam by the grant).
///   - `user` grant (`no|ro`): caller identity — present when `ro`.
///
/// A grant of `no` OMITS the field from the JSON entirely AND is fail-closed the other direction too
/// (a returned value for a field the hook wasn't granted is ignored): `ro`'s rewrite is dropped,
/// `no` sends nothing and accepts nothing back. These are the ONLY two fields that ever carry caller
/// content/identity.
#[derive(Serialize)]
pub(crate) struct HookReqProjection<'a> {
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) message_count: usize,
    pub(crate) has_tools: bool,
    pub(crate) total_chars: usize,
    /// Omitted when the request declares none (ONE idiom for optional signals: absent = unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// SECURITY (`prompt: ro|rw` grant): the flattened system prompt text. Absent when the grant is
    /// `no` — AND when granted but the request carries no (or an empty) system prompt, so a hook must
    /// key the grant off `messages` (always present, possibly `[]`, when granted), never off `system`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) system: Option<&'a str>,
    /// SECURITY (`prompt: ro|rw` grant): every message as `{role, text}`. Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) messages: Option<Vec<HookMessage<'a>>>,
    /// SECURITY (`user: ro` grant): caller identity (key id/name + end-user field, NEVER the secret).
    /// Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<HookUser<'a>>,
}

/// One message of the opt-in prompt projection: the role plus the flattened text content.
#[derive(Serialize)]
pub(crate) struct HookMessage<'a> {
    pub(crate) role: &'a str,
    pub(crate) text: &'a str,
}

/// The opt-in caller identity: the governance virtual-key `id`/`name` (never the secret — the
/// projection is built FROM the resolved key record, the token itself is unreachable here) and the
/// request body's end-user identifier.
#[derive(Serialize)]
pub(crate) struct HookUser<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<&'a str>,
}

/// One candidate as seen by the hook. `idx` is the stable handle the hook echoes back in `order`;
/// the rest are the live signals + operator metadata a policy ranks on. The contract projects
/// EVERYTHING a built-in ranking strategy reads, so an external hook can implement any of them
/// identically ("no hook is different"): `weight` (SWRR), `provider` (provider-preference),
/// `context_max` (context-fit), plus the cost/latency/concurrency/headroom live signals.
#[derive(Serialize)]
pub(crate) struct HookCandidate<'a> {
    pub(crate) idx: usize,
    pub(crate) model: &'a str,
    /// Upstream provider name — lets a hook prefer/avoid a provider (a provider-preference strategy).
    pub(crate) provider: &'a str,
    /// The configured SWRR weight — lets an external hook implement a weighted-variant strategy (the
    /// signal the built-in `weighted` floor ranks on; projected so the contract is complete).
    pub(crate) weight: u32,
    /// Member context-window ceiling — lets a hook route by context-fit. `None` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context_max: Option<usize>,
    // Optional live signals — omitted when unset (ONE idiom across the wire: absent = unset,
    // never a mix of `null` and absence; contract audit #6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cost_per_mtok: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latency_ms: Option<f64>,
    pub(crate) available_concurrency: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rate_headroom: Option<f64>,
    /// The member's operator-declared free-form `tags` (whatever the config author wrote — team
    /// names, regions, compliance labels). Omitted when the member declares none, so untagged
    /// configs keep the exact pre-tags payload.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub(crate) tags: &'a [String],
}

/// The POOL-SCOPED signal bucket (distinct from the per-candidate signals). `request.pool` already
/// names the pool — it is not duplicated here (contract audit #12).
#[derive(Serialize)]
pub(crate) struct HookContext {
    /// Pool-level remaining request budget; omitted when the pool is uncapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_remaining: Option<i64>,
}

/// The CONFIGURE message (D2) — the FIRST line busbar sends on every socket connection (and the
/// push a settings PATCH makes before committing): the hook's current desired-state settings.
/// The top-level `configure` KEY (presence, never key order) discriminates it as a management
/// message; per-request payloads carry the `op` field instead. Idempotent desired-state:
/// re-sending the same settings must be a no-op for the hook.
#[derive(Serialize)]
pub(crate) struct ConfigureMsg<'a> {
    pub(crate) configure: ConfigureBody<'a>,
}

#[derive(Serialize)]
pub(crate) struct ConfigureBody<'a> {
    /// The hook's own registry name (context echo).
    pub(crate) hook: &'a str,
    /// The opaque settings map from the hook's registry entry (operator/API-owned).
    pub(crate) settings: &'a serde_json::Map<String, serde_json::Value>,
    /// Monotonic settings version (the config_version that committed them) — the ack echoes it.
    pub(crate) settings_version: u64,
    pub(crate) busbar_version: &'static str,
}

/// The hook's configure ACK: `{"ack": {"settings_version": N}}`. Anything else (error, wrong
/// version, garbage, timeout) is a FAILED configure — a settings PATCH does not commit.
#[derive(Debug, Deserialize)]
pub(crate) struct ConfigureAck {
    pub(crate) ack: Option<ConfigureAckBody>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConfigureAckBody {
    pub(crate) settings_version: u64,
}

/// The DESCRIBE request (D2): `{"describe": true}` — the hook replies its self-description
/// ENVELOPE: `{"schema": <settings JSON Schema>, "dashboard"?: {"widgets": [...]}}`. ONE
/// declaration drives both the config form (`schema` — served at
/// `GET /api/v1/admin/hooks/{name}/schema`) and the plugin dashboard layout (`dashboard`,
/// reserved for the dashboard read; values come from `status.metrics` — busbar-ui suggestion #2).
/// Both members optional; unknown members ignored (append-only).
#[derive(Serialize)]
pub(crate) struct DescribeMsg {
    pub(crate) describe: bool,
}

/// The describe reply envelope, parsed liberally.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct DescribeReply {
    #[serde(default)]
    pub(crate) schema: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // reserved: consumed by the plugin-dashboard read (post-1.3 additive)
    pub(crate) dashboard: Option<serde_json::Value>,
}

/// The STATUS management message: `{"status": true}` — mirrors `describe`'s key-discriminated
/// idiom. The hook replies its OBSERVED state: `{"status": {"settings_version"?: N,
/// "settings"?: {...}, "metrics"?: {"<name>": {"type": "counter"|"gauge", "value": <number>,
/// "help"?: "..."}}}}`. Every reply key is optional; unknown keys are ignored; a hook that does
/// not implement `status` replies `{}` (busbar treats empty/absent as "unsupported" and fails
/// open). This is the control-plane read that lets busbar surface a hook's own settings and
/// operational data ("Your AI Control Plane" — a dashboard on busbar sees what each plug is
/// doing). Metric names: `^[a-z][a-z0-9_]{0,63}$`, counters SHOULD end `_total`; per-reply and
/// per-hook-lifetime name counts are bounded by busbar (a hostile hook cannot flood the registry).
#[derive(Serialize)]
pub(crate) struct StatusMsg {
    pub(crate) status: bool,
}

/// One hook-reported metric entry (parsed liberally; malformed ENTRIES are dropped, never the
/// whole reply). `type` is `counter` (monotonic over the hook's lifetime) or `gauge`. The optional
/// DISPLAY HINTS (`label`/`unit`/`viz`/`max` — busbar-ui suggestion #1) let a dashboard render the
/// metric correctly without per-plugin code; all are sanitized/bounded like `help` (the same
/// anti-exfiltration rule: hints are presentation, never content). Time SERIES are the CONSUMER's
/// job in 1.3 (a dashboard samples `status` and accumulates client-side); a future engine-side
/// `series` field on this entry is reserved as the additive path.
#[derive(Debug, Deserialize)]
pub(crate) struct HookMetric {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) value: f64,
    #[serde(default)]
    pub(crate) help: Option<String>,
    /// Human display name (a UI falls back to the metric name).
    #[serde(default)]
    pub(crate) label: Option<String>,
    /// Display unit token (`"ms"`, `"$"`, `"%"`, `"req/s"`, …) — max 16 chars, sanitized.
    #[serde(default)]
    pub(crate) unit: Option<String>,
    /// Rendering hint: `number` | `gauge` | `counter` | `sparkline` (anything else is dropped).
    #[serde(default)]
    pub(crate) viz: Option<String>,
    /// Gauge normalization ceiling (finite number, else dropped).
    #[serde(default)]
    pub(crate) max: Option<f64>,
}

/// The hook's `status` reply body (liberal: every field optional, unknown fields ignored),
/// deserialized into the shared `busbar_api::HookStatus` shape.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct StatusReply {
    #[serde(default)]
    pub(crate) settings_version: Option<u64>,
    #[serde(default)]
    pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub(crate) metrics: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

impl From<StatusReply> for busbar_api::HookStatus {
    fn from(r: StatusReply) -> Self {
        busbar_api::HookStatus {
            settings_version: r.settings_version,
            settings: r.settings,
            metrics: r.metrics,
        }
    }
}

/// The `status` reply envelope (`{"status": {...}}`); `None`/absent = the hook doesn't speak it
/// (per the unknown-op contract rule, `{}` = unsupported → busbar fails open).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct StatusEnvelope {
    #[serde(default)]
    pub(crate) status: Option<StatusReply>,
}

/// Per-reply cap on hook-reported metric entries (excess dropped with a warn — bounded registry).
pub(crate) const MAX_HOOK_METRICS: usize = 64;
/// Metric-help length cap (chars), sanitized through `sanitize_reject_message` before exposure.
pub(crate) const MAX_METRIC_HELP_CHARS: usize = 200;
/// Display-hint caps (same sanitize rule as help).
pub(crate) const MAX_METRIC_LABEL_CHARS: usize = 64;
pub(crate) const MAX_METRIC_UNIT_CHARS: usize = 16;

/// Validate a hook-reported metric NAME: `^[a-z][a-z0-9_]{0,63}$`. Anything else is dropped —
/// names become Prometheus label values, so the charset is enforced structurally (a hook granted
/// `prompt: ro` physically cannot smuggle content into a scrape).
pub(crate) fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Parse + validate the metrics map of a `status` reply fail-open: malformed entries (bad name,
/// unknown type, non-finite value) are DROPPED individually, valid ones kept, capped at
/// [`MAX_HOOK_METRICS`]. Help strings are sanitized + length-capped.
pub(crate) fn parse_status_metrics(
    raw: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Vec<(String, HookMetric)> {
    let mut out = Vec::new();
    for (name, v) in raw {
        if out.len() >= MAX_HOOK_METRICS {
            break;
        }
        if !valid_metric_name(name) {
            continue;
        }
        let Ok(mut m) = serde_json::from_value::<HookMetric>(v.clone()) else {
            continue;
        };
        if !m.value.is_finite() || !matches!(m.kind.as_str(), "counter" | "gauge") {
            continue;
        }
        // CHAR-boundary-safe caps (re-audit F1): `String::truncate` takes BYTES and panics off a
        // char boundary — a hook replying multi-byte help (100 × '€') could panic the admin
        // handler. `.chars().take(n)` caps in CHARS, panic-free, matching the documented "≤ N
        // chars" rule. Hints are sanitized + bounded exactly like help; out-of-vocabulary /
        // oversize values are dropped INDIVIDUALLY (the metric itself survives).
        let cap = |raw: &str, n: usize| -> String {
            sanitize_reject_message(raw).chars().take(n).collect()
        };
        m.help = m.help.map(|h| cap(&h, MAX_METRIC_HELP_CHARS));
        m.label = m.label.map(|l| cap(&l, MAX_METRIC_LABEL_CHARS));
        m.unit = m
            .unit
            .map(|u| cap(&u, MAX_METRIC_UNIT_CHARS))
            .filter(|s| !s.is_empty());
        m.viz = m
            .viz
            .filter(|v| matches!(v.as_str(), "number" | "gauge" | "counter" | "sparkline"));
        m.max = m.max.filter(|v| v.is_finite());
        out.push((name.clone(), m));
    }
    out
}

/// The hook's reply. `order` is the ranked preference (candidate `idx` values, most-preferred
/// first); an explicit `abstain: true` (or an absent/empty `order`) means "no opinion". Both fields
/// are optional so an empty `{}` deserializes to Abstain. Unknown JSON fields are ignored, so a hook
/// may attach extra diagnostics without breaking the contract.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct HookResponse {
    #[serde(default)]
    pub(crate) order: Option<Vec<usize>>,
    #[serde(default)]
    pub(crate) abstain: bool,
    /// REJECT the request outright: no upstream is dispatched, the caller gets a dialect-native
    /// error. Takes precedence over `order`/`abstain` — a hook that says both meant reject. The
    /// verb that makes a content-seeing hook (`policy.send_prompt`) a guardrail, not just a router.
    ///
    /// Deliberately an untyped `Value`, parsed best-effort by `normalize`: the verb is FAIL-CLOSED.
    /// Once a hook says "reject", a malformed detail (a status of 70000, a numeric message) must
    /// degrade to "reject with the defaults", never to "silently route the request" — a typed
    /// struct here would abort the WHOLE reply parse on a bad field and coerce the decision to
    /// `on_error`, routing a request the hook tried to stop. `{"reject": false}` (and JSON `null`,
    /// which maps to absent) is the one explicit "not rejecting" shape; anything else present
    /// rejects.
    #[serde(default)]
    pub(crate) reject: Option<serde_json::Value>,
    /// RESTRICT the surviving candidate set to members carrying ANY of these tags
    /// (`{"restrict": {"tags_any": [...]}}`). A compliance gate ("only BAA-covered lanes"). Untyped +
    /// FAIL-CLOSED like `reject`: a malformed restrict must fall to the gate's `on_error`/`on_empty`,
    /// never silently allow-all. Parsed by `parse_restrict`. Wired into the two-phase decision seam in
    /// a later slice-4 step; the reply contract + parser land here first (tested in isolation).
    #[serde(default)]
    pub(crate) restrict: Option<serde_json::Value>,
    /// REWRITE the request body (`{"rewrite": {"messages": [...], "tools": [...]}}`) — the
    /// compression/redaction arm (Headroom). Untyped + FAIL-CLOSED: a malformed/oversize rewrite must
    /// proceed with the UNMODIFIED body, never a corrupted one. Requires the hook's `prompt: rw` grant.
    /// Parsed by `parse_rewrite`. Applied by the priority-ordered transform pass wired in a later
    /// slice-4 step; the reply contract + parser land here first (tested in isolation).
    #[serde(default)]
    #[allow(dead_code)]
    // consumed when the priority-ordered transform pass is wired (later slice-4 step)
    pub(crate) rewrite: Option<serde_json::Value>,
}

/// A parsed, validated `restrict` reply: the set of tags a surviving candidate must carry at least
/// one of. FAIL-CLOSED — `parse_restrict` returns `None` for a malformed/empty restrict so the caller
/// routes it to `on_error`, never to an accidental allow-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestrictReply {
    pub(crate) tags_any: Vec<String>,
}

/// Parse the untyped `restrict` value fail-closed. A well-formed restrict is `{"tags_any": [non-empty
/// strings]}`; anything else (not an object, missing/empty/non-array `tags_any`, no usable string
/// entries) yields `None` — the caller treats that as the gate's `on_error`, never allow-all. Tag
/// strings are trimmed; empty/whitespace-only entries are dropped.
pub(crate) fn parse_restrict(value: &serde_json::Value) -> Option<RestrictReply> {
    let tags_any: Vec<String> = value
        .get("tags_any")?
        .as_array()?
        .iter()
        .filter_map(|t| t.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    if tags_any.is_empty() {
        return None;
    }
    Some(RestrictReply { tags_any })
}

/// A parsed, validated `rewrite` reply — part of the hook contract (`busbar-api`); re-exported so
/// engine-internal paths are unchanged. FAIL-CLOSED: `parse_rewrite` (below) returns `None` for a
/// malformed rewrite so the caller proceeds with the ORIGINAL body, never a corrupted one.
pub(crate) use busbar_api::RewriteReply;

/// Parse the untyped `rewrite` value fail-closed. A well-formed rewrite is `{"messages": [...],
/// "tools"?: [...]}` with a NON-EMPTY messages array; anything else yields `None` (proceed with the
/// original body). `tools` is optional (defaults empty).
#[allow(dead_code)] // applied by the priority-ordered transform pass in a later slice-4 step
pub(crate) fn parse_rewrite(value: &serde_json::Value) -> Option<RewriteReply> {
    let messages: Vec<serde_json::Value> = value.get("messages")?.as_array()?.clone();
    if messages.is_empty() {
        return None;
    }
    let tools = value
        .get("tools")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    Some(RewriteReply { messages, tools })
}

/// Extract a reject's (status, message) fail-closed: status CLAMPED to client errors (anything
/// else — absent, non-integer, 0, 200, 302, 500, 70000, -1 — becomes 403), message sanitized +
/// capped. ONE extraction for both the decide path (`normalize`) and the transform path (a `rw`
/// gate's reject) so the two can never diverge.
pub(crate) fn parse_reject_detail(reject: &serde_json::Value) -> (u16, String) {
    let status = match reject.get("status").and_then(|s| s.as_i64()) {
        Some(s) if (400..=499).contains(&s) => s as u16,
        _ => REJECT_STATUS_DEFAULT,
    };
    let message =
        sanitize_reject_message(reject.get("message").and_then(|m| m.as_str()).unwrap_or(""));
    (status, message)
}

/// Normalize a parsed reply on the TRANSFORM path: reject > rewrite > abstain. `restrict`/`order`
/// are decide-path verbs and are ignored here (documented in the contract). Shared by both
/// transports so they can never diverge.
pub(crate) fn transform_outcome(parsed: HookResponse) -> busbar_api::TransformOutcome {
    use busbar_api::TransformOutcome;
    if let Some(reject) = &parsed.reject {
        if *reject != serde_json::Value::Bool(false) {
            let (status, message) = parse_reject_detail(reject);
            return TransformOutcome::Reject { status, message };
        }
    }
    match parsed.rewrite.as_ref().and_then(parse_rewrite) {
        Some(rw) => TransformOutcome::Rewrite(rw),
        None => TransformOutcome::Abstain,
    }
}

/// Reject-status clamp range + fallback: any status outside 400..=499 becomes 403.
const REJECT_STATUS_DEFAULT: u16 = 403;
/// Reject-message length cap (chars). Long enough for a real reason, short enough for an error body.
const REJECT_MESSAGE_MAX_CHARS: usize = 300;
/// Reject-message fallback when the hook sends none (or nothing survives sanitizing).
const REJECT_MESSAGE_DEFAULT: &str = "Request rejected by the routing policy.";

/// Sanitize a reject message for the client error body AND the operator log line: strip control
/// chars, the Unicode line/paragraph separators (U+2028/29 — several log/OTLP pipelines treat
/// them as newlines: a record-splitting vector like CRLF), and the invisible direction/zero-width
/// formatting chars (bidi overrides U+202A..=U+202E and isolates U+2066..=U+2069 can visually
/// spoof a log line in a terminal; zero-widths U+200B..=U+200F and U+FEFF hide content). Cap the
/// length; fall back to the canned default when nothing printable survives.
///
/// Shared by `normalize` (the transports' reply path) and by `forward`'s seam mapping (defense in
/// depth for a `RoutingDecision::Reject` constructed directly by a policy impl), so the "safe to
/// log, safe for the client" guarantee holds for EVERY producer of a rejection.
pub(crate) fn sanitize_reject_message(raw: &str) -> String {
    let message: String = raw
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{2028}'
                        | '\u{2029}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .take(REJECT_MESSAGE_MAX_CHARS)
        .collect();
    if message.trim().is_empty() {
        REJECT_MESSAGE_DEFAULT.to_string()
    } else {
        message
    }
}

/// Build the wire projection from the live request/candidates/context. Borrows everywhere — the
/// projection is serialized immediately by the transport, never stored.
pub(crate) fn build<'a>(
    op: &'static str,
    req: &'a RoutingRequest<'_>,
    candidates: &'a [Candidate<'_>],
    ctx: &'a RoutingContext<'_>,
) -> HookRequest<'a> {
    HookRequest {
        op,
        request: HookReqProjection {
            pool: req.pool,
            ingress_protocol: req.ingress_protocol,
            message_count: req.message_count,
            has_tools: req.has_tools,
            total_chars: req.total_chars,
            max_tokens: req.max_tokens,
            stream: req.stream,
            // The opt-in projections: `None` (and thus ABSENT from the JSON) unless the pool set
            // `policy.send_prompt` / `policy.send_user` — `forward` only populates the source
            // fields behind those flags, so absence here is enforced upstream by construction.
            system: req.prompt.as_ref().and_then(|p| p.system.as_deref()),
            messages: req.prompt.as_ref().map(|p| {
                p.messages
                    .iter()
                    .map(|(role, text)| HookMessage {
                        role: role.as_ref(),
                        text: text.as_ref(),
                    })
                    .collect()
            }),
            user: req.identity.as_ref().map(|i| HookUser {
                key_id: i.key_id.as_deref(),
                key_name: i.key_name.as_deref(),
                user: i.user.as_deref(),
            }),
        },
        candidates: candidates
            .iter()
            .map(|c| HookCandidate {
                idx: c.idx,
                model: c.model,
                provider: c.provider,
                weight: c.weight,
                context_max: c.context_max,
                tier: c.tier,
                cost_per_mtok: c.cost_per_mtok,
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: c.rate_headroom,
                tags: c.tags,
            })
            .collect(),
        stage: None,
        context: HookContext {
            budget_remaining: ctx.budget_remaining,
        },
    }
}

/// Normalize a parsed hook reply into a decision: `reject` (clamped + sanitized) wins over
/// everything; then explicit abstain / absent order → `Abstain`; otherwise the shared liberal
/// normalizer (drop unknown idxs, dedup, empty → Abstain). One normalization for every transport.
pub(crate) fn normalize(parsed: HookResponse, candidates: &[Candidate<'_>]) -> RoutingDecision {
    // FAIL-CLOSED: any `reject` value except an explicit `false` is a rejection (see the field
    // doc). Details are extracted best-effort; anything missing or out-of-shape falls back to the
    // safe defaults rather than downgrading the verb.
    if let Some(reject) = parsed.reject {
        if reject != serde_json::Value::Bool(false) {
            let (status, message) = parse_reject_detail(&reject);
            return RoutingDecision::Reject { status, message };
        }
    }
    // RESTRICT comes after reject (reject wins) and before order. FAIL-CLOSED like reject: any
    // `restrict` value except an explicit `false` restricts; a malformed one (parse_restrict → None)
    // yields an EMPTY tag set, which downstream resolves via the gate's `on_empty` — never allow-all.
    if let Some(restrict) = parsed.restrict {
        if restrict != serde_json::Value::Bool(false) {
            let tags_any = parse_restrict(&restrict)
                .map(|r| r.tags_any)
                .unwrap_or_default();
            return RoutingDecision::Restrict { tags_any };
        }
    }
    if parsed.abstain {
        return RoutingDecision::Abstain;
    }
    let Some(order) = parsed.order else {
        return RoutingDecision::Abstain;
    };
    let valid: std::collections::HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
    RoutingDecision::from_ranked(order, &valid)
}

#[cfg(test)]
mod tests {
    /// Re-audit F1 REGRESSION: a hook-supplied multi-byte help/label/unit must cap at a CHAR
    /// boundary, never panic (String::truncate takes bytes — 100 × '€' panicked the admin handler).
    #[test]
    fn status_metric_hints_cap_char_safe() {
        let long_euro = "€".repeat(400);
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "ok_total".to_string(),
            serde_json::json!({"type": "counter", "value": 1.0,
                               "help": long_euro, "label": long_euro, "unit": long_euro}),
        );
        let parsed = super::parse_status_metrics(&m);
        assert_eq!(parsed.len(), 1);
        let (_, metric) = &parsed[0];
        assert_eq!(
            metric.help.as_ref().unwrap().chars().count(),
            super::MAX_METRIC_HELP_CHARS
        );
        assert_eq!(
            metric.label.as_ref().unwrap().chars().count(),
            super::MAX_METRIC_LABEL_CHARS
        );
        assert_eq!(
            metric.unit.as_ref().unwrap().chars().count(),
            super::MAX_METRIC_UNIT_CHARS
        );
        // Out-of-vocabulary viz + non-finite max drop individually; the metric survives.
        let mut m2 = std::collections::BTreeMap::new();
        m2.insert(
            "g".to_string(),
            serde_json::json!({"type": "gauge", "value": 0.5, "viz": "hologram",
                               "max": f64::NAN}),
        );
        let parsed2 = super::parse_status_metrics(&m2);
        assert_eq!(parsed2.len(), 1);
        assert!(parsed2[0].1.viz.is_none());
        assert!(parsed2[0].1.max.is_none());
    }

    use super::*;
    use crate::routing::{CallerIdentity, PromptProjection};

    fn cand(idx: usize, tags: &'static [String]) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: Some("large"),
            cost_per_mtok: Some(3.0),
            tags,
            latency_ms: Some(42.0),
            available_concurrency: 4,
            budget_remaining: Some(1000),
            rate_headroom: Some(0.75),
        }
    }

    fn req() -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 2,
            tool_count: 0,
            has_tools: false,
            total_chars: 10,
            system_chars: 0,
            max_tokens: None,
            stream: false,
            prompt: None,
            identity: None,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: None,
        }
    }

    /// The DEFAULT payload is shape-only and byte-stable: none of the opt-in keys (`system`,
    /// `messages`, `user`) nor an empty `tags` may appear — an existing hook parsing strictly must
    /// see the exact pre-opt-in contract.
    #[test]
    fn default_payload_omits_opt_in_keys() {
        let r = req();
        let cands = [cand(0, &[])];
        let c = ctx();
        let json = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
        for key in ["\"system\"", "\"messages\"", "\"user\"", "\"tags\""] {
            assert!(!json.contains(key), "default payload leaked {key}: {json}");
        }
    }

    /// With the opt-ins populated (as `forward` does behind `send_prompt`/`send_user`) and tags
    /// declared, the payload carries all of them — and never any secret-shaped field.
    #[test]
    fn opt_in_payload_carries_prompt_identity_tags() {
        static TAGS: std::sync::LazyLock<Vec<String>> =
            std::sync::LazyLock::new(|| vec!["team-a".into(), "eu".into()]);
        let mut r = req();
        r.prompt = Some(PromptProjection {
            system: Some("be brief".into()),
            messages: vec![("user".into(), "hello world".into())],
        });
        r.identity = Some(CallerIdentity {
            key_id: Some("k-123".into()),
            key_name: Some("sales-team".into()),
            user: Some("alice@example.com".into()),
        });
        let cands = [cand(0, TAGS.as_slice())];
        let c = ctx();
        let json = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["request"]["system"], "be brief");
        assert_eq!(v["request"]["messages"][0]["role"], "user");
        assert_eq!(v["request"]["messages"][0]["text"], "hello world");
        assert_eq!(v["request"]["user"]["key_id"], "k-123");
        assert_eq!(v["request"]["user"]["key_name"], "sales-team");
        assert_eq!(v["request"]["user"]["user"], "alice@example.com");
        assert_eq!(v["candidates"][0]["tags"][0], "team-a");
        assert_eq!(v["candidates"][0]["tags"][1], "eu");
        // The identity projection is built from the key RECORD: no token/secret field exists.
        for key in ["\"token\"", "\"secret\"", "\"key_hash\""] {
            assert!(!json.contains(key), "payload leaked {key}: {json}");
        }
    }

    /// `send_prompt` on + no system prompt: `messages` is PRESENT (possibly empty) so a hook can
    /// distinguish "opted in, empty" from "not opted in"; `system` stays absent.
    #[test]
    fn opt_in_prompt_without_system_still_sends_messages() {
        let mut r = req();
        r.prompt = Some(PromptProjection {
            system: None,
            messages: vec![],
        });
        let cands = [cand(0, &[])];
        let c = ctx();
        let v: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap(),
        )
        .unwrap();
        assert!(v["request"].get("system").is_none());
        assert_eq!(v["request"]["messages"], serde_json::json!([]));
    }

    fn norm(json: &str) -> RoutingDecision {
        let parsed: HookResponse = serde_json::from_str(json).unwrap();
        let cands = [cand(0, &[]), cand(1, &[])];
        normalize(parsed, &cands)
    }

    /// A bare `{"reject":{}}` is a full-strength rejection with the defaults: 403 + generic message.
    #[test]
    fn reject_bare_uses_defaults() {
        match norm(r#"{"reject":{}}"#) {
            RoutingDecision::Reject { status, message } => {
                assert_eq!(status, 403);
                assert_eq!(message, REJECT_MESSAGE_DEFAULT);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// A hook may only speak client errors: in-range statuses pass, everything else clamps to 403 —
    /// including values that would not even FIT a u16 (70000, -1): the reject verb must stay a
    /// rejection, never abort the reply parse and silently route the request.
    #[test]
    fn reject_status_clamps_to_4xx() {
        for (sent, want) in [
            (400, 400),
            (404, 404),
            (499, 499),
            (200, 403),
            (302, 403),
            (500, 403),
            (0, 403),
            (999, 403),
            (70000, 403),
            (-1, 403),
        ] {
            match norm(&format!(r#"{{"reject":{{"status":{sent}}}}}"#)) {
                RoutingDecision::Reject { status, .. } => {
                    assert_eq!(status, want, "sent {sent}");
                }
                other => panic!("expected Reject for {sent}, got {other:?}"),
            }
        }
    }

    /// The reject message is sanitized: control chars (CRLF/log injection) stripped, length capped,
    /// and a message that sanitizes to nothing falls back to the default.
    #[test]
    fn reject_message_is_sanitized() {
        match norm("{\"reject\":{\"message\":\"no\\r\\nSet-Cookie: x\\u0000!\"}}") {
            RoutingDecision::Reject { message, .. } => {
                assert_eq!(message, "noSet-Cookie: x!");
            }
            other => panic!("expected Reject, got {other:?}"),
        }
        let long = "x".repeat(1000);
        match norm(&format!(r#"{{"reject":{{"message":"{long}"}}}}"#)) {
            RoutingDecision::Reject { message, .. } => {
                assert_eq!(message.chars().count(), REJECT_MESSAGE_MAX_CHARS);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
        match norm("{\"reject\":{\"message\":\"\\r\\n\\t\"}}") {
            RoutingDecision::Reject { message, .. } => {
                assert_eq!(message, REJECT_MESSAGE_DEFAULT);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// `reject` wins over `order` AND `abstain`: a hook that says both meant reject.
    #[test]
    fn reject_takes_precedence() {
        for json in [
            r#"{"order":[1,0],"reject":{"status":451}}"#,
            r#"{"abstain":true,"reject":{"status":451}}"#,
        ] {
            match norm(json) {
                RoutingDecision::Reject { status, .. } => assert_eq!(status, 451),
                other => panic!("expected Reject for {json}, got {other:?}"),
            }
        }
    }

    /// The reject verb is FAIL-CLOSED: any malformed / non-object `reject` value still rejects with
    /// the defaults (403 + canned message) — a hook that tried to say "reject" must never have its
    /// request silently routed because a detail was mis-typed. The one explicit opt-out is
    /// `reject: false` (and `null`, which parses as absent): those defer to `order`/`abstain`.
    #[test]
    fn reject_is_fail_closed_on_malformed_values() {
        for json in [
            r#"{"reject":true}"#,
            r#"{"reject":"nope"}"#,
            r#"{"reject":123}"#,
            r#"{"reject":[]}"#,
            r#"{"reject":{"status":"451"}}"#,
            r#"{"reject":{"status":451.5}}"#,
            r#"{"reject":{"message":123}}"#,
        ] {
            match norm(json) {
                RoutingDecision::Reject { status, message } => {
                    assert_eq!(
                        status, 403,
                        "malformed reject must use the default status: {json}"
                    );
                    assert_eq!(message, REJECT_MESSAGE_DEFAULT, "for {json}");
                }
                other => panic!("expected fail-closed Reject for {json}, got {other:?}"),
            }
        }
        // The explicit opt-outs: false / null defer to the rest of the reply.
        assert!(matches!(
            norm(r#"{"order":[1,0],"reject":false}"#),
            RoutingDecision::Prefer(o) if o == vec![1, 0]
        ));
        assert!(matches!(
            norm(r#"{"order":[1,0],"reject":null}"#),
            RoutingDecision::Prefer(o) if o == vec![1, 0]
        ));
    }

    /// U+2028/U+2029 (line/paragraph separators — log-record splitters in several pipelines) AND
    /// the invisible formatting chars (bidi overrides/isolates: terminal log-line spoofing;
    /// zero-widths/BOM: hidden content) are stripped from the reject message.
    #[test]
    fn reject_message_strips_unicode_line_separators() {
        match norm("{\"reject\":{\"message\":\"a\\u2028b\\u2029c\"}}") {
            RoutingDecision::Reject { message, .. } => assert_eq!(message, "abc"),
            other => panic!("expected Reject, got {other:?}"),
        }
        // Bidi override + isolate + zero-width + BOM all stripped; visible text intact.
        match norm("{\"reject\":{\"message\":\"ok\\u202Espoof\\u2066x\\u200By\\uFEFFz\"}}") {
            RoutingDecision::Reject { message, .. } => assert_eq!(message, "okspoofxyz"),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// PINS the "opted in, anonymous" wire shape: `send_user` on with an all-None identity emits
    /// `"user": {}` (present but empty) — a hook detects the opt-in by the KEY's presence, so a
    /// future skip-if-all-none "cleanup" would silently break that contract.
    #[test]
    fn anonymous_identity_emits_empty_user_object() {
        let mut r = req();
        r.identity = Some(CallerIdentity {
            key_id: None,
            key_name: None,
            user: None,
        });
        let cands = [cand(0, &[])];
        let c = ctx();
        let v: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap(),
        )
        .unwrap();
        assert_eq!(v["request"]["user"], serde_json::json!({}));
    }

    /// NDJSON framing invariant: prompt text containing literal newlines/control chars must stay
    /// ONE serialized line — serde_json escapes them inside string values, and the socket
    /// transport's whole framing rests on that. This is the tripwire against any future custom
    /// serializer that would let a raw 0x0A reach the wire and desync the hook's line reader.
    #[test]
    fn opt_in_content_with_newlines_stays_one_line() {
        let mut r = req();
        r.prompt = Some(PromptProjection {
            system: Some("line1\nline2".into()),
            messages: vec![("user".into(), "a\nb\rc\u{2028}d".into())],
        });
        let cands = [cand(0, &[])];
        let c = ctx();
        let line = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "serialized hook payload must contain no raw newline bytes: {line}"
        );
        // And the content round-trips intact through a parse of that single line.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["request"]["system"], "line1\nline2");
        assert_eq!(v["request"]["messages"][0]["text"], "a\nb\rc\u{2028}d");
    }

    /// The pre-reject behaviors are untouched: order normalizes, abstain abstains, `{}` abstains.
    #[test]
    fn non_reject_replies_unchanged() {
        assert!(matches!(
            norm(r#"{"order":[1,0]}"#),
            RoutingDecision::Prefer(o) if o == vec![1, 0]
        ));
        assert!(matches!(
            norm(r#"{"abstain":true}"#),
            RoutingDecision::Abstain
        ));
        assert!(matches!(norm(r#"{}"#), RoutingDecision::Abstain));
    }

    /// `normalize` maps `restrict` to `RoutingDecision::Restrict` with reject > restrict > order
    /// precedence; a malformed restrict is fail-closed to an EMPTY tag set (→ on_empty downstream),
    /// and `restrict: false` is the explicit opt-out.
    #[test]
    fn normalize_restrict_precedence_and_fail_closed() {
        // Well-formed restrict → the tags.
        match norm(r#"{"restrict":{"tags_any":["baa"]}}"#) {
            RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
            other => panic!("expected Restrict, got {other:?}"),
        }
        // reject WINS over a co-present restrict.
        assert!(matches!(
            norm(r#"{"reject":{"status":403},"restrict":{"tags_any":["baa"]}}"#),
            RoutingDecision::Reject { .. }
        ));
        // restrict WINS over a co-present order.
        assert!(matches!(
            norm(r#"{"restrict":{"tags_any":["x"]},"order":[0,1]}"#),
            RoutingDecision::Restrict { .. }
        ));
        // Malformed restrict → fail-closed empty tag set (→ on_empty), never allow-all/order.
        match norm(r#"{"restrict":{"tags_any":[]}}"#) {
            RoutingDecision::Restrict { tags_any } => assert!(tags_any.is_empty()),
            other => panic!("malformed restrict must stay Restrict (fail-closed), got {other:?}"),
        }
        // Explicit opt-out: `restrict: false` is NOT a restriction.
        assert!(matches!(
            norm(r#"{"restrict":false,"order":[1,0]}"#),
            RoutingDecision::Prefer(_)
        ));
    }

    /// `parse_restrict` is FAIL-CLOSED: a well-formed restrict yields the trimmed non-empty tags; any
    /// malformed shape yields `None` (the caller routes to on_error, never allow-all).
    #[test]
    fn parse_restrict_is_fail_closed() {
        let ok = parse_restrict(&serde_json::json!({"tags_any": ["baa", " gpu ", ""]}))
            .expect("well-formed restrict parses");
        assert_eq!(ok.tags_any, vec!["baa".to_string(), "gpu".to_string()]);

        // Malformed → None (fail-closed): no tags_any, empty list, whitespace-only, non-array, non-object.
        assert!(parse_restrict(&serde_json::json!({})).is_none());
        assert!(parse_restrict(&serde_json::json!({"tags_any": []})).is_none());
        assert!(parse_restrict(&serde_json::json!({"tags_any": ["", "  "]})).is_none());
        assert!(parse_restrict(&serde_json::json!({"tags_any": "baa"})).is_none());
        assert!(parse_restrict(&serde_json::json!("baa")).is_none());
    }

    /// `parse_rewrite` is FAIL-CLOSED: a well-formed rewrite yields the messages (+ optional tools);
    /// any malformed shape yields `None` (the caller keeps the ORIGINAL body).
    #[test]
    fn parse_rewrite_is_fail_closed() {
        let ok = parse_rewrite(&serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "headroom_retrieve"}]
        }))
        .expect("well-formed rewrite parses");
        assert_eq!(ok.messages.len(), 1);
        assert_eq!(ok.tools.len(), 1);

        // tools optional → defaults empty.
        let no_tools = parse_rewrite(&serde_json::json!({"messages": [{"role": "user"}]}))
            .expect("rewrite without tools parses");
        assert!(no_tools.tools.is_empty());

        // Malformed → None (fail-closed): no messages, empty messages, non-array, non-object.
        assert!(parse_rewrite(&serde_json::json!({})).is_none());
        assert!(parse_rewrite(&serde_json::json!({"messages": []})).is_none());
        assert!(parse_rewrite(&serde_json::json!({"messages": "hi"})).is_none());
        assert!(parse_rewrite(&serde_json::json!("hi")).is_none());
    }
}
