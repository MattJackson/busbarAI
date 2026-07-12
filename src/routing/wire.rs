// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The ONE hook wire contract — shared by every out-of-process routing transport (HTTP webhook,
//! Unix-socket binary). A policy hook receives this exact JSON projection and returns this exact
//! reply shape, whatever the transport, so a hook graduates between transports (webhook prototype →
//! socket binary) without changing its logic. Versioned by shape, not a field, in v1: the schema is
//! append-only.

use super::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use serde::{Deserialize, Serialize};

/// The stable request schema sent to a hook: the request projection, every candidate, and context.
/// The request-side wire structs deliberately do NOT derive `Debug`: behind the opt-ins they
/// borrow prompt text and end-user identity, and a derived Debug would bypass the redacting
/// impls on `PromptProjection`/`CallerIdentity`.
#[derive(Serialize)]
pub(crate) struct HookRequest<'a> {
    pub(crate) request: HookReqProjection<'a>,
    pub(crate) candidates: Vec<HookCandidate<'a>>,
    pub(crate) context: HookContext<'a>,
}

/// The request projection (a cheap, read-only slice of the ingress request). Shape signals only BY
/// DEFAULT — no prompt text or caller identity rides this projection unless the pool opted in
/// (`policy.send_prompt` / `policy.send_user`). The opt-in fields are omitted from the JSON
/// entirely when off, so the default payload is byte-identical to the pre-opt-in contract.
#[derive(Serialize)]
pub(crate) struct HookReqProjection<'a> {
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) message_count: usize,
    pub(crate) has_tools: bool,
    pub(crate) total_chars: usize,
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// `policy.send_prompt` opt-in: the flattened system prompt text. Absent when off — AND when
    /// on but the request carries no (or an empty) system prompt, so a hook must key the opt-in
    /// off `messages` (always present, possibly `[]`, when on), never off `system`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) system: Option<&'a str>,
    /// `policy.send_prompt` opt-in: every message as `{role, text}`. Absent when off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) messages: Option<Vec<HookMessage<'a>>>,
    /// `policy.send_user` opt-in: caller identity (key id/name + end-user field, NEVER the secret).
    /// Absent when off.
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
/// the rest are the live signals + operator metadata a policy ranks on.
#[derive(Serialize)]
pub(crate) struct HookCandidate<'a> {
    pub(crate) idx: usize,
    pub(crate) model: &'a str,
    pub(crate) tier: Option<&'a str>,
    pub(crate) cost_per_mtok: Option<f64>,
    pub(crate) latency_ms: Option<f64>,
    pub(crate) available_concurrency: usize,
    pub(crate) budget_remaining: Option<i64>,
    pub(crate) rate_headroom: Option<f64>,
    /// The member's operator-declared free-form `tags` (whatever the config author wrote — team
    /// names, regions, compliance labels). Omitted when the member declares none, so untagged
    /// configs keep the exact pre-tags payload.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub(crate) tags: &'a [String],
}

/// The routing context projection.
#[derive(Serialize)]
pub(crate) struct HookContext<'a> {
    pub(crate) pool: &'a str,
    pub(crate) budget_remaining: Option<i64>,
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
    #[allow(dead_code)]
    // consumed when the two-phase decision seam is wired (later slice-4 step)
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
#[allow(dead_code)] // wired into the two-phase decision seam in a later slice-4 step
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

/// A parsed, validated `rewrite` reply: the replacement message body and any injected tools. Both are
/// opaque dialect-agnostic JSON arrays busbar re-renders per target protocol. FAIL-CLOSED —
/// `parse_rewrite` returns `None` for a malformed rewrite so the caller proceeds with the ORIGINAL
/// body, never a corrupted one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RewriteReply {
    pub(crate) messages: Vec<serde_json::Value>,
    pub(crate) tools: Vec<serde_json::Value>,
}

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
    req: &'a RoutingRequest<'_>,
    candidates: &'a [Candidate<'_>],
    ctx: &'a RoutingContext<'_>,
) -> HookRequest<'a> {
    HookRequest {
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
                tier: c.tier,
                cost_per_mtok: c.cost_per_mtok,
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: c.rate_headroom,
                tags: c.tags,
            })
            .collect(),
        context: HookContext {
            pool: ctx.pool,
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
            // Clamp: a hook may only speak client errors. Anything else (absent, non-integer, 0,
            // 200, 302, 500, 70000, -1) → 403.
            let status = match reject.get("status").and_then(|s| s.as_i64()) {
                Some(s) if (400..=499).contains(&s) => s as u16,
                _ => REJECT_STATUS_DEFAULT,
            };
            let message = sanitize_reject_message(
                reject.get("message").and_then(|m| m.as_str()).unwrap_or(""),
            );
            return RoutingDecision::Reject { status, message };
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
        let json = serde_json::to_string(&build(&r, &cands, &c)).unwrap();
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
        let json = serde_json::to_string(&build(&r, &cands, &c)).unwrap();
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
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&build(&r, &cands, &c)).unwrap()).unwrap();
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
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&build(&r, &cands, &c)).unwrap()).unwrap();
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
        let line = serde_json::to_string(&build(&r, &cands, &c)).unwrap();
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
