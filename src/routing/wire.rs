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
#[derive(Debug, Serialize)]
pub(crate) struct HookRequest<'a> {
    pub(crate) request: HookReqProjection<'a>,
    pub(crate) candidates: Vec<HookCandidate<'a>>,
    pub(crate) context: HookContext<'a>,
}

/// The request projection (a cheap, read-only slice of the ingress request). Shape signals only BY
/// DEFAULT — no prompt text or caller identity rides this projection unless the pool opted in
/// (`policy.send_prompt` / `policy.send_user`). The opt-in fields are omitted from the JSON
/// entirely when off, so the default payload is byte-identical to the pre-opt-in contract.
#[derive(Debug, Serialize)]
pub(crate) struct HookReqProjection<'a> {
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) message_count: usize,
    pub(crate) has_tools: bool,
    pub(crate) total_chars: usize,
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// `policy.send_prompt` opt-in: the flattened system prompt text. Absent when off.
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
#[derive(Debug, Serialize)]
pub(crate) struct HookMessage<'a> {
    pub(crate) role: &'a str,
    pub(crate) text: &'a str,
}

/// The opt-in caller identity: the governance virtual-key `id`/`name` (never the secret — the
/// projection is built FROM the resolved key record, the token itself is unreachable here) and the
/// request body's end-user identifier.
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
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
    #[serde(default)]
    pub(crate) reject: Option<HookReject>,
}

/// The reject reply body. Both fields optional: a bare `{"reject":{}}` is a valid full-strength
/// rejection with the defaults (403, a generic message).
#[derive(Debug, Deserialize)]
pub(crate) struct HookReject {
    /// Client-error status for the caller. Clamped by `normalize` to 400..=499 (default 403): a
    /// hook cannot mint a success, a redirect, or a 5xx through this path.
    #[serde(default)]
    pub(crate) status: Option<u16>,
    /// Human-readable reason, surfaced in the dialect-native error body. Sanitized by `normalize`
    /// (control characters stripped, length capped) so a hook reply can never smuggle CRLF or a
    /// megabyte of text into the client error.
    #[serde(default)]
    pub(crate) message: Option<String>,
}

/// Reject-status clamp range + fallback: any status outside 400..=499 becomes 403.
const REJECT_STATUS_DEFAULT: u16 = 403;
/// Reject-message length cap (chars). Long enough for a real reason, short enough for an error body.
const REJECT_MESSAGE_MAX_CHARS: usize = 300;
/// Reject-message fallback when the hook sends none (or nothing survives sanitizing).
const REJECT_MESSAGE_DEFAULT: &str = "Request rejected by the routing policy.";

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
                        role: role.as_str(),
                        text: text.as_str(),
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
    if let Some(reject) = parsed.reject {
        // Clamp: a hook may only speak client errors. Anything else (0, 200, 302, 500) → 403.
        let status = match reject.status {
            Some(s) if (400..=499).contains(&s) => s,
            _ => REJECT_STATUS_DEFAULT,
        };
        // Sanitize: strip control chars (no CRLF/log injection), cap the length, fall back to the
        // default when nothing printable survives.
        let message: String = reject
            .message
            .as_deref()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(REJECT_MESSAGE_MAX_CHARS)
            .collect();
        let message = if message.trim().is_empty() {
            REJECT_MESSAGE_DEFAULT.to_string()
        } else {
            message
        };
        return RoutingDecision::Reject { status, message };
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

    /// A hook may only speak client errors: in-range statuses pass, everything else clamps to 403.
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
}
