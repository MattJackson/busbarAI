// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared helpers and constants for the OpenAI-family protocols (Chat Completions and Responses).
//! Both wire formats belong to the same provider family; items that are identical across them
//! live here so they are single-sourced rather than copy-pasted (and risking drift).

#[cfg(test)]
use axum::http::StatusCode;

/// Machine-readable `code` field emitted in a bad-key 401 OpenAI-family error envelope.
/// Used in `bearer_error_code` to mirror the native `authentication_error` → `invalid_api_key`
/// pairing that official SDKs surface as `error.code`.
const CODE_INVALID_API_KEY: &str = "invalid_api_key";

/// Busbar-internal `provider_signal` label for a context-length result (the LANE label, not the
/// OpenAI wire code). Distinct from `PROVIDER_CODE_CONTEXT_LENGTH` ("context_length_exceeded"),
/// which is the provider-facing code extracted from the request body. `#[cfg(test)]` because its only
/// referent, `openai_classify`, is itself a test-only single-source mirror of the production classifier.
#[cfg(test)]
pub(crate) const PROVIDER_SIGNAL_CONTEXT_LENGTH: &str = "context_length";

/// Fallback model name when a cross-protocol request carries none. The Chat-Completions and
/// Responses writers are two wire formats of the SAME provider family, so this value is
/// deliberately identical and MUST stay in lockstep — single-sourced here and referenced by both
/// modules. If the two protocols ever genuinely diverge, split it back out at that point.
pub(crate) const OPENAI_FAMILY_DEFAULT_MODEL: &str = "gpt-4o";

/// DoS cap on concurrently-tracked open tool-call accumulators per stream. Matches OpenAI's
/// documented parallel-tool-call limit (128). Single-sourced here so Chat Completions and
/// Responses cannot drift.
pub(crate) const OPENAI_FAMILY_MAX_OPEN_TOOLS: usize = 128;

/// OpenAI error `type` for a malformed / bad-argument request.
pub(crate) const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// OpenAI error `type` for a missing or invalid API key.
pub(crate) const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
/// OpenAI error `type` for a permission / access-control denial.
pub(crate) const ERR_TYPE_PERMISSION: &str = "permission_error";
/// OpenAI error `type` for a resource that does not exist.
pub(crate) const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// OpenAI error `type` for a rate-limit / throttle response.
pub(crate) const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// OpenAI error `type` for a transient upstream failure.
pub(crate) const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// OpenAI error `type` for a billing-quota exhaustion (HTTP 429).
pub(crate) const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Anthropic/busbar internal kind for an overloaded upstream; mapped to `server_error` on the
/// OpenAI wire (OpenAI has no `overloaded_error` type).
pub(crate) const ERR_TYPE_OVERLOADED: &str = "overloaded_error";

/// Precise context-length prose scan shared by `OpenAiReader::extract_error` and
/// `ResponsesReader::extract_error` — the message scan was duplicated. The scan must be PRECISE:
/// a naive OR of weak tokens (`token`/`maximum`) misclassifies unrelated errors (e.g. a quota body
/// like "maximum number of tokens allowed per day" — a rate-limit, not oversized). Require a
/// CO-LOCATED context-length phrase: a self-contained canonical phrase, or `exceeds` paired
/// specifically with `context`/`token limit`. The caller supplies its own lowercased source
/// (openai scans `error.message`; responses scans the whole body) and applies the
/// `oversized_status` (400/413) GATE itself — that gate is NOT part of this helper.
pub(crate) fn openai_context_length_prose_scan(text: &str) -> bool {
    text.contains("maximum context length")
        || text.contains("context length exceeded")
        || text.contains("reduce the length")
        || (text.contains("exceeds") && (text.contains("context") || text.contains("token limit")))
}

/// Map an OpenAI-family error `type` string onto its canonical machine-readable `code`, shared by
/// the OpenAI Chat Completions and `/v1/responses` writers (both emit the identical OpenAI error
/// envelope). A real bad-key 401 returns `{"type":"authentication_error", ..., "code":"invalid_api_key"}`
/// and the official SDKs surface `error.code` to callers, so emitting `code: null` on an auth (or
/// over-quota) failure is a deterministic proxy tell that contradicts the total-indistinguishability
/// promise — we mirror the native pairing for those two types. Every other modeled type, plus any
/// caller-supplied passthrough type, keeps `null`: the shape OpenAI uses when no machine-readable
/// code applies. There is no `_ =>` catch-all hiding an unhandled case; the final arm binds `other`
/// explicitly and emits `null`, the correct native value for those types.
pub(crate) fn bearer_error_code(error_type: &str) -> serde_json::Value {
    match error_type {
        crate::forward::KIND_AUTHENTICATION => {
            serde_json::Value::String(CODE_INVALID_API_KEY.to_string())
        }
        // Real OpenAI quota-exhaustion errors carry BOTH `type` and `code` set to
        // `insufficient_quota` (HTTP 429). The over-budget governance path
        // (route.rs `ingress_error(..., KIND_INSUFFICIENT_QUOTA, ...)`) reaches these writers with that
        // type; emitting `code: null` for it is an SDK-visible mismatch (the official client surfaces
        // `error.code == "insufficient_quota"`) and a proxy tell, so we mirror the native pairing.
        crate::forward::KIND_INSUFFICIENT_QUOTA => {
            serde_json::Value::String(crate::forward::KIND_INSUFFICIENT_QUOTA.to_string())
        }
        crate::forward::KIND_INVALID_REQUEST
        | crate::forward::KIND_PERMISSION
        | crate::forward::KIND_NOT_FOUND
        | crate::forward::KIND_RATE_LIMIT
        | crate::forward::KIND_SERVER_ERROR
        | crate::forward::KIND_API_ERROR => serde_json::Value::Null,
        other => {
            // A caller-supplied passthrough type we model no code for: OpenAI carries no
            // machine-readable code for these, so `null` matches the native shape. Named binding
            // (not `_`) keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            serde_json::Value::Null
        }
    }
}

/// Canonical OpenAI-family error classification, shared verbatim by `OpenAiReader::classify` and
/// `ResponsesReader::classify` (the two were word-for-word identical). Both surfaces emit the same
/// OpenAI error envelope, so the mapping — context-length-exceeded (fail over without penalty) first,
/// then 429→RateLimit, 401/403→Auth, 5xx→ServerError, other 4xx→ClientError — is single-sourced here.
#[cfg(test)]
pub(crate) fn openai_classify(status: StatusCode, body: &[u8]) -> crate::breaker::CanonicalSignal {
    use crate::breaker::StatusClass;
    // context-length-exceeded — the lane is healthy; this must fail over (to a larger-context
    // model), not penalize the breaker. Detect by OpenAI code/message first.
    let code_is_context = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|j| {
            j.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        })
        .as_deref()
        == Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH);
    // Mirror production `extract_error`: the prose message scan is GATED to the HTTP statuses an
    // oversized request actually uses (400 invalid_request_error; 413 payload-too-large). Without the
    // gate a 401/429/5xx whose prose happens to contain "maximum context length" would reclassify as
    // ContextLength — letting a genuine auth/rate-limit/server failure escape fault attribution. The
    // structured `code: "context_length_exceeded"` path is NOT gated (it is unambiguous).
    let oversized = status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
    let body_lower = String::from_utf8_lossy(body).to_lowercase();
    if code_is_context || (oversized && body_lower.contains("maximum context length")) {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ContextLength,
            provider_signal: Some(PROVIDER_SIGNAL_CONTEXT_LENGTH.to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::RateLimit,
            provider_signal: Some("429".to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::Auth,
            provider_signal: Some("auth".to_string()),
            retry_after: None,
        };
    }

    if status.is_server_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ServerError,
            provider_signal: Some("5xx".to_string()),
            retry_after: None,
        };
    }

    if status.is_client_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: Some(format!("{}", status.as_u16())),
            retry_after: None,
        };
    }

    crate::breaker::CanonicalSignal {
        class: StatusClass::ClientError,
        provider_signal: None,
        retry_after: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::breaker::StatusClass;
    use crate::proto::ProtocolRegistry;
    use axum::http::StatusCode;

    #[test]
    fn test_openai_classify() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);

        // Test 403 → Auth
        let signal = reader.classify(StatusCode::FORBIDDEN, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);
    }

    /// The shared context-length prose scan must fire on the canonical self-contained phrases and on
    /// the `exceeds`+`context`/`token limit` pairing — this is what lets a genuine oversized-request
    /// body fail over (to a larger-context model) instead of penalizing the lane's breaker.
    #[test]
    fn context_length_prose_scan_fires_on_canonical_phrases() {
        use super::openai_context_length_prose_scan as scan;
        // Caller lowercases before calling; assert on already-lowercased inputs.
        assert!(scan("this model's maximum context length is 8192 tokens"));
        assert!(scan("context length exceeded for this request"));
        assert!(scan("please reduce the length of the messages"));
        // `exceeds` must be CO-LOCATED with context/token-limit to count.
        assert!(scan("your input exceeds the context window"));
        assert!(scan("the request exceeds the token limit"));
    }

    /// Precision guard: the scan must NOT fire on unrelated errors whose prose merely mentions weak
    /// tokens like `token`/`maximum` — e.g. a per-day quota (rate-limit) body — or a bare `exceeds`
    /// with no context/token-limit co-location. Misclassifying these as context-length would let a
    /// real rate-limit/quota failure escape breaker penalty by "failing over" instead.
    #[test]
    fn context_length_prose_scan_precise_no_false_positive() {
        use super::openai_context_length_prose_scan as scan;
        assert!(
            !scan("you have reached the maximum number of tokens allowed per day"),
            "a per-day quota body is a rate-limit, not context-length"
        );
        assert!(
            !scan("the request exceeds your monthly spend limit"),
            "`exceeds` without context/token-limit co-location must not fire"
        );
        assert!(!scan("invalid api key provided"));
        assert!(!scan(""));
    }

    /// `bearer_error_code` mirrors the native OpenAI `type`→`code` pairing: only auth and
    /// insufficient-quota carry a machine-readable `code` (the value official SDKs surface as
    /// `error.code`); every other modeled type — and any passthrough type — stays `null`, matching
    /// the shape OpenAI uses when no code applies. Emitting a spurious code is a proxy tell.
    #[test]
    fn bearer_error_code_mirrors_native_type_code_pairing() {
        use super::bearer_error_code as code;
        assert_eq!(
            code(crate::forward::KIND_AUTHENTICATION),
            serde_json::Value::String("invalid_api_key".to_string())
        );
        assert_eq!(
            code(crate::forward::KIND_INSUFFICIENT_QUOTA),
            serde_json::Value::String("insufficient_quota".to_string())
        );
        // Every modeled non-auth/non-quota type carries no code.
        for t in [
            crate::forward::KIND_INVALID_REQUEST,
            crate::forward::KIND_PERMISSION,
            crate::forward::KIND_NOT_FOUND,
            crate::forward::KIND_RATE_LIMIT,
            crate::forward::KIND_SERVER_ERROR,
            crate::forward::KIND_API_ERROR,
        ] {
            assert_eq!(code(t), serde_json::Value::Null, "{t} must emit code:null");
        }
        // An unmodeled passthrough type also stays null (native shape), never invents a code.
        assert_eq!(code("some_future_error_type"), serde_json::Value::Null);
    }
}
