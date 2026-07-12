// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol-agnostic classifier for breaker dispositions.
//!
//! Stage 2 of the two-stage disposition pipeline:
//! - Stage 1 (src/proto/): per-protocol normalizer → CanonicalSignal with typed StatusClass
//! - Stage 2 (this module): protocol-agnostic classifier → Disposition
//!
//! Mapping (+ ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// Anthropic non-standard 529 overload status — not in the IANA registry but
/// documented by Anthropic as their server-overloaded signal (distinct from 503).
const HTTP_OVERLOADED: u16 = 529;

/// Protocol-neutral, dialect-normalized status class.
/// Emitted by Stage 1 normalizer (the per-protocol classifier) in src/proto/.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusClass {
    /// Rate limit / slow down — transient, may recover with retry-after
    RateLimit,
    /// Overloaded server — transient
    Overloaded,
    /// Server error (5xx) — transient
    ServerError,
    /// Request timeout — transient
    Timeout,
    /// Network failure — transient
    Network,
    /// Authentication failure (401/403) — hard down, key invalid
    Auth,
    /// Billing / insufficient balance — hard down, account issue
    Billing,
    /// Client error (4xx other than 401/403) — client fault, do not penalize lane
    ClientError,
    /// Request exceeds this model's context window — the LANE is healthy; fail over (ideally to
    /// a larger-context model) WITHOUT penalizing the breaker.
    ContextLength,
}

/// Final disposition that drives the StateStore write path.
/// Per ADR-0002 +:
///   - ClientFault: caller's bad input → relay verbatim, record NOTHING
///   - TransientUpstream: transient failure → cooldown + err counter
///   - HardDown: definitive signal → permanent dead state (with probe recovery)
///   - ContextLength: request too big for this model → fail over, record NOTHING (lane healthy)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    ClientFault,
    TransientUpstream,
    HardDown,
    ContextLength,
}

/// Convert a string to StatusClass. Returns None for unknown values.
pub(crate) fn status_class_from_str(s: &str) -> Option<StatusClass> {
    match s {
        "rate_limit" => Some(StatusClass::RateLimit),
        "overloaded" => Some(StatusClass::Overloaded),
        "server_error" => Some(StatusClass::ServerError),
        "timeout" => Some(StatusClass::Timeout),
        "network" => Some(StatusClass::Network),
        "auth" => Some(StatusClass::Auth),
        "billing" => Some(StatusClass::Billing),
        "client_error" => Some(StatusClass::ClientError),
        "context_length" => Some(StatusClass::ContextLength),
        _ => None,
    }
}

/// Warn (once per distinct value) that an operator `error_map` entry maps to a string that is not a
/// recognized StatusClass. Such a value is silently ignored by `normalize_raw_error` — the error
/// then falls through to HTTP-status classification — so without this signal a typo'd mapping (e.g.
/// `rate_limt`) would never take effect and the operator would have no indication why. Deduped via a
/// process-wide set so a misconfiguration on a hot error path logs once, not per request.
fn warn_unrecognized_error_map_value(value: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    // Poisoning is harmless here (the set only dedupes warnings); recover the guard either way.
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.insert(value.to_string()) {
        tracing::warn!(
            error_map_value = value,
            "error_map maps an error to an unrecognized status class; the mapping is IGNORED and \
             classification falls through to HTTP status. Valid classes: rate_limit, overloaded, \
             server_error, timeout, network, auth, billing, client_error, context_length"
        );
    }
}

/// Classify a CanonicalSignal into a disposition.
/// EXHAUSTIVE match on StatusClass — NO `_ =>` allowed.
/// Per ADR-0002: ClientFault never counted; HardDown immediate trip.
pub(crate) fn classify(sig: &CanonicalSignal) -> Disposition {
    match sig.class {
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network => Disposition::TransientUpstream,
        StatusClass::Auth | StatusClass::Billing => Disposition::HardDown,
        StatusClass::ClientError => Disposition::ClientFault,
        StatusClass::ContextLength => Disposition::ContextLength,
    }
}

/// Raw upstream error extracted from HTTP response (Stage 1a output).
#[derive(Debug, Clone)]
pub(crate) struct RawUpstreamError {
    pub(crate) http_status: u16,
    /// Provider-specific error *code* (e.g. a numeric `code` field), checked against `error_map`.
    pub(crate) provider_code: Option<String>,
    /// Provider-specific structured error *type* (e.g. a `type`/`error.type` string), checked
    /// against `error_map` as a second signal when the code doesn't match.
    pub(crate) structured_type: Option<String>,
    /// Upstream `Retry-After` header value in whole seconds, when present. The per-protocol
    /// `extract_error` methods only see the body (no headers), so the forwarding layer — which has
    /// the response headers — parses and sets this after `extract_error` returns. `normalize_raw_error`
    /// then propagates it into `CanonicalSignal.retry_after` so the cooldown floor is honored.
    pub(crate) retry_after_secs: Option<u64>,
}

/// Classify a raw upstream error into a canonical signal using an error_map.
/// Stage 1b (provider normalizer): data-driven mapping from raw errors to StatusClass.
pub(crate) fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
) -> CanonicalSignal {
    // Step 1: a provider error code mapped in error_map refines (overrides) the HTTP-status default.
    let provider_signal = if let Some(ref code) = raw.provider_code {
        if let Some(mapped_class) = error_map.get(code) {
            if let Some(class) = status_class_from_str(mapped_class) {
                // CLASS guard (R27 #8/#3): context_length must NEVER mask a 5xx upstream
                // outage. An operator error_map mapping a code to `context_length` on a 5xx
                // status would otherwise reclassify a transient outage as no-penalty
                // ContextLength and skip the breaker penalty. Suppress the early return in
                // that one case and fall through to HTTP-status classification so the lane is
                // penalized; every other mapped class returns as before.
                if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                    return CanonicalSignal {
                        class,
                        provider_signal: Some(code.clone()),
                        retry_after: raw.retry_after_secs,
                    };
                }
            } else {
                // The operator mapped this code to a string that is not a recognized status class
                // (typo such as `rate_limt`). It is silently ignored below; warn so the misconfig
                // is visible instead of a mapping that never takes effect.
                warn_unrecognized_error_map_value(mapped_class);
            }
        }
        // built-in recognition of the canonical context-length code (the operator
        // error_map above overrides — it is checked first and returns early; this is the default
        // when unmapped). The lane is healthy — ContextLength → fail over without penalty.
        //
        // Gate on a non-5xx status: a 5xx is an upstream server failure, never a context-length
        // error, so a 5xx body that happens to carry a `context_length_exceeded`-ish code must NOT
        // be reclassified as ContextLength (that would mask a transient outage and skip the breaker
        // penalty). Let such cases fall through to the HTTP-status classification below, where the
        // operator error_map can still countermand via the structured-type signal (Step 1b).
        // TIGHTEN (R27 #3, breaker-layer half): the built-in context_length code only ever
        // applies to oversized-request statuses (400 Bad Request / 413 Payload Too Large).
        // The previous `!(500..600)` guard let any non-5xx (e.g. a 200/3xx/auth) carrying a
        // `context_length_exceeded` code masquerade as ContextLength; restrict to the precise
        // request-size set so it can never mask a non-request-size status.
        if code == crate::forward::PROVIDER_CODE_CONTEXT_LENGTH
            && (raw.http_status == 400 || raw.http_status == 413)
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(code.clone()),
                retry_after: raw.retry_after_secs,
            };
        }
        // Code not in map or invalid mapping — fall through to HTTP classification
        Some(code.clone())
    } else {
        None
    };

    // Step 1b: the provider's structured error *type* is a second data-driven signal — an operator
    // can map it in error_map just like a code (useful when a provider has no numeric code but a
    // typed `error.type`). The explicit code (above) wins; this refines when the code didn't match.
    if let Some(ref ty) = raw.structured_type {
        // Resolve the mapped class, warning (once) if the operator mapped this type to an
        // unrecognized status-class string — otherwise it is silently ignored and falls through.
        let mapped = error_map.get(ty).and_then(|m| {
            let class = status_class_from_str(m);
            if class.is_none() {
                warn_unrecognized_error_map_value(m);
            }
            class
        });
        if let Some(class) = mapped {
            // Same CLASS guard as the code path above: a structured-type signal mapped to
            // `context_length` on a 5xx must not mask the upstream outage — fall through to
            // HTTP-status classification so the lane is penalized.
            if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                return CanonicalSignal {
                    class,
                    provider_signal: provider_signal.or_else(|| Some(ty.clone())),
                    retry_after: raw.retry_after_secs,
                };
            }
        }
    }

    // Step 2: Classify by HTTP status (universal spec; exhaustive match)
    let http_status = raw.http_status;
    let class = if http_status == 401 || http_status == 403 {
        StatusClass::Auth
    } else if http_status == 429 {
        StatusClass::RateLimit
    } else if http_status == 408 {
        StatusClass::Timeout
    } else if http_status == HTTP_OVERLOADED {
        StatusClass::Overloaded
    } else if (500..600).contains(&http_status) {
        StatusClass::ServerError
    } else if (400..500).contains(&http_status) {
        // True 4xx (other than the 401/403/408/429 handled above) — caller's fault.
        StatusClass::ClientError
    } else {
        // Unexpected non-error status (2xx/3xx) reaching the error path — e.g. a misconfigured
        // base_url issuing redirects the client didn't follow. The LANE is not at fault, so we do
        // NOT penalize the breaker; classifying as ClientError → ClientFault relays it verbatim and
        // records nothing. (A 3xx is genuinely not a client error, but ClientFault is the closest
        // "record nothing, relay as-is" disposition; revisit if a benign/Unknown class is added.)
        StatusClass::ClientError
    };

    CanonicalSignal {
        class,
        provider_signal,
        retry_after: raw.retry_after_secs,
    }
}

/// Canonical signal emitted by protocol normalizers.
/// Stage 1 output → Stage 2 input.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalSignal {
    pub(crate) class: StatusClass,
    pub(crate) provider_signal: Option<String>,
    pub(crate) retry_after: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_structured_type_drives_error_map() {
        // No provider code, but a structured error type the operator mapped to `overloaded`.
        let raw = RawUpstreamError {
            http_status: 400, // would otherwise classify as ClientError
            provider_code: None,
            structured_type: Some("model_overloaded".to_string()),
            retry_after_secs: None,
        };
        let map = err_map(&[("model_overloaded", "overloaded")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::Overloaded);
        assert_eq!(sig.provider_signal.as_deref(), Some("model_overloaded"));
    }

    #[test]
    fn test_provider_code_wins_over_structured_type() {
        let raw = RawUpstreamError {
            http_status: 500,
            provider_code: Some("1302".to_string()),
            structured_type: Some("server_error".to_string()),
            retry_after_secs: None,
        };
        // Both mapped; the explicit code takes precedence.
        let map = err_map(&[("1302", "rate_limit"), ("server_error", "server_error")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::RateLimit);
    }

    #[test]
    fn test_builtin_context_length_on_real_400_classifies_context_length() {
        // A genuine 400 carrying the canonical context-length code is ContextLength: the lane is
        // healthy, fail over without penalizing the breaker.
        let raw = RawUpstreamError {
            http_status: 400,
            provider_code: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::ContextLength);
        assert_eq!(
            sig.provider_signal.as_deref(),
            Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
        );
    }

    #[test]
    fn test_builtin_context_length_not_recognized_on_5xx() {
        // A 5xx is a real upstream server failure, never a context-length error. Even if the body
        // happens to carry a `context_length_exceeded` code, it must classify as ServerError (→
        // TransientUpstream) so the breaker is penalized — NOT ContextLength.
        let raw = RawUpstreamError {
            http_status: 503,
            provider_code: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::ServerError);
    }

    #[test]
    fn test_operator_error_map_overrides_builtin_context_length() {
        // The operator error_map is checked first and returns early, so it countermands the
        // built-in context-length recognition even for the canonical code on a 400.
        let raw = RawUpstreamError {
            http_status: 400,
            provider_code: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let map = err_map(&[(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH, "client_error")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::ClientError);
    }

    #[test]
    fn test_operator_map_context_length_on_5xx_is_penalized() {
        // R27 #8/#3 regression: an operator error_map mapping a provider code to
        // `context_length` on a 503 must NOT mask the upstream outage. The early return is
        // suppressed and we fall through to HTTP-status classification → ServerError
        // (TransientUpstream), so the breaker is penalized. (Fails against pre-R27 code, which
        // returned ContextLength.)
        let raw = RawUpstreamError {
            http_status: 503,
            provider_code: Some("1234".to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let map = err_map(&[("1234", "context_length")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::ServerError);
        assert_eq!(classify(&sig), Disposition::TransientUpstream);
    }

    #[test]
    fn test_operator_map_context_length_on_400_still_classifies_context_length() {
        // Companion to the 5xx case: a genuine request-size 400 mapped to `context_length`
        // still resolves to ContextLength (fail over without penalty). The guard only fires
        // on 5xx.
        let raw = RawUpstreamError {
            http_status: 400,
            provider_code: Some("1234".to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let map = err_map(&[("1234", "context_length")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::ContextLength);
    }

    #[test]
    fn test_structured_type_context_length_on_5xx_is_penalized() {
        // Same CLASS guard on the structured-type path: a typed signal mapped to
        // `context_length` on a 502 must fall through to ServerError, not mask the outage.
        // (Fails against pre-R27 code, which returned ContextLength.)
        let raw = RawUpstreamError {
            http_status: 502,
            provider_code: None,
            structured_type: Some("ctx_overflow".to_string()),
            retry_after_secs: None,
        };
        let map = err_map(&[("ctx_overflow", "context_length")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::ServerError);
        assert_eq!(classify(&sig), Disposition::TransientUpstream);
    }

    #[test]
    fn test_builtin_context_length_not_recognized_on_non_request_size_4xx() {
        // R27 #3 tighten regression: the built-in context_length code only applies to the
        // oversized-request statuses (400/413). A 403 carrying the canonical code must NOT be
        // reclassified as ContextLength; it falls through to HTTP classification (Auth here).
        // (Fails against pre-R27 code, whose `!(500..600)` guard accepted any non-5xx.)
        let raw = RawUpstreamError {
            http_status: 403,
            provider_code: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::Auth);
    }

    #[test]
    fn test_builtin_context_length_recognized_on_413() {
        // 413 Payload Too Large is the other oversized-request status the tightened guard
        // accepts for the built-in context_length code.
        let raw = RawUpstreamError {
            http_status: 413,
            provider_code: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
            structured_type: None,
            retry_after_secs: None,
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::ContextLength);
    }

    #[test]
    fn test_unmapped_structured_type_falls_through_to_http() {
        let raw = RawUpstreamError {
            http_status: 429,
            provider_code: None,
            structured_type: Some("something_unmapped".to_string()),
            retry_after_secs: None,
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::RateLimit); // from HTTP 429
    }
}
