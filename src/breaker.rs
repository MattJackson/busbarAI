// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Protocol-agnostic classifier for breaker dispositions.
//!
//! Stage 2 of the two-stage disposition pipeline:
//! - Stage 1 (src/proto.rs): per-protocol normalizer → CanonicalSignal with typed StatusClass
//! - Stage 2 (this module): protocol-agnostic classifier → Disposition
//!
//! Mapping (+ ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// Protocol-neutral, dialect-normalized status class.
/// Emitted by Stage 1 normalizer (Protocol::classify) in src/proto.rs.
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
    pub http_status: u16,
    /// Provider-specific error *code* (e.g. a numeric `code` field), checked against `error_map`.
    pub provider_code: Option<String>,
    /// Provider-specific structured error *type* (e.g. a `type`/`error.type` string), checked
    /// against `error_map` as a second signal when the code doesn't match.
    pub structured_type: Option<String>,
}

/// Classify a raw upstream error into a canonical signal using an error_map.
/// Stage 1b (provider normalizer): data-driven mapping from raw errors to StatusClass.
pub(crate) fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
) -> CanonicalSignal {
    // Step 1: Check if provider_code is in error_map (provider override; A3 "codes refine")
    let provider_signal = if let Some(ref code) = raw.provider_code {
        if let Some(mapped_class) = error_map.get(code) {
            if let Some(class) = status_class_from_str(mapped_class) {
                return CanonicalSignal {
                    class,
                    provider_signal: Some(code.clone()),
                    retry_after: None,
                };
            }
        }
        // built-in recognition of the canonical context-length code (the operator
        // error_map above overrides; this is the default when unmapped). The lane is healthy —
        // ContextLength → fail over without penalty.
        if code == "context_length_exceeded" {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(code.clone()),
                retry_after: None,
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
        if let Some(class) = error_map.get(ty).and_then(|m| status_class_from_str(m)) {
            return CanonicalSignal {
                class,
                provider_signal: provider_signal.or_else(|| Some(ty.clone())),
                retry_after: None,
            };
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
    } else if http_status == 529 {
        StatusClass::Overloaded
    } else if (500..600).contains(&http_status) {
        StatusClass::ServerError
    } else if (400..500).contains(&http_status) {
        StatusClass::ClientError
    } else {
        // Default for non-error cases (2xx, 3xx) — safe default that won't trip breaker
        StatusClass::ClientError
    };

    CanonicalSignal {
        class,
        provider_signal,
        retry_after: None,
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
        };
        // Both mapped; the explicit code takes precedence.
        let map = err_map(&[("1302", "rate_limit"), ("server_error", "server_error")]);
        let sig = normalize_raw_error(&raw, &map);
        assert_eq!(sig.class, StatusClass::RateLimit);
    }

    #[test]
    fn test_unmapped_structured_type_falls_through_to_http() {
        let raw = RawUpstreamError {
            http_status: 429,
            provider_code: None,
            structured_type: Some("something_unmapped".to_string()),
        };
        let sig = normalize_raw_error(&raw, &HashMap::new());
        assert_eq!(sig.class, StatusClass::RateLimit); // from HTTP 429
    }
}
