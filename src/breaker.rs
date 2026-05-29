// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! B-301: Protocol-agnostic classifier for breaker dispositions.
//!
//! Stage 2 of the two-stage disposition pipeline:
//! - Stage 1 (src/proto.rs): per-protocol normalizer → CanonicalSignal with typed StatusClass
//! - Stage 2 (this module): protocol-agnostic classifier → Disposition
//!
//! Mapping (§7 + ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// Protocol-neutral, dialect-normalized status class.
/// Emitted by Stage 1 normalizer (Protocol::classify) in src/proto.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants reserved for future protocol normalizers
pub(crate) enum StatusClass {
    /// Rate limit / slow down — transient, may recover with retry-after
    RateLimit,
    /// Overloaded server — transient
    #[allow(dead_code)] // Reserved for future use
    Overloaded,
    /// Server error (5xx) — transient
    ServerError,
    /// Request timeout — transient
    #[allow(dead_code)] // Reserved for future use
    Timeout,
    /// Network failure — transient
    #[allow(dead_code)] // Reserved for future use
    Network,
    /// Authentication failure (401/403) — hard down, key invalid
    Auth,
    /// Billing / insufficient balance — hard down, account issue
    Billing,
    /// Client error (4xx other than 401/403) — client fault, do not penalize lane
    ClientError,
}

/// Final disposition that drives the StateStore write path.
/// Three lanes per ADR-0002:
///   - ClientFault: caller's bad input → relay verbatim, record NOTHING
///   - TransientUpstream: transient failure → cooldown + err counter
///   - HardDown: definitive signal → permanent dead state (with probe recovery)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    ClientFault,
    TransientUpstream,
    HardDown,
}

/// Convert a string to StatusClass. Returns None for unknown values.
#[allow(dead_code)] // Used by config validation
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
    }
}

/// Raw upstream error extracted from HTTP response (Stage 1a output).
#[derive(Debug, Clone)]
pub(crate) struct RawUpstreamError {
    pub http_status: u16,
    pub provider_code: Option<String>,
    #[allow(dead_code)] // structured_type reserved for future use
    pub structured_type: Option<String>,
}

/// Classify a raw upstream error into a canonical signal using an error_map.
/// Stage 1b (provider normalizer): data-driven mapping from raw errors to StatusClass.
#[allow(dead_code)] // Used by forward.rs
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
        // Code not in map or invalid mapping — fall through to HTTP classification
        Some(code.clone())
    } else {
        None
    };

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
#[derive(Debug, Clone)]
pub(crate) struct CanonicalSignal {
    pub(crate) class: StatusClass,
    #[allow(dead_code)] // provider_signal retained for future extensibility (B-301, ADR-0005)
    pub(crate) provider_signal: Option<String>,
    pub(crate) retry_after: Option<u64>,
}
