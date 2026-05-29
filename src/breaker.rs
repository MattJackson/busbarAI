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

/// Canonical signal emitted by protocol normalizers.
/// Stage 1 output → Stage 2 input.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalSignal {
    pub(crate) class: StatusClass,
    #[allow(dead_code)] // provider_signal retained for future extensibility (B-301, ADR-0005)
    pub(crate) provider_signal: Option<&'static str>,
    pub(crate) retry_after: Option<u64>,
}
