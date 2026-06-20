// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Process-wide operational limits ("NEVER CODED CAPS"), installed ONCE at startup from the
//! resolved config (`config::LimitsResolved`) and read by the use sites that live too deep in a
//! call stack to thread `App`/`&self` through — mirroring the existing `OnceLock` set-once idiom in
//! `observability.rs`.
//!
//! Each accessor returns the operator-configured value when `install` has run, and otherwise the
//! HISTORICAL hardcoded default (the same `config::DEFAULT_*` const the serde defaults use). So a
//! unit test that never calls `install` sees byte-for-byte today's behavior, and a double-`install`
//! (only `main` calls it) is a no-op rather than a panic.
//!
//! Values threaded explicitly (the upstream client timeout/pool-idle, the axum `DefaultBodyLimit`,
//! the inbound concurrency layer, the TLS handshake bound, and the store's hard-down /
//! retry-after ceiling) do NOT live here — they reach their site directly from `RootCfg.limits`.
//! This module is only for the sites without such a path.

use std::sync::OnceLock;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS,
    DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS, DEFAULT_RATE_SWEEP_INTERVAL,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
    DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS,
};

/// The installed limits. Unset until `install` runs (then the use sites read it); an unset cell
/// means "use the historical default", which is what the per-accessor fallback returns.
static INSTALLED: OnceLock<LimitsResolved> = OnceLock::new();

/// Install the resolved limits process-wide. Called ONCE from `main` after config resolution, before
/// any router/store/prober is built. A second call is ignored (the first install wins) so the
/// startup ordering can never panic here.
pub(crate) fn install(resolved: &LimitsResolved) {
    let _ = INSTALLED.set(resolved.clone());
}

/// The egress translate-body cap (bytes). COUPLED to ingress `request_body_max_bytes`: one knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap,
/// so a body the gateway accepts inbound is always buffer-translatable on the cross-protocol egress
/// path. When uninstalled, falls back to the historical 32 MiB.
pub(crate) fn translate_body_max_bytes() -> usize {
    INSTALLED
        .get()
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(DEFAULT_REQUEST_BODY_MAX_BYTES)
}

/// TLS handshake wall-clock bound (seconds), read per accepted connection in `tls::serve_one`.
pub(crate) fn tls_handshake_timeout_secs() -> u64 {
    INSTALLED
        .get()
        .map(|l| l.tls_handshake_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS)
}

/// Cap on a buffered upstream ERROR / verbatim-relay body (bytes).
pub(crate) fn upstream_error_body_max_bytes() -> usize {
    INSTALLED
        .get()
        .map(|l| l.upstream_error_body_max_bytes)
        // No standalone const re-export needed: the resolved value always carries the default.
        .unwrap_or(crate::config::DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES)
}

/// Max concurrent webhook deliveries.
pub(crate) fn max_inflight_webhook_deliveries() -> usize {
    INSTALLED
        .get()
        .map(|l| l.max_inflight_webhook_deliveries)
        .unwrap_or(crate::config::DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES)
}

/// Per-delivery webhook timeout (seconds).
pub(crate) fn webhook_delivery_timeout_secs() -> u64 {
    INSTALLED
        .get()
        .map(|l| l.webhook_delivery_timeout_secs)
        .unwrap_or(DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS)
}

/// Max per-key gauge series emitted per `/metrics` scrape.
pub(crate) fn key_gauge_limit() -> usize {
    INSTALLED
        .get()
        .map(|l| l.key_gauge_limit)
        .unwrap_or(DEFAULT_KEY_GAUGE_LIMIT)
}

/// SQLite `busy_timeout` (ms) for the governance store.
pub(crate) fn sqlite_busy_timeout_ms() -> i64 {
    INSTALLED
        .get()
        .map(|l| l.sqlite_busy_timeout_ms)
        .unwrap_or(DEFAULT_SQLITE_BUSY_TIMEOUT_MS)
}

/// Rate-limiter stale-entry sweep amortization interval.
pub(crate) fn rate_sweep_interval() -> u32 {
    INSTALLED
        .get()
        .map(|l| l.rate_sweep_interval)
        .unwrap_or(DEFAULT_RATE_SWEEP_INTERVAL)
}

/// Process-wide active-probe interval fallback (seconds). Per-lane `health.interval_secs` overrides.
pub(crate) fn default_probe_interval_secs() -> u64 {
    INSTALLED
        .get()
        .map(|l| l.default_probe_interval_secs)
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
}

/// Process-wide active-probe timeout fallback (seconds). Per-lane `health.timeout_secs` overrides.
pub(crate) fn default_probe_timeout_secs() -> u64 {
    INSTALLED
        .get()
        .map(|l| l.default_probe_timeout_secs)
        .unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS)
}

/// Global default routing-policy timeout (ms). Per-policy `policy.timeout_ms` overrides.
pub(crate) fn default_policy_timeout_ms() -> u64 {
    INSTALLED
        .get()
        .map(|l| l.default_policy_timeout_ms)
        .unwrap_or(DEFAULT_POLICY_TIMEOUT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Before `install` (the state in unit tests that never call it), every accessor returns the
    /// historical hardcoded default — so an un-installed process is byte-for-byte today's behavior.
    /// NOTE: this asserts the FALLBACK values directly rather than calling `install` (a single
    /// process-wide `OnceLock` cannot be reset between tests, and `main` is the only real installer).
    #[test]
    fn uninstalled_accessors_return_historical_defaults() {
        // Guarded: if some other test in this binary installed already, the values would be the
        // installed ones. The limits unit tests are the only `install`-free readers here, and no
        // test in this module installs, so the OnceLock stays empty and the defaults hold.
        if INSTALLED.get().is_none() {
            assert_eq!(translate_body_max_bytes(), DEFAULT_REQUEST_BODY_MAX_BYTES);
            assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
            assert_eq!(sqlite_busy_timeout_ms(), DEFAULT_SQLITE_BUSY_TIMEOUT_MS);
            assert_eq!(rate_sweep_interval(), DEFAULT_RATE_SWEEP_INTERVAL);
            assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
            assert_eq!(default_probe_timeout_secs(), DEFAULT_PROBE_TIMEOUT_SECS);
            assert_eq!(default_policy_timeout_ms(), DEFAULT_POLICY_TIMEOUT_MS);
            assert_eq!(
                webhook_delivery_timeout_secs(),
                DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
            );
        }
    }
}
