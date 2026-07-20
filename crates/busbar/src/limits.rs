// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Process-wide operational limits ("NEVER CODED CAPS"), installed from the resolved config
//! (`config::LimitsResolved`) at startup AND on every config apply/reload (the config plane
//! refreshes them live), read by the use sites that live too deep in a call stack to thread
//! `App`/`&self` through.
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

use std::sync::RwLock;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS,
    DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS, DEFAULT_RATE_SWEEP_INTERVAL,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS,
};

/// The installed limits. `None` until `install` runs; `None` means "use the historical default",
/// which is what the per-accessor fallback returns. An `RwLock` (not `OnceLock`) because the
/// config plane RE-installs on every apply/reload — limit changes take effect live. Accessors take
/// an uncontended read lock (writes happen only on config changes); the values these guard are not
/// per-byte hot (per-request/per-connection reads at most).
static INSTALLED: RwLock<Option<LimitsResolved>> = RwLock::new(None);

/// Install (or RE-install) the resolved limits process-wide: at boot from `main`'s construction
/// path, and again on every config apply/reload — the newest install wins, so operator limit
/// changes are live without restart.
pub(crate) fn install(resolved: &LimitsResolved) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(resolved.clone());
}

/// Read the installed value (or `None` when uninstalled — tests / pre-install).
fn get() -> Option<LimitsResolved> {
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The egress translate-body cap (bytes). COUPLED to ingress `request_body_max_bytes`: one knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap,
/// so a body the gateway accepts inbound is always buffer-translatable on the cross-protocol egress
/// path. When uninstalled, falls back to the historical 32 MiB.
pub(crate) fn translate_body_max_bytes() -> usize {
    get()
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(DEFAULT_REQUEST_BODY_MAX_BYTES)
}

/// TLS handshake wall-clock bound (seconds), read per accepted connection in `tls::serve_one`.
pub(crate) fn tls_handshake_timeout_secs() -> u64 {
    get()
        .map(|l| l.tls_handshake_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS)
}

/// Cap on a buffered upstream ERROR / verbatim-relay body (bytes).
pub(crate) fn upstream_error_body_max_bytes() -> usize {
    get()
        .map(|l| l.upstream_error_body_max_bytes)
        // No standalone const re-export needed: the resolved value always carries the default.
        .unwrap_or(crate::config::DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES)
}

/// Max concurrent webhook deliveries.
pub(crate) fn max_inflight_webhook_deliveries() -> usize {
    get()
        .map(|l| l.max_inflight_webhook_deliveries)
        .unwrap_or(crate::config::DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES)
}

/// Per-delivery webhook timeout (seconds).
pub(crate) fn webhook_delivery_timeout_secs() -> u64 {
    get()
        .map(|l| l.webhook_delivery_timeout_secs)
        .unwrap_or(DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS)
}

/// Max per-key gauge series emitted per `/metrics` scrape.
pub(crate) fn key_gauge_limit() -> usize {
    get()
        .map(|l| l.key_gauge_limit)
        .unwrap_or(DEFAULT_KEY_GAUGE_LIMIT)
}

/// Rate-limiter stale-entry sweep amortization interval.
pub(crate) fn rate_sweep_interval() -> u32 {
    get()
        .map(|l| l.rate_sweep_interval)
        .unwrap_or(DEFAULT_RATE_SWEEP_INTERVAL)
}

/// Write-behind flush cadence (ms) for the in-memory governance usage/budget counters. On an
/// UNGRACEFUL crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be
/// lost; a graceful shutdown flushes fully (the flusher's shutdown arm). Default 100.
pub(crate) fn usage_flush_interval_ms() -> u64 {
    get()
        .map(|l| l.usage_flush_interval_ms)
        .unwrap_or(DEFAULT_USAGE_FLUSH_INTERVAL_MS)
}

/// Process-wide active-probe interval fallback (seconds). Per-lane `health.interval_secs` overrides.
pub(crate) fn default_probe_interval_secs() -> u64 {
    get()
        .map(|l| l.default_probe_interval_secs)
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
}

/// Process-wide active-probe timeout fallback (seconds). Per-lane `health.timeout_secs` overrides.
pub(crate) fn default_probe_timeout_secs() -> u64 {
    get()
        .map(|l| l.default_probe_timeout_secs)
        .unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS)
}

/// Global default routing-policy timeout (ms). Per-policy `policy.timeout_ms` overrides.
pub(crate) fn default_policy_timeout_ms() -> u64 {
    get()
        .map(|l| l.default_policy_timeout_ms)
        .unwrap_or(DEFAULT_POLICY_TIMEOUT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UNINSTALLED accessors return the historical hardcoded defaults — an un-installed (or
    /// default-config-installed) process is byte-for-byte today's behavior. `install` is
    /// re-runnable (the config plane refreshes limits live), so another test in this binary MAY
    /// have installed by the time this runs; every in-test installer uses a default-limits config,
    /// making the assertions below hold in either order. A future test installing NON-default
    /// limits would break this — give such a test its own values and this note is the pointer.
    #[test]
    fn uninstalled_accessors_return_historical_defaults() {
        assert_eq!(translate_body_max_bytes(), DEFAULT_REQUEST_BODY_MAX_BYTES);
        assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
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
