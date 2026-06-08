// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Prometheus metrics: a process-wide recorder + the `/metrics` exposition.
//!
//! `init()` installs a single global `metrics-exporter-prometheus` recorder. Emission sites
//! across the codebase use the `metrics` facade macros (`counter!`/`histogram!`/`gauge!`), which
//! route to that recorder. `render()` produces the current Prometheus text exposition, served by
//! `handler()` on `GET /metrics`.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

// `Option` inside the cell so the (run-exactly-once) initializer can record an install FAILURE
// without panicking: `None` = install was attempted and failed; `Some(handle)` = installed. The
// `OnceLock` still serializes the single global `install_recorder()` call across threads/tests.
static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// The canonical busbar metric taxonomy. Names are referenced here so the emission sites and the
/// descriptions below stay in one authoritative list.
pub(crate) const REQUESTS_TOTAL: &str = "busbar_requests_total"; // labels: ingress_protocol, pool, outcome
pub(crate) const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total"; // labels: pool, lane
pub(crate) const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total"; // labels: pool, lane, disposition
pub(crate) const BREAKER_TRIPS_TOTAL: &str = "busbar_breaker_trips_total"; // labels: pool, lane
pub(crate) const FAILOVERS_TOTAL: &str = "busbar_failovers_total"; // labels: pool, reason
pub(crate) const REQUEST_DURATION_SECONDS: &str = "busbar_request_duration_seconds"; // histogram
pub(crate) const TRANSLATIONS_TOTAL: &str = "busbar_translations_total"; // labels: from, to

/// Install the global Prometheus recorder. Idempotent: safe to call once at startup and
/// repeatedly from tests (the global recorder can only be installed once per process, so the
/// `OnceLock` guards it). Also registers HELP/TYPE descriptions for the taxonomy.
pub(crate) fn init() {
    // The global recorder can only be installed once per process, so the `OnceLock` runs this
    // initializer exactly once and serializes concurrent callers (startup + tests). On install
    // FAILURE — typically because another library already installed a global recorder — we log and
    // store `None` rather than panicking: `init()` runs on a background thread (main.rs:134) where a
    // panic would be silent, leaving `/metrics` empty with no operator-visible cause. Storing `None`
    // degrades gracefully (empty exposition) AND emits an error log so the cause is discoverable.
    HANDLE.get_or_init(|| match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            describe();
            Some(handle)
        }
        Err(e) => {
            tracing::error!("prometheus recorder install failed; /metrics will be empty: {e}");
            None
        }
    });
}

fn describe() {
    use metrics::{describe_counter, describe_histogram, Unit};
    describe_counter!(
        REQUESTS_TOTAL,
        "Total ingress requests, by ingress protocol, pool, and outcome"
    );
    describe_counter!(
        UPSTREAM_ATTEMPTS_TOTAL,
        "Upstream call attempts, by pool and lane"
    );
    describe_counter!(
        UPSTREAM_FAILURES_TOTAL,
        "Upstream failures, by pool, lane, and breaker disposition"
    );
    describe_counter!(
        BREAKER_TRIPS_TOTAL,
        "Circuit-breaker trips, by pool and lane"
    );
    describe_counter!(FAILOVERS_TOTAL, "Failover events, by pool and reason");
    describe_counter!(
        TRANSLATIONS_TOTAL,
        "Cross-protocol translations, by source and target protocol"
    );
    describe_histogram!(
        REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "End-to-end request duration in seconds"
    );
}

/// Render the current Prometheus exposition text. Empty until `init()` has run.
pub(crate) fn render() -> String {
    // Outer `None` = `init()` not yet run; inner `None` = recorder install failed. Both render an
    // empty exposition rather than panicking.
    match HANDLE.get() {
        Some(Some(h)) => h.render(),
        _ => String::new(),
    }
}

/// `GET /metrics` — Prometheus text exposition (OpenMetrics-compatible 0.0.4).
pub(crate) async fn handler() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_exposes_emitted_counter() {
        init();
        metrics::counter!(
            REQUESTS_TOTAL,
            "ingress_protocol" => "anthropic",
            "pool" => "default",
            "outcome" => "ok"
        )
        .increment(1);

        let out = render();
        assert!(
            out.contains(REQUESTS_TOTAL),
            "exposition should contain the emitted counter; got:\n{out}"
        );
        // The label set and incremented value should be present in the scrape.
        assert!(
            out.contains("outcome=\"ok\""),
            "label should render; got:\n{out}"
        );
    }

    #[test]
    fn test_init_is_idempotent_and_does_not_panic() {
        // Regression: `init()` no longer `expect()`s the recorder install. Calling it repeatedly
        // (as startup + every test does) must be a no-op past the first install and must never
        // panic — even though the global recorder can only be installed once per process. A second
        // install attempt would fail, but the `OnceLock` short-circuits it.
        init();
        init();
        init();
        // After init, render must not panic and (in a process where install succeeded) is non-empty
        // only once a metric is emitted; the key assertion is simply that the calls return cleanly.
        let _ = render();
    }
}
