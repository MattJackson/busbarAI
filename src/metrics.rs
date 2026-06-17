// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Prometheus metrics: a process-wide recorder + the `/metrics` exposition.
//!
//! `init()` installs a single global `metrics-exporter-prometheus` recorder. Emission sites
//! across the codebase use the `metrics` facade macros (`counter!`/`histogram!`/`gauge!`), which
//! route to that recorder. `render()` produces the current Prometheus text exposition, served by
//! `handler()` on `GET /metrics`.
//!
//! ## Scrape-time gauges
//!
//! Three families of gauges are REFRESHED AT SCRAPE TIME (in `handler()`) from already-available
//! in-process reads. They are NOT emitted on the request hot path:
//!
//! * **`busbar_key_spend_cents`** — per-virtual-key accumulated spend in the current budget window
//!   (cents). Only populated when governance is enabled.
//! * **`busbar_key_budget_remaining_cents`** — max_budget_cents minus spend for keys that carry a
//!   budget cap. Enables Prometheus burn-rate alerts on a bounded, operator-configured label space.
//! * **`busbar_key_tokens_total`** — accumulated tokens consumed by each virtual key in the current
//!   budget window. Useful for token-cost dashboards.
//! * **`busbar_lane_state`** — per-(pool, lane-index) health gauge: 0 = healthy/closed, 1 =
//!   half-open (cooling but at least one cell admits), 2 = tripped (all cells Open or hard-down).
//!   Labels use ONLY configured pool names and numeric lane indices — both bounded by operator
//!   config, never client-supplied values.
//!
//! ## Cardinality invariant
//!
//! Every label on every metric in this module is drawn from a FINITE, OPERATOR-CONTROLLED set:
//! * `pool` — the name of a configured pool (`app.pools` key-set), or the sentinel `"unresolved"`.
//! * `key` — the virtual-key id (a hex prefix of the key's secret hash, operator-issued, bounded
//!   by the count of created keys — never the raw bearer token).
//! * `lane` — a numeric index (bounded by the count of configured lanes, a startup constant).
//! * Fixed enumerations (`outcome`, `disposition`, `reason`, `from`, `to`, `ingress_protocol`).
//!
//! Client-supplied values (raw model strings from request bodies, user-facing key secrets, etc.)
//! MUST NOT appear as metric labels. See the taxonomy constant block below for per-metric notes.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::{Arc, OnceLock};

use crate::state::App;

// `Option` inside the cell so the (run-exactly-once) initializer can record an install FAILURE
// without panicking: `None` = install was attempted and failed; `Some(handle)` = installed. The
// `OnceLock` still serializes the single global `install_recorder()` call across threads/tests.
static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// The canonical busbar metric taxonomy. Names are referenced here so the emission sites and the
/// descriptions below stay in one authoritative list.
///
/// BOUNDED-CARDINALITY CONTRACT — the `pool` label.
/// Every metric below that carries a `pool` label is part of a finite, operator-controlled label
/// space. The value of `pool` MUST be EITHER the canonical name of a pool configured in `app.pools`
/// (resolved via `app.by_model`), OR the fixed sentinel `"unresolved"` used when a request is
/// terminated before its model is resolved to a configured pool (e.g. a governance rejection —
/// 400/401/403/429 — that fires before pool resolution).
///
/// Emission sites MUST NOT pass the raw, client-supplied model string as `pool`. A virtual key with
/// a restricted `allowed_pools` list could otherwise submit unbounded distinct model strings, each
/// rejected yet each minting a brand-new time series, growing the Prometheus registry without bound
/// — a low-effort memory-exhaustion DoS that also bloats every `/metrics` scrape. The label space
/// is bounded BY CONSTRUCTION: |configured pools| + 1. The same rule applies to any request-log /
/// webhook field that mirrors `pool`. The `lane`, `reason`, `disposition`, `outcome`,
/// `ingress_protocol`, `from`, and `to` labels are likewise drawn from fixed enumerations, never
/// from free-form client input.
pub(crate) const REQUESTS_TOTAL: &str = "busbar_requests_total"; // labels: ingress_protocol, pool (bounded), outcome
pub(crate) const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total"; // labels: pool (bounded), lane
pub(crate) const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total"; // labels: pool (bounded), lane, disposition
pub(crate) const BREAKER_TRIPS_TOTAL: &str = "busbar_breaker_trips_total"; // labels: pool (bounded), lane
pub(crate) const FAILOVERS_TOTAL: &str = "busbar_failovers_total"; // labels: pool (bounded), reason
pub(crate) const REQUEST_DURATION_SECONDS: &str = "busbar_request_duration_seconds"; // histogram; labels: pool (bounded)
pub(crate) const TRANSLATIONS_TOTAL: &str = "busbar_translations_total"; // labels: from, to

// Routing-policy selections: incremented once per request whose pool resolved a non-default routing
// policy that produced a ranked order (Prefer / on_error: first). `policy` is the native/transport
// NAME (a fixed enumeration: cheapest/fastest/least_busy/usage/webhook/script) and `pool` is the
// configured pool name (bounded at startup) — both safe, bounded labels (no request-derived data).
pub(crate) const ROUTE_POLICY_SELECTIONS_TOTAL: &str = "busbar_route_policy_selections_total"; // labels: policy, pool

// ── Scrape-time gauges (new in feat/observability-depth) ────────────────────────────────────────
//
// These are REFRESHED each scrape from in-process reads (governance SQLite + breaker state).
// They are NOT emitted on the hot request path and carry no request-time client data.
//
// CARDINALITY PROOF:
// * `busbar_key_spend_cents` / `busbar_key_budget_remaining_cents` / `busbar_key_tokens_total`:
//   label `key` = the virtual-key id (a `vk_<16-hex-char>` prefix derived from the secret hash).
//   The label space = {all virtual keys ever created}, which is strictly bounded by the operator
//   (keys are minted via the admin API; an operator can only create as many as they choose). The
//   raw bearer secret is NEVER used as a label value; only the operator-visible `id` field is used.
//   Client requests cannot mint new keys or introduce new label values.
//
// * `busbar_lane_state`: labels `pool` (configured pool name set — bounded by Cargo at startup) and
//   `lane` (numeric index 0..N-1, where N = number of configured lanes — a startup constant).
//   Neither label can be influenced by a client request.

/// Per-virtual-key spend in cents for the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id (operator-bounded). Only emitted when governance is enabled.
pub(crate) const KEY_SPEND_CENTS: &str = "busbar_key_spend_cents";

/// Max budget minus current spend for keys that carry a `max_budget_cents` cap. Scrape-time gauge.
/// Enables Prometheus burn-rate alerting against a bounded, operator-controlled label set.
/// Label: `key` = virtual-key id. Only emitted for keys with a budget cap.
pub(crate) const KEY_BUDGET_REMAINING_CENTS: &str = "busbar_key_budget_remaining_cents";

/// Accumulated tokens consumed by each virtual key in the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id. Only emitted when governance is enabled.
pub(crate) const KEY_TOKENS_TOTAL: &str = "busbar_key_tokens_total";

/// Per-(pool, lane-index) circuit-breaker health gauge.
/// Values: 0 = healthy (Closed), 1 = half-open (cooling but probe admitted), 2 = tripped (Open /
/// hard-down). Scrape-time gauge; side-effect-free (does not trigger Open→HalfOpen transitions).
/// Labels: `pool` (configured pool name, bounded) and `lane` (numeric index, bounded).
pub(crate) const LANE_STATE: &str = "busbar_lane_state";

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
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
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
        ROUTE_POLICY_SELECTIONS_TOTAL,
        "Requests whose routing policy produced a ranked order, by policy name and pool"
    );
    describe_counter!(
        TRANSLATIONS_TOTAL,
        "Cross-protocol translations, by source and target protocol"
    );
    describe_histogram!(
        REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "End-to-end request duration in seconds"
    );
    // Scrape-time gauges.
    describe_gauge!(
        KEY_SPEND_CENTS,
        Unit::Count,
        "Per-virtual-key accumulated spend in cents for the current budget window (scrape-time)"
    );
    describe_gauge!(
        KEY_BUDGET_REMAINING_CENTS,
        Unit::Count,
        "Per-virtual-key budget remaining in cents (max_budget_cents - spend); only for capped keys (scrape-time)"
    );
    describe_gauge!(
        KEY_TOKENS_TOTAL,
        Unit::Count,
        "Per-virtual-key accumulated tokens consumed in the current budget window (scrape-time)"
    );
    describe_gauge!(
        LANE_STATE,
        Unit::Count,
        "Per-(pool,lane) circuit-breaker health: 0=healthy, 1=half-open, 2=tripped (scrape-time)"
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

/// Refresh all scrape-time gauges from in-process reads. Called on every `/metrics` scrape so
/// values are current at observation time. The reads are all side-effect-free:
/// * Governance: `GovState::usage_for` queries the SQLite store (offloaded to the blocking pool
///   by the caller when in async context, or inline in unit tests).
/// * Lane health: `store.snapshot()` + `store.cooldown_remaining_in()` — pure atomic reads that
///   do NOT trigger Open→HalfOpen transitions or acquire the single-flight recovery probe.
///
/// No-op when governance is disabled (the governance arc is `None`). Pool and lane label spaces
/// are bounded by the operator's configuration; virtual-key ids are bounded by the set of
/// keys the admin has created. No client-supplied label values are ever emitted.
pub(crate) fn refresh_scrape_gauges(app: &App) {
    let now = crate::state::now();

    // ── Governance: per-key spend, budget-remaining, tokens ────────────────────────────────────
    if let Some(gov) = &app.governance {
        // `all_keys()` lists every VirtualKey from the SQLite store; this is a low-frequency scrape
        // path. On error we skip the gauge refresh rather than returning a stale/wrong value.
        let keys = match gov.all_keys() {
            Ok(ks) => ks,
            Err(e) => {
                tracing::warn!(error = %e, "metrics scrape: failed to list virtual keys; skipping spend gauges");
                return;
            }
        };
        // Cap per-key gauge emission. Above this many keys, emitting one series per key per scrape
        // (×3 gauges) would blow up Prometheus cardinality AND walk the store once per key on every
        // scrape. Bound BOTH by emitting at most `KEY_GAUGE_LIMIT` keys; warn when truncating so the
        // condition is visible. Generous default — normal deployments never reach it. (A configurable
        // limit / top-N-by-spend selection is a v1.x refinement.)
        const KEY_GAUGE_LIMIT: usize = 2000;
        if keys.len() > KEY_GAUGE_LIMIT {
            tracing::warn!(
                key_count = keys.len(),
                limit = KEY_GAUGE_LIMIT,
                "metrics scrape: virtual-key count exceeds per-key gauge limit; emitting gauges for \
                 only the first `limit` keys to bound cardinality and scrape-path DB load",
            );
        }
        for key in keys.iter().take(KEY_GAUGE_LIMIT) {
            // `usage_for` queries the SQLite store for the key's current-window counters.
            let usage = match gov.usage_for(&key.id, now) {
                Ok(Some(u)) => u,
                Ok(None) => continue, // key vanished between list and get — skip
                Err(e) => {
                    tracing::warn!(key = %key.id, error = %e, "metrics scrape: usage read failed; skipping key");
                    continue;
                }
            };
            // key label = the operator-visible virtual-key id (`vk_<hex>`), never the bearer secret.
            metrics::gauge!(KEY_SPEND_CENTS, "key" => key.id.clone()).set(usage.spend_cents as f64);
            metrics::gauge!(KEY_TOKENS_TOTAL, "key" => key.id.clone()).set(usage.tokens as f64);
            // Budget-remaining: only for keys that carry a `max_budget_cents` cap.
            if let Some(max) = key.max_budget_cents {
                let remaining = max.saturating_sub(usage.spend_cents).max(0);
                metrics::gauge!(KEY_BUDGET_REMAINING_CENTS, "key" => key.id.clone())
                    .set(remaining as f64);
            }
        }
    }

    // ── Lane health: per-(pool, lane-index) breaker state ──────────────────────────────────────
    // For each configured pool, iterate the pool's lane members. The lane state is derived from
    // the lane snapshot (dead flag, aggregate usability, aggregate cooldown remaining), which are
    // pure atomic reads — no FSM transitions are triggered. The `lane` label value is the numeric
    // lane index (a startup-constant bound by the configured lane count), not the model string.
    //
    // State derivation (3-state: 0=healthy, 1=half-open, 2=tripped):
    //   dead || (!usable && cooldown > 0) → 2 (hard-down or all cells Open)
    //   usable && cooldown > 0            → 1 (some cells admit but aggregate cooling down)
    //   usable && cooldown == 0           → 0 (healthy / all cells Closed)
    for (pool_name, weighted_lanes) in &app.pools {
        for wl in weighted_lanes {
            let lane_idx = wl.idx;
            let snap = app.store.snapshot(lane_idx, now);
            // Per-pool cooldown check: use `cooldown_remaining_in` for this specific (pool, lane)
            // cell, not the lane-wide aggregate from the snapshot (which may reflect a different
            // pool's cell). This gives per-pool accuracy without touching the FSM.
            let pool_cooldown = app.store.cooldown_remaining_in(pool_name, lane_idx, now);
            let state_val: f64 = if snap.dead || (pool_cooldown > 0 && !snap.usable) {
                2.0 // hard-down or all cells Open/tripped
            } else if pool_cooldown > 0 {
                1.0 // HalfOpen: this cell has a non-zero cooldown but the lane still admits
            } else {
                0.0 // Closed / healthy
            };
            let lane_label = lane_idx.to_string();
            metrics::gauge!(
                LANE_STATE,
                "pool" => pool_name.clone(),
                "lane" => lane_label
            )
            .set(state_val);
        }
    }
}

/// `GET /metrics` — Prometheus text exposition (OpenMetrics-compatible 0.0.4).
///
/// Refreshes all scrape-time gauges (spend, budget-remaining, tokens, lane health) from
/// in-process reads immediately before rendering, so values are current at observation time.
pub(crate) async fn handler(State(app): State<Arc<App>>) -> Response {
    // Refresh scrape-time gauges on a blocking thread so the SQLite usage reads do not stall
    // the Tokio executor. `refresh_scrape_gauges` is synchronous (SQLite is not async), so it
    // must not run on an async task thread. `spawn_blocking` returns a `JoinHandle`; we await it
    // so the gauges are populated before `render()` reads the registry. On a join error (the
    // blocking task panicked) we log and fall through to render whatever the registry holds from
    // the previous scrape — a slightly stale value is better than a 500.
    let app_clone = app.clone();
    let refresh = tokio::task::spawn_blocking(move || {
        refresh_scrape_gauges(&app_clone);
    });
    if let Err(e) = refresh.await {
        tracing::warn!(error = %e, "metrics scrape: gauge refresh task panicked; rendering stale gauges");
    }
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
    use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, TestApp};
    use std::sync::Arc;

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

    /// Helper: build a minimal `GovState` backed by an in-memory SQLite store.
    fn gov_with_key(key: VirtualKey) -> Arc<GovState> {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        store.put_key(&key).unwrap();
        Arc::new(GovState::new(store, 0, 0, None).unwrap())
    }

    fn sample_vkey(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            key_hash: format!("hash-{id}"),
            name: format!("key-{id}"),
            allowed_pools: vec![],
            max_budget_cents: Some(5000),
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 1_700_000_000,
        }
    }

    /// `refresh_scrape_gauges` with governance enabled must emit `KEY_SPEND_CENTS`,
    /// `KEY_TOKENS_TOTAL`, and `KEY_BUDGET_REMAINING_CENTS` for each key with a budget cap.
    #[test]
    fn test_scrape_gauges_key_spend_and_remaining() {
        init();

        let key = sample_vkey("vk_spend_test01");
        let gov = gov_with_key(key.clone());

        // Record some spend: charge 200 cents worth of usage.
        gov.record_request(&key, 1_700_000_000, 0);
        // Use a price of 0 (set in `gov_with_key`), so spend stays 0 unless we seed it directly.
        // Seed spend via the store directly for a deterministic test.
        let usage_store = gov.store();
        usage_store.add_usage(&key.id, 0, 200, 5000, false).unwrap();

        // Build a minimal App with governance.
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-a", &[(0, 1)])
            .governance(gov)
            .build();

        refresh_scrape_gauges(&app);

        let out = render();
        // The key id must appear in the output (cardinality-bounded label).
        assert!(
            out.contains("vk_spend_test01"),
            "key id must appear as label in scrape output; got:\n{out}"
        );
        assert!(
            out.contains(KEY_SPEND_CENTS),
            "spend gauge must be present; got:\n{out}"
        );
        assert!(
            out.contains(KEY_BUDGET_REMAINING_CENTS),
            "budget-remaining gauge must be present; got:\n{out}"
        );
        assert!(
            out.contains(KEY_TOKENS_TOTAL),
            "tokens gauge must be present; got:\n{out}"
        );
    }

    /// `refresh_scrape_gauges` must NOT emit `KEY_BUDGET_REMAINING_CENTS` for a key with no
    /// `max_budget_cents` cap — the gauge is meaningless without a ceiling and would just be 0.
    #[test]
    fn test_scrape_gauges_uncapped_key_no_remaining() {
        init();

        let mut key = sample_vkey("vk_uncapped_test01");
        key.max_budget_cents = None; // no cap
        let gov = gov_with_key(key);

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-b", &[(0, 1)])
            .governance(gov)
            .build();

        refresh_scrape_gauges(&app);

        let out = render();
        // The remaining gauge for the uncapped key must NOT appear.
        // NOTE: other tests in this process may have emitted it for different keys; we can only
        // check that the uncapped key id does not appear on a budget-remaining line.
        let remaining_lines: Vec<&str> = out
            .lines()
            .filter(|l| l.contains(KEY_BUDGET_REMAINING_CENTS))
            .collect();
        for line in &remaining_lines {
            assert!(
                !line.contains("vk_uncapped_test01"),
                "uncapped key must not appear in budget_remaining_cents lines; got:\n{line}"
            );
        }
    }

    /// `refresh_scrape_gauges` with no governance must not panic and must emit `LANE_STATE` gauges.
    #[test]
    fn test_scrape_gauges_lane_state_no_governance() {
        init();

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "model-x",
                crate::proto::Protocol::openai(),
                "http://x",
            ))
            .pool("pool-x", &[(0, 1)])
            .build();

        // Must not panic.
        refresh_scrape_gauges(&app);

        let out = render();
        assert!(
            out.contains(LANE_STATE),
            "lane_state gauge must appear in exposition; got:\n{out}"
        );
        assert!(
            out.contains("pool=\"pool-x\""),
            "pool label must appear; got:\n{out}"
        );
    }

    /// A healthy lane (no cooldown, not dead) must emit `busbar_lane_state = 0`.
    #[test]
    fn test_lane_state_healthy_is_zero() {
        init();

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "model-h",
                crate::proto::Protocol::openai(),
                "http://h",
            ))
            .pool("pool-h", &[(0, 1)])
            .build();

        refresh_scrape_gauges(&app);

        let out = render();
        // Look for the lane_state line for pool-h. A healthy lane should carry value 0.
        let lane_line = out.lines().find(|l| {
            l.contains(LANE_STATE) && l.contains("pool=\"pool-h\"") && !l.starts_with('#')
        });
        assert!(
            lane_line.is_some(),
            "lane_state metric line for pool-h must be present; got:\n{out}"
        );
        let line = lane_line.unwrap();
        assert!(
            line.ends_with(" 0") || line.ends_with(" 0.0"),
            "healthy lane must have state 0; got:\n{line}"
        );
    }

    /// `refresh_scrape_gauges` must emit at most `KEY_GAUGE_LIMIT` (2000) distinct per-key series
    /// even when the governance store holds more than that many virtual keys.
    ///
    /// The truncation logic (`keys.iter().take(KEY_GAUGE_LIMIT)`) is exercised by creating
    /// KEY_GAUGE_LIMIT + 1 keys, running a scrape, and asserting the count of distinct `key=`
    /// label values in the `busbar_key_spend_cents` lines is ≤ KEY_GAUGE_LIMIT.
    ///
    /// Creating 2001 rows in an in-memory SQLite instance is fast (< 50 ms on any modern machine);
    /// using `put_key` directly on the store bypasses the `GovState` cache and is the simplest
    /// deterministic way to seed a large key set.
    #[test]
    fn test_key_gauge_limit_truncation() {
        init();
        // KEY_GAUGE_LIMIT is 2000 (a private const in `refresh_scrape_gauges`). We use the same
        // value here to keep the test self-consistent.
        const LIMIT: usize = 2000;
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());

        // Insert LIMIT + 1 keys so the truncation branch fires.
        for i in 0..=(LIMIT) {
            let id = format!("vk_limit_{i:04x}");
            let key = VirtualKey {
                id: id.clone(),
                key_hash: format!("hash-limit-{i}"),
                name: format!("key-limit-{i}"),
                allowed_pools: vec![],
                max_budget_cents: None, // no budget cap → only spend + tokens gauges
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 1_700_000_000,
            };
            store.put_key(&key).unwrap();
            // Seed minimal usage so the key has a row in usage_counters and the spend gauge is
            // actually emitted (keys with zero usage_for results are skipped).
            store.add_usage(&id, 0, 1, 10, false).unwrap();
        }

        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-limit", &[(0, 1)])
            .governance(gov)
            .build();

        refresh_scrape_gauges(&app);

        let out = render();

        // Count distinct `key=` values that appear on busbar_key_spend_cents data lines
        // (i.e. non-comment lines that contain the metric name). Each emitted series produces one
        // such line, so this counts emitted series directly.
        let spend_series_count = out
            .lines()
            .filter(|l| !l.starts_with('#') && l.contains(KEY_SPEND_CENTS))
            .filter(|l| l.contains("vk_limit_"))
            .count();

        assert!(
            spend_series_count <= LIMIT,
            "refresh_scrape_gauges must emit at most KEY_GAUGE_LIMIT ({LIMIT}) per-key series; got {spend_series_count}"
        );
        // Also assert we got at least 1 series (sanity — something was emitted).
        assert!(
            spend_series_count > 0,
            "at least one key spend series must be emitted; got 0"
        );
    }

    /// Cardinality invariant: label values in the scrape output must NOT contain raw bearer secrets
    /// (which start with `sk-bb-`). The key id (`vk_<hex>`) is the only key-identifying label.
    #[test]
    fn test_cardinality_invariant_no_raw_secret_in_labels() {
        init();

        let key = sample_vkey("vk_carinv_test01");
        let gov = gov_with_key(key);

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-ci", &[(0, 1)])
            .governance(gov)
            .build();

        refresh_scrape_gauges(&app);

        let out = render();
        assert!(
            !out.contains("sk-bb-"),
            "raw bearer secret prefix must never appear as a label value in the scrape output; got:\n{out}"
        );
    }
}
