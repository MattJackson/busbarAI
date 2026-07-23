// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Prometheus metrics: a process-wide recorder + the `/metrics` exposition.
//!
//! `init()` installs a single global `metrics-exporter-prometheus` recorder. Emission sites
//! across the codebase use the `metrics` facade macros (`counter!`/`histogram!`/`gauge!`), which
//! route to that recorder. `render()` produces the current Prometheus text exposition, served by
//! `handler()` on `GET /metrics`.
//!
//! ## Scrape-time gauges
//!
//! Four families of gauges are REFRESHED AT SCRAPE TIME (in `handler()`) from already-available
//! in-process reads. They are NOT emitted on the request hot path:
//!
//! * **`busbar_key_spend_cents`** — per-virtual-key accumulated spend in the current budget window
//!   (cents). Only populated when governance is enabled.
//! * **`busbar_key_budget_remaining_cents`** — max_budget_cents minus spend for keys that carry a
//!   budget cap. Enables Prometheus burn-rate alerts on a bounded, operator-configured label space.
//! * **`busbar_key_tokens_total`** — accumulated tokens consumed by each virtual key in the current
//!   budget window. Useful for token-cost dashboards.
//! * **`busbar_lane_state`** — per-(pool, lane) health gauge: 0 = healthy/closed, 1 =
//!   half-open (cooling but at least one cell admits), 2 = tripped (all cells Open or hard-down).
//!   Labels use ONLY configured pool names and lane MODEL strings (matching the proxy engine counter
//!   sites so gauge and counters PromQL-join on `lane`) — both bounded by operator config, never
//!   client-supplied values.
//!
//! ## Cardinality invariant
//!
//! Every label on every metric in this module is drawn from a FINITE, OPERATOR-CONTROLLED set:
//! * `pool` — the name of a configured pool (`app.pools` key-set), or the sentinel `"unresolved"`.
//! * `key` — the virtual-key id (a hex prefix of the key's secret hash, operator-issued, bounded
//!   by the count of created keys — never the raw bearer token).
//! * `lane` — the lane's configured MODEL string (bounded by the count of configured lanes, a
//!   startup constant). Identical on the LANE_STATE gauge and every counter that carries `lane`, so
//!   they can be PromQL-joined on the label.
//! * Fixed enumerations (`outcome`, `disposition`, `reason`, `from`, `to`, `ingress_protocol`).
//!
//! Client-supplied values (raw model strings from request bodies, user-facing key secrets, etc.)
//! MUST NOT appear as metric labels. See the taxonomy constant block below for per-metric notes.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

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
pub(crate) const REQUEST_DURATION_SECONDS: &str = "busbar_request_duration_seconds"; // histogram; labels: ingress_protocol, pool (bounded)
pub(crate) const TRANSLATIONS_TOTAL: &str = "busbar_translations_total"; // labels: from, to

// Routing-policy selections: incremented once per request whose pool resolved a non-default routing
// policy that produced a ranked order (Prefer / on_error: first). `policy` is the native/transport
// NAME (a fixed enumeration: cheapest/fastest/least_busy/usage/webhook/script) and `pool` is the
// configured pool name (bounded at startup) — both safe, bounded labels (no request-derived data).
pub(crate) const ROUTE_POLICY_SELECTIONS_TOTAL: &str = "busbar_route_policy_selections_total"; // labels: policy, pool

// Routing-policy REJECTIONS (the hook's reject verb — a guardrail said no; a 4xx to the caller,
// no upstream dispatched). `status` is hook-influenced but BOUNDED: the forward seam that
// constructs `RejectRequest` clamps it to 400..=499 for EVERY producer (wire-normalized or
// direct-constructed), so the worst-case label fan-out is 100 per (policy, pool) — a safe label.
pub(crate) const ROUTE_POLICY_REJECTIONS_TOTAL: &str = "busbar_route_policy_rejections_total"; // labels: policy, pool, status

// Request-log webhook deliveries DROPPED because the in-flight delivery semaphore was saturated (the
// webhook endpoint is slow/unreachable and the bounded delivery pool is full). Incremented once per
// dropped log. Unlabeled — the drop is a global backpressure condition, not per-request. An operator
// alerts on a non-zero rate to detect "the webhook is overwhelmed and logs are being shed silently."
pub(crate) const WEBHOOK_LOGS_DROPPED_TOTAL: &str = "busbar_webhook_logs_dropped_total"; // no labels

// A fire-and-forget TAP notification dropped because the in-flight cap was reached (slow/unreachable
// tap endpoint). Unlabeled global backpressure. Alert on a non-zero rate.
pub(crate) const TAP_NOTIFICATIONS_DROPPED_TOTAL: &str = "busbar_tap_notifications_dropped_total";

// Same-protocol non-stream responses whose billing-side buffer hit the translate-body cap before the
// terminal `usage` block, so token usage could not be parsed and the request billed zero despite a
// full 2xx reaching the client. Incremented once per truncated response. Unlabeled. An operator
// alerts on a non-zero rate to detect an over-cap billing gap. (The client response is unaffected —
// it streams verbatim; only the billing side-channel is capped.)
pub(crate) const BILLING_TRUNCATED_TOTAL: &str = "busbar_billing_truncated_total"; // no labels

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
//   `lane` (the lane's configured MODEL string — bounded by N = number of configured lanes, a
//   startup constant; identical to the `lane` label on the proxy engine counters so the gauge and
//   counters PromQL-join). Neither label can be influenced by a client request.

/// Per-virtual-key spend in cents for the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id (operator-bounded). Only emitted when governance is enabled.
const KEY_SPEND_CENTS: &str = "busbar_key_spend_cents";

/// Accumulated tokens consumed by each virtual key in the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id. Only emitted when governance is enabled.
const KEY_TOKENS_TOTAL: &str = "busbar_key_tokens_total";

/// Per-(bucket, model, tier) token counters for the bucket's CURRENT budget window. Scrape-time
/// gauge, derived from the token ledger. `bucket` is a virtual-key id or `group:<name>` (both
/// operator-bounded); `model` is bounded by the configured fleet (an ad-hoc passthrough model is
/// only possible with pricing off); `tier` is one of the four fixed pricing tiers. Key-bucket
/// series additionally echo the key's mint-time labels, so external dashboards can
/// `sum by (team)` without busbar knowing what "team" means.
const BUCKET_TOKENS: &str = "busbar_bucket_tokens";

/// DERIVED spend (cents, abstract minor units) per BUDGET-GROUP bucket for its current window,
/// recomputed from the token ledger x the CURRENT rate card at scrape time (reprice-on-read).
/// Label: `bucket` = `group:<name>`. Key-bucket spend stays on `busbar_key_spend_cents`.
const BUCKET_SPEND_CENTS: &str = "busbar_bucket_spend_cents";

/// Cap minus derived spend per BUDGET-GROUP bucket. Label: `bucket` = `group:<name>`. The
/// external-alerting linchpin: Alertmanager fires at 80% burn without busbar shipping any
/// alerting of its own.
const BUCKET_BUDGET_REMAINING_CENTS: &str = "busbar_bucket_budget_remaining_cents";

/// Per-(pool, lane-model) circuit-breaker health gauge.
/// Values: 0 = healthy (Closed), 1 = half-open (cooling but probe admitted), 2 = tripped (Open /
/// hard-down). Scrape-time gauge; side-effect-free (does not trigger Open→HalfOpen transitions).
/// Labels: `pool` (configured pool name, bounded) and `lane` (the lane's MODEL string, bounded —
/// matches the proxy engine counter sites so the gauge and counters can be PromQL-joined on `lane`).
const LANE_STATE: &str = "busbar_lane_state";

/// Prometheus text exposition format content-type (version 0.0.4), returned by the `/metrics`
/// scrape handler. Defined as a constant so the string is not duplicated across handler and tests.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Install the global Prometheus recorder. Idempotent: safe to call once at startup and
/// repeatedly from tests (the global recorder can only be installed once per process, so the
/// `OnceLock` guards it). Also registers HELP/TYPE descriptions for the taxonomy.
pub(crate) fn init() {
    // The global recorder can only be installed once per process, so the `OnceLock` runs this
    // initializer exactly once and serializes concurrent callers (startup + tests). On install
    // FAILURE — typically because another library already installed a global recorder — we log and
    // store `None` rather than panicking: `init()` runs on a background thread (main.rs) where a
    // panic would be silent, leaving `/metrics` empty with no operator-visible cause. Storing `None`
    // degrades gracefully (empty exposition) AND emits an error log so the cause is discoverable.
    HANDLE.get_or_init(|| match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            describe();
            // Pre-register the unlabeled counter so `/metrics` is non-empty from the first
            // scrape. The exporter renders only touched metrics; without this, a freshly
            // booted gateway that has served no traffic exposes an EMPTY body, and an
            // operator wiring up Prometheus before sending traffic reasonably concludes
            // the endpoint is broken (found by the acceptance harness, 2026-07-09).
            // Only the unlabeled family is pre-touched: labeled families would require
            // inventing label values, which the cardinality contract above forbids. The
            // labeled gauges appear on the first scrape via `refresh_scrape_gauges`.
            metrics::counter!(BILLING_TRUNCATED_TOTAL).absolute(0);
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
        ROUTE_POLICY_REJECTIONS_TOTAL,
        "Requests deliberately rejected by the routing policy's reject verb, by policy name, pool, and status"
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
        BUCKET_TOKENS,
        "Per-(bucket, model, tier) tokens in the bucket's current budget window (key and budget-group buckets; derived from the token ledger at scrape time)"
    );
    describe_gauge!(
        BUCKET_SPEND_CENTS,
        Unit::Count,
        "Derived spend (abstract minor units) per budget-group bucket for its current window, recomputed from the token ledger x the current rate card at scrape time"
    );
    describe_gauge!(
        BUCKET_BUDGET_REMAINING_CENTS,
        Unit::Count,
        "Budget-group cap minus derived spend for the current window"
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

// ─── PER-REQUEST HANDLE CACHE ─────────────────────────────────────────────────────────────────────
//
// `finish_inner` emits exactly two metrics on EVERY served request: the `REQUESTS_TOTAL` counter and
// the `REQUEST_DURATION_SECONDS` histogram. Emitting them through the `counter!`/`histogram!` macros
// re-runs, per request: two owned-`String` label allocations (`ingress_protocol` + `pool`), a `Key`
// build, and a recorder registry hash+lookup — for a label set drawn from a FINITE, operator-bounded
// space (`|protocols| × (|pools| + 1) × |outcomes|`). `metrics::Counter`/`Histogram` are cheap-to-
// clone `Arc`-backed handles straight to the metric's storage that SURVIVE recorder swaps, so caching
// one per label set turns the steady-state hot path into a lock-free map read + an atomic increment —
// no per-request allocation and no registry lookup.
//
// The cache is a `RwLock<HashMap<Box<str>, Handle>>` keyed on a COMPACT single key built by joining
// the (bounded) label values with a `\x1f` unit separator — a byte that cannot appear in a protocol
// or pool name, so the join is unambiguous. Building that key is a single small allocation, but the
// steady-state path performs the lookup under a shared read lock and never touches the metrics
// registry (which would allocate the two `Label` Strings AND a `Key` AND hash+probe its own map);
// net, one small alloc replaces two label allocs + a `Key` build + a registry probe.
//
// Correctness vs. the recorder-install ordering the module contract calls out (a handle minted before
// `init()` installs the recorder binds to the no-op recorder FOREVER): the cache is populated ONLY
// once the recorder is installed (`HANDLE == Some(Some(_))`). Before that — `init()` not yet run, or
// install failed — these helpers fall through to the plain macro (itself a no-op against the default
// recorder), caching nothing. So a pre-`init()` emission is never cached, and every cached handle is
// bound to the real Prometheus recorder. In production `init()` runs at startup before any request
// reaches `finish_inner`, so the steady state is always the cached fast path.
use std::collections::HashMap;
use std::sync::RwLock;

/// Unit separator joining label values into the compact cache key — a control byte that cannot occur
/// in an ingress-protocol or pool name, so `"a\x1fb"` can never collide with `"a"` + `"\x1fb"`.
const CACHE_KEY_SEP: char = '\u{1f}';

static REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> = OnceLock::new();
static DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> = OnceLock::new();

/// True once the global Prometheus recorder is INSTALLED (not merely that `init()` was attempted).
/// Gating handle caching on this guarantees a cached handle can never be bound to the no-op recorder
/// that stands in before install.
#[inline]
fn recorder_installed() -> bool {
    matches!(HANDLE.get(), Some(Some(_)))
}

/// Increment `REQUESTS_TOTAL` for `(ingress_protocol, pool, outcome)` via a CACHED counter handle —
/// no registry lookup and no per-request `Label`/`Key` construction on the steady-state path. Falls
/// back to the plain macro until the recorder is installed (see the cache-module note above).
/// Byte-for-byte the same series and value the macro produced.
pub(crate) fn incr_requests_total(ingress_protocol: &str, pool: &str, outcome: &'static str) {
    if !recorder_installed() {
        // Pre-install: don't cache (would bind to the no-op recorder). The macro is itself a no-op.
        metrics::counter!(
            REQUESTS_TOTAL,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string(),
            "outcome" => outcome
        )
        .increment(1);
        return;
    }
    let cache = REQUESTS_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}{CACHE_KEY_SEP}{outcome}");
    // Fast path: shared-read hit (the common case — a bounded, quickly-saturated key set).
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.increment(1);
        return;
    }
    // Cold path (first time this label set is seen): register the handle once, then cache it.
    let handle = metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    );
    handle.increment(1);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

/// Record a `REQUEST_DURATION_SECONDS` observation for `(ingress_protocol, pool)` via a CACHED
/// histogram handle. Same caching contract as [`incr_requests_total`].
pub(crate) fn record_request_duration(ingress_protocol: &str, pool: &str, seconds: f64) {
    if !recorder_installed() {
        metrics::histogram!(
            REQUEST_DURATION_SECONDS,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string()
        )
        .record(seconds);
        return;
    }
    let cache = DURATION_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}");
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.record(seconds);
        return;
    }
    let handle = metrics::histogram!(
        REQUEST_DURATION_SECONDS,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    );
    handle.record(seconds);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
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
fn refresh_scrape_gauges(app: &App) {
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
        // scrape. Bound BOTH by emitting at most `key_gauge_limit` keys; warn when truncating so the
        // condition is visible. Generous default — normal deployments never reach it. (A configurable
        // limit / top-N-by-spend selection is a v1.x refinement.)
        // Operator-tunable via `metrics.key_gauge_limit` (default 2000).
        let key_gauge_limit = crate::limits::key_gauge_limit();
        if keys.len() > key_gauge_limit {
            tracing::warn!(
                key_count = keys.len(),
                limit = key_gauge_limit,
                "metrics scrape: virtual-key count exceeds per-key gauge limit; emitting gauges for \
                 only the first `limit` keys to bound cardinality and scrape-path DB load",
            );
        }
        for key in keys.iter().take(key_gauge_limit) {
            // `usage_for` queries the SQLite store for the key's current-window counters.
            let usage = match gov.usage_for(&app.cost, &key.id, now) {
                Ok(Some(u)) => u,
                Ok(None) => continue, // key vanished between list and get — skip
                Err(e) => {
                    tracing::warn!(key = %key.id, error = %e, "metrics scrape: usage read failed; skipping key");
                    continue;
                }
            };
            // key label = the operator-visible virtual-key id (`vk_<hex>`), never the bearer
            // secret. The key's MINT-TIME labels (e.g. team=growth) are echoed onto every series
            // so external Grafana can `sum by (team)` and Alertmanager can fire per team WITHOUT
            // busbar knowing what "team" means. Label KEYS are operator-chosen at mint (bounded by
            // the admin surface), never request bytes.
            let base_labels = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                let mut labels: Vec<metrics::Label> =
                    vec![metrics::Label::new("key", key.id.clone())];
                for (k, v) in &key.labels {
                    labels.push(metrics::Label::new(k.clone(), v.clone()));
                }
                for (k, v) in extra {
                    labels.push(metrics::Label::new(*k, v.clone()));
                }
                labels
            };
            metrics::gauge!(KEY_SPEND_CENTS, base_labels(&[])).set(usage.spend_cents as f64);
            metrics::gauge!(KEY_TOKENS_TOTAL, base_labels(&[])).set(usage.tokens as f64);
            // 1.5.0: keys are PURE AUTH (no inline budget cap), so there is no per-key
            // budget-remaining gauge; remaining/limit headroom lives on the GROUP buckets below.
            // Per-(bucket, model, tier) token gauges from the key bucket's ledger (the raw
            // material any external per-model cost dashboard multiplies by its own catalog). The
            // key's attribution bucket accrues in the all-time window.
            for (model, tokens) in
                gov.bucket_model_tokens(&key.id, crate::governance::WINDOW_TOTAL, now)
            {
                for (tier, v) in [
                    ("input", tokens.input),
                    ("output", tokens.output),
                    ("cache_read", tokens.cache_read),
                    ("cache_write", tokens.cache_write),
                ] {
                    let mut labels: Vec<metrics::Label> =
                        vec![metrics::Label::new("bucket", key.id.clone())];
                    for (k, val) in &key.labels {
                        labels.push(metrics::Label::new(k.clone(), val.clone()));
                    }
                    labels.push(metrics::Label::new("model", model.clone()));
                    labels.push(metrics::Label::new("tier", tier));
                    metrics::gauge!(BUCKET_TOKENS, labels).set(v as f64);
                }
            }
        }

        // ── GROUP buckets: derived spend + remaining + per-(model, tier) tokens, one series per
        // (group, window) enforcement bucket. Bounded by |groups| x |windows-in-use| (operator-
        // owned names + the fixed window vocabulary). Spend derives fresh from the ledger x the
        // CURRENT rate card (reprice-on-read), fee included (each bucket counts its own requests).
        // The `group` and `window` labels are the 1.5.0 limit dimensions; `bucket` stays the raw
        // ledger id for join-ability with the store.
        for group in app.cost.groups() {
            for bucket in &group.buckets {
                let derived = match gov.derived_bucket_usage(
                    &app.cost,
                    &bucket.bucket_id,
                    bucket.window,
                    true,
                    now,
                ) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!(bucket = %bucket.bucket_id, error = %e, "metrics scrape: group ledger read failed; skipping");
                        continue;
                    }
                };
                let dims = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                    let mut labels = vec![
                        metrics::Label::new("bucket", bucket.bucket_id.clone()),
                        metrics::Label::new("group", group.name.clone()),
                        metrics::Label::new("window", bucket.window),
                    ];
                    for (k, v) in extra {
                        labels.push(metrics::Label::new(*k, v.clone()));
                    }
                    labels
                };
                metrics::gauge!(BUCKET_SPEND_CENTS, dims(&[])).set(derived.spend_cents as f64);
                // Budget-remaining: only for a bucket that carries a `budget` cap.
                if let Some(cap) = bucket.budget_cap {
                    let remaining = cap.saturating_sub(derived.spend_cents).max(0);
                    metrics::gauge!(BUCKET_BUDGET_REMAINING_CENTS, dims(&[])).set(remaining as f64);
                }
                for (model, tokens) in
                    gov.bucket_model_tokens(&bucket.bucket_id, bucket.window, now)
                {
                    for (tier, v) in [
                        ("input", tokens.input),
                        ("output", tokens.output),
                        ("cache_read", tokens.cache_read),
                        ("cache_write", tokens.cache_write),
                    ] {
                        metrics::gauge!(
                            BUCKET_TOKENS,
                            dims(&[("model", model.clone()), ("tier", tier.to_string())])
                        )
                        .set(v as f64);
                    }
                }
            }
        }
    }

    // ── Lane health: per-(pool, lane-index) breaker state ──────────────────────────────────────
    // For each configured pool, iterate the pool's lane members. The lane state is derived from
    // the lane snapshot (dead flag, aggregate usability, aggregate cooldown remaining), which are
    // pure atomic reads — no FSM transitions are triggered. The `lane` label value is the lane's
    // MODEL string (matching the proxy engine counters; bounded one-per-configured-lane, a startup
    // constant), not a numeric index.
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
            // The `lane` label is the lane's MODEL string (NOT a numeric index), matching the
            // counter sites in proxy engine so the gauge and counters can be PromQL-joined on `lane`.
            // It is bounded one-per-configured-lane (a startup constant), so cardinality stays safe.
            let lane_label = app.lanes[lane_idx].model.clone();
            metrics::gauge!(
                LANE_STATE,
                "pool" => pool_name.clone(),
                "lane" => lane_label
            )
            .set(state_val);
        }
    }

    // Direct-model lanes (reachable via `by_model` routing, no pool required) get a lane-state
    // gauge too, labeled with the model name as `pool` — the same convention the counters use
    // for model-routed traffic (`proxy::metric_pool_label`: empty pool name → model string),
    // so gauge and counters PromQL-join. Cardinality: bounded by |configured models|, a startup
    // constant. Without this, a pool-less config (the docs' minimal getting-started config)
    // exposes NO lane gauges at all — a fresh boot rendered an empty /metrics (harness finding,
    // 2026-07-09). The breaker cell is the lane-default `""` cell, matching model-routed
    // fault attribution.
    for (model, &lane_idx) in &app.by_model {
        let snap = app.store.snapshot(lane_idx, now);
        let cooldown = app.store.cooldown_remaining_in("", lane_idx, now);
        let state_val: f64 = if snap.dead || (cooldown > 0 && !snap.usable) {
            2.0
        } else if cooldown > 0 {
            1.0
        } else {
            0.0
        };
        metrics::gauge!(
            LANE_STATE,
            "pool" => model.clone(),
            "lane" => app.lanes[lane_idx].model.clone()
        )
        .set(state_val);
    }
}

/// `GET /metrics` — Prometheus text exposition (OpenMetrics-compatible 0.0.4).
///
/// Refreshes all scrape-time gauges (spend, budget-remaining, tokens, lane health) from
/// in-process reads immediately before rendering, so values are current at observation time.
pub(crate) async fn handler(crate::state::CurrentApp(app): crate::state::CurrentApp) -> Response {
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
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
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
        let store = Arc::new(MemoryStore::new());
        store.put_key(&key).unwrap();
        Arc::new(GovState::new(store, None).unwrap())
    }

    fn sample_vkey(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            key_hash: format!("hash-{id}"),
            name: format!("key-{id}"),
            allowed_pools: None,
            enabled: true,
            created_at: 1_700_000_000,
            group: None,
            labels: Default::default(),
        }
    }

    /// `refresh_scrape_gauges` with governance enabled must emit `KEY_SPEND_CENTS`,
    /// `KEY_TOKENS_TOTAL`, and `KEY_BUDGET_REMAINING_CENTS` for each key with a budget cap.
    #[test]
    fn test_scrape_gauges_key_spend_and_remaining() {
        init();

        let key = sample_vkey("vk_spend_test01");
        let gov = gov_with_key(key.clone());

        // Seed a durable ledger directly: 200 requests (derived spend = 200 cents at the
        // TestApp default `CostModel::flat(1)`) plus 5000 tokens so the tokens gauge is nonzero.
        let usage_store = gov.store();
        usage_store
            .put_usage(
                &key.id,
                0,
                &busbar_api::UsageLedger {
                    requests: 200,
                    billable_requests: 200,
                    models: vec![busbar_api::ModelTokens {
                        model: "m".to_string(),
                        tokens: crate::governance::TierTokens {
                            input: 5000,
                            output: 0,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            )
            .unwrap();

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
            out.contains(KEY_TOKENS_TOTAL),
            "tokens gauge must be present; got:\n{out}"
        );
        // 1.5.0: keys are pure auth (no cap), so no per-key budget-remaining gauge exists; the
        // remaining/limit dimension lives on the GROUP buckets (asserted below).
        assert!(
            !out.contains("busbar_key_budget_remaining_cents"),
            "the removed per-key remaining gauge must not resurface; got:\n{out}"
        );
    }

    /// A group bucket WITHOUT a `budget` cap must NOT emit `BUCKET_BUDGET_REMAINING_CENTS` - the
    /// gauge is meaningless without a ceiling and would just be 0. (The per-key remaining gauge is
    /// gone entirely: keys are pure auth.)
    #[test]
    fn test_scrape_gauges_uncapped_group_bucket_no_remaining() {
        init();

        let mut key = sample_vkey("vk_uncapped_test01");
        key.group = Some("uncapped-grp".to_string());
        let gov = gov_with_key(key);

        // The group carries only a requests limit: its minute bucket exists but has NO budget cap.
        let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
            std::collections::BTreeMap::from([(
                "uncapped-grp".to_string(),
                crate::config::GroupCfg {
                    parent: None,
                    enabled: true,
                    limits: vec![crate::config::groups::LimitCfg {
                        metric: crate::config::groups::LimitMetric::Requests,
                        amount: 100,
                        per: Some(crate::config::groups::LimitWindow::Minute),
                    }],
                    ..Default::default()
                },
            )]);
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-b", &[(0, 1)])
            .governance(gov)
            .cost(crate::cost::CostModel::resolve_parts(None, 0, &groups))
            .build();

        refresh_scrape_gauges(&app);

        let out = render();
        // The remaining gauge for the budget-less bucket must NOT appear.
        // NOTE: other tests in this process may have emitted it for different buckets; we can only
        // check that this bucket id does not appear on a budget-remaining line.
        let remaining_lines: Vec<&str> = out
            .lines()
            .filter(|l| l.contains(BUCKET_BUDGET_REMAINING_CENTS))
            .collect();
        for line in &remaining_lines {
            assert!(
                !line.contains("uncapped-grp"),
                "a budget-less group bucket must not appear in budget_remaining_cents lines; got:\n{line}"
            );
        }
        // Its spend series DOES appear, keyed by the new (bucket, group, window) dimensions.
        assert!(
            out.lines().any(|l| l.contains(BUCKET_SPEND_CENTS)
                && l.contains("group:uncapped-grp@minute")
                && l.contains("window=\"minute\"")),
            "the group bucket's spend gauge carries the group/window dimensions; got:\n{out}"
        );
    }

    /// The 1.5.0 cost-model exposure: `busbar_bucket_tokens{bucket, model, tier}` series for key
    /// AND budget-group buckets, derived `busbar_bucket_spend_cents` / `_budget_remaining_cents`
    /// for group buckets, and the key's MINT-TIME labels echoed onto its series (so external
    /// dashboards can `sum by (team)` without busbar knowing what a team is).
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_scrape_gauges_bucket_model_tier_and_key_labels() {
        init();

        let mut key = sample_vkey("vk_bucket_test1");
        key.group = Some("growth".to_string());
        key.labels = std::collections::BTreeMap::from([("team".to_string(), "growth".to_string())]);
        let gov = gov_with_key(key.clone());

        // A cost model with the growth group; flat fee 1 (TestApp default shape).
        let groups = std::collections::BTreeMap::from([(
            "growth".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![crate::config::groups::LimitCfg {
                    metric: crate::config::groups::LimitMetric::Budget,
                    amount: 1_000,
                    per: Some(crate::config::groups::LimitWindow::Total),
                }],
                ..Default::default()
            },
        )]);
        let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

        // Accrue per-model tier tokens through the REAL accrual path (fans out to key + group).
        gov.record_usage(
            &cost,
            &key,
            "gpt-5",
            &busbar_api::TierTokens {
                input: 100,
                output: 40,
                cache_read: 7,
                cache_write: 3,
            },
            1_700_000_000,
        );

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://m",
            ))
            .pool("pool-b", &[(0, 1)])
            .governance(gov)
            .cost(crate::cost::CostModel::resolve_parts(None, 1, &groups))
            .build();
        refresh_scrape_gauges(&app);
        let out = render();

        // Key-bucket per-(model, tier) series with the mint label echoed.
        let key_line = out
            .lines()
            .find(|l| {
                l.starts_with("busbar_bucket_tokens")
                    && l.contains("bucket=\"vk_bucket_test1\"")
                    && l.contains("model=\"gpt-5\"")
                    && l.contains("tier=\"input\"")
            })
            .unwrap_or_else(|| panic!("key-bucket input-tier series missing: {out}"));
        assert!(
            key_line.contains("team=\"growth\""),
            "mint labels echo onto metric series: {key_line}"
        );
        assert!(
            key_line.trim_end().ends_with("100"),
            "input tier value: {key_line}"
        );

        // Group-bucket series exist too (the chain accrual fanned out), keyed by the 1.5.0
        // per-(group, window) bucket id and carrying the group/window dimensions.
        assert!(
            out.lines().any(|l| l.starts_with("busbar_bucket_tokens")
                && l.contains("bucket=\"group:growth@total\"")
                && l.contains("group=\"growth\"")
                && l.contains("window=\"total\"")
                && l.contains("tier=\"output\"")),
            "group-bucket token series missing: {out}"
        );
        // Derived group spend (0 without a rate card and no admitted request) + remaining
        // (= full cap).
        assert!(
            out.lines()
                .any(|l| l.starts_with("busbar_bucket_spend_cents")
                    && l.contains("bucket=\"group:growth@total\"")),
            "group spend gauge missing"
        );
        assert!(
            out.lines()
                .any(|l| l.starts_with("busbar_bucket_budget_remaining_cents")
                    && l.contains("bucket=\"group:growth@total\"")
                    && l.trim_end().ends_with("1000")),
            "group remaining gauge = full cap when token spend derives to 0: {out}"
        );
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
        // The `lane` label is the lane's MODEL string (NOT a numeric index), consistent with the
        // proxy engine counter sites so the gauge and counters can be PromQL-joined on `lane`.
        assert!(
            line.contains("lane=\"model-h\""),
            "lane label must be the model string, not a numeric index; got:\n{line}"
        );
    }

    /// `refresh_scrape_gauges` must emit at most `key_gauge_limit` (2000) distinct per-key series
    /// even when the governance store holds more than that many virtual keys.
    ///
    /// The truncation logic (`keys.iter().take(key_gauge_limit)`) is exercised by creating
    /// key_gauge_limit + 1 keys, running a scrape, and asserting the count of distinct `key=`
    /// label values in the `busbar_key_spend_cents` lines is ≤ key_gauge_limit.
    ///
    /// Creating 2001 rows in an in-memory SQLite instance is fast (< 50 ms on any modern machine);
    /// using `put_key` directly on the store bypasses the `GovState` cache and is the simplest
    /// deterministic way to seed a large key set.
    #[test]
    fn test_key_gauge_limit_truncation() {
        init();
        // The default key-gauge limit is 2000 (no limits installed in this test ⇒ the historical
        // default). We use the same value here to keep the test self-consistent.
        const LIMIT: usize = crate::config::DEFAULT_KEY_GAUGE_LIMIT;
        let store = Arc::new(MemoryStore::new());

        // Insert LIMIT + 1 keys so the truncation branch fires.
        for i in 0..=(LIMIT) {
            let id = format!("vk_limit_{i:04x}");
            let key = VirtualKey {
                id: id.clone(),
                key_hash: format!("hash-limit-{i}"),
                name: format!("key-limit-{i}"),
                allowed_pools: None,
                enabled: true,
                created_at: 1_700_000_000,
                group: None,
                labels: Default::default(),
            };
            store.put_key(&key).unwrap();
            // Seed minimal usage so the key has a row in usage_counters and the spend gauge is
            // actually emitted (keys with zero usage_for results are skipped).
            store
                .put_usage(
                    &id,
                    0,
                    &busbar_api::UsageLedger {
                        requests: 1,
                        billable_requests: 1,
                        models: vec![busbar_api::ModelTokens {
                            model: "m".to_string(),
                            tokens: crate::governance::TierTokens {
                                input: 10,
                                output: 0,
                                cache_read: 0,
                                cache_write: 0,
                            },
                        }],
                    },
                )
                .unwrap();
        }

        let gov = Arc::new(GovState::new(store, None).unwrap());
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
            "refresh_scrape_gauges must emit at most key_gauge_limit ({LIMIT}) per-key series; got {spend_series_count}"
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
