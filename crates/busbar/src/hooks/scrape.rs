// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Prometheus exposition of HOOK-reported metrics — the `GET /metrics/hooks` scrape.
//!
//! A hook reports its own operational metrics over the wire (`status.metrics`, see
//! [`super::wire::HookMetric`]). The admin API surfaces those LIVE, on-demand, per hook
//! (`GET /api/v1/admin/hooks/{name}/status`) — that path is unchanged and is the "truth right now"
//! read. THIS module is the parallel projection for time-series consumers: it renders the same
//! metrics as standard Prometheus text so any Prometheus/Grafana can scrape them, with the hook's
//! metric NAMES verbatim (so an external dashboard built against a hook — e.g. a compression tool's
//! own Grafana — repoints at busbar and just works) plus one automatic `hook="<name>"` label for
//! provenance and multi-hook disambiguation.
//!
//! Design invariants (why this can never break busbar's own `/metrics`):
//! * SEPARATE exposition. Hook metrics render here, never merged into busbar's own `/metrics`, so a
//!   hook can never type-conflict or shadow a first-party `busbar_*` series (Prometheus allows one
//!   TYPE per metric name per exposition; a `hook` label cannot disambiguate type).
//! * RESERVED namespace. A hook metric whose name starts with `busbar_` is dropped — a hook cannot
//!   impersonate a first-party series.
//! * NON-BLOCKING scrape. The scrape renders a CACHE and never awaits a hook socket inline. When a
//!   hook's cache is older than [`HOOK_METRICS_TTL_SECS`] the scrape serves the stale value and fires
//!   an ASYNC refresh (stale-while-revalidate) — a slow or dead hook yields stale-then-absent series
//!   (fail-open), never a stalled `/metrics/hooks`. Zero work when nobody scrapes; self-tunes to the
//!   scrape rate.
//! * BOUNDED. `parse_status_metrics` already caps entries (64) + labels (8) and sanitizes every name/
//!   label/value, so a hostile hook cannot flood or exfiltrate through the scrape.

use super::wire::HookMetric;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Staleness bound for a hook's cached metrics. On a scrape, a cache older than this triggers an
/// async refresh (stale-while-revalidate). Chosen ≤ a typical Prometheus `scrape_interval` (15s) so
/// consecutive scrapes see fresh-enough samples without polling a hook faster than it is scraped.
pub(crate) const HOOK_METRICS_TTL_SECS: u64 = 10;

/// One hook's last-known metrics + when they were fetched (unix secs). `metrics` empty means the
/// hook was queried but reported none / doesn't speak status (fail-open: it simply contributes no
/// series). A hook with no cache entry yet is refreshed on first scrape.
struct Cached {
    fetched_at: u64,
    metrics: Vec<HookMetric>,
}

/// Process-wide hook-metrics cache, keyed by hook name. Populated by the stale-while-revalidate
/// refresh fired from the scrape handler; read (never blocked) by the renderer.
static CACHE: RwLock<Option<HashMap<String, Cached>>> = RwLock::new(None);

/// True iff `name`'s cache is missing or older than the TTL — i.e. the scrape should fire an async
/// refresh for it. Read-only; the refresh itself writes the cache.
fn is_stale(name: &str, now: u64) -> bool {
    let guard = CACHE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref().and_then(|m| m.get(name)) {
        Some(c) => now.saturating_sub(c.fetched_at) >= HOOK_METRICS_TTL_SECS,
        None => true,
    }
}

/// Store a freshly-fetched metric set for `name`.
fn store(name: &str, metrics: Vec<HookMetric>, now: u64) {
    let mut guard = CACHE.write().unwrap_or_else(|e| e.into_inner());
    guard.get_or_insert_with(HashMap::new).insert(
        name.to_string(),
        Cached {
            fetched_at: now,
            metrics,
        },
    );
}

/// Snapshot the current cache as `(hook_name, metrics)` pairs for rendering. Clones the small parsed
/// metric structs (≤64 per hook) so the render never holds the lock across formatting.
fn snapshot() -> Vec<(String, Vec<HookMetric>)> {
    let guard = CACHE.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.metrics.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Live-query one hook's status and update its cache entry. Runs in a spawned task from the scrape
/// (never inline). Reuses the exact same [`super::fetch_status`] path the admin API uses, so the
/// scrape and the live admin read see the identical hook data (just at different freshness).
async fn refresh(
    name: String,
    hook: crate::config::HookCfg,
    settings_version: u64,
    client: reqwest::Client,
) {
    let metrics = match super::fetch_status(&name, &hook, settings_version, &client).await {
        Some(status) => status
            .metrics
            .as_ref()
            .map(|m| super::wire::parse_status_metrics(m))
            .unwrap_or_default(),
        // Unreachable / doesn't speak status: cache an empty set so it contributes no series and is
        // not re-hammered every scrape until the TTL elapses (fail-open).
        None => Vec::new(),
    };
    store(&name, metrics, crate::store::now());
}

/// `GET /metrics/hooks` — render every hook's cached metrics as Prometheus text.
///
/// Stale-while-revalidate: for each configured hook whose cache is stale, spawn an async refresh
/// (the NEXT scrape sees it) and render the current cache now. The handler never awaits a hook.
pub(crate) fn render(app: &Arc<crate::state::App>) -> String {
    let now = crate::store::now();
    // Fire async refreshes for stale hooks; never block the scrape on them.
    for (name, hook) in app.hook_registry.iter() {
        if is_stale(name, now) {
            tokio::spawn(refresh(
                name.clone(),
                hook.clone(),
                app.config_version,
                app.client.clone(),
            ));
        }
    }
    render_text(&snapshot())
}

/// A metric-name group during rendering: `(prometheus_type, help, [(hook_name, metric)])`.
type MetricGroup = (String, Option<String>, Vec<(String, HookMetric)>);

/// Render `(hook_name, metrics)` pairs to Prometheus 0.0.4 text exposition. Grouped by metric name
/// (HELP/TYPE emitted once per name, as the format requires), verbatim names + a `hook="<name>"`
/// label, `busbar_`-prefixed names dropped, histograms rendered as Prometheus SUMMARY (the type that
/// carries `quantile` series). Deterministic order (sorted) so scrapes are stable and testable.
fn render_text(hooks: &[(String, Vec<HookMetric>)]) -> String {
    // Group by metric name -> (prom_type, help, [(hook_name, metric)]). First occurrence fixes the
    // type; a later entry of a DIFFERENT type for the same name is dropped (Prometheus forbids mixing).
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, MetricGroup> = HashMap::new();
    let mut sorted: Vec<(String, Vec<HookMetric>)> = hooks.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (hook_name, metrics) in sorted {
        for m in metrics {
            if m.name.starts_with("busbar_") {
                continue; // reserved first-party namespace — a hook cannot impersonate it
            }
            let prom_type = prom_type_of(&m);
            let entry = groups.entry(m.name.clone()).or_insert_with(|| {
                order.push(m.name.clone());
                (prom_type.to_string(), m.help.clone(), Vec::new())
            });
            if entry.0 != prom_type {
                continue; // type conflict for a shared name: keep the first, drop the rest
            }
            if entry.1.is_none() {
                entry.1 = m.help.clone();
            }
            entry.2.push((hook_name.clone(), m));
        }
    }

    let mut out = String::new();
    order.sort();
    for name in &order {
        let (ptype, help, entries) = &groups[name];
        if let Some(h) = help {
            out.push_str(&format!("# HELP {name} {}\n", escape_help(h)));
        }
        out.push_str(&format!("# TYPE {name} {ptype}\n"));
        for (hook_name, m) in entries {
            match ptype.as_str() {
                "histogram" => render_histogram(&mut out, name, hook_name, m),
                "summary" => render_summary(&mut out, name, hook_name, m),
                _ => {
                    let labels = render_labels(hook_name, m.labels.as_ref(), &[]);
                    out.push_str(&format!("{name}{labels} {}\n", fmt_f64(m.value)));
                }
            }
        }
    }
    out
}

/// Map a hook metric to its Prometheus type. A `histogram` carrying native `buckets` renders as a
/// Prometheus HISTOGRAM (`_bucket`/`_count`, queryable via `histogram_quantile`); a `histogram`
/// carrying precomputed `quantiles` renders as a SUMMARY. Counter/gauge pass through; anything else
/// is `untyped`.
fn prom_type_of(m: &HookMetric) -> &'static str {
    match m.kind.as_str() {
        "counter" => "counter",
        "gauge" => "gauge",
        "histogram" if m.buckets.is_some() => "histogram",
        "histogram" => "summary",
        _ => "untyped",
    }
}

/// Render a native Prometheus histogram: one `name_bucket{le="…"}` line per bucket (cumulative
/// counts, as the hook reported them; a `+Inf` bucket is emitted to close the histogram if the hook
/// omitted it) plus `name_count` = the total observation count (`value`). This is the shape
/// `histogram_quantile()` operates on, so a dashboard built against a `*_bucket` series works
/// unchanged.
fn render_histogram(out: &mut String, name: &str, hook: &str, m: &HookMetric) {
    let mut saw_inf = false;
    if let Some(buckets) = &m.buckets {
        // Sort by le so the exposition is monotonic and stable (finite bounds ascending, +Inf last).
        let mut rows: Vec<(&String, &f64)> = buckets.iter().collect();
        rows.sort_by(|a, b| {
            let pa = if a.0 == "+Inf" {
                f64::INFINITY
            } else {
                a.0.parse().unwrap_or(f64::INFINITY)
            };
            let pb = if b.0 == "+Inf" {
                f64::INFINITY
            } else {
                b.0.parse().unwrap_or(f64::INFINITY)
            };
            pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (le, count) in rows {
            if le == "+Inf" {
                saw_inf = true;
            }
            let labels = render_labels(hook, m.labels.as_ref(), &[("le", le)]);
            out.push_str(&format!("{name}_bucket{labels} {}\n", fmt_f64(*count)));
        }
    }
    // Prometheus requires a +Inf bucket equal to the total count; add it if the hook didn't.
    if !saw_inf {
        let labels = render_labels(hook, m.labels.as_ref(), &[("le", "+Inf")]);
        out.push_str(&format!("{name}_bucket{labels} {}\n", fmt_f64(m.value)));
    }
    let count_labels = render_labels(hook, m.labels.as_ref(), &[]);
    out.push_str(&format!(
        "{name}_count{count_labels} {}\n",
        fmt_f64(m.value)
    ));
}

/// Render a summary: one `name{...,quantile="q"}` line per quantile plus `name_count` = the
/// observation count (the metric's `value` for a histogram).
fn render_summary(out: &mut String, name: &str, hook: &str, m: &HookMetric) {
    if let Some(qs) = &m.quantiles {
        for (q, v) in qs {
            let labels = render_labels(hook, m.labels.as_ref(), &[("quantile", q)]);
            out.push_str(&format!("{name}{labels} {}\n", fmt_f64(*v)));
        }
    }
    let count_labels = render_labels(hook, m.labels.as_ref(), &[]);
    out.push_str(&format!(
        "{name}_count{count_labels} {}\n",
        fmt_f64(m.value)
    ));
}

/// Build the `{hook="...",k="v",...,extra="..."}` label set: the automatic `hook` label first, then
/// the hook's own labels (sorted for determinism), then any renderer-added labels (e.g. `quantile`).
/// Values are Prometheus-escaped. The wire already charset-restricts names/keys, so escaping here is
/// belt-and-suspenders on the values.
fn render_labels(
    hook: &str,
    labels: Option<&std::collections::BTreeMap<String, String>>,
    extra: &[(&str, &str)],
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("hook=\"{}\"", escape_label(hook)));
    if let Some(m) = labels {
        for (k, v) in m {
            parts.push(format!("{k}=\"{}\"", escape_label(v)));
        }
    }
    for (k, v) in extra {
        parts.push(format!("{k}=\"{}\"", escape_label(v)));
    }
    format!("{{{}}}", parts.join(","))
}

/// Prometheus label-value escaping: backslash, double-quote, newline (per the exposition spec).
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// HELP-line escaping: backslash and newline (double-quotes are literal in HELP text).
fn escape_help(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Format a float for Prometheus: integers without a decimal point, otherwise a compact decimal.
/// Non-finite values (already excluded by `parse_status_metrics`) render as `0`.
fn fmt_f64(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// `GET /metrics/hooks` — the Prometheus scrape of hook-reported metrics. Standard text exposition,
/// governed by the auth chain exactly like busbar's own `/metrics` (both carry operational topology,
/// so busbar does NOT exempt them — a scraper authenticates with a bearer token, which Prometheus and
/// Grafana both support in scrape/datasource config). Stale-while-revalidate: renders the cache now,
/// refreshes stale hooks in the background; never blocks on a hook socket.
pub(crate) async fn handler(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(&app),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/scrape_tests.rs"]
mod scrape_tests;
