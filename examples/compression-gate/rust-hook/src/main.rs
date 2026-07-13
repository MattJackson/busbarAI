// Copyright (C) 2026 Busbar Inc and contributors

//! A COMPRESSION GATE for busbar — the `rewrite` reply arm, end to end, modeled on **Headroom**.
//!
//! This binary is a rewrite gate (`kind: gate, prompt: rw`) on a Unix socket: busbar sends it each
//! request's flattened prompt text, and it replies with a smaller replacement body — or nothing.
//! The compression here is deliberately simple (collapse whitespace runs inside every message) so
//! the WIRE is the lesson, not the compressor; swap `compress_text` for your real one.
//!
//! It is dressed as the real **Headroom** context-compression tool
//! (github.com/chopratejas/headroom — "Compress tool outputs, logs, files, and RAG chunks before
//! they reach the LLM. 60-95% fewer tokens, same answers."), so the SETTINGS it exposes and the
//! METRICS it self-reports mirror what Headroom's own `headroom dashboard` surfaces to its users:
//!   - tokens/chars in vs out, and the derived compression RATIO (Headroom's headline "% fewer
//!     tokens"),
//!   - requests SEEN vs COMPRESSED (the "cleared the savings threshold" rate — Headroom skips a
//!     body when the savings aren't worth it, exactly like this hook's `min_savings_pct`),
//!   - estimated COST saved in dollars (Headroom's "Proxy $ Saved" tile, priced via LiteLLM) —
//!     reported as an ESTIMATE with a confidence interval, mirroring Headroom's holdout-control
//!     "measured vs estimated [95% CI]" savings display,
//!   - compression LATENCY as a DISTRIBUTION (p50/p95/p99 histogram — what a mean would hide).
//!
//! Every key counter is broken down PER POOL: one hook process serves N pools (busbar sends
//! `request.pool` on every transform), and the metrics array carries one entry per pool via the
//! `labels: {"pool": ...}` dimension — so `GET /hooks/{name}/status` returns the whole picture and
//! a dashboard drills down by pool. (The same hook on three pools shows three rows, one process.)
//!
//! Sources: Headroom README + docs (github.com/chopratejas/headroom, headroom-docs.vercel.app/docs,
//! dev.to "Cut Your LLM Token Usage by Up to 95%") and, for the cost/latency-saved framing,
//! Microsoft LLMLingua/LongLLMLingua (llmlingua.com).
//!
//! It speaks the full 1.3 hook wire:
//!   configure — busbar's FIRST message on every connection (and a live push on
//!               `PATCH /api/v1/admin/hooks/{name}/settings`): apply the settings, ack the version.
//!   describe  — reply the self-description ENVELOPE `{schema, dashboard}`: the settings JSON
//!               Schema (`GET /api/v1/admin/hooks/{name}/schema`) AND the dashboard widget layout.
//!   status    — reply OBSERVED settings + self-reported operational metrics (an ARRAY of
//!               Prometheus-shaped entries) (`GET /api/v1/admin/hooks/{name}/status`).
//!   transform — the rewrite pass: prompt text in, `{"rewrite": ...}` or `{}` (abstain) out.
//!   notify    — a tap observation: NEVER answered (write nothing on a tap connection).
//!   (decide never reaches a pure rewrite gate; unknown ops get a safe `{}`.)
//!
//! Fail-safe by construction: any reply busbar can't parse — or none at all — means "proceed with
//! the ORIGINAL body" (`on_error` default `nothing`). A broken compressor never corrupts a request.
//!
//! Run it:              cargo run --release -- /run/busbar/compress.sock
//! Register it:         hooks: { headroom: { kind: gate, socket: /run/busbar/compress.sock,
//!                                           prompt: rw, global: true,
//!                                           settings: { min_savings_pct: 10 } } }

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// ── SETTINGS (Headroom-style knobs). Shared across connections so a live settings push retunes
//    every future request at once; each is applied by `configure` and reported back by `status`. ──

/// Rewrite only when the compressed body is at least this % smaller. Below it the savings aren't
/// worth a body swap — abstain and busbar proceeds untouched. (Headroom's "skip when not worth it".)
static MIN_SAVINGS_PCT: AtomicU64 = AtomicU64::new(10);
/// The target compression ratio Headroom aims for, in percent (e.g. 60 = "shrink to 60% of the
/// original"). Advisory for this trivial compressor; a real Headroom strategy tunes toward it.
static TARGET_RATIO_PCT: AtomicU64 = AtomicU64::new(60);
/// Only ATTEMPT compression once the request is at least this many chars — small prompts aren't
/// worth compressing (Headroom triggers on large tool outputs / RAG dumps, not one-liners).
static MIN_TRIGGER_CHARS: AtomicU64 = AtomicU64::new(0);
/// System-prompt-aware compression on/off (1/0). When off, the hook is extra conservative near the
/// system prompt. (The system prompt itself is never rewritable on the wire — this only gates the
/// hook's own behavior; here it is a reported knob, faithful to Headroom's per-content strategies.)
static SYSTEM_AWARE: AtomicU64 = AtomicU64::new(1);
/// Assumed input price in micro-dollars per 1K chars, used to turn chars-saved into the estimated
/// "$ saved" tile (Headroom prices via LiteLLM; here it's a settable proxy so the tile is real).
static PRICE_UDOLLARS_PER_KCHAR: AtomicU64 = AtomicU64::new(50); // $0.00005 / 1K chars

// ── METRICS — accumulated PER POOL. One hook process serves many pools; the status array reports
//    one labeled entry per pool. A single Mutex-guarded map is plenty for an example (a real hook
//    would sample latencies with a reservoir / t-digest instead of holding every sample). ─────────

/// Per-pool operational tallies — the raw material for the `status` metrics array.
#[derive(Default)]
struct PoolStats {
    /// Transform requests SEEN on this pool (the compressed-rate denominator).
    requests_seen: u64,
    /// Requests actually COMPRESSED (cleared the savings threshold).
    requests_compressed: u64,
    /// Lifetime input chars on compressed requests (the "before").
    chars_in: u64,
    /// Lifetime output chars after compression (the "after").
    chars_out: u64,
    /// Lifetime chars removed — Headroom's headline "tokens saved".
    chars_saved: u64,
    /// Estimated cost saved, micro-dollars — Headroom's "Proxy $ saved" tile.
    udollars_saved: u64,
    /// Per-request compression latencies (micros). Held in full for exact example quantiles; a real
    /// hook uses a bounded sketch. Cleared-cap keeps the example's memory flat under a flood.
    latencies_us: Vec<u64>,
}

/// Cap on retained latency samples per pool (a real hook would use a reservoir/t-digest; this keeps
/// the example's memory bounded while still giving representative p50/p95/p99).
const MAX_LATENCY_SAMPLES: usize = 4096;

static POOLS: Mutex<BTreeMap<String, PoolStats>> = Mutex::new(BTreeMap::new());

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/busbar-compress.sock".into());
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind socket path");
    eprintln!("[compression-gate] listening on {path}");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let reply = handle_line(line.trim());
                if reply.is_empty() {
                    continue; // a tap notify: write NOTHING (busbar never reads a tap reply)
                }
                if writer.write_all(reply.as_bytes()).is_err() {
                    break;
                }
            }
        });
    }
}

/// One JSON line in, one JSON line out. Dispatch per the wire contract: MANAGEMENT messages are
/// key-discriminated (`configure` / `describe` / `status`); everything else is a PER-REQUEST
/// message whose `op` field says which kind (`decide` / `transform` / `notify`). Anything
/// unrecognized — including future ops — gets `{}`: busbar reads that as abstain / unsupported,
/// never as an error (the append-only evolvability rule). A `notify` (tap) returns "" → the caller
/// writes nothing.
fn handle_line(line: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return "{}\n".into();
    };
    if let Some(cfg) = v.get("configure") {
        return configure(cfg);
    }
    if v.get("describe").is_some() {
        return describe();
    }
    if v.get("status").is_some() {
        return status();
    }
    match v.get("op").and_then(|o| o.as_str()) {
        Some("transform") => match v.get("request") {
            Some(req) => transform(req),
            None => "{}\n".into(),
        },
        // A tap NOTIFY is fire-and-forget: busbar never reads a reply on a tap connection, so
        // answering one queues bytes forever — write NOTHING (empty string → caller skips the
        // write). A decide from this rw gate is unreachable (rw gates fire on the transform pass);
        // unknown future ops get the safe `{}`.
        Some("notify") => String::new(),
        _ => "{}\n".into(),
    }
}

/// Apply a pushed settings map and ACK by echoing its version — the echo is what commits the PATCH
/// on busbar's side. A bad value gets NO ack, so busbar keeps the previous settings (fail-closed):
/// the whole push is rejected if ANY knob is out of range, so settings never apply partially.
fn configure(cfg: &serde_json::Value) -> String {
    let settings = cfg.get("settings");
    let knobs: &[(&str, &AtomicU64, u64)] = &[
        ("min_savings_pct", &MIN_SAVINGS_PCT, 100),
        ("target_ratio_pct", &TARGET_RATIO_PCT, 100),
        ("min_trigger_chars", &MIN_TRIGGER_CHARS, u64::MAX),
        ("system_aware", &SYSTEM_AWARE, 1),
        (
            "price_udollars_per_kchar",
            &PRICE_UDOLLARS_PER_KCHAR,
            u64::MAX,
        ),
    ];
    // TWO PHASES so the apply is ALL-OR-NOTHING: first VALIDATE every present knob (absent = leave
    // as-is), collecting the pending stores; only if EVERY knob is in range do we commit them. A
    // single out-of-range value refuses the whole push with no ack — busbar keeps the previous
    // settings (fail-closed) and never applies a partial update.
    let mut pending: Vec<(&AtomicU64, u64)> = Vec::new();
    for (key, store, max) in knobs {
        match settings.and_then(|s| s.get(*key)) {
            None => {}
            Some(serde_json::Value::Bool(b)) if *max == 1 => pending.push((store, *b as u64)),
            Some(val) => match val.as_u64().filter(|&n| n <= *max) {
                Some(n) => pending.push((store, n)),
                None => return "{}\n".into(), // out of range: refuse the whole push
            },
        }
    }
    for (store, n) in pending {
        store.store(n, Ordering::Relaxed);
    }
    let version = cfg.get("settings_version").cloned().unwrap_or(0.into());
    format!("{{\"ack\":{{\"settings_version\":{version}}}}}\n")
}

/// Answer `describe` with the self-description ENVELOPE: `schema` (the settings JSON Schema —
/// busbar extracts it for `GET /api/v1/admin/hooks/{name}/schema`) and `dashboard` (the plugin's
/// declared widget layout — ONE declaration drives both the config form and the dashboard; the
/// widget VALUES come from `status.metrics`, matched by `metric` name). The widgets mirror
/// Headroom's dashboard tiles.
fn describe() -> String {
    serde_json::json!({
        "schema": {
            "type": "object",
            "title": "Headroom compression",
            "properties": {
                "min_savings_pct": {
                    "type": "integer", "minimum": 0, "maximum": 100, "default": 10,
                    "description": "Rewrite only when the body shrinks by at least this percent; below it, abstain."
                },
                "target_ratio_pct": {
                    "type": "integer", "minimum": 0, "maximum": 100, "default": 60,
                    "description": "Target compressed size as a percent of the original (Headroom's compression target)."
                },
                "min_trigger_chars": {
                    "type": "integer", "minimum": 0, "default": 0,
                    "description": "Only attempt compression once the request is at least this many characters."
                },
                "system_aware": {
                    "type": "boolean", "default": true,
                    "description": "System-prompt-aware compression: be conservative near the system prompt."
                },
                "price_udollars_per_kchar": {
                    "type": "integer", "minimum": 0, "default": 50,
                    "description": "Assumed input price (micro-dollars per 1K chars) used to estimate dollars saved."
                }
            }
        },
        "dashboard": { "widgets": [
            {"metric": "chars_saved_total",         "label": "Tokens saved",        "viz": "counter"},
            {"metric": "compression_ratio",         "label": "Compression ratio",   "viz": "gauge", "unit": "%", "max": 100},
            {"metric": "requests_compressed_total", "label": "Requests compressed", "viz": "counter"},
            {"metric": "compressed_rate",           "label": "Compressed rate",     "viz": "gauge", "unit": "%", "max": 100},
            {"metric": "dollars_saved",             "label": "Proxy $ saved",       "viz": "number", "unit": "$"},
            {"metric": "compress_latency_us",       "label": "Compress latency",    "viz": "histogram", "unit": "us"}
        ]}
    })
    .to_string()
        + "\n"
}

/// Answer `status` with OBSERVED state: the settings this process is actually running + its own
/// operational metrics — the control-plane read busbar surfaces at
/// `GET /api/v1/admin/hooks/{name}/status`. The `metrics` value is an ARRAY of Prometheus-shaped
/// entries (`{name, type, value, labels?, quantiles?, estimated?, ci_*?, label?, unit?, viz?,
/// max?, help?}`). Every key counter is emitted ONCE PER POOL via `labels: {"pool": ...}` — the
/// per-dimension breakdown a flat map can't carry. Latency is a `histogram` with p50/p95/p99
/// `quantiles`; the dollars-saved estimate carries `estimated: true` + a confidence interval.
/// busbar validates, bounds (64 entries, 8 labels/entry), and sanitizes every entry and hint.
fn status() -> String {
    let mut metrics: Vec<serde_json::Value> = Vec::new();
    let pools = POOLS.lock().unwrap_or_else(|e| e.into_inner());

    for (pool, s) in pools.iter() {
        let lbl = || serde_json::json!({ "pool": pool });

        // Counters, one labeled entry per pool.
        metrics.push(serde_json::json!({
            "name": "requests_seen_total", "type": "counter", "value": s.requests_seen,
            "labels": lbl(), "label": "Requests seen", "viz": "counter",
            "help": "transform requests observed on the compression path"
        }));
        metrics.push(serde_json::json!({
            "name": "requests_compressed_total", "type": "counter", "value": s.requests_compressed,
            "labels": lbl(), "label": "Requests compressed", "viz": "counter",
            "help": "requests whose savings cleared min_savings_pct"
        }));
        metrics.push(serde_json::json!({
            "name": "chars_in_total", "type": "counter", "value": s.chars_in,
            "labels": lbl(), "label": "Chars in", "viz": "counter",
            "help": "input characters seen on compressed requests (the before)"
        }));
        metrics.push(serde_json::json!({
            "name": "chars_out_total", "type": "counter", "value": s.chars_out,
            "labels": lbl(), "label": "Chars out", "viz": "counter",
            "help": "output characters after compression (the after)"
        }));
        metrics.push(serde_json::json!({
            "name": "chars_saved_total", "type": "counter", "value": s.chars_saved,
            "labels": lbl(), "label": "Tokens saved", "viz": "counter",
            "help": "characters removed by compression (Headroom's headline savings)"
        }));

        // Derived gauges, per pool.
        let ratio_pct = if s.chars_in > 0 {
            (s.chars_saved as f64) * 100.0 / (s.chars_in as f64)
        } else {
            0.0
        };
        metrics.push(serde_json::json!({
            "name": "compression_ratio", "type": "gauge", "value": ratio_pct,
            "labels": lbl(), "label": "Compression ratio", "unit": "%", "viz": "gauge", "max": 100.0,
            "help": "percent fewer characters across all compressed requests"
        }));
        let compressed_rate = if s.requests_seen > 0 {
            (s.requests_compressed as f64) * 100.0 / (s.requests_seen as f64)
        } else {
            0.0
        };
        metrics.push(serde_json::json!({
            "name": "compressed_rate", "type": "gauge", "value": compressed_rate,
            "labels": lbl(), "label": "Compressed rate", "unit": "%", "viz": "gauge", "max": 100.0,
            "help": "share of seen requests that cleared the savings threshold"
        }));

        // Dollars saved — an ESTIMATE (priced off an assumed rate, and Headroom derives real savings
        // from a holdout control), so mark it `estimated` and bound it with a ±15% CI, mirroring
        // Headroom's "measured vs estimated [95% CI]" savings display.
        let dollars = (s.udollars_saved as f64) / 1_000_000.0;
        metrics.push(serde_json::json!({
            "name": "dollars_saved", "type": "gauge", "value": dollars,
            "labels": lbl(), "label": "Proxy $ saved", "unit": "$", "viz": "number",
            "estimated": true, "ci_low": dollars * 0.85, "ci_high": dollars * 1.15,
            "help": "estimated input cost saved (priced from price_udollars_per_kchar, ±15% CI)"
        }));

        // Compression latency as a DISTRIBUTION: value = sample count, p50/p95/p99 in `quantiles`
        // (what a mean would hide). A real hook keeps a bounded sketch; the example sorts its
        // retained samples.
        if let Some((count, q)) = latency_quantiles(&s.latencies_us) {
            metrics.push(serde_json::json!({
                "name": "compress_latency_us", "type": "histogram", "value": count,
                "labels": lbl(), "quantiles": q,
                "label": "Compress latency", "unit": "us", "viz": "histogram",
                "help": "per-request compression latency distribution (microseconds)"
            }));
        }
    }

    let out = serde_json::json!({
        "status": {
            "settings": {
                "min_savings_pct": MIN_SAVINGS_PCT.load(Ordering::Relaxed),
                "target_ratio_pct": TARGET_RATIO_PCT.load(Ordering::Relaxed),
                "min_trigger_chars": MIN_TRIGGER_CHARS.load(Ordering::Relaxed),
                "system_aware": SYSTEM_AWARE.load(Ordering::Relaxed) == 1,
                "price_udollars_per_kchar": PRICE_UDOLLARS_PER_KCHAR.load(Ordering::Relaxed)
            },
            "metrics": metrics
        }
    });
    out.to_string() + "\n"
}

/// Compute p50/p95/p99 from retained latency samples: returns `(sample_count, {"0.5":.., "0.95":..,
/// "0.99":..})` or `None` when no samples yet. Quantile keys are probability strings in `[0,1]` —
/// exactly what busbar's `parse_status_metrics` accepts for a histogram.
fn latency_quantiles(samples: &[u64]) -> Option<(u64, serde_json::Value)> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<u64> = samples.to_vec();
    sorted.sort_unstable();
    let at = |p: f64| -> u64 {
        let idx = ((p * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
        sorted[idx]
    };
    Some((
        samples.len() as u64,
        serde_json::json!({
            "0.5":  at(0.50),
            "0.95": at(0.95),
            "0.99": at(0.99)
        }),
    ))
}

/// The rewrite pass: collapse whitespace runs in every message; reply with the smaller body only
/// when the savings clear `min_savings_pct` (and the request is at least `min_trigger_chars`).
/// Note the wire asymmetry — messages ARRIVE flattened as `{role, text}` and the reply is BODY
/// form `{role, content}`; the system prompt is read-only. Every seen request is counted against
/// its `request.pool`; a committed rewrite additionally advances that pool's chars/$/compressed.
fn transform(req: &serde_json::Value) -> String {
    let started = std::time::Instant::now();
    let Ok(p) = serde_json::from_value::<Projection>(req.clone()) else {
        return "{}\n".into();
    };
    // The pool this request is on — the label dimension for every metric it touches. Absent (an
    // older engine, or a probe) folds into a stable "unknown" bucket rather than dropping the count.
    let pool = p.pool.unwrap_or_else(|| "unknown".to_string());
    let Some(messages) = p.messages else {
        return "{}\n".into(); // no prompt grant projected — nothing to compress
    };
    let before: usize = messages.iter().map(|m| m.text.len()).sum();

    // Everything below mutates this request's pool row; take the lock once.
    let mut pools = POOLS.lock().unwrap_or_else(|e| e.into_inner());
    let s = pools.entry(pool).or_default();

    // Count every request we actually LOOK at, and record its compression latency — the
    // denominators for the compressed-rate gauge and the latency histogram.
    s.requests_seen += 1;
    let record_latency = |s: &mut PoolStats, started: std::time::Instant| {
        if s.latencies_us.len() < MAX_LATENCY_SAMPLES {
            s.latencies_us.push(started.elapsed().as_micros() as u64);
        }
    };

    if before == 0 || (before as u64) < MIN_TRIGGER_CHARS.load(Ordering::Relaxed) {
        record_latency(s, started);
        return "{}\n".into(); // too small to bother — abstain
    }
    let compressed: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| serde_json::json!({"role": m.role, "content": compress_text(&m.text)}))
        .collect();
    let after: usize = compressed
        .iter()
        .filter_map(|m| m["content"].as_str())
        .map(str::len)
        .sum();
    let saved = before.saturating_sub(after);
    let saved_pct = saved * 100 / before;
    if (saved_pct as u64) < MIN_SAVINGS_PCT.load(Ordering::Relaxed) {
        record_latency(s, started);
        return "{}\n".into(); // not worth a body swap — busbar proceeds untouched
    }

    // COMMITTED savings — self-reported via `status`, per pool, on the Headroom-style dashboard.
    s.requests_compressed += 1;
    s.chars_in += before as u64;
    s.chars_out += after as u64;
    s.chars_saved += saved as u64;
    // Estimated $ saved: saved chars × price-per-1K-chars (Headroom's "Proxy $ saved" tile).
    s.udollars_saved += (saved as u64) * PRICE_UDOLLARS_PER_KCHAR.load(Ordering::Relaxed) / 1000;
    record_latency(s, started);
    drop(pools);

    format!(
        "{{\"rewrite\":{{\"messages\":{}}}}}\n",
        serde_json::to_string(&compressed).unwrap()
    )
}

/// The stand-in compressor: collapse every run of whitespace to a single space. Real compressors
/// (Headroom's SmartCrusher for JSON, AST-aware CodeCompressor, the Kompress model) plug in here —
/// the wire around it doesn't change.
fn compress_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_ws = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(ch);
            in_ws = false;
        }
    }
    out.trim().to_string()
}

// ── The wire types: the slice of busbar's request projection a compressor reads. ────────────────

/// One flattened message: `{role, text}`. Present only because this hook is registered
/// `prompt: rw` — an ungranted hook never sees message text at all.
#[derive(Deserialize)]
struct Msg {
    role: String,
    text: String,
}

#[derive(Deserialize)]
struct Projection {
    /// The pool this request is routing through — always present on a real transform; the label
    /// dimension for every per-pool metric.
    #[serde(default)]
    pool: Option<String>,
    /// Absent unless the `prompt` grant projected it (and `[]` is possible: key off presence).
    #[serde(default)]
    messages: Option<Vec<Msg>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE sequential test on purpose: the settings + per-pool metrics are process-global (exactly
    /// like the real hook), and cargo runs `#[test]`s in parallel — separate tests mutating them
    /// would race.
    #[test]
    fn full_wire_lifecycle() {
        // describe → the self-description envelope: settings schema + declared dashboard widgets.
        let r = handle_line(r#"{"describe":true}"#);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(
            v["schema"]["properties"]["min_savings_pct"]["type"],
            "integer"
        );
        assert_eq!(v["schema"]["properties"]["system_aware"]["type"], "boolean");
        let widgets = v["dashboard"]["widgets"].as_array().unwrap();
        assert!(widgets
            .iter()
            .any(|w| w["metric"] == "chars_saved_total" && w["label"] == "Tokens saved"));
        assert!(widgets
            .iter()
            .any(|w| w["metric"] == "compress_latency_us" && w["viz"] == "histogram"));

        // transform on POOL "chat" (per-request messages carry the `op` discriminator AND
        // request.pool) → rewrite when the collapse clears the (default 10%) threshold.
        let spaced = "hello      world\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n!";
        let chat = serde_json::json!({"op": "transform", "request": {"pool": "chat", "messages": [{"role": "user", "text": spaced}]}});
        let r = handle_line(&chat.to_string());
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["rewrite"]["messages"][0]["content"], "hello world !");

        // …and the SAME hook on a SECOND pool "batch" — one process, N pools.
        let batch = serde_json::json!({"op": "transform", "request": {"pool": "batch", "messages": [{"role": "user", "text": spaced}]}});
        assert!(handle_line(&batch.to_string()).contains("rewrite"));

        // status → the metrics ARRAY, with one PER-POOL entry per metric via labels.
        let r = handle_line(r#"{"status":true}"#);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["status"]["settings"]["min_savings_pct"], 10);
        assert_eq!(v["status"]["settings"]["system_aware"], true);
        let metrics = v["status"]["metrics"].as_array().unwrap();

        // The array carries chars_saved_total for BOTH pools, distinguished only by labels.pool.
        let saved: Vec<&serde_json::Value> = metrics
            .iter()
            .filter(|m| m["name"] == "chars_saved_total")
            .collect();
        assert_eq!(saved.len(), 2, "one chars_saved_total entry per pool");
        let chat_saved = saved
            .iter()
            .find(|m| m["labels"]["pool"] == "chat")
            .expect("a chat-pool entry");
        assert_eq!(chat_saved["type"], "counter");
        assert!(chat_saved["value"].as_u64().unwrap() > 0);
        assert!(saved.iter().any(|m| m["labels"]["pool"] == "batch"));

        // The compression-ratio gauge is per-pool with unit/viz/max hints.
        let chat_ratio = metrics
            .iter()
            .find(|m| m["name"] == "compression_ratio" && m["labels"]["pool"] == "chat")
            .expect("a chat compression_ratio entry");
        assert_eq!(chat_ratio["type"], "gauge");
        assert_eq!(chat_ratio["unit"], "%");
        assert_eq!(chat_ratio["max"], 100.0);
        assert!(chat_ratio["value"].as_f64().unwrap() > 0.0);

        // The dollars-saved estimate carries estimated + a valid CI (ci_low ≤ value ≤ ci_high).
        let chat_dollars = metrics
            .iter()
            .find(|m| m["name"] == "dollars_saved" && m["labels"]["pool"] == "chat")
            .expect("a chat dollars_saved entry");
        assert_eq!(chat_dollars["estimated"], true);
        let (lo, val, hi) = (
            chat_dollars["ci_low"].as_f64().unwrap(),
            chat_dollars["value"].as_f64().unwrap(),
            chat_dollars["ci_high"].as_f64().unwrap(),
        );
        assert!(lo <= val && val <= hi, "CI must bound the value");

        // Compress latency is a histogram with p50/p95/p99 quantiles, per pool.
        let chat_lat = metrics
            .iter()
            .find(|m| m["name"] == "compress_latency_us" && m["labels"]["pool"] == "chat")
            .expect("a chat compress_latency_us entry");
        assert_eq!(chat_lat["type"], "histogram");
        assert_eq!(chat_lat["viz"], "histogram");
        assert!(chat_lat["quantiles"]["0.5"].is_number());
        assert!(chat_lat["quantiles"]["0.95"].is_number());
        assert!(chat_lat["quantiles"]["0.99"].is_number());

        // transform → abstain below the threshold, and abstain when no prompt was projected.
        let tight = serde_json::json!({"op": "transform", "request": {"pool": "chat", "messages": [{"role": "user", "text": "already tight"}]}});
        assert_eq!(handle_line(&tight.to_string()).trim(), "{}");
        assert_eq!(
            handle_line(r#"{"op":"transform","request":{"pool":"chat"}}"#).trim(),
            "{}"
        );
        // a NOTIFY (tap) → NOTHING is written; unknown future ops → the safe `{}`.
        assert_eq!(
            handle_line(r#"{"op":"notify","request":{"pool":"chat"}}"#),
            ""
        );
        assert_eq!(
            handle_line(r#"{"op":"someday-new","request":{}}"#).trim(),
            "{}"
        );

        // configure → ack echoes the pushed version and every knob applies…
        let r = handle_line(
            r#"{"configure":{"hook":"headroom","settings":{"min_savings_pct":90,"target_ratio_pct":40,"system_aware":false},"settings_version":7}}"#,
        );
        assert_eq!(r.trim(), r#"{"ack":{"settings_version":7}}"#);
        assert_eq!(MIN_SAVINGS_PCT.load(Ordering::Relaxed), 90);
        assert_eq!(TARGET_RATIO_PCT.load(Ordering::Relaxed), 40);
        assert_eq!(SYSTEM_AWARE.load(Ordering::Relaxed), 0);
        // …so the rewrite that cleared 10% now abstains at 90%.
        assert_eq!(handle_line(&chat.to_string()).trim(), "{}");

        // a bad push gets NO ack and applies NOTHING (fail-closed, all-or-nothing).
        let r = handle_line(
            r#"{"configure":{"settings":{"min_savings_pct":15,"target_ratio_pct":250},"settings_version":9}}"#,
        );
        assert_eq!(r.trim(), "{}");
        assert_eq!(MIN_SAVINGS_PCT.load(Ordering::Relaxed), 90);
        assert_eq!(TARGET_RATIO_PCT.load(Ordering::Relaxed), 40);

        // garbage / unknown messages are a safe abstain, never a crash.
        assert_eq!(handle_line("not json").trim(), "{}");
        assert_eq!(handle_line(r#"{"unknown":1}"#).trim(), "{}");
    }
}
