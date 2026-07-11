//! Smart-router hook for busbar (`route: socket`) — task-aware model selection as an
//! operator-run Rust binary on a Unix domain socket.
//!
//! Busbar writes ONE newline-terminated JSON line per decision (the same projection the HTTP
//! webhook receives: request shape + candidates + context) and reads ONE line back:
//! `{"order":[idx,...]}` ranked most-preferred first, or `{"abstain":true}` for "no opinion".
//! The connection is kept alive across decisions; busbar reconnects if this process restarts.
//!
//! Fail-safe: if this binary is slow, down, or wrong, busbar coerces the decision to the pool's
//! `on_error` (default weighted) after `policy.timeout_ms` (default 150 ms). Killing this process
//! mid-traffic never fails a request.
//!
//! Run:   cargo run --release -- /run/busbar/router.sock
//! Pool:  route: socket / policy.socket: /run/busbar/router.sock
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

// ── What busbar sends (shape signals only — never prompt text) ──────────────────────────────────

#[derive(Deserialize)]
struct Req {
    #[serde(default)]
    has_tools: bool,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    total_chars: usize,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    message_count: usize,
}

#[derive(Deserialize)]
struct Cand {
    idx: usize,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    cost_per_mtok: Option<f64>,
    #[serde(default)]
    latency_ms: Option<f64>, // rolling EWMA; null until the lane has served
    #[serde(default)]
    available_concurrency: usize,
    #[serde(default)]
    rate_headroom: Option<f64>, // 1.0 = far from the rate cap, 0.0 = at it
}

#[derive(Deserialize)]
struct Payload {
    request: Req,
    candidates: Vec<Cand>,
}

// ── The policy: classify the request, score every candidate through that bucket's dials ─────────

/// Per-bucket `(cost, latency, concurrency)` weights + the quality tiers to boost. The weights sum
/// to 1.0 so the tier boost (0.5) is a consistent TILT toward quality, never an override of a
/// lane's live health.
fn weights(r: &Req) -> (f64, f64, f64, &'static [&'static str]) {
    if r.has_tools {
        (0.20, 0.40, 0.40, &["large", "primary"]) // code / agent traffic: capability + latency
    } else if r.max_tokens.unwrap_or(0) >= 4096 || r.total_chars > 24_000 {
        (0.40, 0.20, 0.40, &["large", "primary"]) // long-form (~4 chars/token: 24k ≈ 6k tokens)
    } else if !r.stream && r.message_count <= 1 {
        (0.60, 0.10, 0.30, &["small", "overflow"]) // bulk single-shot: optimize cost
    } else {
        (0.30, 0.50, 0.20, &["small", "overflow"]) // interactive default: optimize latency
    }
}

const TIER_BOOST: f64 = 0.5;

fn rank(p: &Payload) -> Vec<usize> {
    let (w_cost, w_lat, w_conc, tiers) = weights(&p.request);
    // Normalization ceilings across the candidate set.
    let max_cost = p.candidates.iter().filter_map(|c| c.cost_per_mtok).fold(0.0, f64::max);
    let max_lat = p.candidates.iter().filter_map(|c| c.latency_ms).fold(0.0, f64::max);
    let max_conc = p.candidates.iter().map(|c| c.available_concurrency).max().unwrap_or(0);
    // Missing signals score neutral (0.5) so a cold lane is neither punished nor favored.
    let score = |c: &Cand| -> f64 {
        let cost_s = c.cost_per_mtok.map_or(0.5, |x| if max_cost > 0.0 { 1.0 - x / max_cost } else { 0.5 });
        let lat_s = c.latency_ms.map_or(0.5, |x| if max_lat > 0.0 { 1.0 - x / max_lat } else { 0.5 });
        let conc_s = if max_conc > 0 { c.available_concurrency as f64 / max_conc as f64 } else { 0.5 };
        let mut s = w_cost * cost_s + w_lat * lat_s + w_conc * conc_s;
        if c.tier.as_deref().is_some_and(|t| tiers.contains(&t)) {
            s += TIER_BOOST; // the operator's quality judgment, encoded as `tier` on the member
        }
        if let Some(h) = c.rate_headroom {
            s *= 0.5 + 0.5 * h; // back off lanes near their rate cap
        }
        s
    };
    let mut scored: Vec<(f64, usize)> = p.candidates.iter().map(|c| (score(c), c.idx)).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().map(|(_, i)| i).collect()
}

// ── The transport: newline-delimited JSON over a Unix socket, one thread per connection ─────────

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/busbar-router.sock".into());
    let _ = std::fs::remove_file(&path); // stale socket file from a previous run
    let listener = UnixListener::bind(&path).expect("bind socket path");
    eprintln!("[smart-router-hook] listening on {path}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break, // busbar closed the connection
                    Ok(_) => {}
                }
                // Never crash on bad input: abstain is the clean "no opinion" path.
                let reply = match serde_json::from_str::<Payload>(&line) {
                    Ok(p) if !p.candidates.is_empty() => {
                        format!("{{\"order\":{}}}\n", serde_json::to_string(&rank(&p)).unwrap())
                    }
                    _ => "{\"abstain\":true}\n".to_string(),
                };
                if writer.write_all(reply.as_bytes()).is_err() {
                    break;
                }
            }
        });
    }
}
