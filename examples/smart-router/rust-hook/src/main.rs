//! A smart-router hook for busbar (a `socket:` ordering gate).
//!
//! This binary IS the routing policy. Busbar connects to the Unix socket below, writes one line of
//! JSON per decision (the request's shape + every candidate lane's live signals), and reads one
//! line back: the order to try the lanes in. That's the whole job.
//!
//! Run it:            cargo run --release -- /run/busbar/router.sock
//! Point busbar at it:  an inline hook ref on the pool
//!                      hooks: [ { module: socket, settings: { path: /run/busbar/router.sock }, kind: gate } ]
//!
//! If this process is slow, wrong, or dead, busbar falls back per the hook's `on_error` after
//! its `timeout_ms` (default 1 ms). Kill it mid-traffic and requests keep flowing.
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

fn main() {
    // The socket path is our identity: busbar's pool config points here. First arg or a default.
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/busbar-router.sock".into());
    // A previous run may have left its socket file behind; a stale file would make bind() fail.
    let _ = std::fs::remove_file(&path);
    // Own the socket. From here on, we are the routing policy for any pool that names this path.
    let listener = UnixListener::bind(&path).expect("bind socket path");
    eprintln!("[smart-router-hook] listening on {path}");

    // Busbar opens one connection and keeps it alive across decisions (that is where the
    // microseconds come from). One thread per connection is plenty: a decision is ~microseconds.
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let mut line = String::new();
            // The conversation: one JSON line in, one JSON line out, forever, on this connection.
            loop {
                line.clear();
                // Read busbar's next decision request. 0 bytes = busbar closed the connection.
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                // Parse it. If we can't (or there is nothing to rank), say "no opinion" —
                // busbar treats abstain as "use your default", never as a failure.
                let reply = match serde_json::from_str::<Payload>(&line) {
                    Ok(p) if !p.candidates.is_empty() => {
                        // The actual decision: rank the lanes for THIS request (below).
                        format!("{{\"order\":{}}}\n", serde_json::to_string(&rank(&p)).unwrap())
                    }
                    _ => "{\"abstain\":true}\n".to_string(),
                };
                // Answer. If busbar is gone, this connection is done; it will reconnect to a new one.
                if writer.write_all(reply.as_bytes()).is_err() {
                    break;
                }
            }
        });
    }
}

/// The dials one kind of request turns: how much it cares about each live signal (the three
/// weights sum to 1.0), and which operator-declared quality tiers it should lean toward.
struct Dials {
    cost: f64,          // how much cheap matters (0.0 = not at all, 1.0 = only thing)
    latency: f64,       // how much fast matters
    free_capacity: f64, // how much an unloaded lane matters
    prefer_tiers: &'static [&'static str], // tiers to tilt toward (+0.5)
}

/// The decision. Two steps: figure out what KIND of request this is (the bucket), then score every
/// candidate lane through that bucket's priorities and sort, best first.
fn rank(p: &Payload) -> Vec<usize> {
    // Step 1: the bucket picks the dials — how much this request cares about cost vs latency vs
    // free capacity, and which quality tier it should lean toward.
    let dials = weights(&p.request);

    // Normalize each signal against the best/worst in THIS pool, so scores are comparable.
    let max_cost = p.candidates.iter().filter_map(|c| c.cost_per_mtok).fold(0.0, f64::max);
    let max_lat = p.candidates.iter().filter_map(|c| c.latency_ms).fold(0.0, f64::max);
    let max_conc = p.candidates.iter().map(|c| c.available_concurrency).max().unwrap_or(0);

    // Step 2: score one lane. Cheaper is better, faster is better, more free slots is better.
    let score = |c: &Cand| -> f64 {
        // Each signal becomes 0.0 (worst in pool) .. 1.0 (best in pool).
        // A missing signal (cold lane, undeclared cost) scores a neutral 0.5: never punished,
        // never favored.
        let cost_s = c.cost_per_mtok.map_or(0.5, |x| if max_cost > 0.0 { 1.0 - x / max_cost } else { 0.5 });
        let lat_s = c.latency_ms.map_or(0.5, |x| if max_lat > 0.0 { 1.0 - x / max_lat } else { 0.5 });
        let conc_s = if max_conc > 0 { c.available_concurrency as f64 / max_conc as f64 } else { 0.5 };

        // Blend the three live signals with the bucket's dials.
        let mut s = dials.cost * cost_s + dials.latency * lat_s + dials.free_capacity * conc_s;

        // Your quality judgment: a lane whose operator-declared tier fits this bucket gets a +0.5
        // tilt. A TILT, not a mandate: a preferred lane that is saturated and slow still loses to
        // a healthy one (its live signals score ~0, the healthy lane's score ~1).
        if c.tier.as_deref().is_some_and(|t| dials.prefer_tiers.contains(&t)) {
            s += 0.5;
        }

        // Back off a lane that is close to its rate limit: at full headroom this is x1.0,
        // at the cap it halves the score. Steers traffic away from a looming 429.
        if let Some(h) = c.rate_headroom {
            s *= 0.5 + 0.5 * h;
        }
        s
    };

    // Score every lane, sort best-first, return the lane indices in that order.
    // Busbar tries them in this order; its breaker still skips anything unhealthy.
    let mut scored: Vec<(f64, usize)> = p.candidates.iter().map(|c| (score(c), c.idx)).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().map(|(_, i)| i).collect()
}

/// What kind of request is this? Pure shape: routing hooks get no prompt text by default.
/// Each bucket returns its own dial settings for `rank` to score through.
fn weights(r: &Req) -> Dials {
    // Four kinds of request, four lanes, one natural home each. The tier names are whatever YOU
    // declare on your pool members; here, the ladder every dev knows: fable is the best and most
    // expensive, then opus, then sonnet, down to haiku, cheap and fast.
    if r.has_tools {
        // Tools declared = agent / code traffic. The work is hard: send it to the frontier model.
        Dials { cost: 0.20, latency: 0.40, free_capacity: 0.40, prefer_tiers: &["fable"] }
    } else if r.max_tokens.unwrap_or(0) >= 4096 || r.total_chars > 24_000 {
        // A big ask or a big prompt (~4 chars/token, 24k chars ≈ 6k tokens) = long-form work.
        // Deep and big, but it takes a while anyway, so latency matters least. Opus territory.
        Dials { cost: 0.40, latency: 0.20, free_capacity: 0.40, prefer_tiers: &["opus"] }
    } else if !r.stream && r.message_count <= 1 {
        // Single-shot, nobody watching it stream = batch work. The cheapest lane wins.
        Dials { cost: 0.60, latency: 0.10, free_capacity: 0.30, prefer_tiers: &["haiku"] }
    } else {
        // A human waiting on an interactive answer. The everyday driver: fast and capable.
        Dials { cost: 0.30, latency: 0.50, free_capacity: 0.20, prefer_tiers: &["sonnet"] }
    }
}

// ── The wire types: exactly what busbar sends. Same JSON as the webhook transport. ──────────────

/// The request's SHAPE. No prompt text or message bodies ride the routing payload by default.
#[derive(Deserialize)]
struct Req {
    #[serde(default)]
    has_tools: bool, // any tools declared on the request?
    #[serde(default)]
    max_tokens: Option<u32>, // the caller's requested output cap, if any
    #[serde(default)]
    total_chars: usize, // prompt size across system + messages (~4 chars/token)
    #[serde(default)]
    stream: bool, // is a human watching this stream?
    #[serde(default)]
    message_count: usize, // conversation length
}

/// One candidate lane: your declared metadata + busbar's live signals for it.
#[derive(Deserialize)]
struct Cand {
    idx: usize, // the handle we echo back in `order`
    #[serde(default)]
    tier: Option<String>, // YOUR quality label on the pool member (e.g. "large")
    #[serde(default)]
    cost_per_mtok: Option<f64>, // YOUR declared cost on the pool member
    #[serde(default)]
    latency_ms: Option<f64>, // busbar's rolling latency average; null until the lane has served
    #[serde(default)]
    available_concurrency: usize, // free slots on the lane right now
    #[serde(default)]
    rate_headroom: Option<f64>, // 1.0 = far from the rate cap, 0.0 = at it
}

/// One decision request off the wire: the request shape + every candidate lane.
#[derive(Deserialize)]
struct Payload {
    request: Req,
    candidates: Vec<Cand>,
}
