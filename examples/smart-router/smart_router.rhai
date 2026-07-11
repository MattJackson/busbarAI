// Smart-router routing policy for busbar (`route: script`, needs the
// `script-policy` cargo feature). Same logic as policy_server.py, in-process.
//
// The script sees `req`, `candidates`, and `ctx` (see docs/routing: the Rhai
// environment). Unlike the webhook payload, candidates here also carry `tags`.
// Return an array of candidate idx values, most preferred first; `()` or a
// non-array abstains (busbar falls back per `on_error`, default weighted).

// ── classify: shape signals only; busbar never exposes prompt text ──────────
let bucket = if req.has_tools {
    "code"
} else if (req.max_tokens ?? 0) >= 4096 || req.total_chars > 24000 {
    "long-form"
} else if !req.stream && req.message_count <= 1 {
    "bulk"
} else {
    "quick-answer"
};

// weights: [cost, latency, concurrency], plus the tiers to boost
let w = switch bucket {
    "quick-answer" => [0.30, 0.50, 0.20, ["small", "overflow"]],
    "code"         => [0.10, 0.20, 0.20, ["large", "primary"]],
    "long-form"    => [0.20, 0.10, 0.20, ["large", "primary"]],
    _              => [0.60, 0.10, 0.30, ["small", "overflow"]],
};

// normalization ceilings across the candidate set
let max_cost = 0.0; let max_lat = 0.0; let max_conc = 0;
for c in candidates {
    if c.cost_per_mtok != () && c.cost_per_mtok > max_cost { max_cost = c.cost_per_mtok; }
    if c.latency_ms != () && c.latency_ms > max_lat { max_lat = c.latency_ms; }
    if c.available_concurrency > max_conc { max_conc = c.available_concurrency; }
}

let scored = [];
for c in candidates {
    // missing signals score neutral (0.5) so a cold lane is not punished
    let cost_s = if c.cost_per_mtok == () || max_cost == 0.0 { 0.5 } else { 1.0 - c.cost_per_mtok / max_cost };
    let lat_s  = if c.latency_ms == () || max_lat == 0.0 { 0.5 } else { 1.0 - c.latency_ms / max_lat };
    let conc_s = if max_conc == 0 { 0.5 } else { c.available_concurrency.to_float() / max_conc.to_float() };
    let s = w[0] * cost_s + w[1] * lat_s + w[2] * conc_s;
    if c.tier != () && w[3].contains(c.tier) { s += 0.5; }
    // tags are script-only: an operator "quality" label the webhook cannot see
    if bucket == "code" && c.tags.contains("code") { s += 0.25; }
    if c.rate_headroom != () { s *= 0.5 + 0.5 * c.rate_headroom; }
    scored.push([s, c.idx]);
}
scored.sort(|a, b| if a[0] > b[0] { -1 } else if a[0] < b[0] { 1 } else { 0 });

let order = [];
for s in scored { order.push(s[1]); }
order
