// Copyright (C) 2026 Busbar Inc and contributors

//! A COMPRESSION GATE for busbar — the `rewrite` reply arm, end to end.
//!
//! This binary is a rewrite gate (`kind: gate, prompt: rw`) on a Unix socket: busbar sends it each
//! request's flattened prompt text, and it replies with a smaller replacement body — or nothing.
//! The compression here is deliberately simple (collapse whitespace runs inside every message) so
//! the WIRE is the lesson, not the compressor; swap `compress_text` for your real one.
//!
//! It speaks all five wire messages:
//!   configure — busbar's FIRST message on every connection (and a live push on
//!               `PATCH /api/v1/admin/hooks/{name}/settings`): apply the settings, ack the version.
//!   describe  — reply with a JSON schema for those settings (`GET /api/v1/admin/hooks/{name}/schema`).
//!   transform — the rewrite pass: prompt text in, `{"rewrite": ...}` or `{}` (abstain) out.
//!   (decide / notify never reach a pure rewrite gate, but unknown messages get a safe `{}`.)
//!
//! Fail-safe by construction: any reply busbar can't parse — or none at all — means "proceed with
//! the ORIGINAL body" (`on_error` default `nothing`). A broken compressor never corrupts a request.
//!
//! Run it:              cargo run --release -- /run/busbar/compress.sock
//! Register it:         hooks: { compressor: { kind: gate, socket: /run/busbar/compress.sock,
//!                                             prompt: rw, global: true,
//!                                             settings: { min_savings_pct: 10 } } }

use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};

/// The one knob: rewrite only when the collapsed body is at least this % smaller. Below it the
/// savings aren't worth a body swap — abstain and busbar proceeds untouched. Shared across
/// connections so a live settings push retunes every future request at once.
static MIN_SAVINGS_PCT: AtomicU64 = AtomicU64::new(10);
/// Lifetime characters removed by compression — the hook's own operational metric, self-reported
/// via the `status` message (monotonic counter; busbar exposes it on the admin API / Prometheus).
static TOKENS_SAVED: AtomicU64 = AtomicU64::new(0);

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
/// never as an error (the append-only evolvability rule).
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
        Some("transform") => {
            if let Some(req) = v.get("request") {
                return transform(req);
            }
            "{}\n".into()
        }
        // A tap notify is fire-and-forget (busbar never reads a reply); a decide from this rw gate
        // is unreachable (rw gates fire on the transform pass) — abstain on both, and on any
        // future op we don't recognize.
        _ => "{}\n".into(),
    }
}

/// Apply a pushed settings map and ACK by echoing its version — the echo is what commits the PATCH
/// on busbar's side. A bad value gets NO ack, so busbar keeps the previous settings (fail-closed).
fn configure(cfg: &serde_json::Value) -> String {
    if let Some(p) = cfg.get("settings").and_then(|s| s.get("min_savings_pct")) {
        match p.as_u64().filter(|&n| n <= 100) {
            Some(n) => MIN_SAVINGS_PCT.store(n, Ordering::Relaxed),
            None => return "{}\n".into(), // out of range: refuse the whole push
        }
    }
    let version = cfg.get("settings_version").cloned().unwrap_or(0.into());
    format!("{{\"ack\":{{\"settings_version\":{version}}}}}\n")
}

/// Answer `describe` with the BARE settings JSON Schema — busbar proxies the reply VERBATIM at
/// `GET /api/v1/admin/hooks/{name}/schema`, so wrapping it (the old `{"schema": {...}}` form)
/// double-nests on the admin API.
fn describe() -> String {
    concat!(
        r#"{"type":"object","properties":{"min_savings_pct":"#,
        r#"{"type":"integer","minimum":0,"maximum":100,"#,
        r#""description":"rewrite only when the body shrinks by at least this percent"}}}"#,
        "\n"
    )
    .into()
}

/// Answer `status` with OBSERVED state: the settings this process is actually running + its own
/// operational metrics — the control-plane read busbar surfaces at
/// `GET /api/v1/admin/hooks/{name}/status` (and a dashboard built on busbar sees per-plug data).
fn status() -> String {
    let pct = MIN_SAVINGS_PCT.load(Ordering::Relaxed);
    let compressed = TOKENS_SAVED.load(Ordering::Relaxed);
    format!(
        concat!(
            r#"{{"status":{{"settings":{{"min_savings_pct":{pct}}},"#,
            r#""metrics":{{"chars_saved_total":{{"type":"counter","value":{saved},"#,
            r#""help":"characters removed by whitespace compression"}}}}}}}}"#,
            "\n"
        ),
        pct = pct,
        saved = compressed,
    )
}

/// The rewrite pass: collapse whitespace runs in every message; reply with the smaller body only
/// when the savings clear the threshold. Note the wire asymmetry — messages ARRIVE flattened as
/// `{role, text}` and the reply is BODY form `{role, content}`; the system prompt is read-only.
fn transform(req: &serde_json::Value) -> String {
    let Ok(p) = serde_json::from_value::<Projection>(req.clone()) else {
        return "{}\n".into();
    };
    let Some(messages) = p.messages else {
        return "{}\n".into(); // no prompt grant projected — nothing to compress
    };
    let before: usize = messages.iter().map(|m| m.text.len()).sum();
    if before == 0 {
        return "{}\n".into();
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
    let saved_pct = (before - after) * 100 / before;
    if (saved_pct as u64) < MIN_SAVINGS_PCT.load(Ordering::Relaxed) {
        return "{}\n".into(); // not worth a body swap — busbar proceeds untouched
    }
    // Count the committed savings — self-reported via `status` as `chars_saved_total`.
    TOKENS_SAVED.fetch_add((before - after) as u64, Ordering::Relaxed);
    format!(
        "{{\"rewrite\":{{\"messages\":{}}}}}\n",
        serde_json::to_string(&compressed).unwrap()
    )
}

/// The stand-in compressor: collapse every run of whitespace to a single space. Real compressors
/// (semantic dedup, history summarization) plug in here — the wire around it doesn't change.
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
    /// Absent unless the `prompt` grant projected it (and `[]` is possible: key off presence).
    #[serde(default)]
    messages: Option<Vec<Msg>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE sequential test on purpose: `MIN_SAVINGS_PCT` is process-global (exactly like the real
    /// hook), and cargo runs `#[test]`s in parallel — separate tests mutating it would race.
    #[test]
    fn five_message_wire_lifecycle() {
        // describe → the BARE settings schema (busbar proxies it verbatim — no wrapper).
        let r = handle_line(r#"{"describe":true}"#);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["properties"]["min_savings_pct"]["type"], "integer");
        assert!(
            v.get("schema").is_none(),
            "no wrapper: the reply IS the schema"
        );

        // transform (per-request messages carry the `op` discriminator) → rewrite when the collapse
        // clears the (default 10%) threshold; body form out.
        let spaced = "hello      world\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n!";
        let line = serde_json::json!({"op": "transform", "request": {"messages": [{"role": "user", "text": spaced}]}});
        let r = handle_line(&line.to_string());
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["rewrite"]["messages"][0]["content"], "hello world !");

        // status → observed settings + self-reported metrics (the committed rewrite counted).
        let r = handle_line(r#"{"status":true}"#);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["status"]["settings"]["min_savings_pct"], 10);
        assert_eq!(
            v["status"]["metrics"]["chars_saved_total"]["type"],
            "counter"
        );
        assert!(
            v["status"]["metrics"]["chars_saved_total"]["value"]
                .as_u64()
                .unwrap()
                > 0
        );

        // transform → abstain below the threshold, and abstain when no prompt was projected.
        let tight = serde_json::json!({"op": "transform", "request": {"messages": [{"role": "user", "text": "already tight"}]}});
        assert_eq!(handle_line(&tight.to_string()).trim(), "{}");
        assert_eq!(
            handle_line(r#"{"op":"transform","request":{"pool":"p"}}"#).trim(),
            "{}"
        );
        // a NOTIFY (tap) or an unknown future op → the safe `{}` (append-only evolvability).
        assert_eq!(
            handle_line(r#"{"op":"notify","request":{"pool":"p"}}"#).trim(),
            "{}"
        );
        assert_eq!(
            handle_line(r#"{"op":"someday-new","request":{}}"#).trim(),
            "{}"
        );

        // configure → ack echoes the pushed version and the setting applies…
        let r = handle_line(
            r#"{"configure":{"hook":"c","settings":{"min_savings_pct":90},"settings_version":7}}"#,
        );
        assert_eq!(r.trim(), r#"{"ack":{"settings_version":7}}"#);
        assert_eq!(MIN_SAVINGS_PCT.load(Ordering::Relaxed), 90);
        // …so the rewrite that cleared 10% now abstains at 90%.
        assert_eq!(handle_line(&line.to_string()).trim(), "{}");

        // a bad push gets NO ack and keeps the committed value (fail-closed).
        let r = handle_line(
            r#"{"configure":{"settings":{"min_savings_pct":250},"settings_version":9}}"#,
        );
        assert_eq!(r.trim(), "{}");
        assert_eq!(MIN_SAVINGS_PCT.load(Ordering::Relaxed), 90);

        // garbage / unknown messages are a safe abstain, never a crash.
        assert_eq!(handle_line("not json").trim(), "{}");
        assert_eq!(handle_line(r#"{"unknown":1}"#).trim(), "{}");
    }
}
