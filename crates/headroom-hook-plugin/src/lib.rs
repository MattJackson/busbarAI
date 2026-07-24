// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first-party **`headroom`** `kind: hook` plugin — a signed, trusted, dlopen'd PROMPT-COMPRESSION
//! rewrite gate.
//!
//! It is a `cdylib` implementing the SDK's [`HookHandler`] trait. On the `transform` op (the `prompt:
//! rw` gate's rewrite pass) it receives the engine's projected prompt (`system` + `messages`) and
//! returns a DETERMINISTIC, RULE-BASED, lossless-of-meaning **compressed rewrite**. Everywhere it is
//! uncertain — nothing safe to compress, no prompt granted, an unexpected projection shape — it
//! **ABSTAINS** (returns the input unchanged / an empty rewrite). It NEVER fails the request.
//!
//! ## The manifest `needs` (recommended)
//!
//! Headroom is a `prompt: rw` gate. Its signed packaging manifest MUST declare `needs.prompt = rw` (it
//! reads AND rewrites the prompt); it declares NOTHING on `user` (identity is irrelevant to
//! compression). This is authored at PACK time (`busbar-plugin-pack pack ... --kind hook
//! --needs-prompt rw`), NOT hardcoded here — the loader/manifest own the declared intent. Recap:
//!
//! ```text
//! needs: { prompt: rw }
//! ```
//!
//! Remember the belt-and-suspenders rule: even with `needs.prompt = rw` declared, the CORE projects the
//! prompt into the `transform` payload ONLY when the OPERATOR also grants `prompt: rw`. When the grant
//! is absent the payload carries no prompt, and Headroom simply abstains — it can never coerce content.
//!
//! ## Ops
//!
//! - **`transform`** — the compression pass. Reads `system` + `messages` from the projection, rewrites
//!   each with the [`compress`] v1 rules, and returns a `{"rewrite":{...}}` reply IFF the rewrite
//!   actually shrank something; otherwise a `{}` abstain. Accounts the char delta into cumulative
//!   metrics.
//! - **`decide` / `notify`** — ABSTAIN / no-op. Headroom is a rewrite gate, not a router or a tap.
//! - **`configure`** — accept a settings push (the `level` aggressiveness knob) and re-validate it.
//! - **`describe`** — the config schema.
//! - **`status`** — cumulative honest savings (transforms run, chars in/out/saved).
//!
//! ## v1 is conservative, by design (flagged for review)
//!
//! The compressor ([`compress`]) is a DEPENDENCY-LIGHT, deterministic, rule-based normalizer — no ML,
//! no network, no tokenizer. It removes only redundancy indistinguishable from the original (whitespace
//! runs, blank runs, consecutive-duplicate lines/blocks). A semantic/LLMLingua-style compressor would
//! save far more but is lossy + non-deterministic + model-backed; it is a deliberate FUTURE
//! enhancement, out of v1 (see [`compress`]'s module docs).

mod compress;

use busbar_plugin_sdk::HookHandler;
use compress::{approx_tokens, compress, Level};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// The plugin's `settings` config (the operator-owned `settings:` map the engine passes at `open` and
/// re-pushes on `configure`).
#[derive(Deserialize, Default)]
struct Config {
    /// The aggressiveness knob: `conservative` | `balanced` (default). Both are lossless-of-meaning;
    /// an unknown value resolves to the safe default (never something MORE aggressive).
    #[serde(default)]
    level: Option<String>,
}

/// The live gate: the resolved compression [`Level`] plus cumulative, honest savings counters. The
/// counters are atomics because [`HookHandler`] methods take `&self` (the engine may drive `transform`
/// concurrently); they are monotonic and non-secret (aggregate char counts only — never prompt text).
struct Headroom {
    level: Level,
    /// Number of `transform` ops that produced an actual rewrite (a shrink).
    transforms: AtomicU64,
    /// Cumulative characters received across compressed fields.
    chars_in: AtomicU64,
    /// Cumulative characters emitted across compressed fields.
    chars_out: AtomicU64,
}

impl Headroom {
    /// Build the gate from validated config. Config cannot fail to load (an unknown `level` degrades to
    /// the default), so this is infallible — Headroom never fails closed at LOAD, because a compression
    /// gate that refused to load would be a worse failure mode than one that conservatively abstains.
    fn new(cfg: Config) -> Self {
        Headroom {
            level: cfg.level.as_deref().map(Level::parse).unwrap_or_default(),
            transforms: AtomicU64::new(0),
            chars_in: AtomicU64::new(0),
            chars_out: AtomicU64::new(0),
        }
    }

    /// Compress one string field, accounting its char delta into the cumulative counters. Returns the
    /// compressed value AND whether it actually changed (so the caller only emits a rewrite when there
    /// was a real saving).
    fn compress_field(&self, s: &str) -> (String, bool) {
        let out = compress(s, self.level);
        self.chars_in.fetch_add(s.len() as u64, Ordering::Relaxed);
        self.chars_out
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        let changed = out != s;
        (out, changed)
    }
}

/// Extract the projected prompt from the `transform` payload. The engine's `hooks::wire` projection
/// carries the prompt under `request.messages` (an array of `{role, text|content}`) and optionally
/// `request.system` — but ONLY when the operator granted `prompt: rw` AND the manifest declared the
/// need. When the grant was not given these keys are absent, and we get `None` → abstain. This reads
/// LIBERALLY (accepts either `text` or `content` for the message body) and never errors: a shape it
/// does not recognize yields `None`, i.e. an abstain, not a failure.
fn projected_prompt(payload: &serde_json::Value) -> Option<&serde_json::Value> {
    payload.get("request")
}

impl HookHandler for Headroom {
    /// `transform` — the compression pass. Reads the granted prompt projection, compresses `system`
    /// and each message body, and returns a `rewrite` reply carrying the shrunk messages IFF something
    /// actually got smaller. If the grant was not given (no prompt in the payload), nothing changed, or
    /// the shape is unrecognized → `{}` (abstain: the engine proceeds with the ORIGINAL body). Never
    /// fails the request.
    fn transform(&self, payload: &serde_json::Value) -> serde_json::Value {
        let Some(request) = projected_prompt(payload) else {
            return serde_json::json!({}); // no grant / no prompt projected → abstain
        };

        let mut any_change = false;

        // Compress the system prompt if present (a string under request.system).
        let mut rewrite = serde_json::Map::new();
        if let Some(system) = request.get("system").and_then(|s| s.as_str()) {
            let (out, changed) = self.compress_field(system);
            any_change |= changed;
            rewrite.insert("system".to_string(), serde_json::Value::String(out));
        }

        // Compress each message body. Preserve the role and every other field verbatim; only the text
        // body is rewritten. A message whose body is not a string is passed through UNCHANGED (never
        // dropped — abstain-on-uncertainty at the per-message granularity).
        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            let mut out_messages = Vec::with_capacity(messages.len());
            for msg in messages {
                let mut obj = match msg.as_object() {
                    Some(o) => o.clone(),
                    // A non-object message is unexpected; relay it verbatim rather than dropping it.
                    None => {
                        out_messages.push(msg.clone());
                        continue;
                    }
                };
                // The projection uses `text`; accept `content` too (liberal read). Rewrite in place
                // under the SAME key it was read from, so the reply mirrors the projection shape.
                for key in ["text", "content"] {
                    if let Some(body) = obj.get(key).and_then(|v| v.as_str()) {
                        let (out, changed) = self.compress_field(body);
                        any_change |= changed;
                        obj.insert(key.to_string(), serde_json::Value::String(out));
                        break;
                    }
                }
                out_messages.push(serde_json::Value::Object(obj));
            }
            rewrite.insert(
                "messages".to_string(),
                serde_json::Value::Array(out_messages),
            );
        }

        // ABSTAIN unless we actually shrank something: an empty/no-op rewrite must not churn the body.
        // The engine treats a reply with no non-empty `rewrite.messages` as Abstain (proceed with the
        // original), so returning `{}` here is the honest "nothing to compress" answer.
        if !any_change || !rewrite.contains_key("messages") {
            return serde_json::json!({});
        }

        self.transforms.fetch_add(1, Ordering::Relaxed);
        serde_json::json!({ "rewrite": rewrite })
    }

    /// `decide` — ABSTAIN. Headroom ranks nothing; it is a rewrite gate, not a router.
    fn decide(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
    }

    /// `notify` — no-op. Headroom is not a tap; it observes nothing out of band.
    fn notify(&self, _payload: &serde_json::Value) {}

    /// `configure` — accept a settings push and RE-VALIDATE the `level` knob. An unknown/absent level
    /// is not an error (it resolves to the safe default), so any settings push ACKs — the live gate
    /// keeps its already-resolved level; committing a new level is a reload concern (parity with the
    /// webrequest forwarder, which keeps its live URL and treats the commit as a reload). We still
    /// PARSE the pushed level to prove it is well-formed JSON of the expected shape.
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        // A `level` present but not a string is a malformed push → NACK. Absent or a valid string ACKs
        // (an unrecognized string resolves to the default; that is not a malformed push).
        match settings.get("level") {
            Some(v) => v.is_string(),
            None => true,
        }
    }

    /// `describe` — Headroom's own config schema (the `level` knob).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": {
                "type": "object",
                "properties": {
                    "level": {
                        "type": "string",
                        "enum": ["conservative", "balanced"],
                        "description": "Compression aggressiveness. Both levels are deterministic and \
                                        lossless-of-meaning (rule-based v1). Default: balanced. An \
                                        unknown value resolves to balanced."
                    }
                }
            }
        })
    }

    /// `status` — cumulative HONEST savings. Reports the resolved level and aggregate char counts
    /// (in/out/saved) plus a coarse token ESTIMATE (chars/4, explicitly labeled an estimate — v1 has
    /// no tokenizer). No prompt/user content is ever surfaced here, only aggregate counts.
    fn status(&self) -> serde_json::Value {
        let chars_in = self.chars_in.load(Ordering::Relaxed);
        let chars_out = self.chars_out.load(Ordering::Relaxed);
        let chars_saved = chars_in.saturating_sub(chars_out);
        let transforms = self.transforms.load(Ordering::Relaxed);
        serde_json::json!({
            "status": {
                "settings": { "level": self.level.as_str() },
                "metrics": [
                    { "name": "headroom_transforms_total", "value": transforms },
                    { "name": "headroom_chars_in_total", "value": chars_in },
                    { "name": "headroom_chars_out_total", "value": chars_out },
                    { "name": "headroom_chars_saved_total", "value": chars_saved },
                    // A coarse token-savings ESTIMATE (chars/4). Named to make the estimate explicit —
                    // v1 has no tokenizer, so this is an order-of-magnitude read, not a billed count.
                    { "name": "headroom_est_tokens_saved_total", "value": approx_tokens(chars_saved as usize) as u64 }
                ]
            }
        })
    }
}

/// Construct the gate from the engine-passed JSON config (the `settings:` map). An empty/missing config
/// is fine (all fields default); a MALFORMED config is a fail-closed load error (better a loud load
/// failure than a silently mis-parsed knob). An UNKNOWN `level` value is NOT malformed — it parses and
/// resolves to the safe default.
fn open(cfg: &str) -> Result<Box<dyn HookHandler>, String> {
    let config: Config = if cfg.trim().is_empty() {
        Config::default()
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("headroom: invalid plugin config: {e}"))?
    };
    Ok(Box::new(Headroom::new(config)))
}

busbar_plugin_sdk::export_hook_plugin!(open);

#[cfg(test)]
mod tests {
    use super::*;

    /// `open` accepts empty/missing config and a valid `level`; a malformed config fails closed; an
    /// unknown level resolves to the default (not an error).
    #[test]
    fn open_config_handling() {
        assert!(open("").is_ok(), "empty config uses defaults");
        assert!(open("{}").is_ok(), "no level uses default");
        assert!(open(r#"{"level":"conservative"}"#).is_ok());
        assert!(
            open(r#"{"level":"nonsense"}"#).is_ok(),
            "unknown level resolves to default, not an error"
        );
        assert!(open("{ not json").is_err(), "malformed config fails closed");
    }

    /// A `transform` with the prompt projected (grant given) rewrites and shrinks; the reply carries
    /// the compressed messages. Savings are accounted into the cumulative counters.
    #[test]
    fn transform_compresses_when_granted() {
        let h = Headroom::new(Config::default());
        let payload = serde_json::json!({
            "request": {
                "system": "You are   helpful.\n\n\n\nBe concise.",
                "messages": [
                    { "role": "user", "text": "hello     world\nhello     world" }
                ]
            }
        });
        let reply = h.transform(&payload);
        let rewrite = reply.get("rewrite").expect("a rewrite reply");
        assert_eq!(rewrite["system"], "You are helpful.\n\nBe concise.");
        assert_eq!(rewrite["messages"][0]["text"], "hello world");
        assert_eq!(rewrite["messages"][0]["role"], "user", "role preserved");
        // Savings were accounted.
        assert!(h.chars_in.load(Ordering::Relaxed) > h.chars_out.load(Ordering::Relaxed));
        assert_eq!(h.transforms.load(Ordering::Relaxed), 1);
    }

    /// ABSTAIN when the grant was NOT given: no `request` in the payload → `{}` (never a failure).
    #[test]
    fn transform_abstains_without_grant() {
        let h = Headroom::new(Config::default());
        // No `request` key at all (the core projected no prompt because the grant was absent).
        assert_eq!(h.transform(&serde_json::json!({})), serde_json::json!({}));
        // A request with no messages/system → abstain.
        assert_eq!(
            h.transform(&serde_json::json!({"request": {}})),
            serde_json::json!({})
        );
    }

    /// ABSTAIN when there is nothing to compress: an already-tight prompt yields `{}` (no churn), and
    /// no transform is counted.
    #[test]
    fn transform_abstains_when_nothing_to_compress() {
        let h = Headroom::new(Config::default());
        let payload = serde_json::json!({
            "request": {
                "messages": [ { "role": "user", "text": "already tight prose here" } ]
            }
        });
        assert_eq!(h.transform(&payload), serde_json::json!({}));
        assert_eq!(
            h.transforms.load(Ordering::Relaxed),
            0,
            "a no-op transform is not counted"
        );
    }

    /// A non-string message body is passed through UNCHANGED (never dropped) — abstain-on-uncertainty
    /// at the per-message granularity.
    #[test]
    fn transform_passes_through_non_string_bodies() {
        let h = Headroom::new(Config::default());
        let payload = serde_json::json!({
            "request": {
                "messages": [
                    { "role": "user", "content": [{ "type": "image" }] },
                    { "role": "user", "text": "squeeze    me\n\n\n\nnow" }
                ]
            }
        });
        let reply = h.transform(&payload);
        let msgs = reply["rewrite"]["messages"].as_array().expect("messages");
        // The structured (non-string) message is preserved verbatim.
        assert_eq!(msgs[0]["content"], serde_json::json!([{ "type": "image" }]));
        // The string message got compressed.
        assert_eq!(msgs[1]["text"], "squeeze me\n\nnow");
    }

    /// `decide` and `notify` abstain / no-op (Headroom is not a router or a tap).
    #[test]
    fn decide_and_notify_are_inert() {
        let h = Headroom::new(Config::default());
        assert_eq!(h.decide(&serde_json::json!({})), serde_json::json!({}));
        h.notify(&serde_json::json!({"anything": true})); // no panic, no effect
    }

    /// `configure` ACKs a well-formed level push (or an absent level) and NACKs a malformed one.
    #[test]
    fn configure_validates_level() {
        let h = Headroom::new(Config::default());
        let mut ok = serde_json::Map::new();
        ok.insert("level".into(), serde_json::json!("conservative"));
        assert!(h.configure(&ok, 2));
        assert!(h.configure(&serde_json::Map::new(), 3), "absent level acks");
        let mut bad = serde_json::Map::new();
        bad.insert("level".into(), serde_json::json!(42));
        assert!(
            !h.configure(&bad, 4),
            "a non-string level is a malformed push"
        );
    }

    /// `describe` returns the config schema; `status` reports the level + cumulative honest savings and
    /// surfaces no prompt content.
    #[test]
    fn describe_and_status_report_own_state() {
        let h = Headroom::new(Config {
            level: Some("conservative".into()),
        });
        assert_eq!(h.describe()["schema"]["type"], "object");
        // Run a transform so there is something to report.
        let _ = h.transform(&serde_json::json!({
            "request": { "messages": [{ "role": "user", "text": "a\n\n\n\nb" }] }
        }));
        let status = h.status();
        assert_eq!(status["status"]["settings"]["level"], "conservative");
        let metrics = status["status"]["metrics"].as_array().unwrap();
        let saved = metrics
            .iter()
            .find(|m| m["name"] == "headroom_chars_saved_total")
            .unwrap();
        assert!(saved["value"].as_u64().unwrap() >= 2, "blank run collapsed");
    }
}
