// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first-party **`webrequest`** `kind: hook` plugin — a signed, trusted, dlopen'd HTTP forwarder.
//!
//! It is a `cdylib` that implements the SDK's [`HookHandler`] trait and, on each hook op
//! (`decide`/`transform`/`notify`/`configure`/`describe`/`status`), POSTs the op envelope to an
//! operator-configured URL and returns the capped JSON reply VERBATIM. The engine parses that reply
//! through its own fail-closed `hooks::wire` normalizers, so this forwarder is a transparent relay for
//! the hook wire contract — it adds a network hop, never a second copy of the reply semantics.
//!
//! ## What it is for
//!
//! - **Migration** off the retired socket/webhook hook transport: point `settings.url` at the same
//!   service a `route: webhook` pool used and the wire is compatible (`{op, ...projection}` POST → a
//!   `{order|abstain|reject|restrict|rewrite}` reply).
//! - **Isolation** of untrusted hook logic: the untrusted brain runs REMOTELY behind this trusted,
//!   signed, dlopen'd forwarder. The forwarder — not busbar core — owns the outbound HTTP call.
//!
//! ## The security stance
//!
//! - **SSRF**: the configured URL is validated at `open`/`configure` against [`net_guard`] — the same
//!   policy the old webhook hook used (loopback sidecars allowed; link-local / IMDS / RFC1918 / CGNAT /
//!   ULA / cloud-metadata / alternate-IPv4-encodings blocked; plaintext `http://` only to loopback).
//! - **Redirects disabled** on the client (`redirect::none`): a target cannot 30x-redirect us to an
//!   internal host at runtime.
//! - **Tight timeouts**; the response body is **capped before allocation** (a hostile target cannot
//!   drive unbounded allocation) and **depth-guarded** before parse (a deeply-nested reply cannot blow
//!   the stack on deserialize).
//! - **Userinfo stripped** from every error string: any `user:pass@` an operator embedded in the URL
//!   never reaches an error the engine might log.
//! - **Grants are CORE-enforced**, never plugin-driven: this forwarder only relays whatever `payload`
//!   the core chose to project. It cannot cause prompt/user content to be sent. Its signed manifest
//!   declares `needs` = the intent it must relay (a forwarder that must relay prompt content for a
//!   `prompt: rw` gate declares `needs.prompt = rw`); the core STILL sends content only if the operator
//!   also grants it. See the crate README / packaging notes for the recommended manifest `needs`.

mod net_guard;

use busbar_plugin_sdk::HookHandler;
use serde::Deserialize;
use std::time::Duration;

/// Maximum reply body accepted from the target, in bytes. Matches the old webhook transport's
/// `MAX_HOOK_REPLY_BYTES` (64 KiB) — the reply is a small ranking/verdict object, so a body past this
/// is a hostile/buggy target and is refused BEFORE the bytes are allocated.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted in a reply. Matches busbar's `MAX_JSON_DEPTH` (128) — a security
/// floor, not a tunable. A reply deeper than this is refused before any `serde_json::Value` is built,
/// so it can neither be recursively deserialized nor recursively dropped (either overflows the stack).
const MAX_REPLY_DEPTH: usize = 128;

/// Default per-op wall-clock timeout when the operator does not set `timeout_ms`. Tight on purpose: a
/// gate is on the request path, so a slow target must fail fast (→ the engine coerces to `on_error`).
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// The plugin's `settings` config (the operator-owned `settings:` map the engine passes at `open`, and
/// re-pushes on `configure`).
#[derive(Deserialize, Default)]
struct Config {
    /// The target URL each op envelope is POSTed to. Validated against the SSRF guard at open/configure.
    url: String,
    /// Optional per-op wall-clock timeout override (milliseconds). Bounded to a sane ceiling so a
    /// fat-fingered huge value cannot make a gate hang the request path.
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// The live forwarder: a validated target URL, its own `reqwest::Client` (redirect-disabled), and a
/// dedicated current-thread tokio runtime to drive the async HTTP call from the SYNC `HookHandler`
/// methods (the engine already runs each `busbar_call` on its own `spawn_blocking` thread, so blocking
/// here never touches the engine's runtime workers).
struct Forwarder {
    url: reqwest::Url,
    client: reqwest::Client,
    timeout: Duration,
    rt: tokio::runtime::Runtime,
}

impl Forwarder {
    /// Build a forwarder from validated config. Fails closed if the URL is missing, malformed, blocked
    /// by the SSRF guard, or the client/runtime cannot be built.
    fn new(cfg: Config) -> Result<Self, String> {
        if cfg.url.trim().is_empty() {
            return Err("webrequest: settings.url is required".to_string());
        }
        let url = net_guard::validate_target_url(&cfg.url)?;
        // Bound the operator timeout to [1ms, 60s] — a gate that could block the request path for
        // minutes is a foot-gun, not a feature.
        let timeout_ms = cfg
            .timeout_ms
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1, 60_000);
        let client = reqwest::Client::builder()
            // Disable redirects so a target cannot 30x us onto an internal host at runtime (the
            // validated URL only guarantees the FIRST hop is safe).
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| format!("webrequest: failed to build HTTP client: {e}"))?;
        // A current-thread runtime is enough: one blocking op at a time per engine spawn_blocking call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("webrequest: failed to build async runtime: {e}"))?;
        Ok(Self {
            url,
            client,
            timeout: Duration::from_millis(timeout_ms),
            rt,
        })
    }

    /// POST the op `envelope` to the target and return the parsed reply `Value`. Bounded by `timeout`,
    /// redirect-disabled, body capped before allocation and depth-guarded before parse. Any error is a
    /// stable, userinfo-masked string — the caller degrades it to the safe reply for the op (the engine
    /// then fails open/closed exactly as it does for the retired transports).
    fn post_op(&self, envelope: &serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::to_vec(envelope)
            .map_err(|e| format!("webrequest: failed to serialize op envelope: {e}"))?;
        self.rt.block_on(async {
            // `.without_url()` on every reqwest error: a reqwest error's Display carries the request URL
            // WITH any embedded `user:pass@` userinfo. This error can reach operator logs, so the URL is
            // stripped before it is formatted. Parity with the old webhook hardening.
            let resp = self
                .client
                .post(self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .timeout(self.timeout)
                .send()
                .await
                .map_err(|e| format!("webrequest: request failed: {}", e.without_url()))?;
            let resp = resp.error_for_status().map_err(|e| {
                format!(
                    "webrequest: target returned an error status: {}",
                    e.without_url()
                )
            })?;
            let buf = read_capped(resp).await?;
            parse_reply(&buf)
        })
    }
}

/// Read a response body under the [`MAX_REPLY_BYTES`] cap, ABORTING (rather than allocating) once the
/// cap is exceeded. Chunk-read errors are userinfo-masked (`.without_url()`).
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("webrequest: response read failed: {}", e.without_url()))?
    {
        if buf.len() + chunk.len() > MAX_REPLY_BYTES {
            return Err(format!(
                "webrequest: response exceeded {MAX_REPLY_BYTES} byte cap"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Parse a reply body into a `Value`, rejecting a pathologically-nested body BEFORE building the
/// `Value` (see [`MAX_REPLY_DEPTH`]). The parse-error path is LENGTH-ONLY: a target that echoed granted
/// prompt content into a malformed reply must not splash it into an error the engine might log.
fn parse_reply(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if exceeds_max_depth(bytes, MAX_REPLY_DEPTH) {
        return Err(format!(
            "webrequest: reply exceeded max nesting depth ({} bytes)",
            bytes.len()
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| format!("webrequest: invalid JSON reply ({} bytes)", bytes.len()))
}

/// Single-pass, string-aware scan for the maximum `{`/`[` nesting depth in `bytes`. Brackets inside
/// JSON string literals (and `\`-escaped quotes) do not count. Short-circuits once `max` is exceeded.
/// Copied from busbar's `json::exceeds_max_depth` (the plugin must not dep on busbar core).
fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Build the POST envelope for a per-request op: the engine's opaque `payload` projection with an `op`
/// discriminator merged in, mirroring the old webhook wire (`{op, request, candidates, context, ...}`).
/// The projection is carried through UNCHANGED — the forwarder never inspects or mutates it, so any
/// opt-in `prompt`/`user` keys the CORE granted ride straight through to the target.
fn request_envelope(op: &str, payload: &serde_json::Value) -> serde_json::Value {
    let mut obj = match payload {
        serde_json::Value::Object(m) => m.clone(),
        // A non-object projection is unexpected, but relay it under a `payload` key rather than dropping.
        other => {
            let mut m = serde_json::Map::new();
            m.insert("payload".to_string(), other.clone());
            m
        }
    };
    obj.insert("op".to_string(), serde_json::Value::String(op.to_string()));
    serde_json::Value::Object(obj)
}

impl HookHandler for Forwarder {
    /// `decide` — POST the projection, return the reply verbatim. On any transport/parse error, return
    /// `{}` (abstain): the engine's normalizer maps that to `Abstain`, and the fail-closed
    /// on_error/on_empty chain takes over — the retired webhook's "no opinion on error" guarantee.
    fn decide(&self, payload: &serde_json::Value) -> serde_json::Value {
        match self.post_op(&request_envelope("decide", payload)) {
            Ok(reply) => reply,
            Err(_) => serde_json::json!({}),
        }
    }

    /// `transform` — POST the projection, return the reply verbatim. On error return `{}` (abstain →
    /// proceed with the ORIGINAL body); a parsed `reject` in the reply is honored by the engine.
    fn transform(&self, payload: &serde_json::Value) -> serde_json::Value {
        match self.post_op(&request_envelope("transform", payload)) {
            Ok(reply) => reply,
            Err(_) => serde_json::json!({}),
        }
    }

    /// `notify` — fire-and-forget POST of the tap projection. The reply is not read and every error is
    /// swallowed: a tap can NEVER delay or fail the served request.
    fn notify(&self, payload: &serde_json::Value) {
        let _ = self.post_op(&request_envelope("notify", payload));
    }

    /// `configure` — RE-VALIDATE the (possibly changed) `settings.url` against the SSRF guard, then ACK
    /// the pushed version. Re-validation is the security point: an operator PATCHing the URL to an
    /// internal target after load must be refused (a NACK → the engine rejects the push). The forwarder
    /// keeps using its already-validated live URL; committing the new URL is a reload concern.
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        match settings.get("url").and_then(|v| v.as_str()) {
            // A pushed URL must still pass the guard. Missing url → nothing to re-check (ACK).
            Some(url) => net_guard::validate_target_url(url).is_ok(),
            None => true,
        }
    }

    /// `describe` — the forwarder's OWN self-description envelope. It does not proxy `describe` to the
    /// target (the schema is the forwarder's config schema: `url` + `timeout_ms`).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The https:// (or loopback http://) URL each hook op envelope is POSTed to."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Per-op wall-clock timeout in milliseconds (default 5000, clamped to [1, 60000])."
                    }
                }
            }
        })
    }

    /// `status` — the forwarder's OWN observed state (it reports the target host it forwards to and its
    /// timeout; it does not proxy `status` to the target, which may not implement it). No prompt/user
    /// content is ever surfaced here.
    fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "status": {
                "settings": {
                    // Host only (no path/query/userinfo) — enough for an operator to see WHERE it forwards.
                    "target_host": self.url.host_str().unwrap_or(""),
                    "timeout_ms": self.timeout.as_millis() as u64
                },
                "metrics": []
            }
        })
    }
}

/// Construct the forwarder from the engine-passed JSON config (the `settings:` map). An empty/missing
/// URL, a malformed config, or an SSRF-blocked URL is a fail-closed LOAD error — never a live forwarder
/// that could be pointed at an internal target.
fn open(cfg: &str) -> Result<Box<dyn HookHandler>, String> {
    let config: Config = if cfg.trim().is_empty() {
        Config::default()
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("webrequest: invalid plugin config: {e}"))?
    };
    Ok(Box::new(Forwarder::new(config)?))
}

busbar_plugin_sdk::export_hook_plugin!(open);

#[cfg(test)]
mod tests {
    use super::*;

    /// `open` fails closed on a missing/empty URL, a malformed config, and an SSRF-blocked URL; and
    /// succeeds for a valid https target and a loopback http sidecar.
    #[test]
    fn open_fails_closed_on_bad_config() {
        assert!(open("").is_err(), "empty config (no url) must fail closed");
        assert!(open("{}").is_err(), "config without url must fail closed");
        assert!(
            open("{ not json").is_err(),
            "malformed config must fail closed"
        );
        assert!(
            open(r#"{"url":"http://169.254.169.254/x"}"#).is_err(),
            "an SSRF-blocked url must fail the load"
        );
        assert!(
            open(r#"{"url":"http://10.0.0.1/x"}"#).is_err(),
            "an RFC1918 url must fail the load"
        );
        assert!(
            open(r#"{"url":"http://api.example.com/x"}"#).is_err(),
            "plaintext http to a remote target must fail the load"
        );
        assert!(
            open(r#"{"url":"https://api.example.com/route"}"#).is_ok(),
            "a valid https target must load"
        );
        assert!(
            open(r#"{"url":"http://127.0.0.1:9000/route"}"#).is_ok(),
            "a loopback http sidecar must load"
        );
    }

    /// The reply parser caps depth and reports a LENGTH-ONLY error (never echoing the reply bytes).
    #[test]
    fn parse_reply_depth_and_length_only_errors() {
        // A ~150-deep body is rejected before a Value is built (well under the size cap).
        let mut deep = String::from(r#"{"order":"#);
        deep.push_str(&"[".repeat(150));
        deep.push_str(&"]".repeat(150));
        deep.push('}');
        assert!(deep.len() < MAX_REPLY_BYTES);
        assert!(parse_reply(deep.as_bytes()).is_err());

        // A malformed reply that echoes prompt content must not splash it into the error.
        let malformed = br#"{"order":[0,, "echo":"SENTINEL-PROMPT-TEXT"}"#;
        let err = parse_reply(malformed).unwrap_err();
        assert!(
            !err.contains("SENTINEL-PROMPT-TEXT"),
            "parse error echoed reply bytes: {err}"
        );
        assert!(
            err.contains("invalid JSON"),
            "expected length-only message: {err}"
        );

        // A well-formed reply parses.
        assert_eq!(
            parse_reply(br#"{"order":[1,0]}"#).unwrap(),
            serde_json::json!({"order": [1, 0]})
        );
    }

    /// The request envelope merges the `op` discriminator into the projection object, preserving every
    /// projected key (so any opt-in prompt/user the core granted rides straight through).
    #[test]
    fn request_envelope_merges_op_and_preserves_projection() {
        let payload = serde_json::json!({
            "request": {"pool": "p", "messages": [{"role": "user", "text": "hi"}]},
            "candidates": [{"idx": 0}]
        });
        let env = request_envelope("decide", &payload);
        assert_eq!(env["op"], "decide");
        assert_eq!(env["request"]["pool"], "p");
        assert_eq!(env["request"]["messages"][0]["text"], "hi");
        assert_eq!(env["candidates"][0]["idx"], 0);
    }

    /// `describe` returns the forwarder's own schema; `status` reports the target host and timeout with
    /// no prompt/user content, and acks its own metrics shape.
    #[test]
    fn describe_and_status_report_own_state() {
        let fwd = Forwarder::new(Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: Some(1234),
        })
        .expect("valid config");
        assert_eq!(fwd.describe()["schema"]["type"], "object");
        let status = fwd.status();
        assert_eq!(
            status["status"]["settings"]["target_host"],
            "api.example.com"
        );
        assert_eq!(status["status"]["settings"]["timeout_ms"], 1234);
    }

    /// `configure` RE-VALIDATES a pushed URL against the SSRF guard: a good URL ACKs (true), an
    /// SSRF-blocked URL NACKs (false → the engine rejects the push), a missing url ACKs (nothing to check).
    #[test]
    fn configure_revalidates_pushed_url() {
        let fwd = Forwarder::new(Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        })
        .expect("valid config");

        let mut ok = serde_json::Map::new();
        ok.insert(
            "url".into(),
            serde_json::json!("https://other.example.com/route"),
        );
        assert!(fwd.configure(&ok, 2), "a valid pushed url must ACK");

        let mut bad = serde_json::Map::new();
        bad.insert("url".into(), serde_json::json!("http://169.254.169.254/x"));
        assert!(
            !fwd.configure(&bad, 3),
            "an SSRF-blocked pushed url must NACK"
        );

        assert!(
            fwd.configure(&serde_json::Map::new(), 4),
            "a missing url ACKs"
        );
    }
}
