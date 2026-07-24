// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: hook` plugin** — a `cdylib` exporting the hook C ABI, used only as TEST
//! support for the end-to-end `DlopenPolicy` seam tests (the engine loading a real signed `kind: hook`
//! tarball over the loader and driving decide/transform/notify/configure/describe/status through it).
//! It does NO network and NO real policy work: it exercises the WIRE — it ranks by echoing a
//! configured order, screens for a configured reject token, rewrites/restricts on demand, and reports
//! a fixed metric. The point under test is the ENGINE seam (project → busbar_call → parse), not a real
//! router. Production hook logic (e.g. the first-party webrequest forwarder) lives elsewhere.
//!
//! Config JSON (the hook's `settings:` map, passed verbatim by the engine at load):
//! ```json
//! { "order": [1, 0], "reject_if_contains": "BLOCKME" }
//! ```
//! Both optional: absent `order` → abstain; absent `reject_if_contains` → never rejects on content.

use busbar_plugin_sdk::HookHandler;
use serde::Deserialize;

/// The plugin's opaque config: how this trivial gate behaves.
#[derive(Deserialize, Default)]
struct HookConfig {
    /// The candidate order this gate always prefers on `decide` (echoed as `{"order": [...]}`).
    /// Absent/empty → the gate abstains.
    #[serde(default)]
    order: Vec<usize>,
    /// If any projected message text CONTAINS this token, `decide`/`transform` reject. This proves the
    /// opt-in `prompt` projection actually reaches an in-process hook and drives a verdict.
    #[serde(default)]
    reject_if_contains: Option<String>,
    /// The `status` the content-reject emits (default 403). Lets a test drive the engine normalizer's
    /// reject-status CLAMP over the ABI (e.g. a hook that says 200/500/70000 → the engine forces 403).
    #[serde(default)]
    reject_status: Option<i64>,
    /// If set, `decide` always RESTRICTS to these tags (`{"restrict": {"tags_any": [...]}}`) — proves
    /// the compliance-gate verb rides the ABI and normalizes to a `Restrict` decision.
    #[serde(default)]
    restrict_tags: Option<Vec<String>>,
    /// A raw reply shape to return VERBATIM from `decide`, overriding everything else — the escape
    /// hatch that lets a test drive a wrong-variant / malformed / arbitrary reply through the engine's
    /// fail-closed normalizer (e.g. `{}` → abstain, a bogus object → abstain, a bad reject detail →
    /// fail-closed 403).
    #[serde(default)]
    raw_decide_reply: Option<serde_json::Value>,
    /// Sleep this many milliseconds inside `decide` before replying — lets a test drive the engine's
    /// hard wall-clock `budget` timeout (a slow gate → the caller's `on_error`).
    #[serde(default)]
    sleep_ms: Option<u64>,
    /// `describe`/`status` reply empty (`{}`) — the "unsupported" reply the engine treats as fail-open
    /// (no schema / no status). Proves the fail-open reads over the dlopen seam.
    #[serde(default)]
    empty_management: bool,
    /// Refuse to ack a `configure` push (the handler returns `false`, so the SDK echoes a mismatched
    /// version) — lets a test prove a NACK'd configure does not commit (Err over the seam).
    #[serde(default)]
    nack_configure: bool,
}

struct TestGate {
    order: Vec<usize>,
    reject_if_contains: Option<String>,
    reject_status: i64,
    restrict_tags: Option<Vec<String>>,
    raw_decide_reply: Option<serde_json::Value>,
    sleep_ms: Option<u64>,
    empty_management: bool,
    nack_configure: bool,
    /// A monotonically incrementing decide count, surfaced via `status` — proves the control-plane
    /// scrape reads a real observed metric back over the ABI. `AtomicU64` keeps `&self` (the handler
    /// is shared behind the ABI handle).
    decides: std::sync::atomic::AtomicU64,
}

impl TestGate {
    /// Does any projected message text contain the configured reject token? Reads the opt-in
    /// `request.messages[].text` projection the engine only sends behind a `prompt` grant.
    fn should_reject(&self, payload: &serde_json::Value) -> bool {
        let Some(token) = self.reject_if_contains.as_deref() else {
            return false;
        };
        payload
            .get("request")
            .and_then(|r| r.get("messages"))
            .and_then(|m| m.as_array())
            .is_some_and(|msgs| {
                msgs.iter().any(|m| {
                    m.get("text")
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| t.contains(token))
                })
            })
    }
}

impl HookHandler for TestGate {
    fn decide(&self, payload: &serde_json::Value) -> serde_json::Value {
        self.decides
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // A slow gate: sleep so the engine's wall-clock budget cuts the exchange off (→ on_error).
        if let Some(ms) = self.sleep_ms {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        // The raw-reply escape hatch wins over everything (drives fail-closed normalizer coverage).
        if let Some(raw) = &self.raw_decide_reply {
            return raw.clone();
        }
        if self.should_reject(payload) {
            return serde_json::json!({
                "reject": {"status": self.reject_status, "message": "blocked by test gate"}
            });
        }
        if let Some(tags) = &self.restrict_tags {
            return serde_json::json!({ "restrict": {"tags_any": tags} });
        }
        if self.order.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "order": self.order })
        }
    }

    fn transform(&self, payload: &serde_json::Value) -> serde_json::Value {
        // A rw gate that also screens: reject on the token, else rewrite the body to a fixed marker
        // (proves the rewrite arm rides the ABI and is applied only under the rw grant).
        if self.should_reject(payload) {
            return serde_json::json!({"reject": {"status": 451, "message": "screened"}});
        }
        serde_json::json!({"rewrite": {"messages": [{"role": "user", "content": "rewritten by test gate"}]}})
    }

    fn describe(&self) -> serde_json::Value {
        if self.empty_management {
            return serde_json::json!({});
        }
        serde_json::json!({
            "schema": {"type": "object", "properties": {"order": {"type": "array"}}}
        })
    }

    fn status(&self) -> serde_json::Value {
        if self.empty_management {
            return serde_json::json!({});
        }
        let n = self.decides.load(std::sync::atomic::Ordering::Relaxed);
        serde_json::json!({
            "status": {
                "metrics": [
                    {"name": "test_decides_total", "type": "counter", "value": n as f64}
                ]
            }
        })
    }

    fn configure(
        &self,
        _settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        // Ack by default; a configured NACK proves a rejected push does not commit over the seam.
        !self.nack_configure
    }
}

/// Construct the gate from the engine-passed JSON config. An empty config is fine (a pure-abstain
/// gate that never rejects); malformed JSON is a fail-closed load error.
fn open(cfg: &str) -> Result<Box<dyn HookHandler>, String> {
    let c: HookConfig = if cfg.trim().is_empty() {
        HookConfig::default()
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid test-hook plugin config: {e}"))?
    };
    Ok(Box::new(TestGate {
        order: c.order,
        reject_if_contains: c.reject_if_contains,
        reject_status: c.reject_status.unwrap_or(403),
        restrict_tags: c.restrict_tags,
        raw_decide_reply: c.raw_decide_reply,
        sleep_ms: c.sleep_ms,
        empty_management: c.empty_management,
        nack_configure: c.nack_configure,
        decides: std::sync::atomic::AtomicU64::new(0),
    }))
}

busbar_plugin_sdk::export_hook_plugin!(open);
