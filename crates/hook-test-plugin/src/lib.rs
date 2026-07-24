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
    /// If any projected message text CONTAINS this token, `decide`/`transform` reject (403). This
    /// proves the opt-in `prompt` projection actually reaches an in-process hook and drives a verdict.
    #[serde(default)]
    reject_if_contains: Option<String>,
}

struct TestGate {
    order: Vec<usize>,
    reject_if_contains: Option<String>,
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
        if self.should_reject(payload) {
            return serde_json::json!({"reject": {"status": 403, "message": "blocked by test gate"}});
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
        serde_json::json!({
            "schema": {"type": "object", "properties": {"order": {"type": "array"}}}
        })
    }

    fn status(&self) -> serde_json::Value {
        let n = self.decides.load(std::sync::atomic::Ordering::Relaxed);
        serde_json::json!({
            "status": {
                "metrics": [
                    {"name": "test_decides_total", "type": "counter", "value": n as f64}
                ]
            }
        })
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
        decides: std::sync::atomic::AtomicU64::new(0),
    }))
}

busbar_plugin_sdk::export_hook_plugin!(open);
