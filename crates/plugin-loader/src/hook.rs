// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOOK seam of the kind-neutral loader: [`DlopenPolicy`], a [`busbar_api::RoutingPolicy`] backed
//! by a dynamically-loaded plugin whose kind was bound to `hook` at load. It translates each async
//! trait method (`decide`/`transform`/`notify`/`configure`/`describe`/`status`) into a `busbar_call`
//! with the matching op envelope ([`busbar_plugin_abi::hook`]).
//!
//! ## Blocking call off the async runtime
//!
//! A hook GATE can be CPU-heavy (a compressor, a classifier), so the synchronous `busbar_call` runs on
//! [`tokio::task::spawn_blocking`], never on a runtime worker. The FFI call is additionally wrapped in
//! [`std::panic::catch_unwind`] on the ENGINE side (defense in depth — the SDK already catches inside
//! the plugin): a panic that somehow crosses becomes a PROTOCOL-style error the caller coerces to the
//! hook's `on_error`, never a torn-down runtime.
//!
//! ## The contract is the engine's, not the plugin's
//!
//! `DlopenPolicy` carries the REPLY back to the engine as an opaque [`serde_json::Value`]; the
//! fail-closed reply semantics (reject-precedence, status-clamp, restrict/rewrite parsing, metric
//! bounding) live in the engine's `hooks::wire`, which parses that value. This is what keeps the
//! retired socket/webhook seam and this dlopen seam provably identical.

use crate::{stage, wire_up_raw, RawPlugin};
use busbar_api::{
    Candidate, HookStatus, PolicyError, PolicyResult, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_plugin_abi::{
    hook::{ConfigureBody, HookReply, HookRequest},
    kind as abi_kind,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

/// A projection builder the engine installs so the loader can turn the borrowed request/candidate/
/// context projections into the owned JSON `payload` the ABI carries — WITHOUT the loader depending on
/// the engine's `hooks::wire`. The engine passes closures at resolution; the loader calls them per op.
/// Kept as boxed fns so `DlopenPolicy` stays `Send + Sync + 'static`.
pub struct HookProjectors {
    /// Build the `decide` projection JSON from (request, candidates, context).
    #[allow(clippy::type_complexity)]
    pub decide: Box<
        dyn for<'a> Fn(
                &RoutingRequest<'a>,
                &[Candidate<'a>],
                &RoutingContext<'a>,
            ) -> serde_json::Value
            + Send
            + Sync,
    >,
    /// Build the `transform` projection JSON from a request (no candidates).
    #[allow(clippy::type_complexity)]
    pub transform: Box<dyn for<'a> Fn(&RoutingRequest<'a>) -> serde_json::Value + Send + Sync>,
    /// Parse a `decide` reply Value into a decision (the engine's fail-closed normalizer).
    #[allow(clippy::type_complexity)]
    pub normalize:
        Box<dyn for<'a> Fn(serde_json::Value, &[Candidate<'a>]) -> RoutingDecision + Send + Sync>,
    /// Parse a `transform` reply Value into an outcome (reject > rewrite > abstain).
    pub transform_outcome: Box<dyn Fn(serde_json::Value) -> TransformOutcome + Send + Sync>,
    /// Parse a `status` reply Value into the engine's `HookStatus` (metrics validated/bounded).
    pub status: Box<dyn Fn(serde_json::Value) -> Option<HookStatus> + Send + Sync>,
    /// Extract the `schema` member of a `describe` reply envelope.
    pub describe_schema: Box<dyn Fn(serde_json::Value) -> Option<serde_json::Value> + Send + Sync>,
}

/// A `RoutingPolicy` loaded from a dynamic library over the kind-neutral ABI. Wraps a [`RawPlugin`]
/// whose kind was bound to `hook` at load; every trait method serializes an op envelope, ships it
/// across `busbar_call` on `spawn_blocking`, and hands the reply to the engine's parsers.
pub struct DlopenPolicy {
    raw: Arc<RawPlugin>,
    projectors: Arc<HookProjectors>,
    /// The hook's stable name (metrics / `x-busbar-route`). Leaked to `'static` (the C ABI can't
    /// return a `&'static str`) — a bounded one-per-plugin leak of a non-secret id.
    name: &'static str,
}

impl DlopenPolicy {
    /// The ONE blocking primitive: run `op` across `busbar_call` on a blocking thread, catching any
    /// panic that crosses the FFI boundary. Returns the [`HookReply`] or a `PolicyError` (coerced to
    /// the hook's `on_error` by the caller). Not bounded here — the caller wraps in a `timeout`.
    async fn call(&self, op: HookRequest) -> Result<HookReply, PolicyError> {
        let raw = self.raw.clone();
        let joined = tokio::task::spawn_blocking(move || {
            catch_unwind(AssertUnwindSafe(|| {
                raw.transport_call::<HookRequest, HookReply>(&op)
            }))
        })
        .await;
        match joined {
            Ok(Ok(Ok(reply))) => Ok(reply),
            Ok(Ok(Err(e))) => Err(e.into()),
            // A panic caught at the FFI boundary is a protocol violation — fail-closed to on_error.
            Ok(Err(_)) => Err("hook plugin panicked across the ABI boundary".into()),
            // The blocking task was cancelled/aborted (runtime shutdown) — treat as a hook failure.
            Err(e) => Err(format!("hook plugin call task failed: {e}").into()),
        }
    }

    /// Bounded variant: `call` under a hard wall-clock `budget`, mapping a timeout to a `PolicyError`.
    async fn call_bounded(
        &self,
        op: HookRequest,
        budget: Duration,
    ) -> Result<HookReply, PolicyError> {
        match tokio::time::timeout(budget, self.call(op)).await {
            Ok(r) => r,
            Err(_) => Err(format!("hook plugin deadline ({budget:?}) exceeded").into()),
        }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for DlopenPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        let payload = (self.projectors.decide)(req, candidates, ctx);
        let reply = self
            .call_bounded(HookRequest::Decide { payload }, budget)
            .await?;
        match reply {
            HookReply::Reply(v) => Ok((self.projectors.normalize)(v, candidates)),
            // A wrong reply variant is a protocol violation → on_error (never a silent route).
            other => Err(format!("hook plugin returned {other:?} for decide").into()),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn transform(&self, req: &RoutingRequest<'_>, budget: Duration) -> TransformOutcome {
        let payload = (self.projectors.transform)(req);
        // FAIL-CLOSED on transport/protocol error → Abstain (proceed with the ORIGINAL body); a
        // parsed reply's reject IS honored by `transform_outcome`.
        match self
            .call_bounded(HookRequest::Transform { payload }, budget)
            .await
        {
            Ok(HookReply::Reply(v)) => (self.projectors.transform_outcome)(v),
            _ => TransformOutcome::Abstain,
        }
    }

    async fn configure(
        &self,
        hook_name: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        settings_version: u64,
        budget: Duration,
    ) -> Result<(), PolicyError> {
        let op = HookRequest::Configure(ConfigureBody {
            hook: hook_name.to_string(),
            settings: settings.clone(),
            settings_version,
            busbar_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        match self.call_bounded(op, budget).await? {
            HookReply::ConfigureAck {
                settings_version: acked,
            } if acked == settings_version => Ok(()),
            HookReply::ConfigureAck {
                settings_version: acked,
            } => Err(format!(
                "hook acked the wrong settings_version ({acked} != {settings_version})"
            )
            .into()),
            other => Err(format!("hook returned {other:?} for configure (expected an ack)").into()),
        }
    }

    async fn describe(&self, budget: Duration) -> Option<serde_json::Value> {
        match self.call_bounded(HookRequest::Describe, budget).await {
            Ok(HookReply::Reply(v)) => (self.projectors.describe_schema)(v),
            _ => None,
        }
    }

    async fn status(&self, budget: Duration) -> Option<HookStatus> {
        match self.call_bounded(HookRequest::Status, budget).await {
            Ok(HookReply::Reply(v)) => (self.projectors.status)(v),
            _ => None,
        }
    }

    async fn notify(&self, projection: &[u8], budget: Duration) {
        // The tap projection arrives pre-serialized (the engine's `hooks::wire::build` bytes). Wrap it
        // in a `Notify` op envelope. A malformed projection or any transport error is swallowed — a
        // tap can NEVER delay or fail the served request.
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(projection) else {
            return;
        };
        let _ = self
            .call_bounded(HookRequest::Notify { payload }, budget)
            .await;
    }
}

impl std::fmt::Debug for DlopenPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlopenPolicy")
            .field("name", &self.name)
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load a HOOK policy from EXACTLY the verified library `bytes` (TOCTOU-safe). Enforces the frozen
/// contract (transport version, kind == `hook` == the signed manifest — mismatch is a hard fail-closed
/// load error naming both), then `open`s it with `cfg_json` and wraps it as a [`DlopenPolicy`]. The
/// `projectors` are the engine-supplied closures that build the wire projection and parse the reply
/// through the engine's own fail-closed `hooks::wire` normalizers. `name` is the hook's registry name.
pub fn load_hook_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
    name: &str,
    projectors: Arc<HookProjectors>,
) -> Result<Arc<dyn RoutingPolicy>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::HOOK,
        manifest_kind,
        Some(staged),
    )?;
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    Ok(Arc::new(DlopenPolicy {
        raw: Arc::new(raw),
        projectors,
        name,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::TransformOutcome;

    /// Locate the test hook plugin cdylib in the build's target dir (mirrors the sqlite loader test).
    /// Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure, never
    /// a silent skip — the only over-the-ABI coverage of the DlopenPolicy seam must not vanish.
    fn hook_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = crate::plugin_library_filename("busbar_hook_test_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the hook test plugin cdylib is not built under CI: `cargo test --workspace` must \
                 build busbar_hook_test_plugin. Refusing to silently skip the only over-the-ABI \
                 coverage of the DlopenPolicy hook seam."
            );
        }
        candidate
    }

    /// Minimal engine-side projectors for the test: build a projection carrying `request.messages`,
    /// and parse the reply with tiny fail-closed shims (the real engine wires `hooks::wire` here).
    fn test_projectors() -> Arc<HookProjectors> {
        Arc::new(HookProjectors {
            decide: Box::new(|req, cands, _ctx| {
                serde_json::json!({
                    "request": {
                        "pool": req.pool,
                        "messages": req.prompt.as_ref().map(|p| {
                            p.messages.iter().map(|(r, t)| {
                                serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                            }).collect::<Vec<_>>()
                        }),
                    },
                    "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
                })
            }),
            transform: Box::new(|req| {
                serde_json::json!({
                    "request": {
                        "messages": req.prompt.as_ref().map(|p| {
                            p.messages.iter().map(|(r, t)| {
                                serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                            }).collect::<Vec<_>>()
                        }),
                    }
                })
            }),
            normalize: Box::new(|v, cands| {
                if let Some(reject) = v.get("reject") {
                    let status = reject
                        .get("status")
                        .and_then(|s| s.as_u64())
                        .map(|s| s as u16)
                        .unwrap_or(403);
                    let message = reject
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    return RoutingDecision::Reject { status, message };
                }
                let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                    return RoutingDecision::Abstain;
                };
                let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
                RoutingDecision::from_ranked(
                    order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                    &valid,
                )
            }),
            transform_outcome: Box::new(|v| {
                if let Some(reject) = v.get("reject") {
                    let status = reject
                        .get("status")
                        .and_then(|s| s.as_u64())
                        .map(|s| s as u16)
                        .unwrap_or(403);
                    return TransformOutcome::Reject {
                        status,
                        message: reject
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("")
                            .to_string(),
                    };
                }
                match v
                    .get("rewrite")
                    .and_then(|r| r.get("messages"))
                    .and_then(|m| m.as_array())
                {
                    Some(msgs) if !msgs.is_empty() => {
                        TransformOutcome::Rewrite(busbar_api::RewriteReply {
                            messages: msgs.clone(),
                            tools: Vec::new(),
                        })
                    }
                    _ => TransformOutcome::Abstain,
                }
            }),
            status: Box::new(|v| {
                v.get("status").map(|s| busbar_api::HookStatus {
                    settings_version: None,
                    settings: None,
                    metrics: s.get("metrics").and_then(|m| m.as_array()).cloned(),
                })
            }),
            describe_schema: Box::new(|v| v.get("schema").cloned()),
        })
    }

    fn load(cfg: &str) -> Arc<dyn RoutingPolicy> {
        let path = hook_plugin_path().expect("hook cdylib built under --workspace");
        let bytes = std::fs::read(&path).expect("read hook cdylib");
        load_hook_from_bytes(
            &bytes,
            cfg,
            "test-hook",
            "hook",
            "test-hook",
            test_projectors(),
        )
        .expect("load hook plugin over the ABI")
    }

    fn req_with_prompt(text: &str) -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 1,
            tool_count: 0,
            has_tools: false,
            total_chars: text.len(),
            system_chars: 0,
            max_tokens: None,
            stream: false,
            prompt: Some(busbar_api::PromptProjection {
                system: None,
                messages: vec![("user".into(), text.to_string().into())],
            }),
            identity: None,
        }
    }

    fn cand(idx: usize) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "prov",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: None,
            tags: &[],
            latency_ms: None,
            available_concurrency: 1,
            budget_remaining: None,
            rate_headroom: None,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: None,
            budget: &[],
        }
    }

    /// END-TO-END over the REAL hook cdylib: load it, then drive every op. `decide` echoes the
    /// configured order; the opt-in prompt projection reaches the in-process gate and drives a
    /// reject; `transform` rewrites (and rejects on the token); `configure` acks the exact version;
    /// `describe` returns the schema; `status` reports the observed decide count. This is the exact
    /// seam the engine sees: an `Arc<dyn RoutingPolicy>` indistinguishable from a compiled-in policy.
    #[tokio::test]
    async fn dlopen_policy_drives_every_op() {
        let Some(_) = hook_plugin_path() else {
            eprintln!("skip: hook test plugin cdylib not built (run under --workspace)");
            return;
        };
        let budget = Duration::from_secs(5);

        // decide: the configured order [1, 0] is echoed and normalized.
        let policy = load(r#"{"order": [1, 0], "reject_if_contains": "BLOCKME"}"#);
        let cands = [cand(0), cand(1)];
        let d = policy
            .decide(&req_with_prompt("hello"), &cands, &ctx(), budget)
            .await
            .expect("decide ok");
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));

        // decide: the opt-in prompt projection reaches the gate → reject (proves content arrives).
        let d = policy
            .decide(
                &req_with_prompt("please BLOCKME now"),
                &cands,
                &ctx(),
                budget,
            )
            .await
            .expect("decide ok");
        assert_eq!(
            d,
            RoutingDecision::Reject {
                status: 403,
                message: "blocked by test gate".to_string()
            }
        );

        // transform: rewrites the body; and rejects on the screen token.
        match policy.transform(&req_with_prompt("hello"), budget).await {
            TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
            other => panic!("expected Rewrite, got {other:?}"),
        }
        match policy.transform(&req_with_prompt("BLOCKME"), budget).await {
            TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
            other => panic!("expected Reject, got {other:?}"),
        }

        // notify: fire-and-forget, never panics, never blocks.
        let projection =
            serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
        policy.notify(&projection, budget).await;

        // configure: the gate acks the exact version → Ok.
        policy
            .configure("test-hook", &serde_json::Map::new(), 7, budget)
            .await
            .expect("configure acks the pushed version");

        // describe: the schema envelope comes back.
        let schema = policy.describe(budget).await.expect("describe");
        assert_eq!(schema["type"], "object");

        // status: the observed decide count (we ran decide twice above).
        let status = policy.status(budget).await.expect("status");
        let metrics = status.metrics.expect("metrics");
        assert_eq!(metrics[0]["name"], "test_decides_total");
        assert!(metrics[0]["value"].as_f64().unwrap() >= 2.0);
    }

    /// An abstain config (no order) → the gate abstains, and an unresolvable order idx is dropped by
    /// the engine's normalizer (fail-closed liberal parse over the ABI).
    #[tokio::test]
    async fn dlopen_policy_abstains_and_drops_unknown_idx() {
        let Some(_) = hook_plugin_path() else {
            return;
        };
        let policy = load(r#"{"order": [9, 0]}"#);
        let cands = [cand(0)];
        let d = policy
            .decide(
                &req_with_prompt("x"),
                &cands,
                &ctx(),
                Duration::from_secs(5),
            )
            .await
            .expect("decide ok");
        // idx 9 is unknown (dropped), idx 0 survives.
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));

        let policy = load("{}");
        let d = policy
            .decide(
                &req_with_prompt("x"),
                &cands,
                &ctx(),
                Duration::from_secs(5),
            )
            .await
            .expect("decide ok");
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// A kind cross-check MISMATCH is a hard fail-closed load error naming both sides (loading the
    /// hook cdylib as the wrong `manifest_kind`).
    #[test]
    fn load_refuses_kind_mismatch() {
        let Some(path) = hook_plugin_path() else {
            return;
        };
        let bytes = std::fs::read(&path).expect("read hook cdylib");
        let err = match load_hook_from_bytes(
            &bytes,
            "{}",
            "test-hook",
            "store",
            "h",
            test_projectors(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("a hook cdylib loaded with manifest kind 'store' must be refused"),
        };
        assert!(err.contains("hook") && err.contains("store"), "got: {err}");
    }
}
