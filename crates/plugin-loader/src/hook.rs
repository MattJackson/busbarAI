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
