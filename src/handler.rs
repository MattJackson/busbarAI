// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The `RequestHandler` and `OperationHandler` trait contracts (design-operations-oop.md §6).
//!
//! NOT to be confused with `handlers.rs` (the axum route functions). Per the design these live under
//! `handlers/request/`; consolidating the physical layout is deferred (a minor, cosmetic move) — the
//! contracts and their behavior are what matter for correctness.
//!
//! - [`OperationHandler`] — ONE per (protocol × operation) cell. A pure codec: wire ↔ IR, both
//!   directions. It never routes, fails over, checks auth, bills, or knows another protocol exists.
//!   Stateless and unit-testable in isolation. The cell exists iff its protocol serves its operation
//!   (§3): an absent cell IS the no-cell 404.
//! - [`RequestHandler`] — ONE per protocol. Owns the dialect and holds its operation cells (its row of
//!   the support matrix). `operation_handler(op) == None` is the no-cell 404 site.
//!
//! Foundation contracts; `dead_code` allowed until the Router/seam wiring consumes them (P3/P4).
#![allow(dead_code)]

use crate::ir::variant::{IrReq, IrResp};
use crate::ir::IrUsage;
use crate::operation::Operation;
use crate::proto::ProtocolWriter;
use bytes::Bytes;
use serde_json::Value;

/// A serialized wire body plus the content-type the cell chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub(crate) struct WireBody {
    pub(crate) bytes: Bytes,
    pub(crate) content_type: axum::http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub(crate) fn json(bytes: Bytes) -> Self {
        Self { bytes, content_type: axum::http::HeaderValue::from_static("application/json") }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub(crate) fn typed(bytes: Bytes, content_type: &str) -> Self {
        let content_type = axum::http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream"));
        Self { bytes, content_type }
    }
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `forward::ingress_error`). `UnsupportedSubOp` is the m3 second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from cell-absence (§3), same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this cell could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodecError {
    Malformed(String),
}

/// What routing hands a `RequestHandler` so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub(crate) struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub(crate) operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for URL-model protocols
    /// (Gemini `models/{model}:…`, Bedrock `model/{model}/invoke`).
    pub(crate) model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub(crate) stream: bool,
}

/// A pure per-(protocol × operation) codec. Feed it wire, assert the IR; feed it IR, assert the wire.
/// That is the entire contract — the load-bearing discipline that makes the matrix scale. It knows
/// NOTHING about routing: no `Lane`, no path, no model. The path is the `RequestHandler`'s concern.
pub(crate) trait OperationHandler: Send + Sync {
    // CELL capabilities: the operation-behavior surface the forward engine reads (never branching on
    // operation identity). Every default is the MOST RESTRICTIVE behavior — no streaming, no stream
    // intent, no affinity, no usage tap. Chat overrides them; the JSON ops keep the defaults. This is
    // exactly the old `OpSpec` surface, now living on the cell so there is ONE operation mechanism.

    /// Can this operation produce a client-facing incremental stream?
    fn streaming(&self) -> bool {
        false
    }
    /// Should the non-stream 2xx body be buffered so [`Self::extract_usage`] can read it?
    fn taps_usage(&self) -> bool {
        false
    }
    /// The caller's stream intent, from the parsed ingress body. Chat reads the OpenAI-family
    /// `"stream"` boolean; a non-streaming op never asks upstream to stream.
    fn wants_stream(&self, _body: &Value) -> bool {
        false
    }
    /// A body-derived session-affinity key (used only when no affinity header is present). Chat uses
    /// the top-level Anthropic-shaped `system` string.
    fn body_affinity_key<'a>(&self, _body: &'a Value) -> Option<&'a str> {
        None
    }
    /// Extract billable usage from a complete same-protocol non-stream 2xx body (called once at stream
    /// end). `None` = flat/no token meter. Chat runs the egress protocol's reader over the body.
    fn extract_usage(&self, _ingress_protocol: &str, _body: &[u8]) -> Option<IrUsage> {
        None
    }
    /// The egress `Accept` header for the upstream request. Default: the writer's stream-aware choice
    /// (JSON / SSE / eventstream). A binary-response op (audio speech) overrides to `*/*`.
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }

    /// Wire → IR (request). The cell owns the ENTIRE wire format: it receives RAW bytes + the request
    /// content-type and decides how to parse — JSON (`serde_json::from_slice`) for JSON ops, multipart
    /// for transcription, etc. The engine never parses; "JSON vs opaque" is the cell's private business.
    fn read_request(&self, body: &[u8], content_type: &str) -> Result<IrReq, IngressReject>;
    /// IR → egress wire (request bytes sent upstream).
    fn write_request(&self, ir: &IrReq) -> Bytes;
    /// Egress wire → IR (response) — called only when `taps_usage()` or a cross-protocol translation
    /// requires the neutral form. Raw bytes: binary responses (audio) were always fine here.
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError>;
    /// IR → caller-dialect wire ([`WireBody`]: bytes + content-type returned to the client). The
    /// content-type lets a binary op (speech → `audio/*`) declare its own; the engine relays it verbatim.
    fn write_response(&self, ir: &IrResp) -> WireBody;
}

/// A protocol's dialect + its operation cells (one impl per protocol).
pub(crate) trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches `proto::Protocol::name()`).
    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation
    /// ⇒ the no-cell 404 (§3). The cell, when present, is a pure codec.
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler>;

    /// The `(protocol, operation) → path template` map: this protocol's upstream URL for the operation
    /// in `ctx`, built from RESOLVED PRIMITIVES ([`EgressCtx`]) — never the `Lane`. One `match op` per
    /// protocol. Routing applies any `lane.path` override BEFORE calling this (so this is the default).
    /// This is the sole path mechanism; chat uses it too.
    fn upstream_path(&self, ctx: &EgressCtx) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trivial cell + handler prove the trait objects are object-safe and the no-cell lookup works.
    struct NoopModeration;
    impl OperationHandler for NoopModeration {
        fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
            Err(IngressReject::BadRequest("noop".into()))
        }
        fn write_request(&self, _ir: &IrReq) -> Bytes {
            Bytes::new()
        }
        fn read_response(&self, _w: &[u8]) -> Result<IrResp, CodecError> {
            Err(CodecError::Malformed("noop".into()))
        }
        fn write_response(&self, _ir: &IrResp) -> WireBody {
            WireBody::json(Bytes::new())
        }
    }

    struct OpenAiLike;
    impl RequestHandler for OpenAiLike {
        fn protocol_name(&self) -> &'static str {
            "openai"
        }
        fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
            // openai serves moderation; not, say, chat-on-a-moderation-only stub → None = no-cell 404.
            match op {
                Operation::Moderation => Some(&NoopModeration),
                _ => None,
            }
        }
        fn upstream_path(&self, ctx: &EgressCtx) -> String {
            match ctx.operation {
                Operation::Moderation => "/v1/moderations".into(),
                _ => String::new(),
            }
        }
    }

    #[test]
    fn no_cell_lookup_returns_none_for_unsupported_op() {
        let h = OpenAiLike;
        assert!(h.operation_handler(Operation::Moderation).is_some());
        assert!(
            h.operation_handler(Operation::Chat).is_none(),
            "an absent cell IS the no-cell 404"
        );
        assert_eq!(h.protocol_name(), "openai");
    }

    #[test]
    fn sub_op_reject_carries_op_and_model() {
        let r = IngressReject::UnsupportedSubOp { op: Operation::Image, model: "gpt-image-1".into() };
        assert!(matches!(r, IngressReject::UnsupportedSubOp { op: Operation::Image, .. }));
    }
}
