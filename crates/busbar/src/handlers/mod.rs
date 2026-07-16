// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol handlers — the design's middle, in one module (design-operations-oop.md §6/§7):
//!
//! `Router → RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`] — ONE per protocol (`openai.rs`, `anthropic.rs`, …). Dumb and
//!   protocol-specific: reads path+body to decide WHICH operation a request asks for
//!   (`resolve_operation`), owns the `(protocol, operation) → path template` (`upstream_path`), and
//!   holds its row of the support matrix (`operation_handler`; `None` = the no-handler 404).
//! - [`OperationHandler`] — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
//!   directions, plus the operation-capability surface the engine reads. It never routes, fails
//!   over, checks auth, bills, or knows another protocol exists.
//! - [`OpDispatch`] — the thin `(operation, OperationHandler)` handle the streaming engine threads.
//!   It mostly delegates to the `RequestHandler` vtable; its one bit of logic is honoring a per-lane
//!   `path` override in `upstream_path` before falling back to the protocol default.
//!   [`request_handler`] is the registry the catch-all dispatch resolves through.
//!
//! Adding a protocol: a Router ID line, a `RequestHandler` impl here, its OperationHandlers. Adding an
//! operation: an OperationHandler + a line in each `RequestHandler` that speaks it. Nothing else moves.
#![allow(dead_code)]

pub(crate) mod anthropic;
pub(crate) mod bedrock;
pub(crate) mod chat;
pub(crate) mod cohere;
pub(crate) mod gemini;
pub(crate) mod openai;
pub(crate) mod responses;

static OPENAI: openai::OpenAiRequestHandler = openai::OpenAiRequestHandler;
static BEDROCK: bedrock::BedrockRequestHandler = bedrock::BedrockRequestHandler;
static COHERE: cohere::CohereRequestHandler = cohere::CohereRequestHandler;
static GEMINI: gemini::GeminiRequestHandler = gemini::GeminiRequestHandler;
static ANTHROPIC: anthropic::AnthropicRequestHandler = anthropic::AnthropicRequestHandler;
static RESPONSES: responses::ResponsesRequestHandler = responses::ResponsesRequestHandler;

/// The protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`). All six
/// protocols are registered (every one speaks chat); a registered handler may still return `None`
/// from `operation_handler` for an op it lacks — that IS the no-handler 404.
pub(crate) fn request_handler(protocol: &str) -> Option<&'static dyn RequestHandler> {
    match protocol {
        "openai" => Some(&OPENAI),
        "bedrock" => Some(&BEDROCK),
        "cohere" => Some(&COHERE),
        "gemini" => Some(&GEMINI),
        "anthropic" => Some(&ANTHROPIC),
        "responses" => Some(&RESPONSES),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;

use crate::ir::variant::{IrReq, IrResp};
use crate::ir::IrUsage;
use crate::operation::Operation;
use crate::proto::ProtocolWriter;
use bytes::Bytes;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub(crate) struct WireBody {
    pub(crate) bytes: Bytes,
    pub(crate) content_type: axum::http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub(crate) fn json(bytes: Bytes) -> Self {
        Self {
            bytes,
            content_type: axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub(crate) fn typed(bytes: Bytes, content_type: &str) -> Self {
        let content_type = axum::http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `proxy::ingress_error`). `UnsupportedSubOp` is the m3 second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from handler-absence (§3), same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this OperationHandler could not decode into its operation's IR.
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
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols
    /// (Gemini) it replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a
    /// provider can be pointed at a different layout — e.g. Vertex AI's
    /// `/v1/projects/{p}/locations/{l}/publishers/google/models`. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub(crate) path_base: Option<&'a str>,
}

/// A pure per-(protocol × operation) codec. Feed it wire, assert the IR; feed it IR, assert the wire.
/// That is the entire contract — the load-bearing discipline that makes the matrix scale. It knows
/// NOTHING about routing: no `Lane`, no path, no model. The path is the `RequestHandler`'s concern.
pub(crate) trait OperationHandler: Send + Sync {
    // OperationHandler capabilities: the operation-behavior surface the forward engine reads (never branching on
    // operation identity). Every default is the MOST RESTRICTIVE behavior — no streaming, no stream
    // intent, no affinity, no usage tap. Chat overrides them; the JSON ops keep the defaults. This is
    // exactly the old `OpSpec` surface, now living on the OperationHandler so there is ONE operation mechanism.

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
    /// end, only when [`Self::taps_usage`] is true). Default: run THIS operation's own reader over the
    /// body and project its token usage — so a token-metered non-chat op (embeddings) bills the same
    /// as the cross-protocol path. Chat overrides this to run the egress protocol's chat reader.
    fn extract_usage(&self, _ingress_protocol: &str, body: &[u8]) -> Option<IrUsage> {
        match self.read_response(body) {
            Ok(r) => r.token_usage(),
            Err(e) => {
                // A same-protocol 2xx body the op's own codec cannot decode: log it (like the
                // cross-protocol seam) rather than silently bill 0 tokens with no operator signal.
                tracing::warn!(
                    error = ?e,
                    "usage tap: read_response failed to decode a same-protocol 2xx body; \
                     billing 0 tokens for this request"
                );
                None
            }
        }
    }
    /// The Content-Type of THIS operation's egress request wire (what `write_request` emits).
    /// JSON for every JSON-bodied operation; a multipart operation overrides with its boundary.
    fn egress_request_content_type(&self) -> &'static str {
        crate::proxy::APPLICATION_JSON
    }

    /// The egress `Accept` header for the upstream request. Default: the writer's stream-aware choice
    /// (JSON / SSE / eventstream). A binary-response op (audio speech) overrides to `*/*`.
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }

    /// Value-level codec bridges — for engine seams that already hold a PARSED JSON body (the
    /// streaming chat engine parses once for shim/intent reads). Defaults round-trip through the
    /// byte codecs (correct for every JSON operation); chat overrides them to call its proto
    /// reader/writer directly (no re-serialize on the hot path). Non-JSON operations never meet
    /// these seams.
    fn read_request_value(&self, v: &Value) -> Result<IrReq, IngressReject> {
        let bytes = serde_json::to_vec(v).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        self.read_request(&bytes, crate::proxy::APPLICATION_JSON)
    }
    fn write_request_value(&self, ir: &IrReq) -> Option<Value> {
        serde_json::from_slice(&self.write_request(ir)).ok()
    }
    fn read_response_value(&self, v: &Value) -> Result<IrResp, CodecError> {
        let bytes = serde_json::to_vec(v).map_err(|e| CodecError::Malformed(e.to_string()))?;
        self.read_response(&bytes)
    }
    fn write_response_value(&self, ir: &IrResp) -> Option<Value> {
        serde_json::from_slice(&self.write_response(ir).bytes).ok()
    }

    /// Wire → IR (request). The OperationHandler owns the ENTIRE wire format: it receives RAW bytes + the request
    /// content-type and decides how to parse — JSON (`serde_json::from_slice`) for JSON ops, multipart
    /// for transcription, etc. The engine never parses; "JSON vs opaque" is the OperationHandler's private business.
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

/// A protocol's dialect + its OperationHandlers (one impl per protocol).
pub(crate) trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches `proto::Protocol::name()`).
    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation
    /// ⇒ the no-handler 404 (§3). The OperationHandler, when present, is a pure codec.
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler>;

    /// WHICH operation this request asks for — the RequestHandler knows its protocol and reads the
    /// path (and, where the protocol multiplexes one endpoint, the body: Gemini `generateContent`
    /// serves chat AND audio; Bedrock `InvokeModel` serves embeddings AND images) and says "this is
    /// audio, this is chat". The Router only picks the protocol; THIS decides the operation.
    /// `None` ⇒ the path is not an operation this protocol serves.
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation>;

    /// The model named in the PATH, for path-model dialects (gemini `models/{m}:action`, bedrock
    /// `/model/{m}/...`). `None` (the default) for body-model dialects — the dispatch then reads the
    /// JSON body `model` / multipart form instead.
    fn path_model(&self, _path: &str) -> Option<String> {
        None
    }

    /// The `(protocol, operation) → path template` map: this protocol's upstream URL for the operation
    /// in `ctx`, built from RESOLVED PRIMITIVES ([`EgressCtx`]) — never the `Lane`. One `match op` per
    /// protocol. Routing applies any `lane.path` override BEFORE calling this (so this is the default).
    /// This is the sole path mechanism; chat uses it too.
    fn upstream_path(&self, ctx: &EgressCtx) -> String;
}

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;

use crate::state::Lane;

/// A `(operation, OperationHandler)` dispatch handle, threaded through the forward engine by value (`Copy`). The
/// engine reads operation behavior off it without ever naming an operation.
#[derive(Clone, Copy)]
pub(crate) struct OpDispatch {
    pub(crate) operation: Operation,
    pub(crate) op_handler: &'static dyn OperationHandler,
}

/// The engine's operation handle. (Kept as `Op` so the engine's signatures read unchanged.)
pub(crate) type Op = OpDispatch;

impl OpDispatch {
    /// Stable identifier — a bounded metric label / tracing span field. VALUE use only; the engine
    /// must never compare or `match` on it (that would be an operation-identity branch).
    pub(crate) fn name(&self) -> &'static str {
        self.operation.name()
    }
    pub(crate) fn streaming(&self) -> bool {
        self.op_handler.streaming()
    }
    pub(crate) fn wants_stream(&self, body: &Value) -> bool {
        self.op_handler.wants_stream(body)
    }
    pub(crate) fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        self.op_handler.body_affinity_key(body)
    }
    pub(crate) fn taps_nonstream_usage(&self) -> bool {
        self.op_handler.taps_usage()
    }
    pub(crate) fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<IrUsage> {
        self.op_handler.extract_usage(ingress_protocol, body)
    }
    pub(crate) fn egress_accept(
        &self,
        writer: &dyn ProtocolWriter,
        wants_stream: bool,
    ) -> &'static str {
        self.op_handler.egress_accept(writer, wants_stream)
    }
    /// The (protocol × operation) upstream path: lane override, else the lane's protocol
    /// `RequestHandler` renders it from resolved primitives (never the `Lane`). `None` only if the
    /// protocol has no registered handler — impossible for chat (all six are registered).
    pub(crate) fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> Option<String> {
        if let Some(p) = &lane.path {
            return Some(p.clone());
        }
        crate::handlers::request_handler(lane.protocol.name()).map(|rh| {
            rh.upstream_path(&EgressCtx {
                operation: self.operation,
                model: lane.wire_model(),
                stream: wants_stream,
                path_base: lane.path_base.as_deref(),
            })
        })
    }
}

/// Chat — operation #1. A const handle to the shared chat OperationHandler, for tests and as the resolver's
/// fallback. Prefer [`chat`] on the request path so the RequestHandler actually decides the OperationHandler.
pub(crate) const CHAT: Op = OpDispatch {
    operation: Operation::Chat,
    op_handler: &crate::handlers::chat::ChatOperation("openai"),
};

/// Resolve the chat dispatch THROUGH the registry — the same path every other operation takes:
/// `request_handler(protocol).operation_handler(Chat)`. This is how "the RequestHandler decides which
/// OperationHandler handles the request" is honored for chat too, not just the JSON ops. Every protocol
/// is registered and serves chat, so the fallback is unreachable (kept for total-safety, not behavior).
pub(crate) fn chat(protocol: &str) -> Op {
    crate::handlers::request_handler(protocol)
        .and_then(|rh| rh.operation_handler(Operation::Chat))
        .map(|op_handler| OpDispatch {
            operation: Operation::Chat,
            op_handler,
        })
        .unwrap_or(CHAT)
}

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;
