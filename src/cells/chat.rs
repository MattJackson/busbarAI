// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The chat cell — chat is operation #1, not the engine's foundation. Reached like every other
//! operation via `RequestHandler::operation_handler(Operation::Chat)`, with its path from
//! `RequestHandler::upstream_path`. This carries chat's capability overrides (the code that used to
//! live on the deleted `OpSpec`/`ChatOp`), verbatim, so the forward engine is byte-identical to
//! before the unification.
//!
//! ONE `ChatHandler` serves every protocol: chat's capabilities are protocol-agnostic — they read the
//! OpenAI-family `stream` boolean, the Anthropic-shaped `system` key, and otherwise delegate to the
//! protocol's `reader()`/`writer()` (passed in as arguments), never to the cell's own identity.
//!
//! Chat's wire↔IR translation is the streaming engine (`forward.rs` via `proto::ProtocolReader`/
//! `ProtocolWriter`), which is stream-safe; the ops bridge (`forward_operation`) is non-stream and is
//! not on chat's path. So the codec methods below are intentionally inert — chat never round-trips
//! through the non-stream bridge.
#![allow(dead_code)]

use crate::handler::{CodecError, IngressReject, OperationHandler, WireBody};
use crate::ir::variant::{IrReq, IrResp};
use crate::ir::IrUsage;
use crate::proto::ProtocolWriter;
use bytes::Bytes;
use serde_json::Value;

/// The chat operation cell — a protocol-agnostic singleton (see module docs).
pub(crate) struct ChatHandler;

/// The shared handle every protocol's `RequestHandler` returns for `Operation::Chat`, and the cell
/// behind `crate::ops::CHAT`.
pub(crate) static CHAT_HANDLER: ChatHandler = ChatHandler;

impl OperationHandler for ChatHandler {
    // ---- capabilities (relocated verbatim from the deleted ops/chat.rs `ChatOp`) ----

    fn streaming(&self) -> bool {
        true
    }
    fn taps_usage(&self) -> bool {
        true
    }
    fn wants_stream(&self, body: &Value) -> bool {
        // The caller's stream intent from the OpenAI-family body.
        body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false)
    }
    fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        // Top-level `system` string as the body-derived affinity key (no header present). Empty
        // strings do not pin affinity.
        body.get("system").and_then(|s| s.as_str()).filter(|s| !s.is_empty())
    }
    fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<IrUsage> {
        // Run the egress reader (== ingress on the same-protocol usage tap) over the reassembled body
        // and report its IR usage. An unknown protocol has no reader and yields `None`.
        crate::proto::protocol_for(ingress_protocol)
            .zip(crate::json::parse::<Value>(body).ok())
            .and_then(|(p, v)| p.reader().read_response(&v).ok())
            .map(|ir| ir.usage)
    }
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }

    // ---- codec: inert (chat translates through the streaming engine, not the non-stream bridge) ----

    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest(
            "chat translates through the streaming engine (proto reader/writer), not the bridge".into(),
        ))
    }
    fn write_request(&self, _ir: &IrReq) -> Bytes {
        Bytes::new()
    }
    fn read_response(&self, _wire: &[u8]) -> Result<IrResp, CodecError> {
        Err(CodecError::Malformed("chat uses the streaming engine, not the non-stream bridge".into()))
    }
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}
