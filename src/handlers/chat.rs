// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Chat as a STANDARD operation — no operation is "more" than another.
//!
//! [`ChatOperation`] is one TYPE with six per-protocol INSTANCES: each protocol's handler file holds
//! its own `static CHAT: ChatOperation = ChatOperation("<proto>")` and returns it from
//! `operation_handler(Operation::Chat)`. The deletion test is literal: remove a protocol's instance
//! (its registry line) and that protocol's chat 404s through the SAME no-handler path as any missing
//! operation, while its other operations — and every other protocol — keep working.
//!
//! The codecs are REAL (wire ↔ `IrReq::Chat`/`IrResp::Chat`), delegating to the protocol's
//! `proto::ProtocolReader`/`ProtocolWriter` — the same relationship an embeddings codec has to
//! `serde_json`: the vtable is chat's parser, the OperationHandler owns the operation. Chat's
//! STREAMING translation additionally rides the stream-event machinery those same vtables provide
//! (`read_response_events`/`write_response_event`), reached through the engine only after the
//! dispatch has resolved THIS handler.
#![allow(dead_code)]

use crate::handlers::{CodecError, IngressReject, OperationHandler, WireBody};
use crate::ir::variant::{IrReq, IrResp};
use crate::ir::IrUsage;
use crate::proto::ProtocolWriter;
use bytes::Bytes;
use serde_json::Value;

/// A protocol's chat operation. The field names the protocol whose `proto::` reader/writer are this
/// instance's codec (resolved per call — `protocol_for` is a static match, no allocation).
pub(crate) struct ChatOperation(pub(crate) &'static str);

impl ChatOperation {
    fn proto(&self) -> Option<crate::proto::Protocol> {
        crate::proto::protocol_for(self.0)
    }
}

impl OperationHandler for ChatOperation {
    // ---- capabilities (verbatim from the former shared handler / OpSpec) ----

    fn streaming(&self) -> bool {
        true
    }
    fn taps_usage(&self) -> bool {
        true
    }
    fn wants_stream(&self, body: &Value) -> bool {
        // The caller's stream intent from the body (`stream` boolean — openai-family/anthropic/
        // cohere). Path-signaled dialects (gemini `:streamGenerateContent`, bedrock
        // `/converse-stream`) are resolved by their routing arms before this is consulted.
        body.get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false)
    }
    fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        // Top-level `system` string as the body-derived affinity key (no header present). Empty
        // strings do not pin affinity.
        body.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }
    fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<IrUsage> {
        // Same-protocol usage tap: run the egress (== ingress) reader over the reassembled body.
        crate::proto::protocol_for(ingress_protocol)
            .zip(crate::json::parse::<Value>(body).ok())
            .and_then(|(p, v)| p.reader().read_response(&v).ok())
            .map(|ir| ir.usage)
    }
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }

    // ---- Value-level bridges: direct vtable calls (the engine seams hold parsed JSON) ----

    fn read_request_value(&self, v: &Value) -> Result<IrReq, IngressReject> {
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(v)
            .map(IrReq::Chat)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn write_request_value(&self, ir: &IrReq) -> Option<Value> {
        let IrReq::Chat(r) = ir else { return None };
        Some(self.proto()?.writer().write_request(r))
    }
    fn read_response_value(&self, v: &Value) -> Result<IrResp, CodecError> {
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(v)
            .map(IrResp::Chat)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
    fn write_response_value(&self, ir: &IrResp) -> Option<Value> {
        let IrResp::Chat(r) = ir else { return None };
        Some(self.proto()?.writer().write_response(r))
    }

    // ---- codecs: REAL — this protocol's chat wire ↔ the chat IR ----

    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(&v)
            .map(IrReq::Chat)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Chat(r) = ir else {
            return Bytes::new();
        };
        let Some(p) = self.proto() else {
            return Bytes::new();
        };
        Bytes::from(serde_json::to_vec(&p.writer().write_request(r)).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(&v)
            .map(IrResp::Chat)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Chat(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let Some(p) = self.proto() else {
            return WireBody::json(Bytes::new());
        };
        WireBody::json(Bytes::from(
            serde_json::to_vec(&p.writer().write_response(r)).unwrap_or_default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codecs are REAL: an openai chat request round-trips wire → IrReq::Chat → wire through the
    /// openai instance, like any other operation's codec.
    #[test]
    fn chat_codec_round_trips_openai_request() {
        let chat = ChatOperation("openai");
        let wire = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let ir = chat.read_request(wire, "application/json").expect("parses");
        assert!(matches!(ir, IrReq::Chat(_)));
        let back = chat.write_request(&ir);
        let v: Value = serde_json::from_slice(&back).unwrap();
        // The writer may emit the bare-string or block-array content form — both are valid OpenAI.
        let content = &v["messages"][0]["content"];
        let text = content
            .as_str()
            .map(str::to_string)
            .or_else(|| content[0]["text"].as_str().map(str::to_string));
        assert_eq!(text.as_deref(), Some("hi"), "content survived: {v}");
    }

    /// Response side too: egress wire → IrResp::Chat → caller-dialect wire.
    #[test]
    fn chat_codec_round_trips_openai_response() {
        let chat = ChatOperation("openai");
        let wire = br#"{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"MOCKTEXT"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}"#;
        let ir = chat.read_response(wire).expect("parses");
        let out = chat.write_response(&ir);
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], "MOCKTEXT");
        assert_eq!(v["usage"]["prompt_tokens"], 11);
    }

    /// Cross-protocol through the IR: openai request in, anthropic wire out — the same bridge shape
    /// every other operation uses.
    #[test]
    fn chat_codec_bridges_openai_to_anthropic() {
        let openai = ChatOperation("openai");
        let anthropic = ChatOperation("anthropic");
        let ir = openai
            .read_request(
                br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
                "application/json",
            )
            .unwrap();
        let wire = anthropic.write_request(&ir);
        let v: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(v["messages"][0]["content"][0]["text"], "hi");
    }
}
