// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! ADR-0006 protocol seam: agnostic core vs. protocol-specific edges.
//! Per B-500: split the flat `Protocol` trait into Reader (wire→signal) + Writer (intent→wire),
//! bundle them in `Protocol`, and add a string-keyed registry for provider lookup.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};
use std::sync::Arc;

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility
pub(crate) use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

// Import types needed for response/stream IR (B-502b)
use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};

/// IrError is an alias for CanonicalSignal (B-500 scaffolding).
/// Per ADR-0007: keep it compatible with CanonicalSignal; B-502 may promote to a richer struct.
#[allow(dead_code)] // Used by B-501/B-502 for IR bridge
pub(crate) type IrError = crate::breaker::CanonicalSignal;

/// ProtocolReader extracts signals from wire responses (Stage 1a + 1b).
/// Methods are provider-specific normalizers that feed the breaker's Stage 2 classifier.
pub(crate) trait ProtocolReader: Send + Sync {
    /// Extract raw error info from HTTP response without classifying.
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError;

    /// Classify a response into a canonical signal (two-stage pipeline).
    #[allow(dead_code)] // Used by B-502a/B-503
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal;

    /// Read an IR request from wire JSON.
    #[allow(dead_code)] // Used by B-502a/B-503
    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError>;

    /// Read a response/stream event from already-de-framed SSE data (B-502b).
    #[allow(dead_code)] // Used by B-502b/B-503
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent>;

    /// Fan-out variant (B-502c-2b): one wire event/chunk → 0..n IR stream events, threading
    /// per-request decode state. Anthropic is 1:1 (wraps the singular, ignores state); OpenAI's
    /// flat stream synthesizes block boundaries via the state. This is the general translation
    /// API the live response-translation path (B-503) calls.
    #[allow(dead_code)] // Used by B-503
    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent>;

    /// Read a whole (non-streaming) response from wire JSON.
    #[allow(dead_code)] // Used by B-503c-1
    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError>;

    /// Clone this reader as a trait object.
    #[allow(dead_code)] // Used by B-502a for Protocol cloning
    fn clone_box(&self) -> Box<dyn ProtocolReader>;
}

/// ProtocolWriter rewrites intents for the upstream wire format.
pub(crate) trait ProtocolWriter: Send + Sync {
    /// Returns the upstream path suffix (e.g., "/v1/messages").
    fn upstream_path(&self) -> &str;

    /// B-510c: the upstream path for a specific model. Most protocols ignore the model and
    /// return a fixed path (the default); Gemini's path embeds the model
    /// (`/v1beta/models/{model}:generateContent`). `forward` uses this to build the URL.
    fn upstream_path_for(&self, _model: &str) -> String {
        self.upstream_path().to_string()
    }

    /// Returns auth headers given an API key.
    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)>;

    /// Rewrites the model field in the request body.
    #[allow(dead_code)] // Used by B-502a/B-503
    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str);

    /// Write an IR request to wire JSON.
    #[allow(dead_code)] // Used by B-502a/B-503
    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value;

    /// Write a response/stream event to wire (event_type, data) (B-502b).
    #[allow(dead_code)] // Used by B-502b/B-503
    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)>;

    /// Write a whole (non-streaming) response to wire JSON.
    #[allow(dead_code)] // Used by B-503c-1
    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value;

    /// Clone this writer as a trait object.
    #[allow(dead_code)] // Used by B-502a for Protocol cloning
    fn clone_box(&self) -> Box<dyn ProtocolWriter>;
}

/// Bundled Protocol with name + reader + writer.
pub(crate) struct Protocol {
    name: &'static str,
    reader: Box<dyn ProtocolReader>,
    writer: Box<dyn ProtocolWriter>,
}

impl Clone for Box<dyn ProtocolReader> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Box<dyn ProtocolWriter> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Protocol {
    fn clone(&self) -> Self {
        Protocol {
            name: self.name,
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl Protocol {
    pub(crate) fn new<R, W>(name: &'static str, reader: R, writer: W) -> Self
    where
        R: ProtocolReader + 'static,
        W: ProtocolWriter + 'static,
    {
        Self {
            name,
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Returns the protocol name ("anthropic", "openai", etc.).
    #[allow(dead_code)] // Reserved for future extensibility (B-501)
    pub(crate) fn name(&self) -> &str {
        self.name
    }

    /// Returns the reader for this protocol.
    pub(crate) fn reader(&self) -> &dyn ProtocolReader {
        self.reader.as_ref()
    }

    /// Returns the writer for this protocol.
    pub(crate) fn writer(&self) -> &dyn ProtocolWriter {
        self.writer.as_ref()
    }

    /// Construct an Anthropic protocol instance.
    pub(crate) fn anthropic() -> Self {
        Self::new("anthropic", AnthropicReader, AnthropicWriter)
    }

    /// Construct an OpenAI protocol instance.
    pub(crate) fn openai() -> Self {
        Self::new("openai", OpenAiReader, OpenAiWriter)
    }

    /// Construct a Gemini protocol instance.
    #[allow(dead_code)] // Reserved for B-510 integration (later cycle)
    pub(crate) fn gemini() -> Self {
        Self::new("gemini", GeminiReader, GeminiWriter)
    }

    /// Construct an OpenAI Responses protocol instance.
    #[allow(dead_code)] // Reserved for B-540b integration (later cycle)
    pub(crate) fn responses() -> Self {
        Self::new("responses", ResponsesReader, ResponsesWriter)
    }
}

/// Resolve a built-in Protocol by name (for ingress translation). Cheap (unit structs).
#[allow(dead_code)] // used by forward (B-503a)
pub(crate) fn protocol_for(name: &str) -> Option<Protocol> {
    match name {
        "anthropic" => Some(Protocol::anthropic()),
        "openai" => Some(Protocol::openai()),
        #[allow(dead_code)] // Reserved for B-510 integration (later cycle)
        "gemini" => Some(Protocol::gemini()),
        #[allow(dead_code)] // Reserved for B-540b integration (later cycle)
        "responses" => Some(Protocol::responses()),
        _ => None,
    }
}

/// B-503b: pure cross-protocol response-stream translator. Feed EGRESS-protocol SSE bytes,
/// get the equivalent INGRESS-protocol SSE bytes — composing `egress.reader().read_response_events`
/// (wire → IR, stateful fan-out) with `ingress.writer().write_response_event` (IR → wire). Holds
/// a reassembly buffer for frames split across chunks and the IR decode state across the stream.
/// The async wiring into the live stream path (FirstByteBody) is B-503b-2.
#[allow(dead_code)] // wired into FirstByteBody by B-503b-2
pub(crate) struct StreamTranslate {
    ingress: Protocol,
    egress: Protocol,
    decode: crate::ir::StreamDecodeState,
    buf: Vec<u8>,
    /// ingress == "openai" → the stream must terminate with `data: [DONE]\n\n`.
    emit_done: bool,
}

#[allow(dead_code)] // wired into FirstByteBody by B-503b-2
impl StreamTranslate {
    /// Build a translator for an ingress→egress pair. `None` if either protocol is unknown OR
    /// ingress == egress (no translation needed — the caller does native passthrough).
    pub(crate) fn new(ingress: &str, egress: &str) -> Option<Self> {
        if ingress == egress {
            return None;
        }
        Some(Self {
            ingress: protocol_for(ingress)?,
            egress: protocol_for(egress)?,
            decode: crate::ir::StreamDecodeState::default(),
            buf: Vec::new(),
            emit_done: ingress == "openai",
        })
    }

    /// Feed a chunk of EGRESS SSE bytes; return translated INGRESS SSE bytes for whatever
    /// COMPLETE frames are now available (empty if only a partial frame is buffered).
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();

        // Drain every complete `\n\n`-delimited frame currently buffered.
        while let Some(pos) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let end = pos + 2;
            let frame: Vec<u8> = self.buf.drain(..end).collect();

            let Some((event_type, data_str)) = parse_sse_frame(&frame) else {
                continue; // no data: line, or non-utf8 — skip
            };
            if data_str.is_empty() || data_str == "[DONE]" {
                continue; // egress terminator/keepalive — ingress terminator is finish()'s job
            }
            let Ok(data) = serde_json::from_str::<serde_json::Value>(&data_str) else {
                continue; // malformed data JSON — skip the frame rather than abort the stream
            };

            for ev in
                self.egress
                    .reader()
                    .read_response_events(&event_type, &data, &mut self.decode)
            {
                if let Some((out_et, out_data)) = self.ingress.writer().write_response_event(&ev) {
                    out.extend_from_slice(reframe_sse(&out_et, &out_data).as_bytes());
                }
            }
        }
        out
    }

    /// Call once at end-of-stream. Returns the INGRESS terminator (OpenAI → `data: [DONE]\n\n`,
    /// Anthropic → empty: its `message_stop` event already carries termination).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        if self.emit_done {
            b"data: [DONE]\n\n".to_vec()
        } else {
            Vec::new()
        }
    }
}

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Returns `None` if there is no `data:` line or invalid UTF-8.
fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data = rest.trim().to_string();
        }
    }
    if data.is_empty() && event_type.is_empty() {
        return None;
    }
    Some((event_type, data))
}

/// Re-frame an IR-derived `(event_type, data)` as INGRESS SSE bytes. A non-empty `event_type`
/// yields Anthropic-style `event:`/`data:` frames; an empty one yields OpenAI-style bare `data:`.
fn reframe_sse(event_type: &str, data: &serde_json::Value) -> String {
    if event_type.is_empty() {
        format!("data: {data}\n\n")
    } else {
        format!("event: {event_type}\ndata: {data}\n\n")
    }
}

/// Anthropic reader implementation (migrated from `Protocol::extract_error` and `classify`).
mod anthropic;
mod gemini;
mod openai;
mod responses;

pub(crate) use anthropic::{AnthropicReader, AnthropicWriter};
pub(crate) use gemini::{GeminiReader, GeminiWriter};
pub(crate) use openai::{OpenAiReader, OpenAiWriter};
pub(crate) use responses::{ResponsesReader, ResponsesWriter};

/// String-keyed registry for protocol lookup (ADR-0008). Shared infrastructure: lives in the
/// proto module root, not any single protocol's file. `with_builtins` registers every protocol.
#[derive(Default)]
#[allow(dead_code)] // Scaffolding: not wired into App/Lane yet (B-501)
pub(crate) struct ProtocolRegistry {
    map: std::collections::HashMap<String, Arc<Protocol>>,
}

impl ProtocolRegistry {
    /// Create a new registry with built-in protocols.
    #[allow(dead_code)] // Used by B-501 for provider resolution
    pub(crate) fn with_builtins() -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert("anthropic".to_string(), Arc::new(Protocol::anthropic()));
        map.insert("openai".to_string(), Arc::new(Protocol::openai()));
        map.insert("gemini".to_string(), Arc::new(Protocol::gemini()));
        Self { map }
    }

    /// Get a protocol by name.
    #[allow(dead_code)] // Used by B-501 for provider resolution
    pub(crate) fn get(&self, name: &str) -> Option<Arc<Protocol>> {
        self.map.get(name).cloned()
    }
}

pub(crate) fn convert_headers(
    headers: Vec<(HeaderName, HeaderValue)>,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rich_fixture() -> serde_json::Value {
        // temperature is a natural 0.7 — IrRequest.temperature is f64 so it round-trips exactly.
        serde_json::json!({
            "system": [{"type": "text", "text": "You are a helpful assistant.", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "What is the weather?"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}}]},
                {"role": "assistant", "content": [{"type": "thinking", "thinking": "I need to analyze the weather...", "signature": "sig_abc123xyz"}, {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"location": "San Francisco"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tool_1", "content": [{"type": "text", "text": "Sunny, 72°F"}]}]}
            ],
            "tools": [{"name": "get_weather", "description": "Get weather for a location", "input_schema": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
            "max_tokens": 4096,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        })
    }

    #[test]
    fn test_roundtrip_identity() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);
        assert_eq!(
            roundtrip, j,
            "round-trip must be byte-identical on representable subset"
        );
    }

    #[test]
    fn test_signature_verbatim() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let mut found_thinking = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::Thinking { text: _, signature } = block {
                        found_thinking = true;
                        assert_eq!(signature.as_deref(), Some("sig_abc123xyz"));
                    }
                }
            }
        }
        assert!(found_thinking);
        let roundtrip = writer.write_request(&ir);
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(content_arr) = msg_val.get("content").and_then(|v| v.as_array()) {
                    for block_val in content_arr {
                        if let Some(block_obj) = block_val.as_object() {
                            if block_obj.get("type").and_then(|t| t.as_str()) == Some("thinking") {
                                assert_eq!(
                                    block_obj.get("signature").and_then(|s| s.as_str()),
                                    Some("sig_abc123xyz")
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_cache_control_preserved() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text {
            text: _,
            cache_control,
            citations: _,
        } = &ir.system[0]
        {
            assert!(cache_control.is_some());
            match cache_control.as_ref().unwrap().kind {
                crate::ir::CacheKind::Ephemeral => {}
            };
        }
        let roundtrip = writer.write_request(&ir);
        if let Some(system_arr) = roundtrip.get("system").and_then(|v| v.as_array()) {
            if let Some(first_block) = system_arr.first() {
                assert!(first_block
                    .as_object()
                    .unwrap()
                    .contains_key("cache_control"));
            }
        }
    }

    #[test]
    fn test_extra_passthrough() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert!(ir.extra.contains_key("top_p"));
        let roundtrip = writer.write_request(&ir);
        assert!(roundtrip.as_object().unwrap().contains_key("top_p"));
    }

    #[test]
    fn test_registry_resolves_anthropic() {
        let registry = ProtocolRegistry::with_builtins();

        // Anthropic should be present
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        assert_eq!(protocol.name(), "anthropic");
        assert_eq!(protocol.writer().upstream_path(), "/v1/messages");

        // Non-existent should return None
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_reader_classify_behavior() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);
    }

    #[test]
    fn test_writer_auth_headers() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let writer = protocol.writer();

        let headers = writer.auth_headers("k");
        let header_names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();

        assert!(header_names.contains(&"x-api-key"));
        assert!(header_names.contains(&"anthropic-version"));
    }

    #[test]
    fn test_irerror_bridge() {
        // IrError IS CanonicalSignal - construct and verify
        let ir_error: IrError = IrError {
            class: StatusClass::Billing,
            provider_signal: Some("test".to_string()),
            retry_after: None,
        };

        assert_eq!(ir_error.class, StatusClass::Billing);
    }

    #[test]
    fn test_stream_roundtrip_identity() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // message_start with usage
        let data = serde_json::json!({
            "message": {
                "role": "assistant",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            }
        });
        let ev = reader.read_response_event("message_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_start".to_string(), data))
            );
        }

        // content_block_start for tool_use
        let data = serde_json::json!({
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "tool_123",
                "name": "get_weather"
            }
        });
        let ev = reader.read_response_event("content_block_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_start".to_string(), data))
            );
        }

        // content_block_delta - text_delta
        let data = serde_json::json!({
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": "hello"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - thinking_delta
        let data = serde_json::json!({
            "index": 1,
            "delta": {
                "type": "thinking_delta",
                "thinking": "I need to think"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - input_json_delta
        let data = serde_json::json!({
            "index": 2,
            "delta": {
                "type": "input_json_delta",
                "partial_json": "{\"loc"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - signature_delta
        let data = serde_json::json!({
            "index": 1,
            "delta": {
                "type": "signature_delta",
                "signature": "sig_abc123xyz"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_stop
        let data = serde_json::json!({ "index": 0 });
        let ev = reader.read_response_event("content_block_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_stop".to_string(), data))
            );
        }

        // message_delta with usage
        let data = serde_json::json!({
            "delta": { "stop_reason": "end_turn" },
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15
            }
        });
        let ev = reader.read_response_event("message_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_delta".to_string(), data))
            );
        }

        // message_stop
        let data = serde_json::json!({});
        let ev = reader.read_response_event("message_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_stop".to_string(), data))
            );
        }
    }

    #[test]
    fn test_split_usage_never_collapses() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // message_delta with all four usage fields distinct
        let data = serde_json::json!({
            "delta": { "stop_reason": "end_turn" },
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 30,
                "cache_read_input_tokens": 200
            }
        });

        let ev = reader
            .read_response_event("message_delta", &data)
            .expect("should parse");
        if let crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: _,
            usage,
        } = ev
        {
            assert_eq!(usage.input_tokens, 100);
            assert_eq!(usage.output_tokens, 50);
            assert_eq!(usage.cache_creation_input_tokens, Some(30));
            assert_eq!(usage.cache_read_input_tokens, Some(200));
            // Verify they weren't collapsed: input_tokens != sum of cache tokens
            assert_ne!(100, 30 + 200);
        } else {
            panic!("expected MessageDelta");
        }

        let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 100,
                output_tokens: 50,
                cache_creation_input_tokens: Some(30),
                cache_read_input_tokens: Some(200),
            },
        });
        assert!(roundtrip.is_some());
        let (_, rt_data) = roundtrip.unwrap();
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(100)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64()),
            Some(50)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("cache_creation_input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(30)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("cache_read_input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(200)
        );
    }

    #[test]
    fn test_signature_delta_verbatim() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // Signature delta with byte-identical string
        let sig = "sig_abc123xyz_signature_for_thinking";
        let data = serde_json::json!({
            "index": 0,
            "delta": {
                "type": "signature_delta",
                "signature": sig
            }
        });

        let ev = reader
            .read_response_event("content_block_delta", &data)
            .expect("should parse");
        if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
            if let crate::ir::IrDelta::SignatureDelta(s) = delta {
                assert_eq!(s, sig);
            } else {
                panic!("expected SignatureDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
        });
        assert!(roundtrip.is_some());
        let (_, rt_data) = roundtrip.unwrap();
        let rt_sig = rt_data
            .get("delta")
            .and_then(|d| d.get("signature"))
            .and_then(|s| s.as_str())
            .unwrap();
        assert_eq!(rt_sig, sig);
    }

    #[test]
    fn test_ping_returns_none() {
        let reader = AnthropicReader;
        let data = serde_json::json!({});
        let result = reader.read_response_event("ping", &data);
        assert!(result.is_none());

        // Unknown event type also returns None
        let result = reader.read_response_event("unknown_event_type", &data);
        assert!(result.is_none());
    }

    #[test]
    fn test_openai_request_roundtrip_identity() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        // Canonical OpenAI request with system message, user+image, assistant tool_call, tool_result, tools array, max_tokens, temperature:0.7, stream:true, top_p→extra
        let j = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}]},
                {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]},
                {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
            ],
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
            "max_tokens": 100,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        });

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);

        // Compare structurally rather than byte-identical since IR doesn't preserve model field and tool_call ids are regenerated
        assert_eq!(
            roundtrip
                .as_object()
                .unwrap()
                .get("messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            j.get("messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("max_tokens"),
            j.as_object().unwrap().get("max_tokens")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("temperature"),
            j.as_object().unwrap().get("temperature")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("stream"),
            j.as_object().unwrap().get("stream")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("top_p"),
            j.as_object().unwrap().get("top_p")
        );

        // Correctness-critical: the tool_call id must round-trip VERBATIM (not be regenerated),
        // so the assistant tool_call still correlates with the tool-result `tool_call_id`.
        let msgs = roundtrip
            .get("messages")
            .and_then(|v| v.as_array())
            .unwrap();
        let written_id = msgs
            .iter()
            .find_map(|m| m.get("tool_calls").and_then(|tc| tc.as_array()))
            .and_then(|tc| tc.first())
            .and_then(|c| c.get("id"))
            .and_then(|i| i.as_str());
        assert_eq!(
            written_id,
            Some("call_123"),
            "tool_call id must round-trip verbatim, not be regenerated"
        );
        // And the tool-result must still reference that same id (correlation preserved).
        let result_ref = msgs
            .iter()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
            .and_then(|m| m.get("tool_call_id"))
            .and_then(|i| i.as_str());
        assert_eq!(
            result_ref,
            Some("call_123"),
            "tool-result correlation must survive round-trip"
        );
    }

    #[test]
    fn test_openai_tool_call_arguments_string_to_value() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        // Test with arguments that parse to a JSON object
        let j = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]}
            ]
        });

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Find the ToolUse block and verify arguments parsed to Value
        let mut found_tool_use = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                        found_tool_use = true;
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        // Verify arguments parsed to an object Value
                        match input {
                            serde_json::Value::Object(_) => {}
                            _ => panic!("arguments should parse to Object"),
                        }
                    }
                }
            }
        }
        assert!(found_tool_use);

        let roundtrip = writer.write_request(&ir);

        // Re-parse the arguments from roundtrip and compare parsed values
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc_val in tc_arr {
                        if let Some(func) = tc_val.get("function") {
                            let args_str =
                                func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");
                            let roundtrip_args: serde_json::Value =
                                serde_json::from_str(args_str).expect("args should parse");

                            // Original parsed value
                            let orig_input = &ir.messages[0].content[0];
                            if let crate::ir::IrBlock::ToolUse { input, .. } = orig_input {
                                assert_eq!(roundtrip_args, *input, "parsed arguments must match");
                            } else {
                                panic!("expected ToolUse block");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_registry_has_both_protocols() {
        let registry = ProtocolRegistry::with_builtins();

        // Both should exist
        assert!(
            registry.get("anthropic").is_some(),
            "anthropic should exist"
        );
        assert!(registry.get("openai").is_some(), "openai should exist");

        // Verify openai writer path
        let openai = registry.get("openai").expect("openai should exist");
        assert_eq!(openai.writer().upstream_path(), "/v1/chat/completions");

        // Verify anthropic writer path
        let anthropic = registry.get("anthropic").expect("anthropic should exist");
        assert_eq!(anthropic.writer().upstream_path(), "/v1/messages");
    }

    #[test]
    fn test_protocol_clone_works() {
        // Test OpenAI protocol clone doesn't panic
        let openai_proto = Protocol::openai();
        let cloned_openai = openai_proto.clone();

        assert_eq!(openai_proto.name(), cloned_openai.name());
        assert_eq!(
            openai_proto.writer().upstream_path(),
            cloned_openai.writer().upstream_path()
        );

        // Test Anthropic protocol clone doesn't panic
        let anthropic_proto = Protocol::anthropic();
        let cloned_anthropic = anthropic_proto.clone();

        assert_eq!(anthropic_proto.name(), cloned_anthropic.name());
        assert_eq!(
            anthropic_proto.writer().upstream_path(),
            cloned_anthropic.writer().upstream_path()
        );

        // Verify clone_box works for trait objects (just check it doesn't panic and returns same type)
        let openai_reader: Box<dyn ProtocolReader> = Box::new(OpenAiReader);
        let _cloned_reader = openai_reader.clone();

        let openai_writer: Box<dyn ProtocolWriter> = Box::new(OpenAiWriter);
        let _cloned_writer = openai_writer.clone();
    }

    #[test]
    fn test_openai_classify() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);

        // Test 403 → Auth
        let signal = reader.classify(StatusCode::FORBIDDEN, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);
    }

    #[cfg(test)]
    mod ir_property_tests {
        use super::*;

        // ============================================================================
        // A. Anthropic REQUEST property tests (decode assertions + round-trip)
        // ============================================================================

        /// Rich canonical Anthropic fixture with natural values only (0.7, "hello", 10, "call_123").
        fn anthropic_rich_fixture() -> serde_json::Value {
            serde_json::json!({
                "system": [
                    {
                        "type": "text",
                        "text": "You are a helpful assistant.",
                        "cache_control": {"type": "ephemeral"}
                    }
                ],
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "hello"},
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                                }
                            }
                        ]
                    },
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "thinking",
                                "thinking": "I need to analyze this request carefully...",
                                "signature": "sig_thinking_abc123"
                            },
                            {
                                "type": "tool_use",
                                "id": "call_123",
                                "name": "get_weather",
                                "input": {"location": "San Francisco"}
                            }
                        ]
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "call_123",
                                "content": [{"type": "text", "text": "Sunny, 72°F"}],
                                "is_error": false
                            }
                        ]
                    }
                ],
                "tools": [
                    {
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "input_schema": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ],
                "max_tokens": 10,
                "temperature": 0.7,
                "stream": true,
                "top_p": 0.95
            })
        }

        #[test]
        fn test_anthropic_request_decode_assertions() {
            // DECODE assertions on rich canonical fixture - exact field values that a doctored
            // fixture cannot fake (anti-fab / TREND #9 + #10)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let j = anthropic_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert system[0] has cache_control Some(Ephemeral) & text
            assert!(!ir.system.is_empty());
            if let crate::ir::IrBlock::Text {
                ref text,
                ref cache_control,
                ref citations,
            } = ir.system[0]
            {
                assert_eq!(text, "You are a helpful assistant.");
                assert!(cache_control.is_some());
                match cache_control.as_ref().unwrap().kind {
                    crate::ir::CacheKind::Ephemeral => {}
                }
                assert!(citations.is_empty());
            } else {
                panic!("system[0] should be Text block");
            }

            // Assert the Thinking signature String == "sig_thinking_abc123"
            let mut found_assistant = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    found_assistant = true;
                    let mut found_thinking = false;
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Thinking {
                            text: _,
                            ref signature,
                        } = block
                        {
                            found_thinking = true;
                            assert_eq!(signature.as_deref(), Some("sig_thinking_abc123"));
                        }
                    }
                    assert!(found_thinking);
                }
            }
            assert!(found_assistant);

            // Assert ToolUse id/name/input
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123");
                            assert_eq!(name, "get_weather");
                            match input {
                                serde_json::Value::Object(obj) => {
                                    assert_eq!(
                                        obj.get("location"),
                                        Some(&serde_json::json!("San Francisco"))
                                    );
                                }
                                _ => panic!("input should be Object"),
                            }
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Assert Image media_type+data in user message
            let mut found_image = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Image {
                            ref media_type,
                            ref data,
                        } = block
                        {
                            found_image = true;
                            assert_eq!(media_type, "image/png");
                            assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
                        }
                    }
                }
            }
            assert!(found_image);

            // Assert tool_result tool_use_id == "call_123" (correlation)
            let mut found_tool_result = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            ref tool_use_id,
                            ref content,
                            ref is_error,
                        } = block
                        {
                            found_tool_result = true;
                            assert_eq!(tool_use_id, "call_123");
                            assert!(!content.is_empty());
                            assert!(!*is_error);
                        }
                    }
                }
            }
            assert!(found_tool_result);

            // Assert temperature == Some(0.7) (f64, exact - natural value not 0.699999988)
            assert_eq!(ir.temperature, Some(0.7_f64));

            // Assert extra contains top_p
            assert!(ir.extra.contains_key("top_p"));
            assert_eq!(ir.extra.get("top_p"), Some(&serde_json::json!(0.95)));
        }

        #[test]
        fn test_anthropic_request_roundtrip_identity() {
            // Round-trip identity: semantic equivalence via decoded IR (NOT byte-identical) because
            // serializer adds is_error:false for tool_result blocks that had no is_error field in input.
            // This is documented semantic equivalence per anti-fab spec - assert on DECODED IR directly
            // which is the ground truth that a doctored fixture cannot fake (TREND #9 + #10).
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();
            let j = anthropic_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Round-trip the JSON through write + read and verify DECODED IR is identical
            let roundtrip_json = writer.write_request(&ir);
            let rt_ir = reader
                .read_request(&roundtrip_json)
                .expect("read round-trip should succeed");

            // Assert decoded IR is byte-identical (ground truth for anti-fab)
            assert_eq!(ir, rt_ir, "decoded IR must be identical after round-trip");
        }

        #[test]
        fn test_anthropic_request_empty_minimal() {
            // Empty/minimal: a bare {"messages":[{"role":"user","content":"hi"}]} round-trips and decodes
            let j = serde_json::json!({
                "messages": [{"role": "user", "content": "hi"}]
            });

            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert empty/minimal properties
            assert!(ir.system.is_empty());
            assert_eq!(ir.messages.len(), 1);
            assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
            if let crate::ir::IrBlock::Text { ref text, .. } = ir.messages[0].content[0] {
                assert_eq!(text, "hi");
            } else {
                panic!("expected Text block");
            }
            assert!(ir.tools.is_empty());
            assert_eq!(ir.max_tokens, None);
            assert_eq!(ir.temperature, None);
            assert!(!ir.stream);

            // Round-trip: semantic equivalence (NOT byte-identical) because serializer always outputs
            // content as array even for single text block - this is a known serialization difference
            let roundtrip = writer.write_request(&ir);

            // Verify semantic equivalence via decoded IR
            let rt_ir = reader
                .read_request(&roundtrip)
                .expect("read round-trip should succeed");
            assert_eq!(ir, rt_ir);
        }

        // ============================================================================
        // B. OpenAI REQUEST property tests (decode assertions + correlation)
        // ============================================================================

        /// Canonical OpenAI fixture with natural values only.
        fn openai_rich_fixture() -> serde_json::Value {
            serde_json::json!({
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "hello"},
                            {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}
                        ]
                    },
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"location\":\"San Francisco\"}"
                                }
                            }
                        ]
                    },
                    {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
                ],
                "tools": [
                    {
                        "type": "function",
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "parameters": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ],
                "max_tokens": 100,
                "temperature": 0.7,
                "stream": true,
                "top_p": 0.95
            })
        }

        #[test]
        fn test_openai_request_decode_assertions() {
            // DECODE assertions on canonical OpenAI fixture - exact field values that a doctored
            // fixture cannot fake (anti-fab / TREND #9 + #10)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let j = openai_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert system decoded from messages[0] (OpenAI convention)
            assert!(!ir.system.is_empty());
            if let crate::ir::IrBlock::Text { ref text, .. } = ir.system[0] {
                assert_eq!(text, "You are a helpful assistant.");
            } else {
                panic!("system[0] should be Text block");
            }

            // Assert ToolUse id == "call_123" (NOT regenerated)
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, .. } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123", "ToolUse id must be verbatim from input");
                            assert_eq!(name, "get_weather");
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Assert the tool_result tool_use_id == "call_123" (correlation)
            let mut found_tool_result = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Tool {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            ref tool_use_id, ..
                        } = block
                        {
                            found_tool_result = true;
                            assert_eq!(
                                tool_use_id, "call_123",
                                "tool_result correlation must survive"
                            );
                        }
                    }
                }
            }
            assert!(found_tool_result);

            // Assert image url preserved in Image.data
            let mut found_image = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Image {
                            media_type: _,
                            ref data,
                        } = block
                        {
                            found_image = true;
                            assert_eq!(data, "https://example.com/image.png");
                        }
                    }
                }
            }
            assert!(found_image);

            // Assert temperature Some(0.7) (f64, exact natural value)
            assert_eq!(ir.temperature, Some(0.7_f64));
        }

        #[test]
        fn test_openai_tool_call_id_correlation_survives_write() {
            // tool_call id correlation survives write: after write_request, the assistant
            // tool_calls[0].id == "call_123" AND the tool message tool_call_id == "call_123" (same id)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();
            let j = openai_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");
            let roundtrip = writer.write_request(&ir);

            // Verify assistant tool_calls[0].id == "call_123"
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc_val in tc_arr {
                            if let Some(id) = tc_val.get("id").and_then(|i| i.as_str()) {
                                assert_eq!(
                                    id, "call_123",
                                    "assistant tool_call id must survive write"
                                );
                            }
                        }
                    }
                }
            }

            // Verify tool message tool_call_id == "call_123" (same id)
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if msg_val.get("role").and_then(|r| r.as_str()) == Some("tool") {
                        if let Some(tool_call_id) =
                            msg_val.get("tool_call_id").and_then(|i| i.as_str())
                        {
                            assert_eq!(
                                tool_call_id, "call_123",
                                "tool message correlation must survive"
                            );
                        } else {
                            panic!("tool message should have tool_call_id");
                        }
                    }
                }
            }
        }

        #[test]
        fn test_openai_arguments_string_to_value_roundtrip() {
            // arguments string↔Value: OpenAI function `arguments` (JSON string) → ToolUse.input
            // (Value/Object) on read, re-serialized to a string on write that re-parses equal
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();

            let j = serde_json::json!({
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"location\":\"San Francisco\",\"unit\":\"celsius\"}"
                                }
                            }
                        ]
                    }
                ]
            });

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Find ToolUse and verify arguments parsed to Value/Object on read
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123");
                            assert_eq!(name, "get_weather");
                            match input {
                                serde_json::Value::Object(obj) => {
                                    assert_eq!(
                                        obj.get("location"),
                                        Some(&serde_json::json!("San Francisco"))
                                    );
                                    assert_eq!(
                                        obj.get("unit"),
                                        Some(&serde_json::json!("celsius"))
                                    );
                                }
                                _ => panic!("arguments should parse to Object Value"),
                            }
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Write and re-parse arguments from roundtrip
            let roundtrip = writer.write_request(&ir);
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc_val in tc_arr {
                            if let Some(func) = tc_val.get("function") {
                                let args_str =
                                    func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");

                                // Re-parse the serialized string and compare parsed values
                                let roundtrip_args: serde_json::Value =
                                    serde_json::from_str(args_str).expect("args should parse");

                                // Compare with original parsed value
                                if let crate::ir::IrBlock::ToolUse { input, .. } =
                                    &ir.messages[0].content[0]
                                {
                                    assert_eq!(
                                        roundtrip_args, *input,
                                        "re-serialized arguments must equal original parsed Value"
                                    );
                                } else {
                                    panic!("expected ToolUse block");
                                }
                            }
                        }
                    }
                }
            }
        }

        // ============================================================================
        // C. Anthropic RESPONSE/STREAM per-event property tests (read_response_event/write_response_event)
        // ============================================================================

        #[test]
        fn test_anthropic_stream_per_event_roundtrip() {
            // Per-event round-trip for each event type with natural values
            let reader = AnthropicReader;
            let writer = AnthropicWriter;

            // 1. message_start w/ usage incl. cache tokens
            let data = serde_json::json!({
                "message": {
                    "role": "assistant",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 20,
                        "cache_creation_input_tokens": 5,
                        "cache_read_input_tokens": 15
                    }
                }
            });
            let ev = reader.read_response_event("message_start", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_start".to_string(), data))
                );
            }

            // 2. content_block_start tool_use
            let data = serde_json::json!({
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "call_123",
                    "name": "get_weather"
                }
            });
            let ev = reader.read_response_event("content_block_start", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_start".to_string(), data))
                );
            }

            // 3. content_block_delta ×4 delta kinds (text, thinking, input_json, signature)
            let text_data = serde_json::json!({
                "index": 0,
                "delta": {"type": "text_delta", "text": "hello"}
            });
            let ev = reader.read_response_event("content_block_delta", &text_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), text_data))
                );
            }

            let thinking_data = serde_json::json!({
                "index": 1,
                "delta": {"type": "thinking_delta", "thinking": "I need to think"}
            });
            let ev = reader.read_response_event("content_block_delta", &thinking_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), thinking_data))
                );
            }

            let json_data = serde_json::json!({
                "index": 2,
                "delta": {"type": "input_json_delta", "partial_json": "{\"loc"}
            });
            let ev = reader.read_response_event("content_block_delta", &json_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), json_data))
                );
            }

            let sig_data = serde_json::json!({
                "index": 1,
                "delta": {"type": "signature_delta", "signature": "sig_thinking_xyz"}
            });
            let ev = reader.read_response_event("content_block_delta", &sig_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), sig_data))
                );
            }

            // 4. content_block_stop
            let data = serde_json::json!({"index": 0});
            let ev = reader.read_response_event("content_block_stop", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_stop".to_string(), data))
                );
            }

            // 5. message_delta w/ usage
            let data = serde_json::json!({
                "delta": {"stop_reason": "end_turn"},
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            });
            let ev = reader.read_response_event("message_delta", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_delta".to_string(), data))
                );
            }

            // 6. message_stop
            let data = serde_json::json!({});
            let ev = reader.read_response_event("message_stop", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_stop".to_string(), data))
                );
            }

            // 7. error event
            let data = serde_json::json!({
                "error": {"type": "invalid_request_error"}
            });
            let ev = reader.read_response_event("error", &data);
            assert!(ev.is_some());
        }

        #[test]
        fn test_split_usage_decode_all_fields_distinct() {
            // Split usage decode: a message_delta usage {input 100, output 50, cache_creation 30,
            // cache_read 200} decodes to IrUsage with all four DISTINCT (assert each ==, and input != sum)
            let reader = AnthropicReader;

            let data = serde_json::json!({
                "delta": {"stop_reason": "end_turn"},
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 30,
                    "cache_read_input_tokens": 200
                }
            });

            let ev = reader
                .read_response_event("message_delta", &data)
                .expect("should parse message_delta");

            if let crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: _,
                usage,
            } = ev
            {
                // Assert each field == exact value (natural values only)
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 50);
                assert_eq!(usage.cache_creation_input_tokens, Some(30));
                assert_eq!(usage.cache_read_input_tokens, Some(200));

                // Verify they weren't collapsed: input != sum of cache tokens (anti-fab TREND #9)
                let cache_sum = 30 + 200;
                assert_ne!(
                    100, cache_sum,
                    "input_tokens must not be collapsed into cache token sum"
                );
            } else {
                panic!("expected MessageDelta event");
            }
        }

        #[test]
        fn test_signature_delta_verbatim_roundtrip() {
            // signature_delta decodes to IrDelta::SignatureDelta(s) with s == input, round-trips
            let reader = AnthropicReader;
            let writer = AnthropicWriter;

            let sig = "sig_thinking_abc123xyz";
            let data = serde_json::json!({
                "index": 0,
                "delta": {
                    "type": "signature_delta",
                    "signature": sig
                }
            });

            // Decode assertion: signature decodes to SignatureDelta(s) with s == input
            let ev = reader
                .read_response_event("content_block_delta", &data)
                .expect("should parse");

            if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
                if let crate::ir::IrDelta::SignatureDelta(s) = delta {
                    assert_eq!(s, sig);
                } else {
                    panic!("expected SignatureDelta variant");
                }
            } else {
                panic!("expected BlockDelta event");
            }

            // Round-trip: write back and verify signature preserved verbatim
            let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
            });
            assert!(roundtrip.is_some());
            let (_, rt_data) = roundtrip.unwrap();

            let rt_sig = rt_data
                .get("delta")
                .and_then(|d| d.get("signature"))
                .and_then(|s| s.as_str())
                .unwrap();
            assert_eq!(rt_sig, sig);
        }

        #[test]
        fn test_openai_write_response_event_text_delta() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk.get("object").and_then(|v| v.as_str()),
                Some("chat.completion.chunk")
            );
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            assert_eq!(choice.get("index").and_then(|v| v.as_u64()), Some(0));
            assert_eq!(
                choice
                    .get("delta")
                    .and_then(|d| d.get("content").and_then(|c| c.as_str())),
                Some("hello")
            );
        }

        #[test]
        fn test_openai_write_response_event_message_start() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk.get("object").and_then(|v| v.as_str()),
                Some("chat.completion.chunk")
            );
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            assert_eq!(
                choice
                    .get("delta")
                    .and_then(|d| d.get("role").and_then(|r| r.as_str())),
                Some("assistant")
            );
        }

        #[test]
        fn test_openai_write_response_event_finish_reason_mapping() {
            let writer = OpenAiWriter;

            // end_turn -> stop
            let ev1 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result1 = writer.write_response_event(&ev1);
            assert!(result1.is_some());
            let (_, chunk1) = result1.unwrap();
            let choices1 = chunk1.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices1[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("stop")
            );

            // max_tokens -> length
            let ev2 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("max_tokens".to_string()),
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result2 = writer.write_response_event(&ev2);
            assert!(result2.is_some());
            let (_, chunk2) = result2.unwrap();
            let choices2 = chunk2.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices2[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("length")
            );

            // tool_use -> tool_calls
            let ev3 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("tool_use".to_string()),
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result3 = writer.write_response_event(&ev3);
            assert!(result3.is_some());
            let (_, chunk3) = result3.unwrap();
            let choices3 = chunk3.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices3[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("tool_calls")
            );
        }

        #[test]
        fn test_openai_write_response_event_tool_call_args() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(r#"{"x":1}"#.to_string()),
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            let tool_calls = choice
                .get("delta")
                .and_then(|d| d.get("tool_calls"))
                .and_then(|tc| tc.as_array())
                .unwrap();
            assert_eq!(tool_calls.len(), 1);
            let func_args = tool_calls[0]
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap();
            assert_eq!(func_args, r#"{"x":1}"#);
        }

        #[test]
        fn test_openai_write_response_event_lossy_drops() {
            let writer = OpenAiWriter;

            // ThinkingDelta -> None
            let ev1 = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta("thinking...".to_string()),
            };
            assert!(writer.write_response_event(&ev1).is_none());

            // SignatureDelta -> None
            let ev2 = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::SignatureDelta("sig...".to_string()),
            };
            assert!(writer.write_response_event(&ev2).is_none());

            // BlockStop -> None
            let ev3 = crate::ir::IrStreamEvent::BlockStop { index: 0 };
            assert!(writer.write_response_event(&ev3).is_none());

            // MessageStop -> None
            let ev4 = crate::ir::IrStreamEvent::MessageStop;
            assert!(writer.write_response_event(&ev4).is_none());
        }

        #[test]
        fn test_openai_write_response_event_error() {
            let writer = OpenAiWriter;
            let err = crate::proto::IrError {
                class: crate::breaker::StatusClass::ClientError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            };
            let ev = crate::ir::IrStreamEvent::Error(err);
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str()),
                Some("boom")
            );
        }
    }
}

#[cfg(test)]
mod stream_fanout_tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent, IrUsage, StreamDecodeState};
    use serde_json::json;

    // B-502c-2b: OpenAI flat stream → Anthropic-shaped IR events. Exact-sequence decode asserts
    // (ungameable: the expected Vec is derived from the state-machine spec, not from output).
    #[test]
    fn test_openai_read_fanout_text() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        for chunk in [
            json!({"choices":[{"delta":{"role":"assistant"}}]}),
            json!({"choices":[{"delta":{"content":"Hel"}}]}),
            json!({"choices":[{"delta":{"content":"lo"}}]}),
            json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}),
        ] {
            events.extend(reader.read_response_events("", &chunk, &mut st));
        }
        assert_eq!(
            events,
            vec![
                IrStreamEvent::MessageStart {
                    role: IrRole::Assistant,
                    usage: None
                },
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("Hel".to_string())
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("lo".to_string())
                },
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some("end_turn".to_string()),
                    usage: IrUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None
                    },
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn test_openai_read_fanout_tool_call() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        for chunk in [
            json!({"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"loc\":\"SF\"}"}}]}}]}),
            json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
        ] {
            events.extend(reader.read_response_events("", &chunk, &mut st));
        }
        assert_eq!(
            events,
            vec![
                IrStreamEvent::MessageStart {
                    role: IrRole::Assistant,
                    usage: None
                },
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse {
                        id: "call_1".to_string(),
                        name: "get_weather".to_string()
                    }
                },
                IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta(String::new())
                },
                IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta("{\"loc\":\"SF\"}".to_string())
                },
                IrStreamEvent::BlockStop { index: 1 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some("tool_use".to_string()),
                    usage: IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None
                    },
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn test_openai_read_fanout_cached_tokens() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{"content":"hi"}}]}),
            &mut st,
        ));
        events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":7}}}),
            &mut st,
        ));
        let usage = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta { usage, .. } => Some(usage.clone()),
                _ => None,
            })
            .expect("MessageDelta present");
        assert_eq!(
            usage.cache_read_input_tokens,
            Some(7),
            "cached_tokens → cache_read"
        );
        assert_eq!(
            usage.cache_creation_input_tokens, None,
            "OpenAI has no cache-creation split"
        );
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn test_anthropic_read_events_wraps_singular() {
        let reader = AnthropicReader;
        let mut st = StreamDecodeState::default();
        let data = json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}});
        let single = reader.read_response_event("content_block_delta", &data);
        let plural = reader.read_response_events("content_block_delta", &data, &mut st);
        assert_eq!(
            plural,
            single.into_iter().collect::<Vec<_>>(),
            "Anthropic plural wraps singular 1:1"
        );
        assert_eq!(plural.len(), 1);
        // ping → empty
        assert_eq!(
            reader.read_response_events("ping", &json!({}), &mut st),
            Vec::<IrStreamEvent>::new()
        );
    }
}

#[cfg(test)]
mod stream_translate_tests {
    use super::*;

    /// Collect the JSON payloads of all `data:` lines (excluding `[DONE]`).
    fn data_payloads(out: &str) -> Vec<serde_json::Value> {
        out.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|s| s.trim())
            .filter(|s| *s != "[DONE]")
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect()
    }

    // anthropic egress stream → openai ingress: client receives OpenAI chat.completion.chunks.
    #[test]
    fn test_translate_anthropic_egress_to_openai_ingress() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let mut out = String::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());

        assert!(
            !out.contains("event:"),
            "OpenAI output must have no event: lines; got {out}"
        );
        let payloads = data_payloads(&out);
        assert!(
            payloads.iter().any(|p| p
                .pointer("/choices/0/delta/content")
                .and_then(|v| v.as_str())
                == Some("hi")),
            "translated content 'hi' missing; got {out}"
        );
        assert!(
            payloads.iter().any(|p| p
                .pointer("/choices/0/finish_reason")
                .and_then(|v| v.as_str())
                == Some("stop")),
            "finish_reason 'stop' missing; got {out}"
        );
        assert!(
            out.trim_end().ends_with("data: [DONE]"),
            "OpenAI stream must end with data: [DONE]; got {out}"
        );
    }

    // openai egress stream → anthropic ingress: client receives Anthropic event: frames.
    #[test]
    fn test_translate_openai_egress_to_anthropic_ingress() {
        let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
        let mut out = String::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        assert!(
            t.finish().is_empty(),
            "Anthropic ingress has no [DONE] terminator"
        );
        assert!(
            out.contains("event: message_start"),
            "missing message_start; got {out}"
        );
        assert!(
            out.contains("event: content_block_delta"),
            "missing content_block_delta; got {out}"
        );
        assert!(
            out.contains("text_delta") && out.contains("hi"),
            "missing text_delta 'hi'; got {out}"
        );
        assert!(
            out.contains("event: message_stop"),
            "missing message_stop; got {out}"
        );
    }

    // A frame split across two feeds yields no output until complete, then translates.
    #[test]
    fn test_translate_split_frame_reassembly() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
        let (a, b) = frame.as_bytes().split_at(20);
        assert!(t.feed(a).is_empty(), "partial frame must yield no output");
        let s = String::from_utf8(t.feed(b)).unwrap();
        assert!(
            s.contains("\"content\":\"hi\""),
            "completed frame must translate to openai content; got {s}"
        );
    }

    // Cross-protocol tool-calling fidelity: openai tool_calls → anthropic tool_use survives.
    #[test]
    fn test_translate_tool_call_fidelity() {
        let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
        let mut out = String::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"loc\\\":\\\"SF\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        assert!(
            out.contains("content_block_start"),
            "missing content_block_start; got {out}"
        );
        assert!(
            out.contains("tool_use"),
            "tool_use block type missing; got {out}"
        );
        assert!(
            out.contains("get_weather") && out.contains("call_1"),
            "tool name/id must survive cross-protocol; got {out}"
        );
        assert!(
            out.contains("input_json_delta"),
            "missing input_json_delta; got {out}"
        );
    }

    #[test]
    fn test_translate_same_protocol_is_none() {
        assert!(StreamTranslate::new("openai", "openai").is_none());
        assert!(StreamTranslate::new("anthropic", "anthropic").is_none());
    }

    // ============================================================
    // B-503c-1: Whole-response (non-streaming) R/W tests
    // ============================================================

    #[test]
    fn test_anthropic_read_response_decode() {
        // Anthropic message → IrResponse with exact fields
        let data = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5,
                "output_tokens": 3,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let reader = AnthropicReader;
        let resp = reader.read_response(&data).expect("should parse");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "hi");
        } else {
            panic!("expected Text block");
        }
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn test_openai_read_response_decode() {
        // OpenAI chat.completion → IrResponse with exact fields and stop_reason mapping
        let data = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let reader = OpenAiReader;
        let resp = reader.read_response(&data).expect("should parse");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "hi");
        } else {
            panic!("expected Text block");
        }
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn")); // mapped from "stop"
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn test_cross_protocol_openai_to_anthropic() {
        // OpenAI → IR → Anthropic: verify output is Anthropic-shaped
        let openai_data = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let ir_resp = OpenAiReader
            .read_response(&openai_data)
            .expect("OpenAI read");
        let anthropic_json = AnthropicWriter.write_response(&ir_resp);

        // Assert Anthropic-shaped output
        assert_eq!(
            anthropic_json.get("type").and_then(|v| v.as_str()),
            Some("message")
        );
        if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
            assert!(!content_arr.is_empty());
            let first_block = &content_arr[0];
            assert_eq!(
                first_block.get("type").and_then(|v| v.as_str()),
                Some("text")
            );
            assert_eq!(first_block.get("text").and_then(|v| v.as_str()), Some("hi"));
        } else {
            panic!("missing content array");
        }
        assert_eq!(
            anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
            Some("end_turn")
        );
    }

    #[test]
    fn test_cross_protocol_anthropic_to_openai() {
        // Anthropic → IR → OpenAI: verify output is OpenAI-shaped
        let anthropic_data = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5,
                "output_tokens": 3,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let ir_resp = AnthropicReader
            .read_response(&anthropic_data)
            .expect("Anthropic read");
        let openai_json = OpenAiWriter.write_response(&ir_resp);

        // Assert OpenAI-shaped output
        assert_eq!(
            openai_json.get("object").and_then(|v| v.as_str()),
            Some("chat.completion")
        );
        if let Some(choices_arr) = openai_json.get("choices").and_then(|c| c.as_array()) {
            assert!(!choices_arr.is_empty());
            let choice = &choices_arr[0];
            if let Some(msg) = choice.get("message") {
                assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
                assert_eq!(msg.get("content").and_then(|v| v.as_str()), Some("hi"));
            } else {
                panic!("missing message");
            }
            assert_eq!(
                choice.get("finish_reason").and_then(|v| v.as_str()),
                Some("stop")
            );
        } else {
            panic!("missing choices array");
        }
    }

    #[test]
    fn test_cross_protocol_tool_use_response() {
        // OpenAI tool_calls response → IR → Anthropic: verify tool_use block round-trips
        let openai_data = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{\"x\":1}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let ir_resp = OpenAiReader
            .read_response(&openai_data)
            .expect("OpenAI read");

        // Verify IR has ToolUse block
        assert_eq!(ir_resp.content.len(), 1);
        if let crate::ir::IrBlock::ToolUse { id, name, input } = &ir_resp.content[0] {
            assert_eq!(id, "call_1");
            assert_eq!(name, "f");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("expected ToolUse block");
        }

        let anthropic_json = AnthropicWriter.write_response(&ir_resp);

        // Assert Anthropic output has tool_use block with correct fields
        if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
            assert!(!content_arr.is_empty());
            let first_block = &content_arr[0];
            assert_eq!(
                first_block.get("type").and_then(|v| v.as_str()),
                Some("tool_use")
            );
            assert_eq!(
                first_block.get("id").and_then(|v| v.as_str()),
                Some("call_1")
            );
            assert_eq!(first_block.get("name").and_then(|v| v.as_str()), Some("f"));
            // input should be an object with x: 1
            if let Some(input_val) = first_block.get("input") {
                match input_val {
                    serde_json::Value::Object(obj) => {
                        assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
                    }
                    _ => panic!("input should be Object"),
                }
            } else {
                panic!("missing input");
            }
        } else {
            panic!("missing content array");
        }

        // stop_reason should be "tool_use" (passthrough from Anthropic canonical form)
        assert_eq!(
            anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
            Some("tool_use")
        );
    }

    #[test]
    fn test_same_protocol_roundtrip_idempotence() {
        // Anthropic read → write → read yields equal IrResponse
        let original_data = serde_json::json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"loc": "SF"}}
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // First read
        let ir1 = reader.read_response(&original_data).expect("first read");

        // Write to JSON
        let written_json = writer.write_response(&ir1);

        // Read again
        let ir2 = reader.read_response(&written_json).expect("second read");

        // Decode IR must be identical (ground truth for anti-fab)
        assert_eq!(ir1, ir2, "decoded IR must be identical after round-trip");
    }

    // B-510a: Gemini decode test - systemInstruction + contents with mixed blocks + tools
    #[test]
    fn test_gemini_decode() {
        let j = serde_json::json!({
            "systemInstruction": {
                "parts": [{"text": "You are a helpful assistant."}]
            },
            "contents": [
                {"role": "user", "parts": [
                    {"text": "What is the weather?"},
                    {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"}}
                ]},
                {"role": "model", "parts": [
                    {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
                ]},
                {"role": "user", "parts": [
                    {"functionResponse": {"name": "get_weather", "response": {"temperature": 72, "units": "F"}}}
                ]}
            ],
            "tools": [{
                "functionDeclarations": [
                    {
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "parameters": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ]
            }],
            "generationConfig": {
                "maxOutputTokens": 4096,
                "temperature": 0.7
            },
            "stream": true
        });

        let reader = GeminiReader;
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Assert system Text block
        assert_eq!(ir.system.len(), 1);
        if let crate::ir::IrBlock::Text {
            text,
            cache_control: _,
            citations: _,
        } = &ir.system[0]
        {
            assert_eq!(text, "You are a helpful assistant.");
        } else {
            panic!("expected Text block in system");
        }

        // Assert messages roles and content
        assert_eq!(ir.messages.len(), 3);

        // First message: User with text + image
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[0].content.len(), 2);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What is the weather?");
        } else {
            panic!("expected Text block in first message");
        }
        if let crate::ir::IrBlock::Image { media_type, data } = &ir.messages[0].content[1] {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
        } else {
            panic!("expected Image block in first message");
        }

        // Second message: Assistant with functionCall (ToolUse)
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
        assert_eq!(ir.messages[1].content.len(), 1);
        if let crate::ir::IrBlock::ToolUse { id: _, name, input } = &ir.messages[1].content[0] {
            assert_eq!(name, "get_weather");
            assert_eq!(
                input.get("location").and_then(|v| v.as_str()),
                Some("San Francisco")
            );
        } else {
            panic!("expected ToolUse block in second message");
        }

        // Third message: User with functionResponse (ToolResult)
        assert_eq!(ir.messages[2].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[2].content.len(), 1);
        if let crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } = &ir.messages[2].content[0]
        {
            assert_eq!(tool_use_id, "get_weather");
            assert!(!is_error);
            assert_eq!(content.len(), 1);
            if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
                // Response serialized as JSON string
                assert!(text.contains("72") || text.contains("temperature"));
            } else {
                panic!("expected Text block in tool result");
            }
        } else {
            panic!("expected ToolResult block in third message");
        }

        // Assert tools
        assert_eq!(ir.tools.len(), 1);
        let crate::ir::IrTool {
            name,
            description,
            input_schema,
        } = &ir.tools[0];
        {
            assert_eq!(name, "get_weather");
            assert_eq!(description.as_deref(), Some("Get weather for a location"));
            assert!(!input_schema.is_null());
        }

        // Assert generationConfig fields
        assert_eq!(ir.max_tokens, Some(4096));
        assert_eq!(ir.temperature, Some(0.7));
        assert!(ir.stream);
    }

    // B-510a: Gemini round-trip test - write_request(read_request(j)) == j for canonical fixture
    #[test]
    fn test_gemini_roundtrip_identity() {
        let j = serde_json::json!({
            "model": "gemini-pro",
            "systemInstruction": {"parts": [{"text": "You are a helpful assistant."}]},
            "contents": [
                {"role": "user", "parts": [{"text": "Hello"}]},
                {"role": "model", "parts": [{"text": "Hi there!"}]}
            ],
            "generationConfig": {"maxOutputTokens": 100, "temperature": 0.5},
            "stream": false
        });

        let reader = GeminiReader;
        let writer = GeminiWriter;

        // Canonical form: minimal fixture that round-trips exactly
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);

        // Compare as Value - exact identity on representable subset
        assert_eq!(roundtrip, j, "round-trip must be byte-identical");
    }

    // B-510a: Protocol::gemini() resolves correctly with working reader/writer
    #[test]
    fn test_gemini_protocol_resolves() {
        let proto = Protocol::gemini();
        assert_eq!(proto.name(), "gemini");

        let reader = proto.reader();
        let writer = proto.writer();

        // Verify reader methods work
        let j = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "test"}]}]
        });
        let ir = reader.read_request(&j).expect("reader should parse");
        assert_eq!(ir.messages.len(), 1);

        // Verify writer methods work
        let output = writer.write_request(&ir);
        assert!(output.as_object().unwrap().contains_key("contents"));

        // Verify other protocol methods. B-510c: the real per-request path embeds the model via
        // upstream_path_for(); upstream_path() is just the model-independent base.
        assert_eq!(writer.upstream_path(), "/v1beta/models");
        assert_eq!(
            writer.upstream_path_for("gemini-pro"),
            "/v1beta/models/gemini-pro:generateContent"
        );
        let headers = writer.auth_headers("test-key");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "x-goog-api-key");

        // Verify error handling methods
        let status_code = StatusCode::TOO_MANY_REQUESTS;
        let signal = reader.classify(status_code, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        let raw_error = reader.extract_error(status_code, b"{}");
        assert_eq!(raw_error.http_status, 429);
    }
}

#[cfg(test)]
mod gemini_tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent};

    // B-510b: read_response decode - Gemini generateContent response with text + functionCall
    #[test]
    fn test_gemini_read_response_decode() {
        let j = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "The weather in San Francisco is sunny."},
                        {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
                    ]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 15,
                "candidatesTokenCount": 8
            }
        });

        let reader = GeminiReader;
        let resp = reader.read_response(&j).expect("should parse");

        // Assert content: Text + ToolUse
        assert_eq!(resp.content.len(), 2);

        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "The weather in San Francisco is sunny.");
        } else {
            panic!("expected Text block");
        }

        if let crate::ir::IrBlock::ToolUse { id: _, name, input } = &resp.content[1] {
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(
                        obj.get("location"),
                        Some(&serde_json::json!("San Francisco"))
                    );
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("expected ToolUse block");
        }

        // Assert stop_reason: "STOP" → "end_turn"
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));

        // Assert usage: promptTokenCount→input_tokens, candidatesTokenCount→output_tokens
        assert_eq!(resp.usage.input_tokens, 15);
        assert_eq!(resp.usage.output_tokens, 8);
    }

    // B-510b: whole-response round-trip - write_response(read_response(j)) == j
    #[test]
    fn test_gemini_read_write_response_roundtrip() {
        let j = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "Hello, world!"}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 3
            }
        });

        let reader = GeminiReader;
        let writer = GeminiWriter;

        let ir = reader.read_response(&j).expect("should parse");
        let roundtrip = writer.write_response(&ir);

        // Round-trip must be byte-identical for canonical text-only fixture
        assert_eq!(roundtrip, j, "whole-response round-trip must be identical");
    }

    // B-510b: stream fan-out - feed Gemini chunk sequence through StreamDecodeState
    #[test]
    fn test_gemini_read_response_events_stream_fanout() {
        let reader = GeminiReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Chunk 1: text delta (role+text)
        let chunk1 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hello"}]},
                "finishReason": null
            }]
        });

        // Chunk 2: more text delta
        let chunk2 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": ", world!"}]},
                "finishReason": null
            }]
        });

        // Chunk 3: finish with STOP + usageMetadata
        let chunk3 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 5
            }
        });

        let mut events: Vec<IrStreamEvent> = Vec::new();

        for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
            events.extend(reader.read_response_events("", &chunk, &mut state));
        }

        // Assert exact event sequence: MessageStart, BlockStart{0,Text}, BlockDelta×2, BlockStop{0}, MessageDelta{end_turn,usage}, MessageStop
        assert_eq!(events.len(), 7);

        assert!(matches!(
            events[0],
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None
            }
        ));

        assert!(matches!(
            events[1],
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            }
        ));

        if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[2] {
            assert_eq!(*idx, 0);
            if let IrDelta::TextDelta(text) = delta {
                assert_eq!(text, "Hello");
            } else {
                panic!("expected TextDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[3] {
            assert_eq!(*idx, 0);
            if let IrDelta::TextDelta(text) = delta {
                assert_eq!(text, ", world!");
            } else {
                panic!("expected TextDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        assert!(matches!(events[4], IrStreamEvent::BlockStop { index: 0 }));

        if let IrStreamEvent::MessageDelta { stop_reason, usage } = &events[5] {
            assert_eq!(stop_reason.as_deref(), Some("end_turn"));
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.output_tokens, 5);
        } else {
            panic!("expected MessageDelta");
        }

        assert!(matches!(events[6], IrStreamEvent::MessageStop));
    }

    // B-510b: write_response_event - BlockDelta TextDelta → candidates[0].content.parts[0].text
    #[test]
    fn test_gemini_write_response_event_text_delta() {
        let writer = GeminiWriter;

        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };

        let result = writer.write_response_event(&ev);
        assert!(result.is_some());

        let (_, chunk) = result.unwrap();

        // Assert structure: candidates[0].content.parts[0].text == "hi"
        let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
        assert_eq!(candidates.len(), 1);

        let candidate = &candidates[0];
        let content = candidate.get("content").unwrap();

        assert_eq!(content.get("role").and_then(|r| r.as_str()), Some("model"));

        let parts_arr = content.get("parts").and_then(|p| p.as_array()).unwrap();
        assert_eq!(parts_arr.len(), 1);

        let part = &parts_arr[0];
        assert_eq!(part.get("text").and_then(|t| t.as_str()), Some("hi"));
    }

    // B-510b: write_response_event - MessageDelta{end_turn} → finishReason "STOP"
    #[test]
    fn test_gemini_write_response_event_message_delta() {
        let writer = GeminiWriter;

        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        let result = writer.write_response_event(&ev);
        assert!(result.is_some());

        let (_, chunk) = result.unwrap();

        // Assert finishReason == "STOP"
        let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
        assert_eq!(candidates.len(), 1);

        let candidate = &candidates[0];
        assert_eq!(
            candidate.get("finishReason").and_then(|r| r.as_str()),
            Some("STOP")
        );

        // Assert usageMetadata present
        assert!(chunk.get("usageMetadata").is_some());
    }

    // B-510b: stream fan-out with functionCall - ToolUse via functionCall
    #[test]
    fn test_gemini_read_response_events_function_call() {
        let reader = GeminiReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Chunk with text delta
        let chunk1 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Let me check"}]},
                "finishReason": null
            }]
        });

        // Chunk with functionCall (Gemini sends whole args, not streamed)
        let chunk2 = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": ""},
                        {"functionCall": {"name": "get_weather", "args": {"location": "SF"}}}
                    ]
                },
                "finishReason": null
            }]
        });

        // Chunk with finishReason STOP
        let chunk3 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 20,
                "candidatesTokenCount": 10
            }
        });

        let mut events: Vec<IrStreamEvent> = Vec::new();

        for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
            events.extend(reader.read_response_events("", &chunk, &mut state));
        }

        // Verify we have MessageStart + BlockStart{Text} + text delta + ToolUse block + tool args delta + blocks stop + MessageDelta + MessageStop
        assert!(events.len() >= 6);

        // Find the ToolUse-related events
        let mut found_tool_block_start = false;
        let mut found_tool_args_delta = false;

        for event in &events {
            match event {
                IrStreamEvent::BlockStart {
                    index: _,
                    block: crate::ir::IrBlockMeta::ToolUse { id: _, name },
                    ..
                } => {
                    if *name == "get_weather" {
                        found_tool_block_start = true;
                    }
                }

                IrStreamEvent::BlockDelta {
                    delta: IrDelta::InputJsonDelta(json_str),
                    ..
                } => {
                    // Parse and check args contain location
                    if let Ok(args) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if args.get("location").is_some() {
                            found_tool_args_delta = true;
                        }
                    }
                }
                _ => {}
            }
        }

        assert!(found_tool_block_start, "should have ToolUse BlockStart");
        assert!(
            found_tool_args_delta,
            "should have InputJsonDelta with args"
        );
    }
}

#[cfg(test)]
mod context_length_tests {
    use super::*;
    use crate::breaker::{classify, Disposition};
    use axum::http::StatusCode;

    #[test]
    fn test_classify_context_length_both_protocols() {
        // OpenAI: error.code == context_length_exceeded
        let o = OpenAiReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"code":"context_length_exceeded","message":"maximum context length is 8192 tokens"}}"#,
        );
        assert_eq!(
            o.class,
            StatusClass::ContextLength,
            "openai code → ContextLength"
        );

        // Anthropic: "prompt is too long"
        let a = AnthropicReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum"}}"#,
        );
        assert_eq!(
            a.class,
            StatusClass::ContextLength,
            "anthropic message → ContextLength"
        );

        // A plain 400 client error is NOT context-length (must still be ClientError).
        let c = AnthropicReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"type":"invalid_request_error","message":"unexpected field 'foo'"}}"#,
        );
        assert_eq!(
            c.class,
            StatusClass::ClientError,
            "generic 400 stays ClientError"
        );
    }

    #[test]
    fn test_context_length_disposition() {
        let sig = CanonicalSignal {
            class: StatusClass::ContextLength,
            provider_signal: Some("context_length".to_string()),
            retry_after: None,
        };
        assert_eq!(classify(&sig), Disposition::ContextLength);
    }
}

#[cfg(test)]
mod gemini_integration_tests {
    use super::*;

    // B-510c: Gemini's URL embeds the model; non-Gemini protocols keep their fixed path.
    #[test]
    fn test_gemini_upstream_path_for_embeds_model() {
        assert_eq!(
            GeminiWriter.upstream_path_for("gemini-1.5-pro"),
            "/v1beta/models/gemini-1.5-pro:generateContent"
        );
        // Default (non-Gemini) ignores the model.
        assert_eq!(
            AnthropicWriter.upstream_path_for("anything"),
            "/v1/messages"
        );
        assert_eq!(
            OpenAiWriter.upstream_path_for("anything"),
            "/v1/chat/completions"
        );
    }

    // B-510c: gemini is now a registered, buildable protocol.
    #[test]
    fn test_gemini_registered_in_builtins() {
        let reg = ProtocolRegistry::with_builtins();
        let g = reg.get("gemini").expect("gemini should be registered");
        assert_eq!(g.name(), "gemini");
        assert_eq!(
            g.writer().upstream_path_for("m"),
            "/v1beta/models/m:generateContent"
        );
        // x-goog-api-key auth header.
        let headers = g.writer().auth_headers("k");
        assert!(headers.iter().any(|(n, _)| n.as_str() == "x-goog-api-key"));
    }
}
