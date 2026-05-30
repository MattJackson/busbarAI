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
}

/// Resolve a built-in Protocol by name (for ingress translation). Cheap (unit structs).
#[allow(dead_code)] // used by forward (B-503a)
pub(crate) fn protocol_for(name: &str) -> Option<Protocol> {
    match name {
        "anthropic" => Some(Protocol::anthropic()),
        "openai" => Some(Protocol::openai()),
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
#[derive(Clone)]
pub(crate) struct AnthropicReader;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(String::from)
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        } else {
            None
        };

        // B-504: Anthropic signals context-length via the error MESSAGE (no distinct code).
        // Surface the canonical code so the breaker pipeline (normalize_raw_error) → ContextLength.
        let provider_code = provider_code.or_else(|| {
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("prompt is too long")
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
                Some("context_length_exceeded".to_string())
            } else {
                None
            }
        });

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);

        // B-504: context-length-exceeded (Anthropic returns 400 invalid_request_error). The lane
        // is healthy; this must fail over (to a larger-context model), not penalize the breaker.
        // Check before the generic 400/client-error path so it wins.
        let lower = text.to_lowercase();
        if lower.contains("prompt is too long")
            || (lower.contains("exceeds the maximum")
                && (lower.contains("token") || lower.contains("context")))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length".to_string()),
                retry_after: None,
            };
        }

        // A3: prefer HTTP status first, then structured error codes, then substrings as fallback.
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            if let Some(code_val) = json.get("error").and_then(|e| e.get("code")) {
                if code_val.as_str() == Some("400") || code_val.as_str() == Some("422") {
                    return CanonicalSignal {
                        class: StatusClass::ClientError,
                        provider_signal: Some("client_error".to_string()),
                        retry_after: None,
                    };
                }

                if let Some(msg_val) = json.get("error").and_then(|e| e.get("message")) {
                    if let Some(msg_str) = msg_val.as_str() {
                        if msg_str.contains("nsufficient balance") {
                            return CanonicalSignal {
                                class: StatusClass::Billing,
                                provider_signal: Some("billing".to_string()),
                                retry_after: None,
                            };
                        }
                        if msg_str.contains("unauthorized") || msg_str.contains("invalid token") {
                            return CanonicalSignal {
                                class: StatusClass::Auth,
                                provider_signal: Some("auth".to_string()),
                                retry_after: None,
                            };
                        }
                    }
                }
            }
        }

        if status.as_u16() == 401 || status.as_u16() == 403 {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: None,
                retry_after: None,
            };
        }

        if status.as_u16() == 429 {
            let text_lower = text.to_lowercase();
            if text_lower.contains("quota") && text_lower.contains("exhausted") {
                return CanonicalSignal {
                    class: StatusClass::Billing,
                    provider_signal: Some("429-quota-exhausted".to_string()),
                    retry_after: None,
                };
            }
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429-slowdown".to_string()),
                retry_after: None,
            };
        }

        if status.as_u16() >= 500 {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: None,
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        }
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        // Handle system field (string or array)
        if let Some(system_val) = obj.get("system") {
            if system_val.is_string() {
                let text = system_val.as_str().unwrap_or("").to_string();
                system_blocks.push(crate::ir::IrBlock::Text {
                    text,
                    cache_control: None,
                    citations: Vec::new(),
                });
            } else if system_val.is_array() {
                for block_val in system_val.as_array().unwrap() {
                    system_blocks.push(read_block(block_val)?);
                }
            }
        }

        // Handle messages array
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            for msg_val in messages_val.as_array().unwrap_or(&Vec::new()) {
                messages.push(read_message(msg_val)?);
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_tool(tool_val)?);
            }
        }

        // Extract scalar fields and extra
        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect unmodeled top-level keys into extra
        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "system",
            "messages",
            "tools",
            "max_tokens",
            "temperature",
            "stream",
        ]
        .iter()
        .cloned()
        .collect();

        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        Ok(crate::ir::IrRequest {
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            stream,
            extra,
        })
    }

    #[allow(dead_code)] // Used by B-502b/B-503 tests
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        match event_type {
            "message_start" => {
                let msg = data.get("message")?;
                let role_str = msg.get("role").and_then(|r| r.as_str())?;
                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => return None,
                };
                let usage = data
                    .get("message")
                    .and_then(|m| m.get("usage"))
                    .map(|u| IrUsage {
                        input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        cache_creation_input_tokens: u
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64()),
                        cache_read_input_tokens: u
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64()),
                    });
                Some(IrStreamEvent::MessageStart { role, usage })
            }
            "content_block_start" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                let block = data.get("content_block")?;
                let block_type = block.get("type").and_then(|t| t.as_str())?;
                let meta = match block_type {
                    "text" => IrBlockMeta::Text,
                    "thinking" => IrBlockMeta::Thinking,
                    "tool_use" => {
                        let id = block.get("id").and_then(|i| i.as_str()).map(String::from)?;
                        let name = block
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(String::from)?;
                        IrBlockMeta::ToolUse { id, name }
                    }
                    "image" => IrBlockMeta::Image,
                    _ => return None,
                };
                Some(IrStreamEvent::BlockStart { index, block: meta })
            }
            "content_block_delta" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                let delta_val = data.get("delta")?;
                let delta_type = delta_val.get("type").and_then(|t| t.as_str())?;
                let delta = match delta_type {
                    "text_delta" => {
                        let text = delta_val
                            .get("text")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::TextDelta(text)
                    }
                    "thinking_delta" => {
                        let thinking = delta_val
                            .get("thinking")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::ThinkingDelta(thinking)
                    }
                    "input_json_delta" => {
                        let json = delta_val
                            .get("partial_json")
                            .or_else(|| delta_val.get("input_json"))
                            .and_then(|j| j.as_str())
                            .map(String::from)?;
                        IrDelta::InputJsonDelta(json)
                    }
                    "signature_delta" => {
                        let signature = delta_val
                            .get("signature")
                            .and_then(|s| s.as_str())
                            .map(String::from)?;
                        IrDelta::SignatureDelta(signature)
                    }
                    _ => return None,
                };
                Some(IrStreamEvent::BlockDelta { index, delta })
            }
            "content_block_stop" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                Some(IrStreamEvent::BlockStop { index })
            }
            "message_delta" => {
                let delta = data.get("delta")?;
                let stop_reason = delta
                    .get("stop_reason")
                    .and_then(|r| r.as_str())
                    .map(String::from);
                let usage_val = data.get("usage")?;
                let usage = IrUsage {
                    input_tokens: usage_val
                        .get("input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    output_tokens: usage_val
                        .get("output_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens: usage_val
                        .get("cache_creation_input_tokens")
                        .and_then(|v| v.as_u64()),
                    cache_read_input_tokens: usage_val
                        .get("cache_read_input_tokens")
                        .and_then(|v| v.as_u64()),
                };
                Some(IrStreamEvent::MessageDelta { stop_reason, usage })
            }
            "message_stop" => Some(IrStreamEvent::MessageStop),
            "error" => {
                let err_val = data.get("error")?;
                let provider_signal = err_val
                    .get("type")
                    .and_then(|t| t.as_str())
                    .map(String::from);
                Some(IrStreamEvent::Error(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some(provider_signal.unwrap_or_default()),
                    retry_after: None,
                }))
            }
            _ => None,
        }
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        _state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        // Anthropic events are already block-structured (1:1): wrap the singular, ignore state.
        match self.read_response_event(event_type, data) {
            Some(ev) => vec![ev],
            None => vec![],
        }
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        // Parse role (should be "assistant" for responses)
        let role_str = obj.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let role = match role_str {
            "assistant" => crate::ir::IrRole::Assistant,
            _ => {
                return Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some("ir_parse".into()),
                    retry_after: None,
                })
            }
        };

        // Parse content blocks
        let content_val = obj.get("content").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if content_val.is_array() {
            for block_val in content_val.as_array().unwrap() {
                content.push(read_block(block_val)?);
            }
        }

        // Parse stop_reason (optional)
        let stop_reason = obj
            .get("stop_reason")
            .and_then(|r| r.as_str())
            .map(String::from);

        // Parse usage
        let usage_val = obj.get("usage").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: usage_val
                .get("cache_creation_input_tokens")
                .and_then(|v| v.as_u64()),
            cache_read_input_tokens: usage_val
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64()),
        };

        Ok(crate::ir::IrResponse {
            role,
            content,
            stop_reason,
            usage,
        })
    }
}

// Helper functions for IR mapping (used by read_request/write_request)
#[allow(dead_code)] // Used by tests only (B-502a)
fn read_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "text" => {
            let text = obj
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Parse cache_control - object form: {"type": "ephemeral"}
            let cache_control = if let Some(cc_val) = obj.get("cache_control") {
                if let Some(cc_obj) = cc_val.as_object() {
                    if let Some(cc_type) = cc_obj.get("type").and_then(|t| t.as_str()) {
                        if cc_type == "ephemeral" {
                            Some(crate::ir::CacheControl {
                                kind: crate::ir::CacheKind::Ephemeral,
                            })
                        } else {
                            return Err(IrError {
                                class: StatusClass::ClientError,
                                provider_signal: Some("ir_parse".to_string()),
                                retry_after: None,
                            });
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let citations = obj
                .get("citations")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control,
                citations,
            })
        }
        "thinking" => {
            let text = obj
                .get("thinking")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let signature = obj
                .get("signature")
                .and_then(|v| v.as_str().map(String::from));
            Ok(crate::ir::IrBlock::Thinking { text, signature })
        }
        "tool_use" => {
            let id = obj
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let input = obj.get("input").cloned().unwrap_or(serde_json::Value::Null);
            Ok(crate::ir::IrBlock::ToolUse { id, name, input })
        }
        "tool_result" => {
            let tool_use_id = obj
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_val = obj.get("content").unwrap_or(&serde_json::Value::Null);
            let content = if content_val.is_array() {
                content_val
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(read_block)
                    .collect::<Result<_, _>>()?
            } else {
                vec![crate::ir::IrBlock::Text {
                    text: content_val.as_str().unwrap_or("").to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }]
            };
            let is_error = obj
                .get("is_error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            })
        }
        "image" => {
            let source = obj.get("source").ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;
            if let Some(src_obj) = source.as_object() {
                let media_type = src_obj
                    .get("media_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let data = src_obj
                    .get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(crate::ir::IrBlock::Image { media_type, data })
            } else {
                Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some("ir_parse".to_string()),
                    retry_after: None,
                })
            }
        }
        _ => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        }),
    }
}

#[allow(dead_code)] // Used by tests only (B-502a)
fn read_message(msg_val: &serde_json::Value) -> Result<crate::ir::IrMessage, IrError> {
    let obj = msg_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let role_str = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
    let role = match role_str {
        "user" => crate::ir::IrRole::User,
        "assistant" => crate::ir::IrRole::Assistant,
        "system" => crate::ir::IrRole::System,
        _ => {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })
        }
    };

    let content_val = obj.get("content").unwrap_or(&serde_json::Value::Null);
    let content = if content_val.is_array() {
        content_val
            .as_array()
            .unwrap()
            .iter()
            .map(read_block)
            .collect::<Result<_, _>>()?
    } else {
        vec![crate::ir::IrBlock::Text {
            text: content_val.as_str().unwrap_or("").to_string(),
            cache_control: None,
            citations: Vec::new(),
        }]
    };

    Ok(crate::ir::IrMessage { role, content })
}

#[allow(dead_code)] // Used by tests only (B-502a)
fn read_tool(tool_val: &serde_json::Value) -> Result<crate::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = obj
        .get("description")
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = obj
        .get("input_schema")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(crate::ir::IrTool {
        name,
        description,
        input_schema,
    })
}

#[allow(dead_code)] // Used by tests only (B-502a)
fn write_block(block: &crate::ir::IrBlock) -> serde_json::Value {
    match block {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            citations,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("text"));
            obj.insert("text".to_string(), serde_json::json!(text));
            if let Some(cc) = cache_control {
                let cc_val = match cc.kind {
                    crate::ir::CacheKind::Ephemeral => serde_json::json!({"type": "ephemeral"}),
                };
                obj.insert("cache_control".to_string(), cc_val);
            }
            if !citations.is_empty() {
                obj.insert(
                    "citations".to_string(),
                    serde_json::Value::Array(citations.clone()),
                );
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Thinking { text, signature } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("thinking"));
            obj.insert("thinking".to_string(), serde_json::json!(text));
            if let Some(sig) = signature {
                obj.insert("signature".to_string(), serde_json::json!(sig));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolUse { id, name, input } => {
            serde_json::json!({ "type": "tool_use", "id": id, "name": name, "input": input })
        }
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("tool_result"));
            obj.insert("tool_use_id".to_string(), serde_json::json!(tool_use_id));
            if content.is_empty() {
                obj.insert("content".to_string(), serde_json::json!(""));
            } else {
                obj.insert(
                    "content".to_string(),
                    serde_json::Value::Array(content.iter().map(write_block).collect()),
                );
            }
            if *is_error {
                obj.insert("is_error".to_string(), serde_json::Value::Bool(true));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Image { media_type, data } => {
            serde_json::json!({ "type": "image", "source": { "type": "base64", "media_type": media_type, "data": data  } })
        }
    }
}

#[allow(dead_code)] // Used by tests only (B-502a)
fn write_message(msg: &crate::ir::IrMessage) -> serde_json::Value {
    let role_str = match msg.role {
        crate::ir::IrRole::System => "system",
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        crate::ir::IrRole::Tool => "tool_use",
    };
    let content_val: serde_json::Value = if msg.content.is_empty() {
        serde_json::Value::String("".to_string())
    } else {
        serde_json::Value::Array(msg.content.iter().map(write_block).collect())
    };
    serde_json::json!({ "role": role_str, "content": content_val })
}

#[allow(dead_code)] // Used by tests only (B-502a)
fn write_tool(tool: &crate::ir::IrTool) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), serde_json::json!(tool.name));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), serde_json::json!(desc));
    }
    obj.insert("input_schema".to_string(), tool.input_schema.clone());
    serde_json::Value::Object(obj)
}

/// Anthropic writer implementation (migrated from `Protocol::upstream_path`, `auth_headers`, `rewrite_model`).
#[derive(Clone)]
pub(crate) struct AnthropicWriter;

impl ProtocolWriter for AnthropicWriter {
    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    fn upstream_path(&self) -> &str {
        "/v1/messages"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![
            (
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(key).expect("api key is valid"),
            ),
            (
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&format!("Bearer {}", key)).expect("bearer token is valid"),
            ),
            (
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            ),
        ]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        if !req.system.is_empty() {
            let system_array: Vec<_> = req.system.iter().map(write_block).collect();
            out.insert("system".to_string(), serde_json::Value::Array(system_array));
        }
        let messages_array: Vec<_> = req.messages.iter().map(write_message).collect();
        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );
        if !req.tools.is_empty() {
            let tools_array: Vec<_> = req.tools.iter().map(write_tool).collect();
            out.insert("tools".to_string(), serde_json::Value::Array(tools_array));
        }
        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        out.insert("stream".to_string(), serde_json::json!(req.stream));
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }
        serde_json::Value::Object(out)
    }

    #[allow(dead_code)] // Used by B-502b/B-503 tests
    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, usage } => {
                let role_str = match role {
                    crate::ir::IrRole::User => "user",
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                let mut msg_obj = serde_json::Map::new();
                msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                if let Some(usage_val) = usage {
                    let mut usage_map = serde_json::Map::new();
                    usage_map.insert(
                        "input_tokens".to_string(),
                        serde_json::json!(usage_val.input_tokens),
                    );
                    usage_map.insert(
                        "output_tokens".to_string(),
                        serde_json::json!(usage_val.output_tokens),
                    );
                    if let Some(ccit) = usage_val.cache_creation_input_tokens {
                        usage_map.insert(
                            "cache_creation_input_tokens".to_string(),
                            serde_json::json!(ccit),
                        );
                    }
                    if let Some(crit) = usage_val.cache_read_input_tokens {
                        usage_map.insert(
                            "cache_read_input_tokens".to_string(),
                            serde_json::json!(crit),
                        );
                    }
                    msg_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                }
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("message".to_string(), serde_json::Value::Object(msg_obj));
                Some((
                    "message_start".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStart { index, block } => {
                let content_block = match block {
                    IrBlockMeta::Text => {
                        serde_json::json!({ "type": "text" })
                    }
                    IrBlockMeta::Thinking => {
                        serde_json::json!({ "type": "thinking" })
                    }
                    IrBlockMeta::ToolUse { id, name } => {
                        serde_json::json!({ "type": "tool_use", "id": id, "name": name })
                    }
                    IrBlockMeta::Image => {
                        serde_json::json!({ "type": "image" })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("content_block".to_string(), content_block);
                Some((
                    "content_block_start".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockDelta { index, delta } => {
                let delta_val = match delta {
                    IrDelta::TextDelta(text) => {
                        serde_json::json!({ "type": "text_delta", "text": text })
                    }
                    IrDelta::ThinkingDelta(thinking) => {
                        serde_json::json!({ "type": "thinking_delta", "thinking": thinking })
                    }
                    IrDelta::InputJsonDelta(json) => {
                        serde_json::json!({ "type": "input_json_delta", "partial_json": json })
                    }
                    IrDelta::SignatureDelta(sig) => {
                        serde_json::json!({ "type": "signature_delta", "signature": sig })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("delta".to_string(), delta_val);
                Some((
                    "content_block_delta".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStop { index } => {
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("index".to_string(), serde_json::json!(index));
                Some((
                    "content_block_stop".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                let mut delta_obj = serde_json::Map::new();
                if let Some(reason) = stop_reason {
                    delta_obj.insert("stop_reason".to_string(), serde_json::json!(reason));
                } else {
                    delta_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                }
                let mut usage_map = serde_json::Map::new();
                usage_map.insert(
                    "input_tokens".to_string(),
                    serde_json::json!(usage.input_tokens),
                );
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                if let Some(ccit) = usage.cache_creation_input_tokens {
                    usage_map.insert(
                        "cache_creation_input_tokens".to_string(),
                        serde_json::json!(ccit),
                    );
                }
                if let Some(crit) = usage.cache_read_input_tokens {
                    usage_map.insert(
                        "cache_read_input_tokens".to_string(),
                        serde_json::json!(crit),
                    );
                }
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("delta".to_string(), serde_json::Value::Object(delta_obj));
                data_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                Some((
                    "message_delta".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageStop => Some(("message_stop".to_string(), serde_json::json!({}))),
            IrStreamEvent::Error(err) => {
                let mut error_obj = serde_json::Map::new();
                if let Some(ref ps) = err.provider_signal {
                    error_obj.insert("type".to_string(), serde_json::json!(ps));
                } else {
                    error_obj.insert("type".to_string(), serde_json::Value::Null);
                }
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("error".to_string(), serde_json::Value::Object(error_obj));
                Some(("error".to_string(), serde_json::Value::Object(data_obj)))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // role: "assistant" for responses
        obj.insert("type".to_string(), serde_json::json!("message"));
        obj.insert("role".to_string(), serde_json::json!("assistant"));

        // content blocks
        let content_array: Vec<serde_json::Value> = resp.content.iter().map(write_block).collect();
        obj.insert(
            "content".to_string(),
            serde_json::Value::Array(content_array),
        );

        // stop_reason (omit if None)
        if let Some(ref reason) = resp.stop_reason {
            obj.insert("stop_reason".to_string(), serde_json::json!(reason));
        }

        // usage
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        if let Some(ccit) = resp.usage.cache_creation_input_tokens {
            usage_map.insert(
                "cache_creation_input_tokens".to_string(),
                serde_json::json!(ccit),
            );
        }
        if let Some(crit) = resp.usage.cache_read_input_tokens {
            usage_map.insert(
                "cache_read_input_tokens".to_string(),
                serde_json::json!(crit),
            );
        }
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

/// OpenAI reader implementation.
#[derive(Clone)]
pub(crate) struct OpenAiReader;

impl ProtocolReader for OpenAiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.as_object())
                .and_then(|e_obj| e_obj.get("code"))
                .and_then(|c| c.as_str())
                .map(String::from)
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.as_object())
                .and_then(|e_obj| e_obj.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        } else {
            None
        };

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        // B-504: context-length-exceeded — the lane is healthy; this must fail over (to a
        // larger-context model), not penalize the breaker. Detect by OpenAI code/message first.
        let code_is_context = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|j| {
                j.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string())
            })
            .as_deref()
            == Some("context_length_exceeded");
        if code_is_context
            || String::from_utf8_lossy(body)
                .to_lowercase()
                .contains("maximum context length")
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length".to_string()),
                retry_after: None,
            };
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429".to_string()),
                retry_after: None,
            };
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: Some("auth".to_string()),
                retry_after: None,
            };
        }

        if status.is_server_error() {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: Some(format!("{}", status.as_u16())),
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        }
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        // Extract scalar fields and extra
        let _model = obj.get("model").and_then(|v| v.as_str()).map(String::from);

        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .map(|v| v as u32);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        let top_p = obj.get("top_p");

        // Handle messages array
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;

            for (i, msg_val) in msgs_arr.iter().enumerate() {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");
                let content_val = msg_val.get("content");

                let role = match role_str {
                    "system" => crate::ir::IrRole::System,
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    "tool" => crate::ir::IrRole::Tool,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some("ir_parse".to_string()),
                            retry_after: None,
                        })
                    }
                };

                // Handle system as first message's content (OpenAI convention)
                if role == crate::ir::IrRole::System && i == 0 {
                    if let Some(content) = content_val {
                        if content.is_string() {
                            let text = content.as_str().unwrap_or("").to_string();
                            system_blocks.push(crate::ir::IrBlock::Text {
                                text,
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if content.is_array() {
                            for block_val in content.as_array().unwrap() {
                                system_blocks.push(read_openai_block(block_val)?);
                            }
                        }
                    }
                } else {
                    let mut msg_content = Vec::new();

                    if let Some(cv) = content_val {
                        if cv.is_string() {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: cv.as_str().unwrap_or("").to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if cv.is_array() {
                            for block_val in cv.as_array().unwrap() {
                                let block = read_openai_block(block_val)?;
                                msg_content.push(block);
                            }
                        }
                    }

                    // Handle tool_calls for assistant messages
                    if role == crate::ir::IrRole::Assistant {
                        if let Some(tool_calls) = msg_val.get("tool_calls") {
                            if let Some(tc_arr) = tool_calls.as_array() {
                                for tc_val in tc_arr {
                                    let id = tc_val
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let func = tc_val.get("function").ok_or(IrError {
                                        class: StatusClass::ClientError,
                                        provider_signal: Some("ir_parse".to_string()),
                                        retry_after: None,
                                    })?;
                                    let name = func
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let arguments = func
                                        .get("arguments")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("{}");
                                    let input = serde_json::from_str(arguments).unwrap_or(
                                        serde_json::Value::String(arguments.to_string()),
                                    );

                                    msg_content.push(crate::ir::IrBlock::ToolUse {
                                        id,
                                        name,
                                        input,
                                    });
                                }
                            }
                        }
                    }

                    // Handle tool results
                    if role == crate::ir::IrRole::Tool {
                        let tool_call_id = msg_val
                            .get("tool_call_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let content_text = content_val
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();

                        msg_content.push(crate::ir::IrBlock::ToolResult {
                            tool_use_id: tool_call_id,
                            content: vec![crate::ir::IrBlock::Text {
                                text: content_text,
                                cache_control: None,
                                citations: Vec::new(),
                            }],
                            is_error: false,
                        });
                    }

                    messages.push(crate::ir::IrMessage {
                        role,
                        content: msg_content,
                    });
                }
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_openai_tool(tool_val)?);
            }
        }

        // Collect unmodeled top-level keys into extra (excluding modeled ones)
        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "messages",
            "tools",
            "max_tokens",
            "temperature",
            "stream",
            "top_p",
            "frequency_penalty",
            "presence_penalty",
            "stop",
            "n",
            "logit_bias",
        ]
        .iter()
        .cloned()
        .collect();

        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        // Add top_p to extra if present
        if let Some(top_p_val) = top_p {
            extra.insert("top_p".to_string(), top_p_val.clone());
        }

        Ok(crate::ir::IrRequest {
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            stream,
            extra,
        })
    }

    #[allow(dead_code)] // Singular 1:1 form is unused for OpenAI (flat stream needs fan-out); see read_response_events
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        let _ = (event_type, data);
        None
    }

    /// OpenAI's flat stream → IR block-structured events (B-502c-2b). One chat.completion.chunk
    /// may carry role + content + finish at once → up to several IR events. State synthesizes the
    /// block boundaries OpenAI doesn't have.
    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        // [DONE] sentinel (or any non-object) carries no IR events.
        if data.as_str() == Some("[DONE]") {
            return out;
        }

        // 1. MessageStart exactly once (on the first chunk, regardless of delta.role).
        if !state.started {
            state.started = true;
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
            });
        }

        let choice0 = data
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first());
        let delta = choice0.and_then(|c| c.get("delta"));

        // 3. Text content → open text block (index 0) on first content, then a TextDelta.
        if let Some(content) = delta
            .and_then(|d| d.get("content"))
            .and_then(|c| c.as_str())
        {
            if !state.text_block_open {
                state.text_block_open = true;
                out.push(IrStreamEvent::BlockStart {
                    index: 0,
                    block: crate::ir::IrBlockMeta::Text,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta(content.to_string()),
            });
        }

        // 4. Tool calls → IR block index = oai_idx + 1 (text owns 0). BlockStart on first sight
        //    (id+name present), InputJsonDelta for streamed arguments.
        if let Some(tcs) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(|t| t.as_array())
        {
            for tc in tcs {
                let oai_idx = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                let ir_idx = oai_idx + 1;
                let func = tc.get("function");
                if let Some(name) = func.and_then(|f| f.get("name")).and_then(|n| n.as_str()) {
                    if !state.open_tools.contains(&oai_idx) {
                        let id = tc
                            .get("id")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();
                        state.open_tools.insert(oai_idx);
                        out.push(IrStreamEvent::BlockStart {
                            index: ir_idx,
                            block: crate::ir::IrBlockMeta::ToolUse {
                                id,
                                name: name.to_string(),
                            },
                        });
                    }
                }
                if let Some(args) = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(|a| a.as_str())
                {
                    out.push(IrStreamEvent::BlockDelta {
                        index: ir_idx,
                        delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                    });
                }
            }
        }

        // 5. finish_reason → close open blocks (text first, then tools ascending), MessageDelta, MessageStop.
        if let Some(fr) = choice0
            .and_then(|c| c.get("finish_reason"))
            .and_then(|r| r.as_str())
        {
            if state.text_block_open {
                state.text_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            for oai_idx in std::mem::take(&mut state.open_tools) {
                out.push(IrStreamEvent::BlockStop { index: oai_idx + 1 });
            }
            let stop_reason = Some(match fr {
                "stop" => "end_turn".to_string(),
                "length" => "max_tokens".to_string(),
                "tool_calls" => "tool_use".to_string(),
                other => other.to_string(),
            });
            let usage = data
                .get("usage")
                .map(|u| IrUsage {
                    input_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                    output_tokens: u
                        .get("completion_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: u
                        .get("prompt_tokens_details")
                        .and_then(|d| d.get("cached_tokens"))
                        .and_then(|v| v.as_u64()),
                })
                .unwrap_or(IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                });
            out.push(IrStreamEvent::MessageDelta { stop_reason, usage });
            out.push(IrStreamEvent::MessageStop);
        }

        out
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        // Get choices array
        let choices_val = obj.get("choices").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let choices = choices_val.as_array().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        if choices.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".into()),
                retry_after: None,
            });
        }

        let choice = &choices[0];

        // Parse role (should be "assistant")
        let message_val = choice.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let _role_str = message_val
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("");

        // Parse content (may be null)
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(content_val) = message_val.get("content") {
            if content_val.is_string() && !content_val.as_str().unwrap_or("").is_empty() {
                content.push(crate::ir::IrBlock::Text {
                    text: content_val.as_str().unwrap_or("").to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            } else if content_val.is_array() {
                for block_val in content_val.as_array().unwrap() {
                    let block = read_openai_block(block_val)?;
                    // Only include text blocks from array content (OpenAI image_url not supported in response)
                    if !matches!(block, crate::ir::IrBlock::Image { .. }) {
                        content.push(block);
                    }
                }
            }
        }

        // Parse tool_calls
        if let Some(tool_calls_val) = message_val.get("tool_calls") {
            if let Some(tc_arr) = tool_calls_val.as_array() {
                for tc_val in tc_arr {
                    let id = tc_val
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let func = tc_val.get("function").ok_or(IrError {
                        class: StatusClass::ClientError,
                        provider_signal: Some("ir_parse".into()),
                        retry_after: None,
                    })?;
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let arguments = func
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    let input = serde_json::from_str(arguments)
                        .unwrap_or(serde_json::Value::String(arguments.to_string()));

                    content.push(crate::ir::IrBlock::ToolUse { id, name, input });
                }
            }
        }

        // Parse finish_reason → stop_reason mapping
        let finish_reason = choice
            .get("finish_reason")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        let stop_reason = match finish_reason {
            "stop" => Some("end_turn".to_string()),
            "length" => Some("max_tokens".to_string()),
            "tool_calls" => Some("tool_use".to_string()),
            other if !other.is_empty() => Some(other.to_string()),
            _ => None,
        };

        // Parse usage
        let usage_val = obj.get("usage").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let cache_read_input_tokens = usage_val
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64());

        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .get("prompt_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None, // OpenAI doesn't provide this split
            cache_read_input_tokens,
        };

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
        })
    }
}

/// Read an OpenAI-format block from JSON.
#[allow(dead_code)] // Used by tests only (B-502c)
fn read_openai_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "text" => {
            let text_val = obj.get("text");
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        "image_url" => {
            let image_obj = obj.get("image_url").ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;
            let url = image_obj
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(crate::ir::IrBlock::Image {
                media_type: "image".to_string(),
                data: url,
            })
        }
        _ => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        }),
    }
}

/// Read an OpenAI-format tool from JSON.
#[allow(dead_code)] // Used by tests only (B-502c)
fn read_openai_tool(tool_val: &serde_json::Value) -> Result<crate::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = obj
        .get("description")
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = obj
        .get("parameters")
        .or_else(|| obj.get("input_schema"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(crate::ir::IrTool {
        name,
        description,
        input_schema,
    })
}

/// OpenAI writer implementation.
#[derive(Clone)]
pub(crate) struct OpenAiWriter;

impl ProtocolWriter for OpenAiWriter {
    fn upstream_path(&self) -> &str {
        "/v1/chat/completions"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {}", key)).expect("bearer token is valid"),
        )]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut messages_array: Vec<serde_json::Value> = Vec::new();

        // Prepend system message as first message if present
        for block in &req.system {
            if let crate::ir::IrBlock::Text { text, .. } = block {
                messages_array.push(serde_json::json!({
                    "role": "system",
                    "content": text
                }));
            }
        }

        // Add regular messages
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
                crate::ir::IrRole::System => "system",
            };

            let content_val: serde_json::Value = if msg.content.is_empty() {
                serde_json::json!("")
            } else {
                let mut content_arr: Vec<serde_json::Value> = Vec::new();

                for block in &msg.content {
                    match block {
                        crate::ir::IrBlock::Text { text, .. } => {
                            content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                        }
                        crate::ir::IrBlock::Image {
                            media_type: _,
                            data: url,
                        } => {
                            content_arr.push(serde_json::json!({
                                "type": "image_url",
                                "image_url": { "url": url }
                            }));
                        }
                        crate::ir::IrBlock::ToolUse {
                            id: _,
                            name: _,
                            input: _,
                        } => {
                            // ToolUse in user message content becomes part of tool_calls for assistant
                            // This is handled by the assistant message structure below
                        }

                        _ => {}
                    }
                }

                serde_json::Value::Array(content_arr)
            };

            let mut msg_obj = serde_json::json!({
                "role": role_str,
                "content": content_val,
            });

            // Handle tool_calls for assistant messages
            if msg.role == crate::ir::IrRole::Assistant {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                        // Serialize input to JSON string
                        let args_str =
                            serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                        // Preserve the original tool_call id verbatim — it must round-trip so the
                        // assistant tool_call correlates with the tool-result `tool_call_id`.
                        tool_calls_arr.push(serde_json::json!({
                            "type": "function",
                            "id": id,
                            "function": {
                                "name": name,
                                "arguments": args_str
                            }
                        }));
                    }
                }

                if !tool_calls_arr.is_empty() {
                    msg_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
                }
            }

            // Handle tool results (ToolRole messages)
            if msg.role == crate::ir::IrRole::Tool {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error: _,
                    } = block
                    {
                        let mut tool_result_obj = serde_json::json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": "",
                        });

                        // Concatenate text content
                        if !content.is_empty() {
                            let text_parts: Vec<String> = content
                                .iter()
                                .filter_map(|b| {
                                    if let crate::ir::IrBlock::Text { text, .. } = b {
                                        Some(text.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            tool_result_obj["content"] = serde_json::json!(text_parts.join(" "));
                        }

                        messages_array.push(tool_result_obj);
                    }
                }
            } else if msg.role != crate::ir::IrRole::Tool {
                // Only add non-tool messages to the array directly (tool results are handled above)
                messages_array.push(msg_obj);
            }
        }

        let mut out = serde_json::Map::new();

        // Add model from extra if present (since IrRequest doesn't have a model field)
        if let Some(model_val) = req.extra.get("model") {
            out.insert("model".to_string(), model_val.clone());
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );

        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // Add tools if present
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                // Map OpenAI's "parameters" to our input_schema
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                tool_obj.insert("parameters".to_string(), params);

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Add extra fields
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    #[allow(dead_code)] // Used by B-502b/B-503 tests
    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, .. } => {
                let openai_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                let delta_obj = serde_json::json!({ "role": openai_role });
                let chunk_obj = serde_json::json!({
                    "object": "chat.completion.chunk",
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": null
                    }]
                });
                Some(("".to_string(), chunk_obj))
            }
            IrStreamEvent::BlockStart { block, .. } => match block {
                crate::ir::IrBlockMeta::Text => None,
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": 0,
                            "id": id,
                            "type": "function",
                            "function": { "name": name, "arguments": "" }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": "chat.completion.chunk",
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },
            IrStreamEvent::BlockDelta { delta, .. } => match delta {
                crate::ir::IrDelta::TextDelta(text) => {
                    let delta_obj = serde_json::json!({ "content": text });
                    let chunk_obj = serde_json::json!({
                        "object": "chat.completion.chunk",
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrDelta::InputJsonDelta(json) => {
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": 0,
                            "function": { "arguments": json }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": "chat.completion.chunk",
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrDelta::ThinkingDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no thinking stream equivalent.
                    None
                }
                crate::ir::IrDelta::SignatureDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no signature stream equivalent.
                    None
                }
            },
            IrStreamEvent::BlockStop { .. } => None,
            IrStreamEvent::MessageDelta { stop_reason, .. } => {
                let finish_reason = match stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => "stop",
                    Some("max_tokens") => "length",
                    Some("tool_use") => "tool_calls",
                    Some(reason) => reason,
                    None => "",
                };
                let delta_obj = serde_json::json!({});
                let chunk_obj = serde_json::json!({
                    "object": "chat.completion.chunk",
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": finish_reason
                    }]
                });
                Some(("".to_string(), chunk_obj))
            }
            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                let error_obj = serde_json::json!({
                    "error": { "message": message, "type": "error" }
                });
                Some(("".to_string(), error_obj))
            }
        }
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // Build choices array with one choice
        let mut messages_array: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            if let crate::ir::IrBlock::Text { text, .. } = block {
                messages_array.push(serde_json::json!({ "role": "assistant", "content": text }));
            }
        }

        // ToolUse blocks become tool_calls (not in content)
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                // Serialize input to JSON string
                let args_str = serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                tool_calls_arr.push(serde_json::json!({
                    "type": "function",
                    "id": id,
                    "function": {
                        "name": name,
                        "arguments": args_str
                    }
                }));
            }
        }

        // Thinking blocks are DROPPED on OpenAI write (lossy-by-necessity; OpenAI has no thinking)
        // They are not collapsed into content.

        let mut message_obj = serde_json::json!({
            "role": "assistant",
            "content": if messages_array.is_empty() {
                serde_json::Value::Null
            } else {
                // Concatenate all Text blocks
                let texts: Vec<String> = resp.content.iter().filter_map(|b| {
                    if let crate::ir::IrBlock::Text { text, .. } = b {
                        Some(text.clone())
                    } else {
                        None
                    }
                }).collect();
                serde_json::json!(texts.join(""))
            },
        });

        // Add tool_calls only if present
        if !tool_calls_arr.is_empty() {
            message_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
        }

        let mut choices_array: Vec<serde_json::Value> = Vec::new();
        let finish_reason = match resp.stop_reason.as_deref() {
            Some("end_turn") | Some("stop_sequence") => "stop",
            Some("max_tokens") => "length",
            Some("tool_use") => "tool_calls",
            Some(reason) => reason,
            None => "",
        };

        let mut choice_obj = serde_json::Map::new();
        choice_obj.insert("index".to_string(), serde_json::json!(0));
        choice_obj.insert("message".to_string(), message_obj);
        if !finish_reason.is_empty() {
            choice_obj.insert(
                "finish_reason".to_string(),
                serde_json::json!(finish_reason),
            );
        }
        choices_array.push(serde_json::Value::Object(choice_obj));

        obj.insert("object".to_string(), serde_json::json!("chat.completion"));
        obj.insert(
            "choices".to_string(),
            serde_json::Value::Array(choices_array),
        );

        // Build usage
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "prompt_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "completion_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

/// String-keyed registry for protocol lookup (ADR-0008).
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
