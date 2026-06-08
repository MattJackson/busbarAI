// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Cohere v2 protocol reader/writer implementation.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic per-process counter mixed into a synthesized response id so two responses minted
/// within the same wall-clock second still get distinct ids. Combined with the unix-second prefix
/// this gives a collision-resistant id without pulling in a uuid/rand crate (a new dependency is
/// out of scope for this wave).
static COHERE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Format 128 bits as a UUID-shaped (8-4-4-4-12 lowercase hex) token. Real Cohere v2 chat response
/// ids are bare UUIDs (e.g. `c14c80c3-18eb-4519-9460-6c92edd8cfb4`) with NO literal prefix, so a
/// synthesized id must match that hex layout to stay shape-indistinguishable from a native one.
fn format_uuid_layout(hi: u64, lo: u64) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hi >> 32) as u32,
        ((hi >> 16) & 0xffff) as u16,
        (hi & 0xffff) as u16,
        ((lo >> 48) & 0xffff) as u16,
        lo & 0x0000_ffff_ffff_ffff,
    )
}

/// Current unix epoch seconds, saturating to 0 if the clock is somehow before the epoch (never
/// panics on the request path).
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Synthesize a Cohere-shaped response id for the cross-protocol case where the backend supplied
/// none. Native Cohere v2 ids are bare UUIDs (8-4-4-4-12 hex, no prefix), so we emit that exact
/// shape — seeded from the unix-second and the atomic counter — rather than a `cohere-<…>` token
/// that a client comparing against the documented UUID shape could use as a proxy tell. The
/// unix-second seeds the high bits and the monotonic counter the low bits, so two ids minted in the
/// same second remain distinct without pulling in a uuid/rand crate.
fn synthesize_cohere_id() -> String {
    let n = COHERE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let secs = unix_now_secs();
    // Mix the second and counter across both 64-bit halves so neither half is trivially zero and
    // the layout fills all 32 hex nibbles like a real UUID.
    let hi = (secs << 32) ^ (n.rotate_left(17));
    let lo = (n << 16) ^ secs.rotate_left(31);
    format_uuid_layout(hi, lo)
}

/// Resolve the STABLE IR block index for a Cohere stream tool call identified by its wire
/// `frame_idx`. Tool blocks follow an open text block (which occupies IR index 0), so the base
/// offset is 1 when a text block is open and 0 otherwise. The per-tool offset is the rank of
/// `frame_idx` among every tool frame seen this stream — i.e. the number of recorded frame indices
/// strictly less than it. `state.open_tools` is populated on tool-call-start and NEVER shrunk for
/// the stream's lifetime, so this rank is fixed once a tool starts: start, delta(s), and end for a
/// given tool all resolve to the same IR index even though Cohere closes each tool before opening
/// the next. (Deriving the index from a set that shrank on end was the defect this replaces — it
/// collapsed the second and later tools onto the first tool's index.)
fn cohere_tool_ir_index(state: &crate::ir::StreamDecodeState, frame_idx: usize) -> usize {
    let base = if state.text_block_open { 1 } else { 0 };
    let rank = state.open_tools.iter().filter(|&&i| i < frame_idx).count();
    base + rank
}

#[derive(Clone)]
pub(crate) struct CohereReader;

impl ProtocolReader for CohereReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body exactly once and derive both fields from the single binding — the Gemini
        // and Bedrock readers do the same, preserving the "parse once" invariant. Parsing twice
        // paid a pointless 2x CPU cost on every error response.
        let json = serde_json::from_slice::<serde_json::Value>(body).ok();
        let provider_code = json
            .as_ref()
            .and_then(|j| j.get("message"))
            .and_then(|m| m.as_str())
            .map(String::from);
        let structured_type = json
            .as_ref()
            .and_then(|j| j.get("error_type"))
            .and_then(|e| e.as_str())
            .map(String::from);

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
            retry_after_secs: None,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);
        let lower = text.to_lowercase();

        if lower.contains("too many tokens")
            || (lower.contains("maximum") && lower.contains("tokens"))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length_exceeded".to_string()),
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
        let _model = obj.get("model").and_then(|v| v.as_str()).map(String::from);

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;

            for msg_val in msgs_arr {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");
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

                // System content is canonicalized into IrRequest.system (matching the other
                // protocols), not carried as a System-role message — so it survives translation
                // to a protocol whose writer reads req.system.
                if role == crate::ir::IrRole::System {
                    if let Some(content_val) = msg_val.get("content") {
                        if let Some(s) = content_val.as_str() {
                            system_blocks.push(crate::ir::IrBlock::Text {
                                text: s.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = content_val.as_array() {
                            for block_val in arr {
                                if let Some(bo) = block_val.as_object() {
                                    if bo.get("type").and_then(|t| t.as_str()) == Some("text") {
                                        if let Some(text) = bo.get("text").and_then(|t| t.as_str())
                                        {
                                            system_blocks.push(crate::ir::IrBlock::Text {
                                                text: text.to_string(),
                                                cache_control: None,
                                                citations: Vec::new(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                let mut msg_content = Vec::new();
                if let Some(content_val) = msg_val.get("content") {
                    if content_val.is_string() {
                        msg_content.push(crate::ir::IrBlock::Text {
                            text: content_val.as_str().unwrap_or("").to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    } else if let Some(arr) = content_val.as_array() {
                        for block_val in arr {
                            if let Some(block_obj) = block_val.as_object() {
                                if block_obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(text) =
                                        block_obj.get("text").and_then(|t| t.as_str())
                                    {
                                        msg_content.push(crate::ir::IrBlock::Text {
                                            text: text.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                if role == crate::ir::IrRole::Assistant {
                    if let Some(tool_calls) = msg_val.get("tool_calls") {
                        if let Some(tc_arr) = tool_calls.as_array() {
                            for tc_val in tc_arr {
                                if let Some(func_obj) = tc_val.get("function") {
                                    let id = tc_val
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let name = func_obj
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let arguments = func_obj
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
                }

                if role == crate::ir::IrRole::Tool {
                    let tool_call_id = msg_val
                        .get("tool_call_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let content_text = if let Some(content_val) = msg_val.get("content") {
                        if let Some(arr) = content_val.as_array() {
                            // Cohere v2 tool content is an array. Bare strings are accepted, but
                            // the native (SDK-emitted) shape is an array of typed objects, e.g.
                            // `[{"type":"text","text":"..."}]` or
                            // `[{"type":"document","document":{...}}]`. Mirror the user/assistant
                            // text-block decoding above: pull `text` from `type:"text"` blocks and
                            // JSON-serialize any other typed object block (document, etc.) so its
                            // content is preserved rather than silently dropped.
                            arr.iter()
                                .filter_map(|b| {
                                    if let Some(s) = b.as_str() {
                                        Some(s.to_string())
                                    } else if let Some(bo) = b.as_object() {
                                        if bo.get("type").and_then(|t| t.as_str()) == Some("text") {
                                            bo.get("text")
                                                .and_then(|t| t.as_str())
                                                .map(String::from)
                                        } else {
                                            // Preserve non-text typed blocks (document, etc.)
                                            // verbatim rather than dropping them.
                                            serde_json::to_string(b).ok()
                                        }
                                    } else {
                                        // Non-string, non-object array element: serialize it so no
                                        // content is lost.
                                        serde_json::to_string(b).ok()
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(" ")
                        } else if let Some(s) = content_val.as_str() {
                            s.to_string()
                        } else {
                            serde_json::to_string(content_val).unwrap_or_default()
                        }
                    } else {
                        String::new()
                    };
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
        } else {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_arr) = obj.get("tools").and_then(|v| v.as_array()) {
            for tool_val in tools_arr {
                if let Some(func_obj) = tool_val.get("function") {
                    let name = func_obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let description = func_obj
                        .get("description")
                        .and_then(|v| v.as_str().map(String::from));
                    let input_schema = func_obj
                        .get("parameters")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    tools.push(crate::ir::IrTool {
                        name,
                        description,
                        input_schema,
                    });
                }
            }
        }

        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .map(|v| v as u32);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
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

    fn read_response_event(
        &self,
        _event_type: &str,
        _data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        None
    }

    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();
        if data.as_str() == Some("[DONE]") || !data.is_object() {
            return out;
        }

        let event_type_val = data.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type_val {
            "message-start" => {
                if !state.started {
                    state.started = true;
                    // Cohere v2 streams carry the response `id` on the top-level message-start
                    // frame. Capture it for same-protocol stream passthrough; synthesize a
                    // shape-valid id when the upstream omitted it. Cohere has no stream `created`.
                    let id = data
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or_else(|| Some(synthesize_cohere_id()));
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created: None,
                        model: None,
                    });
                }
            }
            "content-start" => {
                let idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                if !state.text_block_open {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
            }
            "content-delta" => {
                let idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                if !state.text_block_open {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }

                if let Some(delta_obj) = data.get("delta") {
                    if let Some(content_obj) =
                        delta_obj.get("message").and_then(|m| m.get("content"))
                    {
                        if let Some(text) = content_obj.as_str() {
                            if !text.is_empty() {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                });
                            }
                        } else if let Some(content_arr) = content_obj.as_array() {
                            for block_val in content_arr {
                                if let Some(block_obj) = block_val.as_object() {
                                    if block_obj.get("type").and_then(|t| t.as_str())
                                        == Some("text")
                                    {
                                        if let Some(text) =
                                            block_obj.get("text").and_then(|t| t.as_str())
                                        {
                                            out.push(IrStreamEvent::BlockDelta {
                                                index: idx,
                                                delta: crate::ir::IrDelta::TextDelta(
                                                    text.to_string(),
                                                ),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "content-end" => {
                let idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                out.push(IrStreamEvent::BlockStop { index: idx });
                state.text_block_open = false;
            }
            "message-end" => {
                let raw_finish_reason = data
                    .get("delta")
                    .and_then(|d| d.get("finish_reason"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let stop_reason = match raw_finish_reason {
                    "COMPLETE" => Some("end_turn".to_string()),
                    "MAX_TOKENS" => Some("max_tokens".to_string()),
                    "TOOL_CALL" => Some("tool_use".to_string()),
                    "STOP_SEQUENCE" => Some("stop_sequence".to_string()),
                    "ERROR" | "ERROR_TOXIC" => Some("safety".to_string()),
                    other if !other.is_empty() => Some(other.to_lowercase()),
                    _ => None,
                };

                let usage = data
                    .get("delta")
                    .and_then(|d| d.get("usage"))
                    .map(|u| {
                        let tokens_map: serde_json::Map<String, serde_json::Value> = u
                            .get("tokens")
                            .and_then(|t| t.as_object())
                            .cloned()
                            .unwrap_or_default();
                        crate::ir::IrUsage {
                            input_tokens: tokens_map
                                .get("input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            output_tokens: tokens_map
                                .get("output_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        }
                    })
                    .unwrap_or(crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    });

                out.push(IrStreamEvent::MessageDelta {
                    stop_reason,
                    // Cohere has no stop_sequence analog in its stream.
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
            }
            // Cohere v2 streams a tool call as a tool-call-start / tool-call-delta(s) /
            // tool-call-end sequence carrying the call under `delta.message.tool_calls`. Map them
            // onto the IR block lifecycle (BlockStart{ToolUse} / BlockDelta{InputJsonDelta} /
            // BlockStop) exactly as the OpenAI and Gemini readers do, so streaming tool use is not
            // silently discarded. Tool blocks occupy IR indices after any open text block.
            //
            // IR-index assignment must be STABLE for a tool's whole lifetime. Cohere v2 closes each
            // tool (tool-call-end) BEFORE opening the next (tool-call-start), so a scheme that
            // derived the IR index from the LIVE rank of `frame_idx` in a set that shrinks on end
            // collapsed the second and later tools onto the first tool's index. Instead we record
            // each frame_idx in `state.open_tools` on start and NEVER remove it, then derive the IR
            // index from the rank of `frame_idx` among all frames ever seen (the count of recorded
            // frame indices strictly less than it). Because Cohere assigns frame indices in
            // increasing order, that rank is fixed once assigned regardless of earlier tools closing
            // — so start/delta/end for a given tool all resolve to the same IR block index.
            "tool-call-start" => {
                let frame_idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                let tc = data
                    .get("delta")
                    .and_then(|d| d.get("message"))
                    .and_then(|m| m.get("tool_calls"));
                let id = tc
                    .and_then(|t| t.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = tc
                    .and_then(|t| t.get("function"))
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                state.open_tools.insert(frame_idx);
                let ir_idx = cohere_tool_ir_index(state, frame_idx);
                out.push(IrStreamEvent::BlockStart {
                    index: ir_idx,
                    block: crate::ir::IrBlockMeta::ToolUse { id, name },
                });
                // Cohere may include initial argument text on the start frame.
                if let Some(args) = tc
                    .and_then(|t| t.get("function"))
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    out.push(IrStreamEvent::BlockDelta {
                        index: ir_idx,
                        delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                    });
                }
            }
            "tool-call-delta" => {
                let frame_idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                // Resolve to the IR index assigned at start time. The mapping is stable because
                // `open_tools` is never shrunk for the lifetime of the stream (see tool-call-start).
                let ir_idx = cohere_tool_ir_index(state, frame_idx);
                if let Some(args) = data
                    .get("delta")
                    .and_then(|d| d.get("message"))
                    .and_then(|m| m.get("tool_calls"))
                    .and_then(|t| t.get("function"))
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    out.push(IrStreamEvent::BlockDelta {
                        index: ir_idx,
                        delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                    });
                }
            }
            "tool-call-end" => {
                let frame_idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                // Only close a tool we actually opened; resolve its stable IR index. We do NOT
                // remove the frame_idx from `open_tools` — removing it would shift the rank of every
                // later tool and collapse them onto reused indices (the defect this fix addresses).
                if state.open_tools.contains(&frame_idx) {
                    let ir_idx = cohere_tool_ir_index(state, frame_idx);
                    out.push(IrStreamEvent::BlockStop { index: ir_idx });
                }
            }
            // Genuinely unknown event types are intentionally ignored: the Cohere v2 stream may add
            // frames (e.g. citation/debug) that carry no IR-representable content. This is a named,
            // documented no-op arm — not a blanket `_ =>` that would also swallow tool-call frames.
            other => {
                debug_assert!(
                    !other.is_empty(),
                    "unexpected empty Cohere stream event type"
                );
            }
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
        let message_val = obj.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(content_arr) = message_val.get("content").and_then(|c| c.as_array()) {
            for block_val in content_arr {
                if let Some(block_obj) = block_val.as_object() {
                    if block_obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                        if let Some(text) = block_obj.get("text").and_then(|t| t.as_str()) {
                            content.push(crate::ir::IrBlock::Text {
                                text: text.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        if let Some(tool_calls_arr) = message_val.get("tool_calls").and_then(|t| t.as_array()) {
            for tc_val in tool_calls_arr {
                if let Some(func_obj) = tc_val.get("function") {
                    let id = tc_val
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = func_obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let arguments = func_obj
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    let input = serde_json::from_str(arguments)
                        .unwrap_or(serde_json::Value::String(arguments.to_string()));
                    content.push(crate::ir::IrBlock::ToolUse { id, name, input });
                }
            }
        }

        let raw_finish_reason = obj
            .get("finish_reason")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        let stop_reason = match raw_finish_reason {
            "COMPLETE" => Some("end_turn".to_string()),
            "MAX_TOKENS" => Some("max_tokens".to_string()),
            "TOOL_CALL" => Some("tool_use".to_string()),
            "STOP_SEQUENCE" => Some("stop_sequence".to_string()),
            "ERROR" | "ERROR_TOXIC" => Some("safety".to_string()),
            other if !other.is_empty() => Some(other.to_lowercase()),
            _ => None,
        };

        let usage_val = obj.get("usage").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let tokens_val = usage_val.get("tokens");
        let usage = crate::ir::IrUsage {
            input_tokens: tokens_val
                .and_then(|t| t.as_object())
                .and_then(|t_obj| t_obj.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: tokens_val
                .and_then(|t| t.as_object())
                .and_then(|t_obj| t_obj.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response identity so same-protocol (Cohere → Cohere) passthrough
        // preserves it exactly. Cohere v2 chat responses carry an opaque UUID-like `id`; if the
        // upstream omitted it, synthesize a shape-valid one rather than carrying `None` (so a
        // native SDK reading `.id` always sees a string). Cohere v2 has no `created`,
        // `system_fingerprint`, or `stop_sequence` field — those stay `None`.
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| Some(synthesize_cohere_id()));

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CohereWriter;

impl ProtocolWriter for CohereWriter {
    fn upstream_path(&self) -> &str {
        "/v2/chat"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {key}"))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        )]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let mut messages_arr: Vec<serde_json::Value> = Vec::new();

        // Cohere v2 carries the system prompt as a leading system-role message.
        let system_text: String = req
            .system
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::Text { text, .. } = b {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !system_text.is_empty() {
            messages_arr.push(serde_json::json!({ "role": "system", "content": system_text }));
        }

        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::System => "system",
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
            };

            // Build content from the text blocks actually present. A single text block is sent as
            // a bare string (Cohere's preferred shape); multiple text blocks become a text-part
            // array. A message whose only block(s) are non-Text (e.g. a sole ToolUse, surfaced
            // separately via `tool_calls`) must NOT emit `content: []` — Cohere may reject that —
            // so we omit the `content` key entirely in that case.
            let text_blocks: Vec<&String> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Text { text, .. } = b {
                        Some(text)
                    } else {
                        None
                    }
                })
                .collect();

            let content_val: Option<serde_json::Value> = match text_blocks.as_slice() {
                [] => None,
                [single] => Some(serde_json::Value::String((*single).clone())),
                many => Some(serde_json::Value::Array(
                    many.iter()
                        .map(|text| serde_json::json!({ "type": "text", "text": text }))
                        .collect(),
                )),
            };

            if msg.role == crate::ir::IrRole::Tool {
                // Tool-role messages emit one Cohere tool message per ToolResult block. Any plain
                // text carried alongside the tool results (and the degenerate case of a Tool turn
                // with NO ToolResult block at all) must NOT be silently dropped: fold that text in
                // — onto the first tool message if there is one, otherwise as a standalone tool
                // message — so the turn is never lossy.
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error: _,
                    } = block
                    {
                        let mut tool_result_obj = serde_json::Map::new();
                        tool_result_obj.insert("role".to_string(), serde_json::json!("tool"));
                        tool_result_obj.insert(
                            "tool_call_id".to_string(),
                            serde_json::Value::String(tool_use_id.clone()),
                        );
                        let mut text_parts: Vec<String> = content
                            .iter()
                            .filter_map(|b| {
                                if let crate::ir::IrBlock::Text { text, .. } = b {
                                    Some(text.clone())
                                } else {
                                    None
                                }
                            })
                            .collect();
                        // Prepend any message-level text onto the first tool result so it survives.
                        if !emitted_tool_result {
                            for t in text_blocks.iter().rev() {
                                text_parts.insert(0, (*t).clone());
                            }
                        }
                        tool_result_obj.insert(
                            "content".to_string(),
                            serde_json::Value::String(text_parts.join(" ")),
                        );
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                        emitted_tool_result = true;
                    }
                }
                // Degenerate Tool turn with text but no ToolResult: emit the text as a tool message
                // rather than dropping it entirely.
                if !emitted_tool_result {
                    if let Some(content_val) = content_val {
                        let mut tool_obj = serde_json::Map::new();
                        tool_obj.insert("role".to_string(), serde_json::json!("tool"));
                        tool_obj.insert("content".to_string(), content_val);
                        messages_arr.push(serde_json::Value::Object(tool_obj));
                    }
                }
                continue;
            }

            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            if let Some(content_val) = content_val {
                msg_obj.insert("content".to_string(), content_val);
            }

            if msg.role == crate::ir::IrRole::Assistant {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                        let args_str =
                            serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                        tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                    }
                }
                if !tool_calls_arr.is_empty() {
                    msg_obj.insert(
                        "tool_calls".to_string(),
                        serde_json::Value::Array(tool_calls_arr),
                    );
                }
            }

            messages_arr.push(serde_json::Value::Object(msg_obj));
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_arr),
        );

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut func_obj = serde_json::Map::new();
                func_obj.insert("name".to_string(), serde_json::json!(tool.name));
                if let Some(desc) = &tool.description {
                    func_obj.insert("description".to_string(), serde_json::json!(desc));
                }
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                func_obj.insert("parameters".to_string(), params);
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("function".to_string(), serde_json::Value::Object(func_obj));
                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Only emit `stream` when streaming is requested. A native Cohere client omitting `stream`
        // (relying on the `false` default) produces a body WITHOUT the field; always injecting
        // `"stream": false` is a proxy tell and a same-protocol passthrough fidelity break (the
        // reader treats `stream` as a modeled key, so it is never echoed via `extra`). The Gemini
        // writer likewise never emits `stream` in the body.
        if req.stream {
            out.insert("stream".to_string(), serde_json::json!(true));
        }
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, id, .. } => {
                let cohere_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::System
                    | crate::ir::IrRole::User
                    | crate::ir::IrRole::Tool => return None,
                };
                // Cohere v2 streams carry the response `id` on the message-start frame. Preserve a
                // captured id; synthesize a shape-valid one for the cross-protocol case so the
                // emitted stream is indistinguishable from a native Cohere stream.
                let id = id.clone().unwrap_or_else(synthesize_cohere_id);
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "id": id,
                        "type": "message-start",
                        "delta": { "message": { "role": cohere_role } }
                    }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "content-start",
                        "index": index,
                        "delta": {
                            "message": {
                                "content": { "type": "text", "text": "" }
                            }
                        }
                    }),
                )),
                // Cross-protocol streaming tool use (e.g. Anthropic/Gemini → Cohere-ingress) must
                // surface a native `tool-call-start` frame mirroring the shape this file's own
                // reader consumes (delta.message.tool_calls.{id,type,function.{name,arguments}}).
                // Omitting it made streamed tool calls invisible to a Cohere client. The reader
                // expects `function.arguments` to be a (possibly empty) string and accumulates
                // tool-call-delta argument fragments onto it, so we open with an empty string.
                crate::ir::IrBlockMeta::ToolUse { id, name } => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "tool-call-start",
                        "index": index,
                        "delta": {
                            "message": {
                                "tool_calls": {
                                    "id": id,
                                    "type": "function",
                                    "function": { "name": name, "arguments": "" }
                                }
                            }
                        }
                    }),
                )),
                // Cohere v2 has no streamed thinking/image block shape. Emitting a fabricated frame
                // would be a non-native proxy tell, so these IR block kinds carry no opening frame.
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    // Native Cohere v2 content-delta frames carry the text at
                    // delta.message.content.text (an object), matching the content-start shape and
                    // this reader's object path. A bare string here is non-native and a client that
                    // reads content.text would accumulate nothing.
                    serde_json::json!({
                        "type": "content-delta",
                        "index": index,
                        "delta": { "message": { "content": { "type": "text", "text": text } } }
                    }),
                )),
                // Streamed tool-call argument fragments map to a native `tool-call-delta` frame
                // carrying the argument chunk at delta.message.tool_calls.function.arguments — the
                // exact path this file's reader reads. Without this arm, cross-protocol tool-call
                // arguments never reached a Cohere-ingress client.
                crate::ir::IrDelta::InputJsonDelta(args) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "tool-call-delta",
                        "index": index,
                        "delta": {
                            "message": {
                                "tool_calls": { "function": { "arguments": args } }
                            }
                        }
                    }),
                )),
                // Cohere v2 streams carry no thinking/signature delta shape; suppress rather than
                // emit a non-native frame.
                crate::ir::IrDelta::ThinkingDelta(_) => None,
                crate::ir::IrDelta::SignatureDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => Some((
                "".to_string(),
                serde_json::json!({ "type": "content-end", "index": index }),
            )),

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let cohere_finish_reason = match stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => "COMPLETE".to_string(),
                    Some("max_tokens") => "MAX_TOKENS".to_string(),
                    Some("tool_use") => "TOOL_CALL".to_string(),
                    Some("safety") => "ERROR".to_string(),
                    Some(reason) => reason.to_uppercase(),
                    None => "COMPLETE".to_string(),
                };
                // Native Cohere v2 message-end frames carry token usage inside
                // delta.usage.tokens.{input_tokens,output_tokens}. Surface it so a Cohere SDK
                // client tracking billing/rate-limit data from the stream is not silently zeroed.
                // IrUsage is always present (not Option); when upstream supplied nothing it is
                // zero-valued, which serializes here as a safe `{input_tokens:0,output_tokens:0}`.
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "message-end",
                        "delta": {
                            "finish_reason": cohere_finish_reason,
                            "usage": {
                                "tokens": {
                                    "input_tokens": usage.input_tokens,
                                    "output_tokens": usage.output_tokens
                                }
                            }
                        }
                    }),
                ))
            }

            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "".to_string(),
                    serde_json::json!({ "type": "error", "message": message }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let mut content_arr: Vec<serde_json::Value> = Vec::new();
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                }
                crate::ir::IrBlock::ToolUse { id, name, input } => {
                    let args_str =
                        serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    // Accumulate every tool call. Inserting per-iteration would overwrite the
                    // key and silently drop all but the last call on parallel tool use.
                    tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                crate::ir::IrBlock::Image { .. } | crate::ir::IrBlock::ToolResult { .. } => {}
            }
        }

        let cohere_finish_reason = match resp.stop_reason.as_deref() {
            Some("end_turn") | Some("stop_sequence") => "COMPLETE".to_string(),
            Some("max_tokens") => "MAX_TOKENS".to_string(),
            Some("tool_use") => "TOOL_CALL".to_string(),
            Some("safety") => "ERROR".to_string(),
            Some(reason) => reason.to_uppercase(),
            None => "COMPLETE".to_string(),
        };

        // Cohere format: usage.tokens.input_tokens, usage.tokens.output_tokens
        let mut tokens_map = serde_json::Map::new();
        tokens_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        tokens_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        // Emit the response identity. Same-protocol passthrough preserves the captured upstream
        // `id` exactly; the cross-protocol case (a non-Cohere backend that never supplied one)
        // hits `None` and we synthesize a shape-valid Cohere id so a native SDK always reads a
        // non-empty `.id` string.
        let id = resp.id.clone().unwrap_or_else(synthesize_cohere_id);
        out.insert("id".to_string(), serde_json::Value::String(id));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out.insert("model".to_string(), serde_json::json!(model));
        }
        out.insert(
            "finish_reason".to_string(),
            serde_json::json!(cohere_finish_reason),
        );
        // Native Cohere v2 carries tool calls INSIDE the message object (response.message
        // .tool_calls) — exactly where this file's own read_response reads them from. Nesting them
        // here (rather than at the top level) keeps the body native for a real Cohere SDK and lets
        // a Cohere -> Cohere passthrough round-trip every parallel tool call.
        let mut message_obj = serde_json::Map::new();
        message_obj.insert("role".to_string(), serde_json::json!("assistant"));
        message_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
        if !tool_calls_arr.is_empty() {
            message_obj.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls_arr),
            );
        }
        out.insert(
            "message".to_string(),
            serde_json::Value::Object(message_obj),
        );
        // Wrap tokens under "tokens" key per Cohere API spec
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("tokens".to_string(), serde_json::Value::Object(tokens_map));
        out.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(out)
    }

    /// NATIVE Cohere v2 error envelope. The Cohere v2 chat API conveys the error *category* via the
    /// HTTP status (400/401/404/429/5xx) and carries only a human-readable `{"message": <detail>}`
    /// body — it has no typed `error.type`/`code` field the way OpenAI/Anthropic do. So the generic
    /// `kind` is intentionally NOT surfaced in the body (it would be a field a native SDK never
    /// sees); it is dropped here and conveyed solely by the caller's HTTP status. Real Cohere v2
    /// error bodies are a bare `{"message": "..."}` and do NOT carry a synthesized id; this reader's
    /// own `extract_error` reads only `message`/`error_type` and never `id`, so emitting an `id`
    /// here was both a proxy tell and internally inconsistent with the reader. Served as
    /// `application/json` per the trait contract.
    ///
    /// This is a LIVE production code path, not test-only scaffolding: it is reached at runtime via
    /// the `ProtocolWriter` trait object on every Cohere-ingress error response (e.g. route.rs,
    /// forward.rs, and auth.rs all dispatch `p.writer().write_error(...)`). It carries no
    /// `allow(dead_code)` suppression — matching every other protocol writer — because the
    /// dead-code lint never fires on vtable-dispatched trait method implementations.
    fn write_error(&self, _status: u16, _kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "message": message,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "hi".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "t1".to_string(),
                        name: "f".to_string(),
                        input: serde_json::json!({"x": 1}),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "result text".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "f".to_string(),
                description: Some("..".to_string()),
                input_schema: serde_json::json!({}),
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7),
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let json = writer.write_request(&ir);

        assert!(json.get("messages").is_some());
        let msgs = json.get("messages").unwrap().as_array().unwrap();
        // system prompt (from IrRequest.system) is prepended as a leading system message
        assert_eq!(msgs[0].get("role"), Some(&serde_json::json!("system")));
        assert_eq!(
            msgs[0].get("content"),
            Some(&serde_json::json!("You are helpful."))
        );
        assert_eq!(msgs[1].get("role"), Some(&serde_json::json!("user")));
        assert_eq!(msgs[2].get("role"), Some(&serde_json::json!("assistant")));

        let tool_calls = msgs[2].get("tool_calls").unwrap().as_array().unwrap();
        assert_eq!(
            tool_calls[0]
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str()),
            Some("f")
        );

        let tools_arr = json.get("tools").unwrap().as_array().unwrap();
        assert_eq!(
            tools_arr[0]
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str()),
            Some("f")
        );

        assert_eq!(json.get("max_tokens"), Some(&serde_json::json!(1024)));
        assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
    }

    #[test]
    fn test_read_request_roundtrip() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "user msg".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "assistant msg".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: vec![],
            max_tokens: Some(512),
            temperature: Some(0.7),
            stream: true,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let reader = CohereReader;
        let json = writer.write_request(&ir);
        let ir2 = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir, ir2);
    }

    #[test]
    fn test_read_response() {
        let json = serde_json::json!({
            "id": "msg_123",
            "finish_reason": "TOOL_CALL",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "tool_use", "id": "t1", "name": "get_weather", "input": {"location": "SF"}}
                ]
            },
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        });

        let reader = CohereReader;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.stop_reason, Some("tool_use".to_string()));
        assert_eq!(resp.usage.input_tokens, 10);
        // The upstream `id` is captured verbatim into the IR (same-protocol identity fidelity).
        assert_eq!(resp.id.as_deref(), Some("msg_123"));
    }

    #[test]
    fn test_write_response_roundtrip() {
        // Carries a real upstream id; same-protocol read→write must preserve it byte-identically.
        let json = serde_json::json!({
            "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
            "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        });

        let reader = CohereReader;
        let writer = CohereWriter;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");
        let json2 = writer.write_response(&resp);

        assert_eq!(json, json2);
    }

    #[test]
    fn test_stream_fanout() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // message-start
        let evs = reader.read_response_events("", &serde_json::json!({"type": "message-start", "delta": {"message": {"role": "assistant"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::MessageStart { .. }
        ));

        // content-start
        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}), &mut state);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ));

        // content-delta x2
        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": "he"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        if let crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(ref t),
        } = &evs[0]
        {
            assert_eq!(t, "he");
        }

        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": "llo"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        if let crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(ref t),
        } = &evs[0]
        {
            assert_eq!(t, "llo");
        }

        // content-end
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-end", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));

        // message-end with usage
        let evs = reader.read_response_events("", &serde_json::json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE", "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}}}), &mut state);
        assert_eq!(evs.len(), 2);
        if let crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(ref s),
            ref usage,
            ..
        } = &evs[0]
        {
            assert_eq!(s, "end_turn");
            assert_eq!(usage.input_tokens, 10);
        }
        assert!(matches!(evs[1], crate::ir::IrStreamEvent::MessageStop));
    }

    #[test]
    fn test_cross_protocol_system_prompt_preserved_to_cohere() {
        // An Anthropic request carries its system prompt in the top-level `system` field, which
        // the reader canonicalizes into IrRequest.system. Cohere's writer must re-emit it as a
        // leading system-role message — otherwise the system prompt is silently dropped when
        // translating Anthropic → Cohere.
        let anthropic_body = serde_json::json!({
            "model": "x",
            "system": "You are terse.",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 10
        });
        let ir = AnthropicReader
            .read_request(&anthropic_body)
            .expect("anthropic read_request");
        assert!(
            !ir.system.is_empty(),
            "anthropic system must land in IrRequest.system"
        );
        let cohere = CohereWriter.write_request(&ir);
        let msgs = cohere.get("messages").unwrap().as_array().unwrap();
        assert_eq!(
            msgs[0].get("role").and_then(|r| r.as_str()),
            Some("system"),
            "Cohere must emit the system prompt as a leading system message"
        );
        assert_eq!(
            msgs[0].get("content").and_then(|c| c.as_str()),
            Some("You are terse.")
        );
        assert_eq!(msgs[1].get("role").and_then(|r| r.as_str()), Some("user"));
    }

    #[test]
    fn test_write_response_event() {
        let writer = CohereWriter;

        // BlockDelta TextDelta("hi") → content-delta frame
        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, data) = result.unwrap();
        assert_eq!(
            data.get("type").and_then(|t| t.as_str()),
            Some("content-delta")
        );
        // content-delta carries the text at delta.message.content.text (an object), matching the
        // native Cohere v2 stream and the content-start shape.
        assert_eq!(
            data.get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str()),
            Some("hi")
        );
        assert_eq!(
            data.get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.get("type"))
                .and_then(|t| t.as_str()),
            Some("text")
        );
    }

    /// Regression: a response carrying several parallel `ToolUse` blocks must surface ALL of them
    /// in `tool_calls`. The previous per-iteration `out.insert(...)` overwrote the key and silently
    /// dropped every call but the last.
    #[test]
    fn test_write_response_preserves_parallel_tool_calls() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t2".to_string(),
                    name: "get_time".to_string(),
                    input: serde_json::json!({"tz": "PST"}),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t3".to_string(),
                    name: "get_news".to_string(),
                    input: serde_json::json!({}),
                },
            ],
            stop_reason: Some("tool_use".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 2,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let json = CohereWriter.write_response(&resp);
        // tool_calls are nested under the `message` object (native Cohere v2 shape).
        let tool_calls = json
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|v| v.as_array())
            .expect("tool_calls array must be present under message");
        assert_eq!(tool_calls.len(), 3, "all parallel tool calls must survive");
        let ids: Vec<&str> = tool_calls
            .iter()
            .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, ["t1", "t2", "t3"]);
    }

    /// Regression: an assistant message whose only block is a `ToolUse` (surfaced via `tool_calls`)
    /// must NOT emit `content: []`. The `content` key should be omitted entirely.
    #[test]
    fn test_write_request_sole_tooluse_omits_empty_content() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "f".to_string(),
                    input: serde_json::json!({"x": 1}),
                }],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let json = CohereWriter.write_request(&ir);
        let msgs = json.get("messages").unwrap().as_array().unwrap();
        let assistant = &msgs[0];
        assert!(
            assistant.get("content").is_none(),
            "sole-ToolUse message must omit content rather than emit []"
        );
        assert!(
            assistant.get("tool_calls").is_some(),
            "the tool call must still be present"
        );
    }

    /// Multiple text blocks in one message must serialize as a text-part array (not be collapsed),
    /// while a single text block stays a bare string.
    #[test]
    fn test_write_request_text_block_shapes() {
        let single = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let j = CohereWriter.write_request(&single);
        assert_eq!(
            j.get("messages").unwrap().as_array().unwrap()[0].get("content"),
            Some(&serde_json::json!("hi"))
        );

        let multi = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "a".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Text {
                        text: "b".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                ],
            }],
            ..single
        };
        let j = CohereWriter.write_request(&multi);
        let content = j.get("messages").unwrap().as_array().unwrap()[0]
            .get("content")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("a"));
        assert_eq!(content[1].get("text").and_then(|t| t.as_str()), Some("b"));
    }

    /// `read_request` must not allocate a temporary empty Vec when `tools` is absent, and must
    /// produce no tools either way.
    #[test]
    fn test_read_request_missing_tools() {
        let json = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = CohereReader
            .read_request(&json)
            .expect("read_request should succeed");
        assert!(ir.tools.is_empty());
    }

    /// The NATIVE Cohere v2 error envelope is a bare `{"message": <detail>}` — NOT the generic
    /// `{"error":{"message","type"}}`, and NOT carrying a synthesized `id`. The generic `kind` must
    /// NOT leak into the body (a native SDK never reads a typed error category from a Cohere body;
    /// it reads `message`), and no `id` field must be emitted (real Cohere error bodies carry none,
    /// and this reader's `extract_error` never reads `id`).
    #[test]
    fn test_write_error_native_cohere_envelope() {
        let writer = CohereWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");

        // Serializes (no panic) and re-parses as valid JSON.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

        assert_eq!(
            reparsed.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found"),
            "native Cohere error carries the detail under top-level `message`"
        );
        assert!(
            reparsed.get("error").is_none(),
            "must NOT use the generic `error` wrapper"
        );
        assert!(
            reparsed.get("type").is_none() && reparsed.get("code").is_none(),
            "Cohere conveys the error category via HTTP status, not a typed body field"
        );
        assert!(
            reparsed.get("id").is_none(),
            "real Cohere error bodies carry no synthesized id"
        );
        // The body must be exactly the single `message` key.
        assert_eq!(
            reparsed.as_object().map(|o| o.len()),
            Some(1),
            "native Cohere error body is a bare {{\"message\": ...}}"
        );
    }

    /// Same-protocol (Cohere → Cohere) passthrough must preserve the upstream response `id` exactly
    /// — capturing it on read and re-emitting the identical value on write.
    #[test]
    fn test_same_protocol_roundtrip_preserves_id() {
        let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
        let json = serde_json::json!({
            "id": upstream_id,
            "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": {"tokens": {"input_tokens": 3, "output_tokens": 1}}
        });

        let resp = CohereReader
            .read_response(&json)
            .expect("read_response should succeed");
        assert_eq!(
            resp.id.as_deref(),
            Some(upstream_id),
            "upstream id captured verbatim into the IR"
        );

        let out = CohereWriter.write_response(&resp);
        assert_eq!(
            out.get("id").and_then(|i| i.as_str()),
            Some(upstream_id),
            "the same id must be re-emitted on write (same-protocol fidelity)"
        );
    }

    /// Same-protocol stream passthrough preserves the message-start `id`.
    #[test]
    fn test_same_protocol_stream_roundtrip_preserves_id() {
        let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events(
            "",
            &serde_json::json!({
                "id": upstream_id,
                "type": "message-start",
                "delta": {"message": {"role": "assistant"}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        let captured = match &evs[0] {
            crate::ir::IrStreamEvent::MessageStart { id, .. } => id.clone(),
            other => panic!("expected MessageStart, got {other:?}"),
        };
        assert_eq!(captured.as_deref(), Some(upstream_id));

        let (_, frame) = CohereWriter
            .write_response_event(&evs[0])
            .expect("message-start must serialize");
        assert_eq!(
            frame.get("id").and_then(|i| i.as_str()),
            Some(upstream_id),
            "stream message-start id must round-trip verbatim"
        );
    }

    /// Cross-protocol write (the backend supplied NO id — `IrResponse.id == None`) must SYNTHESIZE a
    /// valid, non-empty Cohere id without panicking, so a native Cohere SDK still reads a string.
    #[test]
    fn test_cross_protocol_write_synthesizes_valid_id() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hello".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let out = CohereWriter.write_response(&resp);
        let id = out
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id must be present as a string");
        assert!(!id.is_empty(), "synthesized id must be non-empty");
        assert!(
            is_uuid_shaped(id),
            "synthesized id must be a bare UUID (no `cohere-` prefix), got {id}"
        );
    }

    /// Test helper: validate the 8-4-4-4-12 lowercase-hex UUID layout that native Cohere ids use.
    fn is_uuid_shaped(s: &str) -> bool {
        let groups: Vec<&str> = s.split('-').collect();
        let expected_lens = [8usize, 4, 4, 4, 12];
        groups.len() == 5
            && groups
                .iter()
                .zip(expected_lens.iter())
                .all(|(g, &len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// Regression (MEDIUM/conformance): the synthesized id must be a bare UUID (8-4-4-4-12 hex),
    /// indistinguishable from a native Cohere id — NOT a `cohere-<secs>-<counter>` token, which a
    /// client comparing against the documented UUID shape could use as a proxy tell.
    #[test]
    fn test_synthesized_id_is_uuid_shaped() {
        let id = synthesize_cohere_id();
        assert!(
            is_uuid_shaped(&id),
            "synthesized id must match the UUID layout, got {id}"
        );
        assert!(
            !id.starts_with("cohere-"),
            "synthesized id must NOT carry a literal prefix, got {id}"
        );
    }

    /// Two successive synthesized ids within the same process must be distinct (the atomic counter
    /// guarantees uniqueness even inside one wall-clock second).
    #[test]
    fn test_synthesized_ids_are_unique() {
        let a = synthesize_cohere_id();
        let b = synthesize_cohere_id();
        assert_ne!(a, b, "the atomic counter must make synthesized ids unique");
    }

    /// Regression (HIGH/conformance): `write_response` must nest `tool_calls` INSIDE the `message`
    /// object (native Cohere v2 shape, `response.message.tool_calls`) — not at the top level. The
    /// emitted body must round-trip through this protocol's OWN `read_response`, which reads tool
    /// calls from `message.tool_calls`, so a Cohere -> Cohere passthrough keeps every parallel call.
    #[test]
    fn test_write_response_tool_calls_nested_and_roundtrip() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "calling tools".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t2".to_string(),
                    name: "get_time".to_string(),
                    input: serde_json::json!({"tz": "PST"}),
                },
            ],
            stop_reason: Some("tool_use".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 4,
                output_tokens: 6,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("resp-1".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let body = CohereWriter.write_response(&resp);

        // tool_calls live under message, NOT at the top level.
        assert!(
            body.get("tool_calls").is_none(),
            "tool_calls must NOT be at the top level"
        );
        let nested = body
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
            .expect("tool_calls must be nested under message");
        assert_eq!(nested.len(), 2, "both parallel tool calls survive");

        // Round-trips through this protocol's own reader: every tool call comes back.
        let back = CohereReader
            .read_response(&body)
            .expect("read_response of self-written body");
        let tool_uses: Vec<(&str, &str)> = back
            .content
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::ToolUse { id, name, .. } = b {
                    Some((id.as_str(), name.as_str()))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            tool_uses,
            [("t1", "get_weather"), ("t2", "get_time")],
            "Cohere -> Cohere tool-call passthrough must preserve every call"
        );
        assert_eq!(back.stop_reason.as_deref(), Some("tool_use"));
    }

    /// Regression (MEDIUM/conformance): the streaming `content-delta` frame must carry text at
    /// `delta.message.content.text` (an object), matching `content-start` and the native Cohere v2
    /// stream — not a bare string. A native SDK reads `content.text`.
    #[test]
    fn test_write_response_event_content_delta_is_object() {
        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("chunk".to_string()),
        };
        let (_, frame) = CohereWriter
            .write_response_event(&ev)
            .expect("content-delta must serialize");
        let content = frame
            .get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("content"))
            .expect("content present");
        assert!(
            content.is_object(),
            "content-delta content must be an object, got {content}"
        );
        assert_eq!(content.get("type").and_then(|t| t.as_str()), Some("text"));
        assert_eq!(content.get("text").and_then(|t| t.as_str()), Some("chunk"));
    }

    /// Regression (LOW/correctness): a streaming tool call (tool-call-start / tool-call-delta /
    /// tool-call-end) must NOT be swallowed by a catch-all — it maps onto the IR block lifecycle.
    #[test]
    fn test_stream_tool_call_events_mapped() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // start
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "tool-call-start must emit a BlockStart");
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, name },
            } => {
                assert_eq!(*index, 0);
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        }

        // delta (streamed arguments)
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 0,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"city\":"}}}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(args),
            } => assert_eq!(args, "{\"city\":"),
            other => panic!("expected InputJsonDelta, got {other:?}"),
        }

        // end
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));
        // tool-call-end emits the BlockStop but intentionally does NOT remove the frame index from
        // `open_tools`: the recorded set is what keeps each tool's IR index stable for its lifetime
        // (and the rank of any LATER tool stable), so it grows monotonically across the stream.
        assert!(
            state.open_tools.contains(&0),
            "the closed tool's frame index is retained to keep later tool indices stable"
        );
    }

    /// An unknown Cohere stream event type is a documented no-op (no events, no panic) — the named
    /// fallthrough arm must not break the stream.
    #[test]
    fn test_stream_unknown_event_is_noop() {
        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events(
            "",
            &serde_json::json!({"type": "citation-start", "index": 0}),
            &mut state,
        );
        assert!(evs.is_empty(), "unknown event types produce no IR events");
    }

    /// Regression (MEDIUM/performance): `extract_error` derives both fields from a SINGLE parse.
    /// Behavioral check that both fields are still populated from one body.
    #[test]
    fn test_extract_error_single_parse_both_fields() {
        let body = br#"{"message": "boom", "error_type": "invalid_request"}"#;
        let err = CohereReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(err.provider_code.as_deref(), Some("boom"));
        assert_eq!(err.structured_type.as_deref(), Some("invalid_request"));
        assert_eq!(err.http_status, 400);
    }

    /// Regression (MEDIUM/conformance): a non-streaming request must OMIT the `stream` key entirely
    /// (matching a native client relying on the `false` default), and a streaming request must emit
    /// `"stream": true`. Always injecting `"stream": false` was a proxy tell and a same-protocol
    /// passthrough fidelity break.
    #[test]
    fn test_write_request_stream_field_conditional() {
        let base = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let non_streaming = CohereWriter.write_request(&base);
        assert!(
            non_streaming.get("stream").is_none(),
            "non-streaming request must omit the `stream` key, got {non_streaming}"
        );

        let streaming = CohereWriter.write_request(&crate::ir::IrRequest {
            stream: true,
            ..base
        });
        assert_eq!(
            streaming.get("stream"),
            Some(&serde_json::json!(true)),
            "streaming request must emit `\"stream\": true`"
        );
    }

    /// Regression (MEDIUM/conformance): a non-streaming Cohere -> Cohere passthrough must NOT GAIN a
    /// `stream` field the native client never sent. Reading a body without `stream` then writing it
    /// must yield a body still without `stream`.
    #[test]
    fn test_stream_field_roundtrip_omitted() {
        let native = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = CohereReader
            .read_request(&native)
            .expect("read_request should succeed");
        assert!(!ir.stream, "absent `stream` reads as false");
        let out = CohereWriter.write_request(&ir);
        assert!(
            out.get("stream").is_none(),
            "round-trip must not inject a `stream` field, got {out}"
        );
    }

    /// Regression (MEDIUM/conformance): the streaming `message-end` frame must carry token usage at
    /// `delta.usage.tokens.{input_tokens,output_tokens}` (native Cohere v2 shape) so a Cohere SDK
    /// client tracking billing/rate-limit data is not silently zeroed.
    #[test]
    fn test_write_response_event_message_end_carries_usage() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 42,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = CohereWriter
            .write_response_event(&ev)
            .expect("message-end must serialize");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("message-end")
        );
        let tokens = frame
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
            .expect("delta.usage.tokens must be present");
        assert_eq!(
            tokens.get("input_tokens").and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            tokens.get("output_tokens").and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    /// Regression (MEDIUM/conformance): when upstream usage is zero (no data), the message-end frame
    /// still emits the `tokens` object with zero values rather than omitting the key.
    #[test]
    fn test_write_response_event_message_end_zero_usage_present() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = CohereWriter
            .write_response_event(&ev)
            .expect("message-end must serialize");
        let tokens = frame
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
            .expect("delta.usage.tokens must be present even with zero usage");
        assert_eq!(tokens.get("input_tokens").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            tokens.get("output_tokens").and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    /// The message-end stream frame round-trips usage through this protocol's own reader: the usage
    /// written into `delta.usage.tokens` is read back identically.
    #[test]
    fn test_message_end_usage_stream_roundtrip() {
        let usage = crate::ir::IrUsage {
            input_tokens: 11,
            output_tokens: 3,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        let (_, frame) = CohereWriter
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage.clone(),
            })
            .expect("message-end must serialize");

        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events("", &frame, &mut state);
        let back = evs
            .iter()
            .find_map(|e| {
                if let IrStreamEvent::MessageDelta { usage, .. } = e {
                    Some(usage.clone())
                } else {
                    None
                }
            })
            .expect("a MessageDelta must come back");
        assert_eq!(back.input_tokens, 11);
        assert_eq!(back.output_tokens, 3);
    }

    /// Regression (LOW/correctness): a Tool-role message carrying plain text ALONGSIDE a ToolResult
    /// must not silently drop the text — it is folded into the emitted tool message content.
    #[test]
    fn test_tool_role_text_alongside_result_not_dropped() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "note".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "result".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    },
                ],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = CohereWriter.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 1, "one tool message emitted");
        let content = msgs[0].get("content").and_then(|c| c.as_str()).unwrap();
        assert!(
            content.contains("note") && content.contains("result"),
            "both the message-level text and the tool result text must survive, got {content}"
        );
        assert_eq!(
            msgs[0].get("tool_call_id").and_then(|v| v.as_str()),
            Some("t1")
        );
    }

    /// Regression (LOW/correctness): a degenerate Tool-role message with text but NO ToolResult
    /// block must still emit its text rather than producing nothing at all.
    #[test]
    fn test_tool_role_text_without_result_not_dropped() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::Text {
                    text: "orphan tool text".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = CohereWriter.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "a Tool turn with text but no ToolResult must still emit a message"
        );
        assert_eq!(msgs[0].get("role").and_then(|r| r.as_str()), Some("tool"));
        assert_eq!(
            msgs[0].get("content").and_then(|c| c.as_str()),
            Some("orphan tool text")
        );
    }

    /// Regression (HIGH/dead-code): `write_error` is a LIVE vtable-dispatched trait method, not
    /// test-only scaffolding. Reaching it via a `&dyn ProtocolWriter` (the exact runtime path used
    /// at the Cohere-ingress error sites) must produce the native bare `{"message": ...}` envelope.
    #[test]
    fn test_write_error_via_trait_object_is_live_path() {
        let writer: Box<dyn ProtocolWriter> = Box::new(CohereWriter);
        let v = writer.write_error(401, "authentication_error", "bad key");
        assert_eq!(
            v.get("message").and_then(|m| m.as_str()),
            Some("bad key"),
            "the vtable-dispatched write_error must emit the native Cohere envelope"
        );
        assert_eq!(
            v.as_object().map(|o| o.len()),
            Some(1),
            "native Cohere error body is a bare single-key {{\"message\": ...}}"
        );
    }

    /// Regression (MEDIUM/conformance): a Cohere v2 `tool`-role message whose `content` is the
    /// native object-array shape (`[{"type":"text","text":...}]`, plus a typed `document` block)
    /// must NOT be silently dropped. The previous `filter_map(|b| b.as_str())` returned None for
    /// every object element, yielding empty tool-result content and corrupting the conversation on
    /// passthrough/egress.
    #[test]
    fn test_read_request_tool_content_object_array_preserved() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": [
                        {"type": "text", "text": "first part"},
                        {"type": "text", "text": "second part"},
                        {"type": "document", "document": {"id": "d1", "data": "doc body"}}
                    ]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == crate::ir::IrRole::Tool)
            .expect("tool message present");
        let tool_result = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
            .expect("ToolResult block present");
        let text = match tool_result.first() {
            Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
            other => panic!("expected text block in tool result, got {other:?}"),
        };
        assert!(
            text.contains("first part"),
            "text block text must be preserved: {text}"
        );
        assert!(
            text.contains("second part"),
            "all text blocks must be joined: {text}"
        );
        assert!(
            text.contains("doc body"),
            "non-text typed (document) block must be serialized, not dropped: {text}"
        );
    }

    /// Regression (MEDIUM/conformance): the bare-string tool-content array shape must keep working
    /// alongside the new object-array handling.
    #[test]
    fn test_read_request_tool_content_string_array_still_works() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_2",
                    "content": ["alpha", "beta"]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == crate::ir::IrRole::Tool)
            .expect("tool message present");
        let tool_result = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
            .expect("ToolResult block present");
        let text = match tool_result.first() {
            Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
            other => panic!("expected text block in tool result, got {other:?}"),
        };
        assert_eq!(text, "alpha beta");
    }

    /// Regression (HIGH/correctness): Cohere v2 streams each tool call as a complete
    /// start/delta(s)/end sequence, closing the first tool BEFORE starting the second. The IR block
    /// index assigned to each tool must stay distinct and stable for the tool's whole lifetime. The
    /// prior scheme derived the index from the live rank of `frame_idx` in a set that shrank on
    /// `tool-call-end`, so the second tool-call-start saw `len()==0` and reused the first tool's IR
    /// index — silently merging two distinct tool calls onto one block. Feed two full sequences and
    /// assert two DISTINCT BlockStart indices that match their deltas/stops.
    #[test]
    fn test_stream_two_sequential_tool_calls_get_distinct_indices() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // --- Tool 1: start (frame index 0) ---
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "call_a",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        let idx1 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            } => {
                assert_eq!(id, "call_a");
                *index
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        };

        // Tool 1 delta + end (closing the first tool BEFORE the second starts — the trigger).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 0,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"a\":1}"}}}}
            }),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx1
        ));
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index } if *index == idx1
        ));

        // --- Tool 2: start (frame index 1), AFTER tool 1 closed ---
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 1,
                "delta": {"message": {"tool_calls": {
                    "id": "call_b",
                    "type": "function",
                    "function": {"name": "get_time", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        let idx2 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            } => {
                assert_eq!(id, "call_b");
                *index
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        };

        // The core assertion: the two tool calls occupy DISTINCT IR block indices.
        assert_ne!(
            idx1, idx2,
            "two sequential streamed tool calls must get distinct IR block indices"
        );

        // Tool 2's delta and end resolve to ITS index, not tool 1's.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 1,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"b\":2}"}}}}
            }),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx2
        ));
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 1}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index } if *index == idx2
        ));
    }

    /// A leading text block must push tool blocks to IR index 1+ while keeping each tool distinct.
    #[test]
    fn test_stream_tool_indices_offset_by_open_text_block() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // Open a text block at index 0.
        reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            &mut state,
        );

        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {"id": "c1", "type": "function", "function": {"name": "f1", "arguments": ""}}}}
            }),
            &mut state,
        );
        let idx1 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("expected BlockStart, got {other:?}"),
        };
        assert_eq!(idx1, 1, "first tool follows the open text block at index 0");

        reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );

        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 1,
                "delta": {"message": {"tool_calls": {"id": "c2", "type": "function", "function": {"name": "f2", "arguments": ""}}}}
            }),
            &mut state,
        );
        let idx2 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("expected BlockStart, got {other:?}"),
        };
        assert_eq!(
            idx2, 2,
            "second tool gets the next distinct index after the first"
        );
        assert_ne!(idx1, idx2);
    }

    /// Regression (MEDIUM/conformance): a cross-protocol stream delivering tool calls to a
    /// Cohere-ingress client must emit native `tool-call-start` / `tool-call-delta` frames. The
    /// writer previously returned None for BlockStart{ToolUse} and BlockDelta{InputJsonDelta}, so a
    /// Cohere client watching for streaming tool calls received nothing.
    #[test]
    fn test_write_response_event_emits_tool_call_frames() {
        let writer = CohereWriter;

        // BlockStart{ToolUse} → tool-call-start carrying id/name and an empty-string arguments.
        let start = IrStreamEvent::BlockStart {
            index: 2,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_x".to_string(),
                name: "get_weather".to_string(),
            },
        };
        let (_, frame) = writer
            .write_response_event(&start)
            .expect("BlockStart ToolUse must emit a frame");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("tool-call-start")
        );
        assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
        let tc = frame
            .get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("tool_calls"))
            .expect("tool_calls present");
        assert_eq!(tc.get("id").and_then(|v| v.as_str()), Some("call_x"));
        assert_eq!(tc.get("type").and_then(|v| v.as_str()), Some("function"));
        assert_eq!(
            tc.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str()),
            Some("get_weather")
        );
        assert_eq!(
            tc.get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str()),
            Some(""),
            "the reader accumulates argument deltas onto this opening empty string"
        );

        // BlockDelta{InputJsonDelta} → tool-call-delta carrying the argument fragment.
        let delta = IrStreamEvent::BlockDelta {
            index: 2,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
        };
        let (_, frame) = writer
            .write_response_event(&delta)
            .expect("BlockDelta InputJsonDelta must emit a frame");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("tool-call-delta")
        );
        assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
        assert_eq!(
            frame
                .get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.get("function"))
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str()),
            Some("{\"city\":\"SF\"}")
        );
    }

    /// The writer's emitted tool-call-start/delta frames round-trip through this protocol's OWN
    /// reader: a BlockStart{ToolUse} + BlockDelta(args) re-read yields the same id/name/arguments.
    #[test]
    fn test_writer_tool_call_frames_roundtrip_through_reader() {
        let writer = CohereWriter;
        let (_, start_frame) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_z".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("start frame");
        let (_, delta_frame) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
            })
            .expect("delta frame");

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;
        let start_evs = reader.read_response_events("", &start_frame, &mut state);
        match &start_evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { id, name },
                ..
            } => {
                assert_eq!(id, "call_z");
                assert_eq!(name, "lookup");
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        }
        let delta_evs = reader.read_response_events("", &delta_frame, &mut state);
        match &delta_evs[0] {
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::InputJsonDelta(args),
                ..
            } => assert_eq!(args, "{\"q\":1}"),
            other => panic!("expected InputJsonDelta, got {other:?}"),
        }
    }

    /// Thinking/Image stream blocks have no native Cohere v2 frame shape, so the writer suppresses
    /// them (returns None) rather than emitting a fabricated non-native frame.
    #[test]
    fn test_write_response_event_thinking_and_image_blocks_suppressed() {
        let writer = CohereWriter;
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Thinking,
            })
            .is_none());
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Image,
            })
            .is_none());
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta("x".to_string()),
            })
            .is_none());
    }
}
