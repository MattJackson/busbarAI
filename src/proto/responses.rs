// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI Responses API protocol reader/writer implementation.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic per-process counter mixed into synthesized response ids so two responses minted in
/// the same wall-clock second still get distinct `resp_` ids. Paired with the unix timestamp this
/// gives a collision-free id without pulling in a UUID/random crate (no new dependency).
static RESPONSE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Current unix epoch seconds, or 0 if the clock is before the epoch (never on a sane host).
/// Kept panic-free for the request path: no `unwrap`/`expect` on `SystemTime`.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Synthesize a protocol-correct Responses id (`resp_<hex>`) for cross-protocol responses where the
/// backend supplied none. Uniqueness comes from concatenating the unix timestamp and a monotonic
/// per-process counter as separate hex fields — no XOR folding (which would collide once the counter
/// advances by 2^24 within a second) and no new crate dependency. Native passthrough never calls
/// this: it carries the upstream id verbatim.
fn synthesize_response_id() -> String {
    let counter = RESPONSE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("resp_{:x}{:016x}", now_unix_secs(), counter)
}

/// Parse a Responses `image_url` string into an IR `(media_type, data)` pair.
///
/// A base64 data URI (`data:<mime>;base64,<payload>`) is split on the FIRST comma — the single `;`
/// canonical shape has only two `;`-delimited fields, so the previous `splitn(3, ';')` logic could
/// never recover the payload and silently dropped every image. We take the MIME type from the
/// metadata before the comma and the base64 payload after it, matching `openai.rs`'s
/// `parse_image_url`. Any non-data URL (an https reference, or a data URI we cannot confidently
/// split) is preserved verbatim in `data` with the `image_url` media_type sentinel so the writer can
/// reconstruct the exact original `image_url` on a same-protocol round-trip — never a human-readable
/// comment embedded in the payload.
fn parse_image_url(url: &str) -> (String, String) {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            // meta is e.g. "image/png;base64" or "image/png" — keep only the MIME type.
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return (media_type, payload.to_string());
            }
        }
    }
    // Non-data URL (https://...) or an unrecognized data URI: keep it verbatim under the
    // `image_url` sentinel so the writer round-trips it as-is rather than mangling it.
    ("image_url".to_string(), url.to_string())
}

/// Reconstruct a Responses `image_url` string from the IR `Image` (media_type, data) pair — the
/// inverse of [`parse_image_url`]. A URL-sentinel image is emitted verbatim; a base64 image is
/// re-wrapped into a `data:<mime>;base64,<payload>` URI.
fn image_url_from_ir(media_type: &str, data: &str) -> String {
    if media_type == "image_url" {
        data.to_string()
    } else {
        format!("data:{media_type};base64,{data}")
    }
}

#[derive(Clone)]
pub(crate) struct ResponsesReader;

impl ProtocolReader for ResponsesReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body ONCE and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (matches the anthropic.rs pattern; error paths are
        // already degraded — avoid the extra parse+alloc on every non-2xx response).
        let (provider_code, structured_type) =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(json) => {
                    let error = json.get("error").and_then(|e| e.as_object());
                    let provider_code = error
                        .and_then(|e_obj| e_obj.get("code"))
                        .and_then(|c| c.as_str())
                        .map(String::from);
                    let structured_type = error
                        .and_then(|e_obj| e_obj.get("type"))
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    (provider_code, structured_type)
                }
                Err(_) => (None, None),
            };

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
            retry_after_secs: None,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
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

        if obj.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(instructions) = obj.get("instructions").and_then(|v| v.as_str()) {
            if !instructions.is_empty() {
                system_blocks.push(crate::ir::IrBlock::Text {
                    text: instructions.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();

        if let Some(input_val) = obj.get("input") {
            if input_val.is_string() {
                let text = input_val.as_str().unwrap_or("").to_string();
                messages.push(crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text,
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                });
            } else if input_val.is_array() {
                for item in input_val.as_array().unwrap() {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some("input_text") => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("input_image") => {
                            let image_url =
                                item.get("image_url").and_then(|u| u.as_str()).unwrap_or("");
                            let (media_type, data) = parse_image_url(image_url);
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Image { media_type, data }],
                            });
                        }
                        Some("output_text") => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("function_call") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let arguments = item
                                .get("arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");
                            // On malformed argument JSON, preserve the raw string rather than
                            // discarding the caller's tool arguments to Null (mirrors the OpenAI
                            // reader). Losing arguments entirely is a lossy cross-protocol bug.
                            let input = serde_json::from_str(arguments).unwrap_or_else(|_| {
                                serde_json::Value::String(arguments.to_string())
                            });

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::ToolUse {
                                    id: call_id,
                                    name,
                                    input,
                                }],
                            });
                        }
                        Some("function_call_output") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let output_val = item.get("output");
                            let content_blocks: Vec<crate::ir::IrBlock> = match output_val {
                                Some(serde_json::Value::String(out_str)) => {
                                    vec![crate::ir::IrBlock::Text {
                                        text: out_str.clone(),
                                        cache_control: None,
                                        citations: Vec::new(),
                                    }]
                                }
                                _ => output_val
                                    .and_then(|o| o.as_array())
                                    .map(|arr| {
                                        arr.iter().filter_map(|b| responses_block(b).ok()).collect()
                                    })
                                    .unwrap_or_default(),
                            };

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Tool,
                                content: vec![crate::ir::IrBlock::ToolResult {
                                    tool_use_id: call_id,
                                    content: content_blocks,
                                    is_error: false,
                                }],
                            });
                        }
                        Some("message") => {
                            // The official OpenAI Responses SDK emits conversation turns as typed
                            // `{"type":"message","role":...,"content":[...]}` items. The role-keyed
                            // fallback below only fires for UNTYPED items, so without this arm a
                            // typed message turn would be silently dropped. Read role+content and
                            // map the content blocks via `responses_block`, mirroring the untyped
                            // branch.
                            let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                            let role = match role_str {
                                "user" => Some(crate::ir::IrRole::User),
                                "assistant" => Some(crate::ir::IrRole::Assistant),
                                _ => None,
                            };
                            if let Some(role) = role {
                                if let Some(content_arr) =
                                    item.get("content").and_then(|c| c.as_array())
                                {
                                    let msg_content: Vec<crate::ir::IrBlock> = content_arr
                                        .iter()
                                        .filter_map(|b| responses_block(b).ok())
                                        .collect();
                                    messages.push(crate::ir::IrMessage {
                                        role,
                                        content: msg_content,
                                    });
                                }
                            }
                        }
                        Some("reasoning") => {}
                        Some(_) | None => {}
                    }

                    // Handle role/content structured items (user/assistant messages) ONLY when the
                    // item carries no `type` field. A typed item (e.g. "output_text") that also
                    // happens to include a `role` must NOT be re-processed here, or the turn would
                    // be duplicated in the resulting conversation.
                    if item.get("type").is_none() && item.get("role").is_some() {
                        let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                        let content_val = item.get("content");

                        let role = match role_str {
                            "user" => crate::ir::IrRole::User,
                            "assistant" => crate::ir::IrRole::Assistant,
                            _ => continue,
                        };

                        if let Some(content_arr) = content_val.and_then(|c| c.as_array()) {
                            let msg_content: Vec<crate::ir::IrBlock> = content_arr
                                .iter()
                                .filter_map(|b| responses_block(b).ok())
                                .collect();

                            messages.push(crate::ir::IrMessage {
                                role,
                                content: msg_content,
                            });
                        }
                    }
                }
            }
        } else if !obj.contains_key("instructions") {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                let name = tool_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool_val
                    .get("description")
                    .and_then(|v| v.as_str().map(String::from));
                let input_schema = tool_val
                    .get("parameters")
                    .or_else(|| tool_val.get("input_schema"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                tools.push(crate::ir::IrTool {
                    name,
                    description,
                    input_schema,
                });
            }
        }

        let max_tokens = obj
            .get("max_output_tokens")
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .map(|v| v as u32);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        // The Responses API carries `stream` in the request body — read it (don't drop the intent).
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "instructions",
            "input",
            "tools",
            "max_output_tokens",
            "temperature",
            "metadata",
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

        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
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
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match event_type {
            "response.created" | "response.in_progress" => {
                if !state.started {
                    state.started = true;
                    // Capture stream identity from the nested `response` object so a same-protocol
                    // passthrough preserves it. `created_at` is the Responses field name (mapped to
                    // the IR's `created`).
                    let resp = data.get("response");
                    let id = resp
                        .and_then(|r| r.get("id"))
                        .and_then(|i| i.as_str())
                        .map(String::from);
                    let created = resp
                        .and_then(|r| r.get("created_at"))
                        .and_then(|c| c.as_u64());
                    let model = resp
                        .and_then(|r| r.get("model"))
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created,
                        model,
                    });
                }
            }

            "response.output_item.added" => {
                if let Some(item_obj) = data.get("item") {
                    if item_obj.get("type").and_then(|t| t.as_str()) == Some("function_call") {
                        let call_id = item_obj
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item_obj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            out.push(IrStreamEvent::BlockStart {
                                index: output_index as usize,
                                block: crate::ir::IrBlockMeta::ToolUse { id: call_id, name },
                            });
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str()) == Some("message") {
                    }
                }
            }

            "response.output_text.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                // Drop empty keepalive deltas entirely: they neither open a block nor carry
                // content, so emitting a zero-length TextDelta would be spurious noise.
                if !delta.is_empty() {
                    // Use the wire `output_index` for BOTH the lazy BlockStart and the BlockDelta so
                    // the open/close pair stays index-matched even when the text part is not at
                    // index 0 (e.g. it follows a tool call at index 0).
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| v as usize);
                    if !state.text_block_open {
                        state.text_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::TextDelta(delta),
                    });
                }
            }

            "response.function_call_arguments.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                        out.push(IrStreamEvent::BlockDelta {
                            index: output_index as usize,
                            delta: crate::ir::IrDelta::InputJsonDelta(delta),
                        });
                    }
                }
            }

            "response.output_item.done" | "response.content_part.done" => {
                if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                    // The text block (if any) opened at this index is now closed; clear the flag so a
                    // later text part can lazily re-open its own block instead of silently reusing a
                    // stale "open" state.
                    if state.text_block_open {
                        state.text_block_open = false;
                    }
                    out.push(IrStreamEvent::BlockStop {
                        index: output_index as usize,
                    });
                }
            }

            "response.completed" | "response.failed" | "response.incomplete" => {
                if let Some(response_obj) = data.get("response") {
                    let status = response_obj
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    // A genuinely failed terminal stream must NOT be decoded as a successful
                    // end_turn — that would mask the upstream failure from a downstream client
                    // (e.g. an Anthropic client would see stop_reason=end_turn). Surface it as an
                    // explicit IrStreamEvent::Error so the failure propagates, then still terminate
                    // the stream so consumers do not hang.
                    if status == "failed" {
                        let provider_signal = response_obj
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_str())
                            .or_else(|| {
                                response_obj
                                    .get("error")
                                    .and_then(|e| e.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .map(String::from)
                            .or_else(|| Some("response_failed".to_string()));
                        out.push(IrStreamEvent::Error(IrError {
                            class: StatusClass::ServerError,
                            provider_signal,
                            retry_after: None,
                        }));
                        out.push(IrStreamEvent::MessageStop);
                        return out;
                    }

                    // Enumerate the recognized statuses rather than defaulting unknown ones to a
                    // successful end_turn. An unrecognized status is treated as a terminal stop
                    // with no specific reason (None) rather than silently claiming success.
                    let stop_reason = match status {
                        "completed" => Some("end_turn".to_string()),
                        "incomplete" => {
                            if let Some(incomplete_details) = response_obj.get("incomplete_details")
                            {
                                if let Some(reason) =
                                    incomplete_details.get("reason").and_then(|r| r.as_str())
                                {
                                    match reason {
                                        "max_output_tokens" => Some("max_tokens".to_string()),
                                        "content_filter" => Some("safety".to_string()),
                                        _ => Some(reason.to_string()),
                                    }
                                } else {
                                    Some("end_turn".to_string())
                                }
                            } else {
                                Some("end_turn".to_string())
                            }
                        }
                        "" => Some("end_turn".to_string()),
                        _ => None,
                    };

                    let usage = response_obj
                        .get("usage")
                        .map(|u| crate::ir::IrUsage {
                            input_tokens: u
                                .get("input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            output_tokens: u
                                .get("output_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        })
                        .unwrap_or(crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        });

                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        // Responses API has no stop_sequence analog in its stream.
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                } else {
                    // Terminal event with no nested `response` object. Whether completed, failed, or
                    // incomplete, we must still terminate the translated stream with a
                    // MessageDelta + MessageStop so downstream consumers do not hang waiting for the
                    // end of the message.
                    let stop_reason = Some("end_turn".to_string());
                    let usage = crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                }
            }

            _ => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("");
        let mut stop_reason: Option<String> = match status {
            "completed" => Some("end_turn".to_string()),
            "incomplete" => {
                if let Some(incomplete_details) = obj.get("incomplete_details") {
                    if let Some(reason) = incomplete_details.get("reason").and_then(|r| r.as_str())
                    {
                        match reason {
                            "max_output_tokens" => Some("max_tokens".to_string()),
                            "content_filter" => Some("safety".to_string()),
                            _ => Some(reason.to_string()),
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(output_arr) = obj.get("output").and_then(|o| o.as_array()) {
            for item in output_arr {
                let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

                match item_type {
                    "message" => {
                        if let Some(content_arr) = item.get("content").and_then(|c| c.as_array()) {
                            for block_item in content_arr {
                                let block_type = block_item
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or("");

                                if block_type == "output_text" {
                                    if let Some(text) =
                                        block_item.get("text").and_then(|t| t.as_str())
                                    {
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

                    "function_call" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = item
                            .get("arguments")
                            .and_then(|a| a.as_str())
                            .unwrap_or("{}");
                        // Preserve the raw string on malformed JSON rather than dropping the tool
                        // arguments to Null (mirrors the OpenAI reader; avoids lossy translation).
                        let input = serde_json::from_str(arguments)
                            .unwrap_or_else(|_| serde_json::Value::String(arguments.to_string()));

                        content.push(crate::ir::IrBlock::ToolUse {
                            id: call_id,
                            name,
                            input,
                        });
                    }

                    _ => {}
                }
            }
        } else {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        if content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. }))
        {
            stop_reason = Some("tool_use".to_string());
        }

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
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response's identity so a same-protocol (responses → responses)
        // passthrough preserves `id`/`created_at` exactly. The Responses API names its creation
        // timestamp `created_at` (NOT `created`, which is the Chat Completions field); we map it
        // into the shared IR `created` slot. `system_fingerprint`/`stop_sequence` have no analog in
        // the Responses shape, so they stay `None`.
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        let created = obj.get("created_at").and_then(|c| c.as_u64());

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

fn responses_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "input_text" | "output_text" => {
            let text_val = obj.get("text");
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        "input_image" => {
            let image_url = obj.get("image_url").and_then(|v| v.as_str()).unwrap_or("");
            let (media_type, data) = parse_image_url(image_url);
            Ok(crate::ir::IrBlock::Image { media_type, data })
        }
        _ => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        }),
    }
}

#[derive(Clone)]
pub(crate) struct ResponsesWriter;

impl ProtocolWriter for ResponsesWriter {
    fn upstream_path(&self) -> &str {
        "/v1/responses"
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

        if !req.system.is_empty() {
            let instructions: String = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !instructions.is_empty() {
                out.insert("instructions".to_string(), serde_json::json!(instructions));
            }
        }

        let mut input_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            match msg.role {
                crate::ir::IrRole::User | crate::ir::IrRole::Assistant => {
                    let role_str = if msg.role == crate::ir::IrRole::User {
                        "user"
                    } else {
                        "assistant"
                    };

                    let mut content_arr: Vec<serde_json::Value> = Vec::new();
                    // function_call / function_call_output items are flat top-level `input`
                    // entries in the Responses API, NOT nested inside a message's `content`.
                    // Collect them separately so the enclosing assistant `message` is emitted
                    // FIRST (and only when it actually has content), with the tool items appended
                    // after it in order — matching the conversation order the assistant produced.
                    let mut tool_items: Vec<serde_json::Value> = Vec::new();
                    for block in &msg.content {
                        match block {
                            crate::ir::IrBlock::Text { text, .. } => {
                                let type_str = if msg.role == crate::ir::IrRole::User {
                                    "input_text"
                                } else {
                                    "output_text"
                                };
                                content_arr.push(serde_json::json!({
                                    "type": type_str,
                                    "text": text
                                }));
                            }
                            crate::ir::IrBlock::Image { media_type, data } => {
                                // Reconstruct the original `image_url`: a URL-sentinel image is
                                // emitted verbatim, a base64 image is re-wrapped as a data URI. This
                                // is the inverse of `parse_image_url` so a same-protocol round-trip
                                // is lossless.
                                let image_url = image_url_from_ir(media_type, data);
                                content_arr.push(serde_json::json!({
                                    "type": "input_image",
                                    "image_url": image_url
                                }));
                            }
                            crate::ir::IrBlock::ToolUse { id, name, input } => {
                                let args_str = serde_json::to_string(input)
                                    .unwrap_or_else(|_| "{}".to_string());
                                tool_items.push(serde_json::json!({
                                    "type": "function_call",
                                    "call_id": id,
                                    "name": name,
                                    "arguments": args_str
                                }));
                            }
                            crate::ir::IrBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error: _,
                            } => {
                                let output_text = content
                                    .iter()
                                    .filter_map(|b| match b {
                                        crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" ");

                                tool_items.push(serde_json::json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": output_text
                                }));
                            }
                            crate::ir::IrBlock::Thinking { .. } => {}
                        }
                    }

                    // Emit the assistant/user `message` wrapper only when it carries content. A
                    // turn that is purely a tool call must NOT produce a spurious
                    // `{role, content: []}` item — the Responses API rejects empty-content
                    // message items.
                    if !content_arr.is_empty() {
                        let mut msg_obj = serde_json::Map::new();
                        msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                        msg_obj
                            .insert("content".to_string(), serde_json::Value::Array(content_arr));
                        input_arr.push(serde_json::Value::Object(msg_obj));
                    }
                    // Then the flat tool items, in order, AFTER the message they belong to.
                    input_arr.extend(tool_items);
                }

                crate::ir::IrRole::Tool => {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error: _,
                        } = block
                        {
                            let output_text = content
                                .iter()
                                .filter_map(|b| match b {
                                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join(" ");

                            input_arr.push(serde_json::json!({
                                "type": "function_call_output",
                                "call_id": tool_use_id,
                                "output": output_text
                            }));
                        }
                    }
                }

                crate::ir::IrRole::System => {}
            }
        }

        if !input_arr.is_empty() {
            out.insert("input".to_string(), serde_json::Value::Array(input_arr));
        }

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_obj.insert("description".to_string(), serde_json::json!(desc));
                }

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

        if let Some(max_tokens) = req.max_tokens {
            out.insert(
                "max_output_tokens".to_string(),
                serde_json::json!(max_tokens),
            );
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        // `stream` is a modeled key (excluded from `extra`), so it must be emitted explicitly or it
        // is silently dropped — a `stream: true` request would otherwise be answered non-streaming,
        // stalling the SSE translation loop. Mirrors the OpenAI writer.
        out.insert("stream".to_string(), serde_json::json!(req.stream));

        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                // The official OpenAI Responses SDK reads `response.id`/`created_at`/`model` from the
                // opening `response.created` event to construct its Response object; a stub omitting
                // them yields null identity fields and breaks event correlation. Forward the captured
                // identity when present (same-protocol passthrough), otherwise synthesize a
                // protocol-correct `resp_` id and the current unix time (cross-protocol, where
                // `translate_event` strips these to None) so the event stays SDK-valid.
                let mut resp_obj = serde_json::Map::new();
                let id = id.clone().unwrap_or_else(synthesize_response_id);
                let created_at = created.unwrap_or_else(now_unix_secs);
                resp_obj.insert("id".to_string(), serde_json::json!(id));
                resp_obj.insert("object".to_string(), serde_json::json!("response"));
                resp_obj.insert("created_at".to_string(), serde_json::json!(created_at));
                resp_obj.insert("status".to_string(), serde_json::json!("in_progress"));
                if let Some(model) = model {
                    resp_obj.insert("model".to_string(), serde_json::json!(model));
                }
                Some((
                    "response.created".to_string(),
                    serde_json::json!({ "response": resp_obj }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => None,
                crate::ir::IrBlockMeta::ToolUse { id, name } => Some((
                    "response.output_item.added".to_string(),
                    serde_json::json!({
                        "output_index": index,
                        "item": {
                            "type": "function_call",
                            "call_id": id,
                            "name": name
                        }
                    }),
                )),
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) if !text.is_empty() => Some((
                    "response.output_text.delta".to_string(),
                    serde_json::json!({
                        "output_index": index,
                        "delta": text
                    }),
                )),
                crate::ir::IrDelta::InputJsonDelta(json_str) => Some((
                    "response.function_call_arguments.delta".to_string(),
                    serde_json::json!({
                        "output_index": index,
                        "delta": json_str
                    }),
                )),
                &crate::ir::IrDelta::TextDelta(_) => None,
                crate::ir::IrDelta::ThinkingDelta(_) | crate::ir::IrDelta::SignatureDelta(_) => {
                    None
                }
            },

            IrStreamEvent::BlockStop { index } => Some((
                "response.output_item.done".to_string(),
                serde_json::json!({
                    "output_index": index,
                }),
            )),

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                // Map IR stop reasons to Responses statuses. An unknown/None reason defaults to
                // `completed` (the safe choice) rather than `failed`: a future IR reason (e.g. a
                // new `refusal`) that did NOT explicitly signal an error must not be misclassified
                // as a failed response, which would trigger client-side error handling for a
                // successful turn. Genuine failures arrive via IrStreamEvent::Error, not here.
                let status = match stop_reason.as_deref() {
                    Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
                    Some("max_tokens") => "incomplete",
                    Some("safety") => "incomplete",
                    _ => "completed",
                };

                let mut resp_obj = serde_json::Map::new();
                resp_obj.insert("object".to_string(), serde_json::json!("response"));
                resp_obj.insert("status".to_string(), serde_json::json!(status));

                if status == "incomplete" {
                    let reason = match stop_reason.as_deref() {
                        Some("max_tokens") => "max_output_tokens",
                        Some("safety") => "content_filter",
                        _ => "other",
                    };
                    let mut incomplete_details = serde_json::Map::new();
                    incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
                    resp_obj.insert(
                        "incomplete_details".to_string(),
                        serde_json::Value::Object(incomplete_details),
                    );
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
                resp_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

                // `status` is now always `completed`/`incomplete` (genuine failures arrive via
                // IrStreamEvent::Error, never here), so the terminal event is `response.completed`.
                Some((
                    "response.completed".to_string(),
                    serde_json::json!({ "response": resp_obj }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => {
                // Emit the full Responses/OpenAI error object so an SDK that branches on
                // `error.type`/`error.code` sees the same shape as a native error event, not a
                // partial `{message}`. We have no typed code/param here, so default `type` to
                // `server_error` and leave `code`/`param` explicitly null.
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "response.failed".to_string(),
                    serde_json::json!({
                        "error": {
                            "message": message,
                            "type": "server_error",
                            "code": serde_json::Value::Null,
                            "param": serde_json::Value::Null,
                        }
                    }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Unknown/None stop reasons default to `completed` (not `failed`): a future IR reason that
        // did not explicitly signal an error must not surface as a failed response to a Responses
        // client. Only the explicitly-mapped incomplete reasons downgrade the status.
        let status = match resp.stop_reason.as_deref() {
            Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
            Some("max_tokens") => "incomplete",
            Some("safety") => "incomplete",
            _ => "completed",
        };

        let mut output_arr: Vec<serde_json::Value> = Vec::new();

        let mut text_blocks: Vec<&str> = Vec::new();
        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        text_blocks.push(text);
                    }
                }
                crate::ir::IrBlock::ToolUse { id, name, input } => {
                    let args_str =
                        serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    output_arr.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": id,
                        "name": name,
                        "arguments": args_str
                    }));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                // ToolResult and Image have no representation in a Responses API `output` array
                // (output carries assistant `message`/`function_call` items only), so they are
                // intentionally dropped here. Enumerated explicitly rather than swallowed by a
                // catch-all so a future IrBlock variant forces a compile error instead of silently
                // vanishing from Responses output.
                crate::ir::IrBlock::ToolResult { .. } => {}
                crate::ir::IrBlock::Image { .. } => {}
            }
        }

        if !text_blocks.is_empty() {
            let text_content = text_blocks.join("");
            output_arr.insert(
                0,
                serde_json::json!({
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": text_content
                    }]
                }),
            );
        }

        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        let mut obj = serde_json::Map::new();
        // Emit the SDK-required top-level identity. Same-protocol passthrough carries the captured
        // upstream values verbatim; cross-protocol (backend supplied none) synthesizes a
        // protocol-correct `resp_` id and the current unix time so the body stays SDK-valid.
        // `created_at` is the Responses field name (the official SDK's `Response.created_at`).
        let id = resp.id.clone().unwrap_or_else(synthesize_response_id);
        let created_at = resp.created.unwrap_or_else(now_unix_secs);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!("response"));
        obj.insert("created_at".to_string(), serde_json::json!(created_at));
        obj.insert("status".to_string(), serde_json::json!(status));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
        obj.insert("output".to_string(), serde_json::Value::Array(output_arr));
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        if status == "incomplete" {
            let reason = match resp.stop_reason.as_deref() {
                Some("max_tokens") => "max_output_tokens",
                Some("safety") => "content_filter",
                _ => "other",
            };
            let mut incomplete_details = serde_json::Map::new();
            incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
            obj.insert(
                "incomplete_details".to_string(),
                serde_json::Value::Object(incomplete_details),
            );
        }

        serde_json::Value::Object(obj)
    }

    /// Native OpenAI Responses error envelope. The Responses API shares the OpenAI error shape an
    /// official SDK (`openai` Python / `openai-node`) decodes into a typed `APIError`:
    /// `{"error":{"message":<msg>,"type":<type>,"code":<code|null>,"param":<param|null>}}`, served
    /// as `application/json`. `code` and `param` are always present (null here — busbar's
    /// router/auth/forward errors are not field-level validation errors). The generic `kind` is
    /// mapped to the Responses `type` vocabulary where one exists.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map busbar's generic error `kind` to the OpenAI/Responses `error.type` vocabulary. The
        // canonical Responses/OpenAI types are `invalid_request_error`, `authentication_error`,
        // `permission_error`, `not_found_error`, `rate_limit_error`, `server_error`, and
        // `insufficient_quota`. Anything already in that vocabulary (or any unrecognized caller
        // string) is passed through verbatim rather than swallowed by a catch-all, so a precise
        // upstream type is never lost.
        let error_type = match kind {
            "invalid_request" | "invalid_request_error" => "invalid_request_error",
            "authentication" | "authentication_error" | "auth" => "authentication_error",
            "permission" | "permission_error" | "forbidden" => "permission_error",
            "not_found" | "not_found_error" => "not_found_error",
            "rate_limit" | "rate_limit_error" => "rate_limit_error",
            "server_error" | "internal" | "internal_error" => "server_error",
            "billing" | "insufficient_quota" => "insufficient_quota",
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "code": serde_json::Value::Null,
                "param": serde_json::Value::Null,
            }
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
                        id: "fc_1".to_string(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({"city": "SF"}),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "fc_1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "sunny".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("Get weather for a location".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }),
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7),
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);

        assert_eq!(
            json.get("instructions").and_then(|v| v.as_str()),
            Some("You are helpful.")
        );

        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");

        let first_item = &input[0];
        assert_eq!(
            first_item.get("role").and_then(|r| r.as_str()),
            Some("user")
        );
        let content = first_item
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content should exist");
        assert_eq!(content.len(), 1);
        assert_eq!(
            content[0].get("type"),
            Some(&serde_json::json!("input_text"))
        );
        assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("hi"));

        let func_call_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call"))
            .expect("should have function_call item");
        assert_eq!(
            func_call_item.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        let args = func_call_item
            .get("arguments")
            .and_then(|a| a.as_str())
            .expect("arguments should exist");
        assert!(args.contains("SF") || args.contains("city"));

        let func_output_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call_output"))
            .expect("should have function_call_output item");
        assert_eq!(
            func_output_item.get("call_id").and_then(|c| c.as_str()),
            Some("fc_1")
        );
        let output = func_output_item
            .get("output")
            .and_then(|o| o.as_str())
            .expect("output should exist");
        assert_eq!(output, "sunny");

        let tools = json
            .get("tools")
            .and_then(|v| v.as_array())
            .expect("tools should exist");
        assert_eq!(tools.len(), 1);
        let tool_obj = &tools[0];
        assert_eq!(tool_obj.get("type"), Some(&serde_json::json!("function")));
        assert_eq!(
            tool_obj.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        assert!(
            tool_obj.get("function").is_none(),
            "tools should be flattened"
        );

        assert_eq!(
            json.get("max_output_tokens"),
            Some(&serde_json::json!(1024))
        );
        assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
    }

    #[test]
    fn test_read_request() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "instructions": "You are helpful.",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "What's the weather?"}]},
                {"role": "assistant", "content": [{"type": "output_text", "text": "Let me check that for you."}]},
                {"type": "function_call", "call_id": "fc_1", "name": "get_weather", "arguments": "{\"city\":\"SF\"}"},
                {"type": "function_call_output", "call_id": "fc_1", "output": "Sunny, 72F"}
            ],
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
            "max_output_tokens": 1024,
            "temperature": 0.7
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.system.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
            assert_eq!(text, "You are helpful.");
        } else {
            panic!("system should be Text block");
        }

        // 2 role/content messages + function_call -> assistant + function_call_output -> tool
        assert_eq!(ir.messages.len(), 4);

        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What's the weather?");
        } else {
            panic!("first message should be Text block");
        }

        assert_eq!(ir.max_tokens, Some(1024));
        assert_eq!(ir.temperature, Some(0.7_f64));

        assert_eq!(ir.tools.len(), 1);
        let tool = &ir.tools[0];
        assert_eq!(tool.name, "get_weather");
    }

    #[test]
    fn test_roundtrip_identity() {
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
                        text: "Hello!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Hi there!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: Some(500),
            temperature: Some(0.7),
            stream: false,
            extra: serde_json::Map::new(),
        };

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let json = writer.write_request(&ir);
        let rt_ir = reader
            .read_request(&json)
            .expect("read round-trip should succeed");

        assert_eq!(ir, rt_ir);
    }

    #[test]
    fn test_temperature_fidelity() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "test"}]}],
            "temperature": 0.7,
            "max_output_tokens": 1024
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_auth_headers() {
        let writer = ResponsesWriter;
        let headers = writer.auth_headers("sk-test");

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");
    }

    #[test]
    fn test_read_response_decode() {
        let json = serde_json::json!({
            "id": "resp_1",
            "object": "response",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "The weather in SF is sunny."}]
                },
                {
                    "type": "function_call",
                    "call_id": "fc_1",
                    "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}"
                }
            ],
            "usage": {"input_tokens": 50, "output_tokens": 25}
        });

        let reader = ResponsesReader;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");

        assert_eq!(resp.content.len(), 2);
        match &resp.content[0] {
            crate::ir::IrBlock::Text { text, .. } => {
                assert_eq!(text, "The weather in SF is sunny.")
            }
            _ => panic!("first block should be Text"),
        }
        match &resp.content[1] {
            crate::ir::IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "fc_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input.get("city").and_then(|v| v.as_str()), Some("SF"));
            }
            _ => panic!("second block should be ToolUse"),
        }

        assert_eq!(resp.stop_reason, Some("tool_use".to_string()));
        assert_eq!(resp.usage.input_tokens, 50);
        assert_eq!(resp.usage.output_tokens, 25);
    }

    #[test]
    fn test_write_response_roundtrip_text_only() {
        // Carries `id`/`created_at` so same-protocol read→write is byte-identical: the writer now
        // always emits the SDK-required top-level identity, and a native response carries both.
        let json = serde_json::json!({
            "id": "resp_abc123",
            "object": "response",
            "created_at": 1_700_000_000_u64,
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Hello world"}]
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir_resp = reader.read_response(&json).expect("read should succeed");
        let roundtrip_json = writer.write_response(&ir_resp);

        assert_eq!(roundtrip_json, json);
    }

    /// The native Responses error envelope an official SDK decodes: a JSON object whose `error`
    /// carries `message`, a Responses-vocabulary `type`, and `code`/`param` keys (null here).
    #[test]
    fn test_write_error_native_responses_envelope() {
        let writer = ResponsesWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");

        // Round-trips as JSON without panic.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

        let err = reparsed.get("error").expect("error object present");
        assert_eq!(
            err.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found")
        );
        // Generic `not_found` maps to the Responses vocabulary `not_found_error`.
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("not_found_error")
        );
        // `code` and `param` keys are present and null (Responses/OpenAI always include them).
        assert!(err.get("code").is_some(), "code key must be present");
        assert!(err.get("param").is_some(), "param key must be present");
        assert!(err.get("code").unwrap().is_null());
        assert!(err.get("param").unwrap().is_null());
    }

    /// Each generic `kind` maps to the canonical Responses `error.type`; an unrecognized kind is
    /// passed through verbatim (no catch-all swallowing of a precise upstream type).
    #[test]
    fn test_write_error_kind_mapping() {
        let writer = ResponsesWriter;
        for (kind, want) in [
            ("invalid_request", "invalid_request_error"),
            ("auth", "authentication_error"),
            ("forbidden", "permission_error"),
            ("not_found", "not_found_error"),
            ("rate_limit", "rate_limit_error"),
            ("server_error", "server_error"),
            ("billing", "insufficient_quota"),
            // Already-canonical and unknown types pass through unchanged.
            ("authentication_error", "authentication_error"),
            ("some_future_type", "some_future_type"),
        ] {
            let v = writer.write_error(400, kind, "m");
            assert_eq!(
                v.get("error")
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str()),
                Some(want),
                "kind {kind} should map to {want}"
            );
        }
    }

    /// Same-protocol passthrough: `read_response` captures the upstream `id`/`created_at`, and
    /// `write_response` emits them verbatim — identity is preserved exactly, not regenerated.
    #[test]
    fn test_same_protocol_roundtrip_preserves_identity() {
        let json = serde_json::json!({
            "id": "resp_0123456789abcdef",
            "object": "response",
            "created_at": 1_710_000_000_u64,
            "status": "completed",
            "model": "gpt-4o-2024-08-06",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "hi"}]
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir = reader.read_response(&json).expect("read should succeed");
        assert_eq!(ir.id.as_deref(), Some("resp_0123456789abcdef"));
        assert_eq!(ir.created, Some(1_710_000_000));

        let out = writer.write_response(&ir);
        assert_eq!(
            out.get("id").and_then(|i| i.as_str()),
            Some("resp_0123456789abcdef"),
            "id must be preserved verbatim"
        );
        assert_eq!(
            out.get("created_at").and_then(|c| c.as_u64()),
            Some(1_710_000_000),
            "created_at must be preserved verbatim"
        );
        assert_eq!(out.get("object").and_then(|o| o.as_str()), Some("response"));
    }

    /// The streaming start event captures the nested `response` identity for same-protocol
    /// passthrough.
    #[test]
    fn test_stream_message_start_captures_identity() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.created",
            &serde_json::json!({
                "response": {
                    "id": "resp_streamid",
                    "object": "response",
                    "created_at": 1_720_000_000_u64,
                    "model": "gpt-4o",
                    "status": "in_progress"
                }
            }),
            &mut state,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                assert_eq!(id.as_deref(), Some("resp_streamid"));
                assert_eq!(*created, Some(1_720_000_000));
                assert_eq!(model.as_deref(), Some("gpt-4o"));
            }
            other => panic!("expected MessageStart, got {other:?}"),
        }
    }

    /// Cross-protocol: when the IR carries no identity (the backend supplied none), `write_response`
    /// synthesizes a valid `resp_`-prefixed id and a current `created_at` without panicking, and two
    /// successive synthesized ids are distinct.
    #[test]
    fn test_cross_protocol_write_synthesizes_valid_id() {
        let writer = ResponsesWriter;
        let make_ir = || crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "answer".to_string(),
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

        let out1 = writer.write_response(&make_ir());
        let id1 = out1
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id1.starts_with("resp_"),
            "synthesized id must use the resp_ prefix, got {id1}"
        );
        assert!(
            out1.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );

        let out2 = writer.write_response(&make_ir());
        let id2 = out2.get("id").and_then(|i| i.as_str()).unwrap();
        assert_ne!(id1, id2, "successive synthesized ids must be unique");
    }

    #[test]
    fn test_stream_fanout() {
        let mut state = crate::ir::StreamDecodeState::default();

        // response.created → MessageStart only (first time)
        let events1 = reader_read_response_events(
            "response.created",
            &serde_json::json!({"response": {"object":"response","status":"in_progress"}}),
            &mut state,
        );
        assert_eq!(events1.len(), 1);
        assert!(matches!(
            events1[0],
            crate::ir::IrStreamEvent::MessageStart { .. }
        ));
        // response.output_item.added for function_call → BlockStart
        let events2 = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": 1,
                "item": {"type":"function_call","call_id":"fc_1","name":"get_weather"}
            }),
            &mut state,
        );
        assert_eq!(events2.len(), 1);
        assert!(matches!(
            events2[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        // response.output_text.delta ×3 → BlockStart (lazy) + BlockDelta ×3
        let delta_json = |d: &str| serde_json::json!({"output_index": 0, "delta": d});
        let events3a =
            reader_read_response_events("response.output_text.delta", &delta_json("H"), &mut state);
        assert_eq!(events3a.len(), 2); // BlockStart + BlockDelta
        assert!(matches!(
            events3a[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        assert!(matches!(
            events3a[1],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3b =
            reader_read_response_events("response.output_text.delta", &delta_json("i"), &mut state);
        assert_eq!(events3b.len(), 1); // BlockDelta only
        assert!(matches!(
            events3b[0],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3c =
            reader_read_response_events("response.output_text.delta", &delta_json("!"), &mut state);
        assert_eq!(events3c.len(), 1); // BlockDelta only

        // response.output_item.done → BlockStop
        let events4 = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(events4.len(), 1);
        assert!(matches!(
            events4[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        // response.completed with usage → MessageDelta + MessageStop
        let completed_json = serde_json::json!({
            "response": {
                "status": "completed",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }
        });
        let events5 =
            reader_read_response_events("response.completed", &completed_json, &mut state);
        assert_eq!(events5.len(), 2);
        assert!(matches!(
            events5[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events5[1], crate::ir::IrStreamEvent::MessageStop));
        // response.in_progress should not emit MessageStart again (state.started=true)
        let events6 = reader_read_response_events(
            "response.in_progress",
            &serde_json::json!({"response": {"object":"response","status":"in_progress"}}),
            &mut state,
        );
        assert_eq!(events6.len(), 0);

        // Unknown event type → empty (no panic)
        let events7 = reader_read_response_events(
            "response.content_part.added",
            &serde_json::json!({}),
            &mut state,
        );
        assert_eq!(events7.len(), 0);
    }

    #[test]
    fn test_write_response_event_blockdelta() {
        let writer = ResponsesWriter;

        // BlockDelta TextDelta("hi") → ("response.output_text.delta", delta=="hi")
        let ev1 = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };
        let (etype1, payload1) = writer.write_response_event(&ev1).expect("should emit");
        assert_eq!(etype1, "response.output_text.delta");
        assert_eq!(payload1.get("delta").and_then(|d| d.as_str()), Some("hi"));

        // MessageDelta{end_turn} → ("response.completed", status maps to completed)
        let ev2 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype2, payload2) = writer.write_response_event(&ev2).expect("should emit");
        assert_eq!(etype2, "response.completed");
        let resp_obj = payload2
            .get("response")
            .expect("payload should have response");
        assert_eq!(
            resp_obj.get("status"),
            Some(&serde_json::json!("completed"))
        );
    }

    fn reader_read_response_events(
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<crate::ir::IrStreamEvent> {
        let reader = ResponsesReader;
        reader.read_response_events(event_type, data, state)
    }

    /// Regression: a text part arriving at a non-zero `output_index` must open AND write to the
    /// same block index. Previously BlockStart was hard-coded to index 0 while BlockDelta used the
    /// wire index, producing an unmatched open/write pair for downstream index-keyed consumers.
    #[test]
    fn test_text_delta_index_pairing_nonzero() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 2, "delta": "hello"}),
            &mut state,
        );
        assert_eq!(events.len(), 2, "expected lazy BlockStart + BlockDelta");
        let start_idx = match &events[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("first event should be BlockStart, got {other:?}"),
        };
        let delta_idx = match &events[1] {
            crate::ir::IrStreamEvent::BlockDelta { index, .. } => *index,
            other => panic!("second event should be BlockDelta, got {other:?}"),
        };
        assert_eq!(start_idx, 2, "BlockStart must use the wire output_index");
        assert_eq!(delta_idx, 2, "BlockDelta must use the wire output_index");
        assert_eq!(start_idx, delta_idx, "open/write indices must match");
    }

    /// Regression: an empty-delta keepalive chunk must produce no events, even when a text block is
    /// already open. Previously the guard `|| state.text_block_open` emitted a spurious zero-length
    /// TextDelta for every keepalive after the block opened.
    #[test]
    fn test_empty_delta_keepalive_emits_nothing() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a block with a real delta first.
        let opened = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "x"}),
            &mut state,
        );
        assert_eq!(opened.len(), 2);
        assert!(state.text_block_open);
        // Now an empty keepalive while the block is open -> nothing.
        let keepalive = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut state,
        );
        assert!(
            keepalive.is_empty(),
            "empty keepalive delta must not emit events, got {keepalive:?}"
        );
        // And an empty delta before any block is open also emits nothing.
        let mut fresh = crate::ir::StreamDecodeState::default();
        let pre = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut fresh,
        );
        assert!(pre.is_empty());
        assert!(!fresh.text_block_open);
    }

    /// Regression: output_item.done must clear `text_block_open` so a subsequent text part can
    /// lazily re-open its own block instead of silently reusing stale open state.
    #[test]
    fn test_done_clears_text_block_open() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.text_block_open);
        let done = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(!state.text_block_open, "done must clear text_block_open");
        // A new text part at index 1 re-opens lazily.
        let reopen = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 1, "delta": "b"}),
            &mut state,
        );
        assert_eq!(reopen.len(), 2);
        assert!(matches!(
            reopen[0],
            crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
        ));
    }

    /// Regression: content_part.done is also a terminal-of-part signal and must close its block.
    #[test]
    fn test_content_part_done_closes_block() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        let done = reader_read_response_events(
            "response.content_part.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(!state.text_block_open);
    }

    /// Regression: a minimal `response.completed` lacking a nested `response` object must still
    /// terminate the stream with MessageDelta + MessageStop, not leave it hanging.
    #[test]
    fn test_completed_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events =
            reader_read_response_events("response.completed", &serde_json::json!({}), &mut state);
        assert_eq!(events.len(), 2, "must emit MessageDelta + MessageStop");
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: same for `response.incomplete` with no nested response object.
    #[test]
    fn test_incomplete_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events =
            reader_read_response_events("response.incomplete", &serde_json::json!({}), &mut state);
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

        // response.failed without object still works (pre-existing behavior preserved).
        let mut s2 = crate::ir::StreamDecodeState::default();
        let failed =
            reader_read_response_events("response.failed", &serde_json::json!({}), &mut s2);
        assert_eq!(failed.len(), 2);
        assert!(matches!(failed[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: an input item carrying BOTH a `type` and a `role` must be processed exactly once
    /// (by the type arm), not duplicated by the role-keyed fallback.
    #[test]
    fn test_typed_item_with_role_not_duplicated() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {
                    "type": "output_text",
                    "role": "assistant",
                    "text": "hello",
                    "content": [{"type": "output_text", "text": "DUPLICATE"}]
                }
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        // Exactly one message: the type arm produced the assistant text turn; the role fallback
        // must NOT have added a second turn from the `content` array.
        assert_eq!(ir.messages.len(), 1, "typed+role item must not duplicate");
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::Assistant);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }

    /// Regression: an assistant turn that is PURELY a tool call must emit a flat `function_call`
    /// item and NO companion empty-content assistant `message` wrapper. The Responses API rejects
    /// assistant message items with `content: []`.
    #[test]
    fn test_tool_only_assistant_turn_no_empty_message_wrapper() {
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "fc_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        // Exactly one item: the function_call. No empty-content assistant message.
        assert_eq!(
            input.len(),
            1,
            "tool-only turn must not emit an empty message wrapper, got {input:?}"
        );
        assert_eq!(
            input[0].get("type").and_then(|t| t.as_str()),
            Some("function_call")
        );
        // No item should be a message with an empty content array.
        for item in input {
            if item.get("role").is_some() {
                let content = item.get("content").and_then(|c| c.as_array());
                assert!(
                    content.map(|c| !c.is_empty()).unwrap_or(true),
                    "no assistant message item may have empty content"
                );
            }
        }
    }

    /// Regression: an assistant turn carrying BOTH text and a tool call must emit the assistant
    /// `message` (with the text) FIRST, then the flat `function_call` item AFTER it — preserving
    /// the conversation order the assistant produced.
    #[test]
    fn test_assistant_text_then_tool_call_order() {
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "Let me check.".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::ToolUse {
                        id: "fc_9".to_string(),
                        name: "lookup".to_string(),
                        input: serde_json::json!({}),
                    },
                ],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        assert_eq!(
            input.len(),
            2,
            "expected message + function_call, got {input:?}"
        );
        // Message first.
        assert_eq!(
            input[0].get("role").and_then(|r| r.as_str()),
            Some("assistant")
        );
        let content = input[0]
            .get("content")
            .and_then(|c| c.as_array())
            .expect("message content");
        assert_eq!(
            content[0].get("text").and_then(|t| t.as_str()),
            Some("Let me check.")
        );
        // function_call after it.
        assert_eq!(
            input[1].get("type").and_then(|t| t.as_str()),
            Some("function_call")
        );
        assert_eq!(
            input[1].get("call_id").and_then(|c| c.as_str()),
            Some("fc_9")
        );
    }

    /// Regression: a streaming `response.failed` (status=="failed") must surface an
    /// IrStreamEvent::Error followed by MessageStop, NOT a successful end_turn MessageDelta that
    /// would mask the failure from a downstream client.
    #[test]
    fn test_stream_failed_status_emits_error_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.failed",
            &serde_json::json!({
                "response": {
                    "status": "failed",
                    "error": {"code": "server_error", "type": "server_error"}
                }
            }),
            &mut state,
        );
        assert_eq!(
            events.len(),
            2,
            "expected Error + MessageStop, got {events:?}"
        );
        match &events[0] {
            crate::ir::IrStreamEvent::Error(err) => {
                assert_eq!(err.provider_signal.as_deref(), Some("server_error"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
        // Crucially, no MessageDelta with end_turn was emitted.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageDelta { .. })),
            "failed stream must not emit a MessageDelta"
        );
    }

    /// Regression: an unknown terminal status must not be decoded as a successful end_turn; its
    /// stop_reason is None (terminal, but no success claim).
    #[test]
    fn test_stream_unknown_status_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.completed",
            &serde_json::json!({"response": {"status": "some_future_status"}}),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(*stop_reason, None, "unknown status must not claim end_turn");
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: the streaming error event must carry the full Responses error object
    /// (`type`/`code`/`param`), not just `message`, so SDK clients that branch on `error.type`
    /// see the native shape.
    #[test]
    fn test_write_error_stream_event_full_shape() {
        let writer = ResponsesWriter;
        let ev = crate::ir::IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (etype, payload) = writer
            .write_response_event(&ev)
            .expect("error event should emit");
        assert_eq!(etype, "response.failed");
        let err = payload.get("error").expect("error object present");
        assert_eq!(err.get("message").and_then(|m| m.as_str()), Some("boom"));
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("server_error")
        );
        assert!(err.get("code").is_some(), "code key must be present");
        assert!(err.get("param").is_some(), "param key must be present");
        assert!(err.get("code").unwrap().is_null());
        assert!(err.get("param").unwrap().is_null());
    }

    /// Regression: an unknown/unmapped stop_reason must map to a `completed` status (not `failed`),
    /// so a future IR reason that did not signal an error is not misclassified as a failure.
    #[test]
    fn test_unknown_stop_reason_maps_to_completed() {
        let writer = ResponsesWriter;
        // Streaming MessageDelta path.
        let ev = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("refusal".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.completed");
        assert_eq!(
            payload
                .get("response")
                .and_then(|r| r.get("status"))
                .and_then(|s| s.as_str()),
            Some("completed"),
            "unknown stop_reason must map to completed in stream"
        );

        // Non-streaming write_response path.
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "ok".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("refusal".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("status").and_then(|s| s.as_str()),
            Some("completed"),
            "unknown stop_reason must map to completed in write_response"
        );
    }

    /// Regression: malformed function_call arguments must be preserved as the raw string, not
    /// dropped to Null (mirrors the OpenAI reader). Covers both the request and response readers.
    #[test]
    fn test_malformed_function_call_args_preserved() {
        let reader = ResponsesReader;

        // read_request path.
        let req_json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "function_call", "call_id": "fc_1", "name": "f", "arguments": "not-json{"}
            ]
        });
        let ir = reader.read_request(&req_json).expect("read_request ok");
        let tool_use = ir
            .messages
            .iter()
            .flat_map(|m| &m.content)
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolUse { input, .. } => Some(input),
                _ => None,
            })
            .expect("tool use present");
        assert_eq!(
            tool_use.as_str(),
            Some("not-json{"),
            "malformed args must be preserved as raw string, not Null"
        );

        // read_response path.
        let resp_json = serde_json::json!({
            "id": "resp_1",
            "status": "completed",
            "output": [
                {"type": "function_call", "call_id": "fc_2", "name": "g", "arguments": "broken]"}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let resp = reader.read_response(&resp_json).expect("read_response ok");
        match &resp.content[0] {
            crate::ir::IrBlock::ToolUse { input, .. } => {
                assert_eq!(input.as_str(), Some("broken]"));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` data URI of the canonical single-`;` shape
    /// (`data:image/png;base64,<payload>`) must parse the FULL payload, not drop it to "". The old
    /// `splitn(3, ';')` logic yielded only two fields and silently discarded every image. Covers
    /// both `read_request` and `responses_block`.
    #[test]
    fn test_input_image_base64_payload_preserved() {
        let payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let url = format!("data:image/png;base64,{payload}");

        // read_request path.
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "input_image", "image_url": url}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(ir.messages.len(), 1);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload, "full base64 payload must be preserved");
            }
            other => panic!("expected Image, got {other:?}"),
        }

        // responses_block path (e.g. a content block nested in a function_call_output).
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload);
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` must survive a same-protocol read -> write -> read
    /// round-trip with its payload intact (the writer emits `data:<mime>;base64,<payload>` which the
    /// reader must parse back to the identical pair).
    #[test]
    fn test_input_image_roundtrip_lossless() {
        let payload = "QUJDMTIzKz0=";
        let media_type = "image/jpeg";
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    media_type: media_type.to_string(),
                    data: payload.to_string(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let reader = ResponsesReader;
        let json = writer.write_request(&ir);
        let rt = reader.read_request(&json).expect("read round-trip ok");
        match &rt.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                media_type: mt,
                data,
            } => {
                assert_eq!(mt, media_type);
                assert_eq!(data, payload, "round-trip must not corrupt the payload");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a non-data (https) image URL must be stored verbatim under the `image_url`
    /// sentinel media_type — NOT mangled into a `// note: non-data URL - ...` comment — and must
    /// round-trip back to the exact original URL.
    #[test]
    fn test_input_image_https_url_sentinel_roundtrip() {
        let url = "https://example.com/cat.png";
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        let (media_type, data) = match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image { media_type, data } => (media_type, data),
            other => panic!("expected Image, got {other:?}"),
        };
        assert_eq!(
            media_type, "image_url",
            "non-data URL must use the sentinel"
        );
        assert_eq!(data, url, "URL must be stored verbatim, not a comment");
        assert!(
            !data.starts_with("// note"),
            "must not embed a human comment in the payload"
        );

        // Round-trip through the writer reconstructs the exact original image_url.
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image { media_type, data }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let emitted = json["input"][0]["content"][0]["image_url"]
            .as_str()
            .expect("image_url present");
        assert_eq!(emitted, url, "writer must emit the original URL verbatim");
    }

    /// Regression: `write_request` must emit the `stream` field (a modeled key excluded from
    /// `extra`); omitting it answers a `stream: true` request non-streaming and stalls SSE.
    #[test]
    fn test_write_request_emits_stream() {
        let make = |stream: bool| crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        assert_eq!(
            writer.write_request(&make(true)).get("stream"),
            Some(&serde_json::json!(true)),
            "stream: true must be emitted"
        );
        assert_eq!(
            writer.write_request(&make(false)).get("stream"),
            Some(&serde_json::json!(false)),
            "stream: false must be emitted explicitly"
        );
    }

    /// Regression: a typed `{"type":"message","role":...,"content":[...]}` input item (the official
    /// SDK conversation-turn shape) must be read, not silently dropped.
    #[test]
    fn test_typed_message_item_read() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "message", "role": "user",
                 "content": [{"type": "input_text", "text": "hello typed"}]},
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": "hi back"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(
            ir.messages.len(),
            2,
            "both typed message turns must be read"
        );
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello typed"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
        match &ir.messages[1].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi back"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Regression: the streaming `response.created` event must carry `id`/`created_at`/`status`
    /// (and `model` when present), not a stub. Forwards captured identity for same-protocol
    /// passthrough; synthesizes a valid `resp_` id + current time when the IR carries none.
    #[test]
    fn test_message_start_emits_identity() {
        let writer = ResponsesWriter;

        // Identity present (same-protocol passthrough): forwarded verbatim.
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_streamid".to_string()),
            created: Some(1_720_000_000),
            model: Some("gpt-4o".to_string()),
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.created");
        let resp = payload.get("response").expect("response object");
        assert_eq!(
            resp.get("id").and_then(|i| i.as_str()),
            Some("resp_streamid")
        );
        assert_eq!(
            resp.get("created_at").and_then(|c| c.as_u64()),
            Some(1_720_000_000)
        );
        assert_eq!(resp.get("model").and_then(|m| m.as_str()), Some("gpt-4o"));
        assert_eq!(
            resp.get("status").and_then(|s| s.as_str()),
            Some("in_progress")
        );

        // Identity absent (cross-protocol, stripped by translate_event): synthesized + valid.
        let ev2 = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, payload2) = writer.write_response_event(&ev2).expect("should emit");
        let resp2 = payload2.get("response").expect("response object");
        let id = resp2
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id.starts_with("resp_"),
            "synthesized id must use resp_ prefix, got {id}"
        );
        assert!(
            resp2.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );
        assert!(
            resp2.get("model").is_none(),
            "absent model must not be emitted"
        );
    }

    /// Regression: synthesized response ids stay distinct even across many calls in the same second
    /// (the old `timestamp << 24 ^ counter` folding collided once the counter advanced by 2^24).
    #[test]
    fn test_synthesize_response_id_unique() {
        let n = 1000;
        let ids: std::collections::HashSet<String> =
            (0..n).map(|_| synthesize_response_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "all synthesized ids in a burst must be unique"
        );
        assert!(ids.iter().all(|id| id.starts_with("resp_")));
    }

    /// A role-only item (no `type`) must still be processed via the role fallback.
    #[test]
    fn test_role_only_item_still_processed() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "hi there"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi there"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }
}
