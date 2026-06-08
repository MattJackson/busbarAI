// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Anthropic protocol reader/writer implementation.

use super::*;

/// Value of the required `anthropic-version` request header (the Messages API version busbar
/// targets). Bump when adopting a newer Anthropic API version.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Monotonic counter that disambiguates synthesized ids minted within the same clock second (or
/// when the clock is non-monotonic). Combined with the unix timestamp it makes a collision between
/// two synthesized ids astronomically unlikely without pulling in a uuid/rand crate.
static SYNTH_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Current unix time in whole seconds, or 0 if the system clock predates the epoch. Used as
/// `created` synthesis and as the high bits of a synthesized id; never panics on a bad clock.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a protocol-correct Anthropic message id (`msg_<rand>`) for the cross-protocol path, where
/// the backend supplied none. An official Anthropic SDK only requires the `msg_` prefix and a
/// non-empty unique suffix — it does not parse the body — so a timestamp+counter suffix is
/// indistinguishable in shape from a native id. No new dependency: uniqueness comes from the unix
/// second plus a process-global atomic counter.
fn synth_message_id() -> String {
    let seq = SYNTH_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("msg_{:x}{:x}", unix_now_secs(), seq)
}

/// Mint a protocol-correct Anthropic request id (`req_<hex>`) for the top level of an error
/// envelope, where busbar synthesizes the error itself and has no upstream request id to forward.
/// Current Anthropic API error responses carry a top-level `request_id`; emitting one keeps the
/// shape indistinguishable from a native error body. Same uniqueness construction as
/// `synth_message_id` (unix second + process-global atomic counter) — no new dependency.
fn synth_request_id() -> String {
    let seq = SYNTH_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("req_{:x}{:x}", unix_now_secs(), seq)
}

#[derive(Clone)]
pub(crate) struct AnthropicReader;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body once and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (error paths are already degraded; avoid the extra
        // parse+alloc on every non-2xx response).
        let (provider_code, structured_type) =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(json) => {
                    let error = json.get("error");
                    let provider_code = error
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_str())
                        .map(String::from);
                    let structured_type = error
                        .and_then(|e| e.get("type"))
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    (provider_code, structured_type)
                }
                Err(_) => (None, None),
            };

        // Anthropic signals context-length via the error MESSAGE (no distinct code).
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
            retry_after_secs: None,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);

        // context-length-exceeded (Anthropic returns 400 invalid_request_error). The lane
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

        // Prefer the HTTP status, then structured error codes, then substrings as a fallback.
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
            // Reuse the single lower-cased copy computed at the top of `classify` rather than
            // allocating a second one — on a verbose 429 body this avoids a redundant heap copy.
            if lower.contains("quota") && lower.contains("exhausted") {
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
            } else if let Some(arr) = system_val.as_array() {
                for block_val in arr {
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
                // Capture the stream's native identity so an anthropic→anthropic passthrough
                // re-emits the exact `message_start.message` an SDK expects (it reads
                // `message.id`/`message.model` to populate the assembled `Message`). Anthropic's
                // `message_start` has no `created` field, so `created` stays None on this path; the
                // writer synthesizes one only when translating from a protocol that omitted it.
                let id = msg.get("id").and_then(|i| i.as_str()).map(String::from);
                let model = msg.get("model").and_then(|m| m.as_str()).map(String::from);
                Some(IrStreamEvent::MessageStart {
                    role,
                    usage,
                    id,
                    created: None,
                    model,
                })
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
                // Carry the upstream error `type` through as-is: `Some("rate_limit_error")` when
                // present, `None` when the event omits it. Do NOT `unwrap_or_default()` into
                // `Some("")` — an empty-string type would make the writer emit `"type": ""` where a
                // native Anthropic error event carries either a real type or `null`. The writer
                // (write_response_event) already renders `None` as JSON `null`, so the absence
                // round-trips faithfully.
                let provider_signal = err_val
                    .get("type")
                    .and_then(|t| t.as_str())
                    .map(String::from);
                Some(IrStreamEvent::Error(IrError {
                    class: StatusClass::ClientError,
                    provider_signal,
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
        if let Some(arr) = content_val.as_array() {
            for block_val in arr {
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

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the native response identity so a same-protocol (anthropic→anthropic) passthrough
        // preserves it byte-for-byte. An official SDK's `Message` carries `id` ("msg_<rand>"),
        // `type` ("message"), `role`, `model`, `stop_reason`, `stop_sequence`, and `usage`; the
        // first four plus `stop_sequence` round-trip through these IR fields (role/model/stop_reason
        // are already parsed above; `type` is a constant the writer re-emits).
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        // Anthropic's non-streaming `Message` has no `created` field, so there is nothing to carry
        // through; the writer synthesizes one only on the cross-protocol path (where the IR field is
        // None) for SDKs that read it. `system_fingerprint` is an OpenAI concept Anthropic never
        // emits — left None so a same-protocol round-trip does not invent one.
        let stop_sequence = obj
            .get("stop_sequence")
            .and_then(|s| s.as_str())
            .map(String::from);

        Ok(crate::ir::IrResponse {
            role,
            content,
            stop_reason,
            usage,
            model,
            id,
            created: None,
            system_fingerprint: None,
            stop_sequence,
        })
    }
}

// Helper functions for IR mapping (used by read_request/write_request)
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
            let content = if let Some(arr) = content_val.as_array() {
                arr.iter().map(read_block).collect::<Result<_, _>>()?
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
    let content = if let Some(arr) = content_val.as_array() {
        arr.iter().map(read_block).collect::<Result<_, _>>()?
    } else {
        vec![crate::ir::IrBlock::Text {
            text: content_val.as_str().unwrap_or("").to_string(),
            cache_control: None,
            citations: Vec::new(),
        }]
    };

    Ok(crate::ir::IrMessage { role, content })
}

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

fn write_message(msg: &crate::ir::IrMessage) -> serde_json::Value {
    let role_str = match msg.role {
        crate::ir::IrRole::System => "system",
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        // Anthropic has no "tool" message role — tool results are carried as `user` messages whose
        // content holds `tool_result` block(s). (Reachable when translating an OpenAI `tool` message.)
        crate::ir::IrRole::Tool => "user",
    };
    let content_val: serde_json::Value = if msg.content.is_empty() {
        serde_json::Value::String("".to_string())
    } else {
        serde_json::Value::Array(msg.content.iter().map(write_block).collect())
    };
    serde_json::json!({ "role": role_str, "content": content_val })
}

fn write_tool(tool: &crate::ir::IrTool) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), serde_json::json!(tool.name));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), serde_json::json!(desc));
    }
    obj.insert("input_schema".to_string(), tool.input_schema.clone());
    serde_json::Value::Object(obj)
}

/// Anthropic writer implementation.
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
        // Anthropic authenticates via `x-api-key` (API keys) AND accepts `authorization: Bearer`
        // (OAuth/short-lived tokens). Both are emitted because this one function serves two modes:
        //   * static lane key  -> the configured API key,
        //   * passthrough       -> the *caller's* credential (forward.rs feeds the caller token in
        //                          as `key`), which callers present as `Authorization: Bearer`.
        // The passthrough path REQUIRES the `authorization` header to round-trip a caller's Bearer
        // token to the upstream (see test_support passthrough coverage), so it cannot be dropped
        // without breaking a stable public path. Both headers carry the same single credential.
        //
        // A key with bytes that aren't valid in an HTTP header value (e.g. a stray newline in the
        // env var) yields an empty header rather than panicking the worker — the upstream then
        // returns a clean 401 that the breaker classifies normally. This empty-value fallback is
        // strictly defense-in-depth: keys should be validated at config load. We emit one warning
        // so the misconfig (which would otherwise masquerade as an auth failure) is diagnosable.
        // The key bytes themselves are never logged.
        let safe = |label: &'static str, raw: String| {
            HeaderValue::from_str(&raw).unwrap_or_else(|_| {
                tracing::warn!(
                    header = label,
                    "anthropic auth credential contains bytes invalid for an HTTP header value \
                     (e.g. a trailing newline); sending an empty value, the upstream will return \
                     401 — check the key configuration"
                );
                HeaderValue::from_static("")
            })
        };
        vec![
            (
                HeaderName::from_static("x-api-key"),
                safe("x-api-key", key.to_string()),
            ),
            (
                HeaderName::from_static("authorization"),
                safe("authorization", format!("Bearer {key}")),
            ),
            (
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static(ANTHROPIC_API_VERSION),
            ),
        ]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn requires_max_tokens(&self) -> bool {
        // Anthropic Messages 400s with `max_tokens: Field required` when absent.
        true
    }

    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Native Anthropic error envelope: `{"type":"error","error":{"type":<kind>,"message":<msg>}}`
        // (see the Anthropic SDK / API error shape — the `anthropic.APIStatusError` family decodes
        // `error.type` into the typed exception, e.g. `RateLimitError`, and surfaces `error.message`).
        // Served as `application/json` by the caller, per the `ProtocolWriter::write_error` contract.
        // The generic `kind` strings the router emits are mapped to Anthropic's own error-type
        // vocabulary so a native SDK gets the exception it expects; an unrecognized `kind` is passed
        // through verbatim (it is already an Anthropic-style type, or a value we don't want to
        // silently rewrite — no `_ =>` swallow).
        let anthropic_type = match kind {
            // Generic router/auth/forward `kind`s → Anthropic's typed error vocabulary.
            "invalid_request" | "bad_request" => "invalid_request_error",
            "authentication" | "unauthorized" => "authentication_error",
            "permission" | "forbidden" => "permission_error",
            "not_found" => "not_found_error",
            "request_too_large" | "payload_too_large" => "request_too_large",
            "rate_limit" | "too_many_requests" => "rate_limit_error",
            "overloaded" => "overloaded_error",
            "timeout" => "timeout_error",
            "api_error" | "server_error" | "internal" => "api_error",
            // Already an Anthropic-native type (e.g. "invalid_request_error") or an unmapped value:
            // emit it unchanged rather than collapsing every unknown into one bucket.
            "invalid_request_error"
            | "authentication_error"
            | "permission_error"
            | "not_found_error"
            | "rate_limit_error"
            | "overloaded_error"
            | "timeout_error" => kind,
            other => other,
        };
        // Current Anthropic API error bodies carry a top-level `request_id` (`req_...`) alongside
        // the `error` object. busbar synthesizes this envelope itself (no upstream request to
        // forward), so mint one to match the native shape — the SDK doesn't require it to decode
        // the typed exception, but its absence is a distinguishability tell.
        serde_json::json!({
            "type": "error",
            "error": {
                "type": anthropic_type,
                "message": message,
            },
            "request_id": synth_request_id(),
        })
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

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                usage,
                id,
                model,
                ..
            } => {
                let role_str = match role {
                    crate::ir::IrRole::User => "user",
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                let mut msg_obj = serde_json::Map::new();
                // The native `message_start.message` is a skeleton Message an SDK reads
                // `id`/`type`/`role`/`model`/`content`/`usage` from (plus `stop_reason`/
                // `stop_sequence`, null at stream start). We emit that full skeleton whenever we
                // have identity to anchor it — i.e. the egress stream carried a native `id`/`model`
                // (same-protocol passthrough) or the cross-protocol decode populated either field.
                // When neither is present (a minimal `{role,usage}` event with no identity, which
                // is what a bare same-protocol fixture round-trips), we emit only `role`+`usage` so
                // the passthrough stays byte-faithful and does not fabricate a skeleton the source
                // never sent. Synthesize `id` only on the identity-bearing path where it's missing
                // (cross-protocol gave `model` but no Anthropic id), never on the bare path.
                let has_identity = id.is_some() || model.is_some();
                if has_identity {
                    let msg_id = id.clone().unwrap_or_else(synth_message_id);
                    msg_obj.insert("id".to_string(), serde_json::json!(msg_id));
                    msg_obj.insert("type".to_string(), serde_json::json!("message"));
                }
                msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                if let Some(model_str) = model {
                    msg_obj.insert("model".to_string(), serde_json::json!(model_str));
                }
                if has_identity {
                    msg_obj.insert("content".to_string(), serde_json::Value::Array(Vec::new()));
                    msg_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                    msg_obj.insert("stop_sequence".to_string(), serde_json::Value::Null);
                }
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
                // Native Anthropic in-stream error event:
                // `{"type":"error","error":{"type":<type>,"message":<msg>}}`. The SDK's streaming
                // decoder reads BOTH `error.type` (→ typed exception) AND `error.message` (the
                // human-readable description, a required field in the documented shape). Omitting
                // `message` leaves the SDK's `APIError` with an undefined description and is a
                // distinguishability tell vs a native event.
                let mut error_obj = serde_json::Map::new();
                match err.provider_signal {
                    Some(ref ps) => {
                        error_obj.insert("type".to_string(), serde_json::json!(ps));
                    }
                    None => {
                        error_obj.insert("type".to_string(), serde_json::Value::Null);
                    }
                }
                // The IR carries no separate message string (IrError == CanonicalSignal, which has
                // no `message` field), so derive a human-readable one from the signal: prefer the
                // provider type when present, otherwise a generic fallback. Always non-empty so the
                // SDK's `error.message` is never undefined/null.
                let message = match err.provider_signal.as_deref() {
                    Some(ps) if !ps.is_empty() => format!("upstream error: {ps}"),
                    Some(_) | None => "an error occurred while streaming the response".to_string(),
                };
                error_obj.insert("message".to_string(), serde_json::json!(message));
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("error".to_string(), serde_json::Value::Object(error_obj));
                Some(("error".to_string(), serde_json::Value::Object(data_obj)))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // id: an official SDK's `Message.id` is `"msg_<rand>"`. Three cases:
        //   * same-protocol passthrough — the upstream id was captured into `resp.id`; re-emit it
        //     verbatim so a native SDK sees the exact id its backend assigned.
        //   * cross-protocol with a foreign id absent — `resp.id == None` AND `resp.created` is set
        //     (every cross-protocol reader that lacks an Anthropic id still records `created`, e.g.
        //     OpenAI's `created`), so synthesize a protocol-correct `msg_<rand>`. The SDK only
        //     requires the `msg_` prefix + uniqueness, which `synth_message_id` guarantees with no
        //     new crate.
        //   * minimal same-protocol IR with neither id nor created (a body that carried no id) —
        //     omit `id` rather than fabricate one, so a read→write→read round-trip is lossless
        //     (synthesizing here would make the re-read IR carry an id the original lacked).
        // This keys synthesis off "did we cross a protocol boundary" (proxied by `created` being
        // populated) rather than off `id` alone, preserving same-protocol idempotence.
        match (&resp.id, resp.created) {
            (Some(id), _) => {
                obj.insert("id".to_string(), serde_json::json!(id));
            }
            (None, Some(_)) => {
                obj.insert("id".to_string(), serde_json::json!(synth_message_id()));
            }
            (None, None) => {}
        }

        // type/role are constant for a Messages API response ("message"/"assistant").
        obj.insert("type".to_string(), serde_json::json!("message"));
        obj.insert("role".to_string(), serde_json::json!("assistant"));

        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            obj.insert("model".to_string(), serde_json::json!(model));
        }

        // content blocks
        let content_array: Vec<serde_json::Value> = resp.content.iter().map(write_block).collect();
        obj.insert(
            "content".to_string(),
            serde_json::Value::Array(content_array),
        );

        // stop_reason (omit if None — a native body omits it until the turn ends, and omitting
        // keeps same-protocol round-trips lossless)
        if let Some(ref reason) = resp.stop_reason {
            obj.insert("stop_reason".to_string(), serde_json::json!(reason));
        }

        // stop_sequence: emit the captured value when a stop string actually matched; omit when
        // None so a same-protocol round-trip of a body without one stays byte-faithful.
        if let Some(ref seq) = resp.stop_sequence {
            obj.insert("stop_sequence".to_string(), serde_json::json!(seq));
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

#[cfg(test)]
mod anthropic_hardening_tests {
    use super::*;

    /// auth_headers carries the canonical x-api-key plus the passthrough-required authorization
    /// header and the anthropic-version header, each with the configured credential verbatim.
    #[test]
    fn auth_headers_emits_x_api_key_authorization_and_version() {
        let headers = AnthropicWriter.auth_headers("secret-key");
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();

        assert!(names.contains(&"x-api-key"), "x-api-key must be present");
        assert!(
            names.contains(&"authorization"),
            "authorization (passthrough Bearer) must be present"
        );
        assert!(
            names.contains(&"anthropic-version"),
            "anthropic-version must be present"
        );

        let value = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.as_str() == name)
                .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
        };
        assert_eq!(value("x-api-key").as_deref(), Some("secret-key"));
        assert_eq!(value("authorization").as_deref(), Some("Bearer secret-key"));
    }

    /// A key with bytes invalid for an HTTP header value (e.g. a trailing newline) must not panic
    /// the worker; both credential headers fall back to empty so the upstream returns a clean 401.
    #[test]
    fn auth_headers_invalid_key_falls_back_to_empty_no_panic() {
        let headers = AnthropicWriter.auth_headers("bad\nkey");
        let value = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.as_str() == name)
                .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
        };
        assert_eq!(value("x-api-key").as_deref(), Some(""));
        assert_eq!(value("authorization").as_deref(), Some(""));
        // anthropic-version is static and unaffected by the bad key.
        assert_eq!(value("anthropic-version").as_deref(), Some("2023-06-01"));
    }

    /// extract_error parses the body once and surfaces both provider_code and structured_type.
    #[test]
    fn extract_error_parses_both_fields() {
        let body = br#"{"error":{"type":"invalid_request_error","code":"some_code"}}"#;
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.http_status, 400);
        assert_eq!(raw.provider_code.as_deref(), Some("some_code"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
    }

    /// A non-JSON error body must not yield codes from the structured fields, but the
    /// context-length text heuristic must still fire when the message indicates it.
    #[test]
    fn extract_error_non_json_body() {
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, b"not json at all");
        assert_eq!(raw.provider_code, None);
        assert_eq!(raw.structured_type, None);
    }

    /// Context-length is signalled via the error message; the single-parse refactor must preserve
    /// the canonical code synthesis from the body text.
    #[test]
    fn extract_error_context_length_from_message() {
        let body = br#"{"error":{"type":"invalid_request_error","message":"prompt is too long"}}"#;
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded")
        );
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
    }

    /// write_error must produce the NATIVE Anthropic envelope
    /// `{"type":"error","error":{"type":<mapped kind>,"message":<msg>}}`, mapping a generic router
    /// `kind` into Anthropic's typed error vocabulary so a native SDK decodes the right exception.
    #[test]
    fn write_error_native_anthropic_envelope_shape() {
        let v = AnthropicWriter.write_error(404, "not_found", "model 'x' not found");
        // Top-level discriminator is "error" (Anthropic), NOT the generic `{"error":{...}}`.
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
        let err = v.get("error").expect("error object present");
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("not_found_error"),
            "generic `not_found` must map to Anthropic `not_found_error`"
        );
        assert_eq!(
            err.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found")
        );
        // Round-trips as JSON (the caller serves it as application/json) — no panic.
        let s = serde_json::to_string(&v).expect("must serialize");
        let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
    }

    /// A `kind` already in Anthropic's vocabulary passes through unchanged (no double-mapping, no
    /// `_ =>` collapse), and a representative sample of generic kinds map to the right native type.
    #[test]
    fn write_error_kind_vocabulary_mapping() {
        let map_of = |kind: &str| {
            AnthropicWriter
                .write_error(400, kind, "m")
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        };
        assert_eq!(map_of("rate_limit").as_deref(), Some("rate_limit_error"));
        assert_eq!(
            map_of("authentication").as_deref(),
            Some("authentication_error")
        );
        assert_eq!(
            map_of("invalid_request").as_deref(),
            Some("invalid_request_error")
        );
        // Already-native type is emitted verbatim.
        assert_eq!(
            map_of("invalid_request_error").as_deref(),
            Some("invalid_request_error")
        );
        // Unknown/unmapped kind passes through rather than being swallowed into one bucket.
        assert_eq!(
            map_of("some_custom_kind").as_deref(),
            Some("some_custom_kind")
        );
    }

    /// Same-protocol (anthropic→anthropic) passthrough must preserve the upstream response identity:
    /// `read_response` captures `id`/`stop_sequence` (and model/stop_reason), and `write_response`
    /// re-emits them verbatim alongside the constant `type`/`role`. Mirrors the exact non-streaming
    /// `Message` shape an official SDK assembles.
    #[test]
    fn read_then_write_response_preserves_identity() {
        let body = serde_json::json!({
            "id": "msg_01XYZabc123",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "stop_sequence",
            "stop_sequence": "\n\nHuman:",
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });
        let ir = AnthropicReader.read_response(&body).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("msg_01XYZabc123"));
        assert_eq!(ir.model.as_deref(), Some("claude-opus-4-8"));
        assert_eq!(ir.stop_reason.as_deref(), Some("stop_sequence"));
        assert_eq!(ir.stop_sequence.as_deref(), Some("\n\nHuman:"));

        let out = AnthropicWriter.write_response(&ir);
        assert_eq!(
            out.get("id").and_then(|v| v.as_str()),
            Some("msg_01XYZabc123"),
            "id must round-trip verbatim on same-protocol passthrough"
        );
        assert_eq!(out.get("type").and_then(|v| v.as_str()), Some("message"));
        assert_eq!(out.get("role").and_then(|v| v.as_str()), Some("assistant"));
        assert_eq!(
            out.get("model").and_then(|v| v.as_str()),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            out.get("stop_reason").and_then(|v| v.as_str()),
            Some("stop_sequence")
        );
        assert_eq!(
            out.get("stop_sequence").and_then(|v| v.as_str()),
            Some("\n\nHuman:")
        );
    }

    /// Same-protocol streaming `message_start` passthrough must preserve `id`/`model` and re-emit
    /// the SDK-expected skeleton (`id`/`type`/`role`/`model`/`content`/`usage`).
    #[test]
    fn message_start_roundtrip_preserves_id_and_model() {
        let data = serde_json::json!({
            "message": {
                "id": "msg_stream_01",
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-4-8",
                "content": [],
                "usage": {"input_tokens": 7, "output_tokens": 0}
            }
        });
        let ev = AnthropicReader
            .read_response_event("message_start", &data)
            .expect("message_start parses");
        match &ev {
            IrStreamEvent::MessageStart { id, model, .. } => {
                assert_eq!(id.as_deref(), Some("msg_stream_01"));
                assert_eq!(model.as_deref(), Some("claude-opus-4-8"));
            }
            _ => panic!("expected MessageStart"),
        }
        let (et, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("writes message_start");
        assert_eq!(et, "message_start");
        let msg = out.get("message").expect("message object");
        assert_eq!(
            msg.get("id").and_then(|v| v.as_str()),
            Some("msg_stream_01")
        );
        assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
        assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
        assert_eq!(
            msg.get("model").and_then(|v| v.as_str()),
            Some("claude-opus-4-8")
        );
        assert!(
            msg.get("content").and_then(|c| c.as_array()).is_some(),
            "content[] must be present for an SDK to initialize its Message"
        );
    }

    /// Cross-protocol write (the backend supplied no Anthropic id, but a non-Anthropic reader
    /// recorded `created`) must SYNTHESIZE a protocol-correct `msg_`-prefixed id without panicking,
    /// and the synthesized id must be unique across calls (timestamp + atomic counter).
    #[test]
    fn cross_protocol_write_synthesizes_valid_unique_id() {
        let make = || crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "x".to_string(),
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
            model: Some("gpt-4o".to_string()),
            id: None,
            // `created` populated → marks a cross-protocol response → synthesis fires.
            created: Some(1_700_000_000),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out1 = AnthropicWriter.write_response(&make());
        let out2 = AnthropicWriter.write_response(&make());
        let id1 = out1.get("id").and_then(|v| v.as_str()).expect("synth id 1");
        let id2 = out2.get("id").and_then(|v| v.as_str()).expect("synth id 2");
        assert!(
            id1.starts_with("msg_"),
            "synthesized id must carry the Anthropic `msg_` prefix, got {id1}"
        );
        assert!(
            id1.len() > "msg_".len(),
            "synthesized id must have a suffix"
        );
        assert_ne!(id1, id2, "synthesized ids must be unique across calls");
        // Shape stays SDK-valid: type/role/content present, no panic.
        assert_eq!(out1.get("type").and_then(|v| v.as_str()), Some("message"));
    }

    /// A minimal same-protocol IR carrying neither `id` nor `created` must NOT fabricate an id —
    /// omitting it keeps a read→write→read round-trip lossless (the synthesis is gated to the
    /// cross-protocol path only).
    #[test]
    fn minimal_same_protocol_write_omits_synthesized_id() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        assert!(
            out.get("id").is_none(),
            "no id must be fabricated when neither id nor created is set (loss-free passthrough)"
        );
    }

    /// `synth_message_id` must never panic and always returns a non-empty `msg_`-prefixed id.
    #[test]
    fn synth_message_id_is_well_formed() {
        let id = synth_message_id();
        assert!(id.starts_with("msg_"));
        assert!(id.len() > "msg_".len());
    }

    /// `synth_request_id` must never panic and always returns a non-empty `req_`-prefixed id.
    #[test]
    fn synth_request_id_is_well_formed() {
        let id = synth_request_id();
        assert!(id.starts_with("req_"));
        assert!(id.len() > "req_".len());
    }

    /// write_response_event(Error(...)) must serialize the NATIVE Anthropic in-stream error shape:
    /// event type `"error"`, with `error.type` carrying the provider signal AND a non-empty
    /// `error.message` (the SDK's `APIError` reads both). Regression guard for the message-omission
    /// and the JSON-key shape (a wrong key would silently break SDK decoding into a hang).
    #[test]
    fn write_response_event_error_serializes_native_shape() {
        let err = IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("rate_limit_error".to_string()),
            retry_after: None,
        };
        let (event_type, data) = AnthropicWriter
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("error event must serialize");
        assert_eq!(event_type, "error");
        let error_obj = data.get("error").expect("error sub-object present");
        assert_eq!(
            error_obj.get("type").and_then(|t| t.as_str()),
            Some("rate_limit_error"),
            "error.type must carry the provider signal"
        );
        let message = error_obj
            .get("message")
            .and_then(|m| m.as_str())
            .expect("error.message must be present (SDK reads it)");
        assert!(
            !message.is_empty(),
            "error.message must be non-empty so the SDK's APIError is never undefined"
        );
        // Round-trips as valid JSON — no panic on the error path.
        let s = serde_json::to_string(&data).expect("must serialize");
        let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
    }

    /// When the upstream error event carries no `type`, the writer must emit `error.type: null`
    /// (not `""`) and still a non-empty `message`. Guards finding #7 (Option carried through, no
    /// `unwrap_or_default()`) end-to-end and finding #3 (message always present).
    #[test]
    fn write_response_event_error_null_type_when_signal_absent() {
        let err = IrError {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        };
        let (event_type, data) = AnthropicWriter
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("error event must serialize");
        assert_eq!(event_type, "error");
        let error_obj = data.get("error").expect("error sub-object present");
        assert!(
            error_obj.get("type").map(|t| t.is_null()).unwrap_or(false),
            "error.type must be JSON null when no provider signal, not an empty string"
        );
        assert!(
            error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .map(|m| !m.is_empty())
                .unwrap_or(false),
            "error.message must still be present and non-empty"
        );
    }

    /// The reader must carry a missing error `type` through as `None` (not `Some("")`), so a
    /// `read -> write` of a type-less error event yields `error.type: null` rather than `""`.
    /// Regression guard for finding #7.
    #[test]
    fn read_error_event_without_type_carries_none() {
        let data = serde_json::json!({ "error": { "message": "boom" } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        match ev {
            IrStreamEvent::Error(err) => assert_eq!(
                err.provider_signal, None,
                "missing error.type must be None, not Some(\"\")"
            ),
            other => panic!("expected Error event, got {other:?}"),
        }
    }

    /// A reader-captured error type round-trips through the writer verbatim.
    #[test]
    fn read_error_event_with_type_round_trips() {
        let data = serde_json::json!({ "error": { "type": "overloaded_error" } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        let (_, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("writes error event");
        assert_eq!(
            out.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("overloaded_error")
        );
    }

    /// write_error must include a synthesized top-level `request_id` (`req_...`) to match the native
    /// Anthropic error envelope, alongside the `type`/`error` fields. Regression guard for finding #6.
    #[test]
    fn write_error_includes_synthesized_request_id() {
        let v = AnthropicWriter.write_error(429, "rate_limit", "slow down");
        let request_id = v
            .get("request_id")
            .and_then(|r| r.as_str())
            .expect("top-level request_id must be present");
        assert!(
            request_id.starts_with("req_"),
            "request_id must carry the Anthropic `req_` prefix, got {request_id}"
        );
        assert!(
            request_id.len() > "req_".len(),
            "request_id must have a suffix"
        );
        // The error envelope's other fields are untouched.
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("rate_limit_error")
        );
    }

    /// Finding #3 regression: a `system` field in ARRAY form must be read via `as_array()` (no
    /// `is_array()`/`unwrap()` pair on the request path) and yield one IR block per element without
    /// panicking. Guards that the unwrap-removal refactor preserves array-system behavior.
    #[test]
    fn read_request_array_system_parses_blocks() {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "system": [
                {"type": "text", "text": "you are helpful"},
                {"type": "text", "text": "be concise"}
            ],
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("array system must parse without panic");
        assert_eq!(ir.system.len(), 2, "both system text blocks must be read");
        match &ir.system[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "you are helpful"),
            other => panic!("expected text block, got {other:?}"),
        }
    }

    /// Finding #3 regression: a non-array, non-string `system` value (e.g. a number) must NOT panic
    /// — the refactored `as_array()`/`is_string()` guards simply produce no system blocks rather
    /// than reaching a `.unwrap()`. Direct guard that the unwrap is gone from the request path.
    #[test]
    fn read_request_non_array_non_string_system_is_ignored_no_panic() {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "system": 12345,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("unexpected system shape must not panic the request path");
        assert!(
            ir.system.is_empty(),
            "a non-array/non-string system yields no blocks (no unwrap panic)"
        );
    }

    /// Finding #3 regression: a `tool_result` block whose `content` is an ARRAY of nested blocks
    /// must be read via `as_array()` (no `is_array()`/`unwrap()`) and recurse into each nested
    /// block without panic. Exercises the read_block tool_result array branch.
    #[test]
    fn read_block_tool_result_array_content_parses() {
        let block = serde_json::json!({
            "type": "tool_result",
            "tool_use_id": "toolu_01",
            "content": [
                {"type": "text", "text": "result line 1"},
                {"type": "text", "text": "result line 2"}
            ]
        });
        let ir = read_block(&block).expect("tool_result array content must parse without panic");
        match ir {
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                assert_eq!(tool_use_id, "toolu_01");
                assert_eq!(content.len(), 2, "both nested blocks must be read");
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    /// Finding #3 regression: a `read_response` body whose top-level `content` is an array must be
    /// read via `as_array()` without the removed `unwrap()`. Guards the response-path array read.
    #[test]
    fn read_response_array_content_parses_no_unwrap() {
        let body = serde_json::json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "a"},
                {"type": "text", "text": "b"}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 2}
        });
        let ir = AnthropicReader
            .read_response(&body)
            .expect("array content must parse without panic");
        assert_eq!(ir.content.len(), 2);
    }
}
