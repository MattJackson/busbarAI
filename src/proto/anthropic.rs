// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Anthropic protocol reader/writer implementation.

use super::*;

/// Value of the required `anthropic-version` request header (the Messages API version busbar
/// targets). Bump when adopting a newer Anthropic API version.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

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

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        Ok(crate::ir::IrResponse {
            role,
            content,
            stop_reason,
            usage,
            model,
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
        // A key with bytes that aren't valid in an HTTP header (e.g. a stray newline in the env
        // var) yields an empty header rather than panicking the worker — the upstream then returns
        // a clean 401 that the breaker classifies normally.
        vec![
            (
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(key).unwrap_or_else(|_| HeaderValue::from_static("")),
            ),
            (
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&format!("Bearer {key}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
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
