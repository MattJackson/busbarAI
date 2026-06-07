// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Cohere v2 protocol reader/writer implementation.

use super::*;

#[derive(Clone)]
pub(crate) struct CohereReader;

impl ProtocolReader for CohereReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("message")
                .and_then(|m| m.as_str())
                .map(String::from)
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error_type")
                .and_then(|e| e.as_str())
                .map(String::from)
        } else {
            None
        };

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
                    } else if content_val.is_array() {
                        for block_val in content_val.as_array().unwrap() {
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
                        if content_val.is_array() {
                            content_val
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter_map(|b| b.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        } else if content_val.is_string() {
                            content_val.as_str().unwrap_or("").to_string()
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
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id: None,
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

                out.push(IrStreamEvent::MessageDelta { stop_reason, usage });
                out.push(IrStreamEvent::MessageStop);
            }
            _ => {}
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

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id: None,
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

            if msg.role == crate::ir::IrRole::Tool {
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
                        tool_result_obj.insert(
                            "content".to_string(),
                            serde_json::Value::String(text_parts.join(" ")),
                        );
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                    }
                }
            } else if msg.role != crate::ir::IrRole::Tool {
                messages_arr.push(serde_json::Value::Object(msg_obj));
            }
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
        out.insert("stream".to_string(), serde_json::json!(req.stream));
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, .. } => {
                let cohere_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "message-start",
                        "delta": { "message": { "role": cohere_role } }
                    }),
                ))
            }

            IrStreamEvent::BlockStart { index: _, block } => match block {
                crate::ir::IrBlockMeta::Text => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "content-start",
                        "index": 0,
                        "delta": {
                            "message": {
                                "content": { "type": "text", "text": "" }
                            }
                        }
                    }),
                )),
                _ => None,
            },

            IrStreamEvent::BlockDelta { index: _, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "content-delta",
                        "index": 0,
                        "delta": { "message": { "content": text } }
                    }),
                )),
                crate::ir::IrDelta::InputJsonDelta(_) => None,
                crate::ir::IrDelta::ThinkingDelta(_) => None,
                crate::ir::IrDelta::SignatureDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index: _ } => Some((
                "".to_string(),
                serde_json::json!({ "type": "content-end", "index": 0 }),
            )),

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage: _,
            } => {
                let cohere_finish_reason = match stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => "COMPLETE".to_string(),
                    Some("max_tokens") => "MAX_TOKENS".to_string(),
                    Some("tool_use") => "TOOL_CALL".to_string(),
                    Some("safety") => "ERROR".to_string(),
                    Some(reason) => reason.to_uppercase(),
                    None => "COMPLETE".to_string(),
                };
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "message-end",
                        "delta": { "finish_reason": cohere_finish_reason }
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

        if !tool_calls_arr.is_empty() {
            out.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls_arr),
            );
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

        out.insert("id".to_string(), serde_json::Value::String(String::new()));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out.insert("model".to_string(), serde_json::json!(model));
        }
        out.insert(
            "finish_reason".to_string(),
            serde_json::json!(cohere_finish_reason),
        );
        out.insert(
            "message".to_string(),
            serde_json::json!({ "role": "assistant", "content": content_arr }),
        );
        // Wrap tokens under "tokens" key per Cohere API spec
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("tokens".to_string(), serde_json::Value::Object(tokens_map));
        out.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(out)
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
    }

    #[test]
    fn test_write_response_roundtrip() {
        let json = serde_json::json!({
            "id": "",
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
        assert_eq!(
            data.get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str()),
            Some("hi")
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
        let tool_calls = json
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .expect("tool_calls array must be present");
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
}
