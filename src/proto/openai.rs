// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI protocol reader/writer implementation.

use super::*;

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
