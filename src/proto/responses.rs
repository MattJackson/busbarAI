// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI Responses API protocol reader/writer implementation.

use super::*;

#[derive(Clone)]
pub(crate) struct ResponsesReader;

impl ProtocolReader for ResponsesReader {
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
                            let (media_type, data) = if image_url.starts_with("data:") {
                                let parts: Vec<&str> = image_url.splitn(3, ';').collect();
                                if parts.len() >= 2 && parts[0].starts_with("data:") {
                                    let mt =
                                        parts[0].strip_prefix("data:").unwrap_or("image/unknown");
                                    let full_base64 = parts
                                        .get(2)
                                        .map(|s| s.trim_start_matches(',').to_string())
                                        .or_else(|| {
                                            image_url
                                                .split(';')
                                                .nth(2)
                                                .map(|s| s.trim_start_matches(',').to_string())
                                        });
                                    (mt.to_string(), full_base64.unwrap_or_default())
                                } else {
                                    ("image/unknown".to_string(), image_url.to_string())
                                }
                            } else {
                                ("image/unknown".to_string(), image_url.to_string())
                            };
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
                            let input =
                                serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);

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
                        Some("reasoning") => {}
                        _ => {}
                    }

                    // Also handle role/content structured items (user/assistant messages)
                    if item.get("role").is_some() {
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
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
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
                if !state.text_block_open && !delta.is_empty() {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: 0,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
                if !delta.is_empty() || state.text_block_open {
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| v as usize);
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

                    let stop_reason = match status {
                        "completed" => Some("end_turn".to_string()),
                        "incomplete" | "failed" => {
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
                        _ => Some("end_turn".to_string()),
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

                    out.push(IrStreamEvent::MessageDelta { stop_reason, usage });
                    out.push(IrStreamEvent::MessageStop);
                } else if event_type == "response.failed" {
                    let stop_reason = Some("end_turn".to_string());
                    let usage = crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };
                    out.push(IrStreamEvent::MessageDelta { stop_reason, usage });
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
                        let input =
                            serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);

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

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
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
            if image_url.starts_with("data:") {
                let parts: Vec<&str> = image_url.splitn(3, ';').collect();
                if parts.len() >= 2 && parts[0].starts_with("data:") {
                    let mt = parts[0].strip_prefix("data:").unwrap_or("image/unknown");
                    let full_base64 = parts
                        .get(2)
                        .map(|s| s.trim_start_matches(',').to_string())
                        .or_else(|| {
                            image_url
                                .split(';')
                                .nth(2)
                                .map(|s| s.trim_start_matches(',').to_string())
                        });
                    Ok(crate::ir::IrBlock::Image {
                        media_type: mt.to_string(),
                        data: full_base64.unwrap_or_default(),
                    })
                } else {
                    Ok(crate::ir::IrBlock::Image {
                        media_type: "image/unknown".to_string(),
                        data: image_url.to_string(),
                    })
                }
            } else {
                Ok(crate::ir::IrBlock::Image {
                    media_type: "image/unknown".to_string(),
                    data: format!("// note: non-data URL - {}", image_url),
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
                                let image_url = format!("data:{};base64,{}", media_type, data);
                                content_arr.push(serde_json::json!({
                                    "type": "input_image",
                                    "image_url": image_url
                                }));
                            }
                            crate::ir::IrBlock::ToolUse { id, name, input } => {
                                let args_str = serde_json::to_string(input)
                                    .unwrap_or_else(|_| "{}".to_string());
                                input_arr.push(serde_json::json!({
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

                                input_arr.push(serde_json::json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": output_text
                                }));
                            }
                            crate::ir::IrBlock::Thinking { .. } => {}
                        }
                    }

                    let mut msg_obj = serde_json::Map::new();
                    msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                    msg_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
                    input_arr.push(serde_json::Value::Object(msg_obj));
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

        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { .. } => Some((
                "response.created".to_string(),
                serde_json::json!({
                    "response": {
                        "object": "response",
                        "status": "in_progress"
                    }
                }),
            )),

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

            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                let status = match stop_reason.as_deref() {
                    Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
                    Some("max_tokens") => "incomplete",
                    Some("safety") => "incomplete",
                    _ => "failed",
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

                Some((
                    if status == "failed" {
                        "response.failed".to_string()
                    } else {
                        "response.completed".to_string()
                    },
                    serde_json::json!({ "response": resp_obj }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => Some((
                "response.failed".to_string(),
                serde_json::json!({
                    "error": {
                        "message": err.provider_signal.clone().unwrap_or_else(|| "error".to_string())
                    }
                }),
            )),
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let status = match resp.stop_reason.as_deref() {
            Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
            Some("max_tokens") => "incomplete",
            Some("safety") => "incomplete",
            _ => "failed",
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
                _ => {}
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
        obj.insert("object".to_string(), serde_json::json!("response"));
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
        let json = serde_json::json!({
            "object": "response",
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
}
