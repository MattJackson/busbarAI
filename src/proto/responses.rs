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
        let stream = false;

        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "instructions",
            "input",
            "tools",
            "max_output_tokens",
            "temperature",
            "metadata",
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
        _event_type: &str,
        _data: &serde_json::Value,
        _state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        Vec::new()
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let _ = body;
        Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(
                "responses read_response not yet implemented (B-540b)".to_string(),
            ),
            retry_after: None,
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
            HeaderValue::from_str(&format!("Bearer {}", key)).expect("bearer token is valid"),
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

    fn write_response_event(&self, _ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        None
    }

    #[allow(dead_code)]
    fn write_response(&self, _resp: &crate::ir::IrResponse) -> serde_json::Value {
        serde_json::json!({})
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
}
