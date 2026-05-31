// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Gemini protocol reader/writer implementation.

use super::*;

#[derive(Clone)]
pub(crate) struct GeminiReader;

impl ProtocolReader for GeminiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.as_object())
                .and_then(|e_obj| e_obj.get("code"))
                .and_then(|c| c.as_str())
                .map(String::from)
                .or_else(|| {
                    json.get("error")
                        .and_then(|e| e.as_object())
                        .and_then(|e_obj| e_obj.get("status"))
                        .and_then(|s| s.as_str())
                        .map(String::from)
                })
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.as_object())
                .and_then(|e_obj| e_obj.get("status"))
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
        let text = String::from_utf8_lossy(body);
        let lower = text.to_lowercase();

        // context-length-exceeded via message pattern
        if lower.contains("input is longer than the maximum number of tokens")
            || (lower.contains("maximum-tokens") && lower.contains("requested"))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length_exceeded".to_string()),
                retry_after: None,
            };
        }

        // 429 → RateLimit
        if status == StatusCode::TOO_MANY_REQUESTS {
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429".to_string()),
                retry_after: None,
            };
        }

        // 401/403 → Auth
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: Some("auth".to_string()),
                retry_after: None,
            };
        }

        // 5xx → ServerError
        if status.is_server_error() {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        // 4xx (other) → ClientError
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

        // Handle systemInstruction (Gemini uses this for system content)
        if let Some(sys_instr) = obj.get("systemInstruction") {
            if let Some(parts_arr) = sys_instr.get("parts").and_then(|p| p.as_array()) {
                for part in parts_arr {
                    if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                        system_blocks.push(crate::ir::IrBlock::Text {
                            text: text_val.to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                }
            }
        }

        // Handle contents array (messages)
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(contents_arr) = obj.get("contents").and_then(|c| c.as_array()) {
            for content_val in contents_arr {
                let role_str = content_val
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "model" => crate::ir::IrRole::Assistant,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some("ir_parse".to_string()),
                            retry_after: None,
                        })
                    }
                };

                let mut msg_content = Vec::new();
                if let Some(parts_arr) = content_val.get("parts").and_then(|p| p.as_array()) {
                    for part in parts_arr {
                        // Text part
                        if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text_val.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        }
                        // FunctionCall (ToolUse)
                        else if let Some(func_call) = part.get("functionCall") {
                            let name = func_call
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let args = func_call
                                .get("args")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);
                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id: String::new(),
                                name,
                                input: args,
                            });
                        }
                        // FunctionResponse (ToolResult)
                        else if let Some(func_resp) = part.get("functionResponse") {
                            let name = func_resp
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let response_val = func_resp
                                .get("response")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);
                            // Convert response to string representation for content
                            let response_text = serde_json::to_string(&response_val)
                                .unwrap_or_else(|_| "unknown".to_string());
                            msg_content.push(crate::ir::IrBlock::ToolResult {
                                tool_use_id: name,
                                content: vec![crate::ir::IrBlock::Text {
                                    text: response_text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                                is_error: false,
                            });
                        }
                        // InlineData (Image)
                        else if let Some(inline_data) = part.get("inlineData") {
                            let mime_type = inline_data
                                .get("mimeType")
                                .and_then(|m| m.as_str())
                                .unwrap_or("")
                                .to_string();
                            let data = inline_data
                                .get("data")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();
                            msg_content.push(crate::ir::IrBlock::Image {
                                media_type: mime_type,
                                data,
                            });
                        }
                    }
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        }

        // Handle tools array (functionDeclarations)
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_arr) = obj.get("tools").and_then(|t| t.as_array()) {
            for tool_val in tools_arr {
                // Gemini has functionDeclarations inside tools
                if let Some(func_decls) = tool_val
                    .get("functionDeclarations")
                    .and_then(|f| f.as_array())
                {
                    for func_decl in func_decls {
                        let name = func_decl
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = func_decl
                            .get("description")
                            .and_then(|d| d.as_str().map(String::from));
                        let parameters = func_decl
                            .get("parameters")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);

                        tools.push(crate::ir::IrTool {
                            name,
                            description,
                            input_schema: parameters,
                        });
                    }
                }
            }
        }

        // Extract scalar fields and extra
        let max_tokens = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("maxOutputTokens"))
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .map(|v| v as u32);
        let temperature = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("temperature"))
            .and_then(|v| v.as_f64());
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect unmodeled top-level keys into extra (excluding modeled ones)
        let modeled_keys: std::collections::HashSet<&str> = [
            "contents",
            "tools",
            "systemInstruction",
            "generationConfig",
            "stream",
            "tool_config",
        ]
        .iter()
        .cloned()
        .collect();

        // model is modeled but we preserve it in extra for round-trip identity
        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
        }

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
        // Gemini streaming uses read_response_events (fan-out); this singular form is unused.
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

        // 1. MessageStart exactly once on first chunk
        if !state.started {
            state.started = true;
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
            });
        }

        let candidates = data.get("candidates").and_then(|c| c.as_array());

        if let Some(cands) = candidates {
            for candidate in cands {
                // 2. Process content parts (text + functionCall)
                if let Some(content) = candidate.get("content") {
                    let role_val = content.get("role").and_then(|r| r.as_str()).unwrap_or("");

                    if role_val == "model" || role_val.is_empty() {
                        if let Some(parts_arr) = content.get("parts").and_then(|p| p.as_array()) {
                            let mut ir_idx: usize = 0;

                            for part in parts_arr {
                                // Text block
                                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                    if !text.is_empty() {
                                        if !state.text_block_open {
                                            state.text_block_open = true;
                                            out.push(IrStreamEvent::BlockStart {
                                                index: ir_idx,
                                                block: crate::ir::IrBlockMeta::Text,
                                            });
                                        }
                                        out.push(IrStreamEvent::BlockDelta {
                                            index: ir_idx,
                                            delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                        });
                                    }
                                }

                                // FunctionCall (ToolUse) - Gemini sends whole args, not streamed
                                if let Some(func_call) = part.get("functionCall") {
                                    let name_val = func_call
                                        .get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("")
                                        .to_string();

                                    if !name_val.is_empty() {
                                        // Open tool block at next index (after text)
                                        ir_idx += 1;
                                        let args = func_call
                                            .get("args")
                                            .cloned()
                                            .unwrap_or(serde_json::Value::Null);

                                        out.push(IrStreamEvent::BlockStart {
                                            index: ir_idx,
                                            block: crate::ir::IrBlockMeta::ToolUse {
                                                id: String::new(),
                                                name: name_val.clone(),
                                            },
                                        });

                                        // Emit the whole args as InputJsonDelta (Gemini doesn't stream functionCall)
                                        let args_str =
                                            serde_json::to_string(&args).unwrap_or_default();
                                        out.push(IrStreamEvent::BlockDelta {
                                            index: ir_idx,
                                            delta: crate::ir::IrDelta::InputJsonDelta(args_str),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. finishReason → close blocks + MessageDelta + MessageStop
                if let Some(finish_reason_val) =
                    candidate.get("finishReason").and_then(|r| r.as_str())
                {
                    let stop_reason = match finish_reason_val {
                        "STOP" => "end_turn".to_string(),
                        "MAX_TOKENS" => "max_tokens".to_string(),
                        "SAFETY" => "safety".to_string(),
                        other => other.to_lowercase(),
                    };

                    // Close text block first if open
                    if state.text_block_open {
                        state.text_block_open = false;
                        out.push(IrStreamEvent::BlockStop { index: 0 });
                    }

                    // Close tools in ascending order (track via open_tools)
                    for oai_idx in std::mem::take(&mut state.open_tools) {
                        out.push(IrStreamEvent::BlockStop { index: oai_idx });
                    }

                    // Parse usageMetadata if present
                    let usage = data
                        .get("usageMetadata")
                        .map(|u| crate::ir::IrUsage {
                            input_tokens: u
                                .get("promptTokenCount")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            output_tokens: u
                                .get("candidatesTokenCount")
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
                        stop_reason: Some(stop_reason.to_string()),
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                }
            }
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        // Parse candidates array - must have at least one
        let candidates_val = obj.get("candidates").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let candidates = candidates_val.as_array().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        if candidates.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".into()),
                retry_after: None,
            });
        }

        let candidate = &candidates[0];

        // Parse content → IrResponse.content
        let content_val = candidate.get("content").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(parts_arr) = content_val.get("parts").and_then(|p| p.as_array()) {
            for part in parts_arr {
                // Text part → IrBlock::Text
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    if !text.is_empty() {
                        content.push(crate::ir::IrBlock::Text {
                            text: text.to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                }

                // FunctionCall → IrBlock::ToolUse (id="", name from functionCall.name, input=funcCall.args)
                if let Some(func_call) = part.get("functionCall") {
                    let name_val = func_call
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let args = func_call
                        .get("args")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    content.push(crate::ir::IrBlock::ToolUse {
                        id: String::new(),
                        name: name_val,
                        input: args,
                    });
                }
            }
        }

        // Parse finishReason → stop_reason (map Gemini→canonical)
        let stop_reason = candidate
            .get("finishReason")
            .and_then(|r| r.as_str())
            .map(|fr| {
                let s = match fr {
                    "STOP" => "end_turn",
                    "MAX_TOKENS" => "max_tokens",
                    "SAFETY" => "safety",
                    other => &other.to_lowercase(),
                };
                String::from(s)
            });

        // Parse usageMetadata: promptTokenCount→input_tokens, candidatesTokenCount→output_tokens
        let usage_val = obj.get("usageMetadata");
        let usage = if let Some(u) = usage_val {
            crate::ir::IrUsage {
                input_tokens: u
                    .get("promptTokenCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                output_tokens: u
                    .get("candidatesTokenCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            }
        } else {
            crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            }
        };

        // Gemini reports the serving model as `modelVersion` (fall back to `model`).
        let model = obj
            .get("modelVersion")
            .or_else(|| obj.get("model"))
            .and_then(|m| m.as_str())
            .map(String::from);

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

/// Gemini writer implementation.
#[derive(Clone)]
pub(crate) struct GeminiWriter;

impl ProtocolWriter for GeminiWriter {
    fn upstream_path(&self) -> &str {
        // Model-independent fallback; the real per-request path comes from upstream_path_for().
        "/v1beta/models"
    }

    /// Gemini's URL embeds the model AND the stream mode. Streaming requests go to
    /// `:streamGenerateContent?alt=sse` (the gemini reader already decodes those SSE chunks);
    /// non-streaming to `:generateContent`.
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        if stream {
            // SSE streaming endpoint. `alt=sse` yields `data:`-framed chunks the gemini
            // reader's read_response_events already decodes.
            format!("/v1beta/models/{model}:streamGenerateContent?alt=sse")
        } else {
            format!("/v1beta/models/{model}:generateContent")
        }
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("/v1beta/models/{model}:generateContent")
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![(
            HeaderName::from_static("x-goog-api-key"),
            HeaderValue::from_str(key).unwrap_or_else(|_| HeaderValue::from_static("")),
        )]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        // systemInstruction.parts[] from IrRequest.system
        if !req.system.is_empty() {
            let parts: Vec<_> = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        Some(serde_json::json!({ "text": text }))
                    }
                    _ => None, // Only Text blocks in systemInstruction (Gemini limitation)
                })
                .collect();
            if !parts.is_empty() {
                out.insert(
                    "systemInstruction".to_string(),
                    serde_json::json!({ "parts": parts }),
                );
            }
        }

        // messages → contents (Assistant→"model", User→"user")
        let mut contents_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant | crate::ir::IrRole::Tool => "model",
                crate::ir::IrRole::System => continue, // Already in systemInstruction
            };

            let mut parts_arr: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        parts_arr.push(serde_json::json!({ "text": text }))
                    }
                    crate::ir::IrBlock::ToolUse { id: _, name, input } => {
                        // ToolUse → functionCall{name, args}
                        let args_val = if input.is_object() || input.is_array() {
                            input.clone()
                        } else {
                            // If it's a string, parse or wrap as object
                            serde_json::from_str(input.as_str().unwrap_or("{}"))
                                .unwrap_or_else(|_| input.clone())
                        };
                        parts_arr.push(serde_json::json!({
                            "functionCall": { "name": name, "args": args_val }
                        }))
                    }
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id: name,
                        content,
                        is_error: _,
                    } => {
                        // ToolResult → functionResponse{name, response}
                        let response_text = content
                            .iter()
                            .filter_map(|b| match b {
                                crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(" ");
                        let response_val: serde_json::Value =
                            serde_json::from_str(&response_text).unwrap_or(serde_json::json!({}));
                        parts_arr.push(serde_json::json!({
                            "functionResponse": { "name": name, "response": response_val }
                        }))
                    }
                    crate::ir::IrBlock::Image { media_type, data } => {
                        // Image → inlineData{mimeType, data}
                        parts_arr.push(serde_json::json!({
                            "inlineData": { "mimeType": media_type, "data": data }
                        }))
                    }
                    _ => {} // Drop unsupported blocks (thinking, etc.)
                }
            }

            if !parts_arr.is_empty() {
                let mut content_obj = serde_json::Map::new();
                content_obj.insert("role".to_string(), serde_json::json!(role_str));
                content_obj.insert("parts".to_string(), serde_json::Value::Array(parts_arr));
                contents_arr.push(serde_json::Value::Object(content_obj));
            }
        }

        // Write contents to output after building all messages
        if !contents_arr.is_empty() {
            out.insert(
                "contents".to_string(),
                serde_json::Value::Array(contents_arr),
            );
        }

        // tools → tools[0].functionDeclarations[]
        if !req.tools.is_empty() {
            let func_decls: Vec<_> = req
                .tools
                .iter()
                .map(|tool| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("name".to_string(), serde_json::json!(tool.name));
                    if let Some(desc) = &tool.description {
                        obj.insert("description".to_string(), serde_json::json!(desc));
                    }
                    obj.insert("parameters".to_string(), tool.input_schema.clone());
                    serde_json::Value::Object(obj)
                })
                .collect();
            out.insert(
                "tools".to_string(),
                serde_json::json!([{"functionDeclarations": func_decls}]),
            );
        }

        // generationConfig{maxOutputTokens, temperature}
        let mut gen_config = serde_json::Map::new();
        if let Some(max_tokens) = req.max_tokens {
            gen_config.insert("maxOutputTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            gen_config.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        if !gen_config.is_empty() {
            out.insert(
                "generationConfig".to_string(),
                serde_json::Value::Object(gen_config),
            );
        }

        // stream flag
        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // Merge extra fields (may override, but that's expected behavior)
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            // MessageStart → None (no frame needed for start in Gemini)
            IrStreamEvent::MessageStart { .. } => None,

            // BlockStart → None (Gemini has no block-start SSE frame; inline parts)
            IrStreamEvent::BlockStart { .. } => None,

            // TextDelta → chunk with text part
            IrStreamEvent::BlockDelta { index: _, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": text}]
                            }
                        }]
                    }),
                )),

                // InputJsonDelta → functionCall with args (best-effort, parse JSON string)
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    let args: serde_json::Value =
                        serde_json::from_str(json_str).unwrap_or(serde_json::json!({}));
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "candidates": [{
                                "content": {
                                    "role": "model",
                                    "parts": [{"functionCall": {"name": "", "args": args}}]
                                }
                            }]
                        }),
                    ))
                }

                // ThinkingDelta/SignatureDelta → None (Gemini has no thinking, lossy)
                crate::ir::IrDelta::ThinkingDelta(_) | crate::ir::IrDelta::SignatureDelta(_) => {
                    None
                }
            },

            // BlockStop → None (no frame; stateless)
            IrStreamEvent::BlockStop { .. } => None,

            // MessageDelta → chunk with finishReason + usageMetadata
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                let finish_reason = match stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => "STOP".to_string(),
                    Some("max_tokens") => "MAX_TOKENS".to_string(),
                    Some("safety") => "SAFETY".to_string(),
                    Some(other) => other.to_uppercase(),
                    None => "STOP".to_string(),
                };

                Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "finishReason": finish_reason
                        }],
                        "usageMetadata": {
                            "promptTokenCount": usage.input_tokens,
                            "candidatesTokenCount": usage.output_tokens
                        }
                    }),
                ))
            }

            // MessageStop → None (no frame needed)
            IrStreamEvent::MessageStop => None,

            // Error → error object
            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "error": {"message": message}
                    }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Build candidates array (Gemini whole-response format)
        let mut parts_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        parts_arr.push(serde_json::json!({"text": text}));
                    }
                }

                // ToolUse → functionCall{name, args}
                crate::ir::IrBlock::ToolUse { id: _, name, input } => {
                    let args_val = if input.is_object() || input.is_array() {
                        input.clone()
                    } else {
                        serde_json::from_str(input.as_str().unwrap_or("{}"))
                            .unwrap_or_else(|_| input.clone())
                    };
                    parts_arr.push(serde_json::json!({
                        "functionCall": {"name": name, "args": args_val}
                    }));
                }

                // Thinking blocks are DROPPED (Gemini has no thinking) - lossy-by-necessity
                crate::ir::IrBlock::Thinking { .. } => {}

                // Image/ToolResult not supported in response output (lossy)
                crate::ir::IrBlock::Image { .. } | crate::ir::IrBlock::ToolResult { .. } => {}
            }
        }

        let finish_reason = match resp.stop_reason.as_deref() {
            Some("end_turn") | Some("stop_sequence") => "STOP".to_string(),
            Some("max_tokens") => "MAX_TOKENS".to_string(),
            Some("safety") => "SAFETY".to_string(),
            Some(other) => other.to_uppercase(),
            None => "STOP".to_string(),
        };

        let mut out = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": parts_arr
                },
                "finishReason": finish_reason
            }],
            "usageMetadata": {
                "promptTokenCount": resp.usage.input_tokens,
                "candidatesTokenCount": resp.usage.output_tokens
            }
        });
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out["modelVersion"] = serde_json::json!(model);
        }
        out
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}
