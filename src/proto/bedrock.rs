// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Bedrock Converse protocol reader/writer implementation.

use super::*;

/// Bedrock stopReason → canonical IR stop_reason.
fn stop_reason_map(ward: &str) -> String {
    match ward {
        "end_turn" => "end_turn".to_string(),
        "tool_use" => "tool_use".to_string(),
        "max_tokens" => "max_tokens".to_string(),
        "stop_sequence" => "stop_sequence".to_string(),
        "content_filtered" => "safety".to_string(),
        other => other.to_string(),
    }
}

/// Canonical IR stop_reason → Bedrock stopReason (inverse of `stop_reason_map`).
fn stop_reason_reverse(canonical: &str) -> String {
    match canonical {
        "end_turn" => "end_turn".to_string(),
        "tool_use" => "tool_use".to_string(),
        "max_tokens" => "max_tokens".to_string(),
        "stop_sequence" => "stop_sequence".to_string(),
        "safety" => "content_filtered".to_string(),
        other => other.to_string(),
    }
}

#[derive(Clone)]
pub(crate) struct BedrockReader;

impl ProtocolReader for BedrockReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("message")
                .and_then(|m| m.as_str())
                .map(String::from)
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("message")
                .and_then(|m| m.as_str())
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

        if lower.contains("input is longer than the maximum number of tokens")
            || (lower.contains("maximum-tokens") && lower.contains("requested"))
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

        let extra = serde_json::Map::new();

        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(system_arr) = obj.get("system").and_then(|s| s.as_array()) {
            for sys_val in system_arr {
                if let Some(text_val) = sys_val.get("text").and_then(|t| t.as_str()) {
                    system_blocks.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                }
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(msgs_arr) = obj.get("messages").and_then(|m| m.as_array()) {
            for msg_val in msgs_arr {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");

                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some("ir_parse".to_string()),
                            retry_after: None,
                        })
                    }
                };

                let mut msg_content: Vec<crate::ir::IrBlock> = Vec::new();
                if let Some(content_arr) = msg_val.get("content").and_then(|c| c.as_array()) {
                    for content_val in content_arr {
                        if let Some(text_val) = content_val.get("text").and_then(|t| t.as_str()) {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text_val.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(tool_use) = content_val.get("toolUse") {
                            let tu_id = tool_use
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = tool_use
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let input = tool_use
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);

                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id: tu_id,
                                name,
                                input,
                            });
                        } else if let Some(tool_result) = content_val.get("toolResult") {
                            let tu_id = tool_result
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();

                            let mut inner_content: Vec<crate::ir::IrBlock> = Vec::new();
                            if let Some(inner_arr) =
                                tool_result.get("content").and_then(|c| c.as_array())
                            {
                                for inner_val in inner_arr {
                                    if let Some(text_val) =
                                        inner_val.get("text").and_then(|t| t.as_str())
                                    {
                                        inner_content.push(crate::ir::IrBlock::Text {
                                            text: text_val.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    } else if let Some(json_val) = inner_val.get("json") {
                                        let text_repr = serde_json::to_string(json_val)
                                            .unwrap_or_else(|_| "unknown".to_string());
                                        inner_content.push(crate::ir::IrBlock::Text {
                                            text: text_repr,
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                }
                            }

                            let is_error = tool_result
                                .get("status")
                                .and_then(|s| s.as_str())
                                .map(|s| s == "error")
                                .unwrap_or(false);

                            msg_content.push(crate::ir::IrBlock::ToolResult {
                                tool_use_id: tu_id,
                                content: inner_content,
                                is_error,
                            });
                        } else if let Some(image) = content_val.get("image") {
                            let format_str = image
                                .get("format")
                                .and_then(|f| f.as_str())
                                .unwrap_or("")
                                .to_string();
                            let media_type = format!("image/{}", format_str);

                            let data = if let Some(source) = image.get("source") {
                                source
                                    .get("bytes")
                                    .and_then(|b| b.as_str())
                                    .unwrap_or("")
                                    .to_string()
                            } else {
                                String::new()
                            };

                            msg_content.push(crate::ir::IrBlock::Image { media_type, data });
                        }
                    }
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tool_config) = obj.get("toolConfig").and_then(|t| t.as_object()) {
            if let Some(tools_arr) = tool_config.get("tools").and_then(|t| t.as_array()) {
                for tool_val in tools_arr {
                    if let Some(tool_spec) = tool_val.get("toolSpec").and_then(|t| t.as_object()) {
                        let name = tool_spec
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = tool_spec
                            .get("description")
                            .and_then(|d| d.as_str().map(String::from));

                        let input_schema = if let Some(input_schema) = tool_spec.get("inputSchema")
                        {
                            input_schema
                                .get("json")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        } else {
                            serde_json::Value::Null
                        };

                        tools.push(crate::ir::IrTool {
                            name,
                            description,
                            input_schema,
                        });
                    }
                }
            }
        }

        let max_tokens = if let Some(inference_config) =
            obj.get("inferenceConfig").and_then(|i| i.as_object())
        {
            inference_config
                .get("maxTokens")
                .and_then(|v| v.as_u64())
                .filter(|&v| v > 0)
                .map(|v| v as u32)
        } else {
            None
        };

        let temperature = if let Some(inference_config) =
            obj.get("inferenceConfig").and_then(|i| i.as_object())
        {
            inference_config.get("temperature").and_then(|v| v.as_f64())
        } else {
            None
        };

        Ok(crate::ir::IrRequest {
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            stream: false,
            extra,
        })
    }

    fn read_response_event(
        &self,
        _event_type: &str,
        _data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        // Bedrock streaming uses read_response_events (fan-out); this singular form is unused.
        None
    }

    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match data.get("type").and_then(|t| t.as_str()) {
            Some("messageStart") => {
                if !state.started {
                    state.started = true;
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                    });
                }
            }

            Some("contentBlockStart") => {
                let idx = data
                    .get("contentBlockIndex")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(0) as usize;

                if let Some(start_obj) = data.get("start").and_then(|s| s.as_object()) {
                    if let Some(tool_use) = start_obj.get("toolUse").and_then(|t| t.as_object()) {
                        let tu_id = tool_use
                            .get("toolUseId")
                            .and_then(|id| id.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = tool_use
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();

                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::ToolUse { id: tu_id, name },
                        });
                    } else if state.started && !state.text_block_open {
                        state.text_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                } else if state.started && !state.text_block_open {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
            }

            Some("contentBlockDelta") => {
                let idx = data
                    .get("contentBlockIndex")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(0) as usize;

                if let Some(delta_obj) = data.get("delta").and_then(|d| d.as_object()) {
                    if delta_obj.contains_key("text") {
                        let text_val = delta_obj
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();

                        out.push(IrStreamEvent::BlockDelta {
                            index: idx,
                            delta: crate::ir::IrDelta::TextDelta(text_val),
                        });
                    } else if let Some(tool_use) =
                        delta_obj.get("toolUse").and_then(|t| t.as_object())
                    {
                        if let Some(input_str) = tool_use.get("input").and_then(|i| i.as_str()) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(input_str.to_string()),
                            });
                        }
                    }
                }
            }

            Some("contentBlockStop") => {
                let idx = data
                    .get("contentBlockIndex")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(0) as usize;

                if state.text_block_open && idx == 0 {
                    state.text_block_open = false;
                }

                out.push(IrStreamEvent::BlockStop { index: idx });
            }

            Some("messageStop") => {
                let stop_reason_val = data
                    .get("stopReason")
                    .and_then(|s| s.as_str())
                    .map(stop_reason_map);

                // Bedrock splits stop reason (messageStop) from usage (a following `metadata`
                // event). Emit the stop_reason here with zero usage; `metadata` emits a second
                // MessageDelta carrying the real usage, then the single terminating MessageStop.
                if let Some(reason) = stop_reason_val {
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason: Some(reason),
                        usage: crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        },
                    });
                }
            }

            Some("metadata") => {
                if let Some(usage_obj) = data.get("usage").and_then(|u| u.as_object()) {
                    let usage = crate::ir::IrUsage {
                        input_tokens: usage_obj
                            .get("inputTokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        output_tokens: usage_obj
                            .get("outputTokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };

                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason: None,
                        usage,
                    });
                }

                out.push(IrStreamEvent::MessageStop);
            }

            _ => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir-parse".to_string()),
            retry_after: None,
        })?;

        let output_val = obj.get("output").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir-parse".to_string()),
            retry_after: None,
        })?;

        let message_val = output_val.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir-parse".to_string()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(content_arr) = message_val.get("content").and_then(|c| c.as_array()) {
            for block_val in content_arr {
                if let Some(text_val) = block_val.get("text").and_then(|t| t.as_str()) {
                    content.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                } else if let Some(tool_use) = block_val.get("toolUse").and_then(|t| t.as_object())
                {
                    let tu_id = tool_use
                        .get("toolUseId")
                        .and_then(|id| id.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = tool_use
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let input = tool_use
                        .get("input")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    content.push(crate::ir::IrBlock::ToolUse {
                        id: tu_id,
                        name,
                        input,
                    });
                }
            }
        }

        let stop_reason_val = obj
            .get("stopReason")
            .and_then(|s| s.as_str())
            .map(stop_reason_map);

        let usage_val = obj.get("usage").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir-parse".to_string()),
            retry_after: None,
        })?;

        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .get("inputTokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .get("outputTokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason: stop_reason_val,
            usage,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub(crate) struct BedrockWriter;

impl ProtocolWriter for BedrockWriter {
    fn upstream_path(&self) -> &str {
        "/model"
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("/model/{}/converse", model)
    }

    fn auth_headers(&self, _key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Bedrock auth is per-request SigV4 — see `sign_request`. Static headers can't carry it.
        vec![]
    }

    /// C-4: AWS SigV4 signing for the Converse request. The lane key encodes credentials as
    /// `ACCESS_KEY_ID:SECRET_ACCESS_KEY` or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN`; the
    /// region is parsed from the host (`bedrock-runtime.<region>.amazonaws.com`); service=`bedrock`.
    fn sign_request(
        &self,
        key: &str,
        ctx: &super::SigningContext,
    ) -> Vec<(HeaderName, HeaderValue)> {
        let mut parts = key.splitn(3, ':');
        let (access, secret, token) = match (parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(s), tok) if !a.is_empty() && !s.is_empty() => (a, s, tok),
            _ => return vec![], // misconfigured key → no signature (AWS will 403, surfaced as auth)
        };
        let region = ctx
            .host
            .strip_prefix("bedrock-runtime.")
            .and_then(|r| r.split('.').next())
            .unwrap_or("us-east-1");
        let service = "bedrock";
        let (amzdate, datestamp) = crate::sigv4::format_amz_time(ctx.timestamp_epoch);
        let payload_hash = crate::sigv4::sha256_hex(ctx.body);

        let mut signed = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), ctx.host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amzdate.clone()),
        ];
        if let Some(t) = token {
            signed.push(("x-amz-security-token".to_string(), t.to_string()));
        }

        let (signature, signed_headers) = crate::sigv4::sign_v4(
            secret,
            region,
            service,
            "POST",
            &ctx.canonical_uri,
            "",
            &signed,
            &payload_hash,
            &amzdate,
            &datestamp,
        );
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access}/{datestamp}/{region}/{service}/aws4_request, \
             SignedHeaders={signed_headers}, Signature={signature}"
        );

        // Headers to ADD to the wire request (content-type + host are set elsewhere / by the client).
        let mut out = vec![
            (
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&authorization).expect("valid auth header"),
            ),
            (
                HeaderName::from_static("x-amz-date"),
                HeaderValue::from_str(&amzdate).expect("valid date header"),
            ),
            (
                HeaderName::from_static("x-amz-content-sha256"),
                HeaderValue::from_str(&payload_hash).expect("valid sha header"),
            ),
        ];
        if let Some(t) = token {
            if let Ok(v) = HeaderValue::from_str(t) {
                out.push((HeaderName::from_static("x-amz-security-token"), v));
            }
        }
        out
    }

    fn rewrite_model(&self, _body: &mut serde_json::Value, _model: &str) {}

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        if !req.system.is_empty() {
            let text_arr: Vec<serde_json::Value> = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        Some(serde_json::json!({ "text": text }))
                    }
                    _ => None,
                })
                .collect();

            if !text_arr.is_empty() {
                out.insert("system".to_string(), serde_json::Value::Array(text_arr));
            }
        }

        let mut msgs_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::System | crate::ir::IrRole::Tool => "user",
            };

            let mut content_arr: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        content_arr.push(serde_json::json!({ "text": text }));
                    }
                    crate::ir::IrBlock::ToolUse { id, name, input } => {
                        content_arr.push(serde_json::json!({"toolUse": {"toolUseId": id, "name": name, "input": input}}));
                    }
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                    } => {
                        let mut inner_content: Vec<serde_json::Value> = Vec::new();
                        for inner_block in content {
                            match inner_block {
                                crate::ir::IrBlock::Text { text, .. } => {
                                    inner_content.push(serde_json::json!({ "text": text }));
                                }
                                _ => {
                                    let json_repr = "{}".to_string();
                                    inner_content.push(serde_json::json!({ "text": json_repr }));
                                }
                            }
                        }

                        let status_str = if *is_error { "error" } else { "success" };
                        content_arr.push(serde_json::json!({"toolResult": {"toolUseId": tool_use_id, "content": inner_content, "status": status_str}}));
                    }
                    crate::ir::IrBlock::Image { media_type, data } => {
                        let format_str = media_type
                            .strip_prefix("image/")
                            .unwrap_or("png")
                            .to_string();
                        content_arr.push(serde_json::json!({"image": {"format": format_str, "source": {"bytes": data}}}));
                    }
                    crate::ir::IrBlock::Thinking { .. } => {}
                }
            }

            if !content_arr.is_empty() {
                let mut msg_obj = serde_json::Map::new();
                msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                msg_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
                msgs_arr.push(serde_json::Value::Object(msg_obj));
            }
        }

        if !msgs_arr.is_empty() {
            out.insert("messages".to_string(), serde_json::Value::Array(msgs_arr));
        }

        let mut inference_config = serde_json::Map::new();
        if let Some(max_tokens) = req.max_tokens {
            inference_config.insert("maxTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            inference_config.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        if !inference_config.is_empty() {
            out.insert(
                "inferenceConfig".to_string(),
                serde_json::Value::Object(inference_config),
            );
        }

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_spec = serde_json::Map::new();
                tool_spec.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_spec.insert("description".to_string(), serde_json::json!(desc));
                }

                let mut input_schema = serde_json::Map::new();
                input_schema.insert("json".to_string(), tool.input_schema.clone());
                tool_spec.insert(
                    "inputSchema".to_string(),
                    serde_json::Value::Object(input_schema),
                );

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("toolSpec".to_string(), serde_json::Value::Object(tool_spec));
                tools_arr.push(serde_json::Value::Object(tool_obj));
            }

            let mut tool_config = serde_json::Map::new();
            tool_config.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
            out.insert(
                "toolConfig".to_string(),
                serde_json::Value::Object(tool_config),
            );
        }

        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role: _, usage: _ } => Some((
                "messageStart".to_string(),
                serde_json::json!({ "role": "assistant" }),
            )),

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => None,
                crate::ir::IrBlockMeta::ToolUse { id, name } => Some((
                    "contentBlockStart".to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "start": { "toolUse": { "toolUseId": id, "name": name } }
                    }),
                )),
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "contentBlockDelta".to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "text": text }
                    }),
                )),

                crate::ir::IrDelta::InputJsonDelta(json_str) => Some((
                    "contentBlockDelta".to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "toolUse": { "input": json_str } }
                    }),
                )),

                crate::ir::IrDelta::ThinkingDelta(_) | crate::ir::IrDelta::SignatureDelta(_) => {
                    None
                }
            },

            IrStreamEvent::BlockStop { index } => Some((
                "contentBlockStop".to_string(),
                serde_json::json!({ "contentBlockIndex": index }),
            )),

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage: _,
            } => {
                let reason_str = stop_reason.as_deref().unwrap_or("end_turn");
                Some((
                    "messageStop".to_string(),
                    serde_json::json!({ "stopReason": stop_reason_reverse(reason_str) }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "error".to_string(),
                    serde_json::json!({ "message": message }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut content_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        content_arr.push(serde_json::json!({ "text": text }));
                    }
                }

                crate::ir::IrBlock::ToolUse { id, name, input } => {
                    content_arr.push(serde_json::json!({
                        "toolUse": {
                            "toolUseId": id,
                            "name": name,
                            "input": input
                        }
                    }));
                }

                crate::ir::IrBlock::Thinking { .. } => {}

                crate::ir::IrBlock::ToolResult { .. } | crate::ir::IrBlock::Image { .. } => {}
            }
        }

        let stop_reason_str = resp.stop_reason.as_deref().unwrap_or("end_turn");
        let reverse_reason = stop_reason_reverse(stop_reason_str);

        serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": content_arr
                }
            },
            "stopReason": reverse_reason,
            "usage": {
                "inputTokens": resp.usage.input_tokens,
                "outputTokens": resp.usage.output_tokens,
                "totalTokens": resp.usage.input_tokens + resp.usage.output_tokens
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
    fn test_bedrock_sigv4_sign_request_structure() {
        // C-4: SigV4 header assembly + scope/region derivation. (The signing crypto itself is
        // verified against AWS's published vector in sigv4::tests.)
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: crate::sigv4::uri_encode_path("/model/anthropic.claude:0/converse"),
            body: br#"{"messages":[]}"#,
            timestamp_epoch: 1_440_938_160, // 20150830T123600Z
        };
        let headers = writer.sign_request("AKIDEXAMPLE:SECRETKEY", &ctx);

        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.as_str() == name)
                .map(|(_, v)| v.to_str().unwrap().to_string())
        };
        let auth = get("authorization").expect("authorization header");
        assert!(
            auth.starts_with(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, "
            ),
            "scope/region derived from host; got: {auth}"
        );
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
        assert!(auth.contains("Signature="));
        assert_eq!(get("x-amz-date").as_deref(), Some("20150830T123600Z"));
        assert!(get("x-amz-content-sha256").is_some());
        // No session token configured → no security-token header.
        assert!(get("x-amz-security-token").is_none());
    }

    #[test]
    fn test_bedrock_sigv4_session_token() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.eu-west-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
        };
        let headers = writer.sign_request("AKID:SECRET:SESSIONTOKEN", &ctx);
        let tok = headers
            .iter()
            .find(|(k, _)| k.as_str() == "x-amz-security-token")
            .map(|(_, v)| v.to_str().unwrap().to_string());
        assert_eq!(tok.as_deref(), Some("SESSIONTOKEN"));
        // region parsed from the eu-west-1 host + token in the signed set.
        let auth = headers
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .unwrap();
        assert!(auth.contains("/eu-west-1/bedrock/aws4_request"));
        assert!(auth.contains("x-amz-security-token"));
    }

    #[test]
    fn test_bedrock_sigv4_misconfigured_key_no_signature() {
        // A key without ACCESS:SECRET shape yields no headers (AWS will 403 → surfaced as auth).
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
        };
        assert!(writer.sign_request("not-a-valid-key", &ctx).is_empty());
    }

    fn bedrock_rich_fixture() -> serde_json::Value {
        serde_json::json!({
            "system": [{"text": "You are a helpful assistant."}],
            "messages": [
                {"role": "user", "content": [{"text": "What is the weather in San Francisco?"}]},
                {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tool_123", "name": "get_weather", "input": {"city": "San Francisco"}}}]},
                {"role": "user", "content": [{"toolResult": {"toolUseId": "tool_123", "content": [{"text": "Sunny, 72°F"}], "status": "success"}}]}
            ],
            "inferenceConfig": {"maxTokens": 1024, "temperature": 0.7},
            "toolConfig": {
                "tools": [{
                    "toolSpec": {
                        "name": "get_weather",
                        "description": "Get weather for a city",
                        "inputSchema": {"json": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}
                    }
                }]
            },
            "top_p": 0.95
        })
    }

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
            system: vec![crate::ir::IrBlock::Text {
                text: "You are a helpful assistant.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "What is the weather in San Francisco?".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "tool_123".to_string(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({"city": "San Francisco"}),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "tool_123".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "Sunny, 72°F".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("Get weather for a city".to_string()),
                input_schema: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}),
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7_f64),
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = BedrockWriter;
        let json = writer.write_request(&ir);

        assert_eq!(
            json.get("system")
                .and_then(|s| s.as_array())
                .and_then(|a| a.first())
                .and_then(|b| b.get("text"))
                .and_then(|t| t.as_str()),
            Some("You are a helpful assistant.")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.first())
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("text"))
                .and_then(|t| t.as_str()),
            Some("What is the weather in San Francisco?")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("toolUseId"))
                .and_then(|id| id.as_str()),
            Some("tool_123")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("name"))
                .and_then(|n| n.as_str()),
            Some("get_weather")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("input"))
                .and_then(|i| i.get("city"))
                .and_then(|c| c.as_str()),
            Some("San Francisco")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(2))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolResult"))
                .and_then(|tr| tr.get("status"))
                .and_then(|s| s.as_str()),
            Some("success")
        );
        assert_eq!(
            json.get("inferenceConfig")
                .and_then(|ic| ic.get("maxTokens"))
                .and_then(|m| m.as_u64()),
            Some(1024)
        );
        assert_eq!(
            json.get("inferenceConfig")
                .and_then(|ic| ic.get("temperature"))
                .and_then(|t| t.as_f64()),
            Some(0.7)
        );
        assert_eq!(
            json.get("toolConfig")
                .and_then(|tc| tc.get("tools"))
                .and_then(|ts| ts.as_array())
                .and_then(|arr| arr.first())
                .and_then(|t| t.get("toolSpec"))
                .and_then(|spec| spec.get("name"))
                .and_then(|n| n.as_str()),
            Some("get_weather")
        );
    }

    #[test]
    fn test_read_request() {
        let reader = BedrockReader;
        let j = bedrock_rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
            assert_eq!(text, "You are a helpful assistant.");
        } else {
            panic!("system[0] should be Text block");
        }

        assert_eq!(ir.messages.len(), 3);

        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What is the weather in San Francisco?");
        } else {
            panic!("messages[0].content[0] should be Text block");
        }

        if let crate::ir::IrBlock::ToolUse { id, name, input } = &ir.messages[1].content[0] {
            assert_eq!(id, "tool_123");
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("city"), Some(&serde_json::json!("San Francisco")));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("messages[1].content[0] should be ToolUse block");
        }

        if let crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } = &ir.messages[2].content[0]
        {
            assert_eq!(tool_use_id, "tool_123");
            assert!(!is_error);
            if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
                assert_eq!(text, "Sunny, 72°F");
            } else {
                panic!("toolResult content[0] should be Text block");
            }
        } else {
            panic!("messages[2].content[0] should be ToolResult block");
        }

        assert_eq!(ir.max_tokens, Some(1024));
        assert_eq!(ir.temperature, Some(0.7_f64));
        assert_eq!(ir.tools.len(), 1);
        let crate::ir::IrTool {
            ref name,
            ref description,
            ..
        } = ir.tools[0];
        assert_eq!(name, "get_weather");
        assert_eq!(description.as_deref(), Some("Get weather for a city"));
    }

    #[test]
    fn test_roundtrip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;

        let ir = crate::ir::IrRequest {
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "Hello!".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: Some(512),
            temperature: Some(0.7_f64),
            stream: false,
            extra: serde_json::Map::new(),
        };

        let ir_before = ir.clone();
        let json = writer.write_request(&ir);
        let ir_after = reader
            .read_request(&json)
            .expect("read round-trip should succeed");

        assert_eq!(
            ir_before, ir_after,
            "round-trip must be byte-identical for text-only IrRequest"
        );
    }

    #[test]
    fn test_temperature_fidelity() {
        let j = serde_json::json!({"inferenceConfig": {"temperature": 0.7}, "messages": [{"role": "user", "content": [{"text": "hi"}]}]});
        let reader = BedrockReader;
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_read_response_decode() {
        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Let me check the weather for you."},
                        {"toolUse": {"toolUseId": "tu_1", "name": "get_weather", "input": {"city": "SF"}}}
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": {
                "inputTokens": 42,
                "outputTokens": 15,
                "totalTokens": 57
            }
        });

        let reader = BedrockReader;
        let resp = reader
            .read_response(&j)
            .expect("read_response should succeed");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 2);

        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "Let me check the weather for you.");
        } else {
            panic!("content[0] should be Text block");
        }

        if let crate::ir::IrBlock::ToolUse { id, name, input } = &resp.content[1] {
            assert_eq!(id, "tu_1");
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("city"), Some(&serde_json::json!("SF")));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("content[1] should be ToolUse block");
        }

        assert_eq!(resp.stop_reason, Some("tool_use".to_string()));
        assert_eq!(resp.usage.input_tokens, 42);
        assert_eq!(resp.usage.output_tokens, 15);
    }

    #[test]
    fn test_read_write_response_roundtrip() {
        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello, world!"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5,
                "totalTokens": 15
            }
        });

        let reader = BedrockReader;
        let writer = BedrockWriter;

        let resp = reader
            .read_response(&j)
            .expect("read_response should succeed");
        let written = writer.write_response(&resp);

        assert_eq!(
            written, j,
            "round-trip must be byte-identical for text-only response"
        );
    }

    #[test]
    fn test_stream_decode_sequence() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            (serde_json::json!({"type": "messageStart", "role": "assistant"})),
            (serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {}
            })),
            (serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": "Hello"}
            })),
            (serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": ", world!"}
            })),
            (serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0})),
            (serde_json::json!({
                "type": "messageStop",
                "stopReason": "end_turn"
            })),
            (serde_json::json!({
                "type": "metadata",
                "usage": {"inputTokens": 10, "outputTokens": 5}
            })),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        assert_eq!(events.len(), 8);

        match &events[0] {
            IrStreamEvent::MessageStart { role, usage } => {
                assert_eq!(*role, crate::ir::IrRole::Assistant);
                assert!(usage.is_none());
            }
            _ => panic!("event[0] should be MessageStart"),
        }

        match &events[1] {
            IrStreamEvent::BlockStart { index, block } => {
                assert_eq!(*index, 0);
                assert!(matches!(block, crate::ir::IrBlockMeta::Text));
            }
            _ => panic!("event[1] should be BlockStart"),
        }

        match &events[2] {
            IrStreamEvent::BlockDelta { index, delta } => {
                assert_eq!(*index, 0);
                if let crate::ir::IrDelta::TextDelta(text) = delta {
                    assert_eq!(text, "Hello");
                } else {
                    panic!("event[2] should be TextDelta");
                }
            }
            _ => panic!("event[2] should be BlockDelta"),
        }

        match &events[3] {
            IrStreamEvent::BlockDelta { index, delta } => {
                assert_eq!(*index, 0);
                if let crate::ir::IrDelta::TextDelta(text) = delta {
                    assert_eq!(text, ", world!");
                } else {
                    panic!("event[3] should be TextDelta");
                }
            }
            _ => panic!("event[3] should be BlockDelta"),
        }

        match &events[4] {
            IrStreamEvent::BlockStop { index } => assert_eq!(*index, 0),
            _ => panic!("event[4] should be BlockStop"),
        }

        // messageStop carries the stop reason with zero usage...
        match &events[5] {
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                assert_eq!(stop_reason.as_deref(), Some("end_turn"));
                assert_eq!(usage.input_tokens, 0);
                assert_eq!(usage.output_tokens, 0);
            }
            _ => panic!("event[5] should be MessageDelta"),
        }

        // ...and the trailing `metadata` event carries the real usage (lossless), then MessageStop.
        match &events[6] {
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                assert!(stop_reason.is_none());
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => panic!("event[6] should be MessageDelta carrying usage"),
        }

        match &events[7] {
            IrStreamEvent::MessageStop => {}
            _ => panic!("event[7] should be MessageStop"),
        }
    }

    #[test]
    fn test_write_response_event() {
        let writer = BedrockWriter;

        let delta_ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };

        if let Some((event_type, payload)) = writer.write_response_event(&delta_ev) {
            assert_eq!(event_type, "contentBlockDelta");
            assert_eq!(
                payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
                Some(0)
            );
            assert_eq!(
                payload
                    .get("delta")
                    .and_then(|d| d.as_object())
                    .and_then(|o| o.get("text"))
                    .and_then(|t| t.as_str()),
                Some("hi")
            );
        } else {
            panic!("write_response_event should return Some for BlockDelta");
        }

        let delta_ev2 = IrStreamEvent::MessageDelta {
            stop_reason: Some("tool_use".to_string()),
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        if let Some((event_type, payload)) = writer.write_response_event(&delta_ev2) {
            assert_eq!(event_type, "messageStop");
            assert_eq!(
                payload.get("stopReason").and_then(|s| s.as_str()),
                Some("tool_use")
            );
        } else {
            panic!("write_response_event should return Some for MessageDelta with tool_use");
        }
    }
}
