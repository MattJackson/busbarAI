// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Gemini protocol reader/writer implementation.

use super::*;

#[derive(Clone)]
pub(crate) struct GeminiReader;

impl ProtocolReader for GeminiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body once; both `provider_code` and `structured_type` are derived from the
        // same parsed value to avoid deserializing the JSON twice on every error response.
        let json = serde_json::from_slice::<serde_json::Value>(body).ok();
        let error_obj = json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_object());

        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get("code"))
            .and_then(|c| c.as_str())
            .map(String::from)
            .or_else(|| {
                error_obj
                    .and_then(|e_obj| e_obj.get("status"))
                    .and_then(|s| s.as_str())
                    .map(String::from)
            });

        let structured_type = error_obj
            .and_then(|e_obj| e_obj.get("status"))
            .and_then(|t| t.as_str())
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
                            // ACCEPTED GEMINI-PROTOCOL LIMITATION: a Gemini `functionResponse`
                            // carries only a `name` (no call id), and the corresponding
                            // `functionCall` ToolUse blocks are themselves read with an empty id
                            // (`id: String::new()` above), so there is no id to correlate back to.
                            // We therefore set `tool_use_id` to the function name — the only stable
                            // correlation key Gemini provides. Cross-protocol egress (Anthropic
                            // `tool_use_id` / OpenAI `tool_call_id`) that correlates strictly by id
                            // will see the name; same-protocol Gemini passthrough is unaffected
                            // because the writer round-trips `name` back into `functionResponse.name`.
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

        // Collect unmodeled top-level keys into extra (excluding modeled ones). `model` is in the
        // set so the loop below does NOT re-insert it: it is preserved in `extra` exactly once via
        // the explicit pre-insert below (preventing the silent duplicate insert the loop used to
        // perform, which would be discarded the moment the two writes ever diverged).
        //
        // `stream` is deliberately NOT modeled here. The writer never injects a `stream` member
        // unconditionally any more (the native GenerateContentRequest has no such field — streaming
        // is URL-selected), so the only way `stream` reaches the wire is if the SOURCE request
        // literally carried it: such a value is preserved verbatim through `extra` and echoed back,
        // making a read→write round-trip lossless. A native Gemini client never sends `stream`, so
        // for real traffic `extra` carries no `stream` and the egress body carries none either —
        // the indistinguishability goal. `IrRequest.stream` (captured above) is read ONLY by
        // path-selection (`upstream_path_for_stream`), never serialised into the body.
        let modeled_keys: std::collections::HashSet<&str> = [
            "contents",
            "tools",
            "systemInstruction",
            "generationConfig",
            "tool_config",
            "model",
        ]
        .iter()
        .cloned()
        .collect();

        // model is modeled but we preserve it in extra for round-trip identity. Done once here;
        // the loop skips it because `model` is in `modeled_keys`.
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

        // 1. MessageStart exactly once on first chunk. Capture the stream identity from the first
        // chunk so same-protocol passthrough preserves it: streamed Gemini chunks carry the same
        // `responseId`/`modelVersion` as the whole-response body. Gemini streams carry no `created`
        // timestamp, so it stays `None` (the writer omits it rather than fabricate one).
        if !state.started {
            state.started = true;
            let id = data
                .get("responseId")
                .and_then(|i| i.as_str())
                .map(String::from);
            let model = data
                .get("modelVersion")
                .or_else(|| data.get("model"))
                .and_then(|m| m.as_str())
                .map(String::from);
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id,
                created: None,
                model,
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
                            // The text block always owns IR index 0. Tool blocks take indices 1..n.
                            // The next tool index is derived from persistent state (`open_tools`)
                            // rather than a per-chunk local, so indices stay stable across the
                            // multiple SSE chunks of a single response.
                            for part in parts_arr {
                                // Text block
                                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                    if !text.is_empty() {
                                        if !state.text_block_open {
                                            state.text_block_open = true;
                                            out.push(IrStreamEvent::BlockStart {
                                                index: 0,
                                                block: crate::ir::IrBlockMeta::Text,
                                            });
                                        }
                                        out.push(IrStreamEvent::BlockDelta {
                                            index: 0,
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
                                        // Tool blocks follow the text block (index 0). The next
                                        // index is 1 + however many tool blocks are already open.
                                        // Record it in `open_tools` so the finishReason handler
                                        // emits a matching BlockStop for every tool block.
                                        let ir_idx = 1 + state.open_tools.len();
                                        state.open_tools.insert(ir_idx);

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
        let stop_reason =
            candidate
                .get("finishReason")
                .and_then(|r| r.as_str())
                .map(|fr| match fr {
                    "STOP" => "end_turn".to_string(),
                    "MAX_TOKENS" => "max_tokens".to_string(),
                    "SAFETY" => "safety".to_string(),
                    other => other.to_lowercase(),
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

        // Capture the upstream response identity so same-protocol (Gemini→Gemini) passthrough
        // preserves it byte-for-byte. The native generateContent body carries an opaque
        // `responseId` (surfaced by the official `google-genai` SDK as
        // `GenerateContentResponse.response_id`); Gemini bodies carry NO `created`/timestamp field,
        // so `created` stays `None` here and the writer omits it (synthesizing one would be a
        // fabricated field a native client never sees). `system_fingerprint`/`stop_sequence` have
        // no Gemini analogue and remain `None`.
        let id = obj
            .get("responseId")
            .and_then(|i| i.as_str())
            .map(String::from);

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

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

/// Process-global counter feeding synthesized `responseId`s, mirroring the Anthropic writer's
/// `SYNTH_ID_COUNTER`. Combined with the unix second it makes two synthesized ids astronomically
/// unlikely to collide without pulling in a uuid/rand crate.
static SYNTH_RESPONSE_ID_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Current unix time in whole seconds, or 0 if the system clock predates the epoch. Never panics.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a Gemini-shaped `responseId` for the cross-protocol path where the backend supplied none.
/// Real `responseId`s are opaque strings with no documented prefix a native SDK could reject, so a
/// timestamp+counter suffix is indistinguishable in shape. No new dependency.
fn synth_response_id() -> String {
    let seq = SYNTH_RESPONSE_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{:x}{:x}", unix_now_secs(), seq)
}

/// Map a canonical `StatusClass` onto the `(HTTP code, google.rpc.Code name)` pair Gemini uses in
/// its `google.rpc.Status` error envelope. Exhaustive over `StatusClass` (no `_ =>` catch-all) so
/// a new class forces a conscious choice here rather than silently degrading to INTERNAL.
fn gemini_stream_error_code_status(class: StatusClass) -> (u16, &'static str) {
    match class {
        StatusClass::RateLimit => (429, "RESOURCE_EXHAUSTED"),
        StatusClass::Overloaded => (503, "UNAVAILABLE"),
        StatusClass::ServerError => (500, "INTERNAL"),
        StatusClass::Timeout => (504, "DEADLINE_EXCEEDED"),
        StatusClass::Network => (503, "UNAVAILABLE"),
        StatusClass::Auth => (401, "UNAUTHENTICATED"),
        StatusClass::Billing => (403, "PERMISSION_DENIED"),
        StatusClass::ClientError => (400, "INVALID_ARGUMENT"),
        StatusClass::ContextLength => (400, "INVALID_ARGUMENT"),
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
                        // If the joined text is valid JSON, forward it as the structured response.
                        // Otherwise (e.g. multiple plain-text chunks) wrap the raw text in
                        // `{"output": <text>}` — the Gemini functionResponse convention for
                        // plain-text tool output — rather than silently discarding the content
                        // with an empty `{}` object.
                        let response_val: serde_json::Value = serde_json::from_str(&response_text)
                            .unwrap_or_else(|_| serde_json::json!({ "output": response_text }));
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

        // NB: the native Gemini GenerateContentRequest schema has NO top-level `stream` field —
        // streaming is selected entirely by the URL endpoint (`:generateContent` vs
        // `:streamGenerateContent?alt=sse`, produced by `upstream_path_for_stream`). Injecting a
        // `stream` member here would make every egress request non-native (a backend could tell it
        // wasn't a real client) and the Google Generative Language API rejects unknown top-level
        // fields with INVALID_ARGUMENT. `req.stream` is therefore read only by path selection and
        // never serialised into the body. It is also kept out of the `extra` passthrough below: the
        // reader lists `stream` in `modeled_keys`, so a `stream` key is never echoed from `extra`.

        // Merge extra fields (may override, but that's expected behavior)
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    /// Native Gemini error envelope: `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`.
    /// This mirrors the google.rpc.Status shape every Gemini/Google AI Generative Language API error
    /// uses (and that `extract_error` above already parses on the read side: `error.code` /
    /// `error.status`). The official `google-genai` SDK raises `APIError` whose `.code`/`.status`
    /// read straight off these fields, so a native client gets its typed exception. Served as
    /// application/json (the trait contract; every vendor error envelope is JSON).
    ///
    /// `status` is mapped to the canonical google.rpc.Code name for the HTTP status; the generic
    /// `kind` is mapped onto that vocabulary where a known busbar/router category exists, otherwise
    /// the HTTP-status-derived name wins (so an unrecognized `kind` never produces a non-canonical
    /// `status` string a native SDK would choke on). No `_ =>` catch-all is used on `kind`; the
    /// final fallback is the explicit HTTP-status mapping.
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // google.rpc.Code name for an HTTP status (the canonical Generative Language API mapping).
        fn status_name_for_http(status: u16) -> &'static str {
            match status {
                400 => "INVALID_ARGUMENT",
                401 => "UNAUTHENTICATED",
                403 => "PERMISSION_DENIED",
                404 => "NOT_FOUND",
                409 => "ABORTED",
                429 => "RESOURCE_EXHAUSTED",
                499 => "CANCELLED",
                500 => "INTERNAL",
                501 => "UNIMPLEMENTED",
                503 => "UNAVAILABLE",
                504 => "DEADLINE_EXCEEDED",
                s if (400..500).contains(&s) => "INVALID_ARGUMENT",
                s if (500..600).contains(&s) => "INTERNAL",
                _ => "UNKNOWN",
            }
        }

        // Map busbar/router `kind` categories onto google.rpc.Code names where one exists. An
        // unknown `kind` yields `None` so the HTTP-status mapping (always defined) is authoritative.
        fn status_name_for_kind(kind: &str) -> Option<&'static str> {
            match kind {
                "invalid_request_error" | "invalid_argument" | "bad_request" => {
                    Some("INVALID_ARGUMENT")
                }
                "authentication_error" | "unauthenticated" | "auth" => Some("UNAUTHENTICATED"),
                "permission_error" | "permission_denied" | "forbidden" => Some("PERMISSION_DENIED"),
                "not_found_error" | "not_found" => Some("NOT_FOUND"),
                "rate_limit_error" | "resource_exhausted" | "rate_limit" => {
                    Some("RESOURCE_EXHAUSTED")
                }
                "overloaded_error" | "unavailable" => Some("UNAVAILABLE"),
                "deadline_exceeded" | "timeout" => Some("DEADLINE_EXCEEDED"),
                "api_error" | "internal" | "server_error" => Some("INTERNAL"),
                "unimplemented" | "not_implemented" => Some("UNIMPLEMENTED"),
                _ => None,
            }
        }

        let status_str = status_name_for_kind(kind).unwrap_or_else(|| status_name_for_http(status));

        serde_json::json!({
            "error": {
                "code": status,
                "message": message,
                "status": status_str,
            }
        })
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            // MessageStart → a leading identity-only chunk WHEN identity is known. Native Gemini SSE
            // chunks carry top-level `responseId`/`modelVersion`; the official `google-genai` SDK
            // reads `chunk.response_id`/`chunk.model_version` off the stream. We emit one leading
            // frame carrying whatever identity the egress captured (so a Gemini→Gemini stream is
            // indistinguishable on those fields, and a cross-protocol stream that carries an id/model
            // surfaces them). When NEITHER an id NOR a model is present (`None`/`None`), we emit no
            // frame at all — mirroring `write_response`'s omit-on-`None` fidelity rule, so a native
            // stream that carried no identity is not made distinguishable by an injected empty chunk.
            // `created` has no Gemini stream analogue and is never emitted.
            IrStreamEvent::MessageStart { id, model, .. } => {
                let mut frame = serde_json::Map::new();
                match (id, model) {
                    (Some(id), _) => {
                        frame.insert("responseId".to_string(), serde_json::json!(id));
                    }
                    // Cross-protocol stream: `StreamTranslate` strips the foreign id/model to `None`
                    // before this writer runs. A native google-genai SDK reads `chunk.response_id`
                    // off the FIRST chunk (for observability/tracing), so emitting no identity frame
                    // at all is a detectable fidelity gap from a native Gemini stream (which always
                    // carries `responseId` in the first chunk). Synthesize one — matching the
                    // non-stream `write_response` behavior — rather than dropping the frame.
                    (None, _) => {
                        frame.insert(
                            "responseId".to_string(),
                            serde_json::json!(synth_response_id()),
                        );
                    }
                }
                if let Some(model) = model {
                    frame.insert("modelVersion".to_string(), serde_json::json!(model));
                }
                Some(("".to_string(), serde_json::Value::Object(frame)))
            }

            // BlockStart → for a tool block, emit a `functionCall` frame carrying the tool NAME.
            // The IR carries the tool name only on BlockStart (IrBlockMeta::ToolUse{name}); the
            // arguments arrive on the following InputJsonDelta(s). Mirroring the OpenAI writer,
            // we split the Gemini frame the same way: name here, args on the delta. Dropping this
            // frame (as before) silently lost the function name, producing an unusable tool call.
            // Text blocks have no Gemini block-start frame (inline parts), so → None.
            IrStreamEvent::BlockStart { block, .. } => match block {
                crate::ir::IrBlockMeta::ToolUse { name, .. } => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"functionCall": {"name": name, "args": {}}}]
                            }
                        }]
                    }),
                )),
                crate::ir::IrBlockMeta::Text
                | crate::ir::IrBlockMeta::Thinking
                | crate::ir::IrBlockMeta::Image => None,
            },

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

                // InputJsonDelta → functionCall with args (best-effort, parse JSON string). The
                // function NAME is emitted on the preceding BlockStart frame (above); the Gemini
                // client merges the parts within `candidates[].content.parts`.
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    let args: serde_json::Value =
                        serde_json::from_str(json_str).unwrap_or(serde_json::json!({}));
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "candidates": [{
                                "content": {
                                    "role": "model",
                                    "parts": [{"functionCall": {"args": args}}]
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

            // Error → full google.rpc.Status envelope `{"error":{"code","message","status"}}`.
            // Real Gemini stream errors carry an HTTP `code` (int) and an UPPER_SNAKE `status`
            // (e.g. INTERNAL, UNAVAILABLE, RESOURCE_EXHAUSTED); a Gemini SDK branches on
            // `error.status`/`error.code`. Emitting only `message` (as before) was detectable and
            // left SDK retry-decision code reading null. We derive `code`/`status` from the
            // canonical `StatusClass`; an untyped/unknown class falls back to 500 / INTERNAL.
            IrStreamEvent::Error(err) => {
                let (code, status_name) = gemini_stream_error_code_status(err.class);
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "error": {
                            "code": code,
                            "message": message,
                            "status": status_name,
                        }
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
        // Response identity. This mirrors the Anthropic writer's id rule, keying synthesis off
        // "did we cross a protocol boundary" (proxied by `created` being populated) rather than off
        // `id` alone, so same-protocol round-trips stay idempotent. Three cases:
        //   * Same-protocol passthrough: the Gemini reader set `id` from the upstream `responseId`
        //     (and `created == None`, since Gemini bodies carry no timestamp), so it is re-emitted
        //     verbatim — `(Some(id), _)`.
        //   * Cross-protocol with a foreign id present: the non-Gemini backend reader set `id` to
        //     that protocol's response id (OpenAI `chatcmpl-…`, Anthropic `msg_…`); the id is opaque
        //     to the Gemini SDK (Gemini ids carry no documented prefix it could reject), so we
        //     surface it verbatim — `(Some(id), _)`.
        //   * Cross-protocol with NO foreign id: `forward.rs` strips `id` to `None` on every
        //     cross-protocol response but LEAVES `created` populated as the boundary signal, so
        //     `(None, Some(_))` — synthesize a Gemini-shaped `responseId` so a native `google-genai`
        //     client reading `GenerateContentResponse.response_id` always sees a value (real Gemini
        //     responses carry one). Previously this case omitted `responseId` on EVERY
        //     cross-protocol response, a distinguishability signal; the old comment wrongly claimed a
        //     value was "always present", contradicting `forward.rs` which sets `ir.id = None`.
        //   * Minimal same-protocol IR with neither id nor created: a native body that legitimately
        //     omitted `responseId` yields `(None, None)` — omit it rather than fabricate, since
        //     `responseId` is `Optional` in the Gemini schema / SDK and fabricating one would make a
        //     read→write round-trip distinguishable from the native response.
        // Gemini bodies carry no `created`, so none is emitted in the wire shape.
        match (&resp.id, resp.created) {
            (Some(id), _) => {
                out["responseId"] = serde_json::json!(id);
            }
            (None, Some(_)) => {
                out["responseId"] = serde_json::json!(synth_response_id());
            }
            (None, None) => {}
        }
        out
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, StreamDecodeState};

    fn collect_stream(chunks: &[serde_json::Value]) -> Vec<IrStreamEvent> {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(reader.read_response_events("", chunk, &mut state));
        }
        events
    }

    /// Regression: a streamed functionCall MUST produce a matching BlockStop for its tool block.
    /// Previously the tool index was never recorded in `state.open_tools`, so the finishReason
    /// drain (which is the only thing that closes tool blocks) left an orphaned BlockStart.
    #[test]
    fn test_stream_tool_block_is_closed() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
                },
                "finishReason": "STOP"
            }]
        })]);

        // Find the tool BlockStart and capture its index.
        let tool_start_idx = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { name, .. },
            } if name == "get_weather" => Some(*index),
            _ => None,
        });
        let idx = tool_start_idx.expect("tool BlockStart must be emitted");

        // The same index MUST be closed by a BlockStop.
        let closed = events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx));
        assert!(
            closed,
            "tool block {idx} was opened but never closed: {events:?}"
        );

        // Balance check: every BlockStart has a matching BlockStop.
        let starts = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        let stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count();
        assert_eq!(starts, stops, "unbalanced block events: {events:?}");
    }

    /// Regression: text + tool in the same response use distinct, stable indices (text=0, tool=1)
    /// and BOTH are closed.
    #[test]
    fn test_stream_text_and_tool_indices_stable_and_closed() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "hello"},
                        {"functionCall": {"name": "f", "args": {}}}
                    ]
                },
                "finishReason": "STOP"
            }]
        })]);

        let text_start = events.iter().any(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                }
            )
        });
        assert!(text_start, "text block must open at index 0");

        let tool_start = events.iter().any(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse { .. }
                }
            )
        });
        assert!(tool_start, "tool block must open at index 1");

        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 })),
            "text block (0) must be closed"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 1 })),
            "tool block (1) must be closed"
        );
    }

    /// Regression: tool block indices stay stable when the functionCall arrives in a different
    /// chunk than the finishReason (per-chunk local reset previously corrupted this).
    #[test]
    fn test_stream_tool_index_stable_across_chunks() {
        let events = collect_stream(&[
            serde_json::json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{"functionCall": {"name": "f", "args": {"a": 1}}}]
                    }
                }]
            }),
            serde_json::json!({
                "candidates": [{ "finishReason": "STOP" }]
            }),
        ]);

        let start_idx = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        });
        let idx = start_idx.expect("tool BlockStart must be emitted");
        assert_eq!(idx, 1, "tool block must take index 1 (text owns 0)");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
            "tool block opened in chunk 1 must be closed by finishReason in chunk 2: {events:?}"
        );
    }

    /// Regression: two functionCalls in one response get distinct indices (1 and 2) and both close.
    #[test]
    fn test_stream_two_tools_distinct_indices() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"functionCall": {"name": "a", "args": {}}},
                        {"functionCall": {"name": "b", "args": {}}}
                    ]
                },
                "finishReason": "STOP"
            }]
        })]);

        let mut tool_indices: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::ToolUse { .. },
                } => Some(*index),
                _ => None,
            })
            .collect();
        tool_indices.sort_unstable();
        assert_eq!(tool_indices, vec![1, 2], "two tools must take indices 1,2");

        for idx in [1usize, 2usize] {
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
                "tool block {idx} must be closed"
            );
        }
    }

    /// Regression: the Gemini writer must NOT drop the tool name. The name is carried on the
    /// BlockStart frame (mirroring the OpenAI writer); previously BlockStart returned None and the
    /// InputJsonDelta frame emitted `"name": ""`, losing the function name entirely.
    #[test]
    fn test_writer_tool_blockstart_carries_name() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        };
        let (_, chunk) = writer
            .write_response_event(&ev)
            .expect("tool BlockStart must emit a functionCall frame carrying the name");

        let name = chunk
            .pointer("/candidates/0/content/parts/0/functionCall/name")
            .and_then(|n| n.as_str());
        assert_eq!(name, Some("get_weather"), "frame: {chunk}");
    }

    /// The text BlockStart still produces no frame (Gemini inlines text parts).
    #[test]
    fn test_writer_text_blockstart_is_none() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Text,
        };
        assert!(writer.write_response_event(&ev).is_none());
    }

    /// The InputJsonDelta frame carries args (and no longer asserts an empty name).
    #[test]
    fn test_writer_input_json_delta_carries_args() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
        };
        let (_, chunk) = writer.write_response_event(&ev).expect("args frame");
        let city = chunk
            .pointer("/candidates/0/content/parts/0/functionCall/args/city")
            .and_then(|c| c.as_str());
        assert_eq!(city, Some("SF"), "frame: {chunk}");
        // The args frame must NOT carry an empty/placeholder name.
        assert!(
            chunk
                .pointer("/candidates/0/content/parts/0/functionCall/name")
                .is_none(),
            "args frame must not carry a name field: {chunk}"
        );
    }

    /// extract_error parses the body once and derives both the provider code and structured type.
    #[test]
    fn test_extract_error_single_parse_fields() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":"429","status":"RESOURCE_EXHAUSTED"}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.http_status, 429);
        assert_eq!(raw.provider_code.as_deref(), Some("429"));
        assert_eq!(raw.structured_type.as_deref(), Some("RESOURCE_EXHAUSTED"));
        // classify()/extract_error do not see headers, so retry_after is sourced elsewhere.
        assert_eq!(raw.retry_after_secs, None);
    }

    /// When `code` is absent, extract_error falls back to `status` for the provider code.
    #[test]
    fn test_extract_error_status_fallback() {
        let reader = GeminiReader;
        let body = br#"{"error":{"status":"PERMISSION_DENIED"}}"#;
        let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
        assert_eq!(raw.provider_code.as_deref(), Some("PERMISSION_DENIED"));
        assert_eq!(raw.structured_type.as_deref(), Some("PERMISSION_DENIED"));
    }

    /// Malformed (non-JSON) error bodies yield None fields without panicking.
    #[test]
    fn test_extract_error_non_json_body() {
        let reader = GeminiReader;
        let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, b"upstream exploded");
        assert_eq!(raw.http_status, 500);
        assert_eq!(raw.provider_code, None);
        assert_eq!(raw.structured_type, None);
    }

    /// The native Gemini error envelope is google.rpc.Status-shaped:
    /// `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`. `code` is the HTTP status
    /// int, `status` is the canonical google.rpc.Code name. A known `kind` maps to the matching
    /// name; the body is valid JSON the official SDK can decode into `APIError.code`/`.status`.
    #[test]
    fn test_write_error_native_gemini_envelope() {
        let writer = GeminiWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");
        // Round-trips as JSON (no panic).
        let serialized = serde_json::to_string(&v).expect("write_error must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error must be valid JSON");
        assert_eq!(reparsed["error"]["code"], serde_json::json!(404));
        assert_eq!(
            reparsed["error"]["message"],
            serde_json::json!("model 'x' not found")
        );
        assert_eq!(reparsed["error"]["status"], serde_json::json!("NOT_FOUND"));
        // The generic envelope's `type` field must NOT appear (this is the native shape).
        assert!(
            reparsed["error"].get("type").is_none(),
            "native gemini envelope must not carry an OpenAI-style `type`: {v}"
        );
    }

    /// `kind` is mapped onto the google.rpc.Code vocabulary (e.g. rate-limit → RESOURCE_EXHAUSTED).
    #[test]
    fn test_write_error_kind_maps_to_status_vocabulary() {
        let writer = GeminiWriter;
        let v = writer.write_error(429, "rate_limit_error", "slow down");
        assert_eq!(v["error"]["code"], serde_json::json!(429));
        assert_eq!(
            v["error"]["status"],
            serde_json::json!("RESOURCE_EXHAUSTED")
        );

        let v = writer.write_error(400, "invalid_request_error", "bad");
        assert_eq!(v["error"]["status"], serde_json::json!("INVALID_ARGUMENT"));
    }

    /// An unrecognized `kind` falls back to the HTTP-status-derived google.rpc.Code name (never a
    /// non-canonical `status` string a native SDK would choke on). Exercises the no-catch-all path.
    #[test]
    fn test_write_error_unknown_kind_falls_back_to_http_status() {
        let writer = GeminiWriter;
        let v = writer.write_error(403, "totally_made_up_kind", "nope");
        assert_eq!(v["error"]["status"], serde_json::json!("PERMISSION_DENIED"));
        // A 5xx with an unknown kind maps to INTERNAL.
        let v = writer.write_error(502, "totally_made_up_kind", "bad gateway");
        assert_eq!(v["error"]["status"], serde_json::json!("INTERNAL"));
    }

    /// Same-protocol (Gemini→Gemini) passthrough preserves the upstream `responseId` and
    /// `modelVersion` exactly: read_response captures them, write_response emits them verbatim.
    #[test]
    fn test_response_identity_roundtrip_preserves_id_and_model() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let upstream = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1},
            "modelVersion": "gemini-1.5-pro-002",
            "responseId": "abc-XYZ-123_opaque"
        });
        let ir = reader.read_response(&upstream).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("abc-XYZ-123_opaque"));
        assert_eq!(ir.model.as_deref(), Some("gemini-1.5-pro-002"));

        let wire = writer.write_response(&ir);
        assert_eq!(
            wire["responseId"],
            serde_json::json!("abc-XYZ-123_opaque"),
            "responseId must be preserved verbatim on same-protocol passthrough: {wire}"
        );
        assert_eq!(
            wire["modelVersion"],
            serde_json::json!("gemini-1.5-pro-002"),
            "modelVersion must be preserved verbatim: {wire}"
        );
        // Gemini bodies carry no `created`; we must not fabricate one.
        assert!(
            wire.get("created").is_none(),
            "must not synthesize a `created` field Gemini never emits: {wire}"
        );
    }

    /// Cross-protocol write where a non-Gemini backend reader DID set a response id (the normal
    /// cross-protocol case — OpenAI `chatcmpl-…`, Anthropic `msg_…`) emits it as `responseId`, so a
    /// native `google-genai` SDK reading `GenerateContentResponse.response_id` always sees a value.
    /// No panic; the emitted value matches the IR id verbatim.
    #[test]
    fn test_response_identity_cross_protocol_emits_foreign_id() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
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
            id: Some("chatcmpl-abc123".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire["responseId"],
            serde_json::json!("chatcmpl-abc123"),
            "a cross-protocol response id must surface as responseId: {wire}"
        );
    }

    /// Fidelity guard: when the IR carries NO id (a native Gemini body that omitted `responseId`, or
    /// a backend with no identity at all), `write_response` must NOT fabricate one — emitting a
    /// `responseId` would make a native passthrough distinguishable from the real response. The
    /// field is optional in the Gemini schema, so omission is SDK-valid. No panic.
    #[test]
    fn test_response_identity_none_id_is_omitted_not_fabricated() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
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
        let wire = writer.write_response(&ir);
        assert!(
            wire.get("responseId").is_none(),
            "must not fabricate a responseId when the IR carries none: {wire}"
        );
    }

    /// The streaming reader captures the stream identity from the first chunk into MessageStart,
    /// and the streaming writer emits it back (synthesizing when absent) — same-protocol fidelity.
    #[test]
    fn test_stream_message_start_captures_and_emits_identity() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]}
            }],
            "modelVersion": "gemini-1.5-flash",
            "responseId": "stream-abc-1"
        })]);
        let start = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageStart { id, model, .. } => Some((id.clone(), model.clone())),
                _ => None,
            })
            .expect("MessageStart emitted");
        assert_eq!(start.0.as_deref(), Some("stream-abc-1"));
        assert_eq!(start.1.as_deref(), Some("gemini-1.5-flash"));

        // The writer emits a leading identity frame carrying the captured responseId.
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: start.0.clone(),
                created: None,
                model: start.1.clone(),
            })
            .expect("MessageStart must emit an identity frame");
        assert_eq!(
            frame.1["responseId"],
            serde_json::json!("stream-abc-1"),
            "stream MessageStart frame must carry responseId: {}",
            frame.1
        );
    }

    /// Cross-protocol fidelity (stream): a MessageStart with NO identity (the post-strip state on a
    /// cross-protocol Gemini-ingress stream — `StreamTranslate` clears the foreign id/model) must
    /// still SYNTHESIZE a `responseId`, because a native google-genai SDK reads `chunk.response_id`
    /// off the first chunk. Emitting no frame (the old behavior) left the client with no responseId on
    /// any cross-protocol Gemini stream — a detectable fidelity gap. Mirrors the non-stream
    /// `write_response` synthesis. (Same-protocol Gemini streams never reach this writer — they pass
    /// through byte-for-byte — so this only affects the cross-protocol path.)
    #[test]
    fn test_stream_message_start_no_identity_synthesizes_response_id() {
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("a synthesized-identity MessageStart must emit a frame");
        assert!(
            frame
                .1
                .get("responseId")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "post-strip MessageStart must synthesize a responseId: {}",
            frame.1
        );
    }

    /// Regression: `write_request` must NOT inject a top-level `stream` field. The native Gemini
    /// GenerateContentRequest has no such field (streaming is URL-selected); injecting it makes the
    /// request non-native and can trigger INVALID_ARGUMENT on the real API.
    #[test]
    fn test_write_request_omits_stream_field() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
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
            stream: true,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert!(
            wire.get("stream").is_none(),
            "write_request must not serialise a top-level `stream` field: {wire}"
        );
    }

    /// Regression: a NATIVE request (which never carries `stream`) must produce a body with no
    /// `stream` member — i.e. the writer no longer injects one unconditionally. The streaming
    /// intent (`IrRequest.stream == true`) must NOT leak into the body even when set.
    #[test]
    fn test_native_request_without_stream_stays_streamless() {
        let reader = GeminiReader;
        // Native Gemini request — no `stream` field.
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let mut ir = reader.read_request(&body).expect("read_request");
        // Caller wants streaming (URL-selected), but it must not reach the body.
        ir.stream = true;
        assert!(
            !ir.extra.contains_key("stream"),
            "a native request carries no stream in extra: {:?}",
            ir.extra
        );
        let wire = GeminiWriter.write_request(&ir);
        assert!(
            wire.get("stream").is_none(),
            "stream intent must not be serialised into the body: {wire}"
        );
    }

    /// Regression: `model` is preserved in `extra` exactly once (no duplicate insert) and survives
    /// the read path because it is excluded from the loop via `modeled_keys`.
    #[test]
    fn test_read_request_model_preserved_in_extra_once() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "model": "gemini-1.5-pro"
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.extra.get("model"),
            Some(&serde_json::json!("gemini-1.5-pro")),
            "model must be preserved in extra: {:?}",
            ir.extra
        );
    }

    /// Regression: a ToolResult whose content is multi-part PLAIN TEXT (not JSON) must be wrapped in
    /// `{"output": <text>}` rather than silently discarded as an empty `{}` object.
    #[test]
    fn test_write_request_tool_result_plaintext_wrapped_not_dropped() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "get_weather".to_string(),
                    content: vec![
                        crate::ir::IrBlock::Text {
                            text: "sunny".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                        crate::ir::IrBlock::Text {
                            text: "and warm".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                    ],
                    is_error: false,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let resp = wire
            .pointer("/contents/0/parts/0/functionResponse/response")
            .expect("functionResponse.response must be present");
        assert_ne!(
            resp,
            &serde_json::json!({}),
            "plain-text tool result must not be discarded as empty object: {wire}"
        );
        assert_eq!(
            resp.get("output").and_then(|o| o.as_str()),
            Some("sunny and warm"),
            "plain-text tool result must be wrapped as {{\"output\": text}}: {wire}"
        );
    }

    /// A ToolResult whose joined text IS valid JSON is forwarded structurally (not wrapped).
    #[test]
    fn test_write_request_tool_result_json_passthrough() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "f".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "{\"temp\":21}".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let temp = wire
            .pointer("/contents/0/parts/0/functionResponse/response/temp")
            .and_then(|v| v.as_i64());
        assert_eq!(temp, Some(21), "JSON tool result must pass through: {wire}");
    }

    /// Regression: a cross-protocol response with NO foreign id but a populated `created` (the
    /// boundary signal `forward.rs` leaves intact after stripping `id`) must SYNTHESIZE a
    /// Gemini-shaped `responseId` so a native SDK always sees a value. Previously omitted entirely.
    #[test]
    fn test_response_identity_cross_protocol_synthesizes_id_when_created_set() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
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
            created: Some(1_700_000_000),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        let synth = wire
            .get("responseId")
            .and_then(|v| v.as_str())
            .expect("cross-protocol response (created set, id none) must synthesize responseId");
        assert!(
            !synth.is_empty(),
            "synthesized responseId must be non-empty: {wire}"
        );
    }

    /// Regression: the in-stream Error frame emits the FULL google.rpc.Status envelope
    /// (`code` int + UPPER_SNAKE `status` + message), not a message-only object, so a Gemini SDK
    /// can branch on `error.status`/`error.code`. Class → code/status is exhaustive (no catch-all).
    #[test]
    fn test_stream_error_emits_full_google_rpc_status() {
        let writer = GeminiWriter;
        let err = crate::proto::IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        };
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("Error event must emit a frame");
        assert_eq!(
            frame.pointer("/error/code"),
            Some(&serde_json::json!(429)),
            "frame: {frame}"
        );
        assert_eq!(
            frame.pointer("/error/status").and_then(|s| s.as_str()),
            Some("RESOURCE_EXHAUSTED"),
            "frame: {frame}"
        );
        assert_eq!(
            frame.pointer("/error/message").and_then(|m| m.as_str()),
            Some("slow down"),
            "frame: {frame}"
        );
    }

    /// A server-error class maps to 500/INTERNAL in the stream error envelope.
    #[test]
    fn test_stream_error_server_error_maps_internal() {
        let writer = GeminiWriter;
        let err = crate::proto::IrError {
            class: StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        };
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("Error event must emit a frame");
        assert_eq!(frame.pointer("/error/code"), Some(&serde_json::json!(500)));
        assert_eq!(
            frame.pointer("/error/status").and_then(|s| s.as_str()),
            Some("INTERNAL")
        );
        // No provider_signal → default message, no panic.
        assert_eq!(
            frame.pointer("/error/message").and_then(|m| m.as_str()),
            Some("error")
        );
    }

    /// A cross-protocol stream that carries only a model (no id) surfaces `modelVersion` AND a
    /// synthesized `responseId` on the leading frame — a native SDK reads both `chunk.model_version`
    /// and `chunk.response_id` off the first chunk.
    #[test]
    fn test_stream_message_start_model_only_emits_model_version() {
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: Some("gemini-1.5-pro".to_string()),
            })
            .expect("a model-bearing MessageStart must emit a frame");
        assert_eq!(
            frame.1["modelVersion"],
            serde_json::json!("gemini-1.5-pro"),
            "frame must carry modelVersion: {}",
            frame.1
        );
        assert!(
            frame
                .1
                .get("responseId")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "no id → responseId synthesized so the SDK still sees one: {}",
            frame.1
        );
    }
}
