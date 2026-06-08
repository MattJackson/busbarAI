// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Bedrock Converse protocol reader/writer implementation.

use super::*;

/// Map busbar's generic error `kind` vocabulary to the AWS Bedrock Converse exception name carried
/// in `__type`. AWS's Converse error model is a fixed, closed set of exception shapes
/// (`ValidationException`, `ThrottlingException`, `AccessDeniedException`, `ResourceNotFoundException`,
/// `ModelTimeoutException`, `ServiceUnavailableException`, `InternalServerException`,
/// `ServiceQuotaExceededException`, `ModelErrorException`); a native SDK matches on exactly these.
/// Any kind without a Bedrock-native counterpart falls back to `ValidationException` (the generic
/// client-error shape) — chosen deliberately over a catch-all so the wire `__type` is always a real
/// AWS exception name. This is the inverse of the `__type` token `extract_error` reads back, so a
/// same-protocol error round-trips its structured type.
pub(crate) fn error_kind_to_bedrock_type(kind: &str) -> &'static str {
    match kind {
        "invalid_request_error" | "invalid_request" | "validation" | "bad_request" => {
            "ValidationException"
        }
        "rate_limit_error" | "rate_limit" | "too_many_requests" | "throttling" => {
            "ThrottlingException"
        }
        "authentication_error" | "permission_error" | "auth" | "forbidden" | "unauthorized" => {
            "AccessDeniedException"
        }
        "not_found" | "not_found_error" | "model_not_found" => "ResourceNotFoundException",
        "timeout" | "model_timeout" => "ModelTimeoutException",
        "overloaded_error" | "service_unavailable" | "unavailable" => "ServiceUnavailableException",
        "quota_exceeded" | "service_quota_exceeded" | "insufficient_quota" => {
            "ServiceQuotaExceededException"
        }
        "api_error" | "internal_error" | "server_error" => "InternalServerException",
        // No native Bedrock counterpart: fall back to the generic client-error exception so the
        // wire `__type` is still a real AWS exception name a native SDK can decode.
        _ => "ValidationException",
    }
}

/// Map a mid-stream `IrError` to the native AWS Converse `(exception_name, message)` a Bedrock SDK
/// expects. Shared by `write_response_exception` (the StreamTranslate exception-frame path) and the
/// fallback `write_response_event` Error arm so the class→exception mapping has a single source of
/// truth. The message prefers the upstream's `provider_signal`, falling back to the exception name.
fn bedrock_exception_for(err: &crate::proto::IrError) -> (&'static str, String) {
    let kind = match err.class {
        StatusClass::RateLimit => "throttling",
        StatusClass::Timeout => "model_timeout",
        StatusClass::Auth => "auth",
        StatusClass::Billing => "quota_exceeded",
        StatusClass::ClientError | StatusClass::ContextLength => "invalid_request",
        StatusClass::Overloaded => "service_unavailable",
        StatusClass::ServerError | StatusClass::Network => "api_error",
    };
    let exception_name = error_kind_to_bedrock_type(kind);
    let message = err
        .provider_signal
        .clone()
        .unwrap_or_else(|| exception_name.to_string());
    (exception_name, message)
}

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
        // Parse the body once. Bedrock error responses carry the human-readable
        // text in `message` and the machine-readable error type in `__type`
        // (e.g. `ValidationException`, `ThrottlingException`). The structured
        // type is what the breaker's error_map keys on for fine-grained routing,
        // so it must come from `__type`, not from `message`.
        let (provider_code, structured_type) =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(json) => {
                    let provider_code = json
                        .get("message")
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    // AWS may also serialise the type as `__type` containing a
                    // shape ARN suffix (e.g. `com.amazon...#ThrottlingException`);
                    // keep only the trailing type token in that case.
                    let structured_type = json
                        .get("__type")
                        .and_then(|t| t.as_str())
                        .map(|t| t.rsplit(['#', '/']).next().unwrap_or(t).to_string());
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

        // Collect every unmodeled top-level request field into `extra` so a same-protocol
        // Bedrock->Bedrock passthrough re-emits them faithfully (see `write_request`, which merges
        // `req.extra`). Without this, native Converse fields this reader does not explicitly model —
        // `topP`, `topK`, `stopSequences`, `additionalModelRequestFields`, `guardrailConfig`,
        // `additionalModelResponseFieldPaths`, `performanceConfig`, `promptVariables`, etc. — are
        // silently dropped, changing model behaviour (guardrails disabled, sampling reset) and making
        // the proxy behaviourally divergent from a direct AWS call. Mirrors the Gemini/Cohere readers.
        // `stream` is the route-injected streaming discriminant captured into `IrRequest.stream`
        // below; it is intentionally NOT echoed via `extra` (a native Bedrock body never carries it,
        // and re-emitting it would be a tell). All other modeled keys are re-serialised by
        // `write_request` from the structured IR, so excluding them here avoids a double-emit.
        let modeled_keys: std::collections::HashSet<&str> = [
            "system",
            "messages",
            "toolConfig",
            "inferenceConfig",
            "stream",
            "model",
        ]
        .iter()
        .cloned()
        .collect();

        let mut extra = serde_json::Map::new();
        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

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
            // Bedrock's native Converse request body has no `stream` field — streaming is selected
            // by the endpoint (converse vs converse-stream). The Bedrock ingress route therefore
            // INJECTS `"stream": true` into the body for converse-stream requests before this reader
            // runs (see `ingress_path_model`), so on a Bedrock-INGRESS cross-protocol request the
            // re-parsed IR must carry that flag through — otherwise the target egress writer is never
            // told to produce a streaming body and a client that called /converse-stream silently
            // gets a buffered (non-streaming) response. Defaults to false when the field is absent
            // (a native Bedrock egress reads the flag from the endpoint, not the body, so this is
            // a no-op for the same-protocol path).
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
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
                        id: None,
                        created: None,
                        model: None,
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
                    } else if start_obj.is_empty() && state.started && !state.text_block_open {
                        // The native Bedrock ConverseStream wire sends `contentBlockStart` with an
                        // empty `start: {}` for a text block. Only that empty-object shape opens a
                        // Text block. A `start` object carrying an unrecognized key (e.g. a future
                        // `image`/`reasoningContent` block type) is NOT a text block: skip it rather
                        // than mis-opening a spurious Text block (forward-compatibility). Mirrors the
                        // defensive Gemini/Cohere readers.
                        state.text_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                } else if state.started && !state.text_block_open {
                    // No `start` object at all → a text block (the absent-`start` text shape).
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

                // Clear `text_block_open` on ANY contentBlockStop while a text block is open, not
                // only at index 0. Bedrock indexes text blocks that follow a tool-use block at
                // index > 0 (reachable via cross-protocol ingress where a tool-use precedes text).
                // The old `idx == 0` guard left the flag set for a text block opened at index N>0,
                // so the `!state.text_block_open` guard in contentBlockStart stayed true-blocked and
                // every subsequent text block was suppressed — silently dropping the rest of the
                // text content. At most one text block is open at a time on this wire (a new text
                // block only opens once the prior is closed), so the open flag unambiguously belongs
                // to the block whose stop we are processing; tool-use stops never set the flag.
                if state.text_block_open {
                    state.text_block_open = false;
                }

                out.push(IrStreamEvent::BlockStop { index: idx });
            }

            Some("messageStop") => {
                // Bedrock splits the stop reason (`messageStop` frame) from the token usage (a
                // following `metadata` frame). To emit ONE combined `MessageDelta{stop_reason, usage}`
                // — so a cross-protocol ingress (e.g. Anthropic) sees the SINGLE `message_delta` a
                // native non-Bedrock stream carries, instead of two (the previous behavior was a
                // detectable tell) — we BUFFER the stop_reason here and pair it with the usage when
                // `metadata` arrives (see below). The combined delta is emitted from the `metadata`
                // branch.
                //
                // The terminating MessageStop is still emitted here, on the wire-guaranteed terminal
                // event, so a malformed/truncated upstream that ends after `messageStop` without a
                // trailing `metadata` frame still terminates the downstream stream (the reader has no
                // end-of-stream hook). In that truncated case the buffered stop_reason is simply
                // dropped — exactly as usage was already dropped on a metadata-less stream — but the
                // client still receives its terminal frame.
                state.pending_stop_reason = data
                    .get("stopReason")
                    .and_then(|s| s.as_str())
                    .map(stop_reason_map);
                out.push(IrStreamEvent::MessageStop);
            }

            Some("metadata") => {
                // Usage trails the terminal MessageStop (Bedrock sends `metadata` after
                // `messageStop`). Pair it with the stop_reason buffered from the preceding
                // `messageStop` frame into ONE combined MessageDelta, so a cross-protocol ingress
                // emits a single `message_delta`/usage event (native fidelity) rather than two. The
                // terminal frame was already produced by the `messageStop` branch, so we do NOT emit
                // a second MessageStop here. A bedrock->bedrock round-trip re-splits this combined
                // delta back into the native `messageStop` + `metadata` frame pair in the writer
                // (`BedrockWriter::write_response_event` fan-out, driven by `StreamTranslate`).
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
                        stop_reason: state.pending_stop_reason.take(),
                        stop_sequence: None,
                        usage,
                    });
                }
            }

            // Bedrock-documented mid-stream exception event shapes. The ConverseStream wire can
            // carry a modeled error event in place of (or before) `messageStop`
            // (`internalServerException`, `modelStreamErrorException`, `modelTimeoutException`,
            // `throttlingException`, `validationException`, `serviceUnavailableException`). Surface
            // these as an `IrStreamEvent::Error` so the downstream ingress writer terminates the
            // client stream with a protocol-shaped error rather than silently dropping the event and
            // leaving the client on a hanging / EOF-without-terminator stream.
            Some(
                exc @ ("internalServerException"
                | "modelStreamErrorException"
                | "modelTimeoutException"
                | "throttlingException"
                | "validationException"
                | "serviceUnavailableException"),
            ) => {
                let message = data
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(String::from);
                let class = match exc {
                    "throttlingException" => StatusClass::RateLimit,
                    "modelTimeoutException" => StatusClass::Timeout,
                    "validationException" => StatusClass::ClientError,
                    "serviceUnavailableException" => StatusClass::Overloaded,
                    // internalServerException | modelStreamErrorException
                    _ => StatusClass::ServerError,
                };
                out.push(IrStreamEvent::Error(crate::proto::IrError {
                    class,
                    provider_signal: message.or_else(|| Some(exc.to_string())),
                    retry_after: None,
                }));
            }

            // Any other (or absent) event type is a no-op. This is NOT a disposition/breaker match:
            // it is the wire event-type demux for an open-ended, vendor-extensible event stream, so
            // an unrecognized future event must be skipped (not error) to avoid breaking forward
            // compatibility. The error-bearing event types are handled explicitly above.
            Some(_) | None => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let output_val = obj.get("output").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let message_val = output_val.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
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
            provider_signal: Some("ir_parse".to_string()),
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
            // Identity capture for same-protocol passthrough fidelity. The AWS Converse response
            // body is deliberately minimal: it has NO `id`, NO `created`, NO `system_fingerprint`,
            // and NO stop-sequence echo (`stopReason` is the discriminant, captured above; `usage`
            // is captured above). The only identity AWS returns is the `x-amzn-RequestId` HTTP
            // header, which is not part of the body this reader sees. So every body-level identity
            // field is `None` here — that is the faithful capture of what Bedrock actually sends,
            // and a bedrock→bedrock passthrough reproduces the native (id-less) body exactly.
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
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

    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        // streaming uses ConverseStream (binary application/vnd.amazon.eventstream response).
        if stream {
            format!("/model/{}/converse-stream", model)
        } else {
            format!("/model/{}/converse", model)
        }
    }

    fn auth_headers(&self, _key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Bedrock auth is per-request SigV4 — see `sign_request`. Static headers can't carry it.
        vec![]
    }

    /// AWS SigV4 signing for the Converse request. The lane key encodes credentials as
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

        // Validate the session token as a wire HeaderValue BEFORE adding it to the SIGNED set, so
        // the signed header set and the emitted header set can never diverge. If a session (STS)
        // token contains a byte `HeaderValue::from_str` rejects (e.g. an ASCII control char),
        // the previous code signed `x-amz-security-token` (committing the signature to it) but then
        // silently dropped the header on the wire — yielding a request whose signature claims the
        // token header is present while it is absent, which AWS rejects with SignatureDoesNotMatch
        // (a confusing 403, not the intended graceful "misconfigured credential" path). Instead,
        // bail to the same empty-header path used for a structurally-misconfigured key (request goes
        // out unsigned → AWS 403 surfaced as auth), with a diagnostic so the operator can see why.
        let token_header = match token {
            Some(t) => match HeaderValue::from_str(t) {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(
                        "Bedrock lane session token contains a byte rejected by HeaderValue \
                         (e.g. a control char); skipping signing to avoid a signed-but-absent \
                         x-amz-security-token header. Request goes out unsigned (AWS will 403)."
                    );
                    return vec![];
                }
            },
            None => None,
        };

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
        // The authorization value embeds `access` (the AWS access key id) taken directly from the
        // lane key config. A key id containing a control character (CR/LF) or any byte >= 0x80
        // makes `HeaderValue::from_str` fail. This runs on the request hot path, so we must NOT
        // panic: a malformed credential takes the same graceful "misconfigured key" path as the
        // parse failure above (return an empty header set → request goes out unsigned → AWS 403,
        // surfaced upstream as an auth failure) rather than aborting the request-handling task.
        let (Ok(authorization_val), Ok(amzdate_val), Ok(payload_hash_val)) = (
            HeaderValue::from_str(&authorization),
            HeaderValue::from_str(&amzdate),
            HeaderValue::from_str(&payload_hash),
        ) else {
            return vec![];
        };

        let mut out = vec![
            (HeaderName::from_static("authorization"), authorization_val),
            (HeaderName::from_static("x-amz-date"), amzdate_val),
            (
                HeaderName::from_static("x-amz-content-sha256"),
                payload_hash_val,
            ),
        ];
        // Use the HeaderValue validated up front (above): the signed set and the wire set are now
        // gated by the same check, so they can never diverge into a signed-but-absent token header.
        if let Some(v) = token_header {
            out.push((HeaderName::from_static("x-amz-security-token"), v));
        }
        out
    }

    fn rewrite_model(&self, _body: &mut serde_json::Value, _model: &str) {}

    // NOTE: Bedrock Converse treats `inferenceConfig.maxTokens` as OPTIONAL (it applies the model's
    // default when omitted, and this writer omits an empty `inferenceConfig` entirely). So Bedrock
    // does NOT override `requires_max_tokens` — injecting a default here would silently cap output.

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
                // A Tool-role IR message carries `toolResult` blocks; Bedrock Converse has no
                // freestanding "tool" role — a tool result is a `toolResult` content block inside a
                // USER-turn message, so mapping Tool → "user" is the correct native wire shape.
                crate::ir::IrRole::Tool => "user",
                // System text is extracted by the caller into `req.system` (emitted as the top-level
                // `system` array above), so a System-role MESSAGE should never reach the Bedrock
                // wire. If one somehow escapes extraction, skip it rather than silently mislabeling
                // it as a "user" turn (which would inject system instructions as a user message and
                // corrupt the conversation). Each role is handled explicitly — no catch-all.
                crate::ir::IrRole::System => continue,
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
                                // Bedrock Converse natively supports structured tool-result content
                                // via a `{"json": <value>}` block (the inverse of what `read_request`
                                // decodes). Preserve the actual content instead of collapsing it to
                                // the constant string `"{}"`: a JSON-string Text-equivalent or a
                                // structured result that arrives via the IR is re-encoded faithfully.
                                crate::ir::IrBlock::Image { media_type, data } => {
                                    let format_str = media_type
                                        .strip_prefix("image/")
                                        .unwrap_or("png")
                                        .to_string();
                                    inner_content.push(serde_json::json!({
                                        "image": { "format": format_str, "source": { "bytes": data } }
                                    }));
                                }
                                crate::ir::IrBlock::ToolUse { id, name, input } => {
                                    // Nested ToolUse inside a tool result has no native Bedrock
                                    // tool-result shape; carry it as a structured `json` block rather
                                    // than discarding the call identity.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": id, "name": name, "input": input }
                                    }));
                                }
                                crate::ir::IrBlock::ToolResult {
                                    tool_use_id,
                                    is_error,
                                    ..
                                } => {
                                    // A tool result nested inside another tool result is not a native
                                    // Bedrock shape; preserve its identity as a `json` block instead
                                    // of emitting a meaningless `"{}"` placeholder.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": tool_use_id, "isError": is_error }
                                    }));
                                }
                                // Thinking blocks have no representable Bedrock tool-result shape and
                                // carry no result data; omit them entirely (with a trace) rather than
                                // emitting a misleading placeholder block.
                                crate::ir::IrBlock::Thinking { .. } => {
                                    tracing::warn!(
                                        "dropping non-representable Thinking block inside a Bedrock toolResult"
                                    );
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
            IrStreamEvent::MessageStart {
                role: _, usage: _, ..
            } => Some((
                "messageStart".to_string(),
                serde_json::json!({ "role": "assistant" }),
            )),

            IrStreamEvent::BlockStart { index, block } => match block {
                // AWS ConverseStream emits a `contentBlockStart` frame at the start of EVERY content
                // block, including text blocks, with an empty `start` struct. A native AWS SDK uses
                // this event to initialize its per-block streaming decoder; omitting it for text
                // blocks leaves the following `contentBlockDelta`s orphaned (no preceding start),
                // which strict SDK parsers discard or reject — and is a detectable proxy tell.
                crate::ir::IrBlockMeta::Text => Some((
                    "contentBlockStart".to_string(),
                    serde_json::json!({ "contentBlockIndex": index, "start": {} }),
                )),
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

            // The native Bedrock ConverseStream wire carries `stopReason` in a `messageStop` frame
            // and token `usage` in a SEPARATE `metadata` frame that FOLLOWS it. The IR, however,
            // carries ONE combined `MessageDelta{stop_reason, usage}` (the reader collapses the two
            // native frames into one so a cross-protocol ingress sees a single `message_delta`/usage
            // event). A single `(event_type, json)` return cannot emit two frames, so the two-frame
            // FAN-OUT for a Bedrock INGRESS lives in `StreamTranslate::translate_event` (proto/mod.rs),
            // which splits a combined delta into a stop-only delta (→ here, `messageStop`) and a
            // usage-only delta (→ here, `metadata`) before calling this writer, and injects the real
            // `metrics.latencyMs` onto the `metadata` frame.
            //
            // This arm therefore maps each (already-split) MessageDelta to its single native frame:
            //   - stop_reason = Some(...)  → `messageStop` (the stop discriminant; usage ignored)
            //   - stop_reason = None       → `metadata` carrying the real token usage (no `metrics`
            //                                here — the StreamTranslate fan-out adds it with the real
            //                                elapsed wall-clock, or omits it when timing is absent;
            //                                fabricating a `latencyMs: 0` was itself a detectable tell).
            // Bedrock has no stop_sequence field in its stream, so `stop_sequence` is ignored here.
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => match stop_reason {
                Some(reason) => Some((
                    "messageStop".to_string(),
                    serde_json::json!({ "stopReason": stop_reason_reverse(reason) }),
                )),
                None => Some((
                    "metadata".to_string(),
                    serde_json::json!({
                        "usage": {
                            "inputTokens": usage.input_tokens,
                            "outputTokens": usage.output_tokens,
                            // Saturating add: token counts arrive from an untrusted upstream
                            // (`as_u64().unwrap_or(0)` in the reader); a pathological/hostile pair
                            // near `u64::MAX` would panic this request-path code under
                            // overflow-checks (all debug builds, opt-in release) or silently wrap to
                            // a nonsense `totalTokens` in plain release. Mirror the Gemini writer's
                            // explicit `saturating_add` so the total clamps at `u64::MAX` instead.
                            "totalTokens": usage.input_tokens.saturating_add(usage.output_tokens)
                        }
                    }),
                )),
            },

            IrStreamEvent::MessageStop => None,

            // A mid-stream error on the Bedrock-ingress path. The fully native representation is an
            // AWS modeled-exception EVENT-STREAM frame (`:message-type: exception` +
            // `:exception-type: <ExceptionName>`), which `StreamTranslate` now emits via
            // `write_response_exception` + `eventstream::encode_exception_frame` BEFORE reaching this
            // arm (a Bedrock-ingress stream never routes an `Error` through `write_response_event`).
            // This arm therefore only fires if a non-eventstream consumer ever drives a Bedrock
            // writer with an `Error` event; it falls back to a normal `event`-typed frame naming the
            // real Converse exception so the type token is still a genuine AWS name rather than the
            // literal `"error"`.
            IrStreamEvent::Error(err) => {
                let (exception_name, message) = bedrock_exception_for(err);
                Some((
                    exception_name.to_string(),
                    serde_json::json!({ "message": message }),
                ))
            }
        }
    }

    /// A Bedrock-ingress stream signals a mid-stream error with a MODELED-EXCEPTION event-stream
    /// frame (`:message-type: exception`), which `StreamTranslate` emits via
    /// `eventstream::encode_exception_frame`. This maps the IR error to that frame's
    /// `(exception_name, message)`, sharing the class→exception mapping with the (fallback)
    /// `write_response_event` Error arm so both stay consistent.
    fn write_response_exception(&self, err: &crate::proto::IrError) -> Option<(String, String)> {
        let (exception_name, message) = bedrock_exception_for(err);
        Some((exception_name.to_string(), message))
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

        // Identity emission. The native AWS Converse response body (the shape the official SDK
        // deserializes — `output` / `stopReason` / `usage` / optional `metrics`) carries NO id or
        // `created` field; AWS returns the request id only in the `x-amzn-RequestId` HTTP header.
        // Injecting a synthesized `id`/`created` into the JSON body would therefore be a
        // proxy-tell, not fidelity — so we deliberately do NOT add one. (The inverse direction — a
        // Bedrock egress feeding an OpenAI/Anthropic ingress that DOES require a body id — is the
        // job of that ingress writer, not this one; no Bedrock-side id synthesizer is wired into the
        // production path, so none is shipped.) `stopReason` and `usage` (the only identity-bearing
        // fields Bedrock emits) are reproduced exactly from the captured IR below, so a
        // same-protocol round-trip is byte-identical.
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
                // Saturating add, same rationale as the streaming `metadata` frame: token counts are
                // upstream-derived and unbounded, so a bare `u64 + u64` here is an overflow-panic
                // (overflow-checks) / silent-wrap (release) hazard on the buffered Converse body.
                "totalTokens": resp.usage.input_tokens.saturating_add(resp.usage.output_tokens)
            }
        })
    }

    /// Native AWS Bedrock Converse error envelope. The Converse error model (REST-JSON protocol)
    /// serializes every modeled exception as a flat body whose human-readable detail lives in a
    /// lowercase `"message"` member, with the machine-readable exception name in `"__type"` (the
    /// exact two fields `BedrockReader::extract_error` reads back). A native AWS SDK deserializes
    /// the typed exception from `__type` and surfaces the text from `message`; serving the generic
    /// `{"error":{...}}` envelope here would make a Bedrock SDK fail to decode the error. We map
    /// busbar's generic `kind` to the closed AWS exception set via `error_kind_to_bedrock_type` so
    /// the `__type` is always a real Converse exception name. Served as `application/json`.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "__type": error_kind_to_bedrock_type(kind),
            "message": message,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Cross-protocol response-id synthesis is NOT wired into any production path (Bedrock's own
    // body has no id field, and the inverse direction is the consuming ingress writer's job — see
    // `write_response`). The helper trio below was previously shipped in the production binary under
    // `#[cfg_attr(not(test), allow(dead_code))]`; it is now confined to the test module so 1.0 does
    // not carry dead production scaffolding. If/when the cross-protocol id-population seam lands, the
    // trio moves back into production scope (and loses this test-only home).

    /// Monotonic per-process counter so two ids minted in the same wall-clock second still differ.
    static SYNTH_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Current unix time in whole seconds; a pre-epoch clock degrades to 0 rather than panicking.
    fn unix_now_secs() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Mint a syntactically-plausible, collision-resistant `<hex16>-<hex16>` token from
    /// (unix seconds + a monotonic counter) — no UUID crate, no panic.
    fn synth_response_id() -> String {
        let n = SYNTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}-{:016x}", unix_now_secs(), n)
    }

    #[test]
    fn test_bedrock_sigv4_sign_request_structure() {
        // SigV4 header assembly + scope/region derivation. (The signing crypto itself is
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

        // Seven events: MessageStart, text BlockStart, 2×BlockDelta, BlockStop, the terminal
        // MessageStop (from `messageStop`, which now only BUFFERS the stop_reason), and ONE combined
        // MessageDelta{stop_reason, usage} (from `metadata`). Previously this was eight events because
        // `messageStop` emitted a separate stop-only MessageDelta and `metadata` emitted a second
        // usage-only one — two deltas, a tell for non-Bedrock ingress. The combined delta is now the
        // single source of both stop_reason and usage (finding: combined MessageDelta).
        assert_eq!(events.len(), 7);

        match &events[0] {
            IrStreamEvent::MessageStart { role, usage, .. } => {
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

        // The terminating MessageStop is emitted from the `messageStop` branch (the wire-guaranteed
        // terminal event), so a missing/truncated `metadata` event can no longer leave the downstream
        // stream without its terminal frame. The stop_reason is BUFFERED (not emitted here) so it can
        // be combined with the usage that arrives on the next frame.
        match &events[5] {
            IrStreamEvent::MessageStop => {}
            _ => panic!("event[5] should be MessageStop"),
        }

        // The trailing `metadata` event emits ONE combined MessageDelta carrying BOTH the buffered
        // stop_reason AND the real usage — a single `message_delta`-equivalent event, matching what a
        // native non-Bedrock stream emits (finding: combined MessageDelta, no second delta).
        match &events[6] {
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                assert_eq!(stop_reason.as_deref(), Some("end_turn"));
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => {
                panic!("event[6] should be the combined MessageDelta carrying stop_reason + usage")
            }
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
            stop_sequence: None,
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

    // --- Regression tests for the 1.0 hardening pass -------------------------------------------

    /// Regression: a malformed lane credential (access key id containing a control char that
    /// `HeaderValue::from_str` rejects) must NOT panic the request-handling task. It takes the
    /// same graceful path as a structurally-misconfigured key: an empty header set, so the
    /// request goes out unsigned and AWS surfaces a 403 auth error instead of aborting the task.
    #[test]
    fn test_bedrock_sigv4_control_char_in_access_key_no_panic() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
        };
        // CR/LF embedded in the access key id → invalid Authorization header value
        // (HeaderValue::from_str rejects ASCII control chars, including CR/LF). This is the
        // header-injection / misconfiguration vector the finding describes.
        let headers = writer.sign_request("AKID\r\nINJECT:SECRET", &ctx);
        assert!(
            headers.is_empty(),
            "control-char access key must yield no headers (graceful), not panic; got: {headers:?}"
        );

        // A bare NUL / control byte is likewise rejected gracefully rather than panicking.
        let headers2 = writer.sign_request("AKID\u{0001}X:SECRET", &ctx);
        assert!(
            headers2.is_empty(),
            "control-char access key must yield no headers; got: {headers2:?}"
        );

        // Sanity: a well-formed key still produces the full signed header set.
        let ok = writer.sign_request("AKIDEXAMPLE:SECRETKEY", &ctx);
        assert!(
            ok.iter().any(|(k, _)| k.as_str() == "authorization"),
            "valid key still signs"
        );
    }

    /// Regression: `extract_error` must read the machine-readable error type from the AWS `__type`
    /// field (used by the breaker's error_map for fine-grained routing), keeping the
    /// human-readable text in `provider_code` from `message`. Previously both were set from
    /// `message`, so error_map rules keyed on `structured_type` never matched.
    #[test]
    fn test_extract_error_structured_type_from_type_field() {
        let reader = BedrockReader;
        let body = br#"{"__type":"ThrottlingException","message":"Rate exceeded"}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.http_status, 429);
        assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("ThrottlingException"),
            "structured_type must come from __type, not the message"
        );
    }

    /// `__type` is sometimes serialised as a shape ARN suffix
    /// (`com.amazon.coral.service#ValidationException`); only the trailing type token is kept.
    #[test]
    fn test_extract_error_strips_type_arn_prefix() {
        let reader = BedrockReader;
        let body =
            br#"{"__type":"com.amazon.coral.service#ValidationException","message":"bad input"}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.provider_code.as_deref(), Some("bad input"));
        assert_eq!(raw.structured_type.as_deref(), Some("ValidationException"));
    }

    /// When `__type` is absent, `structured_type` is None (no longer duplicated from `message`).
    #[test]
    fn test_extract_error_no_type_field_yields_none_structured_type() {
        let reader = BedrockReader;
        let body = br#"{"message":"something went wrong"}"#;
        let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, body);
        assert_eq!(raw.provider_code.as_deref(), Some("something went wrong"));
        assert!(
            raw.structured_type.is_none(),
            "structured_type must NOT be duplicated from message"
        );
    }

    /// A non-JSON body parses gracefully to (None, None) — single parse, no panic.
    #[test]
    fn test_extract_error_non_json_body() {
        let reader = BedrockReader;
        let raw = reader.extract_error(StatusCode::BAD_GATEWAY, b"<html>502</html>");
        assert_eq!(raw.http_status, 502);
        assert!(raw.provider_code.is_none());
        assert!(raw.structured_type.is_none());
    }

    /// Regression: a ConverseStream that ends after `messageStop` WITHOUT a trailing `metadata`
    /// event (malformed/truncated upstream, or a provider variant) must still emit a terminal
    /// MessageStop so the downstream client receives its terminator instead of hanging.
    #[test]
    fn test_stream_terminates_without_metadata() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": "Hi"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            // NOTE: no `metadata` event — the upstream truncated here.
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageStop)),
            "a terminal MessageStop must be emitted even without a metadata event; got: {events:?}"
        );
        // The terminal MessageStop is the last event of the stream.
        assert!(
            matches!(events.last(), Some(IrStreamEvent::MessageStop)),
            "MessageStop must be the final event; got: {events:?}"
        );
    }

    /// Exactly one terminal MessageStop is emitted across the full happy-path sequence
    /// (messageStop + metadata) — no duplicate terminator.
    #[test]
    fn test_stream_emits_single_message_stop_with_metadata() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            serde_json::json!({"type": "metadata", "usage": {"inputTokens": 3, "outputTokens": 1}}),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        let stop_count = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStop))
            .count();
        assert_eq!(
            stop_count, 1,
            "exactly one terminal MessageStop expected; got: {events:?}"
        );
    }

    // --- 1.0 ingress: native error envelope + response-identity fidelity ----------------------

    /// The native Bedrock Converse error envelope is a flat `{"__type", "message"}` body (the exact
    /// shape `extract_error` reads back) — NOT the generic `{"error":{...}}` default. A generic kind
    /// maps to a real AWS exception name in `__type`, and the human text lands in lowercase
    /// `message`. There must be no top-level `error` object (that would be a non-native tell).
    #[test]
    fn test_write_error_native_bedrock_shape() {
        let writer = BedrockWriter;
        let v = writer.write_error(400, "invalid_request_error", "bad input");
        assert_eq!(
            v.get("message").and_then(|m| m.as_str()),
            Some("bad input"),
            "human text must be in lowercase `message`"
        );
        assert_eq!(
            v.get("__type").and_then(|t| t.as_str()),
            Some("ValidationException"),
            "generic kind must map to a native Converse exception name in `__type`"
        );
        assert!(
            v.get("error").is_none(),
            "must NOT carry the generic `{{\"error\":...}}` envelope (non-native tell)"
        );
        // Serializes cleanly (served as application/json).
        let s = serde_json::to_string(&v).expect("error envelope must serialize");
        assert!(s.contains("\"__type\""));
    }

    /// Kind → Bedrock exception-name mapping covers the common categories and falls back to a real
    /// exception name (never an invented one) for anything unmapped.
    #[test]
    fn test_error_kind_to_bedrock_type_mapping() {
        assert_eq!(
            error_kind_to_bedrock_type("rate_limit_error"),
            "ThrottlingException"
        );
        assert_eq!(error_kind_to_bedrock_type("auth"), "AccessDeniedException");
        assert_eq!(
            error_kind_to_bedrock_type("not_found"),
            "ResourceNotFoundException"
        );
        assert_eq!(
            error_kind_to_bedrock_type("overloaded_error"),
            "ServiceUnavailableException"
        );
        assert_eq!(
            error_kind_to_bedrock_type("api_error"),
            "InternalServerException"
        );
        // Unmapped → still a real AWS exception name, not a catch-all literal.
        assert_eq!(
            error_kind_to_bedrock_type("some_future_kind"),
            "ValidationException"
        );
    }

    /// The native error envelope round-trips back through `extract_error`: a Bedrock SDK (and the
    /// breaker's own reader) recovers both the structured type from `__type` and the text from
    /// `message`. This is the indistinguishability check that ties the writer to the reader.
    #[test]
    fn test_write_error_roundtrips_through_extract_error() {
        let writer = BedrockWriter;
        let reader = BedrockReader;
        let v = writer.write_error(429, "rate_limit_error", "Rate exceeded");
        let body = serde_json::to_vec(&v).expect("serialize");
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, &body);
        assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
        assert_eq!(raw.structured_type.as_deref(), Some("ThrottlingException"));
    }

    /// Same-protocol passthrough fidelity: reading a native Converse response and writing it back
    /// preserves stopReason + usage exactly, and the written body carries NO synthesized identity
    /// (`id`/`created`) — the native Converse body has none, so injecting one would be a tell.
    #[test]
    fn test_response_identity_same_protocol_roundtrip_no_synth() {
        let reader = BedrockReader;
        let writer = BedrockWriter;

        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello, world!"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
        });

        let resp = reader.read_response(&j).expect("read_response");
        // Capture: Bedrock's minimal body yields no body-level identity.
        assert_eq!(resp.id, None, "Converse body has no id to capture");
        assert_eq!(
            resp.created, None,
            "Converse body has no created to capture"
        );
        assert_eq!(resp.system_fingerprint, None);
        assert_eq!(resp.stop_sequence, None);
        // stopReason + usage are present (the identity-bearing fields Bedrock does emit).
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);

        let written = writer.write_response(&resp);
        assert_eq!(
            written, j,
            "same-protocol round-trip must be byte-identical"
        );
        // No proxy-tell identity fields injected into the native body.
        assert!(written.get("id").is_none(), "native body must carry no id");
        assert!(
            written.get("created").is_none(),
            "native body must carry no created"
        );
    }

    /// Cross-protocol synthesis: minting a Bedrock-flavored response id never panics and yields a
    /// unique, non-empty token (so an OpenAI/Anthropic ingress fed by a Bedrock egress can always
    /// get a valid body id). Uniqueness comes from the monotonic counter even within one second.
    #[test]
    fn test_synth_response_id_unique_and_nonempty() {
        let a = synth_response_id();
        let b = synth_response_id();
        assert!(!a.is_empty(), "synthesized id must be non-empty");
        assert!(!b.is_empty(), "synthesized id must be non-empty");
        assert_ne!(a, b, "two synthesized ids minted back-to-back must differ");
        // Shape sanity: `<hex16>-<hex16>` (no panic on parse of either half).
        let (lhs, rhs) = a.split_once('-').expect("synth id has a `-` separator");
        assert_eq!(lhs.len(), 16, "left half is 16 hex chars");
        assert_eq!(rhs.len(), 16, "right half is 16 hex chars");
        assert!(u64::from_str_radix(lhs, 16).is_ok());
        assert!(u64::from_str_radix(rhs, 16).is_ok());
    }

    // --- Round 2 regression tests --------------------------------------------------------------

    /// Regression (writer): a stream MessageDelta with `stop_reason = None` (the usage-only trailing
    /// delta the reader emits from the Bedrock `metadata` event, or a cross-protocol egress's usage
    /// frame) must be reframed as a native `metadata` frame carrying the real token usage — NOT a
    /// second `messageStop` (the old behavior, which both discarded usage and produced two
    /// `messageStop` frames, a distinguishable tell). A delta WITH a stop_reason still maps to
    /// `messageStop`.
    #[test]
    fn test_write_response_event_usage_delta_is_metadata_frame() {
        let writer = BedrockWriter;

        // Usage-only delta → `metadata` frame with the real usage (and a derived totalTokens).
        let usage_only = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&usage_only)
            .expect("usage-only delta must emit a frame");
        assert_eq!(
            et, "metadata",
            "usage-only delta must be a `metadata` frame, not messageStop"
        );
        assert_eq!(
            payload
                .pointer("/usage/inputTokens")
                .and_then(|v| v.as_u64()),
            Some(11)
        );
        assert_eq!(
            payload
                .pointer("/usage/outputTokens")
                .and_then(|v| v.as_u64()),
            Some(7)
        );
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(18),
            "totalTokens must be inputTokens + outputTokens"
        );

        // Stop-reason delta still maps to `messageStop` (the stop discriminant).
        let stop = IrStreamEvent::MessageDelta {
            stop_reason: Some("tool_use".to_string()),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et2, payload2) = writer
            .write_response_event(&stop)
            .expect("stop delta must emit a frame");
        assert_eq!(et2, "messageStop");
        assert_eq!(
            payload2.get("stopReason").and_then(|s| s.as_str()),
            Some("tool_use")
        );
    }

    /// Regression (writer): a text BlockStart must emit a native `contentBlockStart` frame with an
    /// empty `start` struct (AWS emits one for every block, text included) so a native SDK can
    /// initialize its block decoder and the following deltas are not orphaned.
    #[test]
    fn test_write_response_event_text_block_start_emits_frame() {
        let writer = BedrockWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        };
        let (et, payload) = writer
            .write_response_event(&ev)
            .expect("text BlockStart must emit a contentBlockStart frame");
        assert_eq!(et, "contentBlockStart");
        assert_eq!(
            payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
            Some(0)
        );
        assert!(
            payload
                .get("start")
                .and_then(|s| s.as_object())
                .map(|o| o.is_empty())
                .unwrap_or(false),
            "text block start must carry an empty `start` struct; got {payload}"
        );
    }

    /// Regression (reader): a mid-stream Bedrock exception event (`internalServerException` etc.)
    /// must surface as an `IrStreamEvent::Error` rather than being silently swallowed by a catch-all,
    /// so a client whose stream hits an upstream model error receives a protocol-shaped error frame
    /// instead of a hanging / EOF-without-terminator stream.
    #[test]
    fn test_stream_decode_surfaces_midstream_exception() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "internalServerException",
                "message": "the model is on fire"
            }),
            &mut state,
        );
        assert_eq!(
            events.len(),
            1,
            "exactly one Error event expected; got {events:?}"
        );
        match &events[0] {
            IrStreamEvent::Error(err) => {
                assert_eq!(err.class, StatusClass::ServerError);
                assert_eq!(err.provider_signal.as_deref(), Some("the model is on fire"));
            }
            other => panic!("expected IrStreamEvent::Error, got {other:?}"),
        }

        // A throttling exception maps to the RateLimit class and falls back to the exception name
        // when no `message` is present.
        let throttle = reader.read_response_events(
            "",
            &serde_json::json!({"type": "throttlingException"}),
            &mut state,
        );
        match throttle.as_slice() {
            [IrStreamEvent::Error(err)] => {
                assert_eq!(err.class, StatusClass::RateLimit);
                assert_eq!(err.provider_signal.as_deref(), Some("throttlingException"));
            }
            other => panic!("expected a single RateLimit Error; got {other:?}"),
        }

        // An unrecognized (future / non-error) event type is still a silent no-op.
        let unknown = reader.read_response_events(
            "",
            &serde_json::json!({"type": "someFutureEvent"}),
            &mut state,
        );
        assert!(
            unknown.is_empty(),
            "unknown event types must be skipped; got {unknown:?}"
        );
    }

    /// Regression (reader): the injected `stream` flag on a Bedrock-INGRESS converse-stream request
    /// must be read into the IR so a cross-protocol egress writer produces a streaming body. A body
    /// without the flag (native Bedrock egress, where streaming is endpoint-selected) defaults false.
    #[test]
    fn test_read_request_honors_injected_stream_flag() {
        let reader = BedrockReader;

        let streaming = serde_json::json!({
            "stream": true,
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });
        let ir = reader.read_request(&streaming).expect("read_request");
        assert!(
            ir.stream,
            "injected `stream: true` must be read into the IR"
        );

        let buffered = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });
        let ir2 = reader.read_request(&buffered).expect("read_request");
        assert!(
            !ir2.stream,
            "absent `stream` defaults to false (native egress)"
        );
    }

    /// Regression (writer): a System-role message that escapes the caller's system extraction is
    /// SKIPPED, not silently emitted as a `user` turn (which would inject system text as a user
    /// message). A Tool-role message is still emitted as a `user` turn (the native shape for a
    /// `toolResult` block).
    #[test]
    fn test_write_request_skips_system_role_message() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            system: vec![],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::System,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "leaked system text".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "ok".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    }],
                },
            ],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let json = writer.write_request(&req);
        let msgs = json
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array");
        assert_eq!(
            msgs.len(),
            1,
            "the System-role message must be dropped; got {msgs:?}"
        );
        assert_eq!(
            msgs[0].get("role").and_then(|r| r.as_str()),
            Some("user"),
            "the surviving Tool-role message maps to a user turn"
        );
        // The leaked system text must not appear anywhere on the wire.
        let wire = serde_json::to_string(&json).unwrap();
        assert!(
            !wire.contains("leaked system text"),
            "system text must not leak onto the wire; got {wire}"
        );
    }

    /// Regression (writer): a non-Text block inside a ToolResult must be re-encoded faithfully
    /// (Image → Bedrock `{"image":...}`, ToolUse/ToolResult → `{"json":...}`), never collapsed to
    /// the constant string `"{}"` placeholder the old catch-all produced.
    #[test]
    fn test_write_request_tool_result_preserves_non_text_content() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Image {
                        media_type: "image/png".to_string(),
                        data: "BASE64DATA".to_string(),
                    }],
                    is_error: false,
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let json = writer.write_request(&req);
        let inner = json
            .pointer("/messages/0/content/0/toolResult/content/0")
            .expect("tool result inner content block");
        assert_eq!(
            inner.pointer("/image/format").and_then(|v| v.as_str()),
            Some("png"),
            "image inner block must be a native Bedrock image block; got {inner}"
        );
        assert_eq!(
            inner
                .pointer("/image/source/bytes")
                .and_then(|v| v.as_str()),
            Some("BASE64DATA")
        );
        // The old `"{}"` placeholder must be gone.
        let wire = serde_json::to_string(&json).unwrap();
        assert!(
            !wire.contains(r#"{"text":"{}"}"#),
            "must not emit the `{{}}` placeholder; got {wire}"
        );
    }

    /// Regression (writer): a stream Error event names a REAL Converse exception (mapped from the IR
    /// error class) as its event-type token instead of the non-native literal `"error"`. (The
    /// `:message-type: exception` framing itself is the encoder's job — see the production
    /// mid-stream-error path in forward.rs — and is out of this unit's scope.)
    #[test]
    fn test_write_response_event_error_names_real_exception() {
        let writer = BedrockWriter;

        let throttle = IrStreamEvent::Error(crate::proto::IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        });
        let (et, payload) = writer
            .write_response_event(&throttle)
            .expect("error event must emit a frame");
        assert_eq!(
            et, "ThrottlingException",
            "event-type token must be a real Converse exception name, not `error`"
        );
        assert_eq!(
            payload.get("message").and_then(|m| m.as_str()),
            Some("slow down")
        );

        // A server-class error maps to InternalServerException and falls back to the exception name
        // when no provider_signal is present.
        let server = IrStreamEvent::Error(crate::proto::IrError {
            class: StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        });
        let (et2, payload2) = writer
            .write_response_event(&server)
            .expect("error event must emit a frame");
        assert_eq!(et2, "InternalServerException");
        assert_eq!(
            payload2.get("message").and_then(|m| m.as_str()),
            Some("InternalServerException")
        );
    }

    // --- Round 3 regression tests --------------------------------------------------------------

    /// Regression (reader): unmodeled top-level request fields must be collected into `extra` so a
    /// same-protocol Bedrock->Bedrock passthrough re-emits them faithfully (via `write_request`'s
    /// extra-merge). Previously `extra` was built empty and every native Converse field this reader
    /// does not explicitly model — `topP`, `topK`, `stopSequences`, `guardrailConfig`,
    /// `additionalModelRequestFields`, etc. — was silently dropped, disabling guardrails / resetting
    /// sampling on passthrough. The modeled keys (system/messages/toolConfig/inferenceConfig/stream)
    /// must NOT leak into `extra` (they are re-serialised from the structured IR; a double-emit /
    /// echoed `stream` would be a tell).
    #[test]
    fn test_read_request_collects_unmodeled_fields_into_extra() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 10},
            "system": [{"text": "sys"}],
            "toolConfig": {"tools": []},
            "stream": true,
            "topP": 0.95,
            "topK": 40,
            "stopSequences": ["STOP"],
            "guardrailConfig": {"guardrailIdentifier": "gr-1", "guardrailVersion": "1"},
            "additionalModelRequestFields": {"foo": "bar"}
        });
        let ir = reader.read_request(&j).expect("read_request");

        // Unmodeled fields are preserved verbatim.
        assert_eq!(ir.extra.get("topP"), Some(&serde_json::json!(0.95)));
        assert_eq!(ir.extra.get("topK"), Some(&serde_json::json!(40)));
        assert_eq!(
            ir.extra.get("stopSequences"),
            Some(&serde_json::json!(["STOP"]))
        );
        assert_eq!(
            ir.extra.get("guardrailConfig"),
            Some(&serde_json::json!({"guardrailIdentifier": "gr-1", "guardrailVersion": "1"}))
        );
        assert_eq!(
            ir.extra.get("additionalModelRequestFields"),
            Some(&serde_json::json!({"foo": "bar"}))
        );

        // Modeled keys must NOT be duplicated into `extra` (avoids double-emit / echoed `stream`).
        for k in [
            "system",
            "messages",
            "toolConfig",
            "inferenceConfig",
            "stream",
        ] {
            assert!(
                ir.extra.get(k).is_none(),
                "modeled key `{k}` must not leak into extra; got {:?}",
                ir.extra
            );
        }
        // `stream` is still captured in the structured field.
        assert!(
            ir.stream,
            "injected stream flag still captured structurally"
        );
    }

    /// Regression (reader + writer): a full passthrough — read a native Converse request carrying
    /// unmodeled fields, then write it back — must re-emit `topP`/`stopSequences`/`guardrailConfig`
    /// onto the wire, never strip them. Uses the existing rich fixture (which carries `top_p`).
    #[test]
    fn test_request_passthrough_preserves_unmodeled_fields() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let j = bedrock_rich_fixture(); // carries a top-level `top_p`
        let ir = reader.read_request(&j).expect("read_request");
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("top_p").and_then(|v| v.as_f64()),
            Some(0.95),
            "unmodeled `top_p` must survive a Bedrock->Bedrock passthrough; got {out}"
        );
    }

    /// Regression (reader): a text block that opens at index > 0 (after a preceding tool-use block,
    /// reachable via cross-protocol ingress) must have its `text_block_open` flag cleared on its
    /// contentBlockStop, so a LATER text block still emits a fresh BlockStart. The old `idx == 0`
    /// guard left the flag set for a text block at index N>0, suppressing all subsequent text
    /// BlockStarts and silently dropping the rest of the text content.
    #[test]
    fn test_stream_text_block_after_tool_not_dropped() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            // tool-use block at index 0
            serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            // text block at index 1 (start has no `start` object → text)
            serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 1}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 1,
                "delta": {"text": "first"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 1}),
            // a SECOND text block at index 2 — must still open (flag was cleared at idx 1 stop)
            serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 2}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 2,
                "delta": {"text": "second"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 2}),
        ]
        .into_iter()
        .flat_map(|d| reader.read_response_events("", &d, &mut state))
        .collect();

        // Two text BlockStarts must appear (at index 1 and index 2).
        let text_starts: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: crate::ir::IrBlockMeta::Text,
                } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(
            text_starts,
            vec![1, 2],
            "both text blocks (idx 1 and idx 2) must emit a BlockStart; got {events:?}"
        );
        // Both text deltas survive.
        let deltas: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::TextDelta(t),
                    ..
                } => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(deltas, vec!["first".to_string(), "second".to_string()]);
    }

    /// Regression (reader): a `contentBlockStart` whose `start` object carries an UNRECOGNIZED key
    /// (not `toolUse`, and not the empty `{}` text shape — e.g. a future `image`/`reasoningContent`
    /// block) must NOT be mis-opened as a Text block. Only an empty `start: {}` (or an absent
    /// `start`) opens text. Forward-compatibility / defensive parsing.
    #[test]
    fn test_stream_unrecognized_start_does_not_open_text() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let _ = reader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStart", "role": "assistant"}),
            &mut state,
        );
        // A `start` with an unrecognized key — must emit nothing (no spurious Text BlockStart).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"reasoningContent": {"foo": "bar"}}
            }),
            &mut state,
        );
        assert!(
            !evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::Text,
                    ..
                }
            )),
            "an unrecognized `start` key must not open a Text block; got {evs:?}"
        );
        assert!(
            !state.text_block_open,
            "text_block_open must remain false for an unrecognized start shape"
        );

        // The empty `start: {}` text shape still opens a Text block (sanity).
        let evs2 = reader.read_response_events(
            "",
            &serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 0, "start": {}}),
            &mut state,
        );
        assert!(
            evs2.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::Text,
                    ..
                }
            )),
            "an empty `start: {{}}` must still open a Text block; got {evs2:?}"
        );
    }

    /// Regression (writer): a session (STS) token containing a byte `HeaderValue` rejects (control
    /// char / >= 0x80) must NOT produce a request signed over `x-amz-security-token` with the header
    /// absent (which AWS rejects with SignatureDoesNotMatch). The signed set and the wire set are
    /// gated by the same up-front validation, so an un-encodable token bails to the graceful
    /// empty-header path (unsigned request → AWS 403 as auth) — no panic, no divergence.
    #[test]
    fn test_bedrock_sigv4_unencodable_session_token_bails_gracefully() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
        };
        // Session token with an embedded control char → un-encodable HeaderValue.
        let headers = writer.sign_request("AKID:SECRET:TOK\r\nEN", &ctx);
        assert!(
            headers.is_empty(),
            "un-encodable session token must yield no headers (graceful), not a signed-but-absent \
             token header; got {headers:?}"
        );
        // A bare control byte (e.g. NUL / U+0001) likewise bails — `HeaderValue::from_str` rejects
        // ASCII control characters, the same vector as the misconfigured access-key path.
        let headers2 = writer.sign_request("AKID:SECRET:TOK\u{0001}EN", &ctx);
        assert!(
            headers2.is_empty(),
            "control-byte token must bail; got {headers2:?}"
        );

        // Sanity: a clean token still signs AND emits the token header, and the signed set commits
        // to it (so the two never diverge in the success case either).
        let ok = writer.sign_request("AKID:SECRET:CLEANTOKEN", &ctx);
        let auth = ok
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .expect("authorization header");
        assert!(
            auth.contains("x-amz-security-token"),
            "clean token must be in the signed header set"
        );
        assert!(
            ok.iter().any(|(k, v)| k.as_str() == "x-amz-security-token"
                && v.to_str().unwrap() == "CLEANTOKEN"),
            "clean token must be emitted on the wire; got {ok:?}"
        );
    }

    /// Regression (writer): a usage-only delta's `metadata` frame carries the real `usage` but does
    /// NOT fabricate a `metrics` object at the writer layer. The native ConverseStream `metrics`
    /// object reports the stream's REAL `latencyMs`, which the writer cannot know — so it is injected
    /// (with the elapsed wall-clock) by `StreamTranslate::emit_ir_event` on the Bedrock-ingress path,
    /// or OMITTED when timing is unavailable. Emitting a hard-coded `latencyMs: 0` here (the old
    /// behavior) was itself a detectable tell (a real stream never reports exactly 0). The live
    /// latency injection is covered by the StreamTranslate test in proto/mod.rs.
    #[test]
    fn test_write_response_event_metadata_no_fabricated_metrics() {
        let writer = BedrockWriter;
        let usage_only = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 3,
                output_tokens: 2,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&usage_only)
            .expect("usage-only delta emits a metadata frame");
        assert_eq!(et, "metadata");
        assert!(
            payload.pointer("/metrics").is_none(),
            "writer must NOT fabricate a `metrics` object (latency is injected by StreamTranslate \
             or omitted); got {payload}"
        );
        // usage is still present and correct.
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(5)
        );
    }

    /// Regression (writer, streaming `metadata` frame): `totalTokens` is computed with a saturating
    /// add, so a pathological/hostile upstream sending token counts near `u64::MAX` clamps to
    /// `u64::MAX` instead of panicking under overflow-checks (debug / opt-in release) or silently
    /// wrapping to a near-zero nonsense total in plain release. Mirrors the Gemini writer's
    /// `test_stream_message_delta_total_token_count_saturates`.
    #[test]
    fn test_write_response_event_total_tokens_saturates() {
        let writer = BedrockWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&ev)
            .expect("usage-only delta emits a metadata frame");
        assert_eq!(et, "metadata");
        // No panic on the request path, and the total clamps at u64::MAX rather than wrapping to 0.
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(u64::MAX),
            "totalTokens must saturate, not wrap; got {payload}"
        );
        // Component counts are passed through untouched.
        assert_eq!(
            payload
                .pointer("/usage/inputTokens")
                .and_then(|v| v.as_u64()),
            Some(u64::MAX)
        );
        assert_eq!(
            payload
                .pointer("/usage/outputTokens")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    /// Regression (writer, non-stream `write_response` body): the buffered Converse `totalTokens`
    /// uses the same saturating add as the streaming frame, so an upstream response carrying token
    /// counts near `u64::MAX` does not panic (overflow-checks) or wrap (release).
    #[test]
    fn test_write_response_total_tokens_saturates() {
        let writer = BedrockWriter;
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("end_turn".to_string()),
            usage: IrUsage {
                input_tokens: u64::MAX - 1,
                output_tokens: 100,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let body = writer.write_response(&resp);
        assert_eq!(
            body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
            Some(u64::MAX),
            "totalTokens must saturate, not wrap; got {body}"
        );
        // A normal (non-overflowing) pair still sums exactly.
        let normal = crate::ir::IrResponse {
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            ..resp
        };
        let body = writer.write_response(&normal);
        assert_eq!(
            body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
            Some(15)
        );
    }
}
