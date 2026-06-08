// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Bedrock Converse protocol reader/writer implementation.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Monotonic per-process counter mixed into a synthesized response id so two responses minted in
/// the same wall-clock second still get distinct ids. Stdlib-only (no new crate dependency).
#[cfg_attr(not(test), allow(dead_code))]
static SYNTH_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Current unix time in whole seconds. Stdlib-only. A clock before the epoch (impossible on a
/// sane host, but `duration_since` is fallible) degrades to 0 rather than panicking on the
/// request path. Only reachable via `synth_response_id` on the test path until the cross-protocol
/// wiring lands.
#[cfg_attr(not(test), allow(dead_code))]
fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Synthesize a unique, Bedrock-flavored response identity for the CROSS-protocol case (the egress
/// backend was not Bedrock, so the IR carries no id). The AWS SDK shapes a Converse response id as
/// the request id surfaced in the `x-amzn-RequestId` HTTP header; those are uppercase-hyphen UUIDs.
/// We mint a syntactically-plausible, collision-resistant token from (unix seconds + a monotonic
/// counter) — no UUID crate, no panic. Used only to populate the IR's `id` when a downstream
/// cross-protocol writer needs one; see `write_response` for why it is NOT injected into Bedrock's
/// own response body (the native Converse body has no id field). Only reachable on the test path
/// until the cross-protocol wiring lands in a later wave.
#[cfg_attr(not(test), allow(dead_code))]
fn synth_response_id() -> String {
    let n = SYNTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}-{:016x}", unix_now_secs(), n)
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
            // Bedrock has no `stream` field in the request body — streaming is selected by the
            // endpoint (converse vs converse-stream), so there is nothing to read here.
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

                // Bedrock splits stop reason (`messageStop`) from usage (a following `metadata`
                // event). Emit the stop_reason here with zero usage, then emit the terminating
                // MessageStop immediately so the downstream stream always receives its terminal
                // frame. Previously the terminal MessageStop was emitted only from the `metadata`
                // branch; a malformed/truncated upstream (or a provider variant) that ends after
                // `messageStop` without a trailing `metadata` event left the client stream hanging
                // with no terminal frame. The reader has no end-of-stream hook, so `messageStop`
                // (the wire-guaranteed terminal event) is the correct place to terminate.
                //
                // Usage from a subsequent `metadata` event is still forwarded as a trailing
                // MessageDelta (see below). `metadata` no longer emits its own MessageStop, so
                // exactly one terminal frame is produced regardless of whether `metadata` arrives.
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
                out.push(IrStreamEvent::MessageStop);
            }

            Some("metadata") => {
                // Usage trails the terminal MessageStop (Bedrock sends `metadata` after
                // `messageStop`). Emit it as a usage-only MessageDelta; the terminal frame was
                // already produced by the `messageStop` branch, so we do NOT emit a second
                // MessageStop here (that would duplicate the terminator).
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
        if let Some(t) = token {
            if let Ok(v) = HeaderValue::from_str(t) {
                out.push((HeaderName::from_static("x-amz-security-token"), v));
            }
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
            IrStreamEvent::MessageStart {
                role: _, usage: _, ..
            } => Some((
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

        // Identity emission. The native AWS Converse response body (the shape the official SDK
        // deserializes — `output` / `stopReason` / `usage` / optional `metrics`) carries NO id or
        // `created` field; AWS returns the request id only in the `x-amzn-RequestId` HTTP header.
        // Injecting a synthesized `id`/`created` into the JSON body would therefore be a
        // proxy-tell, not fidelity — so we deliberately do NOT add one. The cross-protocol
        // synthesizer (`synth_response_id`) exists for the inverse direction (a Bedrock egress
        // feeding an OpenAI/Anthropic ingress that DOES require a body id) and to populate the IR
        // id when a downstream writer needs it; it is intentionally unused by Bedrock's own body
        // writer. `stopReason` and `usage` (the only identity-bearing fields Bedrock emits) are
        // reproduced exactly from the captured IR below, so a same-protocol round-trip is
        // byte-identical.
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

        assert_eq!(events.len(), 8);

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

        // messageStop carries the stop reason with zero usage...
        match &events[5] {
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                assert_eq!(stop_reason.as_deref(), Some("end_turn"));
                assert_eq!(usage.input_tokens, 0);
                assert_eq!(usage.output_tokens, 0);
            }
            _ => panic!("event[5] should be MessageDelta"),
        }

        // ...and the terminating MessageStop is emitted immediately from the `messageStop` branch
        // (the wire-guaranteed terminal event), so a missing/truncated `metadata` event can no
        // longer leave the downstream stream without its terminal frame.
        match &events[6] {
            IrStreamEvent::MessageStop => {}
            _ => panic!("event[6] should be MessageStop"),
        }

        // The trailing `metadata` event still forwards the real usage (lossless) as a usage-only
        // MessageDelta; it no longer emits a second (duplicate) MessageStop.
        match &events[7] {
            IrStreamEvent::MessageDelta { stop_reason, usage } => {
                assert!(stop_reason.is_none());
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => panic!("event[7] should be MessageDelta carrying usage"),
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
}
