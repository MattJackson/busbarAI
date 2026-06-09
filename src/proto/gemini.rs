// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Gemini protocol reader/writer implementation.

use super::*;

/// Hard cap on the number of distinct tool-call block indices recorded in `state.open_tools` for a
/// single Gemini SSE stream. The set is only drained when a `finishReason` chunk arrives (the
/// terminal frame closes every open tool block), so a hostile or buggy upstream that streams an
/// unbounded run of `functionCall` parts WITHOUT ever emitting `finishReason` would grow it without
/// bound — one inserted index per part — until the process is OOM-killed. No legitimate Gemini
/// response approaches this many parallel tool calls in a single turn; past the cap we stop both
/// recording new tool frames and emitting their BlockStart/BlockDelta events, so per-request heap
/// stays bounded. The cap leaves every realistic stream untouched. Mirrors the Cohere reader's
/// `MAX_TRACKED_TOOL_FRAMES`.
const MAX_GEMINI_TOOL_FRAMES: usize = 4096;

/// The set of top-level Gemini request keys the reader models into typed `IrRequest` fields (any
/// OTHER key is swept verbatim into `extra` for round-trip fidelity). This set is a compile-time
/// constant, so it is built ONCE into a process-global `OnceLock` and shared by every
/// `read_request` call instead of being re-allocated and re-hashed per request on the ingress hot
/// path. Every member is a `&'static str`, so the cached set borrows nothing request-scoped.
fn modeled_request_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        [
            "contents",
            "tools",
            "systemInstruction",
            "generationConfig",
            "model",
            crate::proto::GEMINI_JSON_ARRAY_SHIM_KEY,
        ]
        .into_iter()
        .collect()
    })
}

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

        // The real Gemini REST API returns `error.code` as a JSON INTEGER (the HTTP status, per
        // google.rpc.Status), e.g. `"code": 429`. `serde_json::Value::as_str()` returns None on a
        // number, so reading it as a string silently dropped the numeric code and fell back to the
        // gRPC status name — breaking any breaker/metrics comparison against numeric strings. Read
        // the integer first and stringify it; tolerate a string-typed `code` (some proxies emit one)
        // as a secondary path; fall back to `status` only when `code` is absent entirely.
        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get("code"))
            .and_then(|c| {
                c.as_u64()
                    .map(|n| n.to_string())
                    .or_else(|| c.as_str().map(String::from))
            })
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

    #[cfg(test)]
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

        // Per-request tool-call index. Gemini `functionCall` parts carry no id, so we synthesize a
        // deterministic, non-empty one (see `synth_tool_call_id`). The index makes each synthesized
        // id distinct even when two calls in the same request share a function name, so a downstream
        // Anthropic/OpenAI egress block gets a unique, non-empty `id`/`tool_use_id`.
        let mut tool_call_index: usize = 0;

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
                    // Gemini's Content.role is optional; an absent/empty role is an
                    // implicit user turn per the GenerateContentRequest schema and the
                    // official SDK. Match the streaming reader's leniency (line ~467).
                    "user" | "" => crate::ir::IrRole::User,
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
                            // Gemini carries no tool-call id; synthesize a stable, non-empty one
                            // keyed by (index, name). The Gemini writer ignores the ToolUse `id`
                            // (it round-trips `name`), so this is safe for same-protocol passthrough
                            // and gives cross-protocol Anthropic/OpenAI egress a non-empty id.
                            let id = synth_tool_call_id(tool_call_index, &name);
                            tool_call_index += 1;
                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id,
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
                            // carries only a `name` (no call id). We set `tool_use_id` to the
                            // function name — the only correlation handle Gemini provides on the
                            // RESULT side. This is deliberate and load-bearing for SAME-PROTOCOL
                            // (Gemini→Gemini) passthrough: the writer round-trips `tool_use_id`
                            // straight back into `functionResponse.name`, so it MUST stay the name
                            // (NOT the synthetic id we mint for the `functionCall` ToolUse above —
                            // the writer ignores the ToolUse `id`, so synthesizing it there is safe,
                            // but it must not leak onto the result name here). Cross-protocol egress
                            // that correlates strictly by id is the pre-existing Gemini limitation:
                            // the result still carries the name as its handle.
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
                        // InlineData (Image, base64)
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
                        // FileData (Image by URI) → carry the URI under the `"image_url"` sentinel so
                        // it survives into the IR exactly as the OpenAI/Responses readers store a
                        // remote image URL. The writer (and cross-protocol egress) re-emit the
                        // sentinel as a native URL reference rather than mangling it into base64.
                        else if let Some(file_data) = part.get("fileData") {
                            let uri = file_data
                                .get("fileUri")
                                .and_then(|u| u.as_str())
                                .unwrap_or("")
                                .to_string();
                            msg_content.push(crate::ir::IrBlock::Image {
                                media_type: "image_url".to_string(),
                                data: uri,
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

        // Extract scalar fields and extra. `maxOutputTokens` is read as i64 and converted with a
        // BOUNDS-CHECKED `u32::try_from` rather than a bare `as u32`: a pathological/garbage value
        // above `u32::MAX` (e.g. `5_000_000_000`) would silently TRUNCATE under `as u32` (wrapping to
        // a small token cap the caller never asked for), so an out-of-range value is dropped to `None`
        // instead — the request then carries no `maxOutputTokens` and the backend applies its default,
        // which is strictly safer than forwarding a silently-mangled cap.
        let max_tokens = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("maxOutputTokens"))
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("temperature"))
            .and_then(|v| v.as_f64());
        // Promoted sampling controls live under `generationConfig`: topP, topK, stopSequences.
        let top_p = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("topP"))
            .and_then(|v| v.as_f64());
        let top_k = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("topK"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let stop = crate::ir::read_stop_sequences(
            obj.get("generationConfig")
                .and_then(|gc| gc.get("stopSequences")),
        );
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect unmodeled top-level keys into extra (excluding modeled ones). `model` is in the
        // set so the loop below does NOT re-insert it: it is preserved in `extra` exactly once via
        // the explicit pre-insert below (preventing the silent duplicate insert the loop used to
        // perform, which would be discarded the moment the two writes ever diverged).
        //
        // `stream` is NOT in `modeled_keys`: when the SOURCE body carries it, it is preserved through
        // `extra` and echoed back by the writer — mirroring how `model` (also captured into a typed
        // field) round-trips, so a read→write of a body that carried `stream` stays byte-identical
        // (the `test_gemini_roundtrip_identity` invariant). `IrRequest.stream` (captured above) is the
        // source of truth for path selection (`upstream_path_for_stream`); the `extra` copy is purely
        // for round-trip fidelity. The router-injected `stream`/shim NEVER reach a real backend
        // because `forward::strip_router_shim_keys` now runs UNCONDITIONALLY (same- AND cross-protocol)
        // before the upstream call.
        //
        // The router-internal `__busbar_gemini_json_array` shim IS in `modeled_keys`, so it never
        // enters `extra` and can never be re-emitted onto a cross-protocol upstream body by a
        // downstream writer. Unlike `stream` it is not a caller field with any round-trip meaning (a
        // native Gemini request never carries it), so excluding it costs no fidelity. Previously it
        // was absent from the set, so the CROSS-protocol path (which rebuilds the body via
        // read/write_request, bypassing the same-protocol-only strip that existed before this fix)
        // swept it into `extra` and every egress writer re-emitted this router fingerprint onto a
        // foreign OpenAI/Anthropic/Cohere/Bedrock backend. Both the unconditional forward-layer strip
        // and this exclusion now guard that leak (defense in depth).
        //
        // The set is a compile-time constant, so it is built ONCE into a process-global `OnceLock`
        // rather than re-allocated and re-hashed on every ingress `read_request` (it was previously
        // rebuilt per request — heap churn + hashing on the hot path under load). All members are
        // `&'static str` (`GEMINI_JSON_ARRAY_SHIM_KEY` is a `&'static str` const), so the cached set
        // borrows nothing request-scoped and is cache-hot after first call. Mirrors the lazy-static
        // pattern used elsewhere for per-request constant lookups.
        let modeled_keys = modeled_request_keys();

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
            top_p,
            top_k,
            stop,
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

                                    // Bound `state.open_tools` so an adversarial/buggy upstream that
                                    // streams an unbounded run of `functionCall` parts without ever
                                    // emitting `finishReason` (the only event that drains the set)
                                    // cannot grow per-request heap without bound. Past the cap we
                                    // skip recording the frame AND emitting its BlockStart/BlockDelta
                                    // — the next index is derived from `open_tools.len()`, so a
                                    // recorded-but-uncapped frame would also produce duplicate
                                    // indices once growth stalled. No legitimate Gemini turn carries
                                    // this many parallel tool calls. Mirrors the Cohere reader's cap.
                                    if !name_val.is_empty()
                                        && state.open_tools.len() < MAX_GEMINI_TOOL_FRAMES
                                    {
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

                                        // Gemini streams carry no tool-call id; synthesize a stable,
                                        // non-empty one keyed by (tool-position, name) so the
                                        // Anthropic/OpenAI stream writers emit a non-empty id on the
                                        // content_block_start. Tool blocks occupy indices 1..n, so
                                        // `ir_idx - 1` is the 0-based tool position.
                                        let id = synth_tool_call_id(ir_idx - 1, &name_val);
                                        out.push(IrStreamEvent::BlockStart {
                                            index: ir_idx,
                                            block: crate::ir::IrBlockMeta::ToolUse {
                                                id,
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
                        // Gemini has no stop_sequence analog in its stream.
                        stop_sequence: None,
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
        // Per-response tool-call index feeding `synth_tool_call_id` (Gemini carries no tool id).
        let mut tool_call_index: usize = 0;
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

                // FunctionCall → IrBlock::ToolUse. Gemini carries no id, so synthesize a stable,
                // non-empty one keyed by (index, name) — the writer ignores the ToolUse `id`, and
                // cross-protocol Anthropic/OpenAI egress requires a non-empty id for correlation.
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

                    let id = synth_tool_call_id(tool_call_index, &name_val);
                    tool_call_index += 1;
                    content.push(crate::ir::IrBlock::ToolUse {
                        id,
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
///
/// The two components are joined by a `-` separator (NOT a bare hex concat). A bare `{:x}{:x}` of
/// `(secs, seq)` is NOT collision-free: e.g. `(0x1ab, 0xc)` and `(0x1a, 0xbc)` both render as
/// `"1abc"`, so two distinct (time, counter) pairs could mint the SAME id within a process. The
/// separator makes the boundary unambiguous so every distinct pair yields a distinct id.
fn synth_response_id() -> String {
    let seq = SYNTH_RESPONSE_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{:x}-{:x}", unix_now_secs(), seq)
}

/// Synthesize a stable, non-empty tool-call id for a Gemini `functionCall`.
///
/// The Gemini wire format carries no tool-call id on `functionCall` parts, so reading them with
/// `id: String::new()` (the old behavior) produced an empty `tool_use_id`/`id` on cross-protocol
/// egress (Anthropic / OpenAI), both of which REQUIRE a non-empty id to correlate the later
/// `tool_result`/`tool` message. With an empty id, two tool calls sharing a function name could not
/// be told apart and `tool_result` routing broke.
///
/// We derive a deterministic id from `(call_index, function_name)` via the FNV-1a hash of the
/// stdlib (no new dependency). The id only needs to be stable WITHIN a single request so the
/// synthesized `tool_result` (which the reader keys by function name — Gemini's only correlation
/// handle) and the `tool_use` agree; including the call index disambiguates repeated function
/// names. The `call_` prefix keeps it visibly synthetic and matches no native id shape we must
/// preserve. An empty `name` still yields a non-empty id (the index disambiguates).
fn synth_tool_call_id(call_index: usize, function_name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    call_index.hash(&mut hasher);
    function_name.hash(&mut hasher);
    format!("call_{:016x}", hasher.finish())
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
///
/// Carries one piece of per-stream state: the open streaming tool calls. A native Gemini SSE stream
/// emits a tool call as a SINGLE `functionCall` part `{name, args}`. The IR, however, carries the
/// tool NAME only on the `BlockStart` (`IrBlockMeta::ToolUse{name}`) and the arguments only on the
/// following `InputJsonDelta(String)` fragment(s) — and a cross-protocol backend (OpenAI / Anthropic)
/// commonly streams the `arguments` JSON across MULTIPLE partial-JSON fragments (`{"lo`, `c":"SF"}`),
/// each surfaced as its OWN `InputJsonDelta`. A stateless writer that emits one IR event at a time
/// therefore produced N parts on the wire — a `{name, args:{}}` BlockStart frame plus one nameless
/// `{args}` delta frame PER fragment, each parsing a partial fragment that fails (so `args:{}`) — a
/// split-and-data-loss shape a native google-genai client never sees (and where a strict client
/// reading `part.function_call.name` sees an empty name and lost arguments).
///
/// To emit the native single `{name, args}` shape REGARDLESS of fragmentation we BUFFER per open tool
/// block: the name from its `BlockStart` and every `InputJsonDelta` fragment CONCATENATED into one
/// arg string. We emit nothing on the BlockStart or the deltas; on `BlockStop` we parse the fully
/// reassembled arg string ONCE and emit a single `{name, args}` part. A zero-argument tool call (no
/// delta at all) flushes `{name, args:{}}` the same way, so the call is never lost.
///
/// The buffer is a `Vec` keyed by IR block index, NOT a single slot: a cross-protocol backend may
/// open several parallel tool blocks (OpenAI streams `tool_calls` index 0 and 1; the OpenAI reader
/// emits BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2) at finish —
/// the BlockStarts are NOT strictly interleaved with their own BlockStop). A single-slot buffer would
/// be clobbered by the second BlockStart, dropping the first tool's name and args. The per-index Vec
/// lets every open tool accumulate independently.
///
/// `StreamTranslate::new` builds a FRESH `Protocol::gemini()` (hence a fresh `GeminiWriter` with an
/// empty buffer) for each stream, so this state is stream-scoped by construction — exactly the
/// precedent `ResponsesWriter`'s per-stream `sequence`/`response_id` fields established.
pub(crate) struct GeminiWriter {
    /// The currently open streaming tool calls, one `(index, name, args)` tuple per OPEN tool block:
    /// - `index` is the IR block index from the opening `BlockStart`, used to match subsequent
    ///   `BlockDelta`/`BlockStop` events to THE RIGHT tool block (parallel tool calls share no slot).
    /// - `name` is the function name buffered off the `BlockStart`.
    /// - `args` is every `InputJsonDelta` fragment for this block CONCATENATED, so a multi-chunk
    ///   streamed `arguments` JSON reassembles into one string parsed once on `BlockStop`. An empty
    ///   string (no delta arrived) flushes `args:{}` for a zero-argument tool call.
    ///
    /// A `Vec` (not a map) keeps the dependency surface nil and the common case (0–2 open tools)
    /// trivially cheap; lookups are a linear scan over the open set, which is bounded by the upstream
    /// reader's own tool-frame cap.
    ///
    /// `Mutex` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires; a
    /// stream is single-threaded at any instant so contention is nil, and a poisoned lock degrades
    /// to the stateless behavior rather than panicking on the request path.
    open_tools: std::sync::Mutex<Vec<(usize, String, String)>>,
}

/// Value-namespace constructor for [`GeminiWriter`]. A `const` and a struct may share a name (they
/// live in the value and type namespaces respectively), so every existing site that writes the bare
/// `GeminiWriter` literal — `Protocol::gemini()` and the tests — keeps compiling unchanged while the
/// type now carries per-stream state. Each USE of the const inlines a FRESH `GeminiWriter` with an
/// empty `open_tool` buffer, so every `Protocol::gemini()` call mints an independent buffer — the
/// per-stream scoping the single-frame functionCall fix needs. `Mutex::new`/`None` are const, so
/// this is valid in const context.
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is inlined
/// per use rather than shared. That per-use fresh instance is PRECISELY the semantics we need: a
/// `static` would share ONE buffer across every stream in the process, bleeding one stream's open
/// tool name into another. So the lint's suggestion is wrong for this site and is suppressed
/// deliberately — mirroring `ResponsesWriter`.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const GeminiWriter: GeminiWriter = GeminiWriter {
    open_tools: std::sync::Mutex::new(Vec::new()),
};

impl Clone for GeminiWriter {
    fn clone(&self) -> Self {
        // Preserve the in-flight open tool calls across a mid-stream `Protocol::clone` so the
        // functionCall name/args correlation survives; a poisoned lock degrades to an empty buffer
        // (stateless behavior) rather than panicking on the request path.
        GeminiWriter {
            open_tools: std::sync::Mutex::new(
                self.open_tools
                    .lock()
                    .map(|t| t.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

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
        // Validate the credential against the HTTP header-value byte rules (`HeaderValue::from_str`
        // rejects ASCII control bytes such as a newline or NUL). A mis-encoded key — e.g. a stray
        // newline injected by a config system — would otherwise be SILENTLY swallowed into an empty
        // `x-goog-api-key` value, and every request to the lane would get a Google-side 401 with NO
        // proxy-side signal
        // (the operator cannot tell a bad credential from a bad encoding). Instead, surface a
        // `tracing::warn!` and OMIT the header entirely (empty vec) — mirroring bedrock's
        // misconfigured-credential path, which returns no signature rather than a meaningless empty
        // one. The request is still sent (the trait can't refuse it here) and Google answers 401, but
        // the warn line tells the operator the lane's credential bytes are invalid. The key itself is
        // NEVER logged (it is the secret); only the fact that it is malformed.
        match HeaderValue::from_str(key) {
            Ok(value) => vec![(HeaderName::from_static("x-goog-api-key"), value)],
            Err(_) => {
                tracing::warn!(
                    "gemini: x-goog-api-key credential contains invalid header bytes (ASCII \
                     control character); omitting auth header — upstream will reject with 401"
                );
                Vec::new()
            }
        }
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
                        // Image → inlineData{mimeType, data} for base64 payloads. The cross-protocol
                        // OpenAI/Responses readers store a non-data (https) image URL verbatim in
                        // `data` under the `"image_url"` media_type SENTINEL (they cannot guess a MIME
                        // type for a remote URL). Emitting that sentinel as `inlineData` would write
                        // the URL string into the base64 `data` field with a bogus `mimeType:
                        // "image_url"` — a corrupt part the model cannot decode. Gemini's native way to
                        // reference an image by URI is `fileData{fileUri, mimeType}`, so route the
                        // sentinel there (URL natively, not base64). `mimeType` is omitted: it is
                        // unknown for a remote URL and is optional on `fileData`.
                        if media_type == "image_url" {
                            parts_arr.push(serde_json::json!({
                                "fileData": { "fileUri": data }
                            }))
                        } else {
                            parts_arr.push(serde_json::json!({
                                "inlineData": { "mimeType": media_type, "data": data }
                            }))
                        }
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

        // generationConfig{maxOutputTokens, temperature, topP, topK, stopSequences}
        let mut gen_config = serde_json::Map::new();
        if let Some(max_tokens) = req.max_tokens {
            gen_config.insert("maxOutputTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            gen_config.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling controls in Gemini's native generationConfig shape.
        if let Some(top_p) = req.top_p {
            gen_config.insert("topP".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            gen_config.insert("topK".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            gen_config.insert("stopSequences".to_string(), serde_json::json!(req.stop));
        }
        if !gen_config.is_empty() {
            out.insert(
                "generationConfig".to_string(),
                serde_json::Value::Object(gen_config),
            );
        }

        // NB: the native Gemini GenerateContentRequest schema has NO top-level `stream` field —
        // streaming is selected entirely by the URL endpoint (`:generateContent` vs
        // `:streamGenerateContent?alt=sse`, produced by `upstream_path_for_stream`). This writer
        // therefore NEVER synthesizes a `stream` member from `req.stream`; the streaming intent is
        // read only by path selection. The ONLY way a `stream` key appears on the egress body is if
        // the SOURCE request carried one and it was preserved verbatim through `extra` (the reader
        // does NOT model `stream`, mirroring how it round-trips `model` for byte-identity). For a
        // NATIVE Gemini request `extra` carries no `stream`, so the egress body carries none either.
        // On same-protocol passthrough `forward::strip_router_shim_keys` removes any router-injected
        // `stream` before the upstream call. (An earlier version of this comment wrongly claimed the
        // reader excludes `stream` via `modeled_keys`; it does not — the accurate behavior is here.)

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
                    // Cross-protocol stream: `StreamTranslate` strips the foreign `id` to `None`
                    // before this writer runs (it does NOT strip `model` — that is the lane's model
                    // name, emitted as `modelVersion` below). A native google-genai SDK reads
                    // `chunk.response_id` off the FIRST chunk (for observability/tracing), so emitting
                    // no identity frame at all is a detectable fidelity gap from a native Gemini stream
                    // (which always carries `responseId` in the first chunk). Synthesize one —
                    // matching the non-stream `write_response` behavior — rather than dropping it.
                    (None, _) => {
                        frame.insert(
                            "responseId".to_string(),
                            serde_json::json!(synth_response_id()),
                        );
                    }
                }
                // A native Gemini SSE stream ALWAYS carries `modelVersion` in the first chunk (the
                // official google-genai SDK reads `chunk.model_version`). `StreamTranslate` now
                // preserves the lane's `model` across the cross-protocol boundary, so this is
                // populated on cross-protocol streams (not just same-protocol passthrough) and the
                // SDK no longer sees an empty model on every cross-protocol response.
                if let Some(model) = model {
                    frame.insert("modelVersion".to_string(), serde_json::json!(model));
                }
                Some(("".to_string(), serde_json::Value::Object(frame)))
            }

            // BlockStart → for a tool block, OPEN a buffer holding the tool name and an empty args
            // accumulator, and emit NO frame. A native Gemini SSE stream carries a tool call as a
            // SINGLE `functionCall` part `{name, args}`; the IR carries the name here and the
            // arguments on the following InputJsonDelta fragment(s). We accumulate name + every arg
            // fragment per block and emit the one native `{name, args}` part on BlockStop, so a
            // multi-chunk streamed `arguments` JSON reassembles into one valid functionCall (and a
            // zero-arg tool call still flushes `{name, args:{}}`). Re-opening the SAME index resets
            // its accumulator; a NEW index appends a fresh entry so parallel tool blocks (whose
            // BlockStarts are not strictly interleaved with their BlockStops) never clobber each
            // other. Text blocks have no Gemini block-start frame (inline parts) → None.
            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::ToolUse { name, .. } => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        match guard.iter_mut().find(|(idx, _, _)| idx == index) {
                            Some(entry) => {
                                entry.1 = name.clone();
                                entry.2.clear();
                            }
                            None => guard.push((*index, name.clone(), String::new())),
                        }
                    }
                    None
                }
                crate::ir::IrBlockMeta::Text
                | crate::ir::IrBlockMeta::Thinking
                | crate::ir::IrBlockMeta::Image => None,
            },

            // TextDelta → chunk with text part
            IrStreamEvent::BlockDelta { index, delta } => match delta {
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

                // InputJsonDelta → ACCUMULATE this fragment into the open tool block's arg buffer and
                // emit NO frame. A cross-protocol backend streams `arguments` as MULTIPLE partial-JSON
                // fragments (`{"lo`, `c":"SF"}`); parsing each fragment independently here (as before)
                // failed on the partials (→ `args:{}`) AND emitted one nameless/partial `functionCall`
                // part per fragment — data loss plus a multi-part split a native Gemini client never
                // sees. Concatenating the fragments and emitting once on BlockStop yields the single
                // native `{name, args}` part with the FULLY reassembled arguments. If no matching open
                // block is tracked (no tool BlockStart seen, or a poisoned lock) the fragment is
                // dropped silently rather than panicking on the request path — the same degraded
                // outcome the stateless arm produced, never a crash.
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        if let Some((_, _, args)) =
                            guard.iter_mut().find(|(idx, _, _)| idx == index)
                        {
                            args.push_str(json_str);
                        }
                    }
                    None
                }

                // ThinkingDelta/SignatureDelta → None (Gemini has no thinking, lossy)
                crate::ir::IrDelta::ThinkingDelta(_) | crate::ir::IrDelta::SignatureDelta(_) => {
                    None
                }
            },

            // BlockStop → FLUSH the open tool block as a single native `{name, args}` part. This is
            // the ONLY point a functionCall frame is written: by here every arg fragment has been
            // accumulated, so the buffered arg string is the COMPLETE `arguments` JSON and parses
            // once into the args object (a multi-chunk stream reassembles correctly; a zero-arg call
            // — empty buffer — flushes `args:{}`, so the call is never lost). A non-tool BlockStop
            // (text block, or an index with no tracked tool) finds no entry and emits no frame. The
            // matched entry is REMOVED so parallel tool blocks each flush exactly once. A poisoned
            // lock degrades to no frame rather than panicking on the request path.
            IrStreamEvent::BlockStop { index } => {
                let flushed = match self.open_tools.lock() {
                    Ok(mut guard) => guard
                        .iter()
                        .position(|(idx, _, _)| idx == index)
                        .map(|pos| {
                            let (_, name, args) = guard.remove(pos);
                            (name, args)
                        }),
                    Err(_) => None,
                };
                flushed.map(|(name, args_str)| {
                    // Parse the fully reassembled arg string. An empty buffer (zero-arg call) or an
                    // unparseable accumulation degrades to `{}` rather than panicking — the args are
                    // best-effort, but the single-part `{name, ...}` shape and the name are always
                    // preserved.
                    let args: serde_json::Value = if args_str.is_empty() {
                        serde_json::json!({})
                    } else {
                        serde_json::from_str(&args_str).unwrap_or_else(|_| serde_json::json!({}))
                    };
                    (
                        "".to_string(),
                        serde_json::json!({
                            "candidates": [{
                                "content": {
                                    "role": "model",
                                    "parts": [{"functionCall": {"name": name, "args": args}}]
                                }
                            }]
                        }),
                    )
                })
            }

            // MessageDelta → chunk with finishReason + usageMetadata
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let finish_reason = match stop_reason.as_deref() {
                    // Gemini reports STOP for a normal completion AND for a tool/function-call
                    // completion (its `FinishReason` enum has NO TOOL_USE member). Every other
                    // protocol's reader emits the canonical `tool_use` stop reason for a tool-call
                    // turn, so it MUST map to STOP here — upper-casing it to "TOOL_USE" would emit an
                    // invalid enum value a strict google-genai client rejects.
                    Some("end_turn") | Some("stop_sequence") | Some("tool_use") => {
                        "STOP".to_string()
                    }
                    Some("max_tokens") => "MAX_TOKENS".to_string(),
                    Some("safety") => "SAFETY".to_string(),
                    Some(other) => other.to_uppercase(),
                    None => "STOP".to_string(),
                };

                // Native Gemini SSE carries `usageMetadata` (incl. `totalTokenCount`) on the final
                // chunk; a strict google-genai client computing totals reads `totalTokenCount`.
                // Emit it (= prompt + candidates, saturating) alongside the component counts so the
                // streamed usage frame matches the native final-chunk shape. This path runs only on
                // cross-protocol egress (same-protocol Gemini streams pass through byte-for-byte and
                // never reach this writer), so emitting the total here cannot disturb a same-protocol
                // round-trip. Saturating add avoids an overflow panic on the request path for
                // pathological/garbage counts.
                let total = usage.input_tokens.saturating_add(usage.output_tokens);
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "finishReason": finish_reason
                        }],
                        "usageMetadata": {
                            "promptTokenCount": usage.input_tokens,
                            "candidatesTokenCount": usage.output_tokens,
                            "totalTokenCount": total
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
            // Gemini reports STOP for a normal completion AND for a tool/function-call completion
            // (its `FinishReason` enum has NO TOOL_USE member). The canonical `tool_use` stop reason
            // every other protocol's reader emits for a tool-call turn MUST map to STOP here — upper-
            // casing it to "TOOL_USE" would emit an invalid enum value a strict google-genai client
            // rejects on the most common cross-protocol tool-calling path.
            Some("end_turn") | Some("stop_sequence") | Some("tool_use") => "STOP".to_string(),
            Some("max_tokens") => "MAX_TOKENS".to_string(),
            Some("safety") => "SAFETY".to_string(),
            Some(other) => other.to_uppercase(),
            None => "STOP".to_string(),
        };

        // A native Gemini `generateContent` response ALWAYS carries
        // `usageMetadata.totalTokenCount` (= promptTokenCount + candidatesTokenCount); the
        // google-genai SDK surfaces it as `usage_metadata.total_token_count` for billing/accounting.
        // On the CROSS-protocol egress path a native Gemini client therefore expects the sum, and the
        // value is a faithfully DERIVED total from the IR counts — not a fabricated field — so we emit
        // it (mirroring the stream final-chunk frame), closing a concrete token-accounting gap and a
        // distinguishability tell. `saturating_add` avoids an overflow panic on the request path.
        //
        // We gate emission on a cross-protocol BOUNDARY signal: `resp.created.is_some()` OR
        // `resp.model.is_some()`. Gemini bodies carry no `created`, so a populated `created` means a
        // non-Gemini backend reader set it (the OpenAI reader does) — but the Anthropic, Bedrock, and
        // Cohere readers all return `created: None`, so `created` ALONE missed three of the five
        // foreign backends, dropping `totalTokenCount` for a Gemini client routed to them (the
        // google-genai SDK then read `usage_metadata.total_token_count` as None, breaking billing).
        // The Anthropic and Cohere readers DO populate `model` from the upstream body (a real
        // Anthropic `Message` / Cohere response always names its model), so OR-ing `model.is_some()`
        // closes the gap for those two as well. (Bedrock's Converse body carries no body-level model
        // or timestamp, so its IR is identity-field-empty here — that residual cannot be distinguished
        // from a minimal native body without crossing into a non-owned reader.)
        //
        // This still keeps a SAME-protocol read→write idempotent on the in-IR identity invariant that
        // `src/proto/mod.rs::test_gemini_read_write_response_roundtrip` guards: that fixture is a
        // native Gemini body with neither `modelVersion` nor a timestamp, so `model`/`created` are
        // BOTH `None` and no `totalTokenCount` is injected — the round-trip stays byte-identical.
        // (`write_response` only ever runs on cross-protocol egress in production — same-protocol
        // passthrough is byte-exact and bypasses the writer — so this gate is conservative there.)
        let mut usage_metadata = serde_json::json!({
            "promptTokenCount": resp.usage.input_tokens,
            "candidatesTokenCount": resp.usage.output_tokens
        });
        if resp.created.is_some() || resp.model.is_some() {
            let total = resp
                .usage
                .input_tokens
                .saturating_add(resp.usage.output_tokens);
            usage_metadata["totalTokenCount"] = serde_json::json!(total);
        }
        let mut out = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": parts_arr
                },
                "finishReason": finish_reason
            }],
            "usageMetadata": usage_metadata
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

    /// Regression: the tool BlockStart now BUFFERS the name and emits NO frame; a native Gemini
    /// stream carries a tool call as a single `functionCall` part, so the name must NOT appear in a
    /// separate opening frame (that produced a two-part split a native client never sees).
    #[test]
    fn test_writer_tool_blockstart_emits_no_frame() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        };
        assert!(
            writer.write_response_event(&ev).is_none(),
            "tool BlockStart must buffer the name and emit no separate frame"
        );
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

    /// Helper: drive a sequence of IR events through ONE GeminiWriter (preserving its per-stream
    /// tool buffer) and return only the emitted `functionCall` parts (the `{name, args}` objects),
    /// in wire order. This is the shape a native google-genai client decodes off the stream.
    fn collect_function_calls(events: &[IrStreamEvent]) -> Vec<serde_json::Value> {
        let writer = GeminiWriter;
        let mut calls = Vec::new();
        for ev in events {
            if let Some((_, chunk)) = writer.write_response_event(ev) {
                if let Some(parts) = chunk
                    .pointer("/candidates/0/content/parts")
                    .and_then(|p| p.as_array())
                {
                    for part in parts {
                        if let Some(fc) = part.get("functionCall") {
                            calls.push(fc.clone());
                        }
                    }
                }
            }
        }
        calls
    }

    /// Regression: a tool BlockStart + one whole-JSON InputJsonDelta + BlockStop emits EXACTLY ONE
    /// native `functionCall` part carrying BOTH the buffered name and the args. The part is written
    /// on BlockStop (the flush point), not on the BlockStart or the delta.
    #[test]
    fn test_writer_tool_call_emits_single_name_and_args_part() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
        ]);
        assert_eq!(
            calls.len(),
            1,
            "tool call must emit exactly one functionCall part: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "part must carry the buffered name: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/city").and_then(|c| c.as_str()),
            Some("SF"),
            "part must carry the args: {calls:?}"
        );
    }

    /// Regression for the HIGH finding: the `arguments` JSON arrives SPLIT across MULTIPLE partial-
    /// JSON InputJsonDelta fragments (the normal OpenAI/Anthropic streaming behavior — the reader
    /// emits one InputJsonDelta per upstream `arguments` fragment, none coalesced). The fragments
    /// individually do NOT parse (`{"lo`, `c":"SF","u":1}`); the writer MUST reassemble them and emit
    /// EXACTLY ONE functionCall part whose `args` is the fully reassembled object — not one (empty-
    /// args) part per fragment.
    #[test]
    fn test_writer_tool_call_reassembles_split_json_args() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"lo".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("c\":\"SF\",\"unit".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("\":\"C\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
        ]);
        assert_eq!(
            calls.len(),
            1,
            "multi-fragment args must still emit exactly ONE functionCall part: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "part name must be non-empty after reassembly: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/loc").and_then(|c| c.as_str()),
            Some("SF"),
            "args must be the FULLY reassembled object, not a partial fragment: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/unit").and_then(|c| c.as_str()),
            Some("C"),
            "every reassembled arg key must survive: {calls:?}"
        );
    }

    /// Regression for the MEDIUM finding: TWO parallel tool blocks in one stream, with their
    /// BlockStarts NOT strictly interleaved with their own BlockStops (the OpenAI reader emits
    /// BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2)). The
    /// single-slot buffer this replaced would clobber tool 1 when tool 2's BlockStart arrived. Each
    /// tool must flush its OWN name + args as a distinct functionCall part.
    #[test]
    fn test_writer_parallel_tool_calls_keep_distinct_names_and_args() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockStart {
                index: 2,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_time".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 2,
                delta: IrDelta::InputJsonDelta("{\"tz\":\"UTC\"}".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("\"SF\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
            IrStreamEvent::BlockStop { index: 2 },
        ]);
        assert_eq!(
            calls.len(),
            2,
            "two parallel tool calls must emit two functionCall parts: {calls:?}"
        );
        // Tool 1 flushed on its BlockStop (emitted first).
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "first flushed part must keep tool 1's name (not clobbered by tool 2): {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/city").and_then(|c| c.as_str()),
            Some("SF"),
            "tool 1's interleaved split args must reassemble: {calls:?}"
        );
        assert_eq!(
            calls[1].pointer("/name").and_then(|n| n.as_str()),
            Some("get_time"),
            "second flushed part must keep tool 2's name: {calls:?}"
        );
        assert_eq!(
            calls[1].pointer("/args/tz").and_then(|c| c.as_str()),
            Some("UTC"),
            "tool 2's args must survive: {calls:?}"
        );
    }

    /// Regression: a zero-argument tool call (BlockStart then BlockStop with NO InputJsonDelta) must
    /// still emit one `{name, args:{}}` part on the BlockStop flush — the call is never lost.
    #[test]
    fn test_writer_tool_call_empty_args_flushed_on_stop() {
        let writer = GeminiWriter;
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "ping".to_string(),
                },
            })
            .is_none());
        let (_, chunk) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .expect("zero-arg tool call must flush a functionCall frame on BlockStop");
        let func = chunk
            .pointer("/candidates/0/content/parts/0/functionCall")
            .expect("functionCall part");
        assert_eq!(
            func.pointer("/name").and_then(|n| n.as_str()),
            Some("ping"),
            "flushed frame must carry the name: {chunk}"
        );
        assert!(
            func.get("args").map(|a| a.is_object()).unwrap_or(false),
            "flushed frame must carry an (empty) args object: {chunk}"
        );
    }

    /// Regression: neither the BlockStart nor the args delta emits a frame — the functionCall part
    /// is written ONCE, on BlockStop. Guards against re-introducing a per-fragment emit.
    #[test]
    fn test_writer_tool_call_no_frame_before_block_stop() {
        let writer = GeminiWriter;
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse {
                        id: String::new(),
                        name: "get_weather".to_string(),
                    },
                })
                .is_none(),
            "tool BlockStart must emit no frame"
        );
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
                })
                .is_none(),
            "args delta must accumulate, not emit a frame"
        );
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
                .is_some(),
            "BlockStop must flush the single functionCall frame"
        );
    }

    /// extract_error parses the body once and derives both the provider code and structured type.
    /// The real Gemini API returns `error.code` as a JSON INTEGER (google.rpc.Status), so the
    /// fixture uses `429` (not `"429"`); `provider_code` must be the stringified integer.
    #[test]
    fn test_extract_error_single_parse_fields() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.http_status, 429);
        assert_eq!(raw.provider_code.as_deref(), Some("429"));
        assert_eq!(raw.structured_type.as_deref(), Some("RESOURCE_EXHAUSTED"));
        // classify()/extract_error do not see headers, so retry_after is sourced elsewhere.
        assert_eq!(raw.retry_after_secs, None);
    }

    /// Regression (R5): an integer `error.code` (the real Gemini shape) must be stringified into
    /// `provider_code` — NOT silently dropped to the gRPC status name. Previously `code` was read
    /// via `.as_str()`, which returns None on a number, so a real 429 surfaced as
    /// "RESOURCE_EXHAUSTED" and broke breaker/metrics comparisons against numeric strings.
    #[test]
    fn test_extract_error_integer_code_is_stringified() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":503,"status":"UNAVAILABLE","message":"overloaded"}}"#;
        let raw = reader.extract_error(StatusCode::SERVICE_UNAVAILABLE, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("503"),
            "integer code must be stringified, not fall back to status"
        );
        assert_eq!(raw.structured_type.as_deref(), Some("UNAVAILABLE"));
    }

    /// A string-typed `code` (some proxies emit one) is still accepted as the secondary path.
    #[test]
    fn test_extract_error_string_code_still_accepted() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":"429","status":"RESOURCE_EXHAUSTED"}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.provider_code.as_deref(), Some("429"));
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
            top_p: None,
            top_k: None,
            stop: vec![],
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
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert!(
            wire.get("stream").is_none(),
            "stream intent must not be serialised into the body: {wire}"
        );
    }

    /// Regression: Gemini's `Content.role` is OPTIONAL. A single-turn request that omits `role`
    /// (a common native shape, accepted by the real API and the official SDK as an implicit user
    /// turn) must NOT be hard-rejected. Previously `read_request` mapped any non-`user`/`model`
    /// role (including absent/empty) to a `ClientError`, 400ing a request the real API serves —
    /// and diverging from the streaming reader, which already treats an empty role as a model turn.
    #[test]
    fn test_read_request_absent_role_defaults_to_user() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"parts": [{"text": "hi"}]}]
        });
        let ir = reader
            .read_request(&body)
            .expect("a role-less content must be accepted as a user turn, not rejected");
        assert_eq!(ir.messages.len(), 1, "one message expected: {ir:?}");
        assert_eq!(
            ir.messages[0].role,
            crate::ir::IrRole::User,
            "an absent role must default to user: {ir:?}"
        );
    }

    /// An explicitly EMPTY role string (`"role": ""`) is likewise treated as a user turn, matching
    /// the absent-role case and the streaming reader's `role_val.is_empty()` leniency.
    #[test]
    fn test_read_request_empty_role_defaults_to_user() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "", "parts": [{"text": "hi"}]}]
        });
        let ir = reader
            .read_request(&body)
            .expect("an empty role must be accepted as a user turn, not rejected");
        assert_eq!(
            ir.messages[0].role,
            crate::ir::IrRole::User,
            "an empty role must default to user: {ir:?}"
        );
    }

    /// A genuinely unexpected NON-EMPTY role string is still a hard client error — the leniency is
    /// scoped to the absent/empty case (the real API's optional-role default), not to arbitrary
    /// role values.
    #[test]
    fn test_read_request_unknown_nonempty_role_still_rejected() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "function", "parts": [{"text": "hi"}]}]
        });
        assert!(
            reader.read_request(&body).is_err(),
            "an unexpected non-empty role must still be rejected"
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
            top_p: None,
            top_k: None,
            stop: vec![],
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
            top_p: None,
            top_k: None,
            stop: vec![],
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

    // --- Round 3 fix 1: functionCall ToolUse blocks must carry a non-empty, stable id ---

    /// Regression: a Gemini `functionCall` in `read_request` must produce a NON-EMPTY tool-use id
    /// (Gemini carries none). Previously `id: String::new()` made cross-protocol Anthropic/OpenAI
    /// egress emit an empty `id`/`tool_use_id`, which those APIs reject / mis-correlate.
    #[test]
    fn test_read_request_functioncall_gets_nonempty_id() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let id = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        });
        let id = id.expect("ToolUse block must be present");
        assert!(!id.is_empty(), "synthesized tool-use id must be non-empty");
    }

    /// Regression: two `functionCall`s sharing the SAME function name in one request must get
    /// DISTINCT non-empty ids (the call index disambiguates) so `tool_result` routing cannot
    /// collapse them on cross-protocol egress.
    #[test]
    fn test_read_request_same_name_tool_calls_get_distinct_ids() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [
                    {"functionCall": {"name": "search", "args": {"q": "a"}}},
                    {"functionCall": {"name": "search", "args": {"q": "b"}}}
                ]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let ids: Vec<String> = ir.messages[0]
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2, "two tool-use blocks expected");
        assert!(ids.iter().all(|i| !i.is_empty()), "ids must be non-empty");
        assert_ne!(
            ids[0], ids[1],
            "repeated function name must still yield distinct ids: {ids:?}"
        );
    }

    /// Regression: the synthesized id is DETERMINISTIC for a given (index, name) — two reads of the
    /// same request body produce the same ids (stable within a request lifetime).
    #[test]
    fn test_read_request_tool_call_id_is_deterministic() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [{"functionCall": {"name": "f", "args": {}}}]
            }]
        });
        let id_of = |r: &GeminiReader| {
            r.read_request(&body).unwrap().messages[0]
                .content
                .iter()
                .find_map(|b| match b {
                    crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(id_of(&reader), id_of(&reader), "id must be deterministic");
    }

    /// Regression: the same-protocol ToolResult correlation key stays the function NAME (the writer
    /// round-trips it into `functionResponse.name`), NOT the synthetic ToolUse id. Guards against a
    /// regression where the synth id leaks onto the result name and breaks Gemini→Gemini passthrough.
    #[test]
    fn test_read_request_functionresponse_tool_use_id_is_name() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"functionResponse": {"name": "get_weather", "response": {"t": 21}}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let tid = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolResult { tool_use_id, .. } => Some(tool_use_id.clone()),
            _ => None,
        });
        assert_eq!(
            tid.as_deref(),
            Some("get_weather"),
            "result correlation key must remain the function name for same-protocol round-trip"
        );
    }

    /// Regression: a `functionCall` in `read_response` (non-stream) must also carry a non-empty id.
    #[test]
    fn test_read_response_functioncall_gets_nonempty_id() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "f", "args": {}}}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let ir = reader.read_response(&body).expect("read_response");
        let id = ir.content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        });
        assert!(
            id.is_some_and(|i| !i.is_empty()),
            "response ToolUse must carry a non-empty id"
        );
    }

    /// Regression: the streaming `BlockStart` for a tool block must carry a non-empty synthesized
    /// id (Gemini streams carry none) so the Anthropic/OpenAI stream writers emit a usable id.
    #[test]
    fn test_stream_tool_blockstart_id_is_nonempty() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "f", "args": {}}}]
                },
                "finishReason": "STOP"
            }]
        })]);
        let id = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                block: IrBlockMeta::ToolUse { id, .. },
                ..
            } => Some(id.clone()),
            _ => None,
        });
        assert!(
            id.is_some_and(|i| !i.is_empty()),
            "stream tool BlockStart must carry a non-empty id"
        );
    }

    // --- Round 3 fix 2: `stream` round-trip semantics + accurate comment ---

    /// Regression / documentation guard for the corrected `stream` comment. A source `stream` is
    /// captured into the typed `IrRequest.stream` (used only by path selection) AND preserved in
    /// `extra` for byte-identical round-trip (exactly like `model`), so the writer echoes it back.
    /// This is the behavior `src/proto/mod.rs::test_gemini_roundtrip_identity` (a non-owned test)
    /// enforces. The Round-3 finding's prescribed "drop stream from extra" would break that
    /// byte-identity invariant; the real defect (a FALSE comment claiming stream was excluded from
    /// extra) is fixed by making the comment accurate instead.
    #[test]
    fn test_read_request_source_stream_round_trips_via_extra() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "stream": true
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert!(ir.stream, "stream must be captured into IrRequest.stream");
        assert_eq!(
            ir.extra.get("stream"),
            Some(&serde_json::json!(true)),
            "a source `stream` is preserved in extra for round-trip identity (like model): {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.get("stream"),
            Some(&serde_json::json!(true)),
            "source `stream` round-trips onto the egress body via extra: {wire}"
        );
    }

    /// Regression: a NATIVE Gemini request carries no `stream`, so neither `extra` nor the egress
    /// body gains one even when the caller wants streaming (URL-selected). Guards the writer's
    /// "never synthesizes a stream member from req.stream" invariant.
    #[test]
    fn test_read_request_native_no_stream_stays_absent() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let mut ir = reader.read_request(&body).expect("read_request");
        ir.stream = true; // caller wants streaming; must not reach the body
        assert!(
            !ir.extra.contains_key("stream"),
            "native request carries no stream in extra: {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert!(
            wire.get("stream").is_none(),
            "stream intent must not be synthesized onto a native body: {wire}"
        );
    }

    /// Regression (R6, class D — integer-overflow on a cast): a `maxOutputTokens` above `u32::MAX`
    /// must NOT silently truncate (wrap) into a tiny token cap. The bounds-checked `u32::try_from`
    /// drops an out-of-range value to `None`, so the request carries no cap and the backend applies
    /// its default — never a mangled one. A bare `as u32` would have wrapped `5_000_000_000` to
    /// `705_032_704`, a cap the caller never asked for.
    #[test]
    fn test_read_request_max_output_tokens_overflow_drops_to_none() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 5_000_000_000i64}
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.max_tokens, None,
            "an out-of-u32-range maxOutputTokens must drop to None, not truncate"
        );

        // An in-range value still round-trips faithfully.
        let body_ok = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 1024}
        });
        let ir_ok = reader.read_request(&body_ok).expect("read_request");
        assert_eq!(
            ir_ok.max_tokens,
            Some(1024),
            "in-range cap must be preserved"
        );
    }

    // --- Round 3 fix 3: bogus snake_case `tool_config` removed; native `toolConfig` round-trips ---

    /// Regression: native Gemini `toolConfig` (camelCase) is NOT in `modeled_keys`, so it
    /// round-trips through `extra` and back onto the wire unchanged. The old bogus snake_case
    /// `tool_config` modeled-key entry (which matched no real field) has been removed.
    #[test]
    fn test_read_request_native_tool_config_round_trips_via_extra() {
        let reader = GeminiReader;
        let tool_config = serde_json::json!({
            "functionCallingConfig": {"mode": "ANY"}
        });
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "toolConfig": tool_config.clone()
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.extra.get("toolConfig"),
            Some(&tool_config),
            "native toolConfig must round-trip through extra: {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.get("toolConfig"),
            Some(&tool_config),
            "toolConfig must be re-emitted on the wire: {wire}"
        );
    }

    // --- Round 3 fix 4: streamed and whole-body usageMetadata include totalTokenCount ---

    /// Regression: the streamed `MessageDelta` usage frame must include `totalTokenCount`
    /// (= prompt + candidates), matching the native final-chunk shape.
    #[test]
    fn test_stream_message_delta_includes_total_token_count() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 7,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(12)),
            "streamed usage must carry totalTokenCount = prompt + candidates: {frame}"
        );
        assert_eq!(
            frame.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(7))
        );
        assert_eq!(
            frame.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(5))
        );
    }

    /// The streamed total saturates (never overflow-panics) on pathological counts — guards the
    /// `saturating_add` on the request path.
    #[test]
    fn test_stream_message_delta_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {frame}"
        );
    }

    /// Regression (R5): on the CROSS-protocol egress path (signalled by a populated `created` — the
    /// boundary marker a non-Gemini backend reader leaves, since Gemini bodies carry no timestamp)
    /// the whole-body `write_response` usageMetadata MUST include `totalTokenCount` (= prompt +
    /// candidates). A native Gemini `generateContent` body always carries the sum, and the value is a
    /// faithfully derived total (not a fabricated field). Earlier it was omitted, leaving the
    /// google-genai SDK's `total_token_count` at None/0 for cross-protocol callers.
    #[test]
    fn test_write_response_includes_total_token_count_cross_protocol() {
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
                input_tokens: 5,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: Some(1_700_000_000), // cross-protocol boundary signal
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(8)),
            "cross-protocol usage must carry totalTokenCount = prompt + candidates: {wire}"
        );
        assert_eq!(
            wire.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(5))
        );
        assert_eq!(
            wire.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(3))
        );
    }

    /// Fidelity guard: a SAME-protocol read→write (no `created` — native Gemini bodies carry no
    /// timestamp) must NOT inject `totalTokenCount` the upstream omitted, so the round-trip stays
    /// byte-identical. (Production same-protocol passthrough bypasses the writer entirely; this
    /// guards the in-IR read→write identity invariant `test_gemini_read_write_response_roundtrip`
    /// in mod.rs depends on.)
    #[test]
    fn test_write_response_omits_total_token_count_same_protocol() {
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
                input_tokens: 5,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None, // same-protocol: no boundary signal
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert!(
            wire.pointer("/usageMetadata/totalTokenCount").is_none(),
            "same-protocol round-trip must omit totalTokenCount for byte-identity: {wire}"
        );
    }

    /// The cross-protocol whole-body total saturates (never overflow-panics) on pathological counts.
    #[test]
    fn test_write_response_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: Vec::new(),
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: Some(1_700_000_000), // cross-protocol
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {wire}"
        );
    }

    // --- Round 9 fix (conformance): totalTokenCount also emits when the boundary signal is `model`
    //     (not just `created`), so Anthropic/Cohere backends — whose readers return `created: None`
    //     but DO populate `model` — no longer drop the total for a Gemini client. ---

    /// Regression (R9): a cross-protocol response from a backend whose reader sets `created: None`
    /// but `model: Some(..)` (the Anthropic and Cohere shape) MUST still carry
    /// `usageMetadata.totalTokenCount`. Before R9 the gate keyed on `created` alone, so these three-
    /// of-five backends produced a usageMetadata block lacking the total, leaving the google-genai
    /// SDK's `total_token_count` at None and breaking client-side billing.
    #[test]
    fn test_write_response_includes_total_token_count_when_only_model_present() {
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
                input_tokens: 11,
                output_tokens: 4,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            // Anthropic/Cohere cross-protocol shape: model survives, created/id are None.
            model: Some("claude-opus-4-8".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(15)),
            "model-only cross-protocol boundary must still carry totalTokenCount: {wire}"
        );
        assert_eq!(
            wire.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(11))
        );
        assert_eq!(
            wire.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(4))
        );
    }

    /// The model-only cross-protocol total saturates (never overflow-panics) on pathological counts,
    /// guarding the `saturating_add` on this newly-reachable branch of the request path.
    #[test]
    fn test_write_response_model_only_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: Vec::new(),
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("command-r".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {wire}"
        );
    }

    // --- Round 9 fix (performance): modeled_keys is hoisted to a process-global OnceLock. ---

    /// Regression (R9): the modeled-key set is a stable process-global — repeated calls return the
    /// SAME backing allocation (proving it is built once, not per request) and the set's membership
    /// is exactly the modeled top-level keys, so unmodeled keys still flow to `extra`.
    #[test]
    fn test_modeled_request_keys_is_stable_singleton() {
        let a = modeled_request_keys();
        let b = modeled_request_keys();
        assert!(
            std::ptr::eq(a, b),
            "modeled_request_keys must return the same cached set, not rebuild per call"
        );
        for k in [
            "contents",
            "tools",
            "systemInstruction",
            "generationConfig",
            "model",
            crate::proto::GEMINI_JSON_ARRAY_SHIM_KEY,
        ] {
            assert!(a.contains(k), "modeled key set must contain {k}");
        }
        // An arbitrary caller field is NOT modeled, so the reader sweeps it into `extra`.
        assert!(!a.contains("toolConfig"), "toolConfig must not be modeled");
    }

    /// Regression (R9): hoisting the set must not change read behavior — an unmodeled top-level key
    /// still round-trips through `extra`, and the modeled `model` key is preserved exactly once.
    #[test]
    fn test_read_request_unmodeled_key_still_flows_to_extra_after_hoist() {
        let reader = GeminiReader;
        let j = serde_json::json!({
            "model": "gemini-pro",
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}}
        });
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert_eq!(
            ir.extra.get("toolConfig"),
            Some(&serde_json::json!({"functionCallingConfig": {"mode": "AUTO"}})),
            "unmodeled toolConfig must be preserved in extra"
        );
        assert_eq!(
            ir.extra.get("model"),
            Some(&serde_json::json!("gemini-pro")),
            "modeled `model` is preserved in extra exactly once for round-trip identity"
        );
        assert!(
            !ir.extra.contains_key("contents"),
            "modeled `contents` must NOT leak into extra"
        );
    }

    // --- Round 5 fix: tool_use stop reason maps to STOP (Gemini has no TOOL_USE enum member) ---

    /// Regression: a buffered `write_response` with stop_reason=tool_use (the canonical value every
    /// other protocol's reader emits for a tool-call turn) must emit finishReason "STOP", NOT the
    /// invalid "TOOL_USE" the old upper-casing fallback produced.
    #[test]
    fn test_write_response_tool_use_maps_to_stop() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
            }],
            stop_reason: Some("tool_use".to_string()),
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
        assert_eq!(
            wire.pointer("/candidates/0/finishReason")
                .and_then(|f| f.as_str()),
            Some("STOP"),
            "tool_use must map to STOP, never TOOL_USE: {wire}"
        );
    }

    /// Regression: the streamed `MessageDelta` with stop_reason=tool_use also emits finishReason
    /// "STOP" (matching native Gemini, whose FinishReason enum has no TOOL_USE member).
    #[test]
    fn test_stream_message_delta_tool_use_maps_to_stop() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("tool_use".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame
                .pointer("/candidates/0/finishReason")
                .and_then(|f| f.as_str()),
            Some("STOP"),
            "streamed tool_use must map to STOP, never TOOL_USE: {frame}"
        );
    }

    // --- Round 5 fix: image_url sentinel emitted as native fileData URI, not corrupt base64 ---

    /// Regression: an IR Image carrying the `"image_url"` media_type SENTINEL (a remote https URL
    /// stored verbatim by the OpenAI/Responses readers) must be emitted as Gemini `fileData{fileUri}`
    /// — the native URL reference — NOT as `inlineData` with the URL stuffed into the base64 `data`
    /// field and a bogus `mimeType: "image_url"`.
    #[test]
    fn test_write_request_image_url_sentinel_emits_file_data() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    media_type: "image_url".to_string(),
                    data: "https://example.com/cat.png".to_string(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri")
                .and_then(|u| u.as_str()),
            Some("https://example.com/cat.png"),
            "image_url sentinel must emit native fileData.fileUri: {wire}"
        );
        assert!(
            wire.pointer("/contents/0/parts/0/inlineData").is_none(),
            "sentinel URL must NOT be emitted as base64 inlineData: {wire}"
        );
    }

    /// A real base64 image (a genuine mimeType) still emits as `inlineData` — the sentinel branch
    /// must not divert legitimate base64 payloads.
    #[test]
    fn test_write_request_base64_image_still_inline_data() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    media_type: "image/png".to_string(),
                    data: "aGVsbG8=".to_string(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/inlineData/mimeType")
                .and_then(|m| m.as_str()),
            Some("image/png"),
            "base64 image must stay inlineData: {wire}"
        );
        assert_eq!(
            wire.pointer("/contents/0/parts/0/inlineData/data")
                .and_then(|d| d.as_str()),
            Some("aGVsbG8="),
        );
    }

    /// Round-trip: a native Gemini `fileData{fileUri}` part reads into the `"image_url"` sentinel IR
    /// Image and the writer re-emits it as `fileData{fileUri}` verbatim (same-protocol fidelity).
    #[test]
    fn test_file_data_image_round_trips_via_sentinel() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"fileData": {"fileUri": "gs://bucket/img.jpg"}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let img = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::Image { media_type, data } => {
                Some((media_type.clone(), data.clone()))
            }
            _ => None,
        });
        assert_eq!(
            img,
            Some(("image_url".to_string(), "gs://bucket/img.jpg".to_string())),
            "fileData must read into the image_url sentinel: {ir:?}"
        );
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri")
                .and_then(|u| u.as_str()),
            Some("gs://bucket/img.jpg"),
            "fileData must round-trip verbatim: {wire}"
        );
    }

    // --- Round 5 fix: synth_response_id is collision-free (separator, not bare hex concat) ---

    /// Regression: `synth_response_id` joins its (unix_secs, counter) components with a `-`
    /// separator so distinct pairs cannot alias to the same string (a bare `{:x}{:x}` concat could:
    /// e.g. (0x1ab, 0xc) and (0x1a, 0xbc) both render "1abc"). The id must contain a separator.
    #[test]
    fn test_synth_response_id_has_separator() {
        let id = synth_response_id();
        assert!(
            id.contains('-'),
            "synthesized responseId must carry a separator between time and counter: {id}"
        );
    }

    /// Two consecutive synthesized ids (same process second) differ because the counter advances —
    /// guards the collision-free property within a single unix second.
    #[test]
    fn test_synth_response_id_distinct_within_same_second() {
        let a = synth_response_id();
        let b = synth_response_id();
        assert_ne!(a, b, "consecutive synthesized ids must differ: {a} vs {b}");
    }

    /// Regression (HIGH/performance): `state.open_tools` is only drained on a `finishReason` chunk,
    /// so an upstream that streams an unbounded run of `functionCall` parts WITHOUT a finishReason
    /// must not grow it without bound. Past `MAX_GEMINI_TOOL_FRAMES` new tool frames stop being
    /// recorded (and their events suppressed), keeping the set capped while every realistic stream
    /// (a handful of tools) is unaffected. Mirrors the Cohere reader's cap regression.
    #[test]
    fn test_stream_open_tools_growth_is_capped() {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        // Feed many functionCall parts across many chunks, never sending a finishReason so the
        // drain path never runs — the only thing that can keep the set bounded is the cap.
        for n in 0..(MAX_GEMINI_TOOL_FRAMES + 200) {
            reader.read_response_events(
                "",
                &serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                        }
                    }]
                }),
                &mut state,
            );
        }
        assert!(
            state.open_tools.len() <= MAX_GEMINI_TOOL_FRAMES,
            "open_tools must be capped at MAX_GEMINI_TOOL_FRAMES, got {}",
            state.open_tools.len()
        );
    }

    /// The cap must NOT perturb a realistic stream: a small number of tool calls are all recorded
    /// and each gets a matching BlockStart it can close on finishReason.
    #[test]
    fn test_stream_open_tools_under_cap_records_all() {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        let mut starts = 0usize;
        for n in 0..3 {
            for ev in reader.read_response_events(
                "",
                &serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                        }
                    }]
                }),
                &mut state,
            ) {
                if matches!(ev, IrStreamEvent::BlockStart { .. }) {
                    starts += 1;
                }
            }
        }
        assert_eq!(state.open_tools.len(), 3, "all 3 tool frames recorded");
        assert_eq!(starts, 3, "each tool frame emits exactly one BlockStart");
    }

    /// A well-formed credential yields exactly one `x-goog-api-key` header carrying the verbatim key.
    #[test]
    fn test_auth_headers_valid_key_emits_x_goog_api_key() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("AIzaSyValidKey123");
        assert_eq!(headers.len(), 1, "one auth header for a valid key");
        assert_eq!(headers[0].0.as_str(), "x-goog-api-key");
        assert_eq!(headers[0].1.to_str().ok(), Some("AIzaSyValidKey123"));
    }

    /// MEDIUM/security regression: a credential whose bytes are invalid for an HTTP header value
    /// (here an embedded newline) must NOT be silently swallowed into an empty `x-goog-api-key`
    /// value. The writer omits the header entirely (empty vec) and never panics on the request path.
    /// The accompanying `tracing::warn!` (not asserted here) gives the operator the diagnostic the
    /// empty-header behavior lacked.
    #[test]
    fn test_auth_headers_invalid_key_omits_header_no_empty_value() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("bad\nkey");
        assert!(
            headers.is_empty(),
            "an invalid-byte credential must omit the auth header, not emit an empty value: \
             {headers:?}"
        );
    }

    /// An ASCII control byte other than the newline above (here a NUL) is also rejected, exercising
    /// the control-character class of header-invalid byte the validation guards against.
    #[test]
    fn test_auth_headers_control_byte_key_omits_header() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("key\u{0000}bad");
        assert!(
            headers.is_empty(),
            "a control-byte credential must omit the auth header: {headers:?}"
        );
    }
}
