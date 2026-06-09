// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI protocol reader/writer implementation.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest upstream `tool_calls[].index` we accept in a streaming chunk. OpenAI documents at most
/// 128 parallel tool calls, so any larger index is malformed; we clamp to this value before it
/// reaches the IR index arithmetic (`oai_idx + 1 + offset`) so a crafted `u64::MAX` index can never
/// overflow the `usize` cast or the addition. Chosen as the highest valid 0-based index (127).
const MAX_TOOL_INDEX: u64 = 127;

/// Hard cap on the number of DISTINCT tool-call indices we track per stream (`open_tools`). Bounds
/// per-request memory and the number of synthesized BlockStart events against a pathological backend
/// emitting unbounded unique indices. Matches OpenAI's documented parallel-tool-call limit (128).
const MAX_OPEN_TOOLS: usize = 128;

/// Current unix time in seconds, used to synthesize `created` when the backend supplied none
/// (cross-protocol). Falls back to 0 if the clock is before the epoch (never on a sane host) —
/// `created: 0` is still a valid integer the SDK will accept, and we never panic on the request path.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Process-local monotonic counter that GUARANTEES synthesized-id uniqueness within a process. It
/// never repeats while the process lives, so even on the astronomically unlikely event of the OS
/// CSPRNG returning a duplicate (or being unavailable, when we fall back to it entirely) two
/// distinct calls still mint distinct ids. No crate dependency — just `std`.
static SYNTH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Width of a native OpenAI chat-completion id's random suffix: the `chatcmpl-` prefix is followed
/// by exactly 24 base62 characters (total 33 chars), the shape every native `chat.completion` /
/// `chat.completion.chunk` id carries. Matching this length AND alphabet is what keeps the
/// synthesized id structurally indistinguishable from a native one to any client that length-checks
/// or regex-validates `id` (SDK validators, logging/dedup tooling).
const COMPLETION_ID_TOKEN_LEN: usize = 24;

/// Lowercase+uppercase+digit base62 alphabet — the character class native OpenAI completion ids draw
/// their suffix from. Shared by [`synth_completion_id`].
const BASE62: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Synthesize a protocol-correct OpenAI completion id (`"chatcmpl-<24 base62 chars>"`) for
/// cross-protocol responses where the backend supplied none. Native OpenAI chat-completion ids are
/// `chatcmpl-` plus a fixed-width 24-char base62 token (33 chars total); the official SDKs treat
/// `id` as opaque, but tooling that length-checks or regex-validates the id immediately fingerprints
/// a too-short or wrong-alphabet value as non-native. The previous base-36 form produced a
/// variable-width ~7-char little-endian suffix (~16 chars total) — both too short and non-canonical.
///
/// The 24-char suffix is filled from the OS CSPRNG (mirroring `synth_anthropic_request_id` /
/// `synth_amzn_request_id` in `proto::mod`), giving native-looking entropy. To keep the
/// collision-free guarantee unconditionally — independent of the RNG — the strictly-monotonic
/// process counter is folded MSB-first into the leading characters of the token: two calls that
/// happen to draw the same random bytes still differ because their counter values differ, and if the
/// CSPRNG is unavailable the token degrades to a pure counter/timestamp encoding that is still
/// unique and still 24 base62 chars wide. Never panics on the request path.
fn synth_completion_id() -> String {
    let n = SYNTH_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Fill the suffix with CSPRNG bytes mapped into base62. On entropy failure we leave the buffer
    // zeroed (all '0'); the counter overlay below still makes the id unique, so we never panic.
    let mut rand_bytes = [0u8; COMPLETION_ID_TOKEN_LEN];
    let _ = getrandom::getrandom(&mut rand_bytes);
    let mut token = [b'0'; COMPLETION_ID_TOKEN_LEN];
    for (slot, &byte) in token.iter_mut().zip(rand_bytes.iter()) {
        *slot = BASE62[(byte % 62) as usize];
    }

    // Overlay the monotonic counter MSB-first across the leading characters so the per-process
    // uniqueness guarantee holds regardless of the RNG. 62^11 > 2^65 > u64::MAX, so 11 leading
    // characters fully encode any `u64` counter without losing low bits; the remaining 13 stay
    // random. Big-endian (MSB-first) so the digits read naturally rather than reversed.
    let mut counter = n;
    for slot in token.iter_mut().take(11).rev() {
        *slot = BASE62[(counter % 62) as usize];
        counter /= 62;
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards
    // against an impossible non-ASCII byte and keeps the path panic-free.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("chatcmpl-{token}")
}

/// Derive the native OpenAI `error.code` value for a given OpenAI error `type`.
///
/// Real OpenAI does not emit `code: null` uniformly: a bad-key 401 carries
/// `{"type":"invalid_request_error", ...}` historically, but the modern wire shape returns
/// `{"type":"authentication_error", ..., "code":"invalid_api_key"}` — and crucially the
/// official SDKs (`openai.AuthenticationError`) surface `error.code` to callers, so emitting
/// `code: null` on an auth failure is a deterministic proxy tell that contradicts the
/// total-indistinguishability promise. We map the auth type onto its canonical code; every other
/// type keeps `null` (the shape OpenAI uses when no machine-readable code applies). The match is
/// exhaustive in intent over the type strings this writer can produce — there is no `_ =>`
/// catch-all hiding an unhandled case; the final arm explicitly handles all remaining valid types
/// by emitting `null`, which is the correct native value for them.
fn openai_error_code(error_type: &str) -> serde_json::Value {
    match error_type {
        "authentication_error" => serde_json::Value::String("invalid_api_key".to_string()),
        // Real OpenAI quota-exhaustion errors carry BOTH `type` and `code` set to
        // `insufficient_quota` (HTTP 429). The over-budget governance path
        // (route.rs `ingress_error(..., "insufficient_quota", ...)`) reaches this writer with that
        // type; emitting `code: null` for it is an SDK-visible mismatch (the official client surfaces
        // `error.code == "insufficient_quota"`) and a proxy tell, so we mirror the native pairing.
        "insufficient_quota" => serde_json::Value::String("insufficient_quota".to_string()),
        "invalid_request_error"
        | "permission_error"
        | "not_found_error"
        | "rate_limit_error"
        | "server_error"
        | "api_error" => serde_json::Value::Null,
        other => {
            // A caller-supplied passthrough type we don't model a code for: OpenAI carries no
            // machine-readable code for these, so `null` matches the native shape. Named binding
            // (not `_`) keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            serde_json::Value::Null
        }
    }
}

/// OpenAI reader implementation.
#[derive(Clone)]
pub(crate) struct OpenAiReader;

impl ProtocolReader for OpenAiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body exactly once and derive both fields from the single tree, mirroring
        // the single-parse pattern in AnthropicReader::extract_error. The previous code parsed the
        // same bytes twice (once per field), doubling alloc/CPU on every non-2xx response.
        let json = serde_json::from_slice::<serde_json::Value>(body).ok();
        let error_obj = json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_object());
        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get("code"))
            .and_then(|c| c.as_str())
            .map(String::from);
        let structured_type = error_obj
            .and_then(|e_obj| e_obj.get("type"))
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
        // context-length-exceeded — the lane is healthy; this must fail over (to a
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

        // Handle messages array
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;

            for msg_val in msgs_arr.iter() {
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

                // Promote EVERY system-role message to the top-level system field, regardless of
                // position. OpenAI permits system turns anywhere in the array, but Anthropic (and
                // the IR contract) require system content to live in the top-level `system` field —
                // a System-role IrMessage placed inside the messages array would be rendered as
                // `"role": "system"` by the Anthropic writer and rejected with a 400. We therefore
                // never push a System IrMessage; we accumulate its content into system_blocks.
                if role == crate::ir::IrRole::System {
                    let blocks_before = system_blocks.len();
                    if let Some(content) = content_val {
                        if let Some(text) = content.as_str() {
                            system_blocks.push(crate::ir::IrBlock::Text {
                                text: text.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = content.as_array() {
                            for block_val in arr {
                                system_blocks.push(read_openai_block(block_val)?);
                            }
                        }
                    }
                    // A present-but-degenerate system message (e.g. content omitted, null, or an
                    // empty array) must not silently vanish: emit an empty Text block so the system
                    // turn is preserved rather than dropped. `content_val.is_none()` (key absent)
                    // also lands here, which matches treating an empty system turn as present.
                    if system_blocks.len() == blocks_before {
                        system_blocks.push(crate::ir::IrBlock::Text {
                            text: String::new(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                } else {
                    let mut msg_content = Vec::new();

                    if let Some(cv) = content_val {
                        if let Some(text) = cv.as_str() {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = cv.as_array() {
                            for block_val in arr {
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
                        // OpenAI tool-message `content` may be EITHER a plain string OR an array of
                        // content parts (e.g. `[{"type":"text","text":"..."}]`), both legal per the
                        // current Chat Completions spec. The prior `as_str().unwrap_or("")` handled
                        // only the string form and silently collapsed array-form tool output to an
                        // empty string, dropping the tool result on the cross-protocol path. We now
                        // mirror the user/assistant content handling: a string is used verbatim; an
                        // array is parsed part-by-part via `read_openai_block` and its text parts are
                        // concatenated. Non-text parts (which carry no textual payload) contribute
                        // nothing, matching how a native backend would render the same array.
                        let content_text = match content_val {
                            Some(serde_json::Value::String(s)) => s.clone(),
                            Some(serde_json::Value::Array(parts)) => {
                                let mut acc = String::new();
                                for part in parts {
                                    if let Ok(crate::ir::IrBlock::Text { text, .. }) =
                                        read_openai_block(part)
                                    {
                                        acc.push_str(&text);
                                    }
                                }
                                acc
                            }
                            Some(_) | None => String::new(),
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
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_openai_tool(tool_val)?);
            }
        }

        // Collect unmodeled top-level keys into extra (excluding modeled ones). Only the fields the
        // IR models as first-class (model, messages, tools, max_tokens, temperature, stream) are
        // excluded; everything else — including the sampling parameters top_p, frequency_penalty,
        // presence_penalty, stop, n, and logit_bias — flows through `extra` verbatim so it reaches
        // the upstream after IR translation. (Previously these six were listed here but only top_p
        // was re-inserted, silently dropping the other five and changing generation behavior.)
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
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        let _ = (event_type, data);
        None
    }

    /// OpenAI's flat stream → IR block-structured events. One chat.completion.chunk
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

        // 1. MessageStart exactly once (on the first chunk, regardless of delta.role). Capture the
        //    chunk's top-level identity (`id` = "chatcmpl-...", `created` = unix secs, `model`) so a
        //    same-protocol passthrough stream re-emits it verbatim. Every OpenAI chunk carries these;
        //    we read them off whichever chunk happens to be first.
        if !state.started {
            state.started = true;
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: data.get("id").and_then(|v| v.as_str()).map(String::from),
                created: data.get("created").and_then(|v| v.as_u64()),
                model: data.get("model").and_then(|v| v.as_str()).map(String::from),
            });
        }

        let choice0 = data
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first());
        let delta = choice0.and_then(|c| c.get("delta"));

        // 2. Reasoning (chain-of-thought) → a Thinking block at index 0, ahead of the answer. When
        //    present it shifts the text/tool indices up by one (`offset`) so the thinking block
        //    precedes them. Reasoning streams before content on these models.
        if let Some(reasoning) = delta
            .and_then(|d| d.get("reasoning_content").or_else(|| d.get("reasoning")))
            .and_then(|r| r.as_str())
        {
            if !reasoning.is_empty() {
                state.reasoning_seen = true;
                if !state.thinking_block_open {
                    state.thinking_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: 0,
                        block: crate::ir::IrBlockMeta::Thinking,
                    });
                }
                out.push(IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: crate::ir::IrDelta::ThinkingDelta(reasoning.to_string()),
                });
            }
        }

        // Index offset: a thinking block (when present) owns index 0, so text/tools shift up by one.
        let offset = usize::from(state.reasoning_seen);
        let text_index = offset;

        // 3. Text content → close any open thinking block first, then open the text block + a
        //    TextDelta. Text owns index `offset` (0 normally, 1 when a thinking block precedes it).
        if let Some(content) = delta
            .and_then(|d| d.get("content"))
            .and_then(|c| c.as_str())
        {
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            if !state.text_block_open {
                state.text_block_open = true;
                out.push(IrStreamEvent::BlockStart {
                    index: text_index,
                    block: crate::ir::IrBlockMeta::Text,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: text_index,
                delta: crate::ir::IrDelta::TextDelta(content.to_string()),
            });
        }

        // 4. Tool calls → IR block index = oai_idx + 1 + offset (text owns `offset`). BlockStart on
        //    first sight (id+name present), InputJsonDelta for streamed arguments.
        if let Some(tcs) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(|t| t.as_array())
        {
            // A tool call means the answer phase has begun; close any still-open thinking block.
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            for tc in tcs {
                // Bound the upstream-supplied tool-call index before it touches our index
                // arithmetic. A crafted/proxied chunk can carry `"index": u64::MAX`; casting that
                // raw to `usize` and computing `oai_idx + 1 + offset` overflows — panicking on the
                // request path in debug builds and silently wrapping to a near-zero index in release
                // (corrupting the IR block sequence delivered downstream). OpenAI documents at most
                // 128 parallel tool calls, so any larger index is malformed; clamp to MAX_TOOL_INDEX
                // and compute the IR index with checked arithmetic, skipping the chunk if it still
                // would not fit (never reachable at this cap, but keeps the path panic-free).
                let oai_idx = tc
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map_or(0, |v| v.min(MAX_TOOL_INDEX) as usize);
                let ir_idx = match oai_idx.checked_add(1).and_then(|n| n.checked_add(offset)) {
                    Some(idx) => idx,
                    None => continue,
                };
                let func = tc.get("function");
                if let Some(name) = func.and_then(|f| f.get("name")).and_then(|n| n.as_str()) {
                    // Cap the number of DISTINCT open tool calls per stream. Without this, a
                    // pathological backend emitting unbounded unique indices would grow `open_tools`
                    // (and the emitted BlockStart count) without limit — a per-request memory-
                    // exhaustion DoS. The cap matches OpenAI's documented parallel-tool-call limit;
                    // an index beyond it that is not already open is treated as argument deltas for
                    // an already-open block (its BlockStart is suppressed) rather than opening a new
                    // one. An already-open index is always honored so in-flight blocks keep flowing.
                    let already_open = state.open_tools.contains(&oai_idx);
                    if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
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
                    // Only route argument deltas to indices we actually opened a BlockStart for;
                    // otherwise an over-cap index would emit a delta against a block that was never
                    // started, corrupting the downstream stream.
                    if state.open_tools.contains(&oai_idx) {
                        out.push(IrStreamEvent::BlockDelta {
                            index: ir_idx,
                            delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                        });
                    }
                }
            }
        }

        // Read top-level `usage` INDEPENDENTLY of finish_reason. With
        // `stream_options: {include_usage: true}` the OpenAI API emits usage in a SEPARATE trailing
        // chunk whose `choices` array is EMPTY and which carries NO finish_reason — for that chunk
        // `choice0` is None, so the finish_reason branch below never runs. Reading usage here (rather
        // than only inside the finish_reason block, as the prior code did) ensures the trailing
        // usage chunk is not silently discarded, preserving token accounting across translated /
        // passthrough OpenAI streams that follow the spec'd trailing-usage convention.
        let chunk_usage = data.get("usage").map(|u| IrUsage {
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
        });

        // 5. finish_reason → close open blocks (text first, then tools ascending), MessageDelta, MessageStop.
        let finish_reason = choice0
            .and_then(|c| c.get("finish_reason"))
            .and_then(|r| r.as_str());
        if let Some(fr) = finish_reason {
            // Close in order: thinking (0, if it never yielded to text), then text, then tools.
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            if state.text_block_open {
                state.text_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: text_index });
            }
            for oai_idx in std::mem::take(&mut state.open_tools) {
                // `oai_idx` was clamped to <= MAX_TOOL_INDEX before it entered `open_tools`, so this
                // cannot overflow; use saturating arithmetic anyway so the close index can never wrap
                // and the BlockStop always pairs with the BlockStart's IR index.
                out.push(IrStreamEvent::BlockStop {
                    index: oai_idx.saturating_add(1).saturating_add(offset),
                });
            }
            let stop_reason = Some(match fr {
                "stop" => "end_turn".to_string(),
                "length" => "max_tokens".to_string(),
                "tool_calls" => "tool_use".to_string(),
                // Normalize OpenAI-specific finish reasons to the canonical IR vocabulary so they do
                // not leak verbatim to other protocols' writers. `content_filter` (a common
                // moderation outcome) becomes the canonical `safety` token the Gemini writer maps to
                // its SAFETY enum; legacy `function_call` becomes `tool_use`. Leaving them verbatim
                // produced invalid cross-protocol enum values (e.g. Gemini `CONTENT_FILTER`).
                "content_filter" => "safety".to_string(),
                "function_call" => "tool_use".to_string(),
                other => other.to_string(),
            });
            let usage = chunk_usage.unwrap_or(IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            });
            out.push(IrStreamEvent::MessageDelta {
                stop_reason,
                // OpenAI has no stop_sequence analog in its stream.
                stop_sequence: None,
                usage,
            });
            out.push(IrStreamEvent::MessageStop);
        } else if let Some(usage) = chunk_usage {
            // Trailing usage-only chunk (include_usage convention): no finish_reason and no choices,
            // but a top-level `usage` object. Fold it into a MessageDelta with `stop_reason: None`
            // (in-progress finish per the chunk shape) so cross-protocol consumers — e.g. an
            // Anthropic client reading `message_delta.usage` — see real input/output token counts
            // instead of zeros. No MessageStop is emitted here: the terminal finish_reason chunk
            // (or the stream's `[DONE]`) still ends the message; this only carries the late usage.
            out.push(IrStreamEvent::MessageDelta {
                stop_reason: None,
                stop_sequence: None,
                usage,
            });
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

        // Reasoning models on OpenAI-compatible providers (e.g. GLM, DeepSeek) emit the
        // chain-of-thought in a separate `reasoning_content` (or `reasoning`) field. Map it to a
        // Thinking block — ahead of the answer — so it survives translation to protocols that have
        // one (e.g. Anthropic). (Protocols without a thinking concept drop it on write, as before.)
        for key in ["reasoning_content", "reasoning"] {
            if let Some(r) = message_val.get(key).and_then(|v| v.as_str()) {
                if !r.is_empty() {
                    content.push(crate::ir::IrBlock::Thinking {
                        text: r.to_string(),
                        signature: None,
                    });
                    break;
                }
            }
        }

        if let Some(content_val) = message_val.get("content") {
            if let Some(text) = content_val.as_str() {
                if !text.is_empty() {
                    content.push(crate::ir::IrBlock::Text {
                        text: text.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                }
            } else if let Some(arr) = content_val.as_array() {
                for block_val in arr {
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
            // Normalize OpenAI-specific finish reasons to the canonical IR vocabulary so they do not
            // leak verbatim into IrResponse.stop_reason and out through other protocols' writers.
            // `content_filter` -> the canonical `safety` token (Gemini writer maps it to SAFETY);
            // legacy `function_call` -> `tool_use`. (Mirrors the stream path.)
            "content_filter" => Some("safety".to_string()),
            "function_call" => Some("tool_use".to_string()),
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

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream's response identity so same-protocol (OpenAI→OpenAI) passthrough
        // preserves it exactly: `id` ("chatcmpl-..."), `created` (unix secs), `system_fingerprint`.
        // (`object` is fixed "chat.completion" and re-emitted by the writer; `usage.total_tokens` is
        // derivable from prompt+completion, so it is recomputed on write rather than stored.)
        let id = obj.get("id").and_then(|v| v.as_str()).map(String::from);
        let created = obj.get("created").and_then(|v| v.as_u64());
        let system_fingerprint = obj
            .get("system_fingerprint")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint,
            stop_sequence: None,
        })
    }
}

/// Read an OpenAI-format block from JSON.
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
            let url = image_obj.get("url").and_then(|v| v.as_str()).unwrap_or("");
            // The IR `Image` contract (set by the Anthropic reader) is: `media_type` = a real MIME
            // type (e.g. "image/png") and `data` = the raw base64 payload. The Anthropic writer
            // renders that as a `{"type":"base64", "media_type":..., "data":...}` source. The prior
            // code stored `media_type: "image"` (a literal, not a MIME type) and `data: <the full
            // url>`, which the Anthropic writer then emitted as a base64 source whose data was a
            // URL — an invalid Anthropic request. For a `data:<mime>;base64,<payload>` URI we now
            // split out the real MIME type and payload so the cross-protocol image is valid.
            let (media_type, data) = parse_image_url(url);
            Ok(crate::ir::IrBlock::Image { media_type, data })
        }
        // OpenAI gpt-4o-and-later responses carry `refusal` content parts; a client replaying its
        // OpenAI conversation history through busbar will include them. Map a refusal to a Text block
        // carrying the refusal string so the turn survives translation rather than being rejected with
        // a 400 (the prior `_ => Err` behavior turned legitimate replayed history into a hard error).
        "refusal" => {
            let text = obj
                .get("refusal")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        // Forward-compatibility: an unknown/future content-part type (one OpenAI adds after this
        // build) must not break otherwise-valid conversation history. Degrade gracefully to an empty
        // Text block — preserving the part's position in the turn without injecting foreign data —
        // rather than failing the whole request with a ClientError. This is a content-shape match, not
        // a disposition/breaker match, so a named graceful-degradation arm is correct here.
        other => {
            let _ = other;
            Ok(crate::ir::IrBlock::Text {
                text: String::new(),
                cache_control: None,
                citations: Vec::new(),
            })
        }
    }
}

/// Split an OpenAI `image_url` string into the IR `Image` (media_type, data) pair.
///
/// A `data:<mime>;base64,<payload>` URI is decomposed into its real MIME type ("image/png") and
/// raw base64 payload, matching the IR contract the Anthropic reader/writer use for base64 images.
/// Any other URL (an https reference, or a data URI we cannot confidently split) is preserved
/// verbatim in `data` with an "image_url" media_type sentinel, so the OpenAI writer can reconstruct
/// the original `image_url` exactly on same-protocol round-trips without guessing a MIME type.
fn parse_image_url(url: &str) -> (String, String) {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            // meta is e.g. "image/png;base64" or "image/png" — keep only the MIME type.
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return (media_type, payload.to_string());
            }
        }
    }
    // Non-data URL (https://...) or an unrecognized data URI: keep it verbatim. The "image_url"
    // sentinel marks that `data` is a URL rather than a base64 payload so the OpenAI writer round-
    // trips it as-is. (A faithful cross-protocol projection of a URL-source image to Anthropic's
    // `{"type":"url",...}` source requires an IR discriminant / Anthropic-writer change outside the
    // OpenAI module's ownership and is therefore not handled here.)
    ("image_url".to_string(), url.to_string())
}

/// Reconstruct an OpenAI `image_url` string from the IR `Image` (media_type, data) pair — the
/// inverse of [`parse_image_url`]. A URL-sentinel image is emitted verbatim; a base64 image is
/// re-wrapped into a `data:<mime>;base64,<payload>` URI.
fn image_url_from_ir(media_type: &str, data: &str) -> String {
    if media_type == "image_url" {
        data.to_string()
    } else {
        format!("data:{media_type};base64,{data}")
    }
}

/// Read an OpenAI-format tool from JSON.
fn read_openai_tool(tool_val: &serde_json::Value) -> Result<crate::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    // OpenAI nests the tool definition under `function` ({"type":"function","function":{...}}).
    // Read from there, falling back to the top level so a flattened/native-shaped tool still works.
    let src = obj
        .get("function")
        .and_then(|f| f.as_object())
        .unwrap_or(obj);

    let name = src
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = src
        .get("description")
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = src
        .get("parameters")
        .or_else(|| src.get("input_schema"))
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
        let mut messages_array: Vec<serde_json::Value> = Vec::new();

        // Prepend system message as first message if present. OpenAI system messages carry plain
        // text only, so every system block is projected to text EXPLICITLY here rather than via a
        // silent `if let Text` that would drop non-text blocks without a trace (the prior behavior).
        // Text and Thinking both carry textual system guidance and are forwarded; the structurally
        // text-less variants (ToolUse / ToolResult / Image) have no OpenAI system representation and
        // are projected to empty text — a documented lossy projection, not a silent drop. The match
        // is exhaustive (no `_ =>` catch-all) so a future IrBlock variant forces a compile error.
        for block in &req.system {
            let text: &str = match block {
                crate::ir::IrBlock::Text { text, .. } => text,
                crate::ir::IrBlock::Thinking { text, .. } => text,
                crate::ir::IrBlock::ToolUse { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Image { .. } => "",
            };
            messages_array.push(serde_json::json!({
                "role": "system",
                "content": text
            }));
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
                        crate::ir::IrBlock::Image { media_type, data } => {
                            // Reconstruct the original `image_url` from the IR pair: a URL-sentinel
                            // image is emitted verbatim, a base64 image is re-wrapped as a data URI.
                            let url = image_url_from_ir(media_type, data);
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
                            // ToolUse is not OpenAI message content; it is surfaced via the
                            // `tool_calls` array built for this message below (any role).
                        }
                        crate::ir::IrBlock::ToolResult { .. } => {
                            // ToolResult is not OpenAI message *content*; for a Tool-role message it
                            // is rendered as a standalone `{"role":"tool","tool_call_id":...}` entry
                            // by the tool-result path below. On a non-tool message it has no OpenAI
                            // content representation, so it is intentionally not emitted here.
                        }
                        crate::ir::IrBlock::Thinking { .. } => {
                            // Lossy-by-necessity: OpenAI Chat Completions has no thinking/reasoning
                            // content block on request input, so a Thinking block is dropped here.
                        }
                    }
                }

                // A message carrying only ToolUse blocks (a tool-call-only assistant turn) yields an
                // empty content_arr: ToolUse is surfaced via `tool_calls`, not `content`. The OpenAI
                // Chat Completions API expects such messages to have `content: null`, not `[]` — some
                // validators reject an empty array alongside `tool_calls`. Emit Null in that case.
                if content_arr.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Array(content_arr)
                }
            };

            let mut msg_obj = serde_json::json!({
                "role": role_str,
                "content": content_val,
            });

            // Emit tool_calls for ANY message carrying ToolUse blocks, not only assistant ones.
            // A ToolUse on a non-assistant role is unusual but legal in the IR; gating this on the
            // assistant role silently dropped such tool calls. Building tool_calls for the block's
            // own message is non-lossy and keeps the id/arguments round-tripping.
            {
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
            } else {
                // Only add non-tool messages to the array directly (tool results are handled above).
                // This is the `msg.role != Tool` branch by construction — the guard is implicit.
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

        // Add tools if present. The Chat Completions API requires the NESTED tool shape
        // `{"type":"function","function":{"name":...,"description":...,"parameters":...}}` — name,
        // description, and parameters live INSIDE the `function` sub-object, not at the top level.
        // Emitting the flat `{"type":"function","name":...,"parameters":...}` shape is rejected with a
        // 400 by every native Chat Completions backend and SDK since late 2023, and the off-spec shape
        // is itself a proxy tell. `read_openai_tool` already reads from the nested `function` object,
        // so this writer is the inverse of the reader.
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut function_obj = serde_json::Map::new();
                function_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    function_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                // Map OpenAI's "parameters" to our input_schema
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                function_obj.insert("parameters".to_string(), params);

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert(
                    "function".to_string(),
                    serde_json::Value::Object(function_obj),
                );

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

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                id,
                created,
                model,
                ..
            } => {
                let openai_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::User
                    | crate::ir::IrRole::System
                    | crate::ir::IrRole::Tool => return None,
                };
                let delta_obj = serde_json::json!({ "role": openai_role });
                // The opening chunk carries the stream's identity (`id`, `created`, `model`); an
                // official OpenAI stream repeats these on every chunk, but emitting them on the first
                // (role) chunk is sufficient for the SDKs, which latch the id/created/model from the
                // first chunk that supplies them. When the backend supplied none (cross-protocol),
                // SYNTHESIZE a protocol-correct id/created so a native SDK accepts the stream.
                let chunk_id = id.clone().unwrap_or_else(synth_completion_id);
                let chunk_created = created.unwrap_or_else(unix_now_secs);
                let mut chunk = serde_json::json!({
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": chunk_created,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": null
                    }]
                });
                if let Some(m) = model {
                    chunk["model"] = serde_json::json!(m);
                }
                Some(("".to_string(), chunk))
            }
            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => None,
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Use the IR block index (canonical) so parallel tool calls keep distinct,
                    // stable indices. OpenAI SDKs route streaming argument fragments by
                    // `tool_calls[n].index`; the BlockStart and its BlockDeltas must carry the
                    // same value or the reconstructed arguments collide at index 0.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
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
            IrStreamEvent::BlockDelta { index, delta } => match delta {
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
                    // Mirror the index emitted by the matching BlockStart so argument
                    // fragments are routed to the correct parallel tool call.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
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
                // Map the IR stop_reason onto OpenAI's finish_reason enum. A non-terminal delta with
                // no stop_reason must serialize finish_reason as JSON `null` — NOT the empty string.
                // OpenAI chat.completion.chunk uses null for in-progress chunks and a valid enum
                // string ("stop"/"length"/"tool_calls"/"content_filter") only on the final chunk; an
                // empty string is not a valid enum value and fails strict SDK (Pydantic) validation.
                let finish_reason: serde_json::Value = match stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => serde_json::json!("stop"),
                    Some("max_tokens") => serde_json::json!("length"),
                    Some("tool_use") => serde_json::json!("tool_calls"),
                    // Canonical `safety` -> OpenAI's native `content_filter` (the inverse of the
                    // reader's content_filter -> safety normalization), so a cross-protocol or
                    // same-protocol moderation finish emits a valid OpenAI enum value rather than the
                    // off-spec `safety` token.
                    Some("safety") => serde_json::json!("content_filter"),
                    Some(reason) => serde_json::json!(reason),
                    None => serde_json::Value::Null,
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
                // Map the IR error class onto OpenAI's enumerated error `type` vocabulary. The prior
                // hardcoded "error" is not a valid OpenAI error type — SDK clients that switch on
                // `error.type` would fall through to an unhandled default, and the bogus value is a
                // detectable proxy tell. The match is exhaustive over StatusClass (no `_ =>`), so a
                // new class forces an explicit decision; `server_error` is the safe fallback bucket.
                let error_type = match err.class {
                    crate::breaker::StatusClass::RateLimit => "rate_limit_error",
                    crate::breaker::StatusClass::Auth => "authentication_error",
                    crate::breaker::StatusClass::Billing => "permission_error",
                    crate::breaker::StatusClass::ContextLength
                    | crate::breaker::StatusClass::ClientError => "invalid_request_error",
                    crate::breaker::StatusClass::Overloaded
                    | crate::breaker::StatusClass::ServerError
                    | crate::breaker::StatusClass::Timeout
                    | crate::breaker::StatusClass::Network => "server_error",
                };
                // Include `code` and `param` as JSON null, matching BOTH the native OpenAI error
                // shape and this writer's own non-stream `write_error` envelope. Omitting them made
                // an in-stream error structurally different from a non-stream error (a detectable
                // proxy tell) and broke clients that destructure `error.code` / `error.param`.
                let error_obj = serde_json::json!({
                    "error": {
                        "message": message,
                        "type": error_type,
                        "code": openai_error_code(error_type),
                        "param": serde_json::Value::Null,
                    }
                });
                Some(("".to_string(), error_obj))
            }
        }
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    /// Native OpenAI error envelope, served as `application/json`:
    /// `{"error":{"message":<msg>,"type":<type>,"param":null,"code":null}}`. This is the exact shape
    /// the official OpenAI SDKs decode (`openai.APIError` reads `error.message`/`error.type`/
    /// `error.code`/`error.param`), so a client on the native SDK gets a typed exception rather than
    /// an undecodable body. The generic `kind` is mapped onto OpenAI's own error-`type` vocabulary
    /// where one exists; otherwise it is passed through verbatim (still a valid string `type`).
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map the protocol-agnostic `kind` onto OpenAI's documented error `type` values. OpenAI's
        // vocabulary: "invalid_request_error", "authentication_error", "permission_error",
        // "not_found_error", "rate_limit_error", "server_error", "api_error". HTTP 401/403/404/429
        // categories and common generic kinds are normalized; anything unrecognized falls back to a
        // status-derived bucket (4xx → invalid_request_error, 5xx → server_error) so the emitted
        // `type` is always a real OpenAI type. No `_ =>` catch-all on the kind match: each known
        // kind is listed, with the status-based fallback handled explicitly afterwards.
        let error_type = match kind {
            "invalid_request_error" | "invalid_request" | "bad_request" => "invalid_request_error",
            "authentication_error" | "unauthorized" | "auth" => "authentication_error",
            "permission_error" | "permission_denied" | "forbidden" => "permission_error",
            "not_found_error" => "not_found_error",
            "rate_limit_error" | "rate_limit" | "too_many_requests" => "rate_limit_error",
            "server_error" | "internal_error" | "internal_server_error" => "server_error",
            "api_error" => "api_error",
            // Quota exhaustion is a first-class native OpenAI type (HTTP 429); preserve it so the
            // over-budget governance path keeps the real `insufficient_quota` type AND its matching
            // `code` (set in `openai_error_code`).
            "insufficient_quota" => "insufficient_quota",
            // The all-lanes-exhausted 503 path and the request-timeout 503 path pass the
            // Anthropic-vocabulary kind `overloaded` to EVERY ingress writer. `overloaded` is not an
            // OpenAI error type — real OpenAI reports a 503 / transient upstream failure as
            // `server_error` — so emitting `type:"overloaded"` is both a conformance break (the
            // official SDK's typed-exception mapping fails on an unknown type) and a cross-protocol
            // vocabulary leak. Map every transient/unavailable spelling onto OpenAI's native 5xx type.
            "overloaded"
            | "overloaded_error"
            | "service_unavailable"
            | "unavailable"
            | "transient"
            | "timeout"
            | "network"
            | "5xx" => "server_error",
            "context_length_exceeded" => "invalid_request_error",
            // Empty kind: derive a valid OpenAI type from the HTTP status bucket rather than emitting
            // an empty `type`, so the SDK still sees a real error type.
            "" => {
                if (500..600).contains(&status) {
                    "server_error"
                } else {
                    "invalid_request_error"
                }
            }
            // Any other caller-supplied kind (including the generic `not_found`) is passed through
            // verbatim: OpenAI has no single canonical `type` for it (model-not-found is reported as
            // `invalid_request_error` + `code: "model_not_found"` on some endpoints and
            // `not_found_error` on others), so we preserve the caller's token rather than guess.
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "param": serde_json::Value::Null,
                "code": openai_error_code(error_type),
            }
        })
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // Collect the assistant text parts exactly once: their presence decides whether
        // `content` is null, and their join is the content string. (Previously a parallel Vec of
        // discarded JSON objects was built solely to test emptiness — a dead allocation that
        // duplicated the extraction logic.)
        let text_parts: Vec<&str> = resp
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();

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
            "content": if text_parts.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(text_parts.concat())
            },
        });

        // Add tool_calls only if present
        if !tool_calls_arr.is_empty() {
            message_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
        }

        let mut choices_array: Vec<serde_json::Value> = Vec::new();
        // The OpenAI chat.completion spec requires `finish_reason` to ALWAYS be present in a choice
        // object — a valid enum string ("stop"/"length"/"tool_calls"/...) or JSON `null` when the
        // upstream provided no stop reason (e.g. a cross-protocol Bedrock response whose
        // `read_response` yields `stop_reason: None`). The prior code mapped `None` to "" and then
        // omitted the key entirely; a missing `finish_reason` is not a valid choice shape and the
        // Python SDK's Pydantic model raises a validation error on it. Emit null instead.
        let finish_reason: serde_json::Value = match resp.stop_reason.as_deref() {
            Some("end_turn") | Some("stop_sequence") => serde_json::json!("stop"),
            Some("max_tokens") => serde_json::json!("length"),
            Some("tool_use") => serde_json::json!("tool_calls"),
            // Canonical `safety` -> OpenAI's native `content_filter` (inverse of the reader's
            // content_filter -> safety normalization), keeping the emitted enum value valid.
            Some("safety") => serde_json::json!("content_filter"),
            Some(reason) => serde_json::json!(reason),
            None => serde_json::Value::Null,
        };

        let mut choice_obj = serde_json::Map::new();
        choice_obj.insert("index".to_string(), serde_json::json!(0));
        choice_obj.insert("message".to_string(), message_obj);
        choice_obj.insert("finish_reason".to_string(), finish_reason);
        choices_array.push(serde_json::Value::Object(choice_obj));

        // Identity fields, in the order an official OpenAI chat.completion object carries them
        // ({"id","object","created","model","system_fingerprint","choices","usage"}). The Python and
        // Node SDKs require `id` (str), `object` == "chat.completion", `created` (int), `model` (str),
        // `choices`, and `usage`; `system_fingerprint` is optional. When the IR field is `None`
        // (cross-protocol: the backend never minted one) we SYNTHESIZE a protocol-correct value so a
        // native SDK can't tell this was translated.
        let id = resp.id.clone().unwrap_or_else(synth_completion_id);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!("chat.completion"));
        let created = resp.created.unwrap_or_else(unix_now_secs);
        obj.insert("created".to_string(), serde_json::json!(created));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
        // system_fingerprint is only emitted when the upstream supplied one (same-protocol
        // passthrough); we do not fabricate an opaque backend marker on cross-protocol responses.
        if let Some(ref fp) = resp.system_fingerprint {
            obj.insert("system_fingerprint".to_string(), serde_json::json!(fp));
        }
        obj.insert(
            "choices".to_string(),
            serde_json::Value::Array(choices_array),
        );

        // Build usage, including the `total_tokens` an SDK expects (prompt + completion).
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "prompt_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "completion_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        usage_map.insert(
            "total_tokens".to_string(),
            serde_json::json!(resp
                .usage
                .input_tokens
                .saturating_add(resp.usage.output_tokens)),
        );
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrBlock, IrBlockMeta, IrDelta, IrMessage, IrRole, IrStreamEvent, IrUsage};

    fn text_block(text: &str) -> IrBlock {
        IrBlock::Text {
            text: text.to_string(),
            cache_control: None,
            citations: Vec::new(),
        }
    }

    // --- Streaming: parallel tool calls must keep distinct, stable indices (fix: index passthrough)

    #[test]
    fn stream_tool_use_block_start_uses_ir_index() {
        let w = OpenAiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 2,
            block: IrBlockMeta::ToolUse {
                id: "call_b".to_string(),
                name: "lookup".to_string(),
            },
        };
        let (_, chunk) = w
            .write_response_event(&ev)
            .expect("tool-use start emits a chunk");
        let tc = &chunk["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], serde_json::json!(2));
        assert_eq!(tc["id"], serde_json::json!("call_b"));
        assert_eq!(tc["function"]["name"], serde_json::json!("lookup"));
    }

    #[test]
    fn stream_input_json_delta_uses_ir_index() {
        let w = OpenAiWriter;
        let ev = IrStreamEvent::BlockDelta {
            index: 3,
            delta: IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
        };
        let (_, chunk) = w
            .write_response_event(&ev)
            .expect("json delta emits a chunk");
        let tc = &chunk["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], serde_json::json!(3));
        assert_eq!(tc["function"]["arguments"], serde_json::json!("{\"q\":1}"));
    }

    #[test]
    fn stream_parallel_tool_calls_do_not_collide_at_index_zero() {
        let w = OpenAiWriter;
        let mk_start = |idx: usize, id: &str| IrStreamEvent::BlockStart {
            index: idx,
            block: IrBlockMeta::ToolUse {
                id: id.to_string(),
                name: "f".to_string(),
            },
        };
        let mk_delta = |idx: usize, frag: &str| IrStreamEvent::BlockDelta {
            index: idx,
            delta: IrDelta::InputJsonDelta(frag.to_string()),
        };

        let s1 = w.write_response_event(&mk_start(1, "a")).unwrap().1;
        let s2 = w.write_response_event(&mk_start(2, "b")).unwrap().1;
        let d1 = w.write_response_event(&mk_delta(1, "x")).unwrap().1;
        let d2 = w.write_response_event(&mk_delta(2, "y")).unwrap().1;

        let idx =
            |v: &serde_json::Value| v["choices"][0]["delta"]["tool_calls"][0]["index"].clone();
        // Two distinct tool calls keep distinct indices...
        assert_ne!(idx(&s1), idx(&s2));
        // ...and each argument fragment routes to the index of its matching start.
        assert_eq!(idx(&s1), idx(&d1));
        assert_eq!(idx(&s2), idx(&d2));
    }

    // --- read_request: system messages at any position promote to top-level system (fixes 2 & 3)

    #[test]
    fn read_request_promotes_non_leading_system_message() {
        let body = serde_json::json!({
            "model": "gpt-x",
            "messages": [
                { "role": "user", "content": "hello" },
                { "role": "system", "content": "be terse" },
                { "role": "assistant", "content": "ok" }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        // The mid-conversation system turn lands in the top-level system field...
        assert_eq!(ir.system.len(), 1);
        assert_eq!(ir.system[0], text_block("be terse"));
        // ...and never appears as a System-role IrMessage inside the messages array.
        assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
        assert_eq!(ir.messages.len(), 2);
    }

    #[test]
    fn read_request_concatenates_multiple_system_messages() {
        let body = serde_json::json!({
            "messages": [
                { "role": "system", "content": "first" },
                { "role": "user", "content": "hi" },
                { "role": "system", "content": "second" }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.system, vec![text_block("first"), text_block("second")]);
        assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
    }

    // --- read_request: degenerate (content-less) system message must not vanish (fix 4)

    #[test]
    fn read_request_preserves_contentless_system_message() {
        let body = serde_json::json!({
            "messages": [
                { "role": "system" },
                { "role": "user", "content": "hi" }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.system, vec![text_block("")]);
    }

    #[test]
    fn read_request_preserves_empty_array_system_message() {
        let body = serde_json::json!({
            "messages": [
                { "role": "system", "content": [] },
                { "role": "user", "content": "hi" }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.system, vec![text_block("")]);
    }

    // --- write_request: ToolUse on a non-assistant message must not be dropped (fix 6)

    #[test]
    fn write_request_keeps_tool_use_on_user_message() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolUse {
                    id: "t9".to_string(),
                    name: "search".to_string(),
                    input: serde_json::json!({"q": "rust"}),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages array");
        let user_msg = &msgs[0];
        let tcs = user_msg["tool_calls"]
            .as_array()
            .expect("tool_calls preserved on user message");
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0]["id"], serde_json::json!("t9"));
        assert_eq!(tcs[0]["function"]["name"], serde_json::json!("search"));
        assert_eq!(
            tcs[0]["function"]["arguments"],
            serde_json::json!("{\"q\":\"rust\"}")
        );
    }

    // --- write_response: content collected once; null when no text (fix 5 regression guard)

    #[test]
    fn write_response_joins_text_blocks_and_keeps_tool_calls() {
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![
                text_block("Hello "),
                text_block("world"),
                IrBlock::ToolUse {
                    id: "c1".to_string(),
                    name: "fn".to_string(),
                    input: serde_json::json!({"a": 1}),
                },
            ],
            stop_reason: Some("tool_use".to_string()),
            usage: IrUsage {
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
        let out = OpenAiWriter.write_response(&resp);
        let msg = &out["choices"][0]["message"];
        assert_eq!(msg["content"], serde_json::json!("Hello world"));
        assert_eq!(msg["tool_calls"][0]["id"], serde_json::json!("c1"));
        assert_eq!(
            out["choices"][0]["finish_reason"],
            serde_json::json!("tool_calls")
        );
    }

    #[test]
    fn write_response_content_null_when_no_text() {
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![IrBlock::ToolUse {
                id: "c1".to_string(),
                name: "fn".to_string(),
                input: serde_json::json!({}),
            }],
            stop_reason: Some("tool_use".to_string()),
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = OpenAiWriter.write_response(&resp);
        assert_eq!(
            out["choices"][0]["message"]["content"],
            serde_json::Value::Null
        );
    }

    // --- Task 1: native OpenAI error envelope shape ---

    #[test]
    fn write_error_native_openai_shape() {
        let v = OpenAiWriter.write_error(404, "not_found_error", "model 'gpt-z' not found");
        // Exact native shape: error.{message,type,param,code}, with param/code null.
        assert_eq!(
            v["error"]["message"],
            serde_json::json!("model 'gpt-z' not found")
        );
        assert_eq!(v["error"]["type"], serde_json::json!("not_found_error"));
        assert_eq!(v["error"]["param"], serde_json::Value::Null);
        assert_eq!(v["error"]["code"], serde_json::Value::Null);
        // Must be JSON-serializable (served as application/json) and have exactly the error object.
        let s = serde_json::to_string(&v).expect("serializes");
        let re: serde_json::Value = serde_json::from_str(&s).expect("valid json");
        assert!(re.get("error").is_some());
    }

    #[test]
    fn write_error_maps_kind_vocabulary() {
        // Known generic kinds map onto OpenAI's own error-type vocabulary.
        for (kind, want) in [
            ("auth", "authentication_error"),
            ("rate_limit", "rate_limit_error"),
            ("forbidden", "permission_error"),
            ("invalid_request", "invalid_request_error"),
            ("context_length_exceeded", "invalid_request_error"),
        ] {
            let v = OpenAiWriter.write_error(400, kind, "x");
            assert_eq!(v["error"]["type"], serde_json::json!(want), "kind={kind}");
        }
    }

    #[test]
    fn write_error_empty_kind_falls_back_to_status_bucket() {
        // Empty kind with a 5xx status derives "server_error"; with a 4xx, "invalid_request_error".
        let v5 = OpenAiWriter.write_error(503, "", "down");
        assert_eq!(v5["error"]["type"], serde_json::json!("server_error"));
        let v4 = OpenAiWriter.write_error(400, "", "bad");
        assert_eq!(
            v4["error"]["type"],
            serde_json::json!("invalid_request_error")
        );
    }

    // --- Task 2: identity-field fidelity ---

    #[test]
    fn read_response_captures_upstream_identity() {
        let body = serde_json::json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "system_fingerprint": "fp_deadbeef",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4}
        });
        let ir = OpenAiReader.read_response(&body).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("chatcmpl-abc123"));
        assert_eq!(ir.created, Some(1_700_000_000));
        assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
        assert_eq!(ir.system_fingerprint.as_deref(), Some("fp_deadbeef"));
    }

    #[test]
    fn same_protocol_roundtrip_preserves_identity() {
        // OpenAI → IR → OpenAI must preserve id/created/system_fingerprint/model exactly.
        let body = serde_json::json!({
            "id": "chatcmpl-xyz789",
            "object": "chat.completion",
            "created": 1_711_111_111u64,
            "model": "gpt-4o-mini",
            "system_fingerprint": "fp_cafef00d",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "pong"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2}
        });
        let ir = OpenAiReader.read_response(&body).expect("read_response");
        let out = OpenAiWriter.write_response(&ir);
        assert_eq!(out["id"], serde_json::json!("chatcmpl-xyz789"));
        assert_eq!(out["object"], serde_json::json!("chat.completion"));
        assert_eq!(out["created"], serde_json::json!(1_711_111_111u64));
        assert_eq!(out["model"], serde_json::json!("gpt-4o-mini"));
        assert_eq!(out["system_fingerprint"], serde_json::json!("fp_cafef00d"));
        // total_tokens is synthesized as prompt + completion.
        assert_eq!(out["usage"]["total_tokens"], serde_json::json!(12));
    }

    #[test]
    fn cross_protocol_write_synthesizes_valid_id() {
        // IR with no identity (cross-protocol: backend supplied none) must still emit a
        // protocol-correct id ("chatcmpl-...") and a created timestamp, without panicking.
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("hello")],
            stop_reason: Some("end_turn".to_string()),
            usage: IrUsage {
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
        let out = OpenAiWriter.write_response(&resp);
        let id = out["id"].as_str().expect("synthesized id is a string");
        assert!(
            id.starts_with("chatcmpl-"),
            "synthesized id has the right prefix: {id}"
        );
        assert!(
            id.len() > "chatcmpl-".len(),
            "synthesized id has a token body"
        );
        assert!(
            out["created"].as_u64().is_some(),
            "created synthesized as unix secs"
        );
        // No system_fingerprint fabricated on cross-protocol responses.
        assert!(out.get("system_fingerprint").is_none());
    }

    #[test]
    fn synth_completion_ids_are_unique() {
        // Two synthesized ids minted back-to-back must differ (atomic counter guarantees it).
        let a = synth_completion_id();
        let b = synth_completion_id();
        assert_ne!(a, b);
        assert!(a.starts_with("chatcmpl-") && b.starts_with("chatcmpl-"));
    }

    #[test]
    fn stream_message_start_emits_identity() {
        // Streaming MessageStart carries id/created/model into the opening chunk; synthesized when None.
        let with_id = IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            id: Some("chatcmpl-stream1".to_string()),
            created: Some(1_722_222_222),
            model: Some("gpt-4o".to_string()),
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&with_id)
            .expect("message start emits a chunk");
        assert_eq!(chunk["id"], serde_json::json!("chatcmpl-stream1"));
        assert_eq!(chunk["object"], serde_json::json!("chat.completion.chunk"));
        assert_eq!(chunk["created"], serde_json::json!(1_722_222_222u64));
        assert_eq!(chunk["model"], serde_json::json!("gpt-4o"));

        // Cross-protocol: no identity → synthesized id + created, still a valid chunk.
        let no_id = IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, chunk2) = OpenAiWriter
            .write_response_event(&no_id)
            .expect("message start emits a chunk");
        assert!(chunk2["id"]
            .as_str()
            .map(|s| s.starts_with("chatcmpl-"))
            .unwrap_or(false));
        assert!(chunk2["created"].as_u64().is_some());
    }

    #[test]
    fn stream_read_captures_chunk_identity() {
        // The first streaming chunk's top-level id/created/model land in the MessageStart IR event.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let ev = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-stream9",
                "object": "chat.completion.chunk",
                "created": 1_733_333_333u64,
                "model": "gpt-4o",
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
            }),
            &mut st,
        );
        let start = ev
            .iter()
            .find(|e| matches!(e, IrStreamEvent::MessageStart { .. }))
            .expect("MessageStart emitted");
        match start {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                assert_eq!(id.as_deref(), Some("chatcmpl-stream9"));
                assert_eq!(*created, Some(1_733_333_333));
                assert_eq!(model.as_deref(), Some("gpt-4o"));
            }
            _ => unreachable!(),
        }
    }

    // --- Round 2 fix 1: total_tokens must saturate, never overflow-panic/wrap ---

    #[test]
    fn write_response_total_tokens_saturates_on_overflow() {
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("x")],
            stop_reason: Some("end_turn".to_string()),
            usage: IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        // Must not panic (debug) or wrap (release); saturates at u64::MAX.
        let out = OpenAiWriter.write_response(&resp);
        assert_eq!(out["usage"]["total_tokens"], serde_json::json!(u64::MAX));
    }

    // --- Round 2 fix 8: sampling params must round-trip through extra, not be dropped ---

    #[test]
    fn read_request_preserves_sampling_params_in_extra() {
        let body = serde_json::json!({
            "model": "gpt-x",
            "messages": [{ "role": "user", "content": "hi" }],
            "top_p": 0.9,
            "frequency_penalty": 0.5,
            "presence_penalty": 0.25,
            "stop": ["\n\n"],
            "n": 2,
            "logit_bias": { "50256": -100 }
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.extra.get("top_p"), Some(&serde_json::json!(0.9)));
        assert_eq!(
            ir.extra.get("frequency_penalty"),
            Some(&serde_json::json!(0.5))
        );
        assert_eq!(
            ir.extra.get("presence_penalty"),
            Some(&serde_json::json!(0.25))
        );
        assert_eq!(ir.extra.get("stop"), Some(&serde_json::json!(["\n\n"])));
        assert_eq!(ir.extra.get("n"), Some(&serde_json::json!(2)));
        assert_eq!(
            ir.extra.get("logit_bias"),
            Some(&serde_json::json!({ "50256": -100 }))
        );
        // And they reach the upstream body on write.
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(out["frequency_penalty"], serde_json::json!(0.5));
        assert_eq!(out["n"], serde_json::json!(2));
    }

    // --- Round 2 fix 3: tool-call-only assistant turn → content: null, not [] ---

    #[test]
    fn write_request_tool_call_only_assistant_has_null_content() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "search".to_string(),
                    input: serde_json::json!({"q": "x"}),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let msg = &out["messages"][0];
        assert_eq!(msg["content"], serde_json::Value::Null);
        assert_eq!(msg["tool_calls"][0]["id"], serde_json::json!("t1"));
    }

    // --- Round 2 fix 2: image_url parsing honors the IR base64 contract ---

    #[test]
    fn read_block_data_uri_splits_media_type_and_payload() {
        let block = serde_json::json!({
            "type": "image_url",
            "image_url": { "url": "data:image/png;base64,AAAB" }
        });
        let ir = read_openai_block(&block).expect("parses");
        match ir {
            IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, "AAAB");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn read_block_https_url_kept_verbatim_with_sentinel() {
        let block = serde_json::json!({
            "type": "image_url",
            "image_url": { "url": "https://example.com/cat.png" }
        });
        let ir = read_openai_block(&block).expect("parses");
        match ir {
            IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image_url");
                assert_eq!(data, "https://example.com/cat.png");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn image_url_round_trips_through_writer() {
        for url in ["data:image/png;base64,AAAB", "https://example.com/cat.png"] {
            let (mt, data) = parse_image_url(url);
            assert_eq!(image_url_from_ir(&mt, &data), url);
        }
    }

    // --- Round 2 fix 10: streaming Error type maps to a real OpenAI error type ---

    #[test]
    fn stream_error_uses_enumerated_openai_type() {
        let cases = [
            (crate::breaker::StatusClass::RateLimit, "rate_limit_error"),
            (crate::breaker::StatusClass::Auth, "authentication_error"),
            (crate::breaker::StatusClass::Billing, "permission_error"),
            (
                crate::breaker::StatusClass::ClientError,
                "invalid_request_error",
            ),
            (
                crate::breaker::StatusClass::ContextLength,
                "invalid_request_error",
            ),
            (crate::breaker::StatusClass::ServerError, "server_error"),
            (crate::breaker::StatusClass::Overloaded, "server_error"),
            (crate::breaker::StatusClass::Timeout, "server_error"),
            (crate::breaker::StatusClass::Network, "server_error"),
        ];
        for (class, want) in cases {
            let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
                class,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            });
            let (_, chunk) = OpenAiWriter
                .write_response_event(&ev)
                .expect("error emits a chunk");
            assert_eq!(
                chunk["error"]["type"],
                serde_json::json!(want),
                "class={class:?}"
            );
            assert_eq!(chunk["error"]["message"], serde_json::json!("boom"));
            // Never the bogus literal "error".
            assert_ne!(chunk["error"]["type"], serde_json::json!("error"));
        }
    }

    // --- Round 2 fix 4/6/7: extract_error parses the body once, deriving both fields ---

    #[test]
    fn extract_error_derives_code_and_type_single_parse() {
        let body = br#"{"error":{"message":"nope","type":"invalid_request_error","code":"model_not_found"}}"#;
        let raw = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.provider_code.as_deref(), Some("model_not_found"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
        assert_eq!(raw.http_status, 400);
        // Non-JSON body yields None for both, without panicking.
        let raw2 = OpenAiReader.extract_error(StatusCode::BAD_GATEWAY, b"<html>502</html>");
        assert!(raw2.provider_code.is_none());
        assert!(raw2.structured_type.is_none());
    }

    // --- Round 2 fix 5: non-text system blocks are projected explicitly, not silently dropped ---

    #[test]
    fn write_request_non_text_system_block_does_not_vanish_silently() {
        let req = crate::ir::IrRequest {
            system: vec![
                text_block("be terse"),
                IrBlock::Image {
                    media_type: "image/png".to_string(),
                    data: "AAAB".to_string(),
                },
            ],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text_block("hi")],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages");
        // Both system blocks produce a system message (text forwarded, image projected to "").
        assert_eq!(msgs[0]["role"], serde_json::json!("system"));
        assert_eq!(msgs[0]["content"], serde_json::json!("be terse"));
        assert_eq!(msgs[1]["role"], serde_json::json!("system"));
        assert_eq!(msgs[1]["content"], serde_json::json!(""));
    }

    // --- Round 10 HIGH: synthesized ids must match the native length AND base62 alphabet ---

    #[test]
    fn synth_completion_id_matches_native_length_and_alphabet() {
        // Native OpenAI chat-completion ids are `chatcmpl-` + 24 base62 chars (33 chars total). A
        // too-short or wrong-alphabet suffix is an SDK-/tooling-visible proxy tell.
        let id = synth_completion_id();
        let suffix = id
            .strip_prefix("chatcmpl-")
            .expect("synthesized id has the chatcmpl- prefix");
        assert_eq!(
            suffix.len(),
            COMPLETION_ID_TOKEN_LEN,
            "suffix is exactly the native 24-char width: {id}"
        );
        assert_eq!(id.len(), "chatcmpl-".len() + 24, "total length is 33: {id}");
        // Exactly one hyphen (the prefix's) — no internal field delimiter.
        assert_eq!(id.matches('-').count(), 1, "no internal delimiter: {id}");
        // Every suffix char is in the base62 alphabet [0-9A-Za-z].
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "suffix is base62: {id}"
        );
    }

    #[test]
    fn synth_completion_id_unique_even_with_identical_entropy() {
        // The monotonic counter guarantees uniqueness independent of the RNG: minting many ids in a
        // tight loop (where the timestamp does not advance) must never collide. The counter is folded
        // MSB-first into the leading chars, so adjacent ids differ in those positions.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let id = synth_completion_id();
            assert_eq!(id.len(), "chatcmpl-".len() + 24);
            assert!(seen.insert(id.clone()), "duplicate synthesized id: {id}");
        }
    }

    // --- Round 3 fix 2/5: streaming MessageDelta with no stop_reason emits finish_reason null ---

    #[test]
    fn stream_message_delta_none_stop_reason_serializes_null_not_empty_string() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("message delta emits a chunk");
        let fr = &chunk["choices"][0]["finish_reason"];
        // Must be JSON null, never the empty string (a non-spec value strict SDKs reject).
        assert_eq!(*fr, serde_json::Value::Null);
        assert_ne!(*fr, serde_json::json!(""));
    }

    #[test]
    fn stream_message_delta_maps_stop_reasons_to_openai_enum() {
        let cases = [
            (Some("end_turn"), serde_json::json!("stop")),
            (Some("stop_sequence"), serde_json::json!("stop")),
            (Some("max_tokens"), serde_json::json!("length")),
            (Some("tool_use"), serde_json::json!("tool_calls")),
            (Some("content_filter"), serde_json::json!("content_filter")),
        ];
        for (stop_reason, want) in cases {
            let ev = IrStreamEvent::MessageDelta {
                stop_reason: stop_reason.map(String::from),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let (_, chunk) = OpenAiWriter
                .write_response_event(&ev)
                .expect("message delta emits a chunk");
            assert_eq!(
                chunk["choices"][0]["finish_reason"], want,
                "stop_reason={stop_reason:?}"
            );
        }
    }

    // --- Round 3 fix 4/6: ToolResult block on a non-tool message is not emitted as content,
    //     and the match has no `_ =>` catch-all (compile-time exhaustiveness is the real guard) ---

    #[test]
    fn write_request_assistant_tool_result_block_not_emitted_as_content() {
        // A ToolResult sitting on a non-Tool-role message has no OpenAI content representation; it
        // must not leak into the message content array. (Tool results travel via the tool-role path.)
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![
                    text_block("answer"),
                    IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![text_block("ignored")],
                        is_error: false,
                    },
                ],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let content = out["messages"][0]["content"]
            .as_array()
            .expect("content array");
        // Only the text block survives; the ToolResult is not projected into content.
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], serde_json::json!("text"));
        assert_eq!(content[0]["text"], serde_json::json!("answer"));
    }

    #[test]
    fn write_request_thinking_block_dropped_from_message_content() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![
                    IrBlock::Thinking {
                        text: "secret reasoning".to_string(),
                        signature: None,
                    },
                    text_block("visible"),
                ],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let content = out["messages"][0]["content"]
            .as_array()
            .expect("content array");
        // Thinking is lossy on OpenAI; only the text block is emitted.
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["text"], serde_json::json!("visible"));
    }

    // --- Round 3 fix 3: array content with unwrap-free parse still reads every block ---

    #[test]
    fn read_request_array_content_reads_all_blocks() {
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": "one" },
                    { "type": "text", "text": "two" }
                ]
            }]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(
            ir.messages[0].content,
            vec![text_block("one"), text_block("two")]
        );
    }

    #[test]
    fn read_response_empty_string_content_yields_no_text_block() {
        // An empty-string content must not produce a Text block (the unwrap-free path preserves the
        // prior emptiness guard).
        let body = serde_json::json!({
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": ""},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 0}
        });
        let ir = OpenAiReader.read_response(&body).expect("read_response");
        assert!(ir
            .content
            .iter()
            .all(|b| !matches!(b, IrBlock::Text { .. })));
    }

    // --- Round 4 fix (correctness): trailing usage-only stream chunk is captured, not discarded ---

    #[test]
    fn stream_trailing_usage_only_chunk_emits_message_delta_with_usage() {
        // include_usage convention: a SEPARATE trailing chunk carries top-level `usage` with an
        // EMPTY `choices` array and no finish_reason. The prior code read usage only inside the
        // finish_reason branch, so this chunk's usage was silently dropped. It must now surface as a
        // MessageDelta carrying the real token counts.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        // Prime the stream with a normal first chunk so `started` is set (MessageStart already out).
        let _ = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-u1",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": null}]
            }),
            &mut st,
        );
        // Trailing usage-only chunk: empty choices, no finish_reason, top-level usage present.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-u1",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                    "prompt_tokens_details": { "cached_tokens": 3 }
                }
            }),
            &mut st,
        );
        let delta = evs
            .iter()
            .find(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
            .expect("trailing usage chunk yields a MessageDelta");
        match delta {
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                // In-progress finish per the chunk shape (no finish_reason on a usage-only chunk).
                assert_eq!(*stop_reason, None);
                assert_eq!(*stop_sequence, None);
                assert_eq!(usage.input_tokens, 11);
                assert_eq!(usage.output_tokens, 7);
                assert_eq!(usage.cache_read_input_tokens, Some(3));
            }
            _ => unreachable!(),
        }
        // A usage-only chunk must NOT terminate the message (the finish chunk / [DONE] does that).
        assert!(!evs.iter().any(|e| matches!(e, IrStreamEvent::MessageStop)));
    }

    #[test]
    fn stream_usage_on_finish_chunk_still_captured() {
        // The combined case (usage present on the finish_reason chunk) must keep working: usage
        // flows into the terminal MessageDelta and a MessageStop closes the message.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-u2",
                "created": 1_700_000_001u64,
                "model": "gpt-4o",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": { "prompt_tokens": 5, "completion_tokens": 2 }
            }),
            &mut st,
        );
        let delta = evs
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta {
                    stop_reason, usage, ..
                } => Some((stop_reason.clone(), usage.clone())),
                _ => None,
            })
            .expect("finish chunk yields a MessageDelta");
        assert_eq!(delta.0.as_deref(), Some("end_turn"));
        assert_eq!(delta.1.input_tokens, 5);
        assert_eq!(delta.1.output_tokens, 2);
        assert!(evs.iter().any(|e| matches!(e, IrStreamEvent::MessageStop)));
    }

    // --- Round 4 fix (conformance): in-stream Error envelope includes code/param null ---

    #[test]
    fn stream_error_envelope_includes_null_code_and_param() {
        // The in-stream error body must match the native OpenAI shape (and this writer's non-stream
        // `write_error`): error.{message,type,code,param} with code/param JSON null.
        let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
            class: crate::breaker::StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        });
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("error emits a chunk");
        assert_eq!(chunk["error"]["message"], serde_json::json!("slow down"));
        assert_eq!(
            chunk["error"]["type"],
            serde_json::json!("rate_limit_error")
        );
        // The two fields the prior code omitted, present and explicitly null.
        assert_eq!(chunk["error"]["code"], serde_json::Value::Null);
        assert_eq!(chunk["error"]["param"], serde_json::Value::Null);
        // And present as KEYS (null value), not merely absent — strict destructuring relies on this.
        let err_obj = chunk["error"].as_object().expect("error object");
        assert!(err_obj.contains_key("code"));
        assert!(err_obj.contains_key("param"));
    }

    #[test]
    fn stream_error_shape_matches_write_error_shape() {
        // The set of keys in the in-stream error object must equal the non-stream `write_error`
        // envelope's key set — a divergence is itself a detectable proxy tell.
        let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
            class: crate::breaker::StatusClass::Auth,
            provider_signal: Some("nope".to_string()),
            retry_after: None,
        });
        let (_, stream_chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("error emits a chunk");
        let non_stream = OpenAiWriter.write_error(401, "auth", "nope");
        let mut stream_keys: Vec<&String> = stream_chunk["error"]
            .as_object()
            .expect("stream error object")
            .keys()
            .collect();
        let mut non_stream_keys: Vec<&String> = non_stream["error"]
            .as_object()
            .expect("non-stream error object")
            .keys()
            .collect();
        stream_keys.sort();
        non_stream_keys.sort();
        assert_eq!(stream_keys, non_stream_keys);
    }

    // --- Round 4 fix (conformance): non-stream write_response always emits finish_reason ---

    #[test]
    fn write_response_emits_null_finish_reason_when_stop_reason_none() {
        // A cross-protocol response whose upstream provided no stop reason (stop_reason: None) must
        // still carry a `finish_reason` KEY, serialized as JSON null — never omitted.
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("partial")],
            stop_reason: None,
            usage: IrUsage {
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
        let out = OpenAiWriter.write_response(&resp);
        let choice = out["choices"][0].as_object().expect("choice object");
        assert!(
            choice.contains_key("finish_reason"),
            "finish_reason key must always be present"
        );
        assert_eq!(choice["finish_reason"], serde_json::Value::Null);
    }

    #[test]
    fn write_response_maps_finish_reason_enum_values() {
        let cases = [
            (Some("end_turn"), serde_json::json!("stop")),
            (Some("stop_sequence"), serde_json::json!("stop")),
            (Some("max_tokens"), serde_json::json!("length")),
            (Some("tool_use"), serde_json::json!("tool_calls")),
            (Some("content_filter"), serde_json::json!("content_filter")),
            (None, serde_json::Value::Null),
        ];
        for (stop_reason, want) in cases {
            let resp = crate::ir::IrResponse {
                role: IrRole::Assistant,
                content: vec![text_block("x")],
                stop_reason: stop_reason.map(String::from),
                usage: IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
                model: None,
                id: None,
                created: None,
                system_fingerprint: None,
                stop_sequence: None,
            };
            let out = OpenAiWriter.write_response(&resp);
            assert_eq!(
                out["choices"][0]["finish_reason"], want,
                "stop_reason={stop_reason:?}"
            );
        }
    }

    // --- Round 6 fix 1 (HIGH/security): streaming tool-call index must not overflow the IR index ---

    #[test]
    fn stream_tool_call_index_u64_max_does_not_panic_or_wrap() {
        // A crafted/proxied chunk with `"index": u64::MAX` must not panic (debug) or wrap to a
        // near-zero IR index (release). The index is clamped to MAX_TOOL_INDEX before the
        // `oai_idx + 1 + offset` arithmetic, so the emitted BlockStart index stays bounded.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-ov",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "tool_calls": [{
                        "index": u64::MAX,
                        "id": "call_x",
                        "function": { "name": "f", "arguments": "{}" }
                    }]},
                    "finish_reason": null
                }]
            }),
            &mut st,
        );
        // A BlockStart is emitted with a bounded index (clamped 127 + 1, no thinking offset = 128),
        // never wrapping to a tiny value.
        let start_idx = evs
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::BlockStart { index, .. } => Some(*index),
                _ => None,
            })
            .expect("clamped tool-call still opens a block");
        assert_eq!(start_idx, (MAX_TOOL_INDEX as usize) + 1);
        // The matching argument delta routes to the same bounded index.
        let delta_idx = evs.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: IrDelta::InputJsonDelta(_),
            } => Some(*index),
            _ => None,
        });
        assert_eq!(delta_idx, Some(start_idx));
    }

    #[test]
    fn stream_tool_call_index_close_does_not_overflow_on_finish() {
        // The finish-path close loop computes the same `oai_idx + 1 + offset`; with a clamped index
        // it must close at the matching bounded IR index without panicking/wrapping.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let _ = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-c",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "tool_calls": [{
                        "index": u64::MAX,
                        "id": "call_y",
                        "function": { "name": "g", "arguments": "{}" }
                    }]},
                    "finish_reason": null
                }]
            }),
            &mut st,
        );
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-c",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
            }),
            &mut st,
        );
        let stop_idx = evs
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::BlockStop { index } => Some(*index),
                _ => None,
            })
            .expect("open tool block is closed on finish");
        assert_eq!(stop_idx, (MAX_TOOL_INDEX as usize) + 1);
    }

    // --- Round 6 fix 2 (MEDIUM/security): open_tools cardinality is capped per stream ---

    #[test]
    fn stream_open_tools_is_capped() {
        // A pathological backend emitting many unique tool-call indices must not grow `open_tools`
        // (or the BlockStart count) without bound. After feeding more than MAX_OPEN_TOOLS distinct
        // indices, the tracked set is capped and no further BlockStart events are emitted.
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let mut block_starts = 0usize;
        for i in 0..(MAX_OPEN_TOOLS as u64 + 50) {
            let evs = reader.read_response_events(
                "",
                &serde_json::json!({
                    "id": "chatcmpl-cap",
                    "created": 1_700_000_000u64,
                    "model": "gpt-4o",
                    "choices": [{
                        "index": 0,
                        "delta": { "tool_calls": [{
                            // Distinct indices, all within the clamp ceiling so the cap (not the
                            // clamp) is what limits growth here.
                            "index": i.min(MAX_TOOL_INDEX),
                            "id": format!("call_{i}"),
                            "function": { "name": "f", "arguments": "{}" }
                        }]},
                        "finish_reason": null
                    }]
                }),
                &mut st,
            );
            block_starts += evs
                .iter()
                .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
                .count();
        }
        // The set never exceeds the cap...
        assert!(st.open_tools.len() <= MAX_OPEN_TOOLS);
        // ...and the number of distinct opened blocks is bounded by the clamp ceiling (indices were
        // saturated at MAX_TOOL_INDEX, so the distinct count is MAX_TOOL_INDEX + 1 = 128 = the cap).
        assert!(block_starts <= MAX_OPEN_TOOLS);
    }

    // --- Round 8: synthetic chatcmpl id must not carry an internal field-separator hyphen.

    #[test]
    fn synth_completion_id_has_single_hyphen_after_prefix() {
        let id = synth_completion_id();
        assert!(
            id.starts_with("chatcmpl-"),
            "id must keep the native prefix: {id}"
        );
        // Native ids have exactly one hyphen (the one in `chatcmpl-`); the token after the prefix is
        // pure base62 with no internal delimiter. An extra hyphen is a structural proxy tell.
        assert_eq!(
            id.matches('-').count(),
            1,
            "synthetic id has an internal field separator: {id}"
        );
        let token = id.strip_prefix("chatcmpl-").expect("prefix present");
        assert!(!token.is_empty(), "token after prefix must be non-empty");
        assert!(
            token.chars().all(|c| c.is_ascii_alphanumeric()),
            "token must be base62 ([0-9A-Za-z]), got: {token}"
        );
    }

    #[test]
    fn synth_completion_ids_are_distinct_within_process() {
        // The monotonic atomic counter alone guarantees distinctness even when minted back-to-back
        // within the same second (where the timestamp field is identical).
        let a = synth_completion_id();
        let b = synth_completion_id();
        assert_ne!(a, b);
    }

    // --- Round 8: OpenAI tool-message content given as an array of parts must not be dropped.

    #[test]
    fn read_request_reads_array_form_tool_message_content() {
        let body = serde_json::json!({
            "model": "gpt-x",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_42",
                    "content": [
                        { "type": "text", "text": "part one " },
                        { "type": "text", "text": "part two" }
                    ]
                }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == IrRole::Tool)
            .expect("tool message present");
        let result = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                IrBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => Some((tool_use_id.clone(), content.clone())),
                _ => None,
            })
            .expect("tool result block present");
        assert_eq!(result.0, "call_42");
        // The array parts are concatenated; the prior string-only path collapsed this to "".
        assert_eq!(result.1, vec![text_block("part one part two")]);
    }

    #[test]
    fn read_request_reads_string_form_tool_message_content() {
        let body = serde_json::json!({
            "model": "gpt-x",
            "messages": [
                { "role": "tool", "tool_call_id": "call_7", "content": "plain string" }
            ]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == IrRole::Tool)
            .expect("tool message present");
        let content = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                IrBlock::ToolResult { content, .. } => Some(content.clone()),
                _ => None,
            })
            .expect("tool result block present");
        assert_eq!(content, vec![text_block("plain string")]);
    }

    // --- Round 8: a bad-key 401 must emit `code: "invalid_api_key"`, not `code: null`.

    #[test]
    fn write_error_emits_invalid_api_key_code_for_auth_failure() {
        let w = OpenAiWriter;
        let body = w.write_error(401, "authentication_error", "Incorrect API key provided");
        assert_eq!(
            body["error"]["type"],
            serde_json::json!("authentication_error")
        );
        assert_eq!(body["error"]["code"], serde_json::json!("invalid_api_key"));
        assert_eq!(body["error"]["param"], serde_json::Value::Null);
    }

    #[test]
    fn write_error_keeps_null_code_for_non_auth_errors() {
        let w = OpenAiWriter;
        for (status, kind) in [
            (400u16, "invalid_request_error"),
            (429, "rate_limit_error"),
            (500, "server_error"),
        ] {
            let body = w.write_error(status, kind, "boom");
            assert_eq!(
                body["error"]["code"],
                serde_json::Value::Null,
                "non-auth error must keep code: null (kind={kind})"
            );
        }
    }

    #[test]
    fn stream_error_auth_event_carries_invalid_api_key_code() {
        let w = OpenAiWriter;
        let ev = IrStreamEvent::Error(IrError {
            class: crate::breaker::StatusClass::Auth,
            provider_signal: Some("bad key".to_string()),
            retry_after: None,
        });
        let (_, chunk) = w
            .write_response_event(&ev)
            .expect("error event emits a body");
        assert_eq!(
            chunk["error"]["type"],
            serde_json::json!("authentication_error")
        );
        assert_eq!(chunk["error"]["code"], serde_json::json!("invalid_api_key"));
    }

    // --- Round 11: tool objects must use the nested Chat Completions shape ---

    fn req_with_tool(
        input_schema: serde_json::Value,
        description: Option<&str>,
    ) -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            system: Vec::new(),
            messages: Vec::new(),
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: description.map(String::from),
                input_schema,
            }],
            max_tokens: None,
            temperature: None,
            stream: false,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn write_request_tools_use_nested_function_shape() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"city": {"type": "string"}}
        });
        let req = req_with_tool(schema.clone(), Some("Look up the weather"));
        let out = OpenAiWriter.write_request(&req);
        let tool = &out["tools"][0];
        // Native Chat Completions shape: {"type":"function","function":{name,description,parameters}}.
        assert_eq!(tool["type"], serde_json::json!("function"));
        assert_eq!(tool["function"]["name"], serde_json::json!("get_weather"));
        assert_eq!(
            tool["function"]["description"],
            serde_json::json!("Look up the weather")
        );
        assert_eq!(tool["function"]["parameters"], schema);
        // name/parameters/description must NOT appear flat at the top level (the off-spec shape).
        assert!(tool.get("name").is_none(), "name must not be flat");
        assert!(
            tool.get("parameters").is_none(),
            "parameters must not be flat"
        );
        assert!(
            tool.get("description").is_none(),
            "description must not be flat"
        );
    }

    #[test]
    fn write_request_tool_round_trips_through_read_openai_tool() {
        // The writer's nested output must be readable by the reader (writer is the reader's inverse).
        let schema = serde_json::json!({"type": "object"});
        let req = req_with_tool(schema.clone(), Some("desc"));
        let out = OpenAiWriter.write_request(&req);
        let ir = read_openai_tool(&out["tools"][0]).expect("nested tool parses");
        assert_eq!(ir.name, "get_weather");
        assert_eq!(ir.description.as_deref(), Some("desc"));
        assert_eq!(ir.input_schema, schema);
    }

    #[test]
    fn write_request_tool_without_description_omits_it_inside_function() {
        let req = req_with_tool(serde_json::json!({"type": "object"}), None);
        let out = OpenAiWriter.write_request(&req);
        let func = &out["tools"][0]["function"];
        assert!(func.get("description").is_none());
        // parameters always present (defaults to {} when schema is null) inside `function`.
        assert!(func.get("parameters").is_some());
    }

    #[test]
    fn write_request_tool_null_schema_defaults_to_empty_object_in_function() {
        let req = req_with_tool(serde_json::Value::Null, None);
        let out = OpenAiWriter.write_request(&req);
        assert_eq!(
            out["tools"][0]["function"]["parameters"],
            serde_json::json!({})
        );
    }

    // --- Round 11: overloaded kind maps to a native OpenAI error type (503 = server_error) ---

    #[test]
    fn write_error_overloaded_maps_to_server_error() {
        // The all-lanes-exhausted / request-timeout 503 path passes kind "overloaded" to every
        // ingress writer; OpenAI has no "overloaded" type, so it must map to native server_error.
        for kind in [
            "overloaded",
            "overloaded_error",
            "service_unavailable",
            "unavailable",
            "transient",
            "timeout",
            "network",
            "5xx",
        ] {
            let v = OpenAiWriter.write_error(503, kind, "Service overloaded");
            assert_eq!(
                v["error"]["type"],
                serde_json::json!("server_error"),
                "kind={kind} must map to server_error"
            );
            // No Anthropic-vocabulary leak: the literal token must never appear as the type.
            assert_ne!(v["error"]["type"], serde_json::json!("overloaded"));
            assert_eq!(v["error"]["code"], serde_json::Value::Null);
        }
    }

    #[test]
    fn write_error_insufficient_quota_keeps_type_and_sets_code() {
        // The over-budget governance path passes "insufficient_quota"; real OpenAI sets BOTH the type
        // and the code to that value.
        let v = OpenAiWriter.write_error(429, "insufficient_quota", "quota exceeded");
        assert_eq!(v["error"]["type"], serde_json::json!("insufficient_quota"));
        assert_eq!(v["error"]["code"], serde_json::json!("insufficient_quota"));
    }

    // --- Round 11: refusal content blocks degrade gracefully instead of erroring ---

    #[test]
    fn read_openai_block_refusal_maps_to_text() {
        let block = serde_json::json!({"type": "refusal", "refusal": "I cannot help with that."});
        let ir = read_openai_block(&block).expect("refusal must not error");
        match ir {
            crate::ir::IrBlock::Text { text, .. } => {
                assert_eq!(text, "I cannot help with that.")
            }
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn read_openai_block_unknown_type_degrades_to_empty_text() {
        // A future/unknown content-part type must not break otherwise-valid history.
        let block = serde_json::json!({"type": "some_future_part", "foo": "bar"});
        let ir = read_openai_block(&block).expect("unknown type must degrade, not error");
        match ir {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, ""),
            other => panic!("expected empty Text, got {other:?}"),
        }
    }

    // --- Round 11: finish_reason normalization (content_filter -> safety, function_call -> tool_use) ---

    fn response_with_finish(finish: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "created": 1u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": finish
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        })
    }

    #[test]
    fn read_response_normalizes_content_filter_to_safety() {
        let ir = OpenAiReader
            .read_response(&response_with_finish("content_filter"))
            .expect("parses");
        assert_eq!(ir.stop_reason.as_deref(), Some("safety"));
    }

    #[test]
    fn read_response_normalizes_function_call_to_tool_use() {
        let ir = OpenAiReader
            .read_response(&response_with_finish("function_call"))
            .expect("parses");
        assert_eq!(ir.stop_reason.as_deref(), Some("tool_use"));
    }

    #[test]
    fn write_response_safety_round_trips_to_content_filter() {
        // The canonical `safety` token must serialize back to OpenAI's native `content_filter`.
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("hi")],
            stop_reason: Some("safety".to_string()),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("gpt-4o".to_string()),
            id: Some("chatcmpl-x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = OpenAiWriter.write_response(&resp);
        assert_eq!(
            out["choices"][0]["finish_reason"],
            serde_json::json!("content_filter")
        );
    }

    #[test]
    fn stream_message_delta_safety_round_trips_to_content_filter() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("safety".to_string()),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("message delta emits a chunk");
        assert_eq!(
            chunk["choices"][0]["finish_reason"],
            serde_json::json!("content_filter")
        );
    }

    #[test]
    fn stream_read_normalizes_content_filter_to_safety() {
        let chunk = serde_json::json!({
            "id": "chatcmpl-x",
            "object": "chat.completion.chunk",
            "created": 1u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "content_filter"}]
        });
        let mut state = crate::ir::StreamDecodeState::default();
        let events = OpenAiReader.read_response_events("", &chunk, &mut state);
        let stop = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => stop_reason.clone(),
            _ => None,
        });
        assert_eq!(stop.as_deref(), Some("safety"));
    }
}
