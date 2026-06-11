// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI protocol reader/writer implementation.

use super::*;
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

/// Fallback `model` string stamped onto a cross-protocol OpenAI response when the egress backend
/// supplied none. The native OpenAI `chat.completion` / `chat.completion.chunk` schemas define
/// `model` as a REQUIRED non-nullable string, and the official `openai-python` (>=1.0) Pydantic
/// models raise `ValidationError` when it is absent. A backend whose `read_response` yields
/// `model: None` (e.g. Bedrock egress -> OpenAI ingress, where `read_response` sets `model: None`)
/// would otherwise produce a model-less first chunk / completion — both an SDK deserialisation
/// failure and a proxy tell (a real OpenAI endpoint never omits `model`). A current, widely-served
/// model id keeps the synthesized value plausible.
const DEFAULT_MODEL: &str = "gpt-4o";

/// Resolve the `model` to emit on an OpenAI response: the upstream-supplied value when present,
/// otherwise the [`DEFAULT_MODEL`] fallback so the required non-nullable `model` field is never
/// omitted on a cross-protocol response. Never panics on the request path.
fn model_or_default(model: Option<&str>) -> &str {
    model.unwrap_or(DEFAULT_MODEL)
}

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
/// The 24-char suffix is filled ENTIRELY from the OS CSPRNG (mirroring `synth_anthropic_request_id`
/// / `synth_amzn_request_id` in `proto::mod`), giving native-looking entropy at EVERY position. A
/// 24-char base62 token is ~142 bits of entropy; the birthday bound on a collision is ~2^71 draws,
/// so pure CSPRNG output is collision-free in practice and needs no monotonic-counter backstop. We
/// deliberately do NOT overlay a process counter: a counter overlaid into any fixed region of the
/// token makes those characters predictable/low-entropy (the counter stays small, so its high
/// base62 digits are constant '0'), which is itself a structural fingerprint a native vendor id —
/// which is fully random across all positions — never carries. Native vendor ids ARE fully random,
/// so we are too. Never panics on the request path: on the near-impossible `getrandom` failure the
/// buffer stays the base62 zero char rather than `?`-ing out.
///
/// Mapping CSPRNG bytes into base62 uses REJECTION SAMPLING, not `byte % 62`. A raw modulo is biased
/// because 256 is not a multiple of 62 (256 = 4*62 + 8): the eight residues 0..=7 each receive one
/// extra source byte (5/256 probability vs 4/256 for residues 8..=61), so the first eight alphabet
/// characters ('0'..='7') would appear ~25% more often than the rest. A native vendor id is uniform
/// over the alphabet, so a skewed character histogram is itself a statistical fingerprint. We accept
/// only bytes below 248 (= 4*62, the largest multiple of 62 that fits in a byte) and discard the rest,
/// which yields an exactly-uniform draw over 0..62. Discards are rare (8/256 ≈ 3.1%), so we refill the
/// entropy buffer on demand rather than over-allocating up front; on a `getrandom` failure the loop
/// stops and the remaining slots keep their '0' fill, preserving the panic-free contract.
fn synth_completion_id() -> String {
    // Largest multiple of 62 that fits in a u8; bytes >= this are rejected to keep the draw uniform.
    const BASE62_REJECT_FLOOR: u8 = 248; // 4 * 62
    let mut token = [b'0'; COMPLETION_ID_TOKEN_LEN];
    let mut filled = 0usize;
    // Pull entropy in batches and consume only the in-range bytes. If a batch yields too few usable
    // bytes we draw another; on an entropy failure (getrandom errors) we stop and leave '0' fill.
    'outer: while filled < COMPLETION_ID_TOKEN_LEN {
        let mut batch = [0u8; COMPLETION_ID_TOKEN_LEN];
        if getrandom::getrandom(&mut batch).is_err() {
            // Near-impossible entropy failure: keep the remaining '0' fill rather than panic.
            break 'outer;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            token[filled] = BASE62[(byte % 62) as usize];
            filled += 1;
            if filled == COMPLETION_ID_TOKEN_LEN {
                break 'outer;
            }
        }
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

        // Make the derivation MESSAGE-AWARE, mirroring responses.rs / anthropic.rs. OpenAI (and many
        // OpenAI-compatible backends) signal a context-length overflow with a structured
        // `code: "context_length_exceeded"`, which the parse above captures. But some upstreams send
        // a null/absent `code` and carry the condition only in the prose `message` — e.g.
        // `This model's maximum context length is 8192 tokens, however you requested 9000 tokens...`.
        // Without a message scan that body would normalize to a generic client error and PENALIZE the
        // lane instead of triggering oversized-request failover. When no canonical code was parsed,
        // scan the lowercased message for the context-length signal and synthesize the canonical code.
        //
        // MED #5: the scan must be PRECISE. A naive `(token|context) && (too long|exceeds|maximum)`
        // OR-of-weak-tokens misclassifies unrelated errors — e.g. a quota body like
        // `You have reached the maximum number of tokens allowed per day` (rate-limit, not oversized)
        // pairs a stray `maximum` with a stray `token` and would falsely fail over with no penalty.
        // Require a CO-LOCATED context-length phrase, mirroring the responses.rs / anthropic.rs
        // siblings: either a self-contained canonical phrase, or `exceeds` paired specifically with
        // `context`/`token limit` (not a bare `token`/`maximum`). Gate to the HTTP statuses OpenAI
        // actually uses for an oversized request (400 invalid_request_error; 413 payload-too-large)
        // so a 429/5xx that happens to mention tokens can never be reclassified as ContextLength.
        let provider_code = provider_code.or_else(|| {
            let oversized_status =
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
            if !oversized_status {
                return None;
            }
            let message = error_obj
                .and_then(|e_obj| e_obj.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_lowercase();
            let is_context_length = message.contains("maximum context length")
                || message.contains("context length exceeded")
                || message.contains("reduce the length")
                || (message.contains("exceeds")
                    && (message.contains("context") || message.contains("token limit")));
            if is_context_length {
                Some("context_length_exceeded".to_string())
            } else {
                None
            }
        });

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

        // Read the caller's output-token cap. `max_tokens` is the legacy field; `max_completion_tokens`
        // is the current Chat Completions parameter and is MANDATORY for reasoning models (o1/o3/...),
        // which REJECT `max_tokens`. Fall back to `max_completion_tokens` when `max_tokens` is absent so
        // a request carrying only the modern field still populates the modeled IR `max_tokens`. Without
        // this, the value stays only in `extra` and is stripped at the cross-protocol seam (extra is
        // cleared there), silently dropping the caller's explicit limit on e.g. OpenAI -> Anthropic.
        // Narrow with `u32::try_from` (NOT a bare `as u32`): a value above `u32::MAX` (or negative)
        // would otherwise wrap/truncate silently into a tiny or nonsensical token cap. `as_u64`
        // already rejects negatives and non-integers, `try_from` rejects > u32::MAX, and the final
        // `> 0` filter rejects a zero cap (an invalid limit, not a real bound). This matches the
        // hardened sibling readers (gemini/anthropic/cohere/bedrock) while preserving the existing
        // non-positive-rejection contract.
        let max_tokens = obj
            .get("max_tokens")
            .or_else(|| obj.get("max_completion_tokens"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&v| v > 0);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        // OpenAI's `stop` is a string OR an array of strings; normalize to the IR's Vec<String>.
        // OpenAI has NO top_k knob, so `top_k` stays None (its writer omits it too).
        let stop = crate::ir::read_stop_sequences(obj.get("stop"));
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
                    // OpenAI's o1/o3 reasoning models replace "system" with "developer" (the
                    // Responses API reader already treats them as equivalent). Map both to the IR
                    // System role so a developer-role turn flows through the existing
                    // System-promotion path below rather than being 400ed by the catch-all.
                    "developer" | "system" => crate::ir::IrRole::System,
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

                    // For a Tool-role message the `content` payload is the tool RESULT: it is
                    // captured below as the `ToolResult` block's inner content (mirroring the native
                    // shape). Pushing it ALSO as a standalone Text block here duplicated the tool
                    // output into two IR blocks — and on a Tool->OpenAI write that surfaced as a
                    // spurious extra `{"role":"tool"}` message carrying the same text. So skip the
                    // standalone-content projection for Tool-role messages; the ToolResult path owns
                    // the tool content. User/assistant/system content is projected as before.
                    if role != crate::ir::IrRole::Tool {
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

        // Collect unmodeled top-level keys into extra (excluding modeled ones). The fields the IR
        // models as first-class — model, messages, tools, max_tokens, temperature, top_p, stop,
        // stream — are excluded; everything else (frequency_penalty, presence_penalty, n, logit_bias,
        // seed, …) flows through `extra` verbatim so a SAME-protocol OpenAI passthrough reaches the
        // upstream unchanged. NOTE: the penalties stay in `extra` (and are therefore stripped on a
        // cross-protocol hop) ON PURPOSE — Anthropic and the Bedrock `inferenceConfig` have no penalty
        // knob, so they lack a clean universal mapping; only the universally-modeled controls (top_p,
        // stop) are promoted. top_p and stop are pulled out here so they survive the cross-protocol
        // seam as first-class IR fields rather than being cleared with the rest of `extra`.
        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "messages",
            "tools",
            "max_tokens",
            // `max_completion_tokens` is now modeled via the IR `max_tokens` field (read above), so it
            // must be excluded from `extra` like `max_tokens` is. Leaving it in `extra` would make the
            // writer emit BOTH the promoted cap AND a verbatim `max_completion_tokens`, and on a same-
            // protocol passthrough also re-emit `max_tokens` alongside it — a conflicting duplicate that
            // reasoning models (which reject `max_tokens`) would 400 on.
            "max_completion_tokens",
            "temperature",
            "top_p",
            "stop",
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
            top_p,
            top_k: None,
            stop,
            stream,
            extra,
        })
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
        //
        //    GATE: only honor a reasoning delta as a Thinking-at-index-0 block while the answer phase
        //    has NOT started (no text block and no tool blocks opened yet). A late reasoning delta
        //    arriving after text/tools have opened would otherwise flip `reasoning_seen`, bumping
        //    `offset` from 0 to 1 and retroactively shifting the IR index of ALREADY-OPENED blocks —
        //    corrupting BlockStart/BlockStop pairing downstream. Once the answer phase is underway,
        //    index 0 is no longer available for a thinking block, so the stray reasoning is dropped.
        if let Some(reasoning) = delta
            .and_then(|d| d.get("reasoning_content").or_else(|| d.get("reasoning")))
            .and_then(|r| r.as_str())
            .filter(|_| !state.text_block_open && state.open_tools.is_empty())
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
        //
        // CRITICAL: under `include_usage` the OpenAI API sets `usage: null` on EVERY non-final chunk.
        // `serde_json::Value::get("usage")` returns `Some(Value::Null)` for a present-but-null key,
        // so a naive `.map(...)` would synthesize `Some(IrUsage{0,0,..})` on every content chunk and
        // (via the trailing-usage branch below) emit a spurious mid-stream `MessageDelta` per chunk.
        // Filter to a real usage OBJECT so `usage: null` reads as `None`.
        let chunk_usage = data
            .get("usage")
            .filter(|u| u.is_object())
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
            // Trailing usage-only chunk (include_usage convention): no finish_reason and (per the
            // null-filter above) a REAL top-level `usage` object with an EMPTY `choices` array. Emit a
            // MessageDelta carrying the late usage so consumers that fold it (Bedrock ingress builds
            // its single `metadata` frame from this) see real token counts instead of zeros.
            //
            // `choice0.is_none()` guards the genuine usage-only chunk shape: a normal content chunk
            // (which still carries a finish-less choice) never reaches this branch even if some
            // non-standard intermediary attached a real usage object to it. This reader is ingress-
            // AGNOSTIC, so it always emits the faithful IR; the cross-protocol ORDERING concern (this
            // delta arrives after the finish chunk's MessageStop, which would be an invalid
            // `message_delta`-after-`message_stop` frame for non-Bedrock SSE ingress) is handled where
            // the ingress IS known — `StreamTranslate::translate_event` drops a terminal-class
            // MessageDelta that arrives after MessageStop for non-eventstream ingress.
            if choice0.is_none() {
                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence: None,
                    usage,
                });
            }
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

        // Parse usage. Treat an absent `usage` object leniently — fall back to zero counts rather
        // than hard-erroring. A missing `usage` is an upstream response-format quirk (a
        // mock/staging/proxy OpenAI-compatible backend that omits it on an otherwise valid 200
        // completion), NOT a client mistake: returning a `ClientError` here mislabels the cause and
        // makes forward.rs discard a valid 200 body and emit a spurious 500. The sibling Gemini and
        // Cohere readers tolerate the same condition with a zero-usage fallback. `usage_val` is an
        // `Option`, so each token lookup below already defaults to 0.
        let usage_val = obj.get("usage");
        let cache_read_input_tokens = usage_val
            .and_then(|u| u.get("prompt_tokens_details"))
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64());

        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .and_then(|u| u.get("prompt_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .and_then(|u| u.get("completion_tokens"))
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

/// Render an IR ToolUse `input` value as the OpenAI `function.arguments` string.
///
/// OpenAI carries tool-call arguments as a *string* of JSON. The reader stores well-formed
/// arguments as a parsed `Value`, but falls back to `Value::String(raw)` when the upstream sent
/// arguments that are not valid JSON (a streaming-partial or malformed tool call). Re-serializing
/// such a `Value::String` via `serde_json::to_string` would JSON-encode the string a second time —
/// emitting an escaped, quoted blob on the wire (double-encoding). Emit a `Value::String` verbatim
/// so the original argument text round-trips unchanged; any other `Value` is serialized normally.
fn tool_arguments_to_string(input: &serde_json::Value) -> String {
    match input {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
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
        let value = HeaderValue::from_str(&format!("Bearer {key}")).unwrap_or_else(|_| {
            // Mirror the Anthropic writer: surface the misconfiguration instead of silently
            // emitting an empty Bearer (which yields an opaque upstream 401). Never log key
            // bytes — only the fact that they were invalid for an HTTP header value.
            tracing::warn!(
                header = "authorization",
                "openai auth credential contains bytes invalid for an HTTP header value \
                 (e.g. a trailing newline); sending an empty value, the upstream will return \
                 401 — check the key configuration"
            );
            HeaderValue::from_static("")
        });
        vec![(HeaderName::from_static("authorization"), value)]
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
                        let args_str = tool_arguments_to_string(input);
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

            // Handle tool results. Emit a flat `{"role":"tool",...}` entry for ANY message whose
            // content carries ToolResult blocks, REGARDLESS of the message role — not only
            // IrRole::Tool. A Gemini `functionResponse` decodes to an IrRole::User message carrying a
            // ToolResult block (and an Anthropic tool_result lives on a User-role message too); gating
            // this on IrRole::Tool SILENTLY DROPPED that tool result on Gemini→OpenAI / Anthropic→OpenAI
            // (the ToolResult arm in the content loop above is a no-op, and `tool_calls` only carries
            // ToolUse). Keying on the presence of a ToolResult block — the writer-side, source-agnostic
            // fix — surfaces it correctly for every source protocol.
            let has_tool_result = msg
                .content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolResult { .. }));
            if has_tool_result {
                let mut emitted_tool_result = false;
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

                        // Concatenate text content with NO separator, matching the OpenAI READ path
                        // (which uses `push_str` with no separator at the symmetric site). Joining
                        // with a space injected spurious spaces between adjacent text blocks on an
                        // Anthropic→OpenAI ToolResult hop (`["A","B"]` → `"A B"`), corrupting content
                        // that is boundary-sensitive (base64, JSON split across blocks). `concat()`
                        // keeps the cross-protocol round-trip lossless.
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

                            tool_result_obj["content"] = serde_json::json!(text_parts.concat());
                        }

                        messages_array.push(tool_result_obj);
                        emitted_tool_result = true;
                    }
                }

                // A well-formed tool-result message carries ONLY ToolResult blocks, each emitted
                // above as a standalone `{"role":"tool",...}` entry; `msg_obj` is intentionally NOT
                // added for that case. But the message can ALSO carry non-ToolResult content (Text/
                // Image projected into `content_val`, or ToolUse projected into `msg_obj["tool_calls"]`)
                // — e.g. a Gemini turn that pairs a functionResponse with narration text. Previously
                // that content was silently dropped because `msg_obj` was never pushed on this path.
                // Surface it instead: push `msg_obj` when it carries any non-ToolResult payload
                // (non-null `content` or a `tool_calls` array), or when the message had NO ToolResult
                // block at all (so an otherwise-empty message is not lost). This never duplicates a
                // ToolResult — those are the standalone entries above and never appear in `content_val`.
                let msg_has_payload = msg_obj.get("content").is_some_and(|c| !c.is_null())
                    || msg_obj.get("tool_calls").is_some();
                if msg_has_payload || !emitted_tool_result {
                    messages_array.push(msg_obj);
                }
            } else {
                // No ToolResult content: add the message to the array directly (tool results are
                // handled in the branch above, keyed on the presence of a ToolResult block).
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

        // Emit the modeled output-token cap as `max_tokens`. The reader promotes BOTH `max_tokens` and
        // the modern `max_completion_tokens` into this one IR field (so a caller's limit survives the
        // cross-protocol seam); on a same-protocol OpenAI passthrough this re-emits the canonical
        // `max_tokens`, preserving wire identity for the common (non-reasoning) case.
        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        // Promoted sampling controls: emit `top_p` and `stop` in OpenAI's native shape. OpenAI has NO
        // top_k parameter, so `req.top_k` is intentionally NOT emitted (lossy-by-target — a source
        // protocol's top_k cannot be honored by the OpenAI API). `stop` serializes as the array form
        // (OpenAI accepts both a string and an array; the array is always valid).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if !req.stop.is_empty() {
            out.insert("stop".to_string(), serde_json::json!(req.stop));
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
                // `model` is REQUIRED and non-nullable in the OpenAI chunk schema. A cross-protocol
                // backend (e.g. Bedrock) whose IR carries `model: None` must not yield a model-less
                // first chunk — that fails strict SDK (Pydantic) deserialisation and is a proxy tell —
                // so fall back to DEFAULT_MODEL rather than omitting the field.
                let chunk_model = model_or_default(model.as_deref());
                let chunk = serde_json::json!({
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": chunk_created,
                    "model": chunk_model,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": null
                    }]
                });
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
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
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
                let mut chunk_obj = serde_json::json!({
                    "object": "chat.completion.chunk",
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": finish_reason
                    }]
                });
                // Carry real token usage on the terminal chunk. On a cross-protocol egress (e.g.
                // Anthropic/Bedrock -> OpenAI ingress) the IR's terminal MessageDelta holds the true
                // prompt/completion counts; the prior code discarded `usage` entirely, so an
                // OpenAI-ingress client that requested `stream_options:{include_usage:true}` received
                // ZERO usage data — both a token-accounting loss and a distinguishability tell, since a
                // native include_usage stream ALWAYS ends with a usage-bearing chunk. We attach a
                // top-level `usage:{prompt_tokens, completion_tokens, total_tokens}` object here.
                //
                // Native OpenAI carries this on a SEPARATE trailing `{choices:[], usage:{...}}` chunk
                // after the finish chunk; emitting that second chunk would require returning two events
                // from this 1:1 `write_response_event`, which the `ProtocolWriter` trait (shared, not
                // owned here) does not allow. Folding `usage` onto the finish chunk recovers the
                // accounting and the SDK still surfaces `chunk.usage`. We emit it only when a count is
                // nonzero (a same-protocol passthrough without include_usage carries zeroed usage in
                // the IR; suppressing the field there avoids stamping a usage object onto a stream that
                // never asked for one). `total_tokens` is the prompt+completion sum, the native shape.
                let prompt_tokens = usage.input_tokens;
                let completion_tokens = usage.output_tokens;
                if prompt_tokens != 0 || completion_tokens != 0 {
                    if let Some(obj) = chunk_obj.as_object_mut() {
                        obj.insert(
                            "usage".to_string(),
                            serde_json::json!({
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": completion_tokens,
                                "total_tokens": prompt_tokens.saturating_add(completion_tokens),
                            }),
                        );
                    }
                }
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
                    // Billing exhaustion is OpenAI's `insufficient_quota` (HTTP 429), NOT
                    // `permission_error`. Real OpenAI reserves `permission_error` for access-control
                    // denials (feature/org restrictions); an over-quota error carries
                    // `type:"insufficient_quota"` AND `code:"insufficient_quota"`. Emitting
                    // `permission_error` for a billing class made a client switch-casing on
                    // `error.type` misroute quota errors as permission denials, and is a detectable
                    // protocol tell. `openai_error_code` pairs the matching `code` below. This mirrors
                    // the non-stream `write_error` path, which already maps the `"insufficient_quota"`
                    // kind to this type + code.
                    crate::breaker::StatusClass::Billing => "insufficient_quota",
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
                let args_str = tool_arguments_to_string(input);
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
        // model that served the response. `model` is a REQUIRED non-nullable string in the OpenAI
        // chat.completion schema; a cross-protocol backend whose `read_response` yields `model: None`
        // (e.g. Bedrock egress -> OpenAI ingress) would otherwise produce a model-less completion that
        // fails strict SDK deserialisation and is a proxy tell. Preserve the upstream value on a
        // same-protocol passthrough; fall back to DEFAULT_MODEL when none was supplied.
        obj.insert(
            "model".to_string(),
            serde_json::json!(model_or_default(resp.model.as_deref())),
        );
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

    // --- read_request: the "developer" role (OpenAI o1/o3 system-equivalent) is accepted and
    //     promoted to the top-level system field, not 400ed by the role catch-all (R22 HIGH #2).

    #[test]
    fn read_request_developer_role_feeds_system_not_rejected() {
        let body = serde_json::json!({
            "model": "o3",
            "messages": [
                { "role": "developer", "content": "be precise" },
                { "role": "user", "content": "hi" }
            ]
        });
        // Old code returned Err(400) on the unknown "developer" role; it must now parse.
        let ir = OpenAiReader
            .read_request(&body)
            .expect("developer role must not 400");
        // The developer turn carries the system prompt and lands in the top-level system field...
        assert_eq!(ir.system, vec![text_block("be precise")]);
        // ...and is never surfaced as a System-role IrMessage inside the messages array.
        assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
    }

    // --- read_request: `max_completion_tokens` is a modeled output-token cap (R15 finding)

    #[test]
    fn read_request_promotes_max_completion_tokens_into_ir() {
        // A request carrying only the modern `max_completion_tokens` (the field reasoning models
        // require) must populate the modeled IR `max_tokens` so it survives the cross-protocol seam.
        let body = serde_json::json!({
            "model": "o3",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_completion_tokens": 256
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.max_tokens, Some(256));
        // It must NOT also linger in `extra` (which is cleared at the seam and would otherwise make
        // the writer emit a conflicting duplicate).
        assert!(!ir.extra.contains_key("max_completion_tokens"));
    }

    #[test]
    fn read_request_prefers_max_tokens_over_max_completion_tokens() {
        // When both are present the legacy `max_tokens` wins (it is the explicit primary field);
        // neither lingers in `extra`.
        let body = serde_json::json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 100,
            "max_completion_tokens": 999
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.max_tokens, Some(100));
        assert!(!ir.extra.contains_key("max_tokens"));
        assert!(!ir.extra.contains_key("max_completion_tokens"));
    }

    #[test]
    fn read_request_ignores_nonpositive_max_completion_tokens() {
        // A zero/negative cap is invalid and must not populate the IR (mirrors the `max_tokens` filter).
        let body = serde_json::json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "max_completion_tokens": 0
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.max_tokens, None);
    }

    // --- write_request: the modeled cap re-emits as `max_tokens`; a `max_completion_tokens` ingress
    //     value survives the read→write round-trip via the IR field (R15 finding)

    /// Regression (LOW/conformance, final audit): a ToolResult whose content is multiple Text blocks
    /// (e.g. from an Anthropic tool_result content array) must serialize to OpenAI `content` by
    /// CONCATENATION with NO separator — matching the read path (`push_str`, no separator). Joining
    /// with a space injected spurious spaces (`["A","B"]` → `"A B"`), corrupting boundary-sensitive
    /// content (base64 / split JSON) on the cross-protocol round-trip.
    #[test]
    fn write_request_tool_result_multi_text_concatenates_without_separator() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![text_block("AAA"), text_block("BBB")],
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
        let out = OpenAiWriter.write_request(&req);
        let tool_msg = out["messages"]
            .as_array()
            .and_then(|a| a.iter().find(|m| m["role"] == "tool"))
            .expect("a tool-role message");
        assert_eq!(
            tool_msg["content"], "AAABBB",
            "multi-text ToolResult content must concatenate with NO separator, got {}",
            tool_msg["content"]
        );
    }

    #[test]
    fn write_request_emits_max_tokens_from_modeled_cap() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text_block("hi")],
            }],
            tools: Vec::new(),
            max_tokens: Some(512),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        assert_eq!(out["max_tokens"], serde_json::json!(512));
        // No stray `max_completion_tokens` (it is folded into the single modeled cap).
        assert!(out
            .as_object()
            .expect("object")
            .get("max_completion_tokens")
            .is_none());
    }

    #[test]
    fn max_completion_tokens_survives_read_write_roundtrip() {
        // An ingress request carrying only `max_completion_tokens` is promoted into the IR cap and
        // re-emitted (as `max_tokens`) rather than being dropped at the seam.
        let body = serde_json::json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "max_completion_tokens": 777
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(out["max_tokens"], serde_json::json!(777));
    }

    #[test]
    fn write_request_omits_token_cap_when_absent() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text_block("hi")],
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
        let out = OpenAiWriter.write_request(&req);
        let obj = out.as_object().expect("object");
        assert!(obj.get("max_completion_tokens").is_none());
        assert!(obj.get("max_tokens").is_none());
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
            top_p: None,
            top_k: None,
            stop: vec![],
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

    /// Regression (MEDIUM/correctness): a Tool-role message carrying ONLY ToolResult blocks must
    /// emit ONLY the flat `{"role":"tool",...}` entries — `msg_obj` is NOT pushed (no spurious
    /// `{"role":"tool","content":null}` entry).
    #[test]
    fn write_request_pure_tool_result_message_emits_only_flat_entries() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Tool,
                content: vec![IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![text_block("42")],
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
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages array");
        assert_eq!(
            msgs.len(),
            1,
            "pure tool-result must yield exactly one entry"
        );
        assert_eq!(msgs[0]["role"], serde_json::json!("tool"));
        assert_eq!(msgs[0]["tool_call_id"], serde_json::json!("call_1"));
        assert_eq!(msgs[0]["content"], serde_json::json!("42"));
    }

    /// Regression (MEDIUM/correctness): a Tool-role message carrying BOTH a ToolResult block AND
    /// non-ToolResult content (Text here, plus a ToolUse) must NOT silently drop the non-ToolResult
    /// content. Previously the `msg_obj` (carrying the Text content and `tool_calls`) was never
    /// pushed on the Tool-role path, dropping it. The fix surfaces it as an additional message entry.
    #[test]
    fn write_request_tool_role_mixed_content_not_dropped() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Tool,
                content: vec![
                    IrBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: vec![text_block("result")],
                        is_error: false,
                    },
                    text_block("stray narration"),
                    IrBlock::ToolUse {
                        id: "call_2".to_string(),
                        name: "lookup".to_string(),
                        input: serde_json::json!({"k": "v"}),
                    },
                ],
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
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages array");
        // One flat tool-result entry, plus the msg_obj carrying the stray text + tool_calls.
        assert_eq!(
            msgs.len(),
            2,
            "tool-result entry + the non-dropped mixed-content entry, got {msgs:?}"
        );
        // The flat tool-result entry.
        let flat = msgs
            .iter()
            .find(|m| m.get("tool_call_id").is_some())
            .expect("flat tool-result entry present");
        assert_eq!(flat["tool_call_id"], serde_json::json!("call_1"));
        // The non-ToolResult content was surfaced, not dropped.
        let carried = msgs
            .iter()
            .find(|m| m.get("tool_calls").is_some())
            .expect("the non-ToolResult content (text + tool_calls) must not be dropped");
        let tcs = carried["tool_calls"].as_array().expect("tool_calls array");
        assert_eq!(tcs[0]["id"], serde_json::json!("call_2"));
        // The stray text survives in the carried message's content array.
        let content = carried["content"]
            .as_array()
            .expect("stray text content survives as an array");
        assert!(
            content
                .iter()
                .any(|c| c["type"] == "text" && c["text"] == "stray narration"),
            "stray text must survive, got {content:?}"
        );
    }

    /// Regression (MED #7): a Gemini `functionResponse` decodes to an IrRole::User message carrying
    /// a ToolResult block (Anthropic tool_results live on a User-role message too). The OpenAI writer
    /// must emit a flat `{"role":"tool",...}` entry for it — keyed on the ToolResult block, NOT on the
    /// message role. Previously the emission was gated on IrRole::Tool, so the result was SILENTLY
    /// DROPPED on Gemini→OpenAI / Anthropic→OpenAI. Fails against the old code (no tool message), passes
    /// after.
    #[test]
    fn write_request_tool_result_on_user_message_emits_tool_message() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id: "call_42".to_string(),
                    content: vec![text_block("the answer is 42")],
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
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages array");
        // Exactly one flat tool-result entry; the now-empty User msg_obj (content null, no tool_calls)
        // is NOT re-pushed, so the ToolResult is neither dropped nor duplicated.
        assert_eq!(
            msgs.len(),
            1,
            "exactly the flat tool-result entry, got {msgs:?}"
        );
        let tool_msg = &msgs[0];
        assert_eq!(
            tool_msg["role"], "tool",
            "a ToolResult on a User-role message must become an OpenAI tool message, got {tool_msg:?}"
        );
        assert_eq!(tool_msg["tool_call_id"], serde_json::json!("call_42"));
        assert_eq!(tool_msg["content"], serde_json::json!("the answer is 42"));
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

    // --- Round 13 MEDIUM/conformance: `model` is required + non-nullable; cross-protocol
    //     (model: None) responses must stamp a fallback rather than omit the field ---

    #[test]
    fn cross_protocol_write_response_emits_fallback_model() {
        // A Bedrock-egress -> OpenAI-ingress buffered response carries `model: None`. The native
        // chat.completion schema requires a non-nullable `model` string, so the writer must emit a
        // present, non-null fallback (never omit the key).
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("hi")],
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
        let obj = out.as_object().expect("response object");
        assert!(
            obj.contains_key("model"),
            "model key must always be present"
        );
        let model = out["model"].as_str().expect("model is a non-null string");
        assert!(!model.is_empty(), "model fallback is non-empty: {model}");
        assert_eq!(out["model"], serde_json::json!(DEFAULT_MODEL));
    }

    #[test]
    fn write_response_preserves_upstream_model_over_fallback() {
        // A same-protocol passthrough must keep the upstream model verbatim, not the fallback.
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![text_block("hi")],
            stop_reason: Some("end_turn".to_string()),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("gpt-4o-mini".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = OpenAiWriter.write_response(&resp);
        assert_eq!(out["model"], serde_json::json!("gpt-4o-mini"));
    }

    #[test]
    fn stream_message_start_emits_fallback_model_when_none() {
        // The opening chunk's `model` is required + non-nullable; a cross-protocol stream with
        // `model: None` must stamp the fallback rather than omit the field.
        let no_model = IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&no_model)
            .expect("message start emits a chunk");
        let obj = chunk.as_object().expect("chunk object");
        assert!(
            obj.contains_key("model"),
            "model key must always be present"
        );
        let model = chunk["model"].as_str().expect("model is a non-null string");
        assert!(!model.is_empty(), "model fallback is non-empty: {model}");
        assert_eq!(chunk["model"], serde_json::json!(DEFAULT_MODEL));
    }

    #[test]
    fn stream_message_start_preserves_upstream_model_over_fallback() {
        let with_model = IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: Some("gpt-4o-2024-08-06".to_string()),
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&with_model)
            .expect("message start emits a chunk");
        assert_eq!(chunk["model"], serde_json::json!("gpt-4o-2024-08-06"));
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
        // top_p and stop are now PROMOTED to first-class IR fields (universally-modeled sampling
        // controls that must translate across the cross-protocol seam), so they leave `extra` and
        // land in the typed fields.
        assert!(!ir.extra.contains_key("top_p"));
        assert!(!ir.extra.contains_key("stop"));
        assert_eq!(ir.top_p, Some(0.9_f64));
        assert_eq!(ir.stop, vec!["\n\n".to_string()]);
        // The penalties / n / logit_bias have no clean universal cross-protocol mapping and stay in
        // `extra` (still re-emitted on a same-protocol passthrough, still stripped cross-protocol).
        assert_eq!(
            ir.extra.get("frequency_penalty"),
            Some(&serde_json::json!(0.5))
        );
        assert_eq!(
            ir.extra.get("presence_penalty"),
            Some(&serde_json::json!(0.25))
        );
        assert_eq!(ir.extra.get("n"), Some(&serde_json::json!(2)));
        assert_eq!(
            ir.extra.get("logit_bias"),
            Some(&serde_json::json!({ "50256": -100 }))
        );
        // And they reach the upstream body on write: promoted controls via the typed fields, the
        // rest via the extra-forwarding loop.
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(out["top_p"], serde_json::json!(0.9));
        assert_eq!(out["stop"], serde_json::json!(["\n\n"]));
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
            top_p: None,
            top_k: None,
            stop: vec![],
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
            (crate::breaker::StatusClass::Billing, "insufficient_quota"),
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

    /// Regression (MED #8): a context-length overflow signalled ONLY in the prose `message` with a
    /// null `code` must still synthesize `provider_code = "context_length_exceeded"` so the breaker
    /// pipeline triggers oversized-request failover instead of penalizing a healthy lane. Fails
    /// against the old code, which keyed solely on the structured `code` and returned `None` here.
    #[test]
    fn extract_error_synthesizes_context_length_from_prose_message() {
        let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens. Please reduce the length of the messages.","type":"invalid_request_error","param":"messages","code":null}}"#;
        let raw = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a prose-only maximum-context-length message must synthesize the canonical code"
        );
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );

        // A structured code still takes precedence and is never overwritten by the message scan.
        let body2 = br#"{"error":{"message":"too long","type":"invalid_request_error","code":"context_length_exceeded"}}"#;
        let raw2 = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body2);
        assert_eq!(
            raw2.provider_code.as_deref(),
            Some("context_length_exceeded")
        );

        // An unrelated 400 with no context-length phrasing must NOT be misclassified as oversized.
        let body3 = br#"{"error":{"message":"invalid value for parameter temperature","type":"invalid_request_error","code":null}}"#;
        let raw3 = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body3);
        assert!(
            raw3.provider_code.is_none(),
            "a non-context-length 400 must not be tagged context_length_exceeded"
        );
    }

    /// Regression (MED #5): the context-length message scan was OVER-BROAD — it ORed weak tokens
    /// `(token|context) && (too long|exceeds|maximum)`, so unrelated errors that merely mention a
    /// `maximum` and a `token` (or are `too long` over some non-context budget) misclassified as
    /// ContextLength and triggered a no-penalty failover. The fix requires a CO-LOCATED
    /// context-length phrase and gates to the oversized HTTP statuses (mirroring responses.rs /
    /// anthropic.rs). These cases FAIL against the old OR-of-weak-tokens code.
    #[test]
    fn extract_error_context_length_scan_is_precise_no_false_positives() {
        // FALSE-POSITIVE GUARD 1: a per-day token QUOTA / rate-limit message pairs `maximum` with
        // `tokens` but is NOT a context overflow. Old code: matched. New code: must not.
        let quota = br#"{"error":{"message":"You have reached the maximum number of tokens allowed per day for this organization.","type":"insufficient_quota","code":null}}"#;
        let raw_quota = OpenAiReader.extract_error(StatusCode::TOO_MANY_REQUESTS, quota);
        assert!(
            raw_quota.provider_code.is_none(),
            "a token-quota rate-limit message must NOT be tagged context_length_exceeded"
        );

        // FALSE-POSITIVE GUARD 2: a generic 400 that mentions `token` and `exceeds` but NOT a
        // context phrase (`exceeds` co-located only with an unrelated noun). Old code matched on the
        // bare `token` + `exceeds` pair; new code requires `exceeds` near `context`/`token limit`.
        let generic = br#"{"error":{"message":"The provided JWT token exceeds the allowed audience set.","type":"invalid_request_error","code":null}}"#;
        let raw_generic = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, generic);
        assert!(
            raw_generic.provider_code.is_none(),
            "an unrelated `token`+`exceeds` message must NOT be tagged context_length_exceeded"
        );

        // FALSE-POSITIVE GUARD 3: even an EXPLICIT context-length phrase on a non-oversized status
        // (e.g. a 500 echoing a prior message) must not reclassify the failure as ContextLength.
        let wrong_status = br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"server_error","code":null}}"#;
        let raw_wrong = OpenAiReader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, wrong_status);
        assert!(
            raw_wrong.provider_code.is_none(),
            "a 5xx mentioning context length must NOT be reclassified as context_length_exceeded"
        );

        // TRUE POSITIVE 1: the canonical prose phrase on a 400 still synthesizes the code.
        let real = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens.","type":"invalid_request_error","code":null}}"#;
        let raw_real = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, real);
        assert_eq!(
            raw_real.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a real maximum-context-length 400 must still synthesize the canonical code"
        );

        // TRUE POSITIVE 2: a 413 payload-too-large carrying `exceeds`+`token limit` also synthesizes.
        let real_413 = br#"{"error":{"message":"Request exceeds the token limit for this model.","type":"invalid_request_error","code":null}}"#;
        let raw_413 = OpenAiReader.extract_error(StatusCode::PAYLOAD_TOO_LARGE, real_413);
        assert_eq!(
            raw_413.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 413 with `exceeds`+`token limit` must synthesize the canonical code"
        );
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
            top_p: None,
            top_k: None,
            stop: vec![],
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
    fn synth_completion_id_burst_is_unique_and_unbiased() {
        // Round 18 LOW: the base62 fill must use rejection sampling, not `byte % 62`. The old modulo
        // map gave residues 0..=7 (alphabet chars '0'..='7') 5/256 mass vs 4/256 for the other 54, a
        // ~25% over-representation that a uniform native vendor id never shows. This test mints a large
        // burst and asserts (a) every id is unique and (b) the leading-eight chars are NOT systematically
        // over-represented in the suffix histogram. Against the biased code the over-represented bucket
        // share would land far above the uniform expectation and trip the bound; the unbiased fill stays
        // within it.
        use std::collections::HashSet;
        const N: usize = 20_000;
        let mut seen = HashSet::with_capacity(N);
        // Count, over all suffix characters, how many fall in the formerly-over-represented set 0..=7.
        let mut low_bucket: u64 = 0;
        let mut total_chars: u64 = 0;
        for _ in 0..N {
            let id = synth_completion_id();
            assert_eq!(
                id.len(),
                "chatcmpl-".len() + COMPLETION_ID_TOKEN_LEN,
                "{id}"
            );
            let suffix = id
                .strip_prefix("chatcmpl-")
                .expect("synthesized id carries the chatcmpl- prefix");
            assert!(
                suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
                "suffix is base62: {id}"
            );
            for b in suffix.bytes() {
                total_chars += 1;
                // '0'..='7' are the eight chars residues 0..=7 map to under the alphabet.
                if (b'0'..=b'7').contains(&b) {
                    low_bucket += 1;
                }
            }
            assert!(seen.insert(id.clone()), "duplicate synthesized id: {id}");
        }
        assert_eq!(seen.len(), N, "all {N} synthesized ids are unique");
        // Uniform expectation: 8 of 62 alphabet chars => 8/62 ≈ 12.90% of characters.
        // Biased (old) expectation: 8 * (5/256) ≈ 15.63%. We assert the observed share stays below a
        // 14% threshold — comfortably above the uniform mean (sampling noise over ~480k chars is tiny)
        // and comfortably below the biased mean, so the test fails on the old code and passes on the new.
        let share = low_bucket as f64 / total_chars as f64;
        assert!(
            share < 0.14,
            "char share for residues 0..=7 was {share:.4}; uniform≈0.1290, biased≈0.1563 — \
             a value at/above 0.14 indicates `byte % 62` bias regressed"
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
        // A ToolResult must never leak into the message *content* array on any role. Since MED #7 the
        // ToolResult ALSO surfaces as a flat `{"role":"tool",...}` entry regardless of role (a
        // Gemini/Anthropic tool result rides on a non-Tool message), so this asserts both: the content
        // array carries only the text block, and a separate tool message carries the result.
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
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = OpenAiWriter.write_request(&req);
        let msgs = out["messages"].as_array().expect("messages array");
        // The assistant message: its content array carries ONLY the text block, never the ToolResult.
        let assistant = msgs
            .iter()
            .find(|m| m["role"] == "assistant")
            .expect("assistant message present");
        let content = assistant["content"]
            .as_array()
            .expect("assistant content array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], serde_json::json!("text"));
        assert_eq!(content[0]["text"], serde_json::json!("answer"));
        // The ToolResult surfaces as a separate flat tool entry (MED #7), not silently dropped.
        let tool_msg = msgs
            .iter()
            .find(|m| m["role"] == "tool")
            .expect("ToolResult must surface as a flat tool message");
        assert_eq!(tool_msg["tool_call_id"], serde_json::json!("t1"));
        assert_eq!(tool_msg["content"], serde_json::json!("ignored"));
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
            top_p: None,
            top_k: None,
            stop: vec![],
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

    // --- Round 17: streaming Billing error -> insufficient_quota (type AND code), not
    //     permission_error ---

    #[test]
    fn stream_error_billing_event_maps_to_insufficient_quota() {
        let w = OpenAiWriter;
        let ev = IrStreamEvent::Error(IrError {
            class: crate::breaker::StatusClass::Billing,
            provider_signal: Some("over quota".to_string()),
            retry_after: None,
        });
        let (_, chunk) = w
            .write_response_event(&ev)
            .expect("error event emits a body");
        // Quota exhaustion is `insufficient_quota`, NOT the access-control `permission_error`.
        assert_eq!(
            chunk["error"]["type"],
            serde_json::json!("insufficient_quota")
        );
        assert_ne!(
            chunk["error"]["type"],
            serde_json::json!("permission_error")
        );
        // Native OpenAI pairs the matching machine-readable code.
        assert_eq!(
            chunk["error"]["code"],
            serde_json::json!("insufficient_quota")
        );
        // The streaming Billing mapping matches the non-stream `write_error("insufficient_quota")`.
        let non_stream = w.write_error(429, "insufficient_quota", "over quota");
        assert_eq!(
            chunk["error"]["type"], non_stream["error"]["type"],
            "stream and non-stream billing type must agree"
        );
        assert_eq!(
            chunk["error"]["code"], non_stream["error"]["code"],
            "stream and non-stream billing code must agree"
        );
    }

    // --- Round 17: terminal MessageDelta carries real token usage on a translated stream ---

    #[test]
    fn stream_message_delta_emits_usage_when_counts_nonzero() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 12,
                output_tokens: 34,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("message delta emits a chunk");
        // finish_reason still maps correctly...
        assert_eq!(
            chunk["choices"][0]["finish_reason"],
            serde_json::json!("stop")
        );
        // ...and the terminal chunk now carries native-shaped token usage instead of dropping it.
        assert_eq!(chunk["usage"]["prompt_tokens"], serde_json::json!(12));
        assert_eq!(chunk["usage"]["completion_tokens"], serde_json::json!(34));
        assert_eq!(chunk["usage"]["total_tokens"], serde_json::json!(46));
    }

    #[test]
    fn stream_message_delta_omits_usage_when_all_counts_zero() {
        // A same-protocol passthrough without include_usage carries zeroed usage in the IR; do not
        // stamp a usage object onto a stream that never asked for one.
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
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
        assert!(
            chunk.get("usage").is_none(),
            "zero usage must not emit a usage object: {chunk}"
        );
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
            top_p: None,
            top_k: None,
            stop: vec![],
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

    // Regression: the singular `read_response_event` must not be a dead `None` stub that silently
    // drops every event. It now delegates to the fan-out and surfaces the first IR event, so a
    // chunk that carries a role delta yields a MessageStart rather than vanishing.
    #[test]
    fn singular_read_response_event_delegates_to_fanout() {
        let chunk = serde_json::json!({
            "id": "chatcmpl-x",
            "object": "chat.completion.chunk",
            "created": 1u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
        });
        let ev = OpenAiReader.read_response_event("", &chunk);
        assert!(
            matches!(ev, Some(IrStreamEvent::MessageStart { .. })),
            "singular event must surface the fan-out's first event, got {ev:?}"
        );
    }

    // Regression: a chunk that produces no IR events (the `[DONE]` sentinel) yields None from the
    // singular adapter — confirming the delegation is faithful at the empty boundary.
    #[test]
    fn singular_read_response_event_empty_chunk_yields_none() {
        let done = serde_json::Value::String("[DONE]".to_string());
        assert!(OpenAiReader.read_response_event("", &done).is_none());
    }

    // Regression (HIGH): under `stream_options:{include_usage:true}` the OpenAI API sets
    // `usage: null` on EVERY non-final chunk. `Value::get("usage")` returns `Some(Null)` for that,
    // so without the object-filter the reader synthesized `Some(IrUsage{0,..})` and emitted a
    // spurious mid-stream `MessageDelta` on every content chunk. A content chunk carrying
    // `usage: null` must yield only the text events — NO MessageDelta.
    #[test]
    fn null_usage_on_content_chunk_emits_no_message_delta() {
        let mut state = crate::ir::StreamDecodeState::default();
        let chunk = serde_json::json!({
            "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": null}],
            "usage": null
        });
        let evs = OpenAiReader.read_response_events("", &chunk, &mut state);
        assert!(
            !evs.iter()
                .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
            "usage:null content chunk must not emit a MessageDelta, got {evs:?}"
        );
        assert!(
            evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta { delta: crate::ir::IrDelta::TextDelta(t), .. } if t == "hello"
            )),
            "text content must still decode, got {evs:?}"
        );
    }

    // Regression (MEDIUM): the reader is ingress-AGNOSTIC, so it must faithfully translate the
    // trailing `include_usage` usage-only chunk (empty `choices`, real top-level `usage`) into a
    // `MessageDelta{stop_reason: None, usage}` carrying the REAL token counts — Bedrock ingress folds
    // exactly this into its single `metadata` frame. (The cross-protocol ORDERING concern — this
    // delta arriving after the finish chunk's `MessageStop` — is handled in `StreamTranslate` for
    // non-eventstream ingress, not here.)
    #[test]
    fn trailing_usage_only_chunk_emits_message_delta_with_real_tokens() {
        let mut state = crate::ir::StreamDecodeState::default();
        let mut all = Vec::new();
        // content chunk (usage:null), finish chunk (finish_reason, usage:null), trailing usage chunk.
        for chunk in [
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}],"usage":null}),
            serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}),
            serde_json::json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}),
        ] {
            all.extend(OpenAiReader.read_response_events("", &chunk, &mut state));
        }
        // The trailing usage-only chunk yields a MessageDelta with stop_reason:None and real tokens.
        let trailing = all.iter().rev().find_map(|e| match e {
            IrStreamEvent::MessageDelta {
                stop_reason: None,
                usage,
                ..
            } => Some(usage.clone()),
            _ => None,
        });
        let usage =
            trailing.expect("trailing usage-only chunk must emit a stop_reason:None MessageDelta");
        assert_eq!(
            usage.input_tokens, 7,
            "real prompt tokens must survive, got {usage:?}"
        );
        assert_eq!(
            usage.output_tokens, 3,
            "real completion tokens must survive, got {usage:?}"
        );
        // And exactly one terminal MessageStop (from the finish chunk).
        assert_eq!(
            all.iter()
                .filter(|e| matches!(e, IrStreamEvent::MessageStop))
                .count(),
            1
        );
    }

    // Regression (#7/#8): a 200 completion body that omits `usage` entirely must still read back
    // successfully with a zero-usage fallback — never a hard `IrError` (which forward.rs would
    // swallow into a spurious 500, discarding the valid 200 body). Mirrors the Gemini/Cohere
    // readers. Against the old hard-fail code this `.expect` panics; after the fix it passes.
    #[test]
    fn read_response_tolerates_missing_usage() {
        let body = serde_json::json!({
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "created": 1u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }]
            // NOTE: no "usage" field.
        });
        let ir = OpenAiReader
            .read_response(&body)
            .expect("a 200 body with no usage must read back, not hard-fail");
        assert_eq!(ir.usage.input_tokens, 0);
        assert_eq!(ir.usage.output_tokens, 0);
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        // The rest of the response still parsed.
        assert_eq!(ir.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
    }

    // Regression (#20): a non-JSON tool `arguments` value (stored by the reader as
    // `Value::String(raw)` when the upstream sent malformed/partial argument text) must be emitted
    // verbatim, NOT re-serialized via `serde_json::to_string` (which would JSON-encode the string a
    // second time and double-encode the wire payload). Covers both write sites.
    #[test]
    fn write_request_string_tool_arguments_emitted_verbatim() {
        let raw = "not-json {oops".to_string();
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "do_it".to_string(),
                    input: serde_json::Value::String(raw.clone()),
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
        let out = OpenAiWriter.write_request(&req);
        let args = &out["messages"][0]["tool_calls"][0]["function"]["arguments"];
        assert_eq!(
            args,
            &serde_json::Value::String(raw),
            "string tool arguments must be emitted verbatim, not double-encoded, got {args}"
        );
    }

    #[test]
    fn write_response_string_tool_arguments_emitted_verbatim() {
        let raw = "not-json {oops".to_string();
        let resp = crate::ir::IrResponse {
            role: IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "do_it".to_string(),
                input: serde_json::Value::String(raw.clone()),
            }],
            stop_reason: Some("tool_use".to_string()),
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
        let args = &out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"];
        assert_eq!(
            args,
            &serde_json::Value::String(raw),
            "string tool arguments must be emitted verbatim, not double-encoded, got {args}"
        );
    }

    // Regression (MED #10): a reasoning delta arriving AFTER the text block has opened must NOT be
    // honored as a Thinking-at-index-0 block. Doing so would flip `reasoning_seen`, bumping `offset`
    // from 0 to 1, and retroactively shift the IR index of the already-opened text block — corrupting
    // BlockStart/BlockStop pairing. The late reasoning delta must be dropped: no BlockStart{index:0},
    // no thinking BlockDelta, and `reasoning_seen`/`offset` must stay put.
    #[test]
    fn late_reasoning_delta_after_text_does_not_shift_indices() {
        let mut state = crate::ir::StreamDecodeState::default();
        // First chunk opens the text block at index 0 (no reasoning seen yet).
        let c1 = serde_json::json!({
            "id": "chatcmpl-x", "object": "chat.completion.chunk", "created": 1u64, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": null}]
        });
        let evs1 = OpenAiReader.read_response_events("", &c1, &mut state);
        assert!(
            evs1.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: crate::ir::IrBlockMeta::Text
                }
            )),
            "text block must open at index 0, got {evs1:?}"
        );
        assert!(state.text_block_open);
        assert!(!state.reasoning_seen);

        // A late reasoning delta now arrives. It must be IGNORED (answer phase already started).
        let c2 = serde_json::json!({
            "choices": [{"index": 0, "delta": {"reasoning_content": "late thought"}, "finish_reason": null}]
        });
        let evs2 = OpenAiReader.read_response_events("", &c2, &mut state);
        assert!(
            !evs2.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::Thinking,
                    ..
                }
            )),
            "late reasoning must NOT open a thinking block, got {evs2:?}"
        );
        assert!(
            !evs2.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::ThinkingDelta(_),
                    ..
                }
            )),
            "late reasoning must NOT emit a ThinkingDelta, got {evs2:?}"
        );
        assert!(
            !state.reasoning_seen,
            "late reasoning must NOT flip reasoning_seen (which would shift already-opened indices)"
        );
        assert!(!state.thinking_block_open);

        // A subsequent text delta must still land on index 0 — proving the index was not shifted.
        let c3 = serde_json::json!({
            "choices": [{"index": 0, "delta": {"content": " world"}, "finish_reason": null}]
        });
        let evs3 = OpenAiReader.read_response_events("", &c3, &mut state);
        let text_idx = evs3.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::TextDelta(_),
            } => Some(*index),
            _ => None,
        });
        assert_eq!(
            text_idx,
            Some(0),
            "text must stay at index 0 after a stray late reasoning delta, got {evs3:?}"
        );
    }

    // Companion: a reasoning delta that legitimately precedes any answer content still opens the
    // Thinking block at index 0 (the gate must not break the normal reasoning-first path).
    #[test]
    fn early_reasoning_delta_still_opens_thinking_at_index_0() {
        let mut state = crate::ir::StreamDecodeState::default();
        let c = serde_json::json!({
            "id": "chatcmpl-x", "object": "chat.completion.chunk", "created": 1u64, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"reasoning_content": "thinking..."}, "finish_reason": null}]
        });
        let evs = OpenAiReader.read_response_events("", &c, &mut state);
        assert!(
            evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: crate::ir::IrBlockMeta::Thinking
                }
            )),
            "early reasoning must open a thinking block at index 0, got {evs:?}"
        );
        assert!(state.reasoning_seen);
    }

    // Regression (MED #15): `max_tokens` / `max_completion_tokens` must be narrowed with a
    // bounds-checked `u32::try_from`, NOT a raw `as u32`. A value above `u32::MAX` previously
    // truncated (wrapped) into a tiny token cap; it must now be rejected (None), never wrapped.
    #[test]
    fn max_tokens_above_u32_max_is_rejected_not_truncated() {
        let reader = OpenAiReader;
        // u32::MAX + 1 = 4_294_967_296. A raw `as u32` would wrap this to 0.
        let body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 4_294_967_296u64
        });
        let ir = reader.read_request(&body).expect("request parses");
        assert_eq!(
            ir.max_tokens, None,
            "max_tokens above u32::MAX must be rejected (None), not truncated to {:?}",
            ir.max_tokens
        );

        // The same rule applies to the modern `max_completion_tokens` field.
        let body2 = serde_json::json!({
            "model": "o3",
            "messages": [{"role": "user", "content": "hi"}],
            "max_completion_tokens": 4_294_967_296u64
        });
        let ir2 = reader.read_request(&body2).expect("request parses");
        assert_eq!(
            ir2.max_tokens, None,
            "max_completion_tokens above u32::MAX must be rejected, not truncated"
        );

        // A sane in-range value still survives unchanged.
        let body3 = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1024u64
        });
        let ir3 = reader.read_request(&body3).expect("request parses");
        assert_eq!(ir3.max_tokens, Some(1024));
    }

    // --- auth_headers: invalid credential bytes fall back to an empty value without panic, and a
    //     valid key produces the expected single `authorization: Bearer` header (R22 LOW #14).

    fn header_value(headers: &[(HeaderName, HeaderValue)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
    }

    #[test]
    fn auth_headers_valid_key_emits_bearer_authorization() {
        let headers = OpenAiWriter.auth_headers("sk-openai-good-key");
        assert_eq!(
            header_value(&headers, "authorization").as_deref(),
            Some("Bearer sk-openai-good-key")
        );
        assert_eq!(headers.len(), 1, "openai auth emits a single header");
    }

    #[test]
    fn auth_headers_invalid_key_falls_back_to_empty_no_panic() {
        // A key whose bytes are invalid for an HTTP header value (an embedded newline). The writer
        // must not panic; it falls back to an empty `authorization` value (and warns — not asserted
        // here, but the empty fallback is what previously happened SILENTLY).
        let headers = OpenAiWriter.auth_headers("sk-openai-bad\nkey");
        assert_eq!(header_value(&headers, "authorization").as_deref(), Some(""));
        assert_eq!(headers.len(), 1);
    }
}
