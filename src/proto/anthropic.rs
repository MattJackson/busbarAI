// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Anthropic protocol reader/writer implementation.

use super::*;

/// Value of the required `anthropic-version` request header (the Messages API version busbar
/// targets). Bump when adopting a newer Anthropic API version.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Mixed-case base62 alphabet (`[0-9A-Za-z]`), matching the character set of a native Anthropic id
/// token. A native `msg_`/`req_` id is `01` followed by a fixed-length mixed-case alphanumeric
/// token — NOT lowercase hex — so encoding the synthesized suffix in this alphabet (rather than
/// bare `{:x}`) removes the alphabet/length/version-prefix distinguishability tell.
const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Width of a synthesized Anthropic id's token (the part after the `01` version marker): a native
/// `msg_`/`req_` id is `<prefix>01` followed by a fixed-width 24-char mixed-case base62 token, so
/// `msg_`/`req_` + `01` + 24 = 30 chars total. Matching this exact length AND alphabet is what keeps
/// the synthesized id structurally indistinguishable from a native one.
const SYNTH_ID_TOKEN_LEN: usize = 24;

/// Mint a protocol-correct Anthropic message id for the cross-protocol path, where the backend
/// supplied none. A native id is `msg_01` + a fixed-length mixed-case base62 token; an official
/// Anthropic SDK only requires the `msg_` prefix and a non-empty unique suffix (it does not parse
/// the body), but matching the native alphabet/version-prefix/length AND drawing the token from the
/// OS CSPRNG removes the structural/entropy tell a client could use to spot a synthesized id.
fn synth_message_id() -> String {
    synth_id_with_prefix("msg_")
}

/// Mint a protocol-correct Anthropic request id (`req_01<token>`) for the top level of an error
/// envelope, where busbar synthesizes the error itself and has no upstream request id to forward.
/// Current Anthropic API error responses carry a top-level `request_id`; emitting one whose shape
/// (version prefix, mixed-case base62 alphabet, fixed length) AND entropy match the native form
/// keeps the envelope indistinguishable. Same CSPRNG construction as `synth_message_id`.
fn synth_request_id() -> String {
    synth_id_with_prefix("req_")
}

/// Shared id construction for both `msg_` and `req_`. The suffix is the native `01` version marker
/// followed by a fixed-width 24-char mixed-case base62 token drawn ENTIRELY from the OS CSPRNG
/// (mirroring `proto::mod::synth_anthropic_request_id` and `openai::synth_completion_id`). The
/// earlier `(unix_second, counter)` encoding was a deterministic clock+counter fingerprint, and even
/// a counter overlaid into a fixed region of an otherwise-random token leaves those characters
/// predictable/low-entropy (the counter stays small, so its high base62 digits are constant '0') —
/// a structural tell at WHATEVER position (leading or trailing) it occupies. We therefore overlay NO
/// counter at all: a 24-char base62 token is ~142 bits of entropy with a ~2^71 birthday bound, so
/// pure CSPRNG output is collision-free in practice and every position stays fully random, exactly
/// like a native Anthropic id. Never panics on the request path.
fn synth_id_with_prefix(prefix: &str) -> String {
    // Fill the entire token with CSPRNG bytes mapped into base62 via REJECTION SAMPLING. A bare
    // `byte % 62` is biased: 256 = 4*62 + 8, so the residues 0..7 are drawn from 5 source bytes and
    // 8..61 from only 4 — over-representing the low characters by ~25%, a statistical fingerprint
    // that distinguishes a synthesized id from a native (uniform) one. We therefore reject any byte
    // >= 248 (the largest multiple of 62 that fits in a u8) and consume only the in-range bytes,
    // mirroring `openai::synth_completion_id` and `proto::mod::synth_anthropic_request_id`. On an
    // entropy failure we leave the remaining '0' fill rather than panic; there is no counter overlay.
    const BASE62_REJECT_FLOOR: u8 = 248; // 4 * 62
    let mut token = [b'0'; SYNTH_ID_TOKEN_LEN];
    let mut filled = 0usize;
    'outer: while filled < SYNTH_ID_TOKEN_LEN {
        let mut batch = [0u8; SYNTH_ID_TOKEN_LEN];
        if getrandom::getrandom(&mut batch).is_err() {
            // Near-impossible entropy failure: keep the remaining '0' fill rather than panic.
            break 'outer;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            token[filled] = BASE62_ALPHABET[(byte % 62) as usize];
            filled += 1;
            if filled == SYNTH_ID_TOKEN_LEN {
                break 'outer;
            }
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards
    // against an impossible non-ASCII byte and keeps the path panic-free.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("{prefix}01{token}")
}

#[derive(Clone)]
pub(crate) struct AnthropicReader;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body once and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (error paths are already degraded; avoid the extra
        // parse+alloc on every non-2xx response).
        let (provider_code, structured_type) =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(json) => {
                    let error = json.get("error");
                    let provider_code = error
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_str())
                        .map(String::from);
                    let structured_type = error
                        .and_then(|e| e.get("type"))
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    (provider_code, structured_type)
                }
                Err(_) => (None, None),
            };

        // Anthropic signals context-length via the error MESSAGE (no distinct code).
        // Surface the canonical code so the breaker pipeline (normalize_raw_error) → ContextLength.
        let provider_code = provider_code.or_else(|| {
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("prompt is too long")
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
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
        let text = String::from_utf8_lossy(body);

        // context-length-exceeded (Anthropic returns 400 invalid_request_error). The lane
        // is healthy; this must fail over (to a larger-context model), not penalize the breaker.
        // Check before the generic 400/client-error path so it wins.
        let lower = text.to_lowercase();
        if lower.contains("prompt is too long")
            || (lower.contains("exceeds the maximum")
                && (lower.contains("token") || lower.contains("context")))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length".to_string()),
                retry_after: None,
            };
        }

        // Prefer the HTTP status, then structured error codes, then substrings as a fallback.
        // Parse the JSON once and examine `error.code` and `error.message` INDEPENDENTLY: the
        // message-substring billing/auth checks must fire even when the structured `code` field is
        // absent (some Anthropic error shapes carry a 200/non-401-403 body with only a message), so
        // they live OUTSIDE the `if let Some(code_val)` guard rather than nested inside it.
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            let error = json.get("error");

            if let Some(code_val) = error.and_then(|e| e.get("code")) {
                if code_val.as_str() == Some("400") || code_val.as_str() == Some("422") {
                    return CanonicalSignal {
                        class: StatusClass::ClientError,
                        provider_signal: Some("client_error".to_string()),
                        retry_after: None,
                    };
                }
            }

            // Message-substring billing/auth detection — independent of `error.code` presence.
            if let Some(msg_str) = error
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
            {
                if msg_str.contains("nsufficient balance") {
                    return CanonicalSignal {
                        class: StatusClass::Billing,
                        provider_signal: Some("billing".to_string()),
                        retry_after: None,
                    };
                }
                if msg_str.contains("unauthorized") || msg_str.contains("invalid token") {
                    return CanonicalSignal {
                        class: StatusClass::Auth,
                        provider_signal: Some("auth".to_string()),
                        retry_after: None,
                    };
                }
            }
        }

        if status.as_u16() == 401 || status.as_u16() == 403 {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: None,
                retry_after: None,
            };
        }

        if status.as_u16() == 429 {
            // Reuse the single lower-cased copy computed at the top of `classify` rather than
            // allocating a second one — on a verbose 429 body this avoids a redundant heap copy.
            if lower.contains("quota") && lower.contains("exhausted") {
                return CanonicalSignal {
                    class: StatusClass::Billing,
                    provider_signal: Some("429-quota-exhausted".to_string()),
                    retry_after: None,
                };
            }
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429-slowdown".to_string()),
                retry_after: None,
            };
        }

        if status.as_u16() >= 500 {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: None,
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        }
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        // Handle system field (string or array)
        if let Some(system_val) = obj.get("system") {
            if system_val.is_string() {
                let text = system_val.as_str().unwrap_or("").to_string();
                system_blocks.push(crate::ir::IrBlock::Text {
                    text,
                    cache_control: None,
                    citations: Vec::new(),
                });
            } else if let Some(arr) = system_val.as_array() {
                for block_val in arr {
                    system_blocks.push(read_block(block_val)?);
                }
            }
        }

        // Handle messages array. Anthropic's Messages API has NO `system` role inside `messages` —
        // system instructions live in the top-level `system` field. A cross-protocol IR, however, can
        // carry an `IrRole::System` message (e.g. translated from an OpenAI `system` message), and a
        // wire body could nominally present a `role:"system"` message too. PROMOTE any such message
        // into `system_blocks` here at the root rather than pushing it into `req.messages`, so the
        // writer never sees an `IrRole::System` message and can never emit the INVALID Anthropic
        // `role:"system"` (which upstream rejects with a 400). System blocks are appended in order,
        // preserving their position relative to any top-level `system` field already read above.
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            for msg_val in messages_val.as_array().unwrap_or(&Vec::new()) {
                let msg = read_message(msg_val)?;
                if msg.role == crate::ir::IrRole::System {
                    system_blocks.extend(msg.content);
                } else {
                    messages.push(msg);
                }
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_tool(tool_val)?);
            }
        }

        // Extract scalar fields and extra
        // Checked `u32::try_from` rather than a raw `as u32`: a `max_tokens`/`top_k` larger than
        // `u32::MAX` would silently TRUNCATE under `as` (e.g. 4294967297 → 1), forwarding a wildly
        // wrong cap upstream. An out-of-range value drops to `None` here, matching the sibling
        // readers; the upstream then applies its own default rather than receiving a corrupted limit.
        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        let top_k = obj
            .get("top_k")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Anthropic's native `stop_sequences` is an array of strings.
        let stop = crate::ir::read_stop_sequences(obj.get("stop_sequences"));
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect unmodeled top-level keys into `extra`. The set of modeled keys is a static,
        // never-changing list of `&'static str` literals, so it lives as a compile-time SORTED slice
        // and membership is an O(log n) `binary_search` — zero allocation, zero hashing, on every
        // inbound request (the previous per-call `HashSet` allocated + hashed up to 10 entries and
        // dropped the set immediately, pure churn on the hot ingress path). Kept sorted by hand;
        // `debug_assert` below pins that invariant so a future edit that breaks ordering fails tests.
        const MODELED_KEYS: &[&str] = &[
            "max_tokens",
            "messages",
            "model",
            "stop_sequences",
            "stream",
            "system",
            "temperature",
            "tools",
            "top_k",
            "top_p",
        ];
        debug_assert!(
            MODELED_KEYS.windows(2).all(|w| w[0] < w[1]),
            "MODELED_KEYS must stay sorted for binary_search"
        );

        for (key, value) in obj.iter() {
            if MODELED_KEYS.binary_search(&key.as_str()).is_err() {
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
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        match event_type {
            "message_start" => {
                let msg = data.get("message")?;
                let role_str = msg.get("role").and_then(|r| r.as_str())?;
                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => return None,
                };
                let usage = data
                    .get("message")
                    .and_then(|m| m.get("usage"))
                    .map(|u| IrUsage {
                        input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        cache_creation_input_tokens: u
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64()),
                        cache_read_input_tokens: u
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64()),
                    });
                // Capture the stream's native identity so an anthropic→anthropic passthrough
                // re-emits the exact `message_start.message` an SDK expects (it reads
                // `message.id`/`message.model` to populate the assembled `Message`). Anthropic's
                // `message_start` has no `created` field, so `created` stays None on this path; the
                // writer synthesizes one only when translating from a protocol that omitted it.
                let id = msg.get("id").and_then(|i| i.as_str()).map(String::from);
                // Empty `model` maps to `None`: the writer emits `model: ""` as the mandatory-field
                // fallback when no source model exists, so reading it back as `None` keeps the
                // stream-event round-trip idempotent (a real model id is never empty).
                let model = msg
                    .get("model")
                    .and_then(|m| m.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                Some(IrStreamEvent::MessageStart {
                    role,
                    usage,
                    id,
                    created: None,
                    model,
                })
            }
            "content_block_start" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                let block = data.get("content_block")?;
                let block_type = block.get("type").and_then(|t| t.as_str())?;
                let meta = match block_type {
                    "text" => IrBlockMeta::Text,
                    "thinking" => IrBlockMeta::Thinking,
                    "tool_use" => {
                        let id = block.get("id").and_then(|i| i.as_str()).map(String::from)?;
                        let name = block
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(String::from)?;
                        IrBlockMeta::ToolUse { id, name }
                    }
                    "image" => IrBlockMeta::Image,
                    _ => return None,
                };
                Some(IrStreamEvent::BlockStart { index, block: meta })
            }
            "content_block_delta" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                let delta_val = data.get("delta")?;
                let delta_type = delta_val.get("type").and_then(|t| t.as_str())?;
                let delta = match delta_type {
                    "text_delta" => {
                        let text = delta_val
                            .get("text")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::TextDelta(text)
                    }
                    "thinking_delta" => {
                        let thinking = delta_val
                            .get("thinking")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::ThinkingDelta(thinking)
                    }
                    "input_json_delta" => {
                        let json = delta_val
                            .get("partial_json")
                            .or_else(|| delta_val.get("input_json"))
                            .and_then(|j| j.as_str())
                            .map(String::from)?;
                        IrDelta::InputJsonDelta(json)
                    }
                    "signature_delta" => {
                        let signature = delta_val
                            .get("signature")
                            .and_then(|s| s.as_str())
                            .map(String::from)?;
                        IrDelta::SignatureDelta(signature)
                    }
                    _ => return None,
                };
                Some(IrStreamEvent::BlockDelta { index, delta })
            }
            "content_block_stop" => {
                let index = data
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map(|v| v as usize)?;
                Some(IrStreamEvent::BlockStop { index })
            }
            "message_delta" => {
                let delta = data.get("delta")?;
                let stop_reason = delta
                    .get("stop_reason")
                    .and_then(|r| r.as_str())
                    .map(String::from);
                // `message_delta.delta.stop_sequence` — the matched stop string, present (as a
                // string) only when a stop sequence actually triggered the stop, `null`/absent
                // otherwise. Carry it through so the same-protocol writer can re-emit it.
                let stop_sequence = delta
                    .get("stop_sequence")
                    .and_then(|s| s.as_str())
                    .map(String::from);
                // `usage` is OPTIONAL on read here: do NOT `?` it. `message_delta` is the terminal
                // event that carries `stop_reason`/`stop_sequence`, so propagating `None` out of this
                // closure when `usage` is absent would silently DROP the whole event — the client then
                // never sees the stop reason and cannot tell whether generation completed. A native
                // Anthropic stream always includes `usage`, but an Anthropic-compatible backend that
                // doesn't implement usage counting (or makes it conditional) may omit it; preserve the
                // event regardless by zero-defaulting the counters when `usage` is missing. This mirrors
                // the `message_start` reader above, which already maps a missing `usage` to defaults
                // rather than bailing.
                let usage_val = data.get("usage");
                let usage = IrUsage {
                    input_tokens: usage_val
                        .and_then(|u| u.get("input_tokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    output_tokens: usage_val
                        .and_then(|u| u.get("output_tokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens: usage_val
                        .and_then(|u| u.get("cache_creation_input_tokens"))
                        .and_then(|v| v.as_u64()),
                    cache_read_input_tokens: usage_val
                        .and_then(|u| u.get("cache_read_input_tokens"))
                        .and_then(|v| v.as_u64()),
                };
                Some(IrStreamEvent::MessageDelta {
                    stop_reason,
                    stop_sequence,
                    usage,
                })
            }
            "message_stop" => Some(IrStreamEvent::MessageStop),
            "error" => {
                let err_val = data.get("error")?;
                // Carry the upstream error `type` through as-is: `Some("rate_limit_error")` when
                // present, `None` when the event omits it. Do NOT `unwrap_or_default()` into
                // `Some("")` — an empty-string type would make the writer emit `"type": ""` where a
                // native Anthropic error event carries either a real type or `null`. The writer
                // (write_response_event) already renders `None` as JSON `null`, so the absence
                // round-trips faithfully.
                let type_token = err_val.get("type").and_then(|t| t.as_str());
                let provider_signal = type_token.map(String::from);
                // Derive the breaker class from the upstream error `type`, mirroring the HTTP
                // classifier intent (see `classify`/`write_error`'s Anthropic error vocabulary)
                // instead of hardcoding ClientError. A mid-stream `overloaded_error`/
                // `rate_limit_error`/`api_error` is a TRANSIENT upstream fault, not a client fault —
                // hardcoding ClientError mapped every one of them to Disposition::ClientFault, so the
                // breaker never recorded the transient/hard-down signal and took the wrong transition.
                let class = stream_error_class(type_token);
                Some(IrStreamEvent::Error(IrError {
                    class,
                    provider_signal,
                    retry_after: None,
                }))
            }
            _ => None,
        }
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        _state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        // Anthropic events are already block-structured (1:1): wrap the singular, ignore state.
        match self.read_response_event(event_type, data) {
            Some(ev) => vec![ev],
            None => vec![],
        }
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        // Parse role (should be "assistant" for responses)
        let role_str = obj.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let role = match role_str {
            "assistant" => crate::ir::IrRole::Assistant,
            _ => {
                return Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some("ir_parse".into()),
                    retry_after: None,
                })
            }
        };

        // Parse content blocks
        let content_val = obj.get("content").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(arr) = content_val.as_array() {
            for block_val in arr {
                content.push(read_block(block_val)?);
            }
        }

        // Parse stop_reason (optional)
        let stop_reason = obj
            .get("stop_reason")
            .and_then(|r| r.as_str())
            .map(String::from);

        // Parse usage. `usage` is OPTIONAL on read here: do NOT `ok_or?` it. A native Anthropic
        // non-streaming `Message` always carries `usage`, but an Anthropic-compatible backend that
        // doesn't implement usage counting (or makes it conditional) may omit it — hard-requiring the
        // field turned an otherwise-valid 200 body into a 400, inconsistent with this protocol's own
        // streaming readers (`message_start`/`message_delta` above already zero-default a missing
        // `usage` rather than bailing) and with the gemini/cohere reader tolerance. When `usage` is
        // absent each counter defaults to zero (`Some` → parse, `None` → 0).
        let usage_val = obj.get("usage");
        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: usage_val
                .and_then(|u| u.get("cache_creation_input_tokens"))
                .and_then(|v| v.as_u64()),
            cache_read_input_tokens: usage_val
                .and_then(|u| u.get("cache_read_input_tokens"))
                .and_then(|v| v.as_u64()),
        };

        // Treat an empty `model` string as absent (`None`). The writer emits `model: ""` as the
        // mandatory-field fallback when the source carried no model (see `write_response`); mapping
        // that empty string back to `None` keeps a write→read round-trip IR-idempotent and never
        // mistakes the placeholder for a real model identifier (a genuine model id is never empty).
        let model = obj
            .get("model")
            .and_then(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        // Capture the native response identity so a same-protocol (anthropic→anthropic) passthrough
        // preserves it byte-for-byte. An official SDK's `Message` carries `id` ("msg_<rand>"),
        // `type` ("message"), `role`, `model`, `stop_reason`, `stop_sequence`, and `usage`; the
        // first four plus `stop_sequence` round-trip through these IR fields (role/model/stop_reason
        // are already parsed above; `type` is a constant the writer re-emits).
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        // Anthropic's non-streaming `Message` has no `created` field, so there is nothing to carry
        // through; the writer synthesizes one only on the cross-protocol path (where the IR field is
        // None) for SDKs that read it. `system_fingerprint` is an OpenAI concept Anthropic never
        // emits — left None so a same-protocol round-trip does not invent one.
        let stop_sequence = obj
            .get("stop_sequence")
            .and_then(|s| s.as_str())
            .map(String::from);

        Ok(crate::ir::IrResponse {
            role,
            content,
            stop_reason,
            usage,
            model,
            id,
            created: None,
            system_fingerprint: None,
            stop_sequence,
        })
    }
}

/// Map an Anthropic streaming `error.type` token to its breaker `StatusClass`, mirroring the HTTP
/// classifier intent (`AnthropicReader::classify`) and the `write_error` error vocabulary so a
/// mid-stream error drives the SAME breaker transition an equivalent non-stream HTTP error would.
///
/// Native Anthropic error types and their canonical class (see the Anthropic Messages API error
/// shape — `overloaded_error` is the 529 overload signal, `rate_limit_error` the 429):
///   - `overloaded_error`      → Overloaded   (transient — upstream is shedding load)
///   - `rate_limit_error`      → RateLimit    (transient — back off / retry-after)
///   - `api_error`             → ServerError  (transient — upstream 5xx-family fault)
///   - `timeout_error`         → Timeout      (transient — upstream timed out)
///   - `authentication_error`  → Auth         (hard down — credential invalid)
///   - `permission_error`      → Auth         (hard down — 403-family, key lacks access)
///   - `billing_error`         → Billing      (hard down — account/balance issue)
///   - `invalid_request_error` → ClientError  (caller fault — do NOT penalize the lane)
///   - `not_found_error`       → ClientError
///   - `request_too_large`     → ClientError
///
/// An ABSENT type (`None`) or an unrecognized token falls back to `ClientError`: it is the
/// conservative non-penalizing disposition (ClientFault records nothing), so an unknown mid-stream
/// error can never wrongly trip or hard-down a healthy lane. The fallback is a NAMED arm, not a
/// `_ =>` swallow, so a future Anthropic error type surfaces as an explicit unmapped case here.
fn stream_error_class(error_type: Option<&str>) -> StatusClass {
    match error_type {
        Some("overloaded_error") => StatusClass::Overloaded,
        Some("rate_limit_error") => StatusClass::RateLimit,
        Some("api_error") => StatusClass::ServerError,
        Some("timeout_error") => StatusClass::Timeout,
        Some("authentication_error") | Some("permission_error") => StatusClass::Auth,
        Some("billing_error") => StatusClass::Billing,
        Some("invalid_request_error")
        | Some("not_found_error")
        | Some("request_too_large")
        | None => StatusClass::ClientError,
        Some(_unrecognized) => StatusClass::ClientError,
    }
}

// Helper functions for IR mapping (used by read_request/write_request)
fn read_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "text" => {
            let text = obj
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Parse cache_control - object form: {"type": "ephemeral"}
            let cache_control = if let Some(cc_val) = obj.get("cache_control") {
                if let Some(cc_obj) = cc_val.as_object() {
                    if let Some(cc_type) = cc_obj.get("type").and_then(|t| t.as_str()) {
                        if cc_type == "ephemeral" {
                            Some(crate::ir::CacheControl {
                                kind: crate::ir::CacheKind::Ephemeral,
                            })
                        } else {
                            return Err(IrError {
                                class: StatusClass::ClientError,
                                provider_signal: Some("ir_parse".to_string()),
                                retry_after: None,
                            });
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let citations = obj
                .get("citations")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control,
                citations,
            })
        }
        "thinking" => {
            let text = obj
                .get("thinking")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let signature = obj
                .get("signature")
                .and_then(|v| v.as_str().map(String::from));
            Ok(crate::ir::IrBlock::Thinking { text, signature })
        }
        "tool_use" => {
            let id = obj
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let input = obj.get("input").cloned().unwrap_or(serde_json::Value::Null);
            Ok(crate::ir::IrBlock::ToolUse { id, name, input })
        }
        "tool_result" => {
            let tool_use_id = obj
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_val = obj.get("content").unwrap_or(&serde_json::Value::Null);
            let content = if let Some(arr) = content_val.as_array() {
                arr.iter().map(read_block).collect::<Result<_, _>>()?
            } else {
                vec![crate::ir::IrBlock::Text {
                    text: content_val.as_str().unwrap_or("").to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }]
            };
            let is_error = obj
                .get("is_error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            })
        }
        "image" => {
            let source = obj.get("source").ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })?;
            if let Some(src_obj) = source.as_object() {
                // Anthropic's Messages API has TWO native image source shapes:
                //   - `{"type":"url","url":<url>}`           — a remote image reference
                //   - `{"type":"base64","media_type":...,"data":<b64>}` — inline bytes
                // The base64 path below extracts `media_type`/`data`, which are BOTH absent from a
                // url source — so a url image would otherwise flatten to empty base64 (cross-protocol
                // image data LOSS). Round-trip the url through the same `media_type:"image_url"`
                // sentinel the writer recognizes (see `write_block`'s Image arm): the raw url lives in
                // `data`, and `write_block` re-emits exactly `{"type":"url","url":<url>}` for it.
                if src_obj.get("type").and_then(|v| v.as_str()) == Some("url") {
                    let url = src_obj
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(crate::ir::IrBlock::Image {
                        media_type: "image_url".to_string(),
                        data: url,
                    });
                }
                let media_type = src_obj
                    .get("media_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let data = src_obj
                    .get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(crate::ir::IrBlock::Image { media_type, data })
            } else {
                Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some("ir_parse".to_string()),
                    retry_after: None,
                })
            }
        }
        // Forward-compatibility: a valid native Anthropic content-block type the IR does not model
        // (e.g. `document`, `redacted_thinking`, or a future type Anthropic adds after this build).
        // These appear in legitimate Messages API requests, so the prior `_ => Err(ClientError)`
        // catch-all turned an otherwise-valid request into a 400. Mirror the OpenAI reader's
        // unmodeled-part handling (see `read_openai_block`): degrade gracefully to an empty Text
        // block — preserving the block's position in the turn without injecting foreign data —
        // rather than failing the whole request. This is a content-shape match, not a
        // disposition/breaker match, so a NAMED graceful-degradation arm (binding `other`) is
        // correct here, and there is no `_ =>` swallowing a real disposition.
        other => {
            tracing::warn!(
                block_type = other,
                "skipping unmodeled anthropic content-block type during ir parse; degrading to an \
                 empty text block rather than 400ing a legitimate request"
            );
            Ok(crate::ir::IrBlock::Text {
                text: String::new(),
                cache_control: None,
                citations: Vec::new(),
            })
        }
    }
}

fn read_message(msg_val: &serde_json::Value) -> Result<crate::ir::IrMessage, IrError> {
    let obj = msg_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let role_str = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
    let role = match role_str {
        "user" => crate::ir::IrRole::User,
        "assistant" => crate::ir::IrRole::Assistant,
        "system" => crate::ir::IrRole::System,
        _ => {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            })
        }
    };

    let content_val = obj.get("content").unwrap_or(&serde_json::Value::Null);
    let content = if let Some(arr) = content_val.as_array() {
        arr.iter().map(read_block).collect::<Result<_, _>>()?
    } else {
        vec![crate::ir::IrBlock::Text {
            text: content_val.as_str().unwrap_or("").to_string(),
            cache_control: None,
            citations: Vec::new(),
        }]
    };

    Ok(crate::ir::IrMessage { role, content })
}

fn read_tool(tool_val: &serde_json::Value) -> Result<crate::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = obj
        .get("description")
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = obj
        .get("input_schema")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(crate::ir::IrTool {
        name,
        description,
        input_schema,
    })
}

fn write_block(block: &crate::ir::IrBlock) -> serde_json::Value {
    match block {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            citations,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("text"));
            obj.insert("text".to_string(), serde_json::json!(text));
            if let Some(cc) = cache_control {
                let cc_val = match cc.kind {
                    crate::ir::CacheKind::Ephemeral => serde_json::json!({"type": "ephemeral"}),
                };
                obj.insert("cache_control".to_string(), cc_val);
            }
            if !citations.is_empty() {
                obj.insert(
                    "citations".to_string(),
                    serde_json::Value::Array(citations.clone()),
                );
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Thinking { text, signature } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("thinking"));
            obj.insert("thinking".to_string(), serde_json::json!(text));
            if let Some(sig) = signature {
                obj.insert("signature".to_string(), serde_json::json!(sig));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolUse { id, name, input } => {
            serde_json::json!({ "type": "tool_use", "id": id, "name": name, "input": input })
        }
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("tool_result"));
            obj.insert("tool_use_id".to_string(), serde_json::json!(tool_use_id));
            if content.is_empty() {
                obj.insert("content".to_string(), serde_json::json!(""));
            } else {
                obj.insert(
                    "content".to_string(),
                    serde_json::Value::Array(content.iter().map(write_block).collect()),
                );
            }
            if *is_error {
                obj.insert("is_error".to_string(), serde_json::Value::Bool(true));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Image { media_type, data } => {
            // The OpenAI and Responses readers record an https:// image reference with the
            // "image_url" media_type sentinel (the raw URL lives in `data`, not base64 bytes).
            // Anthropic's Messages API has a native URL image source — emit it as
            // `{"type":"url","url":<url>}` rather than wrapping the URL in a base64 source with
            // `media_type:"image_url"`, which Anthropic rejects with a 400. A genuine base64 image
            // (any real `image/*` media_type) still takes the base64 source path below.
            if media_type == "image_url" {
                serde_json::json!({ "type": "image", "source": { "type": "url", "url": data } })
            } else {
                serde_json::json!({ "type": "image", "source": { "type": "base64", "media_type": media_type, "data": data } })
            }
        }
    }
}

fn write_message(msg: &crate::ir::IrMessage) -> serde_json::Value {
    let role_str = match msg.role {
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        // Anthropic's Messages API has NO `system` role inside `messages` — system content lives in
        // the top-level `system` field. `write_request` folds every `IrRole::System` message into
        // that top-level array and FILTERS it out of the per-message loop, so this arm is unreachable
        // on the request path. Map it to `"user"` defensively (NOT the invalid `"system"`) so that
        // even a direct `write_message` call can never emit a `role:"system"` Anthropic rejects.
        crate::ir::IrRole::System => "user",
        // Anthropic has no "tool" message role — tool results are carried as `user` messages whose
        // content holds `tool_result` block(s). (Reachable when translating an OpenAI `tool` message.)
        crate::ir::IrRole::Tool => "user",
    };
    // REQUEST-side filter (write_message feeds write_request only; write_response/_event call
    // write_block directly, so response reasoning still surfaces). Anthropic's Messages API rejects
    // an assistant `thinking` block that lacks a `signature` with a 400 — a signature is mandatory
    // on the request path. A cross-protocol IR may carry a Thinking block whose signature is None
    // (e.g. reasoning translated from a provider that emits no signature), so drop those blocks here
    // rather than forward an egress that the upstream will 400. Other block types pass through.
    let mut dropped_unsigned_thinking = 0usize;
    let blocks: Vec<&crate::ir::IrBlock> = msg
        .content
        .iter()
        .filter(|block| {
            if let crate::ir::IrBlock::Thinking {
                signature: None, ..
            } = block
            {
                dropped_unsigned_thinking += 1;
                false
            } else {
                true
            }
        })
        .collect();
    if dropped_unsigned_thinking > 0 {
        tracing::warn!(
            dropped = dropped_unsigned_thinking,
            "dropped assistant thinking block(s) with no signature from anthropic request egress \
             (anthropic rejects unsigned thinking blocks with a 400)"
        );
    }
    // When no blocks survive (e.g. an all-thinking assistant message whose unsigned thinking blocks
    // were all dropped above), emit an EMPTY ARRAY `[]`, not an empty STRING `""`. Anthropic's
    // Messages API rejects a message whose top-level `content` is the empty string with a 400
    // ("text content blocks must be non-empty" / "content: field required"), whereas an empty array
    // is a well-formed message with zero content blocks that the API accepts. This matches the
    // empty-array skeleton `write_response_event` already emits for `message_start.message.content`
    // (a message with no blocks yet). The non-empty branch is unchanged: a populated array of blocks.
    let content_val: serde_json::Value =
        serde_json::Value::Array(blocks.into_iter().map(write_block).collect());
    serde_json::json!({ "role": role_str, "content": content_val })
}

fn write_tool(tool: &crate::ir::IrTool) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), serde_json::json!(tool.name));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), serde_json::json!(desc));
    }
    obj.insert("input_schema".to_string(), tool.input_schema.clone());
    serde_json::Value::Object(obj)
}

/// Anthropic writer implementation.
#[derive(Clone)]
pub(crate) struct AnthropicWriter;

/// Which native credential scheme a credential maps to. Anthropic accepts exactly one scheme per
/// request, and a native client presents exactly one: an API-key client sends `x-api-key` and no
/// `authorization`; an OAuth client sends `authorization: Bearer` and no `x-api-key`. Emitting
/// both (the same secret duplicated across two schemes) is a request shape no native client
/// produces — a structural upstream-distinguishability tell — so we classify and emit one.
#[derive(Debug, PartialEq, Eq)]
enum AnthropicCredScheme {
    /// Canonical Anthropic API key (`sk-ant-api...`): `x-api-key` only.
    ApiKey,
    /// OAuth access token (`sk-ant-oat...`): `authorization: Bearer` only.
    OAuth,
    /// Shape not recognizable as either Anthropic credential family. busbar cannot tell from the
    /// credential alone whether this is a static API key or a passthrough Bearer token (the mode
    /// is known to forward.rs but not plumbed into this trait method), so it conservatively emits
    /// BOTH headers — preserving the passthrough Bearer round-trip for an opaque caller token
    /// while still presenting `x-api-key` for a non-canonical static key. Real Anthropic
    /// credentials always match `ApiKey`/`OAuth`, so the dual-header fallback never fires for
    /// genuine API-key or OAuth traffic — the path the distinguishability finding is about.
    Ambiguous,
}

impl AnthropicWriter {
    /// Classify `key` into its native credential scheme by prefix. Matches on the trimmed key so
    /// surrounding whitespace (a likely config artifact) doesn't misclassify a credential.
    fn classify_credential(key: &str) -> AnthropicCredScheme {
        let k = key.trim_start();
        if k.starts_with("sk-ant-api") {
            AnthropicCredScheme::ApiKey
        } else if k.starts_with("sk-ant-oat") {
            AnthropicCredScheme::OAuth
        } else {
            AnthropicCredScheme::Ambiguous
        }
    }

    /// Build the native Anthropic error envelope for a resolved `error.type`.
    ///
    /// Current Anthropic API error bodies carry a top-level `request_id` (`req_...`) alongside the
    /// `error` object. busbar synthesizes this envelope itself (no upstream request to forward), so
    /// we mint one to match the native shape — the SDK doesn't require it to decode the typed
    /// exception, but its absence is a distinguishability tell. Shared by every `write_error` exit
    /// so the status-driven and kind-driven paths emit byte-identical envelopes.
    fn error_envelope(error_type: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": error_type,
                "message": message,
            },
            "request_id": synth_request_id(),
        })
    }
}

/// Build Anthropic auth headers for `key`, resolving the credential scheme to native headers.
///
/// Anthropic accepts exactly ONE credential scheme per request, and a native client presents exactly
/// one: an API-key client sends `x-api-key` and NO `authorization`; an OAuth client sends
/// `authorization: Bearer <token>` and NO `x-api-key`. Emitting both (the same secret duplicated
/// across two schemes) is a request shape no native client produces — a structural upstream-
/// distinguishability tell — and, if upstream ever cross-validates the two headers, a latent 401
/// source. So we classify the credential and emit a single scheme.
///
/// The credential family disambiguates the real cases: a static lane key (the configured
/// `sk-ant-api…`) → `x-api-key`; a passthrough OAuth access token (`sk-ant-oat…`) →
/// `authorization: Bearer`. A credential matching NEITHER family is `Ambiguous` — busbar cannot tell
/// from the credential bytes alone whether it is a static key or a forwarded Bearer token. `mode`
/// carries the front-door auth mode from the wire path (`SigningContext.auth_mode`) to break that
/// tie WITHOUT a dual-header tell:
///   * `Some(Passthrough)` → the caller's token, forwarded as `authorization: Bearer` only;
///   * `Some(Token | None)` → a configured lane key, presented as `x-api-key` only;
///   * `None` → the mode-blind primitive (`auth_headers`, no signing ctx): fall back to BOTH headers
///     so neither path silently drops. Real Anthropic credentials always match ApiKey/OAuth, so the
///     dual-header fallback never fires for genuine traffic; the wire path always passes `Some(_)`.
///
/// The `anthropic-version` header is common to all.
///
/// A key with bytes invalid in an HTTP header value (e.g. a stray newline) yields an empty header
/// (one diagnostic warning, key bytes never logged) rather than panicking the worker — the upstream
/// then returns a clean 401 the breaker classifies normally. Defense-in-depth; keys should be
/// validated at config load.
fn anthropic_auth_headers(
    key: &str,
    mode: Option<crate::auth::AuthMode>,
) -> Vec<(HeaderName, HeaderValue)> {
    let safe = |label: &'static str, raw: String| {
        HeaderValue::from_str(&raw).unwrap_or_else(|_| {
            tracing::warn!(
                header = label,
                "anthropic auth credential contains bytes invalid for an HTTP header value \
                 (e.g. a trailing newline); sending an empty value, the upstream will return \
                 401 — check the key configuration"
            );
            HeaderValue::from_static("")
        })
    };
    let x_api_key = || {
        (
            HeaderName::from_static("x-api-key"),
            safe("x-api-key", key.to_string()),
        )
    };
    // ApiKey-scheme variant of `x-api-key` that strips LEADING whitespace from the configured key
    // (R25 LOW #15). `classify_credential` matches on `key.trim_start()`, so `"  sk-ant-api…"`
    // classifies as `ApiKey` — but the raw `x_api_key` closure above forwards the key VERBATIM,
    // emitting `x-api-key: "  sk-ant-api…"` (a header value with a leading-space artifact the
    // upstream rejects with a 401). Trim the leading whitespace so the emitted header matches the
    // value that was classified. Scope is deliberately narrow: ONLY the canonical configured-key
    // (`ApiKey`) scheme is trimmed here. The OAuth (`authorization: Bearer`) and the Ambiguous
    // passthrough/static fallbacks keep the raw closures below, preserving their byte-for-byte
    // round-trip contract — a forwarded caller token must reach the upstream exactly as presented.
    let x_api_key_trimmed = || {
        (
            HeaderName::from_static("x-api-key"),
            safe("x-api-key", key.trim_start().to_string()),
        )
    };
    let authorization = || {
        (
            HeaderName::from_static("authorization"),
            safe("authorization", format!("Bearer {key}")),
        )
    };
    let version = (
        HeaderName::from_static("anthropic-version"),
        HeaderValue::from_static(ANTHROPIC_API_VERSION),
    );
    match AnthropicWriter::classify_credential(key) {
        // Configured Anthropic API key: native API-key client shape — `x-api-key` only. Use the
        // leading-whitespace-trimmed builder so a configured key with a stray leading space (the
        // value `classify_credential` already matched on its trimmed form) is forwarded clean.
        AnthropicCredScheme::ApiKey => vec![x_api_key_trimmed(), version],
        // OAuth access token / passthrough Bearer token: native OAuth client shape —
        // `authorization: Bearer` only.
        AnthropicCredScheme::OAuth => vec![authorization(), version],
        // Unrecognized shape: the mode resolves it to a single native header on the wire path;
        // the mode-blind primitive falls back to both so neither path silently drops.
        AnthropicCredScheme::Ambiguous => match mode {
            Some(crate::auth::AuthMode::Passthrough) => vec![authorization(), version],
            Some(crate::auth::AuthMode::Token) | Some(crate::auth::AuthMode::None) => {
                vec![x_api_key(), version]
            }
            None => vec![x_api_key(), authorization(), version],
        },
    }
}

impl ProtocolWriter for AnthropicWriter {
    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    fn upstream_path(&self) -> &str {
        "/v1/messages"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Mode-blind primitive (no signing context). An Ambiguous credential emits BOTH headers so
        // neither the static-key nor the passthrough path silently drops. The live wire path uses
        // `sign_request` below, which carries the auth mode and resolves Ambiguous to one header —
        // so a real request never sends the dual-header upstream tell.
        anthropic_auth_headers(key, None)
    }

    fn sign_request(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // Wire path: the front-door auth mode (set by forward.rs into the SigningContext) resolves an
        // Ambiguous Anthropic credential to the SINGLE native header that mode implies — Passthrough
        // forwards the caller's token as `authorization: Bearer`; Token/None present the configured
        // key as `x-api-key`. Clear ApiKey/OAuth credentials are unaffected (still single-header).
        anthropic_auth_headers(key, Some(ctx.auth_mode))
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn requires_max_tokens(&self) -> bool {
        // Anthropic Messages 400s with `max_tokens: Field required` when absent.
        true
    }

    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Native Anthropic error envelope: `{"type":"error","error":{"type":<kind>,"message":<msg>}}`
        // (see the Anthropic SDK / API error shape — the `anthropic.APIStatusError` family decodes
        // `error.type` into the typed exception, e.g. `RateLimitError`, and surfaces `error.message`).
        // Served as `application/json` by the caller, per the `ProtocolWriter::write_error` contract.
        // The generic `kind` strings the router emits are mapped to Anthropic's own error-type
        // vocabulary so a native SDK gets the exception it expects; an unrecognized `kind` is passed
        // through verbatim (it is already an Anthropic-style type, or a value we don't want to
        // silently rewrite — no `_ =>` swallow).
        //
        // Status-driven override first: native Anthropic represents upstream overload as the 529
        // `overloaded_error`, never a generic `api_error`. When a cross-protocol upstream relays a
        // 503 (or 529) to an Anthropic-ingress client, the router hands us the generic `api_error`
        // kind — but the native type for that status family is `overloaded_error`. Map by status so
        // a native SDK raises the right exception (and the body matches what real Anthropic returns
        // under load) rather than a generic server error. Status takes precedence over `kind` here
        // because the wire status is the authoritative signal of the overload condition.
        if status == 503 || status == 529 {
            return Self::error_envelope("overloaded_error", message);
        }
        let anthropic_type = match kind {
            // Generic router/auth/forward `kind`s → Anthropic's typed error vocabulary.
            "invalid_request" | "bad_request" => "invalid_request_error",
            "authentication" | "unauthorized" => "authentication_error",
            "permission" | "forbidden" => "permission_error",
            "not_found" => "not_found_error",
            "request_too_large" | "payload_too_large" => "request_too_large",
            "rate_limit" | "too_many_requests" => "rate_limit_error",
            "overloaded" => "overloaded_error",
            "timeout" => "timeout_error",
            "api_error" | "server_error" | "internal" => "api_error",
            // Already an Anthropic-native type (e.g. "invalid_request_error") or an unmapped value:
            // emit it unchanged rather than collapsing every unknown into one bucket.
            "invalid_request_error"
            | "authentication_error"
            | "permission_error"
            | "not_found_error"
            | "rate_limit_error"
            | "overloaded_error"
            | "timeout_error" => kind,
            other => other,
        };
        Self::error_envelope(anthropic_type, message)
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        // Anthropic's Messages API has NO `system` role inside `messages` — system content lives in
        // the top-level `system` field. Anthropic's OWN reader canonicalizes a wire `role:"system"`
        // message into `req.system` (see `read_request`), but a CROSS-PROTOCOL IR (e.g. read by the
        // OpenAI reader) can still carry an `IrRole::System` message in `req.messages` that never
        // passed through that promotion. Fold any such message's blocks into the top-level system
        // array here so `write_message` never receives a System role and can never emit the INVALID
        // `role:"system"` (which upstream rejects with a 400) — mirroring the gemini/bedrock writers,
        // which `continue` past an `IrRole::System` message in their request message loop.
        let mut system_blocks: Vec<&crate::ir::IrBlock> = req.system.iter().collect();
        for msg in &req.messages {
            if msg.role == crate::ir::IrRole::System {
                system_blocks.extend(msg.content.iter());
            }
        }
        if !system_blocks.is_empty() {
            let system_array: Vec<_> = system_blocks.into_iter().map(write_block).collect();
            out.insert("system".to_string(), serde_json::Value::Array(system_array));
        }
        let messages_array: Vec<_> = req
            .messages
            .iter()
            .filter(|msg| msg.role != crate::ir::IrRole::System)
            .map(write_message)
            .collect();
        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );
        if !req.tools.is_empty() {
            let tools_array: Vec<_> = req.tools.iter().map(write_tool).collect();
            out.insert("tools".to_string(), serde_json::Value::Array(tools_array));
        }
        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Sampling controls promoted to first-class IR fields (see `IrRequest`): emit each in
        // Anthropic's native shape when present. `top_p`/`top_k` map 1:1; the IR's normalized `stop`
        // vec is Anthropic's native `stop_sequences` array. Emitted before the `extra` overlay (these
        // keys were pulled OUT of extra by the reader, so there is no double-emit on passthrough).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            out.insert("top_k".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            out.insert("stop_sequences".to_string(), serde_json::json!(req.stop));
        }
        out.insert("stream".to_string(), serde_json::json!(req.stream));
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }
        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                usage,
                id,
                model,
                ..
            } => {
                let role_str = match role {
                    crate::ir::IrRole::User => "user",
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                let mut msg_obj = serde_json::Map::new();
                // The native `message_start.message` is a skeleton Message EVERY native Anthropic
                // stream carries and an SDK reads `id`/`type`/`role`/`model`/`content`/`usage` from
                // (plus `stop_reason`/`stop_sequence`, null at stream start). Emit that full skeleton
                // UNCONDITIONALLY — synthesizing a `msg_`-prefixed id when the source carried none —
                // exactly as every other ingress writer does (openai/cohere/responses/gemini all
                // `unwrap_or_else` an id). `write_response_event` runs ONLY on the cross-protocol
                // `StreamTranslate` path (same-protocol streams pass raw bytes through and never
                // reconstruct events), where `StreamTranslate` strips the foreign `id` to `None`;
                // gating the skeleton on `has_identity` therefore emitted a DEGENERATE
                // `{role,usage}` message_start on every cross-protocol Anthropic-ingress stream —
                // missing the mandatory `id`/`type`/`content`/`stop_reason`/`stop_sequence` an SDK
                // requires to construct its streaming Message (a decode failure and a proxy tell).
                let msg_id = id.clone().unwrap_or_else(synth_message_id);
                msg_obj.insert("id".to_string(), serde_json::json!(msg_id));
                msg_obj.insert("type".to_string(), serde_json::json!("message"));
                msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                // model: same conformance class as the non-stream `write_response` writer — the SDK
                // types `message_start.message.model` as a REQUIRED non-optional string and reads it to
                // populate the assembled streaming Message. Emit it UNCONDITIONALLY (empty-string
                // fallback when the cross-protocol source didn't carry a model), so the skeleton is
                // structurally valid rather than dropping a mandatory field.
                let model_str = model.as_deref().unwrap_or("");
                msg_obj.insert("model".to_string(), serde_json::json!(model_str));
                msg_obj.insert("content".to_string(), serde_json::Value::Array(Vec::new()));
                msg_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                msg_obj.insert("stop_sequence".to_string(), serde_json::Value::Null);
                // `usage` is a REQUIRED field of `message_start.message`: a native Anthropic stream
                // always carries `usage:{"input_tokens":N,"output_tokens":0}` at stream open, and the
                // official TypeScript SDK types `message.usage` as `Usage` (not `Usage | undefined`) —
                // a client that reads `event.message.usage.input_tokens` on the first event throws if
                // it is absent. On the cross-protocol path (e.g. OpenAI→Anthropic) the first chunk
                // carries no usage, so `usage` is `None`; emit a zero-valued skeleton in that case
                // (which also matches native behavior: output_tokens is 0 at stream open) rather than
                // omitting the key.
                let mut usage_map = serde_json::Map::new();
                let (input_tokens, output_tokens) = usage
                    .as_ref()
                    .map(|u| (u.input_tokens, u.output_tokens))
                    .unwrap_or((0, 0));
                usage_map.insert("input_tokens".to_string(), serde_json::json!(input_tokens));
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(output_tokens),
                );
                if let Some(usage_val) = usage {
                    if let Some(ccit) = usage_val.cache_creation_input_tokens {
                        usage_map.insert(
                            "cache_creation_input_tokens".to_string(),
                            serde_json::json!(ccit),
                        );
                    }
                    if let Some(crit) = usage_val.cache_read_input_tokens {
                        usage_map.insert(
                            "cache_read_input_tokens".to_string(),
                            serde_json::json!(crit),
                        );
                    }
                }
                msg_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                let mut data_obj = serde_json::Map::new();
                // Native Anthropic SSE data bodies carry a top-level `type` matching the SSE `event:`
                // header (e.g. `{"type":"message_start",...}`). The SDK streaming decoder accepts the
                // event off the header, but native parity (and any consumer that dispatches on
                // `data.type`) requires the field — emit it on every event body.
                data_obj.insert("type".to_string(), serde_json::json!("message_start"));
                data_obj.insert("message".to_string(), serde_json::Value::Object(msg_obj));
                Some((
                    "message_start".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStart { index, block } => {
                let content_block = match block {
                    IrBlockMeta::Text => {
                        serde_json::json!({ "type": "text" })
                    }
                    IrBlockMeta::Thinking => {
                        serde_json::json!({ "type": "thinking" })
                    }
                    IrBlockMeta::ToolUse { id, name } => {
                        serde_json::json!({ "type": "tool_use", "id": id, "name": name })
                    }
                    IrBlockMeta::Image => {
                        serde_json::json!({ "type": "image" })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("type".to_string(), serde_json::json!("content_block_start"));
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("content_block".to_string(), content_block);
                Some((
                    "content_block_start".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockDelta { index, delta } => {
                let delta_val = match delta {
                    IrDelta::TextDelta(text) => {
                        serde_json::json!({ "type": "text_delta", "text": text })
                    }
                    IrDelta::ThinkingDelta(thinking) => {
                        serde_json::json!({ "type": "thinking_delta", "thinking": thinking })
                    }
                    IrDelta::InputJsonDelta(json) => {
                        serde_json::json!({ "type": "input_json_delta", "partial_json": json })
                    }
                    IrDelta::SignatureDelta(sig) => {
                        serde_json::json!({ "type": "signature_delta", "signature": sig })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("type".to_string(), serde_json::json!("content_block_delta"));
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("delta".to_string(), delta_val);
                Some((
                    "content_block_delta".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStop { index } => {
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("type".to_string(), serde_json::json!("content_block_stop"));
                data_obj.insert("index".to_string(), serde_json::json!(index));
                Some((
                    "content_block_stop".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                let mut delta_obj = serde_json::Map::new();
                if let Some(reason) = stop_reason {
                    delta_obj.insert("stop_reason".to_string(), serde_json::json!(reason));
                } else {
                    delta_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                }
                // `stop_sequence`: native Anthropic `message_delta` ALWAYS carries this key —
                // the matched stop string when a stop sequence fired, else explicit `null`. Emit
                // `null` rather than omitting the key so a strict property-presence validator sees
                // the native shape (the TS SDK already treats `undefined`/`null` alike).
                delta_obj.insert(
                    "stop_sequence".to_string(),
                    stop_sequence
                        .as_deref()
                        .map(serde_json::Value::from)
                        .unwrap_or(serde_json::Value::Null),
                );
                let mut usage_map = serde_json::Map::new();
                usage_map.insert(
                    "input_tokens".to_string(),
                    serde_json::json!(usage.input_tokens),
                );
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                if let Some(ccit) = usage.cache_creation_input_tokens {
                    usage_map.insert(
                        "cache_creation_input_tokens".to_string(),
                        serde_json::json!(ccit),
                    );
                }
                if let Some(crit) = usage.cache_read_input_tokens {
                    usage_map.insert(
                        "cache_read_input_tokens".to_string(),
                        serde_json::json!(crit),
                    );
                }
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("type".to_string(), serde_json::json!("message_delta"));
                data_obj.insert("delta".to_string(), serde_json::Value::Object(delta_obj));
                data_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                Some((
                    "message_delta".to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageStop => Some((
                "message_stop".to_string(),
                serde_json::json!({ "type": "message_stop" }),
            )),
            IrStreamEvent::Error(err) => {
                // Native Anthropic in-stream error event:
                // `{"type":"error","error":{"type":<type>,"message":<msg>}}`. The SDK's streaming
                // decoder reads BOTH `error.type` (→ typed exception) AND `error.message` (the
                // human-readable description, a required field in the documented shape). Omitting
                // `message` leaves the SDK's `APIError` with an undefined description and is a
                // distinguishability tell vs a native event.
                let mut error_obj = serde_json::Map::new();
                match err.provider_signal {
                    Some(ref ps) => {
                        error_obj.insert("type".to_string(), serde_json::json!(ps));
                    }
                    None => {
                        error_obj.insert("type".to_string(), serde_json::Value::Null);
                    }
                }
                // The IR carries no separate message string (IrError == CanonicalSignal, which has
                // no `message` field), so derive a human-readable one from the signal: prefer the
                // provider type when present, otherwise a generic fallback. Always non-empty so the
                // SDK's `error.message` is never undefined/null.
                //
                // The message text MUST stay native-plausible: a real Anthropic streaming `error`
                // event never carries reverse-proxy vocabulary ("upstream", "gateway", "backend",
                // …). The provider type token (`provider_signal`, e.g. `overloaded_error`) is the
                // provider's OWN type string, so emit it VERBATIM — never prefixed with router/proxy
                // words. When no signal is present, fall back to the generic native phrasing.
                let message = match err.provider_signal.as_deref() {
                    Some(ps) if !ps.is_empty() => ps.to_string(),
                    Some(_) | None => "an error occurred while streaming the response".to_string(),
                };
                error_obj.insert("message".to_string(), serde_json::json!(message));
                let mut data_obj = serde_json::Map::new();
                // Native Anthropic in-stream error data body carries the top-level `type:"error"`
                // discriminator matching the SSE `event: error` header — exactly like every other
                // event arm inserts its own `type`. An SDK that dispatches on `data.type` (the
                // documented shape) won't recognize the event as an error without it, and its
                // absence is a proxy-signature tell vs a native stream.
                data_obj.insert("type".to_string(), serde_json::json!("error"));
                data_obj.insert("error".to_string(), serde_json::Value::Object(error_obj));
                Some(("error".to_string(), serde_json::Value::Object(data_obj)))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // id: an official SDK's `Message.id` is a REQUIRED `"msg_<rand>"` string — the Python/TS SDK
        // types `Message.id` as a non-optional `str`, so a body that omits it fails to decode. Emit
        // it UNCONDITIONALLY, mirroring the streaming `message_start` writer (line ~1065) and every
        // other protocol writer (openai/cohere/responses), all of which `unwrap_or_else` a synthesized
        // id rather than gating on a second field:
        //   * same-protocol passthrough / any source that carried an id — `resp.id` is `Some`; re-emit
        //     it verbatim so a native SDK sees the exact id its backend assigned.
        //   * id absent (`resp.id == None`) — synthesize a protocol-correct `msg_<rand>` via
        //     `synth_message_id`. This covers BOTH the cross-protocol path where the source recorded a
        //     `created` (e.g. OpenAI) AND the path where the source recorded neither id nor created
        //     (e.g. a Bedrock Converse body, whose reader returns `created: None`) — the latter
        //     previously hit a `(None, None)` arm that emitted NO `id`, producing an invalid Message
        //     for a Bedrock→Anthropic non-stream client. Synthesis is safe for idempotence because
        //     `write_response` runs ONLY on the cross-protocol translate path (see the `stop_sequence`
        //     note below: same-protocol non-stream relays the raw upstream body and never reaches this
        //     writer), so there is no same-protocol read→write→read round-trip to keep id-less.
        let id = resp.id.clone().unwrap_or_else(synth_message_id);
        obj.insert("id".to_string(), serde_json::json!(id));

        // type/role are constant for a Messages API response ("message"/"assistant").
        obj.insert("type".to_string(), serde_json::json!("message"));
        obj.insert("role".to_string(), serde_json::json!("assistant"));

        // model: the official SDKs type `Message.model` as a REQUIRED non-optional string, so a body
        // that omits it fails to decode (Pydantic/Zod validation error). Emit it UNCONDITIONALLY,
        // mirroring the `id` handling above. On a cross-protocol path where the egress reader didn't
        // populate `resp.model` (notably Bedrock→Anthropic, whose `read_response` may not surface a
        // model), fall back to an empty string so the key is always present and structurally valid
        // rather than dropping it. Same-protocol passthrough preserves the upstream value verbatim.
        let model = resp.model.as_deref().unwrap_or("");
        obj.insert("model".to_string(), serde_json::json!(model));

        // content blocks
        let content_array: Vec<serde_json::Value> = resp.content.iter().map(write_block).collect();
        obj.insert(
            "content".to_string(),
            serde_json::Value::Array(content_array),
        );

        // stop_reason (omit if None — a native body omits it until the turn ends, and omitting
        // keeps same-protocol round-trips lossless)
        if let Some(ref reason) = resp.stop_reason {
            obj.insert("stop_reason".to_string(), serde_json::json!(reason));
        }

        // stop_sequence: a native non-streaming Anthropic `Message` ALWAYS carries this key — the
        // matched stop string when a stop sequence fired, JSON `null` otherwise (the SDK types
        // `Message.stop_sequence` as `Optional[str]` and always populates it). `write_response` runs
        // ONLY on the cross-protocol translate path (forward.rs: same-protocol non-stream relays the
        // raw upstream body and never reaches here), where the egress is Anthropic and must byte-match
        // the native shape — so emit an explicit `null` when absent rather than omitting the key. A
        // read→write→read round-trip stays IR-idempotent (`read_response` maps a `null`
        // `stop_sequence` back to `None`). Same conformance class as the streaming `message_delta`
        // `stop_sequence`.
        match &resp.stop_sequence {
            Some(seq) => {
                obj.insert("stop_sequence".to_string(), serde_json::json!(seq));
            }
            None => {
                obj.insert("stop_sequence".to_string(), serde_json::Value::Null);
            }
        }

        // usage
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        if let Some(ccit) = resp.usage.cache_creation_input_tokens {
            usage_map.insert(
                "cache_creation_input_tokens".to_string(),
                serde_json::json!(ccit),
            );
        }
        if let Some(crit) = resp.usage.cache_read_input_tokens {
            usage_map.insert(
                "cache_read_input_tokens".to_string(),
                serde_json::json!(crit),
            );
        }
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

#[cfg(test)]
mod anthropic_hardening_tests {
    use super::*;

    fn header_value(headers: &[(HeaderName, HeaderValue)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
    }

    /// A configured API key authenticates the native way: `x-api-key` ONLY, with no
    /// `authorization` header — sending both is the upstream-distinguishability tell we fixed.
    /// `anthropic-version` is always present.
    #[test]
    fn auth_headers_api_key_emits_only_x_api_key() {
        let headers = AnthropicWriter.auth_headers("sk-ant-api03-secret-key");

        assert_eq!(
            header_value(&headers, "x-api-key").as_deref(),
            Some("sk-ant-api03-secret-key")
        );
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an API key must NOT emit an authorization header (native API-key clients never do)"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
    }

    /// R25 LOW #15 regression: a configured API key with LEADING WHITESPACE (a common config
    /// artifact — a stray space or indentation in an env var / secrets file) classifies as `ApiKey`
    /// (because `classify_credential` matches on the trimmed key) but, before the fix, was forwarded
    /// VERBATIM — emitting `x-api-key: "  sk-ant-api…"`, a malformed header value the upstream rejects
    /// with a 401. The configured-key (`ApiKey`) scheme must now emit the key with the leading
    /// whitespace stripped, matching the value the classifier matched on.
    #[test]
    fn auth_headers_api_key_trims_leading_whitespace() {
        // Wire path (sign_request, Token mode) and the mode-blind primitive both route a canonical
        // `sk-ant-api…` key through the ApiKey arm — assert both emit the CLEAN header.
        let raw = "   sk-ant-api03-secret-key";
        let ctx = crate::proto::SigningContext {
            host: "api.anthropic.com".to_string(),
            canonical_uri: "/v1/messages".to_string(),
            body: b"{}",
            timestamp_epoch: 0,
            auth_mode: crate::auth::AuthMode::Token,
        };
        for headers in [
            AnthropicWriter.auth_headers(raw),
            AnthropicWriter.sign_request(raw, &ctx),
        ] {
            assert_eq!(
                header_value(&headers, "x-api-key").as_deref(),
                Some("sk-ant-api03-secret-key"),
                "the ApiKey scheme must forward the configured key with leading whitespace stripped"
            );
            // Still single-header (no Bearer tell) and the trim did not corrupt the value.
            assert!(
                header_value(&headers, "authorization").is_none(),
                "an API key must NOT emit an authorization header"
            );
        }
    }

    /// Precision guard for R25 LOW #15: the leading-whitespace trim is scoped to the configured-key
    /// (`ApiKey`) scheme ONLY. An OAuth (`sk-ant-oat…`) credential — and any Ambiguous passthrough
    /// Bearer token — must round-trip BYTE-FOR-BYTE, leading whitespace included, so a forwarded
    /// caller token reaches the upstream exactly as presented (the passthrough contract). Trimming
    /// the Bearer value here would silently rewrite a caller's credential.
    #[test]
    fn auth_headers_oauth_and_passthrough_preserve_leading_whitespace() {
        // OAuth (sk-ant-oat) keeps its raw Bearer value verbatim — note the leading space is kept
        // inside the value after the `Bearer ` prefix.
        let oat = "  sk-ant-oat01-caller-token";
        let oauth_headers = AnthropicWriter.auth_headers(oat);
        assert_eq!(
            header_value(&oauth_headers, "authorization").as_deref(),
            Some("Bearer   sk-ant-oat01-caller-token"),
            "OAuth Bearer must round-trip the credential verbatim (no trim)"
        );
        assert!(
            header_value(&oauth_headers, "x-api-key").is_none(),
            "OAuth must not emit x-api-key"
        );

        // Ambiguous passthrough Bearer (wire path) likewise round-trips verbatim.
        let amb = "  opaque-caller-token";
        let ctx = crate::proto::SigningContext {
            host: "api.anthropic.com".to_string(),
            canonical_uri: "/v1/messages".to_string(),
            body: b"{}",
            timestamp_epoch: 0,
            auth_mode: crate::auth::AuthMode::Passthrough,
        };
        let pt = AnthropicWriter.sign_request(amb, &ctx);
        assert_eq!(
            header_value(&pt, "authorization").as_deref(),
            Some("Bearer   opaque-caller-token"),
            "passthrough Bearer must round-trip the caller token verbatim (no trim)"
        );
    }

    /// A credential matching neither Anthropic family (no `sk-ant-api` / `sk-ant-oat` prefix) is
    /// Ambiguous: busbar can't tell a static key from a passthrough Bearer token here, so it emits
    /// BOTH headers — preserving both paths. This is the ONLY case where both are sent; real
    /// Anthropic credentials never land here.
    #[test]
    fn auth_headers_unrecognized_credential_emits_both_headers() {
        let headers = AnthropicWriter.auth_headers("caller-specific-token-abc123");

        assert_eq!(
            header_value(&headers, "x-api-key").as_deref(),
            Some("caller-specific-token-abc123")
        );
        assert_eq!(
            header_value(&headers, "authorization").as_deref(),
            Some("Bearer caller-specific-token-abc123")
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
    }

    /// Regression: the WIRE path (`sign_request`, which carries the front-door auth mode in the
    /// SigningContext) resolves an Ambiguous credential to a SINGLE native header — never the
    /// dual-header upstream-distinguishability tell the mode-blind `auth_headers` primitive emits.
    /// Passthrough → caller's `authorization: Bearer` only; Token/None → configured `x-api-key` only.
    #[test]
    fn sign_request_resolves_ambiguous_credential_to_single_header_by_mode() {
        let body = b"{}";
        let ctx = |mode| crate::proto::SigningContext {
            host: "api.anthropic.com".to_string(),
            canonical_uri: "/v1/messages".to_string(),
            body,
            timestamp_epoch: 0,
            auth_mode: mode,
        };
        let amb = "caller-specific-token-abc123";

        // Passthrough: forward the caller's token as Bearer ONLY (no x-api-key tell).
        let pt = AnthropicWriter.sign_request(amb, &ctx(crate::auth::AuthMode::Passthrough));
        assert_eq!(
            header_value(&pt, "authorization").as_deref(),
            Some("Bearer caller-specific-token-abc123")
        );
        assert!(
            header_value(&pt, "x-api-key").is_none(),
            "passthrough wire path must NOT also emit x-api-key (dual-header tell)"
        );

        // Token mode (configured lane key): present the API-key shape ONLY (no Bearer tell).
        for mode in [crate::auth::AuthMode::Token, crate::auth::AuthMode::None] {
            let h = AnthropicWriter.sign_request(amb, &ctx(mode));
            assert_eq!(
                header_value(&h, "x-api-key").as_deref(),
                Some("caller-specific-token-abc123")
            );
            assert!(
                header_value(&h, "authorization").is_none(),
                "token/none wire path must NOT also emit authorization (dual-header tell)"
            );
        }

        // Clear API-key / OAuth credentials stay single-header on the wire path regardless of mode.
        let api = AnthropicWriter.sign_request("sk-ant-api03-x", &ctx(crate::auth::AuthMode::None));
        assert!(
            header_value(&api, "x-api-key").is_some()
                && header_value(&api, "authorization").is_none()
        );
    }

    /// classify_credential maps each credential family deterministically; leading whitespace is
    /// trimmed before matching.
    #[test]
    fn classify_credential_covers_each_family() {
        assert_eq!(
            AnthropicWriter::classify_credential("sk-ant-api03-key"),
            AnthropicCredScheme::ApiKey
        );
        assert_eq!(
            AnthropicWriter::classify_credential("sk-ant-oat01-token"),
            AnthropicCredScheme::OAuth
        );
        assert_eq!(
            AnthropicWriter::classify_credential("opaque-bearer"),
            AnthropicCredScheme::Ambiguous
        );
        // Whitespace must not flip an API key into the Ambiguous (dual-header) bucket.
        assert_eq!(
            AnthropicWriter::classify_credential("  sk-ant-api03-key"),
            AnthropicCredScheme::ApiKey
        );
    }

    /// An OAuth/passthrough Bearer token (the `sk-ant-oat` family) authenticates the native way:
    /// `authorization: Bearer` ONLY, with no `x-api-key`. This preserves the passthrough path that
    /// round-trips a caller's Bearer token to upstream.
    #[test]
    fn auth_headers_oauth_token_emits_only_authorization_bearer() {
        let headers = AnthropicWriter.auth_headers("sk-ant-oat01-caller-token");

        assert_eq!(
            header_value(&headers, "authorization").as_deref(),
            Some("Bearer sk-ant-oat01-caller-token")
        );
        assert!(
            header_value(&headers, "x-api-key").is_none(),
            "an OAuth token must NOT emit an x-api-key header (native OAuth clients never do)"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
    }

    /// Leading whitespace (a likely config artifact) must not cause an OAuth token to be
    /// misclassified as an API key.
    #[test]
    fn auth_headers_oauth_token_classification_trims_leading_whitespace() {
        let headers = AnthropicWriter.auth_headers("  sk-ant-oat01-caller-token");
        // The header value itself is the verbatim (untrimmed) credential — only the
        // classification trims. Round-tripping the caller's exact token is the contract.
        assert_eq!(
            header_value(&headers, "authorization").as_deref(),
            Some("Bearer   sk-ant-oat01-caller-token")
        );
        assert!(header_value(&headers, "x-api-key").is_none());
    }

    /// A key with bytes invalid for an HTTP header value (e.g. a trailing newline) must not panic
    /// the worker; the (single) credential header falls back to empty so the upstream returns a
    /// clean 401. An invalid API key emits only the empty `x-api-key` (no `authorization`).
    #[test]
    fn auth_headers_invalid_api_key_falls_back_to_empty_no_panic() {
        // A recognizable API key (so the single-header API-key path is exercised) whose bytes are
        // invalid for an HTTP header value.
        let headers = AnthropicWriter.auth_headers("sk-ant-api03-bad\nkey");
        assert_eq!(header_value(&headers, "x-api-key").as_deref(), Some(""));
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an invalid API key still must not emit an authorization header"
        );
        // anthropic-version is static and unaffected by the bad key.
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
    }

    /// The same empty-value-no-panic guarantee on the OAuth path: an invalid OAuth token emits
    /// only the empty `authorization` header (no `x-api-key`).
    #[test]
    fn auth_headers_invalid_oauth_token_falls_back_to_empty_no_panic() {
        let headers = AnthropicWriter.auth_headers("sk-ant-oat01-bad\ntoken");
        assert_eq!(header_value(&headers, "authorization").as_deref(), Some(""));
        assert!(
            header_value(&headers, "x-api-key").is_none(),
            "an invalid OAuth token still must not emit an x-api-key header"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
    }

    /// extract_error parses the body once and surfaces both provider_code and structured_type.
    #[test]
    fn extract_error_parses_both_fields() {
        let body = br#"{"error":{"type":"invalid_request_error","code":"some_code"}}"#;
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.http_status, 400);
        assert_eq!(raw.provider_code.as_deref(), Some("some_code"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
    }

    /// A non-JSON error body must not yield codes from the structured fields, but the
    /// context-length text heuristic must still fire when the message indicates it.
    #[test]
    fn extract_error_non_json_body() {
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, b"not json at all");
        assert_eq!(raw.provider_code, None);
        assert_eq!(raw.structured_type, None);
    }

    /// Context-length is signalled via the error message; the single-parse refactor must preserve
    /// the canonical code synthesis from the body text.
    #[test]
    fn extract_error_context_length_from_message() {
        let body = br#"{"error":{"type":"invalid_request_error","message":"prompt is too long"}}"#;
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded")
        );
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
    }

    /// write_error must produce the NATIVE Anthropic envelope
    /// `{"type":"error","error":{"type":<mapped kind>,"message":<msg>}}`, mapping a generic router
    /// `kind` into Anthropic's typed error vocabulary so a native SDK decodes the right exception.
    #[test]
    fn write_error_native_anthropic_envelope_shape() {
        let v = AnthropicWriter.write_error(404, "not_found", "model 'x' not found");
        // Top-level discriminator is "error" (Anthropic), NOT the generic `{"error":{...}}`.
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
        let err = v.get("error").expect("error object present");
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("not_found_error"),
            "generic `not_found` must map to Anthropic `not_found_error`"
        );
        assert_eq!(
            err.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found")
        );
        // Round-trips as JSON (the caller serves it as application/json) — no panic.
        let s = serde_json::to_string(&v).expect("must serialize");
        let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
    }

    /// A `kind` already in Anthropic's vocabulary passes through unchanged (no double-mapping, no
    /// `_ =>` collapse), and a representative sample of generic kinds map to the right native type.
    #[test]
    fn write_error_kind_vocabulary_mapping() {
        let map_of = |kind: &str| {
            AnthropicWriter
                .write_error(400, kind, "m")
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        };
        assert_eq!(map_of("rate_limit").as_deref(), Some("rate_limit_error"));
        assert_eq!(
            map_of("authentication").as_deref(),
            Some("authentication_error")
        );
        assert_eq!(
            map_of("invalid_request").as_deref(),
            Some("invalid_request_error")
        );
        // Already-native type is emitted verbatim.
        assert_eq!(
            map_of("invalid_request_error").as_deref(),
            Some("invalid_request_error")
        );
        // Unknown/unmapped kind passes through rather than being swallowed into one bucket.
        assert_eq!(
            map_of("some_custom_kind").as_deref(),
            Some("some_custom_kind")
        );
    }

    /// A cross-protocol upstream 503 relayed to an Anthropic-ingress client arrives with the
    /// generic router kind `api_error`. Native Anthropic represents upstream overload as the 529
    /// `overloaded_error`, NOT a generic `api_error`, so `write_error` must map by status: a 503
    /// (and the 529 it canonically maps to) yields `error.type == "overloaded_error"`. Regression
    /// guard for the conformance finding — fails against the old `_status`-ignoring code, which
    /// emitted `api_error`.
    #[test]
    fn write_error_503_maps_to_overloaded_error_not_api_error() {
        let type_for = |status: u16| {
            AnthropicWriter
                .write_error(status, "api_error", "upstream is overloaded")
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        };
        // The finding's exact scenario: cross-protocol 503 + generic `api_error` kind.
        assert_eq!(
            type_for(503).as_deref(),
            Some("overloaded_error"),
            "a 503 must surface as Anthropic's overloaded_error, not a generic api_error"
        );
        // The native 529 overload status maps the same way regardless of incoming kind.
        assert_eq!(type_for(529).as_deref(), Some("overloaded_error"));
        // A genuine 500-class server error (not the overload family) still maps to api_error —
        // the status override is scoped to 503/529 and does not swallow other server errors.
        assert_eq!(type_for(500).as_deref(), Some("api_error"));
        // The envelope is still well-formed and request_id is minted on the status-override path.
        let v = AnthropicWriter.write_error(503, "api_error", "upstream is overloaded");
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
        assert!(
            v.get("request_id")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.starts_with("req_")),
            "the status-override path must still mint a native request_id"
        );
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str()),
            Some("upstream is overloaded")
        );
    }

    /// Same-protocol (anthropic→anthropic) passthrough must preserve the upstream response identity:
    /// `read_response` captures `id`/`stop_sequence` (and model/stop_reason), and `write_response`
    /// re-emits them verbatim alongside the constant `type`/`role`. Mirrors the exact non-streaming
    /// `Message` shape an official SDK assembles.
    #[test]
    fn read_then_write_response_preserves_identity() {
        let body = serde_json::json!({
            "id": "msg_01XYZabc123",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "stop_sequence",
            "stop_sequence": "\n\nHuman:",
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });
        let ir = AnthropicReader.read_response(&body).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("msg_01XYZabc123"));
        assert_eq!(ir.model.as_deref(), Some("claude-opus-4-8"));
        assert_eq!(ir.stop_reason.as_deref(), Some("stop_sequence"));
        assert_eq!(ir.stop_sequence.as_deref(), Some("\n\nHuman:"));

        let out = AnthropicWriter.write_response(&ir);
        assert_eq!(
            out.get("id").and_then(|v| v.as_str()),
            Some("msg_01XYZabc123"),
            "id must round-trip verbatim on same-protocol passthrough"
        );
        assert_eq!(out.get("type").and_then(|v| v.as_str()), Some("message"));
        assert_eq!(out.get("role").and_then(|v| v.as_str()), Some("assistant"));
        assert_eq!(
            out.get("model").and_then(|v| v.as_str()),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            out.get("stop_reason").and_then(|v| v.as_str()),
            Some("stop_sequence")
        );
        assert_eq!(
            out.get("stop_sequence").and_then(|v| v.as_str()),
            Some("\n\nHuman:")
        );
    }

    /// Same-protocol streaming `message_start` passthrough must preserve `id`/`model` and re-emit
    /// the SDK-expected skeleton (`id`/`type`/`role`/`model`/`content`/`usage`).
    #[test]
    fn message_start_roundtrip_preserves_id_and_model() {
        let data = serde_json::json!({
            "message": {
                "id": "msg_stream_01",
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-4-8",
                "content": [],
                "usage": {"input_tokens": 7, "output_tokens": 0}
            }
        });
        let ev = AnthropicReader
            .read_response_event("message_start", &data)
            .expect("message_start parses");
        match &ev {
            IrStreamEvent::MessageStart { id, model, .. } => {
                assert_eq!(id.as_deref(), Some("msg_stream_01"));
                assert_eq!(model.as_deref(), Some("claude-opus-4-8"));
            }
            _ => panic!("expected MessageStart"),
        }
        let (et, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("writes message_start");
        assert_eq!(et, "message_start");
        let msg = out.get("message").expect("message object");
        assert_eq!(
            msg.get("id").and_then(|v| v.as_str()),
            Some("msg_stream_01")
        );
        assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
        assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
        assert_eq!(
            msg.get("model").and_then(|v| v.as_str()),
            Some("claude-opus-4-8")
        );
        assert!(
            msg.get("content").and_then(|c| c.as_array()).is_some(),
            "content[] must be present for an SDK to initialize its Message"
        );
    }

    /// Cross-protocol write (the backend supplied no Anthropic id, but a non-Anthropic reader
    /// recorded `created`) must SYNTHESIZE a protocol-correct `msg_`-prefixed id without panicking,
    /// and the synthesized id must be unique across calls (timestamp + atomic counter).
    #[test]
    fn cross_protocol_write_synthesizes_valid_unique_id() {
        let make = || crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "x".to_string(),
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
            model: Some("gpt-4o".to_string()),
            id: None,
            // `created` populated → marks a cross-protocol response → synthesis fires.
            created: Some(1_700_000_000),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out1 = AnthropicWriter.write_response(&make());
        let out2 = AnthropicWriter.write_response(&make());
        let id1 = out1.get("id").and_then(|v| v.as_str()).expect("synth id 1");
        let id2 = out2.get("id").and_then(|v| v.as_str()).expect("synth id 2");
        assert!(
            id1.starts_with("msg_"),
            "synthesized id must carry the Anthropic `msg_` prefix, got {id1}"
        );
        assert!(
            id1.len() > "msg_".len(),
            "synthesized id must have a suffix"
        );
        assert_ne!(id1, id2, "synthesized ids must be unique across calls");
        // Shape stays SDK-valid: type/role/content present, no panic.
        assert_eq!(out1.get("type").and_then(|v| v.as_str()), Some("message"));
    }

    /// Regression (recurring across rounds): an IR carrying NEITHER `id` NOR `created` — the exact
    /// shape a Bedrock Converse reader produces (its `read_response` returns `created: None` and no
    /// Anthropic id) — must STILL emit a synthesized `msg_`-prefixed id. `Message.id` is a REQUIRED,
    /// non-optional field in the official Anthropic SDK, so omitting it (the old `(None, None)` arm)
    /// produced an undecodable Message on the Bedrock→Anthropic non-stream path. `write_response`
    /// runs only on the cross-protocol translate path, so there is no same-protocol round-trip to
    /// keep id-less; the id must never be absent.
    #[test]
    fn write_response_synthesizes_id_when_neither_id_nor_created() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            // The Bedrock egress → Anthropic ingress non-stream path: both None.
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        let id = out.get("id").and_then(|v| v.as_str()).expect(
            "id is mandatory and must be synthesized even when id and created are both None",
        );
        assert!(
            id.starts_with("msg_"),
            "synthesized id must carry the Anthropic `msg_` prefix, got {id}"
        );
        assert!(
            id.len() > "msg_".len(),
            "synthesized id must have a non-empty suffix"
        );
    }

    /// `synth_message_id` must never panic and always returns a non-empty `msg_`-prefixed id.
    #[test]
    fn synth_message_id_is_well_formed() {
        let id = synth_message_id();
        assert!(id.starts_with("msg_"));
        assert!(id.len() > "msg_".len());
    }

    /// `synth_request_id` must never panic and always returns a non-empty `req_`-prefixed id.
    #[test]
    fn synth_request_id_is_well_formed() {
        let id = synth_request_id();
        assert!(id.starts_with("req_"));
        assert!(id.len() > "req_".len());
    }

    /// write_response_event(Error(...)) must serialize the NATIVE Anthropic in-stream error shape:
    /// event type `"error"`, with `error.type` carrying the provider signal AND a non-empty
    /// `error.message` (the SDK's `APIError` reads both). Regression guard for the message-omission
    /// and the JSON-key shape (a wrong key would silently break SDK decoding into a hang).
    #[test]
    fn write_response_event_error_serializes_native_shape() {
        let err = IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("rate_limit_error".to_string()),
            retry_after: None,
        };
        let (event_type, data) = AnthropicWriter
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("error event must serialize");
        assert_eq!(event_type, "error");
        // Top-level `type:"error"` discriminator must be present in the data body, matching every
        // other event arm and the documented native shape (`{"type":"error","error":{...}}`).
        assert_eq!(
            data.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "data body must carry the top-level `type`:\"error\" discriminator"
        );
        let error_obj = data.get("error").expect("error sub-object present");
        assert_eq!(
            error_obj.get("type").and_then(|t| t.as_str()),
            Some("rate_limit_error"),
            "error.type must carry the provider signal"
        );
        let message = error_obj
            .get("message")
            .and_then(|m| m.as_str())
            .expect("error.message must be present (SDK reads it)");
        assert!(
            !message.is_empty(),
            "error.message must be non-empty so the SDK's APIError is never undefined"
        );
        // Round-trips as valid JSON — no panic on the error path.
        let s = serde_json::to_string(&data).expect("must serialize");
        let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
    }

    /// When the upstream error event carries no `type`, the writer must emit `error.type: null`
    /// (not `""`) and still a non-empty `message`. Guards finding #7 (Option carried through, no
    /// `unwrap_or_default()`) end-to-end and finding #3 (message always present).
    #[test]
    fn write_response_event_error_null_type_when_signal_absent() {
        let err = IrError {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        };
        let (event_type, data) = AnthropicWriter
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("error event must serialize");
        assert_eq!(event_type, "error");
        assert_eq!(
            data.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "data body must carry the top-level `type`:\"error\" discriminator even when the inner error.type is null"
        );
        let error_obj = data.get("error").expect("error sub-object present");
        assert!(
            error_obj.get("type").map(|t| t.is_null()).unwrap_or(false),
            "error.type must be JSON null when no provider signal, not an empty string"
        );
        assert!(
            error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .map(|m| !m.is_empty())
                .unwrap_or(false),
            "error.message must still be present and non-empty"
        );
    }

    /// The reader must carry a missing error `type` through as `None` (not `Some("")`), so a
    /// `read -> write` of a type-less error event yields `error.type: null` rather than `""`.
    /// Regression guard for finding #7.
    #[test]
    fn read_error_event_without_type_carries_none() {
        let data = serde_json::json!({ "error": { "message": "boom" } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        match ev {
            IrStreamEvent::Error(err) => assert_eq!(
                err.provider_signal, None,
                "missing error.type must be None, not Some(\"\")"
            ),
            other => panic!("expected Error event, got {other:?}"),
        }
    }

    /// A reader-captured error type round-trips through the writer verbatim.
    #[test]
    fn read_error_event_with_type_round_trips() {
        let data = serde_json::json!({ "error": { "type": "overloaded_error" } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        let (_, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("writes error event");
        assert_eq!(
            out.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("overloaded_error")
        );
    }

    /// Regression for LOW #34: the streaming `error` reader hardcoded `StatusClass::ClientError`
    /// for EVERY error type, so a mid-stream transient/hard-down fault was misclassified as a client
    /// fault (`Disposition::ClientFault` records nothing) and the breaker took the wrong transition.
    /// The class must now derive from the upstream `error.type`, mirroring the HTTP classifier intent.
    /// This drives `read_response_event` end-to-end (not just the helper) so it fails against the old
    /// hardcoded code and passes after, AND asserts the downstream breaker disposition is correct.
    fn read_stream_error_class(error_type: &str) -> StatusClass {
        let data = serde_json::json!({ "error": { "type": error_type } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        match ev {
            IrStreamEvent::Error(err) => err.class,
            other => panic!("expected Error event, got {other:?}"),
        }
    }

    #[test]
    fn stream_error_overloaded_is_transient_not_client_fault() {
        assert_eq!(
            read_stream_error_class("overloaded_error"),
            StatusClass::Overloaded
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("overloaded_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::TransientUpstream,
            "a mid-stream overloaded_error is a transient upstream fault, not a client fault"
        );
    }

    #[test]
    fn stream_error_rate_limit_is_rate_limit_class() {
        assert_eq!(
            read_stream_error_class("rate_limit_error"),
            StatusClass::RateLimit
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("rate_limit_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::TransientUpstream
        );
    }

    #[test]
    fn stream_error_api_error_is_server_error_class() {
        assert_eq!(
            read_stream_error_class("api_error"),
            StatusClass::ServerError
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("api_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::TransientUpstream
        );
    }

    #[test]
    fn stream_error_timeout_is_timeout_class() {
        assert_eq!(
            read_stream_error_class("timeout_error"),
            StatusClass::Timeout
        );
    }

    #[test]
    fn stream_error_authentication_is_auth_hard_down() {
        assert_eq!(
            read_stream_error_class("authentication_error"),
            StatusClass::Auth
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("authentication_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::HardDown,
            "a mid-stream authentication_error must hard-down the lane, not record nothing"
        );
    }

    #[test]
    fn stream_error_permission_is_auth_hard_down() {
        assert_eq!(
            read_stream_error_class("permission_error"),
            StatusClass::Auth
        );
    }

    #[test]
    fn stream_error_billing_is_billing_hard_down() {
        assert_eq!(
            read_stream_error_class("billing_error"),
            StatusClass::Billing
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("billing_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::HardDown
        );
    }

    #[test]
    fn stream_error_invalid_request_stays_client_error() {
        assert_eq!(
            read_stream_error_class("invalid_request_error"),
            StatusClass::ClientError
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class("invalid_request_error"),
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::ClientFault,
            "a genuine client-fault error type must still classify as ClientFault"
        );
    }

    #[test]
    fn stream_error_not_found_and_too_large_are_client_error() {
        assert_eq!(
            read_stream_error_class("not_found_error"),
            StatusClass::ClientError
        );
        assert_eq!(
            read_stream_error_class("request_too_large"),
            StatusClass::ClientError
        );
    }

    #[test]
    fn stream_error_unknown_or_absent_type_falls_back_to_client_error() {
        // Unknown token: conservative non-penalizing fallback (records nothing, never trips a
        // healthy lane).
        assert_eq!(
            read_stream_error_class("some_future_error"),
            StatusClass::ClientError
        );
        // Absent type: the event carries no `type`, so the class defaults to ClientError too.
        let data = serde_json::json!({ "error": { "message": "boom" } });
        let ev = AnthropicReader
            .read_response_event("error", &data)
            .expect("error event parses");
        match ev {
            IrStreamEvent::Error(err) => {
                assert_eq!(err.class, StatusClass::ClientError);
                assert_eq!(err.provider_signal, None);
            }
            other => panic!("expected Error event, got {other:?}"),
        }
    }

    /// write_error must include a synthesized top-level `request_id` (`req_...`) to match the native
    /// Anthropic error envelope, alongside the `type`/`error` fields. Regression guard for finding #6.
    #[test]
    fn write_error_includes_synthesized_request_id() {
        let v = AnthropicWriter.write_error(429, "rate_limit", "slow down");
        let request_id = v
            .get("request_id")
            .and_then(|r| r.as_str())
            .expect("top-level request_id must be present");
        assert!(
            request_id.starts_with("req_"),
            "request_id must carry the Anthropic `req_` prefix, got {request_id}"
        );
        assert!(
            request_id.len() > "req_".len(),
            "request_id must have a suffix"
        );
        // The error envelope's other fields are untouched.
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("rate_limit_error")
        );
    }

    /// Finding #3 regression: a `system` field in ARRAY form must be read via `as_array()` (no
    /// `is_array()`/`unwrap()` pair on the request path) and yield one IR block per element without
    /// panicking. Guards that the unwrap-removal refactor preserves array-system behavior.
    #[test]
    fn read_request_array_system_parses_blocks() {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "system": [
                {"type": "text", "text": "you are helpful"},
                {"type": "text", "text": "be concise"}
            ],
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("array system must parse without panic");
        assert_eq!(ir.system.len(), 2, "both system text blocks must be read");
        match &ir.system[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "you are helpful"),
            other => panic!("expected text block, got {other:?}"),
        }
    }

    /// Finding #3 regression: a non-array, non-string `system` value (e.g. a number) must NOT panic
    /// — the refactored `as_array()`/`is_string()` guards simply produce no system blocks rather
    /// than reaching a `.unwrap()`. Direct guard that the unwrap is gone from the request path.
    #[test]
    fn read_request_non_array_non_string_system_is_ignored_no_panic() {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "system": 12345,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("unexpected system shape must not panic the request path");
        assert!(
            ir.system.is_empty(),
            "a non-array/non-string system yields no blocks (no unwrap panic)"
        );
    }

    /// Finding #3 regression: a `tool_result` block whose `content` is an ARRAY of nested blocks
    /// must be read via `as_array()` (no `is_array()`/`unwrap()`) and recurse into each nested
    /// block without panic. Exercises the read_block tool_result array branch.
    #[test]
    fn read_block_tool_result_array_content_parses() {
        let block = serde_json::json!({
            "type": "tool_result",
            "tool_use_id": "toolu_01",
            "content": [
                {"type": "text", "text": "result line 1"},
                {"type": "text", "text": "result line 2"}
            ]
        });
        let ir = read_block(&block).expect("tool_result array content must parse without panic");
        match ir {
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                assert_eq!(tool_use_id, "toolu_01");
                assert_eq!(content.len(), 2, "both nested blocks must be read");
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    /// Finding #3 regression: a `read_response` body whose top-level `content` is an array must be
    /// read via `as_array()` without the removed `unwrap()`. Guards the response-path array read.
    #[test]
    fn read_response_array_content_parses_no_unwrap() {
        let body = serde_json::json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "a"},
                {"type": "text", "text": "b"}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 2}
        });
        let ir = AnthropicReader
            .read_response(&body)
            .expect("array content must parse without panic");
        assert_eq!(ir.content.len(), 2);
    }

    /// Round-5 finding (id synthesis class): the fixed-width-counter encoding must be injective, so
    /// no `(ts, seq)` pair collides with an adjacent-second pair the bare `{:x}{:x}` scheme would
    /// merge. We can't control the real clock, but we CAN assert the synthesized ids are strictly
    /// unique across many rapid calls (same second, monotonic counter) — the exact regime where the
    /// old scheme collided. Also asserts the suffix is fixed-width (the counter padded to 16 hex).
    #[test]
    fn synth_message_id_no_collision_under_rapid_minting() {
        let n = 10_000;
        let ids: std::collections::HashSet<String> = (0..n).map(|_| synth_message_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "every synthesized message id must be unique (fixed-width counter is injective)"
        );
        // Every id matches the native Anthropic shape: `msg_` + `01` version marker + two
        // 12-digit base62 fields (unix second, counter) = 30 chars total, with the timestamp and
        // counter fields unambiguously separable (the fixed widths kill the bare-concat collision).
        // The 30-char total matches native `msg_01` + 24 random chars, removing the id-LENGTH tell
        // a client could use to distinguish a synthesized id.
        for id in &ids {
            assert_eq!(
                id.len(),
                30,
                "synthesized message id must match the native 30-char length, got {id}"
            );
            let suffix = id
                .strip_prefix("msg_01")
                .expect("msg_01 version-marker prefix");
            assert_eq!(
                suffix.len(),
                24,
                "the post-`01` token must be the native 24-char width, got {suffix}"
            );
            assert!(
                suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
                "the token is base62 (alphanumeric only), got {suffix}"
            );
        }
    }

    /// Round-5 finding (id synthesis class): request ids share the same fixed-width construction and
    /// must likewise never collide across rapid minting.
    #[test]
    fn synth_request_id_no_collision_under_rapid_minting() {
        let n = 10_000;
        let ids: std::collections::HashSet<String> = (0..n).map(|_| synth_request_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "every synthesized request id must be unique (fixed-width counter is injective)"
        );
    }

    /// Round-5 finding (image_url sentinel class): an IR Image carrying the "image_url" media_type
    /// sentinel (an https:// URL recorded by the OpenAI/Responses reader) must be written as
    /// Anthropic's native URL image source `{"type":"url","url":<url>}`, NOT as a base64 source with
    /// `media_type:"image_url"` (which Anthropic 400s).
    #[test]
    fn write_block_image_url_sentinel_emits_native_url_source() {
        let block = crate::ir::IrBlock::Image {
            media_type: "image_url".to_string(),
            data: "https://example.com/cat.png".to_string(),
        };
        let out = write_block(&block);
        assert_eq!(out.get("type").and_then(|t| t.as_str()), Some("image"));
        let source = out.get("source").expect("source present");
        assert_eq!(
            source.get("type").and_then(|t| t.as_str()),
            Some("url"),
            "image_url sentinel must map to Anthropic's url source type"
        );
        assert_eq!(
            source.get("url").and_then(|u| u.as_str()),
            Some("https://example.com/cat.png"),
            "the URL must be emitted natively, not as base64 data"
        );
        assert!(
            source.get("data").is_none(),
            "no base64 `data` field for a URL image source"
        );
        assert!(
            source.get("media_type").is_none(),
            "no `media_type:image_url` leak into the wire body"
        );
    }

    /// Round-5 finding (image_url sentinel class): a genuine base64 image (a real `image/*`
    /// media_type) must still take the base64 source path unchanged — the sentinel handling must not
    /// regress the common case.
    #[test]
    fn write_block_real_base64_image_unchanged() {
        let block = crate::ir::IrBlock::Image {
            media_type: "image/png".to_string(),
            data: "iVBORw0KGgo=".to_string(),
        };
        let out = write_block(&block);
        let source = out.get("source").expect("source present");
        assert_eq!(source.get("type").and_then(|t| t.as_str()), Some("base64"));
        assert_eq!(
            source.get("media_type").and_then(|m| m.as_str()),
            Some("image/png")
        );
        assert_eq!(
            source.get("data").and_then(|d| d.as_str()),
            Some("iVBORw0KGgo=")
        );
    }

    /// R19 #9/#11 (cross-protocol image data loss): an Anthropic URL-type image source
    /// `{"type":"url","url":...}` must round-trip through the `image_url` sentinel rather than
    /// silently flatten to empty base64 (the base64 path reads media_type/data, both absent from a
    /// url source). Old code: `media_type`/`data` both `""`; fixed code: `media_type:"image_url"`,
    /// `data:<url>`, and a re-write emits the native url source again.
    #[test]
    fn read_block_url_image_source_round_trips_via_sentinel() {
        let block_json = serde_json::json!({
            "type": "image",
            "source": { "type": "url", "url": "https://example.com/cat.png" }
        });
        let ir = read_block(&block_json).expect("url image source parses");
        match &ir {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(
                    media_type, "image_url",
                    "url source must map to the image_url sentinel, not empty base64 media_type"
                );
                assert_eq!(
                    data, "https://example.com/cat.png",
                    "the url must be preserved in `data`, not dropped to empty"
                );
            }
            other => panic!("expected IrBlock::Image, got {other:?}"),
        }
        // Round-trip: writing the parsed block must re-emit Anthropic's native url source.
        let out = write_block(&ir);
        let source = out.get("source").expect("source present");
        assert_eq!(source.get("type").and_then(|t| t.as_str()), Some("url"));
        assert_eq!(
            source.get("url").and_then(|u| u.as_str()),
            Some("https://example.com/cat.png")
        );
        assert!(
            source.get("data").is_none() && source.get("media_type").is_none(),
            "no base64 leak after round-trip"
        );
    }

    /// R19 #9/#11 (no regression): a genuine base64 image source must still parse to its real
    /// `image/*` media_type and base64 data — the url branch must not intercept it.
    #[test]
    fn read_block_base64_image_source_unchanged() {
        let block_json = serde_json::json!({
            "type": "image",
            "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" }
        });
        let ir = read_block(&block_json).expect("base64 image source parses");
        match ir {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, "iVBORw0KGgo=");
            }
            other => panic!("expected IrBlock::Image, got {other:?}"),
        }
    }

    /// R23 #9 (completeness): a valid native Anthropic content-block type the IR does not model
    /// (e.g. `document`) must NOT hard-error the whole request with a ClientError 400. Mirroring the
    /// OpenAI reader, `read_block` now degrades an unmodeled block to an empty Text block, preserving
    /// the turn. Against the old `_ => Err(ClientError)` catch-all this asserted `Err`, so this test
    /// fails on old code and passes after the named graceful-degradation arm.
    #[test]
    fn read_block_unmodeled_document_type_degrades_not_400() {
        let block_json = serde_json::json!({
            "type": "document",
            "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0=" }
        });
        let ir = read_block(&block_json)
            .expect("unmodeled native block (document) must degrade, not 400 a valid request");
        match ir {
            crate::ir::IrBlock::Text {
                text,
                cache_control,
                citations,
            } => {
                assert_eq!(text, "", "unmodeled block degrades to an empty text block");
                assert!(cache_control.is_none());
                assert!(citations.is_empty());
            }
            other => panic!("expected graceful IrBlock::Text degradation, got {other:?}"),
        }

        // A `redacted_thinking` block (another valid native type the IR does not model) must
        // likewise degrade rather than 400.
        let redacted = serde_json::json!({ "type": "redacted_thinking", "data": "abc123" });
        assert!(
            matches!(read_block(&redacted), Ok(crate::ir::IrBlock::Text { .. })),
            "redacted_thinking must degrade gracefully, not hard-error"
        );
    }

    /// R19 #10/#26 (synth id uniformity): `synth_id_with_prefix` must draw each base62 character
    /// uniformly via rejection sampling, NOT `byte % 62`. The old modulo over-represents characters
    /// 0..7 by ~25% (256 = 4*62 + 8). Mint a large burst and assert (a) every id is unique, (b) the
    /// per-character frequency of the low/biased band vs the high band is balanced within tolerance.
    #[test]
    fn synth_id_uniform_and_unique_under_burst() {
        let n = 20_000usize;
        let ids: Vec<String> = (0..n).map(|_| synth_request_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            n,
            "burst of synthesized ids must be collision-free"
        );

        // Index each token character into the base62 alphabet and tally how many land in the
        // over-represented band (alphabet positions 0..8, which a `% 62` bias inflates) vs the rest.
        let mut low_band = 0u64; // alphabet indices 0..8
        let mut other_band = 0u64; // alphabet indices 8..62
        for id in &ids {
            let token = id.strip_prefix("req_01").expect("req_01 prefix");
            for &b in token.as_bytes() {
                let idx = BASE62_ALPHABET
                    .iter()
                    .position(|&a| a == b)
                    .expect("token char is in the base62 alphabet");
                if idx < 8 {
                    low_band += 1;
                } else {
                    other_band += 1;
                }
            }
        }
        // Under a uniform draw the expected per-character probability is 1/62; the 8-char low band
        // should hold ~8/62 of all characters. The biased `% 62` would push the low band to ~10/62
        // (each of 0..7 drawn from 5 source bytes instead of 4 → +25%). Assert the observed low-band
        // share sits near 8/62 and well below the 9/62 a meaningful bias would reach.
        let total = low_band + other_band;
        let low_share = low_band as f64 / total as f64;
        let expected = 8.0 / 62.0;
        assert!(
            (low_share - expected).abs() < 0.01,
            "low-band share {low_share:.4} must be near uniform {expected:.4} (rejection sampling); \
             a `% 62` bias would push it toward {:.4}",
            9.0 / 62.0
        );
    }

    /// R19 #10/#26 (synth id shape preserved): rejection sampling must not change the native length
    /// or alphabet — `req_01` + 24 base62 chars = 30 total.
    #[test]
    fn synth_id_matches_native_length_and_alphabet() {
        let id = synth_request_id();
        assert_eq!(id.len(), 30, "native 30-char length");
        let token = id.strip_prefix("req_01").expect("req_01 prefix");
        assert_eq!(token.len(), 24, "24-char base62 token");
        assert!(
            token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "token is base62 alphanumeric, got {token}"
        );
    }

    /// R19 #27 (unchecked cast truncation): `max_tokens`/`top_k` larger than `u32::MAX` must drop to
    /// `None` via checked `try_from`, NOT silently truncate. Old code: `4_294_967_297 as u32` == 1,
    /// forwarding a corrupted cap. Fixed code: out-of-range → None.
    #[test]
    fn read_request_oversized_max_tokens_and_top_k_drop_to_none() {
        let body = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 4_294_967_297u64,
            "top_k": 8_589_934_592u64
        });
        let ir = AnthropicReader.read_request(&body).expect("request parses");
        assert_eq!(
            ir.max_tokens, None,
            "an over-u32 max_tokens must drop to None, not truncate to a small value"
        );
        assert_eq!(
            ir.top_k, None,
            "an over-u32 top_k must drop to None, not truncate to a small value"
        );
        // In-range values still survive the checked cast.
        let body2 = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 1024u64,
            "top_k": 40u64
        });
        let ir2 = AnthropicReader
            .read_request(&body2)
            .expect("request parses");
        assert_eq!(ir2.max_tokens, Some(1024));
        assert_eq!(ir2.top_k, Some(40));
    }

    /// R19 #28 (unsigned thinking 400): on the REQUEST side `write_message` must drop an assistant
    /// Thinking block whose `signature` is None (Anthropic 400s an unsigned thinking block), while a
    /// signed thinking block and surrounding text survive.
    #[test]
    fn write_message_drops_unsigned_thinking_block() {
        let msg = crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Thinking {
                    text: "unsigned reasoning".to_string(),
                    signature: None,
                },
                crate::ir::IrBlock::Thinking {
                    text: "signed reasoning".to_string(),
                    signature: Some("sig-abc".to_string()),
                },
                crate::ir::IrBlock::Text {
                    text: "the answer".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
            ],
        };
        let out = write_message(&msg);
        let content = out
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content array");
        assert_eq!(
            content.len(),
            2,
            "the unsigned thinking block must be dropped, signed thinking + text kept"
        );
        // The surviving thinking block is the signed one; no block lacks a signature.
        for block in content {
            if block.get("type").and_then(|t| t.as_str()) == Some("thinking") {
                assert!(
                    block.get("signature").and_then(|s| s.as_str()).is_some(),
                    "every emitted thinking block must carry a signature"
                );
            }
        }
        let texts: Vec<&str> = content
            .iter()
            .filter_map(|b| b.get("thinking").or_else(|| b.get("text")))
            .filter_map(|v| v.as_str())
            .collect();
        assert!(texts.contains(&"signed reasoning"));
        assert!(texts.contains(&"the answer"));
        assert!(!texts.contains(&"unsigned reasoning"));
    }

    /// R22 LOW #15 (empty-content class): when every content block is filtered out — e.g. an
    /// all-thinking assistant message whose unsigned thinking blocks are all dropped on the request
    /// path — `write_message` must emit `content: []` (an empty array, a valid zero-block message),
    /// NOT `content: ""` (an empty string, which Anthropic's Messages API rejects with a 400). The
    /// old code emitted the bare empty string; this guards the regression.
    #[test]
    fn write_message_emits_empty_array_when_all_blocks_dropped() {
        let msg = crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Thinking {
                    text: "unsigned reasoning A".to_string(),
                    signature: None,
                },
                crate::ir::IrBlock::Thinking {
                    text: "unsigned reasoning B".to_string(),
                    signature: None,
                },
            ],
        };
        let out = write_message(&msg);
        let content = out.get("content").expect("content key present");
        assert!(
            !content.is_string(),
            "content must not be a bare empty string (anthropic 400s an empty content string): {content:?}"
        );
        let arr = content
            .as_array()
            .expect("content must be an array when no blocks survive");
        assert!(
            arr.is_empty(),
            "every block was dropped, so the content array must be empty: {arr:?}"
        );
    }

    /// R22 LOW #15 (companion): a message with a single surviving block still emits a populated
    /// content ARRAY (never the empty-string fallback) — confirms the non-empty branch is intact
    /// after collapsing the old `if blocks.is_empty()` split.
    #[test]
    fn write_message_emits_array_for_surviving_block() {
        let msg = crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "kept".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        };
        let out = write_message(&msg);
        let arr = out
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content must be an array");
        assert_eq!(arr.len(), 1, "the single text block must survive: {arr:?}");
        assert_eq!(arr[0].get("text").and_then(|t| t.as_str()), Some("kept"));
    }

    /// R19 #28 (response reasoning untouched): the request-side filter must NOT affect the response
    /// path — `write_response` still surfaces an unsigned thinking block as a `thinking` content
    /// block (response reasoning has no signature requirement).
    #[test]
    fn write_response_keeps_unsigned_thinking_block() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Thinking {
                text: "visible reasoning".to_string(),
                signature: None,
            }],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("claude-3-5-sonnet".to_string()),
            id: Some("msg_123".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        let content = out
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content array");
        assert!(
            content
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking")),
            "response reasoning must still surface even without a signature"
        );
    }

    /// Round-5 finding (stream-start skeleton class): `message_start` must carry a `usage` object
    /// even when the IR `MessageStart.usage` is None (the OpenAI→Anthropic case). The native API
    /// always emits `usage:{input_tokens,output_tokens}` at stream open, and the TS SDK types it as
    /// required — a missing key crashes a client that reads `message.usage.input_tokens`.
    #[test]
    fn message_start_emits_zero_usage_when_none() {
        let ev = IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: Some(1_700_000_000),
            model: Some("gpt-4o".to_string()),
        };
        let (et, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("message_start writes");
        assert_eq!(et, "message_start");
        let usage = out
            .get("message")
            .and_then(|m| m.get("usage"))
            .expect("usage object must be present even when source usage is None");
        assert_eq!(
            usage.get("input_tokens").and_then(|v| v.as_u64()),
            Some(0),
            "input_tokens must default to 0, not be omitted"
        );
        assert_eq!(
            usage.get("output_tokens").and_then(|v| v.as_u64()),
            Some(0),
            "output_tokens must be 0 at stream open (native behavior)"
        );
    }

    /// Round-5 finding (stream-start skeleton class): when usage IS present, its values and the
    /// optional cache fields must flow through verbatim.
    #[test]
    fn message_start_emits_present_usage_with_cache_fields() {
        let ev = IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: Some(IrUsage {
                input_tokens: 42,
                output_tokens: 0,
                cache_creation_input_tokens: Some(5),
                cache_read_input_tokens: Some(7),
            }),
            id: Some("msg_x".to_string()),
            created: None,
            model: None,
        };
        let (_, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("message_start writes");
        let usage = out
            .get("message")
            .and_then(|m| m.get("usage"))
            .expect("usage present");
        assert_eq!(usage.get("input_tokens").and_then(|v| v.as_u64()), Some(42));
        assert_eq!(
            usage
                .get("cache_creation_input_tokens")
                .and_then(|v| v.as_u64()),
            Some(5)
        );
        assert_eq!(
            usage
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    /// Round-12 finding (terminal-event drop class): reading a `message_delta` whose data omits the
    /// `usage` key must STILL yield the `MessageDelta` event — `usage` is optional on read and must
    /// not be `?`-propagated, because dropping the event would discard the terminal `stop_reason` and
    /// leave the client unable to tell whether generation completed. Counters default to zero.
    #[test]
    fn read_message_delta_without_usage_preserves_terminal_event() {
        let data = serde_json::json!({
            "delta": { "stop_reason": "end_turn", "stop_sequence": null }
        });
        let ev = AnthropicReader
            .read_response_event("message_delta", &data)
            .expect("message_delta without usage must still parse, not be dropped");
        match ev {
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                assert_eq!(
                    stop_reason,
                    Some("end_turn".to_string()),
                    "terminal stop_reason must survive a missing usage"
                );
                assert_eq!(stop_sequence, None);
                assert_eq!(usage.input_tokens, 0, "missing usage zero-defaults input");
                assert_eq!(usage.output_tokens, 0, "missing usage zero-defaults output");
                assert_eq!(usage.cache_creation_input_tokens, None);
                assert_eq!(usage.cache_read_input_tokens, None);
            }
            other => panic!("expected MessageDelta event, got {other:?}"),
        }
    }

    /// Round-12 finding (terminal-event drop class): when `usage` IS present on a `message_delta`,
    /// its counters and optional cache fields flow through verbatim.
    #[test]
    fn read_message_delta_with_usage_flows_through() {
        let data = serde_json::json!({
            "delta": { "stop_reason": "max_tokens" },
            "usage": {
                "input_tokens": 11,
                "output_tokens": 22,
                "cache_creation_input_tokens": 3,
                "cache_read_input_tokens": 4
            }
        });
        let ev = AnthropicReader
            .read_response_event("message_delta", &data)
            .expect("message_delta parses");
        match ev {
            IrStreamEvent::MessageDelta { usage, .. } => {
                assert_eq!(usage.input_tokens, 11);
                assert_eq!(usage.output_tokens, 22);
                assert_eq!(usage.cache_creation_input_tokens, Some(3));
                assert_eq!(usage.cache_read_input_tokens, Some(4));
            }
            other => panic!("expected MessageDelta event, got {other:?}"),
        }
    }

    /// Round-12 finding (required-`model` conformance class): the non-stream `write_response` must
    /// emit `model` UNCONDITIONALLY — the official SDKs type `Message.model` as a required string, so
    /// a body that omits it fails to decode. On a Bedrock→Anthropic path where `resp.model` is None,
    /// the key must still be present (empty-string fallback), not dropped.
    #[test]
    fn write_response_emits_model_even_when_none() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("msg_x".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        assert_eq!(
            out.get("model").and_then(|v| v.as_str()),
            Some(""),
            "model is mandatory; absent source model must emit \"\" rather than omit the key"
        );
    }

    /// Round-12 finding (required-`model` conformance class): a present model round-trips verbatim.
    #[test]
    fn write_response_preserves_present_model() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("claude-opus-4-8".to_string()),
            id: Some("msg_x".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        assert_eq!(
            out.get("model").and_then(|v| v.as_str()),
            Some("claude-opus-4-8")
        );
    }

    /// Round-12 finding (required-`model` conformance class, streaming sibling): the streaming
    /// `message_start.message` must also carry `model` UNCONDITIONALLY — it's the skeleton the SDK
    /// reads to populate the assembled streaming Message. A None source model emits "" rather than
    /// dropping the mandatory field.
    #[test]
    fn message_start_emits_model_even_when_none() {
        let ev = IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, out) = AnthropicWriter
            .write_response_event(&ev)
            .expect("message_start writes");
        assert_eq!(
            out.get("message")
                .and_then(|m| m.get("model"))
                .and_then(|v| v.as_str()),
            Some(""),
            "message_start.message.model is mandatory; emit \"\" when source model is None"
        );
    }

    /// Round-6 finding #1 (cross-protocol `type` discriminator class): EVERY event the writer emits
    /// — including the Error variant — must carry a top-level `type` in its data body that matches
    /// the SSE event name. A native SDK dispatches on `data.type`; a missing/mismatched `type` is a
    /// decode failure and a proxy-signature tell. This sweeps all `write_response_event` arms, not
    /// just the cited Error arm.
    #[test]
    fn every_write_response_event_carries_matching_top_level_type() {
        let events = vec![
            IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            },
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("hi".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            },
            IrStreamEvent::MessageStop,
            IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("overloaded_error".to_string()),
                retry_after: None,
            }),
        ];
        for ev in events {
            let (event_type, data) = AnthropicWriter
                .write_response_event(&ev)
                .expect("event must serialize");
            let data_type = data
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or_else(|| {
                    panic!("data body for `{event_type}` must carry a `type` field")
                });
            assert_eq!(
                data_type, event_type,
                "data.type must equal the SSE event name for every arm"
            );
        }
    }

    /// Round-7 finding (stop_sequence conformance class, non-streaming sibling): a non-streaming
    /// `write_response` whose IR carried no stop sequence must still emit `stop_sequence: null` — a
    /// native `Message` always carries the key. Sweeps the same class beyond the cited streaming arm.
    /// IR-idempotence is preserved: re-reading a `null` stop_sequence yields `None` again.
    #[test]
    fn write_response_emits_null_stop_sequence_when_absent() {
        let resp = crate::ir::IrResponse {
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
            model: Some("claude-opus-4-8".to_string()),
            id: Some("msg_01abc".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        let ss = out
            .get("stop_sequence")
            .expect("stop_sequence key must be present in a non-streaming Message");
        assert!(
            ss.is_null(),
            "stop_sequence must be JSON null when absent, not omitted, got {ss:?}"
        );
        // IR-idempotence: re-reading the written body maps the null back to None.
        let reread = AnthropicReader.read_response(&out).expect("reread");
        assert_eq!(reread.stop_sequence, None);
    }

    /// Round-7 finding (stop_sequence conformance class): when present, the non-streaming
    /// `write_response` must carry the matched string (unchanged from prior behavior).
    #[test]
    fn write_response_emits_matched_stop_sequence_string() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: Some("stop_sequence".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("msg_01abc".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: Some("STOP".to_string()),
        };
        let out = AnthropicWriter.write_response(&resp);
        assert_eq!(
            out.get("stop_sequence").and_then(|s| s.as_str()),
            Some("STOP")
        );
    }

    /// Round-6 finding #2 (classify ordering class): a billing error whose body carries a message
    /// substring but NO structured `error.code` must still classify as Billing — the message check
    /// must not be gated behind the `error.code` guard. Mirror for the auth substring.
    #[test]
    fn classify_billing_substring_without_code_field() {
        // 200-status body (not 401/403/429), only a message — the regime the old nesting missed.
        let body =
            br#"{"error":{"type":"some_error","message":"insufficient balance to complete"}}"#;
        let sig = AnthropicReader.classify(StatusCode::OK, body);
        assert!(
            matches!(sig.class, StatusClass::Billing),
            "billing message substring must classify as Billing even without an error.code field, got {:?}",
            sig.class
        );

        let auth_body = br#"{"error":{"type":"some_error","message":"unauthorized request"}}"#;
        let auth_sig = AnthropicReader.classify(StatusCode::OK, auth_body);
        assert!(
            matches!(auth_sig.class, StatusClass::Auth),
            "auth message substring must classify as Auth even without an error.code field, got {:?}",
            auth_sig.class
        );
    }

    /// Round-6 finding #2 regression: the structured `error.code` 400/422 → ClientError path must
    /// still fire when the code IS present (the lift-out of the message checks must not regress it).
    #[test]
    fn classify_structured_code_still_maps_client_error() {
        let body = br#"{"error":{"type":"invalid_request_error","code":"400","message":"bad"}}"#;
        let sig = AnthropicReader.classify(StatusCode::BAD_REQUEST, body);
        assert!(
            matches!(sig.class, StatusClass::ClientError),
            "structured code 400 must still classify as ClientError, got {:?}",
            sig.class
        );
    }

    /// Round-6 finding #3 (id-shape distinguishability class): synthesized ids must match the native
    /// Anthropic shape — `<prefix>01` version marker, a mixed-case base62 alphabet (`[0-9A-Za-z]`,
    /// NOT lowercase hex), and a FIXED length — so a client inspecting id shape can't tell a
    /// synthesized id from a native one. Covers both `msg_` and `req_`.
    #[test]
    fn synth_ids_match_native_shape_base62_versioned_fixed_length() {
        let check = |id: &str, prefix: &str| {
            let suffix = id
                .strip_prefix(prefix)
                .unwrap_or_else(|| panic!("{id} must start with {prefix}"));
            assert!(
                suffix.starts_with("01"),
                "{id} must carry the native `01` version marker after the prefix"
            );
            let token = &suffix[2..];
            // 12 base62 digits per u64 field × 2 fields = 24 chars, fixed-width — matching the
            // native `<prefix>01` + 24-char token (30 chars total for `msg_`/`req_`).
            assert_eq!(
                token.len(),
                24,
                "token must be fixed-length (2×12 base62 digits), got `{token}`"
            );
            assert!(
                token.bytes().all(|b| b.is_ascii_alphanumeric()),
                "token must be mixed-case base62 (no hex-only/non-alphanumeric chars), got `{token}`"
            );
            // Round-15 HIGH (clock+counter fingerprint): the previous `(unix_second, counter)`
            // encoding base62-padded the timestamp to a fixed `000000…` run, so every synthesized
            // id began `01000000…` — a structural tell impossible in a native (CSPRNG) Anthropic id.
            // Assert the CSPRNG-backed token carries no run of six or more leading '0' chars.
            let leading_zeros = token.bytes().take_while(|&b| b == b'0').count();
            assert!(
                leading_zeros < 6,
                "token must not have a 6+ run of leading '0' (the clock+counter fingerprint), got `{token}`"
            );
        };
        check(&synth_message_id(), "msg_");
        check(&synth_request_id(), "req_");
    }

    /// Round-15 HIGH regression: synthesized ids must come from the CSPRNG, not a deterministic
    /// clock+counter scheme. Two back-to-back calls within the same clock tick must differ (the old
    /// scheme relied on the second-resolution clock for its high bits, so rapid calls within one
    /// second shared a 12-char prefix and differed only in the counter tail — here the leading 13
    /// chars are random and the counter backstop still forces distinctness). Also asserts the token
    /// is not all-zero (which would mean the RNG path silently produced no entropy).
    #[test]
    fn synth_ids_are_csprng_unique_within_tick() {
        let a = synth_message_id();
        let b = synth_message_id();
        assert_ne!(a, b, "two synthesized message ids must never collide");
        let ra = synth_request_id();
        let rb = synth_request_id();
        assert_ne!(ra, rb, "two synthesized request ids must never collide");

        // The full 24-char token must never be all-'0' (that would mean no entropy AND a degenerate
        // counter overlay) — a stronger form of the no-leading-zero-run check.
        for id in [&a, &b, &ra, &rb] {
            let token = &id[id.len() - 24..];
            assert!(
                token.bytes().any(|c| c != b'0'),
                "token must carry entropy, not be all-zero, got `{token}`"
            );
        }
    }

    /// Round-15 HIGH regression: the leading characters of the token must vary across calls. The old
    /// clock+counter scheme produced an IDENTICAL leading prefix for every id minted in the same
    /// second; the CSPRNG scheme keeps the leading 13 chars random, so across many samples the first
    /// character must take on more than one distinct value (a deterministic prefix would yield one).
    #[test]
    fn synth_id_leading_chars_are_not_constant() {
        let mut firsts = std::collections::HashSet::new();
        for _ in 0..64 {
            let id = synth_message_id();
            let token = &id[id.len() - 24..];
            firsts.insert(token.as_bytes()[0]);
        }
        assert!(
            firsts.len() > 1,
            "leading token char is constant across 64 samples — looks deterministic, not CSPRNG"
        );
    }

    /// Round-15 MEDIUM regression: the modeled-key filter (now a sorted `binary_search` slice rather
    /// than a per-request `HashSet`) must still route every unmodeled top-level key into `extra` and
    /// must still EXCLUDE every modeled key. Guards against a typo/ordering break in `MODELED_KEYS`.
    #[test]
    fn read_request_routes_unmodeled_keys_to_extra() {
        let body = serde_json::json!({
            "model": "claude-3",
            "system": "sys",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [],
            "max_tokens": 10,
            "temperature": 0.5,
            "top_p": 0.9,
            "top_k": 40,
            "stop_sequences": ["x"],
            "stream": true,
            // Unmodeled passthrough keys:
            "metadata": {"user_id": "u1"},
            "service_tier": "auto"
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("request must parse");
        assert!(
            ir.extra.contains_key("metadata"),
            "unmodeled `metadata` must flow into extra"
        );
        assert!(
            ir.extra.contains_key("service_tier"),
            "unmodeled `service_tier` must flow into extra"
        );
        for modeled in [
            "model",
            "system",
            "messages",
            "tools",
            "max_tokens",
            "temperature",
            "top_p",
            "top_k",
            "stop_sequences",
            "stream",
        ] {
            assert!(
                !ir.extra.contains_key(modeled),
                "modeled key `{modeled}` must NOT leak into extra"
            );
        }
    }

    /// Round-13 HIGH (error-message proxy vocabulary): the in-stream `error` event's
    /// `error.message` must NEVER carry reverse-proxy vocabulary ("upstream", "gateway",
    /// "backend", "proxy"). When a provider signal is present, the message is the provider's own
    /// type token VERBATIM (no router prefix).
    #[test]
    fn write_response_event_error_message_has_no_proxy_vocabulary() {
        for (signal, expected) in [
            (Some("overloaded_error".to_string()), "overloaded_error"),
            (Some("rate_limit_error".to_string()), "rate_limit_error"),
            (None, "an error occurred while streaming the response"),
        ] {
            let err = IrError {
                class: StatusClass::ServerError,
                provider_signal: signal.clone(),
                retry_after: None,
            };
            let (_, data) = AnthropicWriter
                .write_response_event(&IrStreamEvent::Error(err))
                .expect("error event must serialize");
            let message = data
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .expect("error.message must be present");
            assert_eq!(
                message, expected,
                "message must be native-plausible (verbatim signal or generic fallback) for signal {signal:?}"
            );
            let lower = message.to_lowercase();
            for tell in ["upstream", "gateway", "backend", "proxy", "router"] {
                assert!(
                    !lower.contains(tell),
                    "error.message leaks proxy vocabulary `{tell}`: `{message}`"
                );
            }
        }
    }

    /// Finding #10 regression: a 200 `read_response` body that OMITS `usage` must read back
    /// successfully with each counter zero-defaulted, NOT 400. The prior `obj.get("usage").ok_or?`
    /// hard-required the field — inconsistent with this protocol's own streaming readers
    /// (`message_start`/`message_delta` already zero-default a missing `usage`) and the gemini/cohere
    /// tolerance. Fails against the old `ok_or?` (which returned Err), passes after.
    #[test]
    fn read_response_without_usage_zero_defaults_no_error() {
        let body = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}]
            // NOTE: no `usage` field
        });
        let ir = AnthropicReader
            .read_response(&body)
            .expect("a 200 body without usage must read back, not 400");
        assert_eq!(ir.usage.input_tokens, 0, "missing usage → input_tokens 0");
        assert_eq!(ir.usage.output_tokens, 0, "missing usage → output_tokens 0");
        assert_eq!(ir.usage.cache_creation_input_tokens, None);
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        match &ir.content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi"),
            other => panic!("expected text block, got {other:?}"),
        }
    }

    /// Finding #11 regression (ROOT fix): a wire `role:"system"` message inside `messages` must be
    /// PROMOTED into `IrRequest.system` by `read_request`, not pushed into `req.messages` as an
    /// `IrRole::System` message. Anthropic's Messages API has no `system` role in `messages`
    /// (system goes top-level), so the writer must never see a System message. Guards the root.
    #[test]
    fn read_request_promotes_system_role_message_into_system_blocks() {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "messages": [
                {"role": "system", "content": "you are terse"},
                {"role": "user", "content": "hi"}
            ],
            "max_tokens": 16
        });
        let ir = AnthropicReader
            .read_request(&body)
            .expect("system-role message must parse, not panic");
        // The system message was promoted out of `messages` into `system`.
        assert!(
            ir.messages
                .iter()
                .all(|m| m.role != crate::ir::IrRole::System),
            "no IrRole::System message may remain in req.messages after read_request"
        );
        assert_eq!(
            ir.messages.len(),
            1,
            "only the user message survives in messages"
        );
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        assert_eq!(
            ir.system.len(),
            1,
            "system content promoted into req.system"
        );
        match &ir.system[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "you are terse"),
            other => panic!("expected promoted system text block, got {other:?}"),
        }
    }

    /// Finding #11 regression (writer): `write_request` must NEVER emit a message with
    /// `role:"system"` — even for a CROSS-PROTOCOL IR that still carries an `IrRole::System` message
    /// in `req.messages` (one that never passed through Anthropic's own `read_request` promotion).
    /// The writer folds it into the top-level `system` field and filters it out of `messages`,
    /// mirroring the gemini/bedrock writers. Fails against old code (which emitted `role:"system"`).
    #[test]
    fn write_request_never_emits_system_role_message() {
        let req = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::System,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "be terse".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "hi".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: Some(16),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: Vec::new(),
            stream: false,
            extra: serde_json::Map::new(),
        };
        let out = AnthropicWriter.write_request(&req);
        let messages = out
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array must be present");
        for msg in messages {
            assert_ne!(
                msg.get("role").and_then(|r| r.as_str()),
                Some("system"),
                "write_request must never emit an Anthropic message with role:\"system\""
            );
        }
        assert_eq!(messages.len(), 1, "only the user message remains");
        assert_eq!(
            messages[0].get("role").and_then(|r| r.as_str()),
            Some("user")
        );
        // The system content was folded into the top-level `system` field.
        let system = out
            .get("system")
            .and_then(|s| s.as_array())
            .expect("system content must be promoted to top-level system field");
        assert_eq!(system.len(), 1);
        assert_eq!(
            system[0].get("text").and_then(|t| t.as_str()),
            Some("be terse")
        );
    }

    /// Finding #11 regression (writer unit): a direct `write_message` call on an `IrRole::System`
    /// message must NOT emit `role:"system"` (the invalid Anthropic role). Defense-in-depth: even if
    /// a future caller bypasses `write_request`, the writer can never produce the rejected role.
    #[test]
    fn write_message_system_role_does_not_emit_system() {
        let msg = crate::ir::IrMessage {
            role: crate::ir::IrRole::System,
            content: vec![crate::ir::IrBlock::Text {
                text: "x".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        };
        let out = write_message(&msg);
        assert_ne!(
            out.get("role").and_then(|r| r.as_str()),
            Some("system"),
            "write_message must never emit role:\"system\" for an IrRole::System message"
        );
    }
}
