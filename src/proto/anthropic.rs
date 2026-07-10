// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Anthropic protocol reader/writer implementation.

use super::*;

/// Value of the required `anthropic-version` request header (the Messages API version busbar
/// targets). Bump when adopting a newer Anthropic API version.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Mixed-case base62 alphabet (`[0-9A-Za-z]`), UPPERCASE-FIRST, matching the character set/ordering of
/// a native Anthropic id token. A native `msg_`/`req_` id is `01` followed by a fixed-length mixed-case
/// alphanumeric token — NOT lowercase hex — so encoding the synthesized suffix in this alphabet (rather
/// than bare `{:x}`) removes the alphabet/length/version-prefix distinguishability tell. DISTINCT from
/// the shared `crate::proto::BASE62_ALPHABET` (lowercase-first): named `ANTHROPIC_NATIVE_ALPHABET` so
/// the two can never be confused — `synth_id_with_prefix` (body ids) needs THIS uppercase-first
/// ordering, while `synth_anthropic_request_id` (response-header id) deliberately uses the shared one.
const ANTHROPIC_NATIVE_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The response-header name a native Anthropic endpoint always carries (the SDK reads it into
/// `APIError.request_id` / `Message._request_id`). Defined here (the Anthropic dialect's home) and
/// used within this module; surfaced externally only via the writer vtable
/// (`AnthropicWriter::ingress_response_request_id` / `ingress_relayed_response_header_names`), so
/// the sites that attach it (forward.rs success path) and capture it from upstream cannot drift on
/// spelling.
const HDR_REQUEST_ID: &str = "request-id";

/// Width of a synthesized Anthropic id's token (the part after the `01` version marker): a native
/// `msg_`/`req_` id is `<prefix>01` followed by a fixed-width 24-char mixed-case base62 token, so
/// `msg_`/`req_` + `01` + 24 = 30 chars total. Matching this exact length AND alphabet is what keeps
/// the synthesized id structurally indistinguishable from a native one.
const SYNTH_ID_TOKEN_LEN: usize = 24;

/// SSE event-type strings emitted in the `event:` header of each native Anthropic stream frame.
const EVT_MESSAGE_START: &str = "message_start";
const EVT_CONTENT_BLOCK_START: &str = "content_block_start";
const EVT_CONTENT_BLOCK_DELTA: &str = "content_block_delta";
const EVT_CONTENT_BLOCK_STOP: &str = "content_block_stop";
const EVT_MESSAGE_DELTA: &str = "message_delta";
const EVT_MESSAGE_STOP: &str = "message_stop";

/// `content_block_delta` sub-type values (`delta.type` field).
const DELTA_TYPE_TEXT: &str = "text_delta";
const DELTA_TYPE_THINKING: &str = "thinking_delta";
const DELTA_TYPE_INPUT_JSON: &str = "input_json_delta";
const DELTA_TYPE_SIGNATURE: &str = "signature_delta";
const DELTA_TYPE_CITATIONS: &str = "citations_delta";

/// Native Anthropic `stop_reason` token values.
const STOP_END_TURN: &str = "end_turn";
const STOP_MAX_TOKENS: &str = "max_tokens";
const STOP_STOP_SEQUENCE: &str = "stop_sequence";
const STOP_TOOL_USE: &str = "tool_use";
const STOP_PAUSE_TURN: &str = "pause_turn";
const STOP_REFUSAL: &str = "refusal";

/// Anthropic content block `type` values not covered by the delta sub-type constants above.
const BLOCK_TYPE_REDACTED_THINKING: &str = "redacted_thinking";

/// Anthropic error `type` strings used in error envelopes and in-stream error events.
const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
const ERR_TYPE_API_ERROR: &str = "api_error";
const ERR_TYPE_TIMEOUT: &str = "timeout_error";
const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
const ERR_TYPE_PERMISSION: &str = "permission_error";
const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Anthropic citation `type` tag values (the `type` field on each citation object).
const CITATION_TYPE_CHAR: &str = "char_location";
const CITATION_TYPE_PAGE: &str = "page_location";
const CITATION_TYPE_CONTENT_BLOCK: &str = "content_block_location";

/// The sole valid `cache_control.type` Anthropic exposes today.
const CACHE_KIND_EPHEMERAL: &str = "ephemeral";

/// Header names used when attaching Anthropic credentials to upstream requests.
const HDR_X_API_KEY: &str = "x-api-key";
const HDR_ANTHROPIC_VERSION: &str = "anthropic-version";

/// Credential prefix strings used to classify a raw key into its native Anthropic scheme.
const CRED_PREFIX_API_KEY: &str = "sk-ant-api";
const CRED_PREFIX_OAUTH: &str = "sk-ant-oat";

/// The upstream path this writer targets on the Anthropic Messages API.
const PATH_UPSTREAM: &str = "/v1/messages";

/// HTTP status codes that Anthropic (and cross-protocol upstreams) use to signal overload.
const STATUS_OVERLOADED: u16 = 503;
const STATUS_ANTHROPIC_OVERLOADED: u16 = 529;

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
/// (mirroring the sibling `synth_anthropic_request_id` and `openai_chat::synth_completion_id`). The
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
    // mirroring `openai_chat::synth_completion_id` (the other rejection-sampling base62 synth; the sibling
    // `synth_anthropic_request_id` reaches a uniform distribution differently, via u128
    // division). On an entropy failure we leave the remaining '0' fill rather than panic; no counter.
    // Same ordering-independent reduction cutoff as every other base62 synth (4 * 62 = 248); only
    // this module's ALPHABET *ordering* (uppercase-first) is intentionally local.
    const BASE62_REJECT_FLOOR: u8 = crate::proto::BASE62_REJECT_THRESHOLD;
    let mut token = [b'0'; SYNTH_ID_TOKEN_LEN];
    let mut filled = 0usize;
    'outer: while filled < SYNTH_ID_TOKEN_LEN {
        let mut batch = [0u8; SYNTH_ID_TOKEN_LEN];
        if getrandom::fill(&mut batch).is_err() {
            // Near-impossible entropy failure: keep the remaining '0' fill rather than panic.
            break 'outer;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            token[filled] = ANTHROPIC_NATIVE_ALPHABET[(byte % 62) as usize];
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

/// Mint a protocol-correct Anthropic request id (`req_01<token>`) for the `request-id` RESPONSE HEADER
/// a native Anthropic response always carries. The official SDK reads this header into
/// `APIError.request_id` / `Message._request_id` (NOT the body), so a busbar anthropic response that
/// omitted it left `request_id == None` — impossible against the real API and a deterministic proxy
/// tell. Used by `forward.rs` on anthropic-ingress success/relay 2xx responses that have NO upstream
/// `request-id` to forward (the error path mirrors the writer's own body `request_id` into the header
/// instead; the same-protocol passthrough forwards the UPSTREAM `request-id` verbatim and never calls
/// this). The shape mirrors a native id EXACTLY: the `req_` prefix, the `01` version marker, then a
/// fixed-width 24-char mixed-case base62 token from the OS CSPRNG — `req_01` + 24 = 30 chars
/// total, matching `synth_id_with_prefix("req_")` (used for the body `request_id`) so the
/// response-header length is not a fingerprint tell (a 22-char value would be 8 chars short of
/// native). Returns `None` (caller OMITS the header) only if entropy is unavailable — on the request
/// path, must never panic. Uses the SHARED `crate::proto::BASE62_ALPHABET` (lowercase-first ordering)
/// deliberately — NOT this module's local uppercase-first `ANTHROPIC_NATIVE_ALPHABET` — preserving the
/// exact distribution it had when it lived in `proto::mod`.
pub(crate) fn synth_anthropic_request_id() -> Option<String> {
    const ALPHABET: &[u8; 62] = crate::proto::BASE62_ALPHABET;
    // 24 base62 chars (≈143 bits) of CSPRNG entropy. A u128 holds at most 12 base62 digits worth of
    // headroom safely (62^12 < 2^128), so build the 24-char token from two independent 9-byte (72-bit)
    // draws, each emitting 12 base62 digits — collision-free in practice and matching the native
    // `req_01` + 24 = 30-char shape.
    let mut token = [0u8; 24];
    for half in 0..2 {
        let mut buf = [0u8; 9];
        getrandom::fill(&mut buf).ok()?;
        // 72 bits → 12 base62 digits (62^12 > 2^71, so 9 bytes fit in 12 digits).
        let mut n = buf.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128);
        for slot in token[half * 12..half * 12 + 12].iter_mut().rev() {
            *slot = ALPHABET[(n % 62) as usize];
            n /= 62;
        }
    }
    // token is ASCII base62, always valid UTF-8.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    Some(format!("req_01{token}"))
}

/// Upper bound on an upstream-supplied streaming content-block index. Anthropic's Messages API
/// numbers blocks densely from 0; a real response has a small handful, never a sparse pathological
/// index. An upstream-controlled `index` flows into the IR (`BlockStart`/`BlockDelta`/`BlockStop`)
/// and then into a downstream WRITER that allocates/serializes against it (e.g. `GeminiWriter`'s
/// `open_tools` set, the Bedrock `contentBlockIndex` field), so a hostile/buggy backend sending a
/// huge `index` (up to `u64::MAX`) could drive a pathological allocation/serialization. CLAMP every
/// read site to this bound before the value enters the IR, mirroring the Bedrock reader's
/// `MAX_CONTENT_BLOCK_INDEX` (same 1023 cap), the OpenAI reader's `MAX_TOOL_INDEX`, and the Cohere
/// reader's `MAX_TOOL_FRAME_INDEX`. 1023 is far above any legitimate block count yet bounds the
/// downstream allocation. Cross-protocol sibling of those clamps.
const MAX_ANTHROPIC_BLOCK_INDEX: u64 = 1023;

/// Read a streaming event's `index`, requiring it to be present and numeric (returns `None` to drop
/// the event otherwise, matching the prior `.as_u64()?` semantics), and CLAMP it to
/// `MAX_ANTHROPIC_BLOCK_INDEX` before narrowing to `usize`. Shared by the three `content_block_*`
/// read sites so the bound can never drift between them. Mirrors `bedrock::clamp_content_block_index`
/// (that reader defaults a missing index to 0; the Anthropic stream instead drops an event with no
/// index, preserving this protocol's stricter `?`-on-missing behavior — the clamp is the additive
/// hardening, the presence requirement is unchanged).
fn read_clamped_block_index(data: &serde_json::Value) -> Option<usize> {
    data.get("index")
        .and_then(|i| i.as_u64())
        .map(|v| v.min(MAX_ANTHROPIC_BLOCK_INDEX) as usize)
}

/// Clamp a temperature to Anthropic's native `[0.0, 1.0]` range, returning `(clamped, was_clamped)`
/// where `was_clamped` is `true` iff the clamp ACTUALLY changed the value. OpenAI / Responses
/// accept temperature up to 2.0, so a cross-protocol request
/// can carry a value Anthropic's API rejects with a 422; the writer forwards the closest valid value
/// instead of bouncing a 422, and uses `was_clamped` to emit a `warn!` so the mutation is NOT silent.
/// Factored out so the non-silent-on-change contract is unit-testable without a tracing subscriber.
fn clamp_temperature_for_anthropic(temperature: f64) -> (f64, bool) {
    // Guard against non-finite input (NaN/±Inf): `f64::clamp` panics on a NaN bound but not a NaN
    // value, yet a NaN/Inf temperature is not a "real value clamped from range" — return it unchanged
    // with was_clamped=false so the helper is total. This is confirmed unreachable via valid JSON
    // (sonic_rs rejects NaN/Inf at parse), so it is a defensive no-op, not a behavior change.
    if !temperature.is_finite() {
        return (temperature, false);
    }
    let clamped = temperature.clamp(0.0, 1.0);
    (clamped, clamped != temperature)
}

#[derive(Clone)]
pub(crate) struct AnthropicReader;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body once and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (error paths are already degraded; avoid the extra
        // parse+alloc on every non-2xx response).
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
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
        //
        // GATE the message-scan override on a request-SIZE status (400 Bad Request / 413 Payload Too
        // Large) — the only statuses under which an oversized-prompt body is the authoritative signal.
        // Cross-protocol sibling of the Cohere `body_signals_context_length` gate. Without
        // the gate, ANY non-2xx whose body merely mentions a token/length phrase was reclassified to
        // context_length: a 401/403 ("...invalid token...") or a 429 ("...rate limit on tokens...")
        // would be turned into a non-penalizing ContextLength fail-over, so the breaker never recorded
        // the auth/rate-limit fault and the lane stayed "healthy" while hard-down or throttled. By
        // confining the override to 400/413, a 401/403/429 that happens to mention tokens keeps its
        // auth/rate-limit disposition and is penalized by the breaker as it should be.
        let status_code = status.as_u16();
        let is_request_size_status = status_code == 400 || status_code == 413;
        let provider_code = provider_code.or_else(|| {
            if !is_request_size_status {
                return None;
            }
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("prompt is too long")
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
                Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
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
        if let Ok(json) = crate::json::parse::<serde_json::Value>(body) {
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
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
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
            .and_then(|v| u32::try_from(v).ok())
            // Treat `max_tokens: 0` as absent (matches the OpenAI/Gemini/Bedrock/Cohere/Responses
            // readers). A zero cap is meaningless (no output budget) and would force an invalid body
            // on egress; dropping it to None lets the target apply its own default.
            .filter(|&v| v > 0);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        let top_k = obj
            .get("top_k")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Anthropic's native `stop_sequences` is an array of strings.
        let stop = crate::ir::read_stop_sequences(obj.get("stop_sequences"));
        // Anthropic `tool_choice` is an object: {type:"auto"|"any"|"tool"|"none", name?}. Normalize
        // into the IR union so forced/targeted tool use survives the cross-protocol seam.
        let tool_choice = read_anthropic_tool_choice(obj.get("tool_choice"));
        // `disable_parallel_tool_use` rides INSIDE Anthropic's tool_choice object; normalize it
        // inverted ("parallel allowed?") so it carries to OpenAI's top-level `parallel_tool_calls`.
        let parallel_tool_calls = obj
            .get("tool_choice")
            .and_then(|tc| tc.get("disable_parallel_tool_use"))
            .and_then(|v| v.as_bool())
            .map(|disabled| !disabled);
        // `metadata.user_id` is Anthropic's spelling of OpenAI's `user`; promote it so it carries
        // across the seam. The `metadata` object itself still rides `extra` (unmodeled), keeping
        // same-protocol fidelity byte-exact.
        let user = obj
            .get("metadata")
            .and_then(|m| m.get("user_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // The request-level `thinking` param (the ASK, not the response content blocks):
        // {type:"enabled", budget_tokens:N} promotes into the IR reasoning ask so it can carry to
        // Gemini's thinkingBudget or OpenAI's reasoning_effort. Any other form ({type:"disabled"},
        // malformed) stays in `extra` untouched: same-protocol fidelity, and foreign targets treat
        // an absent ask as off anyway.
        let reasoning = obj
            .get("thinking")
            .filter(|t| t.get("type").and_then(|v| v.as_str()) == Some("enabled"))
            .and_then(|t| t.get("budget_tokens"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .map(crate::ir::IrReasoningAsk::Budget);
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
            "tool_choice",
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
        // A PROMOTED thinking ask must not also ride extra (the writer re-emits it from the typed
        // field; a duplicate from extra would double-emit on a translated same-protocol hop).
        if reasoning.is_some() {
            extra.remove("thinking");
        }

        // (No ingress sentinel scrub needed anymore: a client cannot forge a redacted-reasoning block.
        // `redacted` is a TYPED flag only the Anthropic/Bedrock readers set on a genuine
        // `redacted_thinking`/`redactedContent` block — a client-supplied `signature` string can never
        // mark a block redacted, so the old `__busbar` sentinel forgery vector is structurally closed.)

        Ok(crate::ir::IrRequest {
            reasoning,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user,
            parallel_tool_calls,
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k,
            stop,
            tool_choice,
            stream,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra,
        })
    }

    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        match event_type {
            EVT_MESSAGE_START => {
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
            EVT_CONTENT_BLOCK_START => {
                let index = read_clamped_block_index(data)?;
                let block = data.get("content_block")?;
                let block_type = block.get("type").and_then(|t| t.as_str())?;
                let meta = match block_type {
                    "text" => IrBlockMeta::Text,
                    "thinking" => IrBlockMeta::Thinking,
                    STOP_TOOL_USE => {
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
            EVT_CONTENT_BLOCK_DELTA => {
                let index = read_clamped_block_index(data)?;
                let delta_val = data.get("delta")?;
                let delta_type = delta_val.get("type").and_then(|t| t.as_str())?;
                let delta = match delta_type {
                    DELTA_TYPE_TEXT => {
                        let text = delta_val
                            .get("text")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::TextDelta(text)
                    }
                    DELTA_TYPE_THINKING => {
                        let thinking = delta_val
                            .get("thinking")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::ThinkingDelta(thinking)
                    }
                    DELTA_TYPE_INPUT_JSON => {
                        let json = delta_val
                            .get("partial_json")
                            .or_else(|| delta_val.get("input_json"))
                            .and_then(|j| j.as_str())
                            .map(String::from)?;
                        IrDelta::InputJsonDelta(json)
                    }
                    DELTA_TYPE_SIGNATURE => {
                        let signature = delta_val
                            .get("signature")
                            .and_then(|s| s.as_str())
                            .map(String::from)?;
                        IrDelta::SignatureDelta(signature)
                    }
                    // L2-5 STREAMING citation: a native Anthropic `content_block_delta` whose
                    // `delta.type == "citations_delta"` carries a single `citation` object (one of
                    // the four citation variants). Reuse `read_citation` so the neutral fields AND
                    // the byte-exact `raw` escape hatch are filled (same as the non-stream path),
                    // then carry it as `IrDelta::CitationsDelta` (one citation per delta). Without
                    // this arm a streamed grounding/web-search citation was silently dropped.
                    DELTA_TYPE_CITATIONS => {
                        let citation_val = delta_val.get("citation")?;
                        IrDelta::CitationsDelta(vec![read_citation(citation_val)])
                    }
                    _ => return None,
                };
                Some(IrStreamEvent::BlockDelta { index, delta })
            }
            EVT_CONTENT_BLOCK_STOP => {
                let index = read_clamped_block_index(data)?;
                Some(IrStreamEvent::BlockStop { index })
            }
            EVT_MESSAGE_DELTA => {
                let delta = data.get("delta")?;
                let stop_reason = delta
                    .get("stop_reason")
                    .and_then(|r| r.as_str())
                    .map(read_anthropic_stop_reason);
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
            EVT_MESSAGE_STOP => Some(IrStreamEvent::MessageStop),
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
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;

        // Parse role (should be "assistant" for responses)
        let role_str = obj.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let role = match role_str {
            "assistant" => crate::ir::IrRole::Assistant,
            _ => {
                return Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
                    retry_after: None,
                })
            }
        };

        // Parse content blocks
        let content_val = obj.get("content").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
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
            .map(read_anthropic_stop_reason);

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
            logprobs: Vec::new(),
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
        Some(ERR_TYPE_OVERLOADED) => StatusClass::Overloaded,
        Some(ERR_TYPE_RATE_LIMIT) => StatusClass::RateLimit,
        Some(ERR_TYPE_API_ERROR) => StatusClass::ServerError,
        Some(ERR_TYPE_TIMEOUT) => StatusClass::Timeout,
        Some(ERR_TYPE_AUTHENTICATION) | Some(ERR_TYPE_PERMISSION) => StatusClass::Auth,
        Some("billing_error") => StatusClass::Billing,
        Some(ERR_TYPE_INVALID_REQUEST)
        | Some(ERR_TYPE_NOT_FOUND)
        | Some(ERR_TYPE_REQUEST_TOO_LARGE)
        | None => StatusClass::ClientError,
        Some(_unrecognized) => StatusClass::ClientError,
    }
}

// Helper functions for IR mapping (used by read_request/write_request)
fn read_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
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
            let cache_control = read_cache_control(obj.get("cache_control"))?;
            let citations = obj
                .get("citations")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().map(read_citation).collect())
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
            let cache_control = read_cache_control(obj.get("cache_control"))?;
            Ok(crate::ir::IrBlock::Thinking {
                text,
                signature,
                redacted: false,
                cache_control,
            })
        }
        STOP_TOOL_USE => {
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
            let cache_control = read_cache_control(obj.get("cache_control"))?;
            Ok(crate::ir::IrBlock::ToolUse {
                id,
                name,
                input,
                cache_control,
            })
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
            let cache_control = read_cache_control(obj.get("cache_control"))?;
            Ok(crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                cache_control,
            })
        }
        "image" => {
            let source = obj.get("source").ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            })?;
            // `cache_control` sits on the OUTER image block object (a sibling of `source`), not on
            // the source — read it once and attach to whichever source shape we produce.
            let cache_control = read_cache_control(obj.get("cache_control"))?;
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
                        source: crate::ir::IrImageSource::Url(url),
                        cache_control,
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
                Ok(crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 { media_type, data },
                    cache_control,
                })
            } else {
                Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                    retry_after: None,
                })
            }
        }
        // A native `redacted_thinking` block carries opaque `data` bytes (Anthropic's encrypted
        // reasoning). Map it onto the same typed IR carrier Bedrock's `redactedContent` uses: a
        // `Thinking { redacted: true }` with the opaque bytes in `text` and no signature. The
        // Anthropic WRITER matches `Thinking { redacted: true, .. }` and re-emits a native
        // `redacted_thinking` block, so a `read_response` -> `write_response` (Anthropic->Anthropic)
        // round-trip preserves the block. Forgery is structurally impossible: a client-supplied
        // `thinking` block on the REQUEST path can only set `text`/`signature` (it reads as
        // `redacted: false`), never the typed `redacted: true` flag — so no anti-forgery scrub is
        // needed (the old String-sentinel approach that required one is gone).
        BLOCK_TYPE_REDACTED_THINKING => {
            let data = block_val
                .get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let cache_control = read_cache_control(block_val.get("cache_control"))?;
            Ok(crate::ir::IrBlock::Thinking {
                text: data,
                signature: None,
                redacted: true,
                cache_control,
            })
        }
        // Forward-compatibility: a valid native Anthropic content-block type the IR does not model
        // (e.g. `document`, or a future type Anthropic adds after this build).
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
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
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
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
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
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
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
    let cache_control = read_cache_control(obj.get("cache_control"))?;

    Ok(crate::ir::IrTool {
        name,
        description,
        input_schema,
        cache_control,
    })
}

/// Parse Anthropic's `cache_control` object (`{"type":"ephemeral"}`) into the IR's `CacheControl`.
///
/// Shared by every site that can carry an Anthropic cache breakpoint — text/system blocks, tool
/// definitions, and tool_use/tool_result blocks — so a breakpoint placed ON a tool def or tool
/// result survives the cross-protocol seam instead of being silently dropped. Absent/`null`
/// yields `None`; the only valid `type` is `ephemeral` (Anthropic's sole cache kind today), and an
/// unrecognized `type` is a client error (matching the strictness the text-block parser already had).
fn read_cache_control(
    val: Option<&serde_json::Value>,
) -> Result<Option<crate::ir::CacheControl>, IrError> {
    let Some(cc_val) = val else { return Ok(None) };
    let Some(cc_obj) = cc_val.as_object() else {
        return Ok(None);
    };
    match cc_obj.get("type").and_then(|t| t.as_str()) {
        Some(CACHE_KIND_EPHEMERAL) => Ok(Some(crate::ir::CacheControl {
            kind: crate::ir::CacheKind::Ephemeral,
        })),
        None => Ok(None),
        Some(_) => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        }),
    }
}

/// Serialize the IR's `CacheControl` back to Anthropic's native `{"type":"ephemeral"}` object.
fn write_cache_control(cc: &crate::ir::CacheControl) -> serde_json::Value {
    match cc.kind {
        crate::ir::CacheKind::Ephemeral => serde_json::json!({"type": CACHE_KIND_EPHEMERAL}),
    }
}

/// Normalize Anthropic's native `tool_choice` object into the IR union.
///
/// Anthropic shape: `{"type":"auto"|"any"|"tool"|"none","name"?:"..."}`. `auto` → `Auto`, `none` →
/// `None`, `any` → `Required` (must call some tool), `tool` + `name` → the targeted `Tool{name}`. An
/// absent field or an unrecognized/`tool`-without-`name` shape maps to `None` (omitted) so a request
/// that never carried a directive does not gain a spurious one — except `tool` with a name, which is
/// the load-bearing targeted case this fix exists to preserve.
fn read_anthropic_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    let obj = val?.as_object()?;
    match obj.get("type").and_then(|t| t.as_str())? {
        "auto" => Some(crate::ir::IrToolChoice::Auto),
        "none" => Some(crate::ir::IrToolChoice::None),
        "any" => Some(crate::ir::IrToolChoice::Required),
        "tool" => {
            obj.get("name")
                .and_then(|n| n.as_str())
                .map(|name| crate::ir::IrToolChoice::Tool {
                    name: name.to_string(),
                })
        }
        _ => None,
    }
}

/// Emit the IR tool-choice union in Anthropic's native `tool_choice` object shape.
fn write_anthropic_tool_choice(tc: &crate::ir::IrToolChoice) -> serde_json::Value {
    match tc {
        crate::ir::IrToolChoice::Auto => serde_json::json!({"type": "auto"}),
        crate::ir::IrToolChoice::None => serde_json::json!({"type": "none"}),
        crate::ir::IrToolChoice::Required => serde_json::json!({"type": "any"}),
        crate::ir::IrToolChoice::Tool { name } => {
            serde_json::json!({"type": "tool", "name": name})
        }
    }
}

/// Anthropic native `stop_reason` token → canonical [`crate::ir::IrStopReason`]. The ONLY place that
/// knows Anthropic's finish vocabulary on the read side; an unmodeled token maps to `Other`.
fn read_anthropic_stop_reason(token: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match token {
        STOP_END_TURN => S::EndTurn,
        STOP_MAX_TOKENS => S::MaxTokens,
        STOP_STOP_SEQUENCE => S::StopSequence,
        STOP_TOOL_USE => S::ToolUse,
        STOP_PAUSE_TURN => S::PauseTurn,
        STOP_REFUSAL => S::Refusal,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → Anthropic native `stop_reason`. EXHAUSTIVE: Anthropic's enum is
/// `end_turn | max_tokens | stop_sequence | tool_use | pause_turn | refusal` — there is NO `safety`
/// member, so `safety` (and `error`/`other`, which Anthropic also can't name) degrades to `end_turn`
/// (the turn ended, just not by the model's choice) rather than leak an off-spec value a strict
/// Anthropic SDK rejects.
fn write_anthropic_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn => STOP_END_TURN,
        S::MaxTokens => STOP_MAX_TOKENS,
        S::StopSequence => STOP_STOP_SEQUENCE,
        S::ToolUse => STOP_TOOL_USE,
        S::PauseTurn => STOP_PAUSE_TURN,
        S::Refusal => STOP_REFUSAL,
        S::Safety | S::Error | S::Other => STOP_END_TURN,
    }
}

/// Map one RAW Anthropic citation object → neutral [`crate::ir::IrCitation`]. Fills the neutral
/// fields it recognizes AND stashes the source object verbatim in `raw`, so the Anthropic writer can
/// re-emit it byte-exact (the no-regression guarantee) while a cross-protocol writer still has the
/// neutral coordinates. The Anthropic citation `type` union uses differently-named start/end fields
/// per variant (char/page/block index, or web-search `encrypted_index`); we read each into the shared
/// neutral `start_index`/`end_index`/`encrypted_index` slots, keyed off the `type` tag.
fn read_citation(val: &serde_json::Value) -> crate::ir::IrCitation {
    let kind = val.get("type").and_then(|v| v.as_str()).map(str::to_string);
    let cited_text = val
        .get("cited_text")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // `document_title` (document-location variants) OR `title` (web_search_result_location).
    let title = val
        .get("document_title")
        .or_else(|| val.get("title"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let url = val.get("url").and_then(|v| v.as_str()).map(str::to_string);
    let document_index = val.get("document_index").and_then(|v| v.as_i64());
    // Per-variant start/end field names collapse into the shared neutral slots.
    let start_index = val
        .get("start_char_index")
        .or_else(|| val.get("start_page_number"))
        .or_else(|| val.get("start_block_index"))
        .and_then(|v| v.as_i64());
    let end_index = val
        .get("end_char_index")
        .or_else(|| val.get("end_page_number"))
        .or_else(|| val.get("end_block_index"))
        .and_then(|v| v.as_i64());
    let encrypted_index = val
        .get("encrypted_index")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    crate::ir::IrCitation {
        kind,
        cited_text,
        title,
        url,
        document_index,
        start_index,
        end_index,
        encrypted_index,
        // VERBATIM source object → byte-exact same-protocol re-emission.
        raw: Some(val.clone()),
    }
}

/// True when `raw` is an ANTHROPIC-shaped citation object — its `type` tag is one of the four
/// Anthropic citation variants. Gates the byte-exact `raw` passthrough so a foreign-protocol `raw`
/// (Gemini `citationSources[]`, which has no Anthropic `type`) is rebuilt from neutral fields rather
/// than emitted verbatim.
fn is_anthropic_citation_shape(raw: &serde_json::Value) -> bool {
    matches!(
        raw.get("type").and_then(|v| v.as_str()),
        Some(
            CITATION_TYPE_CHAR
                | CITATION_TYPE_PAGE
                | CITATION_TYPE_CONTENT_BLOCK
                | "web_search_result_location"
        )
    )
}

/// Map a neutral [`crate::ir::IrCitation`] → an Anthropic citation object.
///
/// NO-REGRESSION GUARANTEE: when `raw` is present (an Anthropic-sourced citation, OR any source that
/// preserved its original object), it is emitted VERBATIM — so Anthropic→IR→Anthropic is byte-exact
/// regardless of how the neutral fields map. Only when `raw` is absent (a citation synthesized from
/// neutral fields on a cross-protocol hop, e.g. Gemini→Anthropic) do we BUILD an Anthropic object
/// from the neutral fields, keyed off `kind` to choose the variant + its field names.
fn write_citation(c: &crate::ir::IrCitation) -> serde_json::Value {
    // Re-emit `raw` VERBATIM only when it is an ANTHROPIC citation object (same-protocol path) — keyed
    // off an Anthropic `type` tag. A `raw` from a FOREIGN protocol (e.g. a Gemini `citationSources[]`
    // entry on a Gemini→Anthropic hop, which has `uri`/`startIndex` and no Anthropic `type`) must NOT
    // be emitted as-is; fall through to BUILD the Anthropic shape from the neutral fields instead.
    if let Some(raw) = &c.raw {
        if is_anthropic_citation_shape(raw) {
            return raw.clone();
        }
    }
    let mut obj = serde_json::Map::new();
    let kind = c.kind.as_deref().unwrap_or("web_search_result_location");
    obj.insert("type".to_string(), serde_json::json!(kind));
    if let Some(t) = &c.cited_text {
        obj.insert("cited_text".to_string(), serde_json::json!(t));
    }
    match kind {
        CITATION_TYPE_PAGE => {
            if let Some(di) = c.document_index {
                obj.insert("document_index".to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert("document_title".to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert("start_page_number".to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert("end_page_number".to_string(), serde_json::json!(e));
            }
        }
        CITATION_TYPE_CONTENT_BLOCK => {
            if let Some(di) = c.document_index {
                obj.insert("document_index".to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert("document_title".to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert("start_block_index".to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert("end_block_index".to_string(), serde_json::json!(e));
            }
        }
        "web_search_result_location" => {
            if let Some(u) = &c.url {
                obj.insert("url".to_string(), serde_json::json!(u));
            }
            if let Some(t) = &c.title {
                obj.insert("title".to_string(), serde_json::json!(t));
            }
            if let Some(ei) = &c.encrypted_index {
                obj.insert("encrypted_index".to_string(), serde_json::json!(ei));
            }
        }
        // "char_location" and any unknown/None kind default to the char-location field names.
        _ => {
            if let Some(di) = c.document_index {
                obj.insert("document_index".to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert("document_title".to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert("start_char_index".to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert("end_char_index".to_string(), serde_json::json!(e));
            }
        }
    }
    serde_json::Value::Object(obj)
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
                    crate::ir::CacheKind::Ephemeral => {
                        serde_json::json!({"type": CACHE_KIND_EPHEMERAL})
                    }
                };
                obj.insert("cache_control".to_string(), cc_val);
            }
            if !citations.is_empty() {
                let arr: Vec<serde_json::Value> = citations.iter().map(write_citation).collect();
                obj.insert("citations".to_string(), serde_json::Value::Array(arr));
            }
            serde_json::Value::Object(obj)
        }
        // A REDACTED reasoning block (opaque encrypted bytes in `text`) re-emits as Anthropic's native
        // `redacted_thinking` block so an Anthropic→Anthropic round-trip preserves the native shape and
        // the bytes are NOT leaked as visible `thinking` text.
        crate::ir::IrBlock::Thinking {
            text,
            redacted: true,
            cache_control,
            ..
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "type".to_string(),
                serde_json::json!(BLOCK_TYPE_REDACTED_THINKING),
            );
            obj.insert("data".to_string(), serde_json::json!(text));
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Thinking {
            text,
            signature,
            redacted: false,
            cache_control,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("thinking"));
            obj.insert("thinking".to_string(), serde_json::json!(text));
            if let Some(sig) = signature {
                obj.insert("signature".to_string(), serde_json::json!(sig));
            }
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolUse {
            id,
            name,
            input,
            cache_control,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!(STOP_TOOL_USE));
            obj.insert("id".to_string(), serde_json::json!(id));
            obj.insert("name".to_string(), serde_json::json!(name));
            obj.insert("input".to_string(), input.clone());
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            cache_control,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("tool_result"));
            obj.insert("tool_use_id".to_string(), serde_json::json!(tool_use_id));
            if content.is_empty() {
                obj.insert("content".to_string(), serde_json::json!(""));
            } else {
                // Drop any Bedrock json-tool-result sentinel block BEFORE mapping through
                // `write_block`: unlike the other writers (which Text-filter ToolResult content and so
                // silently drop it), Anthropic maps each block through `write_block`, whose Image arm
                // would emit a CORRUPT base64 source (`media_type:"tool_result_json"`, data = the JSON)
                // — a corrupt image on the Anthropic wire + a busbar fingerprint. There is no lossless
                // cross-protocol projection of a structured json tool-result, so drop it WITH a warn.
                let kept: Vec<serde_json::Value> = content
                    .iter()
                    .filter(|b| {
                        if super::is_json_tool_result_block(b) {
                            tracing::warn!(
                                "dropping structured json tool-result block on Anthropic egress: a \
                                 Bedrock `{{\"json\":...}}` tool-result has no cross-protocol analog \
                                 and is NOT emitted (would otherwise corrupt a base64 image source)"
                            );
                            false
                        } else {
                            true
                        }
                    })
                    .map(write_block)
                    .collect();
                obj.insert("content".to_string(), serde_json::Value::Array(kept));
            }
            if *is_error {
                obj.insert("is_error".to_string(), serde_json::Value::Bool(true));
            }
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Image {
            source,
            cache_control,
        } => {
            // Anthropic's Messages API has both a native URL image source and a base64 source.
            // S3/FileId references have no Anthropic projection and are FILTERED before write_block
            // (see the unresolvable-image drop in write_message); the arm here is a defensive empty
            // placeholder for the unreachable case.
            let mut img = match source {
                crate::ir::IrImageSource::Url(url) => {
                    serde_json::json!({ "type": "image", "source": { "type": "url", "url": url } })
                }
                crate::ir::IrImageSource::Base64 { media_type, data } => {
                    serde_json::json!({ "type": "image", "source": { "type": "base64", "media_type": media_type, "data": data } })
                }
                crate::ir::IrImageSource::Vendor { .. } => {
                    serde_json::json!({ "type": "text", "text": "" })
                }
            };
            if let Some(cc) = cache_control {
                if let Some(obj) = img.as_object_mut() {
                    obj.insert("cache_control".to_string(), write_cache_control(cc));
                }
            }
            img
        }
        crate::ir::IrBlock::Json(_) => {
            // A structured-json tool-result block has no top-level Anthropic content shape; it is
            // dropped before reaching write_block (see the json-tool-result filter in the ToolResult
            // arm). Defensive empty placeholder for the unreachable case.
            serde_json::json!({ "type": "text", "text": "" })
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
    let mut dropped_file_id_image = 0usize;
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
            } else if let crate::ir::IrBlock::Image { source, .. } = block {
                // A Responses `file_id` / Bedrock `s3Location` image is an unresolvable cross-vendor
                // reference with no Anthropic projection. SKIP it rather than emit a corrupt block.
                if super::is_unresolvable_image_ref(source) {
                    dropped_file_id_image += 1;
                    false
                } else {
                    true
                }
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
    if dropped_file_id_image > 0 {
        tracing::warn!(
            dropped = dropped_file_id_image,
            "dropping unresolvable vendor-scoped image reference(s) on Anthropic egress: a \
             Responses input_image.file_id or a Bedrock s3Location has no cross-vendor analog and \
             would corrupt a base64 source; the block(s) are NOT emitted"
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
    if let Some(cc) = &tool.cache_control {
        obj.insert("cache_control".to_string(), write_cache_control(cc));
    }
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
        if k.starts_with(CRED_PREFIX_API_KEY) {
            AnthropicCredScheme::ApiKey
        } else if k.starts_with(CRED_PREFIX_OAUTH) {
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
/// A key with bytes invalid in an HTTP header value (e.g. a stray newline) is OMITTED rather than
/// emitted with an empty value (one diagnostic warning naming the protocol, key bytes never logged)
/// — matching the warn+OMIT policy of the Bearer writers (`proto::bearer_auth_headers`) and the
/// Gemini/Cohere/Responses writers. An empty `x-api-key: ` is both a syntactically invalid header the
/// upstream 401s on AND a fingerprinting tell against well-formed tokens, so we drop just that
/// credential header and keep `anthropic-version`. The worker never panics; the upstream returns a
/// clean 401 the breaker classifies normally. Defense-in-depth; keys should be validated at config
/// load.
fn anthropic_auth_headers(
    key: &str,
    mode: Option<crate::auth::AuthMode>,
) -> Vec<(HeaderName, HeaderValue)> {
    // Build a credential header pair, OMITTING it (returning None) when the value carries bytes
    // invalid for an HTTP header value. Never logs the key bytes — only the header name and the fact
    // that they were malformed.
    let safe = |name: &'static str, raw: String| -> Option<(HeaderName, HeaderValue)> {
        match HeaderValue::from_str(&raw) {
            Ok(v) => Some((HeaderName::from_static(name), v)),
            Err(_) => {
                tracing::warn!(
                    protocol = "anthropic",
                    header = name,
                    "auth credential contains bytes invalid for an HTTP header value (e.g. a \
                     trailing newline); omitting the credential header — upstream will return 401, \
                     check the key configuration"
                );
                None
            }
        }
    };
    let x_api_key = || safe(HDR_X_API_KEY, key.to_string());
    // ApiKey-scheme variant of `x-api-key` that strips LEADING whitespace from the configured key.
    // `classify_credential` matches on `key.trim_start()`, so `"  sk-ant-api…"`
    // classifies as `ApiKey` — but the raw `x_api_key` closure above forwards the key VERBATIM,
    // emitting `x-api-key: "  sk-ant-api…"` (a header value with a leading-space artifact the
    // upstream rejects with a 401). Trim the leading whitespace so the emitted header matches the
    // value that was classified. Scope is deliberately narrow: ONLY the canonical configured-key
    // (`ApiKey`) scheme is trimmed here. The OAuth (`authorization: Bearer`) and the Ambiguous
    // passthrough/static fallbacks keep the raw closures below, preserving their byte-for-byte
    // round-trip contract — a forwarded caller token must reach the upstream exactly as presented.
    let x_api_key_trimmed = || safe(HDR_X_API_KEY, key.trim_start().to_string());
    let authorization = || safe(crate::proto::HDR_AUTHORIZATION, format!("Bearer {key}"));
    let version = (
        HeaderName::from_static(HDR_ANTHROPIC_VERSION),
        HeaderValue::from_static(ANTHROPIC_API_VERSION),
    );
    // Assemble the credential header(s) (each an `Option`, omitted on bad bytes) followed by the
    // always-present `anthropic-version`.
    let assemble =
        |creds: Vec<Option<(HeaderName, HeaderValue)>>| -> Vec<(HeaderName, HeaderValue)> {
            let mut out: Vec<(HeaderName, HeaderValue)> = creds.into_iter().flatten().collect();
            out.push(version.clone());
            out
        };
    match AnthropicWriter::classify_credential(key) {
        // Configured Anthropic API key: native API-key client shape — `x-api-key` only. Use the
        // leading-whitespace-trimmed builder so a configured key with a stray leading space (the
        // value `classify_credential` already matched on its trimmed form) is forwarded clean.
        AnthropicCredScheme::ApiKey => assemble(vec![x_api_key_trimmed()]),
        // OAuth access token / passthrough Bearer token: native OAuth client shape —
        // `authorization: Bearer` only.
        AnthropicCredScheme::OAuth => assemble(vec![authorization()]),
        // Unrecognized shape: the mode resolves it to a single native header on the wire path;
        // the mode-blind primitive falls back to both so neither path silently drops.
        AnthropicCredScheme::Ambiguous => match mode {
            Some(crate::auth::AuthMode::Passthrough) => assemble(vec![authorization()]),
            Some(crate::auth::AuthMode::Token) | Some(crate::auth::AuthMode::None) => {
                assemble(vec![x_api_key()])
            }
            None => assemble(vec![x_api_key(), authorization()]),
        },
    }
}

impl ProtocolWriter for AnthropicWriter {
    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    /// Anthropic's streamed `citations_delta` SSE event carries EXACTLY ONE `citation` object (a
    /// native SDK `JSON.parse`s one object per `data:` line and crashes on an array), so a multi-
    /// citation `CitationsDelta` must be fanned out into one event each. See `StreamTranslate`.
    fn max_citations_per_delta(&self) -> Option<usize> {
        Some(1)
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
        if status == STATUS_OVERLOADED || status == STATUS_ANTHROPIC_OVERLOADED {
            return Self::error_envelope(ERR_TYPE_OVERLOADED, message);
        }
        let anthropic_type = match kind {
            // Generic router/auth/forward `kind`s → Anthropic's typed error vocabulary.
            "invalid_request" | "bad_request" => ERR_TYPE_INVALID_REQUEST,
            "authentication" | "unauthorized" => ERR_TYPE_AUTHENTICATION,
            "permission" | "forbidden" => ERR_TYPE_PERMISSION,
            "not_found" => ERR_TYPE_NOT_FOUND,
            ERR_TYPE_REQUEST_TOO_LARGE | "payload_too_large" => ERR_TYPE_REQUEST_TOO_LARGE,
            "rate_limit" | "too_many_requests" => ERR_TYPE_RATE_LIMIT,
            crate::forward::KIND_OVERLOADED => ERR_TYPE_OVERLOADED,
            crate::forward::KIND_TIMEOUT => ERR_TYPE_TIMEOUT,
            ERR_TYPE_API_ERROR | crate::forward::KIND_SERVER_ERROR | "internal" => {
                ERR_TYPE_API_ERROR
            }
            // Already an Anthropic-native type (e.g. "invalid_request_error") or an unmapped value:
            // emit it unchanged rather than collapsing every unknown into one bucket.
            ERR_TYPE_INVALID_REQUEST
            | ERR_TYPE_AUTHENTICATION
            | ERR_TYPE_PERMISSION
            | ERR_TYPE_NOT_FOUND
            | ERR_TYPE_RATE_LIMIT
            | ERR_TYPE_OVERLOADED
            | ERR_TYPE_TIMEOUT => kind,
            other => other,
        };
        Self::error_envelope(anthropic_type, message)
    }

    fn attach_error_response_headers(
        &self,
        headers: &mut axum::http::HeaderMap,
        _kind: &str,
        envelope: &serde_json::Value,
    ) {
        // A real Anthropic response ALWAYS carries the request id in the `request-id` RESPONSE HEADER
        // (the official SDK reads `request-id` into `APIError.request_id` / `Message._request_id`, NOT
        // the body). The writer already mints a top-level body `request_id`; mirror it into the header
        // so body and header AGREE and the SDK populates `request_id` — omitting it was a deterministic
        // proxy tell on every error response.
        if let Some(rid) = envelope.get("request_id").and_then(|v| v.as_str()) {
            if let Ok(hv) = axum::http::HeaderValue::from_str(rid) {
                headers.insert(HDR_REQUEST_ID, hv);
            }
        }
    }

    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        // Forward the captured UPSTREAM `request-id` verbatim on a same-protocol passthrough;
        // synthesize a shape-correct `req_…` id otherwise. Synthesis failure OMITS the header.
        upstream_request_id
            .map(String::from)
            .or_else(synth_anthropic_request_id)
            .map(|id| (HDR_REQUEST_ID, id))
    }

    fn ingress_relayed_response_header_names(&self) -> &'static [&'static str] {
        // Forwarded VERBATIM on a same-protocol anthropic passthrough: `request-id`.
        &[HDR_REQUEST_ID]
    }

    fn auth_failure_message(&self) -> &'static str {
        "invalid x-api-key"
    }

    fn egress_user_agent(&self) -> &'static str {
        // Anthropic Python SDK UA shape — pinned, see `EGRESS_UA_ANTHROPIC` in forward.rs.
        crate::forward::EGRESS_UA_ANTHROPIC
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
        // Emit `tool_choice` in Anthropic's native object shape when present so a forced /
        // targeted directive translated from another protocol does not silently degrade to `auto`.
        // The parallelism carry (OpenAI `parallel_tool_calls`) rides the same object as Anthropic's
        // inverted `disable_parallel_tool_use` — valid on auto/any/tool, not on `none`.
        if let Some(tc) = &req.tool_choice {
            let mut tc_val = write_anthropic_tool_choice(tc);
            if let (Some(parallel), Some(map)) = (req.parallel_tool_calls, tc_val.as_object_mut()) {
                if map.get("type").and_then(|t| t.as_str()) != Some("none") {
                    map.insert(
                        "disable_parallel_tool_use".to_string(),
                        serde_json::json!(!parallel),
                    );
                }
            }
            out.insert("tool_choice".to_string(), tc_val);
        } else if let Some(parallel) = req.parallel_tool_calls {
            // No directive but the caller did set parallelism: Anthropic can only express it inside
            // a tool_choice object, so synthesize the neutral `auto` carrier — only when tools are
            // actually present (the flag is meaningless without them, and Anthropic rejects a
            // tool_choice on a tool-less request).
            if !req.tools.is_empty() {
                out.insert(
                    "tool_choice".to_string(),
                    serde_json::json!({"type": "auto", "disable_parallel_tool_use": !parallel}),
                );
            }
        }
        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        // The reasoning carry: project the IR ask into Anthropic's `thinking` param. The budget is
        // clamped to leave >=1024 tokens of answer under max_tokens (Anthropic requires
        // budget_tokens < max_tokens and spends thinking FROM it) and floored at the API's 1024
        // minimum; when max_tokens is too small to fit any thinking, the ask is dropped with a
        // warn rather than shipped to a certain 400. Anthropic also rejects temperature/top_k
        // modifications alongside thinking, so when the ask IS emitted those knobs are omitted
        // (warned) below instead of shipped to a 400.
        let mut thinking_emitted = false;
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
            if matches!(ask, crate::ir::IrReasoningAsk::Dynamic) {
                tracing::warn!(
                    "gemini dynamic thinking (-1) has no Anthropic analog; projecting as the \
                     'medium' effort budget"
                );
            }
            let want = ask.to_budget(table);
            let cap = req.max_tokens.map(|mt| mt.saturating_sub(1024));
            let budget = cap.map_or(want, |c| want.min(c));
            if budget >= 1024 {
                if budget != want {
                    tracing::warn!(
                        requested_budget = want,
                        clamped_budget = budget,
                        max_tokens = ?req.max_tokens,
                        "thinking budget clamped to fit under max_tokens"
                    );
                }
                out.insert(
                    "thinking".to_string(),
                    serde_json::json!({"type": "enabled", "budget_tokens": budget}),
                );
                thinking_emitted = true;
            } else {
                tracing::warn!(
                    max_tokens = ?req.max_tokens,
                    "dropping reasoning ask on Anthropic egress: max_tokens leaves no room for \
                     the 1024-token thinking minimum"
                );
            }
        }
        if thinking_emitted && req.temperature.is_some_and(|t| t != 1.0) {
            // Anthropic 400s on temperature != 1 with thinking enabled; the think-ask wins and the
            // sampling knob is omitted, observably.
            tracing::warn!(
                temperature = ?req.temperature,
                "omitting temperature on Anthropic egress: not compatible with thinking"
            );
        }
        if let Some(temperature) = req.temperature.filter(|_| !thinking_emitted) {
            // Clamp to Anthropic's valid [0.0, 1.0] — see `clamp_temperature_for_anthropic`.
            // NON-SILENT clamp: silently rewriting a caller's sampling temperature
            // is exactly the lossy mutation busbar exists to avoid; we keep the clamp (Anthropic 422s on
            // >1.0) but emit a `warn!` whenever it ACTUALLY changes the value so an operator can detect
            // the divergence in logs. A request-time RESPONSE header (`x-busbar-parameter-clamped`)
            // cannot be attached from here: `write_request` returns only the egress request JSON and
            // has no handle on the (much-later-built) client response; surfacing it as a header would
            // require threading a clamp signal back out through the whole `forward` path / trait
            // signature, deferred as out-of-scope for this minimal-safe fix. The warn! is the contract.
            let (clamped, was_clamped) = clamp_temperature_for_anthropic(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "clamping temperature to Anthropic's [0.0, 1.0] range; the requested value was \
                     outside it (e.g. an OpenAI/Responses value up to 2.0) and would 422 — the \
                     forwarded value diverges from the caller's request"
                );
            }
            out.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Sampling controls promoted to first-class IR fields (see `IrRequest`): emit each in
        // Anthropic's native shape when present. `top_p`/`top_k` map 1:1; the IR's normalized `stop`
        // vec is Anthropic's native `stop_sequences` array. Emitted before the `extra` overlay (these
        // keys were pulled OUT of extra by the reader, so there is no double-emit on passthrough).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            if thinking_emitted {
                // Anthropic rejects top_k modifications alongside thinking; omit, observably.
                tracing::warn!(
                    top_k,
                    "omitting top_k on Anthropic egress: not compatible with thinking"
                );
            } else {
                out.insert("top_k".to_string(), serde_json::json!(top_k));
            }
        }
        if !req.stop.is_empty() {
            out.insert("stop_sequences".to_string(), serde_json::json!(req.stop));
        }
        out.insert("stream".to_string(), serde_json::json!(req.stream));
        // response_format (M1): Anthropic's Messages API has NO native `response_format` field. The
        // idiomatic Anthropic mapping is tool-forcing (a synthetic tool + `tool_choice:{type:"tool"}`),
        // which is non-trivial and deliberately NOT implemented in this pass. The reader never sets
        // `response_format` on the same-protocol (Anthropic→Anthropic) path — same-protocol relays the
        // raw upstream body and never reaches this writer — so this only fires for a CROSS-PROTOCOL IR
        // (e.g. an OpenAI/Responses request carrying `response_format`) reaching the Anthropic egress.
        // Dropping it silently would be exactly the lossy mutation busbar exists to avoid; emit a
        // `warn!` so the divergence is observable in logs rather than invisible. (The block is dropped,
        // not forwarded: emitting an unknown `response_format` key would 400 the upstream.)
        if req.response_format.is_some() {
            tracing::warn!(
                parameter = "response_format",
                "dropping response_format on Anthropic egress: the Messages API has no native \
                 response_format field and tool-forcing is not implemented in this pass; the \
                 structured-output directive from a cross-protocol request is NOT forwarded"
            );
        }
        // Carry the end-user identifier into Anthropic's spelling (`metadata.user_id`). Emitted
        // before the `extra` overlay: if the request natively carried an Anthropic `metadata`
        // object it rides `extra` and overwrites this, so the verbatim original always wins.
        if let Some(user) = &req.user {
            out.insert("metadata".to_string(), serde_json::json!({"user_id": user}));
        }
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
                data_obj.insert("type".to_string(), serde_json::json!(EVT_MESSAGE_START));
                data_obj.insert("message".to_string(), serde_json::Value::Object(msg_obj));
                Some((
                    EVT_MESSAGE_START.to_string(),
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
                        serde_json::json!({ "type": STOP_TOOL_USE, "id": id, "name": name })
                    }
                    IrBlockMeta::Image => {
                        serde_json::json!({ "type": "image" })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_START),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("content_block".to_string(), content_block);
                Some((
                    EVT_CONTENT_BLOCK_START.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockDelta { index, delta } => {
                let delta_val = match delta {
                    IrDelta::TextDelta(text) => {
                        serde_json::json!({ "type": DELTA_TYPE_TEXT, "text": text })
                    }
                    IrDelta::ThinkingDelta(thinking) => {
                        serde_json::json!({ "type": DELTA_TYPE_THINKING, "thinking": thinking })
                    }
                    IrDelta::InputJsonDelta(json) => {
                        serde_json::json!({ "type": DELTA_TYPE_INPUT_JSON, "partial_json": json })
                    }
                    IrDelta::SignatureDelta(sig) => {
                        serde_json::json!({ "type": DELTA_TYPE_SIGNATURE, "signature": sig })
                    }
                    // A streamed redacted-reasoning delta (opaque encrypted bytes) has no Anthropic
                    // streaming-delta analog — emit nothing for this frame.
                    IrDelta::RedactedReasoningDelta(_) => return None,
                    // Anthropic has no logprobs concept at all — lossy-by-target, emit nothing.
                    IrDelta::LogprobsDelta(_) => return None,
                    // L2-5 STREAMING citation: re-emit each carried citation as its own native
                    // `content_block_delta`/`citations_delta` event (the native wire carries ONE
                    // `citation` per delta). `write_citation` re-emits a byte-exact Anthropic `raw`
                    // verbatim (same-protocol path) and synthesizes the Anthropic object from neutral
                    // fields otherwise (e.g. a Gemini-sourced citation on a Gemini→Anthropic hop) —
                    // the shape-gate (`is_anthropic_citation_shape`) inside `write_citation` keeps a
                    // foreign `raw` from leaking through. An EMPTY citation vec carries nothing, so we
                    // emit no event (return None) rather than a stray empty `content_block_delta`.
                    IrDelta::CitationsDelta(citations) => {
                        // EVERY Anthropic `citations_delta` event on the wire is EXACTLY ONE citation
                        // object — never a JSON array (a native SDK `JSON.parse`s one object per
                        // `data:` line and crashes on an array). The `ProtocolWriter` trait returns at
                        // most one `(event_type, body)` per event, so a delta MUST carry at most one
                        // citation by the time it reaches this writer. A multi-citation `CitationsDelta`
                        // (e.g. a Gemini chunk batching N `citationSources[]`) is split into N
                        // single-citation deltas UPSTREAM at the `StreamTranslate` framing seam (the
                        // Anthropic-ingress multi-citation fan-out), so each call here sees exactly one.
                        // An EMPTY vec carries nothing → emit no event (None) rather than a stray empty
                        // `content_block_delta`. A vec of >1 cannot occur via the framer, but defend the
                        // invariant anyway: take the FIRST and drop the rest rather than ever emitting
                        // an array.
                        let c = citations.first()?;
                        let mut data_obj = serde_json::Map::new();
                        data_obj.insert(
                            "type".to_string(),
                            serde_json::json!(EVT_CONTENT_BLOCK_DELTA),
                        );
                        data_obj.insert("index".to_string(), serde_json::json!(index));
                        data_obj.insert(
                            "delta".to_string(),
                            serde_json::json!({
                                "type": DELTA_TYPE_CITATIONS,
                                "citation": write_citation(c),
                            }),
                        );
                        return Some((
                            EVT_CONTENT_BLOCK_DELTA.to_string(),
                            serde_json::Value::Object(data_obj),
                        ));
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_DELTA),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("delta".to_string(), delta_val);
                Some((
                    EVT_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStop { index } => {
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_STOP),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                Some((
                    EVT_CONTENT_BLOCK_STOP.to_string(),
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
                    delta_obj.insert(
                        "stop_reason".to_string(),
                        serde_json::json!(write_anthropic_stop_reason(*reason)),
                    );
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
                data_obj.insert("type".to_string(), serde_json::json!(EVT_MESSAGE_DELTA));
                data_obj.insert("delta".to_string(), serde_json::Value::Object(delta_obj));
                data_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                Some((
                    EVT_MESSAGE_DELTA.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageStop => Some((
                EVT_MESSAGE_STOP.to_string(),
                serde_json::json!({ "type": EVT_MESSAGE_STOP }),
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
        // it UNCONDITIONALLY, mirroring the streaming `message_start` writer and every
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
            obj.insert(
                "stop_reason".to_string(),
                serde_json::json!(write_anthropic_stop_reason(*reason)),
            );
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

    #[test]
    fn stop_reason_egress_never_leaks_foreign_tokens() {
        use crate::ir::IrStopReason as S;
        // Anthropic-native reasons map to their wire token; `refusal`/`pause_turn` are real Anthropic
        // StopReason members and survive.
        assert_eq!(write_anthropic_stop_reason(S::EndTurn), "end_turn"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(write_anthropic_stop_reason(S::ToolUse), "tool_use"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(write_anthropic_stop_reason(S::PauseTurn), "pause_turn"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(write_anthropic_stop_reason(S::Refusal), "refusal"); // golden wire-contract literal (kept bare on purpose)
                                                                        // `safety` has no Anthropic member, and `error`/`other` are off-enum → all degrade to
                                                                        // end_turn rather than leak an off-spec value a strict Anthropic SDK rejects.
        assert_eq!(write_anthropic_stop_reason(S::Safety), "end_turn"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(write_anthropic_stop_reason(S::Error), "end_turn"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(write_anthropic_stop_reason(S::Other), "end_turn"); // golden wire-contract literal (kept bare on purpose)
                                                                       // The reader maps an unknown native token (e.g. the non-enum `model_context_window_exceeded`)
                                                                       // to `Other`, which then degrades on egress — it is never carried verbatim.
        assert_eq!(
            read_anthropic_stop_reason("model_context_window_exceeded"),
            S::Other
        );
    }

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
            header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("sk-ant-api03-secret-key")
        );
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an API key must NOT emit an authorization header (native API-key clients never do)"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("2023-06-01")
        );
    }

    /// Regression: a configured API key with LEADING WHITESPACE (a common config
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
            canonical_uri: PATH_UPSTREAM.to_string(),
            body: b"{}",
            timestamp_epoch: 0,
            auth_mode: crate::auth::AuthMode::Token,
        };
        for headers in [
            AnthropicWriter.auth_headers(raw),
            AnthropicWriter.sign_request(raw, &ctx),
        ] {
            assert_eq!(
                header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
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

    /// Precision guard: the leading-whitespace trim is scoped to the configured-key
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
            header_value(&oauth_headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
            "OAuth must not emit x-api-key"
        );

        // Ambiguous passthrough Bearer (wire path) likewise round-trips verbatim.
        let amb = "  opaque-caller-token";
        let ctx = crate::proto::SigningContext {
            host: "api.anthropic.com".to_string(),
            canonical_uri: PATH_UPSTREAM.to_string(),
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
            header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("caller-specific-token-abc123")
        );
        assert_eq!(
            header_value(&headers, "authorization").as_deref(),
            Some("Bearer caller-specific-token-abc123")
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
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
            canonical_uri: PATH_UPSTREAM.to_string(),
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
            header_value(&pt, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
            "passthrough wire path must NOT also emit x-api-key (dual-header tell)"
        );

        // Token mode (configured lane key): present the API-key shape ONLY (no Bearer tell).
        for mode in [crate::auth::AuthMode::Token, crate::auth::AuthMode::None] {
            let h = AnthropicWriter.sign_request(amb, &ctx(mode));
            assert_eq!(
                header_value(&h, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
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
            header_value(&api, "x-api-key").is_some() // golden wire-contract literal (kept bare on purpose)
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
            header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
            "an OAuth token must NOT emit an x-api-key header (native OAuth clients never do)"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
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
        assert!(header_value(&headers, "x-api-key").is_none()); // golden wire-contract literal (kept bare on purpose)
    }

    /// A key with bytes invalid for an HTTP header value (e.g. a trailing newline) must not panic
    /// the worker. Under the warn+OMIT policy (matching the Bearer/Gemini/Cohere/Responses writers)
    /// the credential header is now OMITTED entirely — an empty `x-api-key: ` was both a
    /// syntactically invalid header and a fingerprinting tell. `anthropic-version` stays present so
    /// the upstream still gets a versioned (but unauthenticated) request and returns a clean 401.
    #[test]
    fn auth_headers_invalid_api_key_omits_credential_no_panic() {
        // A recognizable API key (so the single-header API-key path is exercised) whose bytes are
        // invalid for an HTTP header value.
        let headers = AnthropicWriter.auth_headers("sk-ant-api03-bad\nkey");
        assert!(
            header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
            "an invalid API key must OMIT x-api-key, not emit an empty value"
        );
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an invalid API key still must not emit an authorization header"
        );
        // anthropic-version is static and unaffected by the bad key — it remains the only header.
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("2023-06-01")
        );
        assert_eq!(
            headers.len(),
            1,
            "only anthropic-version remains on a bad key"
        );
    }

    /// The same warn+OMIT guarantee on the OAuth path: an invalid OAuth token OMITS the
    /// `authorization` header (and never emits `x-api-key`), keeping only `anthropic-version`.
    #[test]
    fn auth_headers_invalid_oauth_token_omits_credential_no_panic() {
        let headers = AnthropicWriter.auth_headers("sk-ant-oat01-bad\ntoken");
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an invalid OAuth token must OMIT authorization, not emit an empty value"
        );
        assert!(
            header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
            "an invalid OAuth token still must not emit an x-api-key header"
        );
        assert_eq!(
            header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("2023-06-01")
        );
        assert_eq!(
            headers.len(),
            1,
            "only anthropic-version remains on a bad token"
        );
    }

    /// extract_error parses the body once and surfaces both provider_code and structured_type.
    #[test]
    fn extract_error_parses_both_fields() {
        let body_json =
            serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"code":"some_code"}});
        let body = serde_json::to_vec(&body_json).unwrap();
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
        assert_eq!(raw.http_status, 400);
        assert_eq!(raw.provider_code.as_deref(), Some("some_code"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
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
        let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"message":"prompt is too long"}});
        let body = serde_json::to_vec(&body_json).unwrap();
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded")
        );
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
        );
    }

    /// Regression (block-index clamp): a streaming `content_block_start` whose `index` is an
    /// upstream-controlled pathological value (`u64::MAX`) must be CLAMPED to
    /// `MAX_ANTHROPIC_BLOCK_INDEX` before it enters the IR, so a downstream writer (GeminiWriter
    /// `open_tools`, Bedrock `contentBlockIndex`) never allocates/serializes against the raw value.
    /// Mirrors the Bedrock reader's `MAX_CONTENT_BLOCK_INDEX` clamp test. Against the OLD code
    /// (`.map(|v| v as usize)`) this index would be `u64::MAX as usize` and the assertion fails.
    #[test]
    fn content_block_start_clamps_pathological_index() {
        let data = serde_json::json!({
            "type": EVT_CONTENT_BLOCK_START,
            "index": u64::MAX,
            "content_block": { "type": "text" }
        });
        let ev = AnthropicReader
            .read_response_event(EVT_CONTENT_BLOCK_START, &data)
            .expect("content_block_start parses");
        match ev {
            IrStreamEvent::BlockStart { index, .. } => {
                assert_eq!(
                    index, MAX_ANTHROPIC_BLOCK_INDEX as usize,
                    "a u64::MAX block index must be clamped to MAX_ANTHROPIC_BLOCK_INDEX"
                );
            }
            other => panic!("expected BlockStart, got {other:?}"),
        }
    }

    /// Regression (block-index clamp, delta + stop sites): the same clamp must apply to
    /// `content_block_delta` and `content_block_stop`, not just `content_block_start` — all three
    /// share `read_clamped_block_index`. Guards that the class is fixed at every read site.
    #[test]
    fn content_block_delta_and_stop_clamp_pathological_index() {
        let delta = serde_json::json!({
            "type": EVT_CONTENT_BLOCK_DELTA,
            "index": u64::MAX,
            "delta": { "type": DELTA_TYPE_TEXT, "text": "x" }
        });
        match AnthropicReader
            .read_response_event(EVT_CONTENT_BLOCK_DELTA, &delta)
            .expect("content_block_delta parses")
        {
            IrStreamEvent::BlockDelta { index, .. } => {
                assert_eq!(index, MAX_ANTHROPIC_BLOCK_INDEX as usize);
            }
            other => panic!("expected BlockDelta, got {other:?}"),
        }

        let stop = serde_json::json!({
            "type": EVT_CONTENT_BLOCK_STOP,
            "index": u64::MAX
        });
        match AnthropicReader
            .read_response_event(EVT_CONTENT_BLOCK_STOP, &stop)
            .expect("content_block_stop parses")
        {
            IrStreamEvent::BlockStop { index } => {
                assert_eq!(index, MAX_ANTHROPIC_BLOCK_INDEX as usize);
            }
            other => panic!("expected BlockStop, got {other:?}"),
        }
    }

    /// Regression (cross-protocol sibling of the Cohere context-length gate): a 429 whose
    /// body merely MENTIONS tokens/length must NOT be reclassified to context_length. The
    /// message-scan override is now gated on a request-size status (400/413), so a 429 keeps its
    /// rate-limit disposition: `extract_error` leaves `provider_code` empty of the context-length
    /// code, and the breaker's `normalize_raw_error` normalizes the 429 to `RateLimit` (penalizing
    /// the lane). Against the OLD un-gated code, `provider_code` would become
    /// `context_length_exceeded` and `normalize_raw_error` would classify it as `ContextLength`
    /// (a non-penalizing fail-over) — so this asserts `RateLimit`, failing the old behavior.
    #[test]
    fn extract_error_429_with_token_body_not_reclassified_to_context_length() {
        // A 429 rate-limit body that happens to mention tokens (e.g. a per-token rate limit).
        let body_json = serde_json::json!({"error":{"type": ERR_TYPE_RATE_LIMIT,"message":"rate limit exceeds the maximum tokens per minute"}});
        let body = serde_json::to_vec(&body_json).unwrap();
        let raw = AnthropicReader.extract_error(StatusCode::TOO_MANY_REQUESTS, &body);
        assert_eq!(raw.http_status, 429);
        assert_ne!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 429 body mentioning tokens must NOT be overridden to the context-length code"
        );
        // End-to-end: the breaker normalizes it to RateLimit, not ContextLength.
        let empty_map = std::collections::HashMap::new();
        let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert_eq!(
            signal.class,
            StatusClass::RateLimit,
            "a 429 with a token-mentioning body must normalize to RateLimit, not ContextLength"
        );
    }

    /// Regression (positive case): a genuine 400 oversized-prompt body STILL
    /// synthesizes the canonical context-length code under the new 400/413 gate, so legitimate
    /// context-length fail-over is unaffected by the gating change.
    #[test]
    fn extract_error_400_context_length_still_synthesized_under_gate() {
        let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"message":"prompt is too long: 250000 tokens"}});
        let body = serde_json::to_vec(&body_json).unwrap();
        let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a genuine 400 oversized-prompt body must still synthesize the context-length code"
        );
        let empty_map = std::collections::HashMap::new();
        let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert_eq!(signal.class, StatusClass::ContextLength);
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
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
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
        assert_eq!(map_of("rate_limit").as_deref(), Some("rate_limit_error")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            map_of("authentication").as_deref(),
            Some("authentication_error") // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(
            map_of("invalid_request").as_deref(),
            Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
        );
        // Already-native type is emitted verbatim.
        assert_eq!(
            map_of(ERR_TYPE_INVALID_REQUEST).as_deref(),
            Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
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
                .write_error(status, ERR_TYPE_API_ERROR, "upstream is overloaded")
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        };
        // The finding's exact scenario: cross-protocol 503 + generic `api_error` kind.
        assert_eq!(
            type_for(STATUS_OVERLOADED).as_deref(),
            Some("overloaded_error"), // golden wire-contract literal (kept bare on purpose)
            "a 503 must surface as Anthropic's overloaded_error, not a generic api_error"
        );
        // The native 529 overload status maps the same way regardless of incoming kind.
        assert_eq!(
            type_for(STATUS_ANTHROPIC_OVERLOADED).as_deref(),
            Some("overloaded_error")
        ); // golden wire-contract literal (kept bare on purpose)
           // A genuine 500-class server error (not the overload family) still maps to api_error —
           // the status override is scoped to 503/529 and does not swallow other server errors.
        assert_eq!(type_for(500).as_deref(), Some("api_error")); // golden wire-contract literal (kept bare on purpose)
                                                                 // The envelope is still well-formed and request_id is minted on the status-override path.
        let v = AnthropicWriter.write_error(
            STATUS_OVERLOADED,
            ERR_TYPE_API_ERROR,
            "upstream is overloaded",
        );
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
            "stop_reason": STOP_STOP_SEQUENCE,
            "stop_sequence": "\n\nHuman:",
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });
        let ir = AnthropicReader.read_response(&body).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("msg_01XYZabc123"));
        assert_eq!(ir.model.as_deref(), Some("claude-opus-4-8"));
        assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::StopSequence));
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
            Some("stop_sequence") // golden wire-contract literal (kept bare on purpose)
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
            .read_response_event(EVT_MESSAGE_START, &data)
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
        assert_eq!(et, "message_start"); // golden wire-contract literal (kept bare on purpose)
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
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "x".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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
            logprobs: Vec::new(),
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
            provider_signal: Some(ERR_TYPE_RATE_LIMIT.to_string()),
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
            Some("rate_limit_error"), // golden wire-contract literal (kept bare on purpose)
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
    /// (not `""`) and still a non-empty `message`. Guards that the Option is carried through
    /// (no `unwrap_or_default()`) and that a message is always present.
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
        let data = serde_json::json!({ "error": { "type": ERR_TYPE_OVERLOADED } });
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
            Some("overloaded_error") // golden wire-contract literal (kept bare on purpose)
        );
    }

    /// Regression: the streaming `error` reader hardcoded `StatusClass::ClientError`
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
            read_stream_error_class(ERR_TYPE_OVERLOADED),
            StatusClass::Overloaded
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class(ERR_TYPE_OVERLOADED),
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
            read_stream_error_class(ERR_TYPE_RATE_LIMIT),
            StatusClass::RateLimit
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class(ERR_TYPE_RATE_LIMIT),
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
            read_stream_error_class(ERR_TYPE_API_ERROR),
            StatusClass::ServerError
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class(ERR_TYPE_API_ERROR),
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
            read_stream_error_class(ERR_TYPE_TIMEOUT),
            StatusClass::Timeout
        );
    }

    #[test]
    fn stream_error_authentication_is_auth_hard_down() {
        assert_eq!(
            read_stream_error_class(ERR_TYPE_AUTHENTICATION),
            StatusClass::Auth
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class(ERR_TYPE_AUTHENTICATION),
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
            read_stream_error_class(ERR_TYPE_PERMISSION),
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
            read_stream_error_class(ERR_TYPE_INVALID_REQUEST),
            StatusClass::ClientError
        );
        let sig = CanonicalSignal {
            class: read_stream_error_class(ERR_TYPE_INVALID_REQUEST),
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
            read_stream_error_class(ERR_TYPE_NOT_FOUND),
            StatusClass::ClientError
        );
        assert_eq!(
            read_stream_error_class(ERR_TYPE_REQUEST_TOO_LARGE),
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
    /// Anthropic error envelope, alongside the `type`/`error` fields.
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
            Some("rate_limit_error") // golden wire-contract literal (kept bare on purpose)
        );
    }

    /// Regression: a `system` field in ARRAY form must be read via `as_array()` (no
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

    /// Regression: a non-array, non-string `system` value (e.g. a number) must NOT panic
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

    /// Regression: a `tool_result` block whose `content` is an ARRAY of nested blocks
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

    /// Regression: a `read_response` body whose top-level `content` is an array must be
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

    /// Id-synthesis collision guard: `synth_message_id` fills its 24-char suffix with pure CSPRNG
    /// base62 (no timestamp, no counter), so distinct ids must not collide even under rapid minting.
    /// We assert the synthesized ids are strictly unique across many rapid calls, and that each has
    /// the native Anthropic shape (`msg_01` + 24 base62 chars = 30 chars).
    #[test]
    fn synth_message_id_no_collision_under_rapid_minting() {
        let n = 10_000;
        let ids: std::collections::HashSet<String> = (0..n).map(|_| synth_message_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "every synthesized message id must be unique (fixed-width counter is injective)"
        );
        // Every id matches the native Anthropic shape: `msg_` + `01` version marker + 24 random
        // base62 chars = 30 chars total. The 30-char total matches native `msg_01` + 24 random
        // chars, removing the id-LENGTH tell a client could use to distinguish a synthesized id.
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

    /// Request ids share the same fixed-width construction and must never collide across rapid minting.
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

    /// An IR Image carrying the `"image_url"` media_type sentinel (an https:// URL recorded by the
    /// OpenAI/Responses reader) must be written as Anthropic's native URL image source
    /// `{"type":"url","url":<url>}`, NOT as a base64 source with `media_type:"image_url"`
    /// (which Anthropic 400s).
    #[test]
    fn write_block_image_url_sentinel_emits_native_url_source() {
        let block = crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url("https://example.com/cat.png".to_string()),
            cache_control: None,
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

    /// A genuine base64 image (a real `image/*` media_type) must still take the base64 source path
    /// unchanged — the sentinel handling must not regress the common case.
    #[test]
    fn write_block_real_base64_image_unchanged() {
        let block = crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 {
                media_type: "image/png".to_string(),
                data: "iVBORw0KGgo=".to_string(),
            },
            cache_control: None,
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

    /// An Anthropic `cache_control` breakpoint placed ON an `image` or `thinking`
    /// content block must survive read→IR→write instead of silently vanishing (a cache-hit cost
    /// regression and a same-protocol byte difference). Both block types now carry the breakpoint
    /// first-class in the IR; the reader populates it and the writer re-emits it.
    #[test]
    fn cache_control_on_image_and_thinking_blocks_round_trips() {
        // Image block with an ephemeral cache breakpoint.
        let img_in = serde_json::json!({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="},
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        });
        let ir_img = read_block(&img_in).expect("read image block");
        match &ir_img {
            crate::ir::IrBlock::Image { cache_control, .. } => assert!(
                cache_control.is_some(),
                "image cache_control must be carried into the IR"
            ),
            other => panic!("expected Image, got {other:?}"),
        }
        let img_out = write_block(&ir_img);
        assert_eq!(
            img_out.get("cache_control"),
            Some(&serde_json::json!({"type": "ephemeral"})), // golden wire-contract literal (kept bare on purpose)
            "image cache_control must be re-emitted on the wire: {img_out}"
        );

        // Thinking block with an ephemeral cache breakpoint.
        let think_in = serde_json::json!({
            "type": "thinking",
            "thinking": "reasoning…",
            "signature": "sig-xyz",
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        });
        let ir_think = read_block(&think_in).expect("read thinking block");
        match &ir_think {
            crate::ir::IrBlock::Thinking { cache_control, .. } => assert!(
                cache_control.is_some(),
                "thinking cache_control must be carried into the IR"
            ),
            other => panic!("expected Thinking, got {other:?}"),
        }
        let think_out = write_block(&ir_think);
        assert_eq!(
            think_out.get("cache_control"),
            Some(&serde_json::json!({"type": "ephemeral"})), // golden wire-contract literal (kept bare on purpose)
            "thinking cache_control must be re-emitted on the wire: {think_out}"
        );
    }

    /// Regression (cross-protocol image data loss): an Anthropic URL-type image source
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
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(url),
                ..
            } => {
                assert_eq!(
                    url, "https://example.com/cat.png",
                    "a url source must map to the typed Url variant, preserved verbatim"
                );
            }
            other => panic!("expected IrBlock::Image(Url), got {other:?}"),
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

    /// Non-regression: a genuine base64 image source must still parse to its real
    /// `image/*` media_type and base64 data — the url branch must not intercept it.
    #[test]
    fn read_block_base64_image_source_unchanged() {
        let block_json = serde_json::json!({
            "type": "image",
            "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" }
        });
        let ir = read_block(&block_json).expect("base64 image source parses");
        match ir {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 { media_type, data },
                ..
            } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, "iVBORw0KGgo=");
            }
            other => panic!("expected IrBlock::Image, got {other:?}"),
        }
    }

    /// Completeness: a valid native Anthropic content-block type the IR does not model
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

        // A `redacted_thinking` block (a valid native type the IR does not model directly)
        // is now PRESERVED — not degraded to empty Text — by mapping it onto the redacted-reasoning
        // sentinel carrier (the same IR shape Bedrock's `redactedContent` uses), with the opaque
        // `data` bytes in `text`. It must still not 400.
        let redacted =
            serde_json::json!({ "type": BLOCK_TYPE_REDACTED_THINKING, "data": "abc123" });
        match read_block(&redacted).expect("redacted_thinking must not 400") {
            crate::ir::IrBlock::Thinking {
                text,
                redacted,
                signature,
                ..
            } => {
                assert_eq!(text, "abc123", "opaque redacted data preserved in text");
                assert!(redacted, "redacted_thinking sets the typed redacted flag");
                assert!(signature.is_none(), "no sentinel smuggled in signature");
            }
            other => panic!("expected Thinking carrier for redacted_thinking, got {other:?}"),
        }
    }

    /// Round-trip: an Anthropic `redacted_thinking` block read on the RESPONSE path must
    /// re-emit as a NATIVE `redacted_thinking` block (preserving the opaque `data` bytes) on
    /// Anthropic egress — NOT as a plaintext `thinking` block, and WITHOUT leaking the `__busbar`
    /// sentinel onto the wire. This confirms the reader/writer pairing round-trips response reasoning.
    #[test]
    fn redacted_thinking_response_round_trips_as_native_block() {
        let native = serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude",
            "content": [{"type": BLOCK_TYPE_REDACTED_THINKING, "data": "OPAQUEBYTES"}],
            "stop_reason": STOP_END_TURN,
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let ir = AnthropicReader
            .read_response(&native)
            .expect("response with redacted_thinking parses");
        // Carrier shape preserved in the IR.
        match &ir.content[0] {
            crate::ir::IrBlock::Thinking { text, redacted, .. } => {
                assert_eq!(text, "OPAQUEBYTES");
                assert!(*redacted, "redacted_thinking sets the typed redacted flag");
            }
            other => panic!("expected redacted Thinking carrier, got {other:?}"),
        }
        // Writer re-emits a NATIVE redacted_thinking block.
        let out = AnthropicWriter.write_response(&ir);
        let block = &out["content"][0];
        assert_eq!(
            block["type"].as_str(),
            Some("redacted_thinking"), // golden wire-contract literal (kept bare on purpose)
            "must re-emit native redacted_thinking, not plaintext thinking"
        );
        assert_eq!(block["data"].as_str(), Some("OPAQUEBYTES"));
        assert!(
            !out.to_string().contains("__busbar"),
            "no busbar marker may reach the wire"
        );
    }

    /// Uniformity: `synth_id_with_prefix` must draw each base62 character
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
                let idx = ANTHROPIC_NATIVE_ALPHABET
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

    /// Shape invariant: rejection sampling must not change the native length
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

    /// Regression (unchecked cast truncation): `max_tokens`/`top_k` larger than `u32::MAX` must drop to
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

    /// On the REQUEST side `write_message` must drop an assistant
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
                    redacted: false,
                    cache_control: None,
                },
                crate::ir::IrBlock::Thinking {
                    text: "signed reasoning".to_string(),
                    signature: Some("sig-abc".to_string()),
                    redacted: false,
                    cache_control: None,
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

    /// Regression (empty-content): when every content block is filtered out — e.g. an
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
                    redacted: false,
                    cache_control: None,
                },
                crate::ir::IrBlock::Thinking {
                    text: "unsigned reasoning B".to_string(),
                    signature: None,
                    redacted: false,
                    cache_control: None,
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

    /// Companion: a message with a single surviving block still emits a populated
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

    /// Non-regression: the request-side filter must NOT affect the response
    /// path — `write_response` still surfaces an unsigned thinking block as a `thinking` content
    /// block (response reasoning has no signature requirement).
    #[test]
    fn write_response_keeps_unsigned_thinking_block() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Thinking {
                text: "visible reasoning".to_string(),
                signature: None,
                redacted: false,
                cache_control: None,
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

    /// `message_start` must carry a `usage` object even when the IR `MessageStart.usage` is None
    /// (the OpenAI→Anthropic case). The native API always emits `usage:{input_tokens,output_tokens}`
    /// at stream open, and the TS SDK types it as required — a missing key crashes a client that
    /// reads `message.usage.input_tokens`.
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
        assert_eq!(et, "message_start"); // golden wire-contract literal (kept bare on purpose)
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

    /// When usage IS present on `message_start`, its values and the optional cache fields must flow
    /// through verbatim.
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

    /// Regression (terminal-event drop): reading a `message_delta` whose data omits the
    /// `usage` key must STILL yield the `MessageDelta` event — `usage` is optional on read and must
    /// not be `?`-propagated, because dropping the event would discard the terminal `stop_reason` and
    /// leave the client unable to tell whether generation completed. Counters default to zero.
    #[test]
    fn read_message_delta_without_usage_preserves_terminal_event() {
        let data = serde_json::json!({
            "delta": { "stop_reason": STOP_END_TURN, "stop_sequence": null }
        });
        let ev = AnthropicReader
            .read_response_event(EVT_MESSAGE_DELTA, &data)
            .expect("message_delta without usage must still parse, not be dropped");
        match ev {
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                assert_eq!(
                    stop_reason,
                    Some(crate::ir::IrStopReason::EndTurn),
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

    /// When `usage` IS present on a `message_delta`,
    /// its counters and optional cache fields flow through verbatim.
    #[test]
    fn read_message_delta_with_usage_flows_through() {
        let data = serde_json::json!({
            "delta": { "stop_reason": STOP_MAX_TOKENS },
            "usage": {
                "input_tokens": 11,
                "output_tokens": 22,
                "cache_creation_input_tokens": 3,
                "cache_read_input_tokens": 4
            }
        });
        let ev = AnthropicReader
            .read_response_event(EVT_MESSAGE_DELTA, &data)
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

    /// Conformance: the non-stream `write_response` must
    /// emit `model` UNCONDITIONALLY — the official SDKs type `Message.model` as a required string, so
    /// a body that omits it fails to decode. On a Bedrock→Anthropic path where `resp.model` is None,
    /// the key must still be present (empty-string fallback), not dropped.
    #[test]
    fn write_response_emits_model_even_when_none() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
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

    /// A present model round-trips verbatim.
    #[test]
    fn write_response_preserves_present_model() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
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

    /// Conformance (streaming sibling): the streaming
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

    /// EVERY event the writer emits
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
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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
                provider_signal: Some(ERR_TYPE_OVERLOADED.to_string()),
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

    /// A non-streaming `write_response` whose IR carried no stop sequence must still emit
    /// `stop_sequence: null` — a native `Message` always carries the key. IR-idempotence is
    /// preserved: re-reading a `null` stop_sequence yields `None` again.
    #[test]
    fn write_response_emits_null_stop_sequence_when_absent() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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

    /// When a stop sequence IS present, the non-streaming `write_response` must carry the matched
    /// string verbatim.
    #[test]
    fn write_response_emits_matched_stop_sequence_string() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: Some(crate::ir::IrStopReason::StopSequence),
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

    /// A billing error whose body carries a message
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

    /// Non-regression: the structured `error.code` 400/422 → ClientError path must
    /// still fire when the code IS present (the lift-out of the message checks must not regress it).
    #[test]
    fn classify_structured_code_still_maps_client_error() {
        let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"code":"400","message":"bad"}});
        let body = serde_json::to_vec(&body_json).unwrap();
        let sig = AnthropicReader.classify(StatusCode::BAD_REQUEST, &body);
        assert!(
            matches!(sig.class, StatusClass::ClientError),
            "structured code 400 must still classify as ClientError, got {:?}",
            sig.class
        );
    }

    /// Synthesized ids must match the native
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
            // The previous clock+counter `(unix_second, counter)` scheme
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

    /// Regression: synthesized ids must come from the CSPRNG, not a deterministic clock+counter
    /// scheme. Two back-to-back calls within the same clock tick must differ (the old
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

    /// Regression: the leading characters of the token must vary across calls. The old
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

    /// Regression: the modeled-key filter (now a sorted `binary_search` slice rather
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

    /// The in-stream `error` event's
    /// `error.message` must NEVER carry reverse-proxy vocabulary ("upstream", "gateway",
    /// "backend", "proxy"). When a provider signal is present, the message is the provider's own
    /// type token VERBATIM (no router prefix).
    #[test]
    fn write_response_event_error_message_has_no_proxy_vocabulary() {
        for (signal, expected) in [
            (Some(ERR_TYPE_OVERLOADED.to_string()), "overloaded_error"), // golden wire-contract literal (kept bare on purpose)
            (Some(ERR_TYPE_RATE_LIMIT.to_string()), "rate_limit_error"), // golden wire-contract literal (kept bare on purpose)
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

    /// Regression: a 200 `read_response` body that OMITS `usage` must read back
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

    /// Regression: a wire `role:"system"` message inside `messages` must be
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

    /// Regression (writer): `write_request` must NEVER emit a message with
    /// `role:"system"` — even for a CROSS-PROTOCOL IR that still carries an `IrRole::System` message
    /// in `req.messages` (one that never passed through Anthropic's own `read_request` promotion).
    /// The writer folds it into the top-level `system` field and filters it out of `messages`,
    /// mirroring the gemini/bedrock writers. Fails against old code (which emitted `role:"system"`).
    #[test]
    fn write_request_never_emits_system_role_message() {
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
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
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
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

    /// Regression (writer unit): a direct `write_message` call on an `IrRole::System`
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

    // ---- tool_choice round-trips (Anthropic native shape) ----

    fn read_anthropic_request(body: serde_json::Value) -> crate::ir::IrRequest {
        AnthropicReader.read_request(&body).expect("read_request")
    }

    #[test]
    fn tool_choice_any_required_roundtrips() {
        // Anthropic {type:"any"} == "must call some tool" == IR Required; round-trips back to {any}.
        let ir = read_anthropic_request(serde_json::json!({
            "model": "claude", "max_tokens": 16, "messages": [],
            "tool_choice": {"type": "any"}
        }));
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["tool_choice"], serde_json::json!({"type": "any"}));
    }

    #[test]
    fn tool_choice_specific_tool_roundtrips() {
        let ir = read_anthropic_request(serde_json::json!({
            "model": "claude", "max_tokens": 16, "messages": [],
            "tool_choice": {"type": "tool", "name": "get_weather"}
        }));
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out["tool_choice"],
            serde_json::json!({"type": "tool", "name": "get_weather"})
        );
    }

    #[test]
    fn tool_choice_auto_and_none_roundtrip() {
        for (native_type, variant) in [
            ("auto", crate::ir::IrToolChoice::Auto),
            ("none", crate::ir::IrToolChoice::None),
        ] {
            let ir = read_anthropic_request(serde_json::json!({
                "model": "c", "max_tokens": 16, "messages": [],
                "tool_choice": {"type": native_type}
            }));
            assert_eq!(ir.tool_choice, Some(variant));
            let out = AnthropicWriter.write_request(&ir);
            assert_eq!(out["tool_choice"], serde_json::json!({"type": native_type}));
        }
    }

    #[test]
    fn tool_choice_absent_emits_nothing() {
        let ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16, "messages": []
        }));
        assert_eq!(ir.tool_choice, None);
        let out = AnthropicWriter.write_request(&ir);
        assert!(
            out.get("tool_choice").is_none(),
            "absent tool_choice must NOT gain a spurious value on write"
        );
    }

    /// Cross-protocol: an OpenAI forced-function `tool_choice` reaches an Anthropic backend as
    /// the native `{type:"tool", name}` directive — NOT silently degraded to auto. Simulates the
    /// cross-protocol seam by clearing `extra` between read and write (forward.rs `ir.extra.clear()`).
    #[test]
    fn tool_choice_openai_specific_to_anthropic_targeted() {
        let openai_body = serde_json::json!({
            "model": "gpt", "messages": [],
            "tools": [{"type":"function","function":{"name":"get_weather","parameters":{}}}],
            "tool_choice": {"type":"function","function":{"name":"get_weather"}}
        });
        let mut ir = crate::proto::openai_chat::OpenAiReader
            .read_request(&openai_body)
            .expect("openai read");
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );
        ir.extra.clear(); // cross-protocol seam
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out["tool_choice"],
            serde_json::json!({"type": "tool", "name": "get_weather"}),
            "forced OpenAI tool must round-trip to Anthropic's targeted tool_choice, not auto"
        );
    }

    // ---- tool-scoped cache_control survives the cross-protocol seam ----

    #[test]
    fn tool_definition_cache_control_roundtrips() {
        let ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16, "messages": [],
            "tools": [{
                "name": "big_tool", "input_schema": {"type":"object"},
                "cache_control": {"type": CACHE_KIND_EPHEMERAL}
            }]
        }));
        assert!(
            ir.tools[0].cache_control.is_some(),
            "tool-def cache_control must be promoted into the IR"
        );
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out["tools"][0]["cache_control"],
            serde_json::json!({"type": "ephemeral"}), // golden wire-contract literal (kept bare on purpose)
            "tool-def cache breakpoint must survive to the Anthropic egress"
        );
    }

    #[test]
    fn tool_use_and_result_cache_control_roundtrips() {
        let ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16,
            "messages": [
                {"role": "assistant", "content": [
                    {"type":STOP_TOOL_USE,"id":"t1","name":"f","input":{},
                     "cache_control":{"type": CACHE_KIND_EPHEMERAL}}
                ]},
                {"role": "user", "content": [
                    {"type":"tool_result","tool_use_id":"t1","content":"ok",
                     "cache_control":{"type": CACHE_KIND_EPHEMERAL}}
                ]}
            ]
        }));
        // ToolUse cache_control promoted...
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::ToolUse { cache_control, .. } => {
                assert!(cache_control.is_some(), "tool_use cache_control lost")
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        // ...and ToolResult cache_control promoted.
        match &ir.messages[1].content[0] {
            crate::ir::IrBlock::ToolResult { cache_control, .. } => {
                assert!(cache_control.is_some(), "tool_result cache_control lost")
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out["messages"][0]["content"][0]["cache_control"],
            serde_json::json!({"type": "ephemeral"}) // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(
            out["messages"][1]["content"][0]["cache_control"],
            serde_json::json!({"type": "ephemeral"}) // golden wire-contract literal (kept bare on purpose)
        );
    }

    // ---- temperature clamp to Anthropic's [0,1] ----

    #[test]
    fn temperature_above_one_is_clamped_not_422() {
        // An OpenAI/Responses-valid temp of 1.5 must be clamped to 1.0 for Anthropic (which rejects
        // >1.0 with a 422), never forwarded verbatim.
        let mut ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16, "messages": []
        }));
        ir.temperature = Some(1.5);
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out["temperature"],
            serde_json::json!(1.0),
            "temperature 1.5 must clamp to 1.0, not produce a 422-bound body"
        );
        // A value already in range is untouched.
        ir.temperature = Some(0.7);
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["temperature"], serde_json::json!(0.7));
        // A negative value clamps up to 0.0.
        ir.temperature = Some(-0.3);
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["temperature"], serde_json::json!(0.0));
    }

    // ---- temperature clamp is NON-SILENT (signals when it changes the value) ----
    #[test]
    fn test_clamp_temperature_for_anthropic_signals_on_change() {
        // An out-of-range value is clamped AND flagged as changed (so the writer warns).
        assert_eq!(clamp_temperature_for_anthropic(1.5), (1.0, true));
        assert_eq!(clamp_temperature_for_anthropic(2.0), (1.0, true));
        assert_eq!(clamp_temperature_for_anthropic(-0.3), (0.0, true));
        // An in-range value is untouched AND NOT flagged (no spurious warn on a faithful value).
        assert_eq!(clamp_temperature_for_anthropic(0.7), (0.7, false));
        assert_eq!(clamp_temperature_for_anthropic(0.0), (0.0, false));
        assert_eq!(clamp_temperature_for_anthropic(1.0), (1.0, false));
    }

    // ---- is_finite guard: a non-finite temperature is returned unchanged, was_clamped=false. ----
    // Unreachable via valid JSON (sonic_rs rejects NaN/Inf at parse) but makes the helper total: a
    // NaN/Inf must NOT be treated as a real value clamped from range.
    #[test]
    fn test_clamp_temperature_for_anthropic_passes_through_non_finite() {
        let (nan_out, nan_clamped) = clamp_temperature_for_anthropic(f64::NAN);
        assert!(nan_out.is_nan(), "NaN must pass through unchanged");
        assert!(!nan_clamped, "NaN must NOT be flagged as clamped");
        assert_eq!(
            clamp_temperature_for_anthropic(f64::INFINITY),
            (f64::INFINITY, false)
        );
        assert_eq!(
            clamp_temperature_for_anthropic(f64::NEG_INFINITY),
            (f64::NEG_INFINITY, false)
        );
    }

    // ---- max_tokens: 0 is treated as absent (matches the 5 sibling readers' `.filter(|&v| v > 0)`).
    #[test]
    fn test_anthropic_reader_max_tokens_zero_yields_none() {
        let wire = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 0,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = AnthropicReader.read_request(&wire).expect("read_request");
        assert_eq!(
            ir.max_tokens, None,
            "max_tokens: 0 must be treated as absent (None), matching the sibling readers"
        );
        // A positive cap is still read normally.
        let wire_ok = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 256,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir_ok = AnthropicReader
            .read_request(&wire_ok)
            .expect("read_request");
        assert_eq!(ir_ok.max_tokens, Some(256));
    }

    // ---- OpenAI -> Anthropic tool_choice cross-protocol translation ----
    // The IR variant is protocol-neutral, so an OpenAI-ingress tool_choice (read into the IR by the
    // OpenAI reader) must emit the correct Anthropic native shape on the Anthropic writer. The
    // `required` -> `{"type":"any"}` mapping is the load-bearing case.
    #[test]
    fn test_openai_to_anthropic_tool_choice_directions() {
        use crate::ir::IrToolChoice;
        let cases = [
            (IrToolChoice::Auto, serde_json::json!({"type": "auto"})),
            (IrToolChoice::None, serde_json::json!({"type": "none"})),
            // OpenAI `"required"` reads to IR `Required`; Anthropic's native form is `{"type":"any"}`.
            (IrToolChoice::Required, serde_json::json!({"type": "any"})),
            (
                IrToolChoice::Tool {
                    name: "get_weather".to_string(),
                },
                serde_json::json!({"type": "tool", "name": "get_weather"}),
            ),
        ];
        for (tc, expected) in cases {
            let mut ir = read_anthropic_request(serde_json::json!({
                "model": "c", "max_tokens": 16, "messages": []
            }));
            ir.tool_choice = Some(tc.clone());
            let out = AnthropicWriter.write_request(&ir);
            assert_eq!(out["tool_choice"], expected, "tool_choice {tc:?}");
        }
    }

    // ---- catch-all tool_choice values map to None (never silently Auto/Required) ----
    #[test]
    fn test_anthropic_unknown_tool_choice_type_is_none() {
        // An object with an unrecognized `type` must degrade to None, not force a tool call.
        assert_eq!(
            read_anthropic_tool_choice(Some(&serde_json::json!({"type": "future_mode"}))),
            None
        );
    }

    #[test]
    fn test_anthropic_tool_choice_tool_without_name_is_none() {
        // `{"type":"tool"}` with NO `name` is structurally incomplete -> None (we can't target an
        // unnamed tool, and must not fall back to forcing some tool).
        assert_eq!(
            read_anthropic_tool_choice(Some(&serde_json::json!({"type": "tool"}))),
            None
        );
    }

    // ---- IR `safety` stop_reason is not a native Anthropic stop_reason -> map to end_turn ----
    #[test]
    fn test_anthropic_safety_stop_reason_maps_to_end_turn() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: Some(crate::ir::IrStopReason::Safety),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("claude-x".to_string()),
            id: Some("msg_01abc".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = AnthropicWriter.write_response(&resp);
        assert_eq!(
            out["stop_reason"],
            serde_json::json!("end_turn"), // golden wire-contract literal (kept bare on purpose)
            "IR `safety` must collapse to the native `end_turn` on Anthropic egress; got {out}"
        );
        // A native reason still passes through verbatim.
        let resp2 = crate::ir::IrResponse {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            ..resp
        };
        let out2 = AnthropicWriter.write_response(&resp2);
        assert_eq!(out2["stop_reason"], serde_json::json!("max_tokens")); // golden wire-contract literal (kept bare on purpose)
    }

    // ---- Streaming egress: the SAME `safety` -> `end_turn` collapse must hold on the streaming
    // path (`write_response_event` / `MessageDelta`), not just the non-stream `write_response`.
    // A non-native IR `safety` reason must never leak into the wire
    // `message_delta.delta.stop_reason`. ----
    #[test]
    fn test_anthropic_streaming_safety_stop_reason_maps_to_end_turn() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::Safety),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (event, data) = AnthropicWriter
            .write_response_event(&ev)
            .expect("MessageDelta must emit a message_delta event");
        assert_eq!(event, "message_delta"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            data["delta"]["stop_reason"],
            serde_json::json!("end_turn"), // golden wire-contract literal (kept bare on purpose)
            "IR `safety` must collapse to native `end_turn` on the STREAMING Anthropic egress \
             (not leak `safety`); got {data}"
        );

        // A native reason still passes through verbatim on the streaming path.
        let ev2 = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_event2, data2) = AnthropicWriter
            .write_response_event(&ev2)
            .expect("MessageDelta must emit a message_delta event");
        assert_eq!(
            data2["delta"]["stop_reason"],
            serde_json::json!("max_tokens") // golden wire-contract literal (kept bare on purpose)
        );
    }

    // ---- Phase 0 fidelity items (Anthropic egress): sampling-param OMIT, response_format-drop
    // warn, and native thinking-block round-trip with signature. ----

    /// Minimal WARN-capturing tracing layer, kept local to this test module (mirrors the helper in
    /// auth.rs / config_validate.rs). Records each WARN event's `message` field so a test can assert
    /// a particular `tracing::warn!` fired without a global subscriber.
    #[derive(Clone, Default)]
    struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            struct Vis(String);
            impl tracing::field::Visit for Vis {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut vis = Vis(String::new());
            event.record(&mut vis);
            if let Ok(mut msgs) = self.0.lock() {
                msgs.push(vis.0);
            }
        }
    }

    /// SAMPLING (Phase 0): Anthropic's Messages API does NOT support `frequency_penalty`,
    /// `presence_penalty`, `seed`, or `n`. A cross-protocol IR carrying every one of them (e.g. read
    /// from an OpenAI request) must produce an egress that emits NONE of those keys — the writer never
    /// references these fields, so they are dropped (the correct lossy-by-target behavior; emitting an
    /// unknown key would 400 the upstream). Pins that nothing silently mis-maps them onto the wire.
    #[test]
    fn write_request_omits_unsupported_sampling_params() {
        let req = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            max_tokens: Some(16),
            frequency_penalty: Some(0.5),
            presence_penalty: Some(0.25),
            seed: Some(42),
            n: Some(3),
            ..Default::default()
        };
        let out = AnthropicWriter.write_request(&req);
        let obj = out.as_object().expect("write_request emits an object");
        for key in ["frequency_penalty", "presence_penalty", "seed", "n"] {
            assert!(
                !obj.contains_key(key),
                "Anthropic egress must NOT emit `{key}` (Messages API has no such field); got {out}"
            );
        }
        // Sanity: the modeled fields it DOES support are still present, so the omission is targeted.
        assert_eq!(obj.get("max_tokens"), Some(&serde_json::json!(16)));
        assert!(obj.contains_key("messages"));
    }

    /// response_format (M1): a cross-protocol IR carrying `response_format` reaching the Anthropic
    /// writer must NOT silently lose it — Anthropic has no native `response_format` and tool-forcing
    /// is not implemented this pass, so the writer DROPS the directive but emits a `warn!` naming
    /// response_format so the divergence is observable. Asserts (a) the warn fires and (b) no
    /// `response_format` key leaks onto the egress (which would 400 the upstream).
    #[test]
    fn write_request_warns_and_drops_response_format_on_cross_protocol_egress() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let req = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "extract".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            max_tokens: Some(16),
            response_format: Some(crate::ir::IrResponseFormat {
                json: true,
                schema: Some(serde_json::json!({"type": "object"})),
                name: Some("out".to_string()),
                strict: None,
                description: None,
            }),
            ..Default::default()
        };

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let out =
            tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

        assert!(
            !out.as_object().unwrap().contains_key("response_format"),
            "Anthropic egress must NOT emit `response_format` (no native field); got {out}"
        );
        let msgs = cap.0.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains("response_format")),
            "a response_format-drop warning must fire on cross-protocol Anthropic egress; got {msgs:?}"
        );
    }

    /// LOW (json-tool-result drop observability + no-leak): a Bedrock `tool_result_json` sentinel
    /// block (JSON_BLOCK_SENTINEL) nested in a ToolResult reaching the Anthropic egress must (a) NOT
    /// leak a corrupt base64 image source (`media_type:"tool_result_json"`) onto the wire and (b) emit
    /// a `warn!` so the structured-payload loss is observable (drop-with-warn convention).
    #[test]
    fn write_request_warns_and_drops_json_tool_result_block() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let req = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "call-1".to_string(),
                    content: vec![
                        crate::ir::IrBlock::Text {
                            text: "ok".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                        crate::ir::IrBlock::Json(serde_json::json!({ "answer": 42 })),
                    ],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            max_tokens: Some(16),
            ..Default::default()
        };

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let out =
            tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("tool_result_json"),
            "a json-tool-result sentinel must NOT leak onto the Anthropic wire; got {wire}"
        );
        let msgs = cap.0.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains("json tool-result")),
            "a json-tool-result drop warning must fire on Anthropic egress; got {msgs:?}"
        );
    }

    /// Counter-case: a request WITHOUT `response_format` must NOT emit the drop warning — the warn is
    /// gated on the directive's presence, so a request that never carried one is silent.
    #[test]
    fn write_request_no_response_format_warning_when_absent() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let req = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            max_tokens: Some(16),
            ..Default::default()
        };

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let _ =
            tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

        let msgs = cap.0.lock().unwrap();
        assert!(
            !msgs.iter().any(|m| m.contains("response_format")),
            "no response_format warning must fire when the directive is absent; got {msgs:?}"
        );
    }

    /// THINKING (native Anthropic path): an extended-thinking content block with a `signature` must
    /// round-trip through the Anthropic reader/writer LOSSLESSLY — `read_block` maps a native
    /// `{type:"thinking", thinking, signature}` to `IrBlock::Thinking{text, signature}`, and
    /// `write_block` re-emits exactly that native shape (with the signature preserved). This pins the
    /// native path to the same fidelity already verified on the Bedrock reasoningContent↔Thinking
    /// path. A read→write→read cycle must preserve both the text and the (mandatory-on-request)
    /// signature.
    #[test]
    fn thinking_block_roundtrips_with_signature() {
        let native = serde_json::json!({
            "type": "thinking",
            "thinking": "let me reason about this",
            "signature": "EqoBCkgIARAB...sig-bytes"
        });
        // Read → IR.
        let block = read_block(&native).expect("thinking block reads");
        match &block {
            crate::ir::IrBlock::Thinking {
                text, signature, ..
            } => {
                assert_eq!(text, "let me reason about this");
                assert_eq!(
                    signature.as_deref(),
                    Some("EqoBCkgIARAB...sig-bytes"),
                    "the extended-thinking signature must survive into the IR"
                );
            }
            other => panic!("expected IrBlock::Thinking, got {other:?}"),
        }
        // IR → wire: native shape with the signature preserved.
        let out = write_block(&block);
        assert_eq!(out.get("type").and_then(|t| t.as_str()), Some("thinking"));
        assert_eq!(
            out.get("thinking").and_then(|t| t.as_str()),
            Some("let me reason about this")
        );
        assert_eq!(
            out.get("signature").and_then(|s| s.as_str()),
            Some("EqoBCkgIARAB...sig-bytes"),
            "write_block must re-emit the thinking signature, not drop it"
        );
        // Full round-trip: re-reading the written block yields the identical IR block.
        let reread = read_block(&out).expect("written thinking block re-reads");
        assert_eq!(reread, block, "thinking block must round-trip losslessly");
    }

    /// THINKING (response egress, signed): a Thinking block carried in an IR RESPONSE surfaces on the
    /// Anthropic response egress with its signature intact — `write_response` routes content blocks
    /// through `write_block`, which preserves the signature (the request-path `write_message` filter
    /// that drops UNSIGNED thinking blocks does NOT apply here, so a signed reasoning block reaches the
    /// client). Guards that native reasoning is not lost on the response writer.
    #[test]
    fn thinking_block_with_signature_survives_response_egress() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Thinking {
                    text: "step-by-step".to_string(),
                    signature: Some("sig-abc".to_string()),
                    redacted: false,
                    cache_control: None,
                },
                crate::ir::IrBlock::Text {
                    text: "answer".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
            ],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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
        let content = out
            .get("content")
            .and_then(|c| c.as_array())
            .expect("response carries a content array");
        let thinking = content
            .iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking"))
            .expect("a thinking block must be present on the response egress");
        assert_eq!(
            thinking.get("thinking").and_then(|t| t.as_str()),
            Some("step-by-step")
        );
        assert_eq!(
            thinking.get("signature").and_then(|s| s.as_str()),
            Some("sig-abc"),
            "the signed thinking block must reach the client with its signature on response egress"
        );
    }

    /// D2: a Responses `file_id` image (the FILE_ID_IMAGE_SENTINEL media_type) reaching the Anthropic
    /// egress is an unresolvable cross-vendor reference. It must be SKIPPED — NOT emitted as a corrupt
    /// base64 `source` with `media_type:"file_id"` (which Anthropic rejects). The user message's
    /// content must carry no image block; the text block still survives.
    #[test]
    fn test_write_request_file_id_image_dropped_not_corrupted() {
        let writer = AnthropicWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "describe this".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Vendor {
                            vendor: "responses",
                            value: serde_json::json!({ "file_id": "file-abc123" }),
                        },
                        cache_control: None,
                    },
                ],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("file-abc123") && !wire.contains("file_id"),
            "a file_id image must not leak onto the Anthropic wire (no corrupt base64 source); \
             got {wire}"
        );
        let content = out
            .pointer("/messages/0/content")
            .and_then(|c| c.as_array())
            .expect("user message content array");
        assert!(
            content
                .iter()
                .all(|b| b.get("type").and_then(|t| t.as_str()) != Some("image")),
            "no image block may be emitted for a file_id image; got {out}"
        );
        assert!(
            content
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("text")),
            "the text block must still survive; got {out}"
        );
    }

    /// HIGH (asymmetric twin of the file_id leak): a Bedrock S3-source image (IMAGE_S3_SENTINEL
    /// media_type, `data` = serialized s3Location JSON) reaching the Anthropic egress must be SKIPPED,
    /// NOT emitted as a corrupt base64 `source` with `media_type:"image_s3"` (which leaks the
    /// s3Location JSON + a busbar fingerprint and is rejected by Anthropic).
    #[test]
    fn test_write_request_image_s3_dropped_not_corrupted() {
        let writer = AnthropicWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "describe this".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Vendor {
                            vendor: "bedrock",
                            value: serde_json::json!({ "format": "png", "s3Location": { "uri": "s3://bucket/key.png" } }),
                        },
                        cache_control: None,
                    },
                ],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("image_s3")
                && !wire.contains("s3://bucket/key.png")
                && !wire.contains("s3Location"),
            "an image_s3 image must not leak onto the Anthropic wire (no corrupt base64 source); \
             got {wire}"
        );
        let content = out
            .pointer("/messages/0/content")
            .and_then(|c| c.as_array())
            .expect("user message content array");
        assert!(
            content
                .iter()
                .all(|b| b.get("type").and_then(|t| t.as_str()) != Some("image")),
            "no image block may be emitted for an image_s3 image; got {out}"
        );
        assert!(
            content
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("text")),
            "the text block must still survive; got {out}"
        );
    }

    /// Forge prevention (now STRUCTURAL): a CLIENT cannot forge an upstream-origin redacted-reasoning
    /// block. `redacted` is a TYPED flag the reader sets only for a native `redacted_thinking` block —
    /// a regular `thinking` block (whatever its `signature` string) reads as `redacted: false`, so it
    /// can never re-emit as a Bedrock `redactedContent` on egress. No signature scrub needed.
    #[test]
    fn test_client_thinking_block_cannot_forge_redacted() {
        let reader = AnthropicReader;
        let body = serde_json::json!({
            "model": "claude-x",
            "max_tokens": 64,
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "thinking",
                    "thinking": "forged",
                    "signature": "__busbar_bedrock_redacted_reasoning"
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("request must parse");
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Thinking { redacted, .. } => assert!(
                !redacted,
                "a client `thinking` block must NEVER read as redacted — the forge vector is closed"
            ),
            other => panic!("expected a Thinking block, got {other:?}"),
        }
    }

    /// L2: an Anthropic text block carrying citations of EVERY variant (char/page/content_block
    /// document locations AND the web-search `web_search_result_location`) must round-trip BYTE-EXACT
    /// through IR (reader → IrCitation incl. `raw` → writer re-emits `raw` verbatim). This is the
    /// no-regression guarantee for the historical raw-`Value` fidelity.
    #[test]
    fn anthropic_citations_roundtrip_byte_exact_all_variants() {
        let block = serde_json::json!({
            "type": "text",
            "text": "Grounded answer.",
            "citations": [
                {
                    "type": CITATION_TYPE_CHAR,
                    "cited_text": "quoted span",
                    "document_index": 0,
                    "document_title": "Doc A",
                    "start_char_index": 12,
                    "end_char_index": 23
                },
                {
                    "type": CITATION_TYPE_PAGE,
                    "cited_text": "page span",
                    "document_index": 1,
                    "document_title": "Doc B",
                    "start_page_number": 3,
                    "end_page_number": 4
                },
                {
                    "type": CITATION_TYPE_CONTENT_BLOCK,
                    "cited_text": "block span",
                    "document_index": 2,
                    "document_title": "Doc C",
                    "start_block_index": 5,
                    "end_block_index": 7
                },
                {
                    "type": "web_search_result_location",
                    "url": "https://example.com/page",
                    "title": "Example Page",
                    "cited_text": "web span",
                    "encrypted_index": "opaque-cursor-token"
                }
            ]
        });
        let ir = read_block(&block).expect("text block with citations must parse");
        // Neutral fields are populated (cross-protocol projection works) ...
        let citations = match &ir {
            crate::ir::IrBlock::Text { citations, .. } => citations,
            other => panic!("expected Text, got {other:?}"),
        };
        assert_eq!(citations.len(), 4);
        assert_eq!(citations[0].kind.as_deref(), Some("char_location")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(citations[0].start_index, Some(12));
        assert_eq!(citations[1].start_index, Some(3)); // page number into shared slot
        assert_eq!(citations[2].end_index, Some(7)); // block index into shared slot
        assert_eq!(
            citations[3].url.as_deref(),
            Some("https://example.com/page")
        );
        assert_eq!(
            citations[3].encrypted_index.as_deref(),
            Some("opaque-cursor-token")
        );
        // ... AND `raw` is preserved on each, guaranteeing byte-exact re-emission.
        assert!(citations.iter().all(|c| c.raw.is_some()));
        let wire = write_block(&ir);
        assert_eq!(
            wire, block,
            "Anthropic citations must round-trip byte-exact via raw"
        );
    }

    /// L2: when an IrCitation has NO `raw` (synthesized on a cross-protocol hop, e.g. Gemini→IR), the
    /// Anthropic writer BUILDS the correct Anthropic shape from neutral fields. Covers the
    /// web_search_result_location synthesis path (url/title/cited_text) a Gemini grounding source maps to.
    #[test]
    fn anthropic_writes_web_search_citation_from_neutral_fields() {
        let block = crate::ir::IrBlock::Text {
            text: "answer".to_string(),
            cache_control: None,
            citations: vec![crate::ir::IrCitation {
                kind: Some("web_search_result_location".to_string()),
                cited_text: None,
                title: Some("Source Title".to_string()),
                url: Some("https://grounding.example/doc".to_string()),
                document_index: None,
                start_index: Some(10),
                end_index: Some(42),
                encrypted_index: None,
                raw: None,
            }],
        };
        let wire = write_block(&block);
        let c = wire
            .pointer("/citations/0")
            .expect("citation must be emitted");
        assert_eq!(
            c.get("type").and_then(|v| v.as_str()),
            Some("web_search_result_location")
        );
        assert_eq!(
            c.get("url").and_then(|v| v.as_str()),
            Some("https://grounding.example/doc")
        );
        assert_eq!(
            c.get("title").and_then(|v| v.as_str()),
            Some("Source Title")
        );
    }

    /// L2: an empty-citations Text block is unaffected — no `citations` key is emitted.
    #[test]
    fn anthropic_empty_citations_text_block_unaffected() {
        let block = crate::ir::IrBlock::Text {
            text: "plain".to_string(),
            cache_control: None,
            citations: Vec::new(),
        };
        let wire = write_block(&block);
        assert!(
            wire.get("citations").is_none(),
            "no citations key for an empty-citations block; got {wire}"
        );
    }

    /// L2-5 STREAMING citations, Anthropic same-protocol byte-exactness: a native streaming
    /// `content_block_delta`/`citations_delta` must read into `IrDelta::CitationsDelta` (via
    /// `read_citation`, which stashes the source object in `raw`) and the Anthropic writer must
    /// re-emit the citation object VERBATIM through the `raw` escape hatch — so an Anthropic-shaped
    /// streamed citation round-trips byte-exact, never a lossy field-by-field reconstruction.
    #[test]
    fn read_write_streaming_citations_delta_roundtrips_byte_exact() {
        // A native web-search streaming citation (one of the 4 Anthropic variants), with a field the
        // synthesize-from-neutral path would NOT reproduce (`encrypted_index`) to prove `raw` is used.
        let native_citation = serde_json::json!({
            "type": "web_search_result_location",
            "url": "https://example.com/a",
            "title": "Source A",
            "cited_text": "the quoted span",
            "encrypted_index": "opaque-cursor-123"
        });
        let data = serde_json::json!({
            "type": EVT_CONTENT_BLOCK_DELTA,
            "index": 0,
            "delta": { "type": DELTA_TYPE_CITATIONS, "citation": native_citation }
        });

        // READ: a citations_delta content_block_delta → IrDelta::CitationsDelta(vec![citation]).
        let ev = AnthropicReader
            .read_response_event(EVT_CONTENT_BLOCK_DELTA, &data)
            .expect("a citations_delta content_block_delta must parse, not be dropped");
        let (index, citations) = match &ev {
            IrStreamEvent::BlockDelta {
                index,
                delta: IrDelta::CitationsDelta(cs),
            } => (*index, cs.clone()),
            other => panic!("expected a CitationsDelta BlockDelta, got {other:?}"),
        };
        assert_eq!(index, 0);
        assert_eq!(citations.len(), 1, "one citation per citations_delta");
        // Neutral fields filled AND the verbatim source preserved in `raw`.
        assert_eq!(citations[0].url.as_deref(), Some("https://example.com/a"));
        assert_eq!(
            citations[0].encrypted_index.as_deref(),
            Some("opaque-cursor-123")
        );
        assert_eq!(citations[0].raw.as_ref(), Some(&native_citation));

        // WRITE: the same IR delta re-emits the native content_block_delta/citations_delta, and the
        // `citation` object is BYTE-EXACT the source (raw verbatim, not reconstructed).
        let (event_type, body) = AnthropicWriter
            .write_response_event(&ev)
            .expect("a CitationsDelta must emit a content_block_delta, not None");
        assert_eq!(event_type, "content_block_delta"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            body.pointer("/delta/type").and_then(|t| t.as_str()),
            Some("citations_delta") // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(
            body.pointer("/index").and_then(|i| i.as_u64()),
            Some(0),
            "the delta must re-emit on the same block index"
        );
        assert_eq!(
            body.pointer("/delta/citation"),
            Some(&native_citation),
            "Anthropic-shaped streamed citation must round-trip BYTE-EXACT via raw"
        );
    }

    /// An Anthropic `cache_control` breakpoint placed ON a `tool_use` block must survive
    /// read→IR→write byte-for-byte. The IR carries it on `IrBlock::ToolUse.cache_control` (ir.rs:292)
    /// precisely so this Anthropic-native prefix-cache breakpoint is not silently dropped (a cache-hit
    /// cost/latency regression on the same-protocol path).
    #[test]
    fn cache_control_on_tool_use_block_round_trips() {
        let block = serde_json::json!({
            "type": STOP_TOOL_USE,
            "id": "toolu_01abc",
            "name": "get_weather",
            "input": {"location": "SF"},
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        });
        let ir = read_block(&block).expect("tool_use block with cache_control parses");
        match &ir {
            crate::ir::IrBlock::ToolUse {
                id,
                name,
                input,
                cache_control,
            } => {
                assert_eq!(id, "toolu_01abc");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &serde_json::json!({"location": "SF"}));
                assert!(
                    cache_control.is_some(),
                    "cache_control on tool_use must be captured in the IR, not dropped"
                );
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        // WRITE: the breakpoint re-emits in Anthropic's native `{type:"ephemeral"}` shape.
        let out = write_block(&ir);
        assert_eq!(
            out.pointer("/cache_control/type").and_then(|t| t.as_str()),
            Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
            "cache_control must re-emit on the tool_use block"
        );
        assert_eq!(out.get("id").and_then(|v| v.as_str()), Some("toolu_01abc"));
    }

    /// An Anthropic `cache_control` breakpoint on a `tool_result` block must survive
    /// read→IR→write. Anthropic places breakpoints on tool_result to cache the (often large) result
    /// content (ir.rs:302); the IR field `IrBlock::ToolResult.cache_control` keeps it cross-hop.
    #[test]
    fn cache_control_on_tool_result_block_round_trips() {
        let block = serde_json::json!({
            "type": "tool_result",
            "tool_use_id": "toolu_01abc",
            "content": [{"type": "text", "text": "72F and sunny"}],
            "is_error": false,
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        });
        let ir = read_block(&block).expect("tool_result block with cache_control parses");
        match &ir {
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                cache_control,
                is_error,
                ..
            } => {
                assert_eq!(tool_use_id, "toolu_01abc");
                assert!(!is_error);
                assert!(
                    cache_control.is_some(),
                    "cache_control on tool_result must be captured, not dropped"
                );
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
        let out = write_block(&ir);
        assert_eq!(
            out.pointer("/cache_control/type").and_then(|t| t.as_str()),
            Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
            "cache_control must re-emit on the tool_result block"
        );
    }

    /// A `cache_control` breakpoint on a tool DEFINITION (`tools[].cache_control`) round-trips through
    /// `IrTool.cache_control` (ir.rs:449). Anthropic caches the large tool schemas as a prefix; the
    /// breakpoint was being dropped every hop before this field existed.
    #[test]
    fn cache_control_on_tool_definition_round_trips() {
        let tool = serde_json::json!({
            "name": "get_weather",
            "description": "Get weather",
            "input_schema": {"type": "object", "properties": {}},
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        });
        let ir = read_tool(&tool).expect("tool with cache_control parses");
        assert_eq!(ir.name, "get_weather");
        assert!(
            ir.cache_control.is_some(),
            "cache_control on a tool definition must be captured in IrTool"
        );
        let out = write_tool(&ir);
        assert_eq!(
            out.pointer("/cache_control/type").and_then(|t| t.as_str()),
            Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
            "cache_control must re-emit on the tool definition"
        );
    }

    /// Full non-stream response round-trip for an UNKNOWN native `stop_reason`: the reader maps a
    /// token it does not model (here a plausible future `max_tokens_reached` variant spelling) to
    /// `IrStopReason::Other`, and the writer degrades `Other` to the safe `end_turn` default — a
    /// foreign token is NEVER echoed into a strict client's closed enum (the bug class ir.rs:186
    /// documents).
    #[test]
    fn read_write_response_unknown_stop_reason_degrades_to_end_turn() {
        let body = serde_json::json!({
            "id": "msg_01xyz",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "some_future_reason",
            "stop_sequence": null,
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });
        let ir = AnthropicReader.read_response(&body).expect("read_response");
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::Other),
            "an unmodeled native stop_reason must map to Other (never carried verbatim)"
        );
        let out = AnthropicWriter.write_response(&ir);
        assert_eq!(
            out.get("stop_reason").and_then(|v| v.as_str()),
            Some("end_turn"), // golden wire-contract literal (kept bare on purpose)
            "Other must degrade to the safe end_turn default on egress, never leak the foreign token"
        );
    }

    /// Anthropic's `usage` cache fields are ADDITIVE (ir.rs:457): the reader stores
    /// `cache_creation_input_tokens`/`cache_read_input_tokens` AS-IS (unlike OpenAI/Gemini, which
    /// subtract the cached prefix out of the input total). This pins that a non-stream response
    /// carries the wire cache counts through unchanged and that `input_tokens` is NOT reduced by them.
    #[test]
    fn read_response_cache_usage_is_additive_not_subtracted() {
        let body = serde_json::json!({
            "id": "msg_01xyz",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": STOP_END_TURN,
            "stop_sequence": null,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": 200,
                "cache_read_input_tokens": 1000
            }
        });
        let ir = AnthropicReader.read_response(&body).expect("read_response");
        // Wire values stored verbatim — Anthropic input is already the UNCACHED count, so no subtract.
        assert_eq!(
            ir.usage.input_tokens, 10,
            "Anthropic input_tokens stored as-is (already uncached)"
        );
        assert_eq!(ir.usage.output_tokens, 5);
        assert_eq!(ir.usage.cache_creation_input_tokens, Some(200));
        assert_eq!(ir.usage.cache_read_input_tokens, Some(1000));
        // billable_tokens sums all four additively: 10 + 5 + 200 + 1000.
        assert_eq!(ir.usage.billable_tokens(), 1215);

        // WRITE re-emits the additive cache fields on the same-protocol egress.
        let out = AnthropicWriter.write_response(&ir);
        assert_eq!(
            out.pointer("/usage/cache_creation_input_tokens")
                .and_then(|v| v.as_u64()),
            Some(200)
        );
        assert_eq!(
            out.pointer("/usage/cache_read_input_tokens")
                .and_then(|v| v.as_u64()),
            Some(1000)
        );
        assert_eq!(
            out.pointer("/usage/input_tokens").and_then(|v| v.as_u64()),
            Some(10)
        );
    }
}

#[cfg(test)]
mod user_and_parallelism_carry_tests {
    //! The two OpenAI<->Anthropic analog carries: `user` <-> `metadata.user_id` and
    //! `parallel_tool_calls` <-> `!tool_choice.disable_parallel_tool_use`. Same switch, different
    //! spelling/location — these must CROSS the seam instead of dying in `extra`.
    use super::{AnthropicReader, AnthropicWriter};
    use crate::proto::openai_chat::{OpenAiReader, OpenAiWriter};
    use crate::proto::{ProtocolReader, ProtocolWriter};

    fn tools_json() -> serde_json::Value {
        serde_json::json!([{
            "type": "function",
            "function": {"name": "f", "description": "d", "parameters": {"type": "object"}}
        }])
    }

    /// OpenAI -> Anthropic: `user` lands as `metadata.user_id`; `parallel_tool_calls: false`
    /// lands inverted inside the caller's tool_choice object.
    #[test]
    fn openai_user_and_parallel_carry_to_anthropic() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools_json(),
            "tool_choice": "auto",
            "user": "end-user-7",
            "parallel_tool_calls": false
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.user.as_deref(), Some("end-user-7"));
        assert_eq!(ir.parallel_tool_calls, Some(false));
        // Promoted fields must NOT also ride extra (double-emit guard).
        assert!(!ir.extra.contains_key("user"));
        assert!(!ir.extra.contains_key("parallel_tool_calls"));

        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["metadata"]["user_id"], "end-user-7");
        assert_eq!(out["tool_choice"]["type"], "auto");
        assert_eq!(out["tool_choice"]["disable_parallel_tool_use"], true);
    }

    /// Anthropic -> OpenAI: `metadata.user_id` lands as `user`; `disable_parallel_tool_use: true`
    /// lands inverted as `parallel_tool_calls: false`.
    #[test]
    fn anthropic_user_and_parallel_carry_to_openai() {
        let body = serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {"user_id": "end-user-7"},
            "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
        });
        let ir = AnthropicReader.read_request(&body).expect("parses");
        assert_eq!(ir.user.as_deref(), Some("end-user-7"));
        assert_eq!(ir.parallel_tool_calls, Some(false));

        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(out["user"], "end-user-7");
        assert_eq!(out["parallel_tool_calls"], false);
    }

    /// Absence round-trips as absence: a request that never carried either field must not GAIN
    /// `metadata`, `user`, `parallel_tool_calls`, or a synthesized `tool_choice` on translation.
    #[test]
    fn absence_gains_nothing() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = OpenAiReader.read_request(&body).expect("parses");
        assert_eq!(ir.user, None);
        assert_eq!(ir.parallel_tool_calls, None);
        let out = AnthropicWriter.write_request(&ir);
        assert!(out.get("metadata").is_none());
        assert!(out.get("tool_choice").is_none());

        let ir2 = AnthropicReader
            .read_request(&serde_json::json!({
                "model": "m", "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]
            }))
            .expect("parses");
        let out2 = OpenAiWriter.write_request(&ir2);
        assert!(out2.get("user").is_none());
        assert!(out2.get("parallel_tool_calls").is_none());
    }

    /// `parallel_tool_calls` with NO tool_choice synthesizes the neutral `auto` carrier — but only
    /// when tools exist; a tool-less request must not gain a tool_choice Anthropic would reject.
    #[test]
    fn parallel_without_directive_synthesizes_auto_only_with_tools() {
        let with_tools = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools_json(),
            "parallel_tool_calls": false
        });
        let ir = OpenAiReader.read_request(&with_tools).expect("parses");
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["tool_choice"]["type"], "auto");
        assert_eq!(out["tool_choice"]["disable_parallel_tool_use"], true);

        let toolless = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "parallel_tool_calls": false
        });
        let ir2 = OpenAiReader.read_request(&toolless).expect("parses");
        let out2 = AnthropicWriter.write_request(&ir2);
        assert!(
            out2.get("tool_choice").is_none(),
            "no tools -> no synthesized tool_choice: {out2}"
        );
    }

    /// A NATIVE Anthropic `metadata` object (riding `extra`) beats the promoted carry on the
    /// writer's overlay — the verbatim original always wins.
    #[test]
    fn native_metadata_wins_over_promoted_user() {
        let body = serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {"user_id": "original"}
        });
        let ir = AnthropicReader.read_request(&body).expect("parses");
        // Same-protocol translated path: extra still carries metadata verbatim.
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["metadata"]["user_id"], "original");
        assert_eq!(
            out["metadata"].as_object().unwrap().len(),
            1,
            "metadata must be the verbatim original, not a merged object"
        );
    }
}

#[cfg(test)]
mod reasoning_carry_tests {
    //! The gated cross-protocol reasoning/thinking carry. The GATE lives at
    //! `IrReq::prepare_for_egress` (per-lane `reasoning` flag); these tests cover the codec halves
    //! (read the ask, project it) plus the gate itself, the clamp, and the sampling-knob omission.
    use super::{AnthropicReader, AnthropicWriter};
    use crate::ir::variant::{EgressPrep, IrReq};
    use crate::ir::{IrReasoningAsk, IrReasoningEffort};
    use crate::proto::{Protocol, ProtocolReader, ProtocolWriter};

    fn openai_effort_body(effort: &str) -> serde_json::Value {
        serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 32000,
            "reasoning_effort": effort
        })
    }

    /// OpenAI `reasoning_effort` word -> Anthropic `thinking` budget via the table.
    #[test]
    fn openai_effort_projects_to_anthropic_budget() {
        let ir = crate::proto::openai_chat::OpenAiReader
            .read_request(&openai_effort_body("high"))
            .expect("parses");
        assert_eq!(
            ir.reasoning,
            Some(IrReasoningAsk::Effort(IrReasoningEffort::High))
        );
        assert!(!ir.extra.contains_key("reasoning_effort"));

        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["thinking"]["type"], "enabled");
        assert_eq!(out["thinking"]["budget_tokens"], 16384);
    }

    /// Anthropic budget -> Gemini `thinkingBudget` is a straight number copy; and Gemini's
    /// dynamic -1 round-trips to Gemini verbatim while projecting to Anthropic as medium.
    #[test]
    fn budgets_copy_between_anthropic_and_gemini() {
        let body = serde_json::json!({
            "model": "m", "max_tokens": 16000,
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 6000}
        });
        let ir = AnthropicReader.read_request(&body).expect("parses");
        assert_eq!(ir.reasoning, Some(IrReasoningAsk::Budget(6000)));
        assert!(
            !ir.extra.contains_key("thinking"),
            "promoted thinking must not also ride extra"
        );
        let gout = Protocol::gemini().writer().write_request(&ir);
        assert_eq!(
            gout["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            6000
        );

        let gbody = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"thinkingConfig": {"thinkingBudget": -1}}
        });
        let gir = Protocol::gemini()
            .reader()
            .read_request(&gbody)
            .expect("parses");
        assert_eq!(gir.reasoning, Some(IrReasoningAsk::Dynamic));
        let back = Protocol::gemini().writer().write_request(&gir);
        assert_eq!(
            back["generationConfig"]["thinkingConfig"]["thinkingBudget"], -1,
            "dynamic must round-trip to Gemini as its native -1"
        );
    }

    /// A numeric budget projected onto a WORD protocol bucketizes through the same table.
    #[test]
    fn budget_bucketizes_to_effort_words() {
        let body = serde_json::json!({
            "model": "m", "max_tokens": 16000,
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 6000}
        });
        let ir = AnthropicReader.read_request(&body).expect("parses");
        let out = crate::proto::openai_chat::OpenAiWriter.write_request(&ir);
        // 6000 sits between low (4096) and medium (8192) -> "low" (largest entry reached).
        assert_eq!(out["reasoning_effort"], "low");
    }

    /// The Anthropic clamp: budget must leave >=1024 answer tokens under max_tokens; too-small
    /// max_tokens drops the ask entirely (no thinking key, and sampling knobs survive).
    #[test]
    fn anthropic_clamps_and_drops_by_max_tokens() {
        // Clamped: high (16384) under max_tokens 4096 -> 3072.
        let mut body = openai_effort_body("high");
        body["max_tokens"] = serde_json::json!(4096);
        let ir = crate::proto::openai_chat::OpenAiReader
            .read_request(&body)
            .expect("parses");
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["thinking"]["budget_tokens"], 3072);

        // Dropped: max_tokens 1500 leaves <1024 of thinking -> no thinking key at all.
        let mut small = openai_effort_body("high");
        small["max_tokens"] = serde_json::json!(1500);
        let ir2 = crate::proto::openai_chat::OpenAiReader
            .read_request(&small)
            .expect("parses");
        let out2 = AnthropicWriter.write_request(&ir2);
        assert!(
            out2.get("thinking").is_none(),
            "no room -> no thinking: {out2}"
        );
    }

    /// Anthropic rejects temperature/top_k alongside thinking: both are omitted (observably via
    /// warn) when the ask is emitted, and present when it is not.
    #[test]
    fn thinking_omits_incompatible_sampling_knobs() {
        let mut body = openai_effort_body("low");
        body["temperature"] = serde_json::json!(0.5);
        let ir = crate::proto::openai_chat::OpenAiReader
            .read_request(&body)
            .expect("parses");
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["thinking"]["budget_tokens"], 4096);
        assert!(
            out.get("temperature").is_none(),
            "temperature != 1 must be omitted with thinking: {out}"
        );

        // Without a reasoning ask the same temperature is emitted normally.
        let mut plain = openai_effort_body("low");
        plain.as_object_mut().unwrap().remove("reasoning_effort");
        plain["temperature"] = serde_json::json!(0.5);
        let ir2 = crate::proto::openai_chat::OpenAiReader
            .read_request(&plain)
            .expect("parses");
        let out2 = AnthropicWriter.write_request(&ir2);
        assert_eq!(out2["temperature"], 0.5);
    }

    /// THE GATE: prepare_for_egress clears the ask when the lane did not claim the capability and
    /// stamps the budget table when it did. Absence of an ask is untouched either way.
    #[test]
    fn seam_gate_clears_or_stamps() {
        let prep = |allowed: bool| EgressPrep {
            ingress_protocol: "openai",
            egress_requires_max_tokens: true,
            lane_default_max_tokens: None,
            global_default_max_tokens: 32000,
            reasoning_allowed: allowed,
            reasoning_budgets: [1024, 2048, 3072, 4096],
        };
        let ir = crate::proto::openai_chat::OpenAiReader
            .read_request(&openai_effort_body("high"))
            .expect("parses");

        let mut gated = IrReq::Chat(ir.clone());
        gated.prepare_for_egress(&prep(false));
        let IrReq::Chat(gated) = gated else {
            unreachable!()
        };
        assert_eq!(
            gated.reasoning, None,
            "unflagged lane must never see the ask"
        );

        let mut allowed = IrReq::Chat(ir);
        allowed.prepare_for_egress(&prep(true));
        let IrReq::Chat(allowed) = allowed else {
            unreachable!()
        };
        assert_eq!(
            allowed.reasoning,
            Some(IrReasoningAsk::Effort(IrReasoningEffort::High))
        );
        assert_eq!(allowed.reasoning_budgets, Some([1024, 2048, 3072, 4096]));
        // The operator's table (not the defaults) drives the projection.
        let out = AnthropicWriter.write_request(&allowed);
        assert_eq!(out["thinking"]["budget_tokens"], 4096);
    }

    /// Responses `reasoning: {effort}` reads into the ask and re-emits from the typed field.
    #[test]
    fn responses_effort_round_trips() {
        let body = serde_json::json!({
            "model": "m", "input": "hi",
            "reasoning": {"effort": "medium"}
        });
        let ir = Protocol::responses()
            .reader()
            .read_request(&body)
            .expect("parses");
        assert_eq!(
            ir.reasoning,
            Some(IrReasoningAsk::Effort(IrReasoningEffort::Medium))
        );
        // Cross-protocol: extra cleared -> the typed field emits the native shape.
        let mut cleared = ir.clone();
        cleared.extra.clear();
        let out = Protocol::responses().writer().write_request(&cleared);
        assert_eq!(out["reasoning"]["effort"], "medium");
        // Anthropic egress: medium -> 8192.
        let mut with_max = cleared;
        with_max.max_tokens = Some(32000);
        let aout = AnthropicWriter.write_request(&with_max);
        assert_eq!(aout["thinking"]["budget_tokens"], 8192);
    }

    /// A disabled-form `thinking` param is NOT promoted (stays in extra for same-proto fidelity)
    /// and no foreign target gains an ask from it.
    #[test]
    fn disabled_thinking_stays_in_extra() {
        let body = serde_json::json!({
            "model": "m", "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "disabled"}
        });
        let ir = AnthropicReader.read_request(&body).expect("parses");
        assert_eq!(ir.reasoning, None);
        assert!(ir.extra.contains_key("thinking"));
        let gout = Protocol::gemini().writer().write_request(&{
            let mut c = ir.clone();
            c.extra.clear();
            c
        });
        assert!(gout["generationConfig"].get("thinkingConfig").is_none());
    }
}
