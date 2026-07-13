// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

/// Anthropic error `type` strings used in error envelopes and in-stream error events. Values
/// shared with the forward/OpenAI-family vocabulary alias their canonical home in
/// `openai_family.rs`; only `timeout_error` is an Anthropic-specific spelling (the forward layer's
/// agnostic kind is the bare `timeout`).
const ERR_TYPE_OVERLOADED: &str = super::openai_family::ERR_TYPE_OVERLOADED;
const ERR_TYPE_INVALID_REQUEST: &str = super::openai_family::ERR_TYPE_INVALID_REQUEST;
const ERR_TYPE_AUTHENTICATION: &str = super::openai_family::ERR_TYPE_AUTHENTICATION;
const ERR_TYPE_RATE_LIMIT: &str = super::openai_family::ERR_TYPE_RATE_LIMIT;
const ERR_TYPE_API_ERROR: &str = super::openai_family::ERR_TYPE_API_ERROR;
const ERR_TYPE_TIMEOUT: &str = "timeout_error";
const ERR_TYPE_NOT_FOUND: &str = super::openai_family::ERR_TYPE_NOT_FOUND;
const ERR_TYPE_PERMISSION: &str = super::openai_family::ERR_TYPE_PERMISSION;
const ERR_TYPE_REQUEST_TOO_LARGE: &str = super::openai_family::ERR_TYPE_REQUEST_TOO_LARGE;

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
                Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
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
        // A streamed `redacted_thinking` block carries its full opaque encrypted `data` INLINE on the
        // `content_block_start` event (Anthropic sends NO deltas for redacted blocks), so the 1:1
        // single-event reader dropped it entirely (`_ => return None`). Emit the pair the IR models
        // for redacted reasoning — a `Thinking` BlockStart plus a `RedactedReasoningDelta` carrying
        // the opaque bytes — from this one start event (the natural `content_block_stop` that follows
        // produces the BlockStop). Mirrors the Bedrock streaming reader + the non-stream `read_block`.
        // (found: audit c2r2.)
        if event_type == EVT_CONTENT_BLOCK_START {
            if let Some(block) = data.get("content_block") {
                if block.get("type").and_then(|t| t.as_str()) == Some(BLOCK_TYPE_REDACTED_THINKING)
                {
                    if let Some(index) = read_clamped_block_index(data) {
                        let bytes = block
                            .get("data")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string();
                        return vec![
                            IrStreamEvent::BlockStart {
                                index,
                                block: IrBlockMeta::Thinking,
                            },
                            IrStreamEvent::BlockDelta {
                                index,
                                delta: IrDelta::RedactedReasoningDelta(bytes),
                            },
                        ];
                    }
                }
            }
        }
        // Anthropic events are otherwise already block-structured (1:1): wrap the singular.
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
    creds: Option<crate::auth::UpstreamCreds>,
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
        AnthropicCredScheme::Ambiguous => match creds {
            Some(crate::auth::UpstreamCreds::Passthrough) => assemble(vec![authorization()]),
            Some(crate::auth::UpstreamCreds::Own) => assemble(vec![x_api_key()]),
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
        // Wire path: the upstream-credential mode (set by forward.rs into the SigningContext) resolves
        // an Ambiguous Anthropic credential to the SINGLE native header it implies — Passthrough
        // forwards the caller's token as `authorization: Bearer`; Own presents the configured key as
        // `x-api-key`. Clear ApiKey/OAuth credentials are unaffected (still single-header).
        anthropic_auth_headers(key, Some(ctx.upstream_creds))
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
            crate::proxy::KIND_OVERLOADED => ERR_TYPE_OVERLOADED,
            crate::proxy::KIND_TIMEOUT => ERR_TYPE_TIMEOUT,
            ERR_TYPE_API_ERROR | crate::proxy::KIND_SERVER_ERROR | "internal" => ERR_TYPE_API_ERROR,
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
        crate::proxy::EGRESS_UA_ANTHROPIC
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
        if thinking_emitted {
            // Anthropic rejects a FORCED/TARGETED tool_choice (`{type:"any"}` / `{type:"tool"}`)
            // alongside extended thinking with a 400 — only `auto`/`none` are allowed. tool_choice
            // was already written above (before the thinking decision), so downgrade a now-illegal
            // `any`/`tool` to `auto` here, preserving any `disable_parallel_tool_use`, with a warn —
            // same "think-ask wins, observably" rule applied to temperature/top_p/top_k below.
            if let Some(tc) = out.get_mut("tool_choice").and_then(|v| v.as_object_mut()) {
                let ty = tc.get("type").and_then(|t| t.as_str());
                if ty == Some("any") || ty == Some("tool") {
                    tracing::warn!(
                        tool_choice = ?ty,
                        "downgrading forced/targeted tool_choice to 'auto' on Anthropic egress: \
                         not compatible with thinking"
                    );
                    tc.insert("type".to_string(), serde_json::json!("auto"));
                    tc.remove("name"); // `name` is only valid on `{type:"tool"}`
                }
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
            if thinking_emitted {
                // Anthropic rejects top_p modifications alongside thinking (same rule as
                // temperature/top_k); omit it, observably, rather than ship a certain 400.
                tracing::warn!(
                    top_p,
                    "omitting top_p on Anthropic egress: not compatible with thinking"
                );
            } else {
                out.insert("top_p".to_string(), serde_json::json!(top_p));
            }
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
#[path = "tests/anthropic_hardening_tests.rs"]
mod anthropic_hardening_tests;

#[cfg(test)]
#[path = "tests/user_and_parallelism_carry_tests.rs"]
mod user_and_parallelism_carry_tests;

#[cfg(test)]
#[path = "tests/reasoning_carry_tests.rs"]
mod reasoning_carry_tests;
