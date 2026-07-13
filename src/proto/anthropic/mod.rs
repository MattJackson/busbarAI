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

#[cfg(test)]
#[path = "tests/anthropic_hardening_tests.rs"]
mod anthropic_hardening_tests;

#[cfg(test)]
#[path = "tests/user_and_parallelism_carry_tests.rs"]
mod user_and_parallelism_carry_tests;

#[cfg(test)]
#[path = "tests/reasoning_carry_tests.rs"]
mod reasoning_carry_tests;

mod reader;
mod writer;
