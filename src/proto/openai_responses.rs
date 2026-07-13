// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI Responses API protocol reader/writer implementation.

use super::openai_family::{
    bearer_error_code, ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA,
    ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT, ERR_TYPE_SERVER_ERROR,
};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Largest wire `output_index` we accept in a streaming Responses event before clamping. The
/// Responses API, like Chat Completions, documents at most 128 parallel output items, so any larger
/// index is malformed; clamp it to this value (the highest valid 0-based index, 127) before the
/// `usize` cast so a crafted `u64::MAX` index can never participate in unbounded set growth or
/// index arithmetic. Mirrors `openai_chat.rs::MAX_TOOL_INDEX`.
const MAX_OUTPUT_INDEX: usize = 127;

/// Fallback `model` name emitted when the IR carries none. The official OpenAI Responses SDK types
/// `Response.model` as a REQUIRED non-nullable string, so a `response.created`/full response that
/// omits `model` fails a strict Pydantic/Zod decoder — and a real `/v1/responses` endpoint never
/// omits it, making the omission a distinguishability tell. On any cross-protocol path
/// (Anthropic→Responses, Bedrock→Responses) the IR `model` is `None`; emit this fallback rather
/// than dropping the key. Mirrors `openai_family.rs::OPENAI_FAMILY_DEFAULT_MODEL`.
const DEFAULT_MODEL: &str = super::openai_family::OPENAI_FAMILY_DEFAULT_MODEL;

/// Hard cap on the number of DISTINCT output indices tracked per stream in `StreamDecodeState`
/// (`open_tools`) and in the writer's open-item sets. Bounds per-request memory against a
/// pathological backend that emits a unique `output_index` per event (a per-connection amplification
/// DoS). Matches `openai_family.rs::OPENAI_FAMILY_MAX_OPEN_TOOLS` (OpenAI's documented parallel-tool-call limit, 128).
const MAX_OPEN_TOOLS: usize = super::openai_family::OPENAI_FAMILY_MAX_OPEN_TOOLS;

/// Key offset under which the streaming reader tracks OPEN TEXT output indices inside the shared
/// `StreamDecodeState::open_tools` set. A native /v1/responses stream can carry MULTIPLE message
/// (text) output items, each at its OWN `output_index`, so a single index-blind `text_block_open`
/// bool cannot pair a BlockStart/BlockStop per text index: a second text item's delta would emit a
/// BlockDelta with no preceding BlockStart (orphan delta) and the terminal frame would close the
/// wrong index. `StreamDecodeState` (in `ir.rs`) exposes only the `open_tools` set and the
/// `text_block_open` bool, so to give text the SAME per-index discipline tool items already have —
/// without a new shared field — text indices are stored as `idx + TEXT_INDEX_KEY_OFFSET`. Wire
/// `output_index` is clamped to `MAX_OUTPUT_INDEX` (127), so a real tool index (<=127) and an
/// offset text key (>=1000) can never collide; the function-call routing guards
/// (`open_tools.contains(&idx)`) keep matching only raw tool indices, and the terminal arm
/// distinguishes a tool close (`remove(&idx)`) from a text close (`remove(&(idx + offset))`).
const TEXT_INDEX_KEY_OFFSET: usize = 1_000;

/// Base62 alphabet the native Responses ids draw their opaque suffix from — the shared
/// single-source-of-truth atom (see `crate::proto::BASE62_ALPHABET`), aliased locally. Used by
/// [`synthesize_item_id`] and [`synthesize_response_id`].
const BASE62: &[u8; 62] = crate::proto::BASE62_ALPHABET;

/// Width of the opaque base62 suffix on a synthesized item id (`msg_…`/`fc_…`). Native Responses
/// item ids carry a long opaque random token with no positional structure; 48 base62 chars matches
/// the entropy/length profile of native ids so a client that length-checks or regex-validates the
/// `item_id` cannot fingerprint a too-short or structured suffix as non-native.
const ITEM_ID_TOKEN_LEN: usize = 48;

/// Width of the opaque base62 suffix on a synthesized `resp_` id. Native OpenAI Responses ids are
/// ~38+ chars of opaque random data after the `resp_` prefix; 48 base62 chars stays in that profile.
const RESPONSE_ID_TOKEN_LEN: usize = 48;

/// SSE event type names emitted / consumed on the `/v1/responses` wire.
const EVT_RESPONSE_CREATED: &str = "response.created";
const EVT_OUTPUT_ITEM_ADDED: &str = "response.output_item.added";
const EVT_OUTPUT_ITEM_DONE: &str = "response.output_item.done";
const EVT_OUTPUT_TEXT_DELTA: &str = "response.output_text.delta";
const EVT_FUNCTION_CALL_ARGS_DELTA: &str = "response.function_call_arguments.delta";
const EVT_REASONING_TEXT_DELTA: &str = "response.reasoning_text.delta";
const EVT_RESPONSE_COMPLETED: &str = "response.completed";
const EVT_RESPONSE_FAILED: &str = "response.failed";
const EVT_RESPONSE_INCOMPLETE: &str = "response.incomplete";

/// Internal `provider_signal` sentinel emitted when a `response.failed` event carries no recognizable
/// `error.code`/`error.type`. Distinct from the `EVT_RESPONSE_FAILED` wire event type ("response.failed"):
/// this underscore form is the breaker/telemetry label, mapped to `StatusClass::ServerError` via
/// `class_for_response_failed`'s catch-all arm.
const SIGNAL_RESPONSE_FAILED: &str = "response_failed";

/// Response status values on the `/v1/responses` wire.
const STATUS_IN_PROGRESS: &str = "in_progress";
const STATUS_COMPLETED: &str = "completed";
const STATUS_FAILED: &str = "failed";
const STATUS_INCOMPLETE: &str = "incomplete";

/// Output item `type` values on the `/v1/responses` wire.
const ITEM_TYPE_FUNCTION_CALL: &str = "function_call";
const ITEM_TYPE_MESSAGE: &str = "message";
const ITEM_TYPE_REASONING: &str = "reasoning";

/// Content part `type` values on the `/v1/responses` wire.
const CONTENT_TYPE_OUTPUT_TEXT: &str = "output_text";
const CONTENT_TYPE_REASONING_TEXT: &str = "reasoning_text";
const CONTENT_TYPE_INPUT_TEXT: &str = "input_text";

/// `incomplete_details.reason` values on the `/v1/responses` wire.
const INCOMPLETE_REASON_MAX_OUTPUT: &str = "max_output_tokens";
const INCOMPLETE_REASON_CONTENT_FILTER: &str = "content_filter";
const INCOMPLETE_REASON_OTHER: &str = "other";

/// Top-level `object` field value and vendor tag for the Responses protocol.
const OBJ_RESPONSE: &str = "response";
const VENDOR_NAME: &str = "responses";

/// Synthesized id prefixes (bare prefix without trailing underscore for item ids).
const RESPONSE_ID_PREFIX: &str = "resp_";
const ITEM_ID_PREFIX_MSG: &str = "msg";
const ITEM_ID_PREFIX_FC: &str = "fc";
const ITEM_ID_PREFIX_RS: &str = "rs";

/// OpenAI-family error `code` strings self-owned in this protocol module.
const ERR_CODE_RATE_LIMIT: &str = "rate_limit_exceeded";
const ERR_CODE_STRING_ABOVE_MAX: &str = "string_above_max_length";

/// Human-readable authentication failure message returned by this protocol's `auth_failure_message`.
const AUTH_FAILURE_MSG: &str = "Incorrect API key provided.";

/// Fill a fixed-width base62 token ENTIRELY from the OS CSPRNG, with NO counter overlay. A counter
/// overlaid into any fixed region of the token leaves those characters predictable/low-entropy (the
/// counter stays small, so its high base62 digits are constant '0') — a structural fingerprint at
/// whatever position it occupies that a native, fully-random vendor id never carries. The opaque
/// suffixes here are wide (>= 48 chars ≈ 285 bits of base62 entropy), so pure CSPRNG output is
/// collision-free in practice for a per-process id stream and needs no monotonic-counter backstop.
/// On entropy failure the buffer stays zeroed (all '0'), so this never panics on the request path.
/// Returns an owned `String` of exactly `N` base62 characters, each drawn from a UNIFORM base62
/// distribution: a raw `byte % 62` reduction is biased (256 is not a multiple of 62, so bytes
/// 248..=255 wrap to base62 digits 0..=7, making those eight chars ~1.25x more likely than 8..=61
/// and leaving a faint statistical fingerprint a native uniform-random id never carries). We instead
/// use REJECTION SAMPLING: any byte >= 248 (= 62 * 4, the largest multiple of 62 that fits in a u8)
/// is rejected and a fresh CSPRNG byte is drawn for that slot, so every base62 character is
/// equiprobable. Rejection keeps the function infallible/panic-free — on a getrandom failure a slot
/// simply keeps its all-zero fallback rather than retrying.
///
/// `N` MUST be >= 11. A token narrower than that carries too little base62 entropy to stay
/// collision-free across a per-process id stream and falls below the opaque-suffix width a native
/// vendor id never goes under — making a short synthesized id a distinguishability tell. The bound
/// is enforced at COMPILE TIME by the `const _` assertion below: instantiating `synth_token` with a
/// `const N < 11` fails to build (a monomorphization-time `assert!`), so a too-small width can never
/// reach the wire. Both live callers use 48 (`ITEM_ID_TOKEN_LEN`/`RESPONSE_ID_TOKEN_LEN`), far above
/// the floor.
fn synth_token<const N: usize>() -> String {
    // Compile-time guard: a too-small `N` fails to build rather than emitting a short, low-entropy,
    // fingerprintable id at runtime. An inline `const` item cannot reference the outer fn's const
    // generic (E0401), so the assertion lives on an associated const of a zero-sized generic carrier
    // type; referencing `MinWidth::<N>::OK` below forces its evaluation per monomorphization, turning
    // any `N < 11` instantiation into a build error.
    struct MinWidth<const M: usize>;
    impl<const M: usize> MinWidth<M> {
        const OK: () = assert!(M >= 11, "synth_token<N>: N must be >= 11 base62 chars");
    }
    let () = MinWidth::<N>::OK;

    // Largest multiple of 62 that fits in a u8 (62 * 4). A byte in `0..REJECT_THRESHOLD` maps to a
    // base62 digit with NO modular bias; a byte >= this threshold (248..=255) is rejected so every
    // base62 character stays equiprobable. See the docstring for the bias rationale.
    const REJECT_THRESHOLD: u8 = crate::proto::BASE62_REJECT_THRESHOLD;

    let mut token = [b'0'; N];
    for slot in token.iter_mut() {
        // Draw fresh bytes until one falls in the unbiased range. A small scratch buffer is refilled
        // from the CSPRNG as needed; on a getrandom failure the draw yields zeros, which are < the
        // threshold and accepted, so the slot stays at base62 '0' (the existing all-zero fallback)
        // and the loop still terminates — keeping the function infallible and panic-free.
        let mut buf = [0u8; 1];
        loop {
            if getrandom::fill(&mut buf).is_err() {
                // Entropy failure: leave this slot at its existing '0' fallback and move on.
                break;
            }
            if buf[0] < REJECT_THRESHOLD {
                *slot = BASE62[(buf[0] % 62) as usize];
                break;
            }
            // buf[0] >= REJECT_THRESHOLD: biased region, reject and redraw.
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards an
    // impossible non-ASCII byte and keeps the path panic-free (no unwrap/expect on the request path).
    String::from_utf8(token.to_vec()).unwrap_or_else(|_| "0".repeat(N))
}

/// Synthesize a per-output-item id for the streaming writer. Native Responses events carry an
/// `item_id` (`msg_…` for message parts, `fc_…` for function-call parts) that is constant across the
/// `output_item.added` → deltas → `output_item.done` lifecycle of a single output item. The IR's
/// block events carry only the integer `output_index` (and, for tool use, the call id), not a wire
/// `item_id`, so the writer must mint one.
///
/// Per-INDEX determinism within a stream is what the lifecycle correlation needs: the
/// added/delta/done events of one item must share an `item_id`. The previous implementation used a
/// sequential zero-padded hex index (`msg_00000000`, `msg_00000001`, …) — a positional structure no
/// native opaque id has, letting any observer fingerprint a proxied response from the id pattern.
/// We replace the suffix with an opaque CSPRNG-backed base62 token of native length, while keeping
/// per-`(prefix, index)` determinism within a stream via a per-writer cache (see
/// `ResponsesWriter::item_id_for`). This free function mints a FRESH opaque id; callers that need
/// the stream-stable id go through the writer's cache.
fn synthesize_item_id(prefix: &str) -> String {
    format!("{prefix}_{}", synth_token::<ITEM_ID_TOKEN_LEN>())
}

/// Current unix epoch seconds, or 0 if the clock is before the epoch (never on a sane host).
/// Kept panic-free for the request path: no `unwrap`/`expect` on `SystemTime`.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Synthesize a protocol-correct Responses id (`resp_<opaque base62>`) for cross-protocol responses
/// where the backend supplied none. Native OpenAI Responses ids are `resp_` followed by ~38+ chars
/// of opaque random data with NO embedded structure; the previous form encoded the unix timestamp as
/// the leading hex segment (`resp_{timestamp_hex}{counter_hex}`), which both made the id shorter than
/// native AND leaked the proxy's server clock to within one second to anyone holding a response id.
/// The opaque CSPRNG token here matches the native length/entropy profile and embeds no timestamp;
/// the whole token is drawn from `getrandom` (via `synth_token`) with NO counter overlay — at >= 48
/// base62 chars (~285 bits) the birthday bound makes a per-process collision astronomically unlikely,
/// so a counter would only ADD a predictable low-entropy region (a structural fingerprint) for no
/// uniqueness benefit. Native passthrough never calls this: it carries the upstream id verbatim.
fn synthesize_response_id() -> String {
    format!(
        "{}{}",
        RESPONSE_ID_PREFIX,
        synth_token::<RESPONSE_ID_TOKEN_LEN>()
    )
}

/// Accumulate the content of a Responses `system`/`developer` input turn into `system_blocks`
/// (which feeds `IrRequest.system` -> the provider's top-level instructions/system prompt).
/// These turns are NOT conversation messages; routing their text here prevents the system prompt
/// from being silently dropped on a cross-protocol hop. Content may be a bare string or an array
/// of `{"type":"input_text","text":...}` blocks (or `output_text`); both are handled. Empty text
/// is skipped to avoid emitting blank system blocks.
fn push_system_content(
    system_blocks: &mut Vec<crate::ir::IrBlock>,
    content: Option<&serde_json::Value>,
) {
    let mut push_text = |text: &str| {
        if !text.is_empty() {
            system_blocks.push(crate::ir::IrBlock::Text {
                text: text.to_string(),
                cache_control: None,
                citations: Vec::new(),
            });
        }
    };
    match content {
        Some(serde_json::Value::String(s)) => push_text(s),
        Some(serde_json::Value::Array(arr)) => {
            for block in arr {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    push_text(text);
                }
            }
        }
        _ => {}
    }
}

/// Extract the IR content blocks for a user/assistant conversation turn from a Responses
/// `message`-item `content` field. The Responses surface allows `content` to be EITHER an array of
/// typed content blocks (`[{"type":"input_text",...}, ...]`) OR a bare JSON string shorthand
/// (`"content": "hello"`). The array-only path used previously silently DROPPED the entire turn
/// when `content` was a bare string (`as_array()` -> None -> message never pushed), losing a
/// user/assistant turn on a cross-protocol hop. This helper handles both shapes so neither arm
/// loses a turn. A bare string becomes a single `Text` block (empty string -> empty content, but
/// the message is still emitted so the turn survives).
fn message_content_blocks(content: Option<&serde_json::Value>) -> Option<Vec<crate::ir::IrBlock>> {
    match content {
        Some(serde_json::Value::String(s)) => Some(vec![crate::ir::IrBlock::Text {
            text: s.clone(),
            cache_control: None,
            citations: Vec::new(),
        }]),
        Some(serde_json::Value::Array(arr)) => {
            Some(arr.iter().filter_map(|b| responses_block(b).ok()).collect())
        }
        _ => None,
    }
}

/// Normalize the Responses API `tool_choice` into the IR union (PF-H1).
///
/// The Responses surface shares Chat Completions' string forms (`"auto"`/`"none"`/`"required"`) but
/// FLATTENS the targeted object: `{"type":"function","name":"X"}` carries `name` at the top level
/// (Chat nests it under `function`). Accept both shapes (flat preferred, nested as a defensive
/// fallback) so a forced/targeted tool survives the cross-protocol seam instead of degrading to
/// `auto`. Absent / unrecognized → `None` (omitted), so a request that never carried a directive does
/// not gain a spurious one.
fn read_responses_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    match val? {
        serde_json::Value::String(s) => match s.as_str() {
            "auto" => Some(crate::ir::IrToolChoice::Auto),
            "none" => Some(crate::ir::IrToolChoice::None),
            "required" => Some(crate::ir::IrToolChoice::Required),
            _ => None,
        },
        serde_json::Value::Object(o) => {
            if o.get("type").and_then(|t| t.as_str()) == Some("function") {
                o.get("name")
                    .and_then(|n| n.as_str())
                    .or_else(|| {
                        o.get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())
                    })
                    .map(|name| crate::ir::IrToolChoice::Tool {
                        name: name.to_string(),
                    })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Emit the IR tool-choice union in the Responses API's native shape (PF-H1) — string forms for
/// auto/none/required, the FLAT `{"type":"function","name":...}` object for a targeted tool.
fn write_responses_tool_choice(tc: &crate::ir::IrToolChoice) -> serde_json::Value {
    match tc {
        crate::ir::IrToolChoice::Auto => serde_json::json!("auto"),
        crate::ir::IrToolChoice::None => serde_json::json!("none"),
        crate::ir::IrToolChoice::Required => serde_json::json!("required"),
        crate::ir::IrToolChoice::Tool { name } => {
            serde_json::json!({"type": "function", "name": name})
        }
    }
}

/// Map a terminal `response.failed` provider signal (the captured `error.code`/`error.type`) to the
/// breaker `StatusClass` that drives disposition and failover.
///
/// A streamed `response.failed` carries the SAME OpenAI error envelope as the non-streaming HTTP
/// error body, so the mid-stream failure class must be derived from that signal rather than
/// hardcoded to `ServerError`. Hardcoding `ServerError` misclassifies an auth/rate-limit/
/// context-length failure that arrives mid-stream: the breaker would treat a dead key (Auth →
/// HardDown) or an oversized request (ContextLength → fail-over-no-penalty) as a transient 5xx,
/// giving the wrong breaker disposition and the wrong failover decision.
///
/// The mapping mirrors the non-stream HTTP classifier's buckets (`classify`/`normalize_raw_error`):
/// auth codes → Auth, quota/rate codes → RateLimit, context-window codes → ContextLength, and the
/// 5xx/overloaded family → ServerError. The final arm explicitly binds the unrecognized signal and
/// defaults to `ServerError` (the safe transient bucket — a retry/cooldown rather than a permanent
/// HardDown) per the no-`_`-catch-all rule.
fn class_for_response_failed(signal: &str) -> StatusClass {
    match signal {
        "invalid_api_key" | ERR_TYPE_AUTHENTICATION => StatusClass::Auth,
        ERR_CODE_RATE_LIMIT | ERR_TYPE_INSUFFICIENT_QUOTA => StatusClass::RateLimit,
        crate::forward::PROVIDER_CODE_CONTEXT_LENGTH | ERR_CODE_STRING_ABOVE_MAX => {
            StatusClass::ContextLength
        }
        ERR_TYPE_SERVER_ERROR | ERR_TYPE_OVERLOADED => StatusClass::ServerError,
        other => {
            // Unrecognized provider signal: default to the transient ServerError bucket so the lane
            // recovers via cooldown rather than being permanently penalized. Named binding (not `_`)
            // keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            StatusClass::ServerError
        }
    }
}

/// True when `signal` looks like an `error.code` ENUM TOKEN (a single snake/kebab identifier an SDK
/// switch-cases on) rather than a HUMAN sentence. The discriminator is prose: a real code carries no
/// whitespace and stays short, while a transport/cross-protocol signal like `STREAM_ABORT_DETAIL`
/// ("The response stream was interrupted.") or "connection reset by peer" has spaces. This preserves
/// arbitrary code-like upstream signals (`overloaded`, `rate_limit_exceeded`, …) on a round-trip
/// while never leaking prose as the `code` enum.
fn is_code_like_signal(signal: &str) -> bool {
    !signal.is_empty()
        && signal.len() <= 64
        && signal
            .bytes()
            .all(|b| b == b'_' || b == b'-' || b == b'.' || b.is_ascii_alphanumeric())
}

/// The Responses `error.code` enum for a stream failure. A code-like `provider_signal` (a
/// same-protocol / code-bearing round-trip) is preserved verbatim; otherwise — including the
/// cross-protocol and transport-abort paths where `provider_signal` is a HUMAN sentence, not an enum
/// — the code is DERIVED from the error class so the wire ALWAYS carries a valid enum an SDK can
/// switch on, never a free-form string. Exhaustive over `StatusClass` (no `_`) per the no-catch-all
/// rule. (found: audit c2r2.)
fn responses_error_code(err: &crate::proto::IrError) -> String {
    if let Some(s) = err.provider_signal.as_deref() {
        if is_code_like_signal(s) {
            return s.to_string();
        }
    }
    match err.class {
        StatusClass::RateLimit => ERR_TYPE_RATE_LIMIT,
        StatusClass::Auth => ERR_TYPE_AUTHENTICATION,
        StatusClass::Billing => ERR_TYPE_INSUFFICIENT_QUOTA,
        StatusClass::ContextLength | StatusClass::ClientError => ERR_TYPE_INVALID_REQUEST,
        StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network => ERR_TYPE_SERVER_ERROR,
    }
    .to_string()
}

/// The set of top-level Responses API request keys that `ResponsesReader::read_request` MODELS
/// into `IrRequest` fields. Keys in this set are EXCLUDED from `extra` (the pass-through map) so
/// they are not double-emitted by the writer's extra-forwarding loop. Built once per process via
/// `OnceLock` instead of being reconstructed on every `read_request` call — the rebuild was a
/// pointless per-request allocation on the Responses ingress hot path.
///
/// NOTE: `metadata` is deliberately NOT in this set. The Responses API accepts a top-level
/// `metadata` object (user-defined key/value tagging); busbar does not model it on `IrRequest`,
/// so it must flow through `extra` and be re-emitted verbatim. Listing it here would silently
/// drop a stable public API field (a prior revision made exactly that mistake).
fn responses_modeled_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        [
            "model",
            "instructions",
            "input",
            "tools",
            "max_output_tokens",
            "temperature",
            "top_p",
            "stream",
            "tool_choice",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

#[derive(Clone)]
pub(crate) struct ResponsesReader;

impl ProtocolReader for ResponsesReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body ONCE and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (matches the anthropic.rs pattern; error paths are
        // already degraded — avoid the extra parse+alloc on every non-2xx response).
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
            Ok(json) => {
                let error = json.get("error").and_then(|e| e.as_object());
                let provider_code = error
                    .and_then(|e_obj| e_obj.get("code"))
                    .and_then(|c| c.as_str())
                    .map(String::from);
                let structured_type = error
                    .and_then(|e_obj| e_obj.get("type"))
                    .and_then(|t| t.as_str())
                    .map(String::from);
                (provider_code, structured_type)
            }
            Err(_) => (None, None),
        };

        // Native /v1/responses already carries `code: "context_length_exceeded"` on the oversized
        // path, so the common case flows straight through. But some upstreams (and the OpenAI
        // Chat-Completions-shaped surface this proxy also fronts) signal the same condition only via
        // the error MESSAGE — e.g. `This model's maximum context length is 8192 tokens...` — with a
        // null or generic `code`. Mirror openai_chat.rs / anthropic.rs: when no canonical code was parsed,
        // scan the body for the protocol's context-length phrasing and synthesize the canonical code
        // so the breaker pipeline (normalize_raw_error, breaker.rs) → StatusClass::ContextLength
        // and oversized-request failover triggers WITHOUT penalizing the lane. This is the production
        // counterpart of the `#[cfg(test)] classify()` helper's message scan below.
        //
        // GATE the message scan to the HTTP statuses an oversized request actually uses (400
        // invalid_request_error; 413 payload-too-large), mirroring `OpenAiReader::extract_error`.
        // Without the gate a 401/429/5xx whose prose happens to contain "maximum context length"
        // would synthesize `context_length_exceeded` → the breaker maps it to ContextLength → the
        // genuine auth/rate-limit/server failure escapes fault attribution (no fault recorded).
        let provider_code = provider_code.or_else(|| {
            let oversized_status =
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
            if !oversized_status {
                return None;
            }
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if super::openai_family::openai_context_length_prose_scan(&lower) {
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
        // Identical to OpenAiReader::classify — both emit the same OpenAI error envelope, so the
        // mapping is single-sourced in `super::openai_family::openai_classify`.
        super::openai_family::openai_classify(status, body)
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        if obj.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(instructions) = obj.get("instructions").and_then(|v| v.as_str()) {
            if !instructions.is_empty() {
                system_blocks.push(crate::ir::IrBlock::Text {
                    text: instructions.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();

        if let Some(input_val) = obj.get("input") {
            if input_val.is_string() {
                let text = input_val.as_str().unwrap_or("").to_string();
                messages.push(crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text,
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                });
            } else if let Some(arr) = input_val.as_array() {
                for item in arr {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some(CONTENT_TYPE_INPUT_TEXT) => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("input_image") => {
                            // L5: a Responses `input_image` can reference an uploaded file by
                            // `file_id` INSTEAD of carrying an inline `image_url`. The prior code only
                            // read `image_url`, so a file_id-only image produced an EMPTY Image block
                            // (media_type/data both ""), a lossy degradation. Carry the file_id
                            // faithfully under a distinct `file_id` sentinel (mirroring the `image_url`
                            // sentinel) so the writer reconstructs `{type:input_image,file_id}` and the
                            // round-trip is lossless. Prefer `image_url` when present (the inline form).
                            if let Some(block) = responses_input_image_block(item) {
                                messages.push(crate::ir::IrMessage {
                                    role: crate::ir::IrRole::User,
                                    content: vec![block],
                                });
                            }
                        }
                        Some(CONTENT_TYPE_OUTPUT_TEXT) => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some(ITEM_TYPE_FUNCTION_CALL) => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let arguments = item
                                .get("arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");
                            // On malformed argument JSON, preserve the raw string rather than
                            // discarding the caller's tool arguments to Null (mirrors the OpenAI
                            // reader). Losing arguments entirely is a lossy cross-protocol bug.
                            let input = crate::json::parse_str(arguments).unwrap_or_else(|_| {
                                serde_json::Value::String(arguments.to_string())
                            });

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::ToolUse {
                                    id: call_id,
                                    name,
                                    input,
                                    cache_control: None,
                                }],
                            });
                        }
                        Some("function_call_output") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let output_val = item.get("output");
                            let content_blocks: Vec<crate::ir::IrBlock> = match output_val {
                                Some(serde_json::Value::String(out_str)) => {
                                    vec![crate::ir::IrBlock::Text {
                                        text: out_str.clone(),
                                        cache_control: None,
                                        citations: Vec::new(),
                                    }]
                                }
                                _ => output_val
                                    .and_then(|o| o.as_array())
                                    .map(|arr| {
                                        arr.iter().filter_map(|b| responses_block(b).ok()).collect()
                                    })
                                    .unwrap_or_default(),
                            };

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Tool,
                                content: vec![crate::ir::IrBlock::ToolResult {
                                    tool_use_id: call_id,
                                    content: content_blocks,
                                    is_error: false,
                                    cache_control: None,
                                }],
                            });
                        }
                        Some(ITEM_TYPE_MESSAGE) => {
                            // The official OpenAI Responses SDK emits conversation turns as typed
                            // `{"type":"message","role":...,"content":[...]}` items. The role-keyed
                            // fallback below only fires for UNTYPED items, so without this arm a
                            // typed message turn would be silently dropped. Read role+content and
                            // map the content blocks via `responses_block`, mirroring the untyped
                            // branch.
                            let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                            // `system`/`developer` turns carry the system prompt. They have no
                            // IrRole and must NOT become conversation messages — accumulate their
                            // text into `system_blocks` (which feeds `IrRequest.system` ->
                            // top-level instructions), or the system prompt is silently lost on a
                            // cross-protocol hop. Content can be an array of `input_text` blocks or
                            // a bare string; handle both.
                            if role_str == "system" || role_str == "developer" {
                                push_system_content(&mut system_blocks, item.get("content"));
                                continue;
                            }
                            let role = match role_str {
                                "user" => Some(crate::ir::IrRole::User),
                                "assistant" => Some(crate::ir::IrRole::Assistant),
                                _ => None,
                            };
                            if let Some(role) = role {
                                // `content` may be an array of typed blocks OR a bare string
                                // shorthand; `message_content_blocks` handles both so a
                                // string-content turn is not silently dropped.
                                if let Some(msg_content) =
                                    message_content_blocks(item.get("content"))
                                {
                                    messages.push(crate::ir::IrMessage {
                                        role,
                                        content: msg_content,
                                    });
                                }
                            }
                        }
                        Some(ITEM_TYPE_REASONING) => {
                            // Fix #6: a prior-turn `reasoning` INPUT item carries assistant
                            // reasoning (text under `content`/`summary`, opaque blob under
                            // `encrypted_content`). Dropping it lost that reasoning entirely on egress
                            // to a protocol that models reasoning (Anthropic/Bedrock Thinking). Decode
                            // it into an `IrBlock::Thinking` on its own assistant turn (a Responses
                            // `reasoning` item is a top-level sibling of the assistant message it
                            // precedes, so a standalone assistant turn is the faithful mapping). The
                            // paired writer (`write_request`) re-emits this as a `reasoning` input
                            // item, so a same-protocol Responses->Responses round-trip is preserved.
                            let text = read_reasoning_text(item);
                            let signature = item
                                .get("encrypted_content")
                                .and_then(|s| s.as_str())
                                .filter(|s| !s.is_empty())
                                .map(String::from);
                            if !text.is_empty() || signature.is_some() {
                                messages.push(crate::ir::IrMessage {
                                    role: crate::ir::IrRole::Assistant,
                                    content: vec![crate::ir::IrBlock::Thinking {
                                        text,
                                        signature,
                                        redacted: false,
                                        cache_control: None,
                                    }],
                                });
                            }
                        }
                        Some(_) | None => {}
                    }

                    // Handle role/content structured items (user/assistant messages) ONLY when the
                    // item carries no `type` field. A typed item (e.g. "output_text") that also
                    // happens to include a `role` must NOT be re-processed here, or the turn would
                    // be duplicated in the resulting conversation.
                    if item.get("type").is_none() && item.get("role").is_some() {
                        let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                        let content_val = item.get("content");

                        // As in the typed `message` arm, untyped `system`/`developer` turns carry
                        // the system prompt and must be accumulated into `system_blocks` rather than
                        // dropped (the prior `_ => continue` lost them on cross-protocol hops).
                        if role_str == "system" || role_str == "developer" {
                            push_system_content(&mut system_blocks, content_val);
                            continue;
                        }

                        let role = match role_str {
                            "user" => crate::ir::IrRole::User,
                            "assistant" => crate::ir::IrRole::Assistant,
                            _ => continue,
                        };

                        // As in the typed `message` arm, `content` may be an array of typed
                        // blocks OR a bare string shorthand; handle both via
                        // `message_content_blocks` so a string-content untyped turn survives.
                        if let Some(msg_content) = message_content_blocks(content_val) {
                            messages.push(crate::ir::IrMessage {
                                role,
                                content: msg_content,
                            });
                        }
                    }
                }
            }
        } else if !obj.contains_key("instructions") {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                let name = tool_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool_val
                    .get("description")
                    .and_then(|v| v.as_str().map(String::from));
                let input_schema = tool_val
                    .get("parameters")
                    .or_else(|| tool_val.get("input_schema"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                tools.push(crate::ir::IrTool {
                    name,
                    description,
                    input_schema,
                    cache_control: None,
                });
            }
        }

        // Read `max_output_tokens` as u64 and fall back to None on out-of-range values rather than
        // silently truncating a value larger than u32::MAX via `as u32` (matches the anthropic and
        // bedrock readers). `try_from` also rejects negatives, so an explicit `> 0` filter is moot;
        // a value of 0 is preserved as Some(0) just as the prior code dropped it — keep dropping it.
        let max_tokens = obj
            .get("max_output_tokens")
            .and_then(|v| v.as_u64())
            .filter(|&v| v > 0)
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        // The Responses API supports `top_p` but has NO `top_k` and no top-level stop-sequence param,
        // so only top_p is promoted here; `top_k`/`stop` stay None/empty (any unmodeled knob remains
        // in `extra`).
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        // The Responses API carries `stream` in the request body — read it (don't drop the intent).
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        // `tool_choice` (PF-H1): promote to the IR union so a forced/targeted directive survives the
        // cross-protocol seam instead of degrading to `auto`. "tool_choice" is added to the modeled
        // keys below so it does not also linger in `extra`.
        let tool_choice = read_responses_tool_choice(obj.get("tool_choice"));

        // M1 response_format: the Responses API carries structured-output config under `text.format`
        // (NOT a top-level `response_format` as Chat Completions does). Read `text.format` and
        // normalize it into the IR's canonical `response_format` shape (the Chat-Completions shape the
        // OpenAI reader stores), so a Responses structured-output request reaches an OpenAI/Anthropic
        // backend faithfully and a same-protocol round-trip is lossless. `text` is added to the modeled
        // keys below so it does not also linger in `extra` (which would double-emit it on write).
        // SAMPLING (Phase 0): the Responses create API does NOT model `frequency_penalty`,
        // `presence_penalty`, `seed`, or `n` (verified against the official openai-python
        // `ResponseCreateParamsBase` — only `temperature`/`top_p`/`top_logprobs`/`text` are present),
        // so none are promoted here (they stay None) and none are added to the modeled-keys exclusion.
        // STOP (M5): the Responses create API has NO `stop`/`stop_sequences` param either, so `stop`
        // stays empty and is not read.
        let response_format = read_text_format(obj.get("text"));

        // NOTE: `text` is NOT in the modeled-keys set — it is intercepted by its own branch in the
        // loop below (its `format` sub-key → IR `response_format` per M1, the remainder preserved
        // in `extra`). `metadata` is also deliberately excluded from the set; see `responses_modeled_keys`.
        let modeled_keys = responses_modeled_keys();

        for (key, value) in obj.iter() {
            // `text` is partially modeled: its `format` sub-key is promoted to the IR
            // `response_format` (M1) and MUST NOT also linger in `extra` (the writer rebuilds `text`
            // from `response_format`, so a leftover `extra["text"]["format"]` would double-emit /
            // conflict). But `text` may carry OTHER sub-keys (e.g. `verbosity`) that busbar does not
            // model — those must survive via `extra`. So when `text` carries non-`format` keys, route a
            // `format`-stripped copy into `extra`; when `text` is format-only, drop it from `extra`
            // entirely (the writer re-synthesizes it from `response_format`). Checked BEFORE the
            // modeled-keys short-circuit so the format-stripped remainder is preserved even though
            // `text` is listed as modeled.
            if key == "text" {
                if let Some(text_obj) = value.as_object() {
                    let remainder: serde_json::Map<String, serde_json::Value> = text_obj
                        .iter()
                        .filter(|(k, _)| k.as_str() != "format")
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if !remainder.is_empty() {
                        extra.insert("text".to_string(), serde_json::Value::Object(remainder));
                    }
                }
                continue;
            }
            if modeled_keys.contains(key.as_str()) {
                continue;
            }
            extra.insert(key.clone(), value.clone());
        }

        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
        }

        // The reasoning ASK: Responses spells it `reasoning: {effort}`. Promote the effort word so
        // it carries to Anthropic/Gemini thinking budgets; the raw `reasoning` object (which can
        // also carry `summary`) STAYS in extra for same-protocol fidelity — the writer emits from
        // the typed field only when extra does not already carry the verbatim original.
        let reasoning = obj
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(|v| v.as_str())
            .and_then(crate::ir::IrReasoningEffort::parse)
            .map(crate::ir::IrReasoningAsk::Effort);

        Ok(crate::ir::IrRequest {
            reasoning,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k: None,
            stop: vec![],
            tool_choice,
            stream,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format,
            extra,
        })
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match event_type {
            EVT_RESPONSE_CREATED | "response.in_progress" => {
                if !state.started {
                    state.started = true;
                    // Capture stream identity from the nested `response` object so a same-protocol
                    // passthrough preserves it. `created_at` is the Responses field name (mapped to
                    // the IR's `created`).
                    let resp = data.get("response");
                    let id = resp
                        .and_then(|r| r.get("id"))
                        .and_then(|i| i.as_str())
                        .map(String::from);
                    let created = resp
                        .and_then(|r| r.get("created_at"))
                        .and_then(|c| c.as_u64());
                    let model = resp
                        .and_then(|r| r.get("model"))
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created,
                        model,
                    });
                }
            }

            EVT_OUTPUT_ITEM_ADDED => {
                if let Some(item_obj) = data.get("item") {
                    if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_FUNCTION_CALL)
                    {
                        let call_id = item_obj
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item_obj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            // Clamp the wire index before the cast: a crafted `u64::MAX` would
                            // otherwise feed the per-stream set and downstream index arithmetic
                            // unbounded. Saturate at MAX_OUTPUT_INDEX (mirrors openai_chat.rs).
                            let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                            // Record the open tool index so the terminal `output_item.done` for
                            // this index closes the block EXACTLY once. Native Responses emits a
                            // single `output_item.done` per function-call item, so unlike text
                            // (which also gets a `content_part.done`) a tool index is closed by one
                            // event — tracking it here keeps the open/close pair balanced and lets
                            // the done arm distinguish a real open block from a duplicate close.
                            //
                            // Cap the distinct-index cardinality: a backend emitting a unique
                            // `output_index` per event must not grow `open_tools` without bound
                            // (a per-connection amplification DoS). Open a new block ONLY when the
                            // index is not already tracked AND there is room under the cap. An
                            // already-open index must NOT re-emit BlockStart — a second
                            // `output_item.added` for an open index would produce an invalid
                            // BlockStart→BlockStart→BlockStop sequence (a duplicate
                            // `content_block_start`), a deterministic proxy tell that corrupts a
                            // downstream writer's tool-call state. Beyond the cap a NEW index is
                            // silently skipped (no BlockStart), matching openai_chat.rs.
                            // An index must not open as BOTH a tool and a text block: a text delta
                            // at this same `output_index` stores its open marker under
                            // `idx + TEXT_INDEX_KEY_OFFSET`, and if such a text block is already open
                            // here, opening a tool block at the raw `idx` too would leave two open
                            // markers (`idx` and `idx + offset`) for one wire index — both BlockStarts
                            // collapse onto IR index `idx`, yielding a duplicate
                            // `content_block_start` and (at the terminal frame) a duplicate
                            // BlockStop. Require the symmetric text key to be CLEAR before opening a
                            // tool block, so a single output_index is exactly one block kind.
                            let already_open = state.open_tools.contains(&idx)
                                || state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET));
                            if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                                state.open_tools.insert(idx);
                                out.push(IrStreamEvent::BlockStart {
                                    index: idx,
                                    block: crate::ir::IrBlockMeta::ToolUse { id: call_id, name },
                                });
                            }
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_REASONING)
                    {
                        // H1 REASONING (stream): a native Responses stream opens a chain-of-thought
                        // item with `output_item.added` typed `reasoning`. The prior `_`/`message`
                        // no-op DROPPED it, so a reasoning stream lost its thinking on any
                        // cross-protocol hop. Open a Thinking block at this `output_index`, tracked in
                        // `open_tools` at the RAW idx (like a tool item — closed once by the single
                        // `output_item.done` this index receives). Same cardinality cap and
                        // already-open guard as the tool arm so a malformed stream cannot double-open
                        // or grow the set without bound.
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                            let already_open = state.open_tools.contains(&idx)
                                || state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET));
                            if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                                state.open_tools.insert(idx);
                                out.push(IrStreamEvent::BlockStart {
                                    index: idx,
                                    block: crate::ir::IrBlockMeta::Thinking,
                                });
                            }
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_MESSAGE)
                    {
                    }
                }
            }

            // H1 REASONING (stream): native reasoning text arrives as `response.reasoning_text.delta`
            // (the full reasoning) and `response.reasoning_summary_text.delta` (a summarized form),
            // both carrying an `output_index` and a `delta` string. The prior `_ => {}` DROPPED these,
            // so a streamed reasoning response lost its chain-of-thought. Route each as an
            // `IrDelta::ThinkingDelta` against the reasoning block at this `output_index`, lazily
            // opening the Thinking BlockStart if the `output_item.added` was absent (some backends emit
            // reasoning deltas with no preceding `added`). The block is tracked at the RAW idx in
            // `open_tools`, closed once by the terminal `output_item.done`/stream end.
            EVT_REASONING_TEXT_DELTA | "response.reasoning_summary_text.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| (v as usize).min(MAX_OUTPUT_INDEX));
                    // Lazily open the Thinking block if `output_item.added` did not already. Guard the
                    // open against a TEXT key collision at the same index (a reasoning index and a text
                    // index should never share a wire index, but stay defensive) and the cardinality
                    // cap; beyond the cap suppress the delta rather than emit an orphan.
                    if !state.open_tools.contains(&idx)
                        && !state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET))
                    {
                        if state.open_tools.len() >= MAX_OPEN_TOOLS {
                            return out;
                        }
                        state.open_tools.insert(idx);
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Thinking,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::ThinkingDelta(delta),
                    });
                }
            }

            EVT_OUTPUT_TEXT_DELTA => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                // Drop empty keepalive deltas entirely: they neither open a block nor carry
                // content, so emitting a zero-length TextDelta would be spurious noise.
                if !delta.is_empty() {
                    // Use the wire `output_index` for BOTH the lazy BlockStart and the BlockDelta so
                    // the open/close pair stays index-matched even when the text part is not at
                    // index 0 (e.g. it follows a tool call at index 0).
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| (v as usize).min(MAX_OUTPUT_INDEX));
                    // Track open TEXT indices PER INDEX in `open_tools` under a disjoint key offset
                    // (see `TEXT_INDEX_KEY_OFFSET`) instead of the single index-blind
                    // `text_block_open` bool. A native stream can carry multiple message items, each
                    // at its own `output_index`; the per-index set opens a BlockStart lazily ONLY for
                    // an index not already open (so a second text item gets its own BlockStart rather
                    // than an orphan delta), and bounds cardinality under the same cap as tool items
                    // so a backend emitting a unique index per delta cannot grow the set without
                    // bound. Beyond the cap a new index streams no BlockStart/BlockDelta (matching
                    // the tool arm's suppression), never an orphan delta.
                    // Symmetric to the tool arm: an index already open as a TOOL block (raw `idx` in
                    // `open_tools`) must not also open a TEXT block under `idx +
                    // TEXT_INDEX_KEY_OFFSET`. If a function-call item already holds this
                    // `output_index`, a stray text delta at the same index must NOT open a second
                    // block (two BlockStarts collapsing onto one IR index — a duplicate
                    // `content_block_start` and an eventual duplicate BlockStop). Treat the index as
                    // already open and route no text BlockStart/BlockDelta to it.
                    let text_key = idx + TEXT_INDEX_KEY_OFFSET;
                    if state.open_tools.contains(&idx) {
                        // This `output_index` is already held by an OPEN TOOL block. A text delta
                        // here must NOT open a second block (a duplicate `content_block_start`/
                        // `_stop` once both keys collapse onto IR index `idx`) AND must NOT push a
                        // TextDelta into a tool block (a malformed text fragment inside an open
                        // tool-use block a strict SDK rejects). Drop the stray text delta entirely.
                        return out;
                    }
                    let already_open = state.open_tools.contains(&text_key);
                    if !already_open {
                        if state.open_tools.len() >= MAX_OPEN_TOOLS {
                            // Cap reached: suppress this index entirely (no BlockStart, no orphan
                            // BlockDelta) rather than emitting a delta for an unopened block.
                            return out;
                        }
                        state.open_tools.insert(text_key);
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::TextDelta(delta),
                    });
                }
            }

            EVT_FUNCTION_CALL_ARGS_DELTA => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                        let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                        // Route the argument delta ONLY to an index that actually emitted a
                        // BlockStart (tracked in `open_tools` by the `output_item.added` arm).
                        // An index suppressed by the cardinality cap — or an arguments-delta that
                        // arrives with no preceding `output_item.added` at all — has no open block,
                        // so a BlockDelta against it would be a tool-argument fragment for a block
                        // with no `content_block_start`: an invalid event sequence that breaks a
                        // strict SDK reassembling tool-call arguments and a distinguishability tell.
                        // Drop it (mirrors openai_chat.rs's `state.open_tools.contains` guard).
                        if state.open_tools.contains(&idx) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(delta),
                            });
                        }
                    }
                }
            }

            EVT_OUTPUT_ITEM_DONE | "response.content_part.done" => {
                if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                    let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                    // Native Responses closes a single text item with TWO terminal frames at the
                    // SAME `output_index`: `content_part.done` (the text content part) immediately
                    // followed by `output_item.done` (the enclosing message item). Emitting a
                    // BlockStop for BOTH produces a duplicate `content_block_stop` at one index for
                    // a block that opened once — an invalid event sequence and a distinguishability
                    // tell. So close a block EXACTLY once: only emit BlockStop for an index that is
                    // currently open, and clear the open marker so the second terminal frame at the
                    // same index is a no-op. A tool index (raw `idx`) and a text index (stored under
                    // `TEXT_INDEX_KEY_OFFSET`) are tracked PER INDEX in `open_tools`, so the close
                    // routes to the correct block kind AND the correct index — a native stream's two
                    // terminal frames for one text item (`content_part.done` then `output_item.done`,
                    // same index) close it exactly once because the second frame finds the key gone.
                    if state.open_tools.remove(&idx) {
                        // This index was a (now-closed) function-call item.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    } else if state.open_tools.remove(&(idx + TEXT_INDEX_KEY_OFFSET)) {
                        // This index was an open text block; close THIS index once. Removing the
                        // per-index key (rather than clearing a global bool) lets a different text
                        // index stay open and close on its own terminal frame, and makes the paired
                        // `content_part.done`/`output_item.done` for the same item a no-op the
                        // second time.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    }
                    // Otherwise nothing is open at this index (e.g. the second terminal frame of a
                    // text item, or a `done` for an item we never opened): emit nothing.
                }
            }

            EVT_RESPONSE_COMPLETED | EVT_RESPONSE_FAILED | EVT_RESPONSE_INCOMPLETE => {
                // A terminal event ends the message. Any content block still open at this point
                // (a tool index tracked as a raw `idx`, or a text index tracked under
                // `TEXT_INDEX_KEY_OFFSET`) was opened with a BlockStart but never received its
                // matching `output_item.done`/`content_part.done` — e.g. the upstream cut the
                // stream off mid-block, or a `failed`/`incomplete` arrives while content is still
                // streaming. Pushing MessageStop without closing them emits an unbalanced
                // BlockStart-without-BlockStop, which a strict SDK reassembling the stream rejects.
                // Drain `open_tools` and emit a BlockStop for every still-open index BEFORE the
                // MessageStop, converting text keys (>= TEXT_INDEX_KEY_OFFSET) back to their IR
                // index. This closure is invoked in EVERY terminal sub-path (incl. the failed
                // early-return) right before the MessageStop is pushed.
                let close_open_blocks =
                    |out: &mut Vec<IrStreamEvent>, state: &mut crate::ir::StreamDecodeState| {
                        // Drain into a sorted Vec first: closing in ascending IR-index order keeps
                        // the emitted BlockStop sequence deterministic regardless of insertion order
                        // (text and tool keys interleave under the offset scheme).
                        let mut indices: Vec<usize> = state
                            .open_tools
                            .iter()
                            .map(|&key| {
                                if key >= TEXT_INDEX_KEY_OFFSET {
                                    key - TEXT_INDEX_KEY_OFFSET
                                } else {
                                    key
                                }
                            })
                            .collect();
                        state.open_tools.clear();
                        // Dedup AFTER sorting: a tool key (`N`) and a text key (`N +
                        // TEXT_INDEX_KEY_OFFSET`) both map back to the SAME IR index `N`, so without
                        // dedup a single output_index that was (erroneously, pre-fix) opened as both
                        // kinds would emit TWO BlockStop{N} — a duplicate `content_block_stop` the
                        // downstream Anthropic writer relays for an already-closed index. One
                        // BlockStop per distinct IR index, regardless of how many keys collapsed onto
                        // it. (The output_item.added / output_text.delta guards below also prevent the
                        // double-open in the first place; this dedup is the second, defensive layer.)
                        indices.sort_unstable();
                        indices.dedup();
                        for index in indices {
                            out.push(IrStreamEvent::BlockStop { index });
                        }
                    };

                if let Some(response_obj) = data.get("response") {
                    let status = response_obj
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    // A genuinely failed terminal stream must NOT be decoded as a successful
                    // end_turn — that would mask the upstream failure from a downstream client
                    // (e.g. an Anthropic client would see stop_reason=end_turn). Surface it as an
                    // explicit IrStreamEvent::Error so the failure propagates, then still terminate
                    // the stream so consumers do not hang.
                    if status == STATUS_FAILED {
                        let provider_signal = response_obj
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_str())
                            .or_else(|| {
                                response_obj
                                    .get("error")
                                    .and_then(|e| e.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .map(String::from)
                            .or_else(|| Some(SIGNAL_RESPONSE_FAILED.to_string()));
                        // Derive the breaker class from the captured provider signal rather than
                        // hardcoding ServerError: an auth/rate-limit/context-length failure that
                        // arrives mid-stream must classify the same way it would on the non-stream
                        // HTTP path, or the breaker takes the wrong disposition/failover. The
                        // fallback "response_failed" (no error code/type present) maps to the
                        // default ServerError bucket.
                        let class = class_for_response_failed(
                            provider_signal.as_deref().unwrap_or(SIGNAL_RESPONSE_FAILED),
                        );
                        out.push(IrStreamEvent::Error(IrError {
                            class,
                            provider_signal,
                            retry_after: None,
                        }));
                        close_open_blocks(&mut out, state);
                        out.push(IrStreamEvent::MessageStop);
                        return out;
                    }

                    // Enumerate the recognized statuses rather than defaulting unknown ones to a
                    // successful end_turn. An unrecognized status is treated as a terminal stop
                    // with no specific reason (None) rather than silently claiming success.
                    let stop_reason = match status {
                        STATUS_COMPLETED | "" => Some(crate::ir::IrStopReason::EndTurn),
                        // An `incomplete` is NOT a successful end_turn; map its machine-readable
                        // reason, or surface None (don't mask the truncation) when there is none.
                        STATUS_INCOMPLETE => response_obj
                            .get("incomplete_details")
                            .and_then(|d| d.get("reason"))
                            .and_then(|r| r.as_str())
                            .map(read_responses_incomplete_reason),
                        _ => None,
                    };

                    // Tool-use override, mirroring the non-streaming `read_response` (which flips a
                    // `completed` end_turn to `tool_use` when the output carries a function_call).
                    // Without this, a STREAMED Responses tool call terminated stop_reason=end_turn
                    // while the non-stream path said tool_use — so a cross-protocol client (OpenAI/
                    // Anthropic ingress) never saw the tool-call finish signal on the streaming path.
                    // The `response.completed` event carries the fully-assembled `output`, so detect a
                    // function_call item there and override only the successful end_turn cases.
                    let stop_reason = if stop_reason == Some(crate::ir::IrStopReason::EndTurn)
                        && response_obj
                            .get("output")
                            .and_then(|o| o.as_array())
                            .is_some_and(|items| {
                                items.iter().any(|it| {
                                    it.get("type").and_then(|t| t.as_str())
                                        == Some(ITEM_TYPE_FUNCTION_CALL)
                                })
                            }) {
                        Some(crate::ir::IrStopReason::ToolUse)
                    } else {
                        stop_reason
                    };

                    // Refusal override, mirroring the non-streaming `read_response`. A STREAMED
                    // Responses refusal does NOT arrive via `output_text.delta` — the refusal text
                    // appears ONLY in this terminal `response.completed` frame as an
                    // `output[].content[]` `{type:"refusal", refusal:"..."}` part (status stays
                    // `completed`). Without this scan the streaming path SILENTLY DROPPED the refusal
                    // text and left stop_reason=end_turn — the client saw an empty response with no
                    // refusal signal. Emit the refusal text as a Text block (opened here, closed by
                    // `close_open_blocks` below) and promote stop_reason end_turn -> Refusal so a
                    // non-Responses client still sees the refusal. Anthropic/Bedrock have no distinct
                    // refusal part, so a refusal is plain assistant text + a `refusal` stop there.
                    let mut saw_refusal = false;
                    if let Some(items) = response_obj.get("output").and_then(|o| o.as_array()) {
                        for (item_pos, item) in items.iter().enumerate() {
                            let Some(content) = item.get("content").and_then(|c| c.as_array())
                            else {
                                continue;
                            };
                            for block in content {
                                if block.get("type").and_then(|t| t.as_str()) != Some("refusal") {
                                    continue;
                                }
                                let Some(text) = block
                                    .get("refusal")
                                    .and_then(|r| r.as_str())
                                    .filter(|s| !s.is_empty())
                                else {
                                    continue;
                                };
                                saw_refusal = true;
                                // Open a Text block for the refusal text at this item's index, unless
                                // that index is already open (defensive — a refusal is normally the
                                // sole output) or the per-stream block cap is reached.
                                let idx = item_pos.min(MAX_OUTPUT_INDEX);
                                let text_key = idx + TEXT_INDEX_KEY_OFFSET;
                                if !state.open_tools.contains(&idx)
                                    && !state.open_tools.contains(&text_key)
                                    && state.open_tools.len() < MAX_OPEN_TOOLS
                                {
                                    state.open_tools.insert(text_key);
                                    out.push(IrStreamEvent::BlockStart {
                                        index: idx,
                                        block: crate::ir::IrBlockMeta::Text,
                                    });
                                    out.push(IrStreamEvent::BlockDelta {
                                        index: idx,
                                        delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                    });
                                }
                            }
                        }
                    }
                    let stop_reason =
                        if saw_refusal && stop_reason == Some(crate::ir::IrStopReason::EndTurn) {
                            Some(crate::ir::IrStopReason::Refusal)
                        } else {
                            stop_reason
                        };

                    let usage = response_obj
                        .get("usage")
                        .map(|u| {
                            let cached = read_cached_tokens(u);
                            crate::ir::IrUsage {
                                // NORMALIZE to the additive-cache convention: the Responses API's
                                // `input_tokens` is a TOTAL that already INCLUDES the cached prefix,
                                // so subtract the cached tokens to leave only the uncached input.
                                // `saturating_sub` guards an odd upstream where cached > input.
                                input_tokens: u
                                    .get("input_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0)
                                    .saturating_sub(cached.unwrap_or(0)),
                                output_tokens: u
                                    .get("output_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                cache_creation_input_tokens: None,
                                // H6: carry the streamed prompt-cache hit count
                                // (`usage.input_tokens_details.cached_tokens`) into the IR's
                                // read-side cache field so a streaming Responses terminal preserves
                                // the cache saving.
                                cache_read_input_tokens: cached,
                            }
                        })
                        .unwrap_or(crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        });

                    // Close any still-open content blocks BEFORE the MessageDelta so the emitted
                    // order is BlockStop* → MessageDelta → MessageStop, mirroring Anthropic's
                    // content_block_stop-before-message_delta sequencing.
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        // Responses API has no stop_sequence analog in its stream.
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                } else if event_type == EVT_RESPONSE_FAILED {
                    // Terminal failure event with no nested `response` object (e.g. a truncated SSE
                    // frame or a proxy that stripped the body). The wire `event_type` is the only
                    // failure signal available — honour it. Surfacing this as a successful end_turn
                    // would mask the upstream failure from downstream clients AND deny the breaker
                    // the failure signal, so we mirror the body-present failure arm above: emit an
                    // explicit Error followed by MessageStop.
                    // No nested response object → no error code/type to inspect. The only signal is
                    // the wire event_type; classify via the shared helper (which defaults the
                    // unrecognized "response_failed" sentinel to ServerError) so both response.failed
                    // arms derive their class through the same mapping.
                    let provider_signal = SIGNAL_RESPONSE_FAILED;
                    out.push(IrStreamEvent::Error(IrError {
                        class: class_for_response_failed(provider_signal),
                        provider_signal: Some(provider_signal.to_string()),
                        retry_after: None,
                    }));
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageStop);
                } else {
                    // Terminal completed/incomplete event with no nested `response` object. We must
                    // still terminate the translated stream with a MessageDelta + MessageStop so
                    // downstream consumers do not hang waiting for the end of the message.
                    //
                    // The wire `event_type` is the only status signal available — select the stop
                    // reason from it rather than hardcoding end_turn. A bodyless `incomplete` is NOT
                    // a successful end_turn: with no nested `incomplete_details.reason` to inspect
                    // there is no specific truncation reason to surface, so emit None (mirrors the
                    // body-present `incomplete`/no-details precedent above and the non-streaming
                    // `read_response`). Only a `completed` event maps to end_turn. (`failed` is
                    // handled by the branch above; this else covers `completed`/`incomplete`.)
                    let stop_reason = match event_type {
                        EVT_RESPONSE_COMPLETED => Some(crate::ir::IrStopReason::EndTurn),
                        EVT_RESPONSE_INCOMPLETE => None,
                        // No other event_type reaches this arm (the outer match guards the set and
                        // `response.failed` is handled above), so anything else is an unrecognized
                        // terminal with no specific reason.
                        _ => None,
                    };
                    let usage = crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                }
            }

            _ => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("");

        // A non-streaming Responses body with `status:"failed"` is an upstream provider failure
        // (rate_limit, content_filter, server_error, etc.), NOT a parse failure. The writer emits
        // `{"status":"failed","output":[],"error":{...}}` — note `output` is a PRESENT EMPTY array,
        // not null/absent — so this MUST be handled before the `output`-array branch below, or an
        // empty `output:[]` would iterate zero items, fail the usage check, and mask the real error
        // as an internal `ir_parse` (ClientFault, no-retry) — the wrong breaker transition. Handle
        // failed bodies uniformly here whether `output` is `[]`, null, or absent. Surface the
        // upstream signal so the real error reaches the client and the breaker sees the correct
        // class via `class_for_response_failed`. Mirror the streaming `response.failed` arm: prefer
        // the `error.code` enum, fall back to `error.type`, then a generic `response_failed`.
        if status == STATUS_FAILED {
            let provider_signal = obj
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .or_else(|| {
                    obj.get("error")
                        .and_then(|e| e.get("type"))
                        .and_then(|t| t.as_str())
                })
                .map(String::from)
                .or_else(|| Some(SIGNAL_RESPONSE_FAILED.to_string()));
            // Same class as the streaming `response.failed` arms: derive the breaker class from the
            // captured provider signal rather than hardcoding ServerError, so an auth/rate-limit/
            // context-length failed body classifies correctly (right breaker disposition/failover).
            let class = class_for_response_failed(
                provider_signal.as_deref().unwrap_or(SIGNAL_RESPONSE_FAILED),
            );
            return Err(IrError {
                class,
                provider_signal,
                retry_after: None,
            });
        }

        let mut stop_reason: Option<crate::ir::IrStopReason> = match status {
            STATUS_COMPLETED => Some(crate::ir::IrStopReason::EndTurn),
            STATUS_INCOMPLETE => obj
                .get("incomplete_details")
                .and_then(|d| d.get("reason"))
                .and_then(|r| r.as_str())
                .map(read_responses_incomplete_reason),
            _ => None,
        };

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        // A refusal rides on a `refusal` content part with `status:"completed"`, so the refusal
        // SIGNAL is not in `status`. Track it here to promote `stop_reason` to `Refusal` below.
        let mut saw_refusal = false;
        if let Some(output_arr) = obj.get("output").and_then(|o| o.as_array()) {
            for item in output_arr {
                let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

                match item_type {
                    ITEM_TYPE_MESSAGE => {
                        if let Some(content_arr) = item.get("content").and_then(|c| c.as_array()) {
                            for block_item in content_arr {
                                let block_type = block_item
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or("");

                                if block_type == CONTENT_TYPE_OUTPUT_TEXT {
                                    if let Some(text) =
                                        block_item.get("text").and_then(|t| t.as_str())
                                    {
                                        content.push(crate::ir::IrBlock::Text {
                                            text: text.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                } else if block_type == "refusal" {
                                    // A model refusal rides on a `{type:"refusal", refusal:"..."}`
                                    // content part (the status stays `completed`). The prior reader
                                    // only matched `output_text`, SILENTLY DROPPING the refusal text.
                                    // Carry it as assistant Text so the explanation survives the
                                    // translation (Anthropic/Bedrock have no distinct refusal part —
                                    // a refusal is plain assistant text there). The refusal SIGNAL is
                                    // separately promoted onto `stop_reason` below.
                                    if let Some(text) =
                                        block_item.get("refusal").and_then(|t| t.as_str())
                                    {
                                        saw_refusal = true;
                                        content.push(crate::ir::IrBlock::Text {
                                            text: text.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    ITEM_TYPE_FUNCTION_CALL => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = item
                            .get("arguments")
                            .and_then(|a| a.as_str())
                            .unwrap_or("{}");
                        // Preserve the raw string on malformed JSON rather than dropping the tool
                        // arguments to Null (mirrors the OpenAI reader; avoids lossy translation).
                        let input = crate::json::parse_str(arguments)
                            .unwrap_or_else(|_| serde_json::Value::String(arguments.to_string()));

                        content.push(crate::ir::IrBlock::ToolUse {
                            id: call_id,
                            name,
                            input,
                            cache_control: None,
                        });
                    }

                    // H1 REASONING: a native Responses `reasoning` output item carries the model's
                    // chain-of-thought. The prior `_ => {}` DROPPED it, so a reasoning response lost
                    // its thinking entirely on any cross-protocol hop (Responses → Anthropic/Bedrock,
                    // which DO carry thinking). Read it into an `IrBlock::Thinking` so it survives the
                    // seam. The reasoning text lives in `content[].text` (`reasoning_text` parts) and/or
                    // `summary[].text` (`summary_text` parts); concatenate whichever is present (a real
                    // reasoning item carries one or the other). Responses has no `signature`, but it
                    // carries an opaque `encrypted_content` blob for multi-turn reasoning reuse — map it
                    // into the IR `signature` slot so a same-protocol round-trip preserves it (and a
                    // cross-protocol hop to a signature-carrying protocol keeps the opaque token).
                    //
                    // LOW (accepted, non-portable by nature): the IR `signature` slot is a single
                    // opaque token shared across protocols (Anthropic `thinking.signature`, Responses
                    // `encrypted_content`, Gemini `thoughtSignature`). These are each PROTOCOL-OPAQUE
                    // and vendor-scoped: an Anthropic signature carried into a Responses
                    // `encrypted_content` (or vice-versa) preserves the BYTES, but the blob is NOT
                    // re-feedable to the OTHER vendor's API — each vendor only accepts its own. So the
                    // token round-trips faithfully same-protocol and survives the seam as an opaque
                    // value, but cross-vendor reasoning-reuse (replaying a foreign vendor's signature)
                    // is inherently unsupported. No behavior change; documented so the limitation is
                    // explicit rather than an implied promise of cross-vendor reasoning continuation.
                    ITEM_TYPE_REASONING => {
                        let text = read_reasoning_text(item);
                        let signature = item
                            .get("encrypted_content")
                            .and_then(|s| s.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from);
                        // Skip a wholly-empty reasoning item (no text and no encrypted_content)
                        // rather than emitting a blank Thinking block.
                        if !text.is_empty() || signature.is_some() {
                            content.push(crate::ir::IrBlock::Thinking {
                                text,
                                signature,
                                redacted: false,
                                cache_control: None,
                            });
                        }
                    }

                    _ => {}
                }
            }
        } else {
            // `status:"failed"` is handled by the early return above, so a missing/non-array
            // `output` here is a genuine parse failure (malformed body).
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        // Promote a successful end_turn to tool_use when the assembled content carries a tool call,
        // mirroring the streaming `response.completed` arm. Guard the override on `end_turn` ONLY: an
        // `incomplete` status (max_tokens/safety/other truncation reason) means the model was cut off
        // mid-output — even if a partial function_call survived, the turn did NOT cleanly finish on a
        // tool call, and clobbering `max_tokens`/`safety` with `tool_use` would tell the client the
        // call is complete and deny the truncation signal to the breaker. Only the clean-finish case
        // (`end_turn`) is promoted; any other reason is left untouched.
        if stop_reason == Some(crate::ir::IrStopReason::EndTurn)
            && content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. }))
        {
            stop_reason = Some(crate::ir::IrStopReason::ToolUse);
        }

        // A `completed` response that carried a `refusal` part is a refusal, not a clean end_turn.
        // Promote the typed `Refusal` stop_reason (which the Anthropic/OpenAI writers translate) so
        // the refusal signal survives even though the Responses `status` was `completed`.
        if saw_refusal && stop_reason == Some(crate::ir::IrStopReason::EndTurn) {
            stop_reason = Some(crate::ir::IrStopReason::Refusal);
        }

        // Tolerate an absent `usage` object leniently — zero-default rather than hard-erroring,
        // mirroring all five sibling readers (openai_chat.rs, gemini, cohere, etc.). A missing
        // `usage` on an otherwise valid 200 is an upstream response-format quirk (a mock/staging/
        // proxy backend that omits it), NOT a client mistake: a `ClientError` here would make
        // forward.rs discard a valid body and emit a spurious 500.
        let usage_val = obj.get("usage");

        let cached = usage_val.and_then(read_cached_tokens);
        let usage = crate::ir::IrUsage {
            // NORMALIZE to the additive-cache convention: the Responses API's `input_tokens` is a
            // TOTAL that already INCLUDES the cached prefix, so subtract the cached tokens to leave
            // only the uncached input. `saturating_sub` guards an odd upstream where cached > input.
            input_tokens: usage_val
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .saturating_sub(cached.unwrap_or(0)),
            output_tokens: usage_val
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            // H6: the Responses API reports prompt-cache hits under
            // `usage.input_tokens_details.cached_tokens`. Map it into the IR's
            // `cache_read_input_tokens` (the read-side cache field Bedrock already uses) so the cache
            // saving survives a cross-protocol hop instead of being dropped. No new IR field is added.
            cache_read_input_tokens: cached,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response's identity so a same-protocol (responses → responses)
        // passthrough preserves `id`/`created_at` exactly. The Responses API names its creation
        // timestamp `created_at` (NOT `created`, which is the Chat Completions field); we map it
        // into the shared IR `created` slot. `system_fingerprint`/`stop_sequence` have no analog in
        // the Responses shape, so they stay `None`.
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        let created = obj.get("created_at").and_then(|c| c.as_u64());

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

fn responses_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        CONTENT_TYPE_INPUT_TEXT | CONTENT_TYPE_OUTPUT_TEXT => {
            let text_val = obj.get("text");
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        "input_image" => {
            // L5: handle a file_id-referenced image (no inline `image_url`) faithfully rather than
            // emitting an empty Image block. Shared with the request-input reader.
            responses_input_image_block(block_val).ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            })
        }
        _ => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        }),
    }
}

/// Sentinel `media_type` marking an IR `Image` block that carries a Responses `file_id` reference
/// (L5) rather than inline image bytes or a URL. The `image_url` sentinel is already taken by
/// `parse_image_url` for verbatim URL strings, so a DISTINCT sentinel is needed to round-trip a
/// `file_id` image without an `image_url`: the writer keys on this value to re-emit
/// `{type:"input_image","file_id":<data>}` instead of an `image_url`. A real image MIME type
/// (`image/png`, …) and a non-data URL can never equal this literal, so the dispatch is unambiguous.
/// Build an IR `Image` block from a Responses `input_image` content object (L5). Prefers an inline
/// `image_url` (parsed via the shared `parse_image_url` into a `Base64`/`Url` source). Otherwise, an
/// uploaded-file reference becomes the typed `FileId` source so the writer reconstructs the native
/// `file_id` form losslessly. Returns `None` when the block carries NEITHER (a degenerate reference).
fn responses_input_image_block(item: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    let image_url = item.get("image_url").and_then(|u| u.as_str());
    if let Some(url) = image_url.filter(|u| !u.is_empty()) {
        return Some(crate::ir::IrBlock::Image {
            source: super::parse_image_url(url),
            cache_control: None,
        });
    }
    if let Some(file_id) = item
        .get("file_id")
        .and_then(|f| f.as_str())
        .filter(|f| !f.is_empty())
    {
        return Some(crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Vendor {
                vendor: VENDOR_NAME,
                value: serde_json::json!({ "file_id": file_id }),
            },
            cache_control: None,
        });
    }
    None
}

/// Extract the chain-of-thought text from a Responses `reasoning` output item (H1). A reasoning item
/// carries its text in two possible arrays: `content[]` entries of type `reasoning_text` (the full
/// reasoning text) and/or `summary[]` entries of type `summary_text` (a summarized form). Concatenate
/// every `text` found in BOTH arrays WITHOUT a separator (mirrors the no-separator concat the rest of
/// this module uses for fragment reassembly), preferring nothing — a real item carries one or the
/// other, and concatenating both is lossless when only one is present (the other contributes nothing).
/// Returns an empty string when neither array carries text, so the caller can skip an empty item.
fn read_reasoning_text(item: &serde_json::Value) -> String {
    let mut text = String::new();
    for (arr_key, type_key) in [
        ("content", CONTENT_TYPE_REASONING_TEXT),
        ("summary", "summary_text"),
    ] {
        if let Some(arr) = item.get(arr_key).and_then(|c| c.as_array()) {
            for part in arr {
                // Accept the part whether or not it carries the exact `type` literal — a missing or
                // unexpected `type` should not silently drop reasoning text — but only when a `text`
                // string is present. The `type_key` is checked only to skip a non-matching typed part
                // (e.g. a future part kind) while still accepting an untyped `{text}` shorthand.
                let type_ok = part
                    .get("type")
                    .and_then(|t| t.as_str())
                    .is_none_or(|t| t == type_key);
                if type_ok {
                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                        text.push_str(t);
                    }
                }
            }
        }
    }
    text
}

/// Responses `incomplete_details.reason` → canonical [`crate::ir::IrStopReason`]. The ONLY place that
/// knows the Responses truncation-reason vocabulary; an unmodeled reason maps to `Other`.
fn read_responses_incomplete_reason(reason: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match reason {
        INCOMPLETE_REASON_MAX_OUTPUT => S::MaxTokens,
        INCOMPLETE_REASON_CONTENT_FILTER => S::Safety,
        "refusal" => S::Refusal,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → Responses terminal `status`. Only a truncation (`max_tokens`) or a
/// content-filter (`safety`) renders the turn `incomplete`; everything else (incl. tool_use, refusal)
/// is `completed` (a refusal/tool-call is surfaced via output items, not the status).
fn write_responses_status(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::MaxTokens | S::Safety => STATUS_INCOMPLETE,
        _ => STATUS_COMPLETED,
    }
}

/// [`crate::ir::IrStopReason`] → Responses `incomplete_details.reason` (only consulted when the status
/// is `incomplete`, i.e. for `MaxTokens`/`Safety`; any other reason defaults to `other`).
fn write_responses_incomplete_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::MaxTokens => INCOMPLETE_REASON_MAX_OUTPUT,
        S::Safety => INCOMPLETE_REASON_CONTENT_FILTER,
        _ => INCOMPLETE_REASON_OTHER,
    }
}

/// Normalize a Responses `text` object's `format` into the IR's canonical `response_format` shape
/// (M1). The Responses API carries structured-output config at `text.format` with a FLAT json_schema
/// shape (`{"type":"json_schema","name":...,"schema":...,"strict":...,"description":...}`), whereas
/// the IR's canonical `response_format` (the shape the OpenAI Chat-Completions reader stores) NESTS
/// those under a `json_schema` key (`{"type":"json_schema","json_schema":{name,schema,strict,...}}`).
/// This converts the flat Responses form into the nested canonical form so a Responses structured-
/// output request reaches an OpenAI/Anthropic backend faithfully. `text`/`json_object` formats carry
/// no extra fields and pass through as `{"type":...}`. Returns `None` when `text.format` is absent so
/// the IR field stays unset (no spurious response_format on a request that carried none). An
/// unrecognized `type` is passed through verbatim rather than dropped.
fn read_text_format(text_val: Option<&serde_json::Value>) -> Option<crate::ir::IrResponseFormat> {
    let format = text_val.and_then(|t| t.get("format"))?;
    let o = format.as_object()?;
    match o.get("type").and_then(|t| t.as_str()) {
        Some("text") => Some(crate::ir::IrResponseFormat {
            json: false,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        // The Responses `text.format` json_schema form is FLAT — name/schema/strict/description sit
        // beside `type` (not nested under `json_schema` as in OpenAI).
        Some("json_schema") => Some(crate::ir::IrResponseFormat {
            json: true,
            schema: o.get("schema").cloned(),
            name: o.get("name").and_then(|n| n.as_str()).map(String::from),
            strict: o.get("strict").and_then(|s| s.as_bool()),
            description: o
                .get("description")
                .and_then(|d| d.as_str())
                .map(String::from),
        }),
        // `json_object` / any unknown type → free-form JSON (safe default).
        Some(_) => Some(crate::ir::IrResponseFormat {
            json: true,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        None => None,
    }
}

/// Project the agnostic [`crate::ir::IrResponseFormat`] into a Responses `text.format` object (inverse
/// of [`read_text_format`]). The ONLY code that builds the Responses structured-output wire shape: the
/// json_schema form is FLAT — `name`/`schema`/`strict`/`description` sit beside `type`. Returns the
/// `format` value to place under `text.format`; the caller wraps it in `{"text":{"format":...}}`.
fn write_text_format(rf: &crate::ir::IrResponseFormat) -> serde_json::Value {
    if !rf.json {
        return serde_json::json!({"type": "text"});
    }
    match &rf.schema {
        Some(schema) => {
            let mut f = serde_json::Map::new();
            f.insert("type".to_string(), serde_json::json!("json_schema"));
            f.insert(
                "name".to_string(),
                serde_json::json!(rf.name.as_deref().unwrap_or("response")),
            );
            f.insert("schema".to_string(), schema.clone());
            if let Some(s) = rf.strict {
                f.insert("strict".to_string(), serde_json::json!(s));
            }
            if let Some(d) = &rf.description {
                f.insert("description".to_string(), serde_json::json!(d));
            }
            serde_json::Value::Object(f)
        }
        None => serde_json::json!({"type": "json_object"}),
    }
}

/// Read the Responses prompt-cache hit count from a `usage` object (H6):
/// `usage.input_tokens_details.cached_tokens`. Returns `None` when the nested field is absent (so a
/// usage object without cache details does not gain a spurious `Some(0)`), mapping into the IR's
/// `cache_read_input_tokens`. Shared by the non-streaming `read_response` and the streaming terminal.
fn read_cached_tokens(usage_val: &serde_json::Value) -> Option<u64> {
    usage_val
        .get("input_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_u64())
}

/// OpenAI Responses streaming writer.
///
/// EVERY native `/v1/responses` SSE event carries a top-level monotonically-increasing integer
/// `sequence_number` starting at 0 (a REQUIRED field on the official SDK's `Response*Event` types).
/// That counter is PER STREAM, not per process or per worker thread.
///
/// A previous revision kept the counter in thread-local storage, keyed implicitly by the Tokio
/// worker driving the stream. That is unsound on the multi-thread work-stealing runtime: two
/// concurrent streams scheduled on the same worker share one cell, and the second stream's opening
/// `response.created` (which resets the counter to 0) silently clobbers the first stream's in-flight
/// counter — producing non-monotonic `sequence_number`s that a native SDK rejects. The bleed is
/// invisible from any single stream's emitted JSON.
///
/// The counter therefore lives in per-stream INSTANCE state. `StreamTranslate::new` builds a FRESH
/// `Protocol::responses()` (hence a fresh `ResponsesWriter` with a zeroed counter) for each stream,
/// so the counter is stream-scoped by construction and the increments are plain `&self` atomics on
/// that one owned instance — no thread affinity, so the counter follows the stream across Tokio
/// worker migrations.
pub(crate) struct ResponsesWriter {
    /// Per-stream `sequence_number` counter. Reset to 0 on the stream's opening `MessageStart`
    /// (`response.created`) and advanced once per emitted event for the rest of the stream.
    /// `AtomicU64` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires;
    /// the stream is single-threaded at any instant, so `Relaxed` ordering is sufficient.
    sequence: AtomicU64,
    /// Per-stream `response.id`. Captured on the opening `MessageStart` (the synthesized-or-
    /// forwarded id written into `response.created`) and replayed verbatim onto EVERY subsequent
    /// lifecycle event (`response.completed`/`response.incomplete`/`response.failed`). A native
    /// OpenAI Responses stream carries the SAME `id` on every event; the official SDK reads
    /// `event.response.id` on the terminal event to finalize and correlate the `Response`. Before
    /// this cell existed, `MessageDelta`/`Error` each minted a FRESH `resp_` id, so on any
    /// cross-protocol stream (where the IR strips identity) the terminal event's id differed from
    /// `response.created` — an SDK-breaking correctness failure and a hard distinguishability tell.
    /// Per-stream INSTANCE state for the same reason as `sequence` (see the type doc); a poisoned
    /// lock degrades to the synthesize-fresh fallback rather than panicking on the request path.
    response_id: std::sync::Mutex<Option<String>>,
    /// Per-stream `response.created_at` (unix seconds). Captured on the opening `MessageStart`
    /// (`response.created`) and replayed verbatim onto EVERY subsequent lifecycle event
    /// (`response.completed`/`response.incomplete`/`response.failed`). A native OpenAI Responses
    /// stream carries the SAME `created_at` on every event for a given response. Before this cell
    /// existed, the terminal `MessageDelta` (and error) events each called `now_unix_secs()`
    /// directly, so on any stream where the opening event's `created_at` came from upstream IR — or
    /// merely a wall-clock instant earlier than the terminal event — the terminal `created_at`
    /// differed from `response.created`'s, a detectable proxy tell that breaks SDK consumers
    /// comparing timestamps across events. Per-stream INSTANCE state for the same reason as
    /// `response_id`; a poisoned lock degrades to the synthesize-fresh (`now_unix_secs`) fallback
    /// rather than panicking on the request path.
    created_at: std::sync::Mutex<Option<u64>>,
    /// Per-stream `response.model`. Captured on the opening `MessageStart` (the model written into
    /// `response.created`, after the DEFAULT_MODEL fallback) and replayed verbatim onto EVERY
    /// subsequent lifecycle event (`response.completed`/`response.incomplete`/`response.failed`). A
    /// native OpenAI Responses stream carries the SAME `model` on the full `Response` object of
    /// every event, and the official SDK types `Response.model` as a REQUIRED non-nullable string —
    /// so a terminal event whose inner `response` omits `model` fails a strict decoder and is a
    /// distinguishability tell. The IR `MessageDelta`/`Error` events carry no model, so the terminal
    /// arms replay this captured value (falling back to DEFAULT_MODEL only if the cell was never
    /// populated). Per-stream INSTANCE state for the same reason as `response_id`/`created_at`; a
    /// poisoned lock degrades to the DEFAULT_MODEL fallback rather than panicking on the request path.
    model: std::sync::Mutex<Option<String>>,
    /// Output indices for which this writer emitted a function-call `output_item.added`. The IR
    /// `BlockStop` carries only the integer index (no block kind), but a native Responses stream
    /// emits `output_item.done` ONLY for items it previously `added` — and the Text `BlockStart`
    /// arm emits no `added` (so a text block has no `output_item.added`/`.done` pair at all). Track
    /// the tool-call opens here so `BlockStop` emits `output_item.done` for a function-call index
    /// only, never for a text index. Without this a text block's BlockStop emitted a spurious
    /// `output_item.done` with `type:"function_call"` for an item that was never opened — an
    /// unmatched lifecycle event and a hard distinguishability tell. Per-stream INSTANCE state for
    /// the same reason as `sequence` (see the type doc); `Relaxed`-equivalent `Mutex` access is
    /// fine since a stream is single-threaded at any instant and the writer must stay `Sync`.
    open_tool_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Output indices for which this writer opened a TEXT message item (emitted
    /// `output_item.added` type "message" + `content_part.added`). A native /v1/responses stream
    /// ALWAYS brackets a text part with the full lifecycle
    /// `output_item.added(message) → content_part.added → output_text.delta* → output_text.done →
    /// content_part.done → output_item.done`; the official SDK builds `response.output[]` from the
    /// added/done pair, so a stream of orphan `output_text.delta` frames leaves the assembled
    /// Response with an empty output array. The IR `BlockStop` carries only the index, so track the
    /// open text indices here (the same way `open_tool_indices` tracks tool items) so the matching
    /// BlockStop emits the text terminal frames for THIS index only. Per-stream INSTANCE state for
    /// the same reason as the other fields; a poisoned lock degrades safely.
    open_text_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Per-stream cache of synthesized opaque `item_id`s, keyed by `(kind-prefix, output_index)`.
    /// A native /v1/responses stream carries a CONSTANT `item_id` across the
    /// `output_item.added → delta* → output_item.done` lifecycle of one output item; the official
    /// SDK correlates that lifecycle by the shared id. The IR block events carry only the integer
    /// `output_index`, so the writer mints the id — but it must be STABLE per `(prefix, index)` for
    /// the duration of the stream, while still being an opaque CSPRNG token (not the old sequential
    /// `msg_00000000` hex, whose positional structure fingerprinted a proxied response). This cache
    /// gives both: the first reference to a `(prefix, index)` mints a fresh opaque id; every later
    /// reference within the stream returns the same one. Per-stream INSTANCE state for the same
    /// reason as the other fields; a poisoned lock degrades to a freshly-minted id (still opaque,
    /// still valid) rather than panicking on the request path.
    item_ids: std::sync::Mutex<std::collections::BTreeMap<(&'static str, usize), String>>,
    /// Per-stream accumulator of function-call item fields, keyed by `output_index`. A native
    /// /v1/responses stream's `response.output_item.done` for a function-call item carries the FULLY
    /// finalized item — `call_id`, `name`, AND the complete accumulated `arguments` string — and the
    /// official SDK reads `event.item.arguments`/`.name`/`.call_id` off the `done` event to
    /// reconstruct the tool invocation. The IR `BlockStop` carries only the integer index, so the
    /// writer must accumulate those fields across the lifecycle: `call_id`+`name` arrive on the
    /// `BlockStart` (`IrBlockMeta::ToolUse`), and `arguments` is concatenated from the
    /// `InputJsonDelta` fragments on each `BlockDelta`. Without this the `output_item.done` item was
    /// `{"type":"function_call","id":…}` — missing `call_id`/`name`/`arguments`, an
    /// impossible-from-real-OpenAI shape that breaks SDK tool-call handling and is a
    /// distinguishability tell. Per-stream INSTANCE state for the same reason as the other fields; a
    /// poisoned lock degrades to omitting the accumulated fields (still emits the `done`) rather than
    /// panicking on the request path.
    tool_calls: std::sync::Mutex<std::collections::BTreeMap<usize, ToolCallAccum>>,
    /// Per-stream accumulator of streamed assistant TEXT, keyed by `output_index`. A native
    /// /v1/responses terminal `response.completed`/`response.incomplete` event carries the FULLY
    /// assembled `output[]` array, and a message item in it carries its `output_text` parts with the
    /// complete text the stream delivered via `output_text.delta`. The IR streams text only as
    /// `TextDelta` fragments, so the writer concatenates them here as they arrive and drains the
    /// joined text into the terminal `output` message item at BlockStop. Per-stream INSTANCE state
    /// for the same reason as the other fields; a poisoned lock degrades to omitting the accumulated
    /// text (the item then carries empty text) rather than panicking on the request path.
    text_accum: std::sync::Mutex<std::collections::BTreeMap<usize, String>>,
    /// Per-stream buffer of FINALIZED `output[]` items, keyed by `output_index` so the terminal
    /// event emits them in stable index order. A native /v1/responses `response.completed`/
    /// `response.incomplete` event's inner `response.output` is the fully assembled array (each
    /// `message` item with its `output_text` parts, each finalized `function_call` item) — the
    /// official SDK reads `event.response.output` to materialize the final `Response.output`. The IR
    /// `MessageDelta` carries no assembled output, but the writer has already seen every delta, so it
    /// records each item here as the matching `BlockStop` finalizes it and drains the map into the
    /// terminal `response.output`. Before this, the terminal `output` was hard-coded to `[]` even
    /// though real text/tool items streamed — an empty `output` with nonzero `usage.output_tokens`
    /// is a shape real OpenAI never emits and breaks SDK consumers that read the assembled output off
    /// the completed event. Per-stream INSTANCE state for the same reason as the other fields; a
    /// poisoned lock degrades to an empty array (the prior behavior) rather than panicking.
    output_items: std::sync::Mutex<std::collections::BTreeMap<usize, serde_json::Value>>,
    /// Output indices for which this writer opened a REASONING item (H1) — emitted the
    /// `output_item.added` typed "reasoning". Tracked separately from text/tool opens so the matching
    /// `BlockStop` (which carries only the index) emits the `output_item.done` typed "reasoning" for
    /// THIS index, and so a reasoning BlockStop is never mistaken for a text/tool close. Per-stream
    /// INSTANCE state for the same reason as the other open-index sets; a poisoned lock degrades safely.
    open_reasoning_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Per-stream accumulator of streamed reasoning TEXT (H1), keyed by `output_index`. The terminal
    /// `response.output[]` reasoning item carries the COMPLETE reasoning text the stream delivered via
    /// `reasoning_text.delta`; the IR streams it as `ThinkingDelta` fragments, so the writer
    /// concatenates them here and drains the joined text into the finalized reasoning item at
    /// BlockStop. A poisoned lock degrades to empty text rather than panicking.
    reasoning_accum: std::sync::Mutex<std::collections::BTreeMap<usize, String>>,
}

/// Accumulated function-call item fields for one open `output_index`, finalized into the
/// `response.output_item.done` `item` object. `call_id`/`name` are captured from the opening
/// `BlockStart`; `arguments` is built by concatenating the streamed `InputJsonDelta` fragments.
#[derive(Clone, Default)]
struct ToolCallAccum {
    call_id: String,
    name: String,
    arguments: String,
}

/// Value-namespace constructor for [`ResponsesWriter`]. A `const` and a struct may share a name
/// (they live in the value and type namespaces respectively), so `Protocol::responses()` can keep
/// writing the bare `ResponsesWriter` literal while the type now carries per-stream state. Each
/// USE of the const inlines a fresh `ResponsesWriter { sequence: AtomicU64::new(0) }`, so every
/// `Protocol::responses()` call mints an independent zeroed counter — exactly the per-stream
/// scoping the `sequence_number` contract needs. `AtomicU64::new` is a const fn, so this is valid
/// in const context (an `Arc` counter would not be).
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is
/// inlined per use rather than shared. That per-use fresh instance is PRECISELY the semantics we
/// need: a `static` would share ONE counter across every stream in the process — reintroducing the
/// cross-stream `sequence_number` bleed this change exists to fix. So the lint's suggestion is
/// wrong for this site and is suppressed deliberately.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const ResponsesWriter: ResponsesWriter = ResponsesWriter {
    sequence: AtomicU64::new(0),
    response_id: std::sync::Mutex::new(None),
    created_at: std::sync::Mutex::new(None),
    model: std::sync::Mutex::new(None),
    open_tool_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    open_text_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    item_ids: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    tool_calls: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    text_accum: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    output_items: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    open_reasoning_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    reasoning_accum: std::sync::Mutex::new(std::collections::BTreeMap::new()),
};

impl Clone for ResponsesWriter {
    fn clone(&self) -> Self {
        // Preserve the current counter value on clone so a `Protocol::clone` mid-stream keeps the
        // same `sequence_number` position rather than resetting to 0. The open-tool-index set is
        // likewise carried across the clone so a mid-stream `Protocol::clone` keeps the in-flight
        // function-call lifecycle correlation; a poisoned lock degrades to an empty set rather than
        // panicking on the request path.
        ResponsesWriter {
            sequence: AtomicU64::new(self.sequence.load(Ordering::Relaxed)),
            response_id: std::sync::Mutex::new(
                self.response_id.lock().map(|id| id.clone()).unwrap_or(None),
            ),
            // Carry the captured `created_at` across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal events replay the SAME timestamp; a poisoned lock degrades to None
            // (terminal arm then falls back to `now_unix_secs`).
            created_at: std::sync::Mutex::new(self.created_at.lock().map(|c| *c).unwrap_or(None)),
            // Carry the captured `model` across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal events replay the SAME model; a poisoned lock degrades to None
            // (terminal arm then falls back to DEFAULT_MODEL).
            model: std::sync::Mutex::new(self.model.lock().map(|m| m.clone()).unwrap_or(None)),
            open_tool_indices: std::sync::Mutex::new(
                self.open_tool_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            open_text_indices: std::sync::Mutex::new(
                self.open_text_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            // Carry the minted `item_id` cache across a mid-stream `Protocol::clone` so the cloned
            // writer keeps emitting the SAME opaque id for an already-opened item's remaining
            // lifecycle frames; a poisoned lock degrades to an empty cache (later refs re-mint).
            item_ids: std::sync::Mutex::new(
                self.item_ids.lock().map(|m| m.clone()).unwrap_or_default(),
            ),
            // Carry the in-flight function-call field accumulator across a mid-stream
            // `Protocol::clone` so the cloned writer's `output_item.done` still emits the complete
            // finalized item (call_id/name/accumulated arguments); a poisoned lock degrades to an
            // empty map (the done then omits the accumulated fields).
            tool_calls: std::sync::Mutex::new(
                self.tool_calls
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
            // Carry the in-flight text accumulator across a mid-stream `Protocol::clone` so the
            // cloned writer's terminal `output` still assembles the full streamed text; a poisoned
            // lock degrades to an empty map.
            text_accum: std::sync::Mutex::new(
                self.text_accum
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
            // Carry the finalized-output buffer across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal event still emits the assembled `output[]`; a poisoned lock degrades
            // to an empty map (terminal `output` then falls back to `[]`).
            output_items: std::sync::Mutex::new(
                self.output_items
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
            // Carry the in-flight reasoning open-set and text accumulator across a mid-stream
            // `Protocol::clone` so the cloned writer's reasoning `output_item.done` still emits the
            // assembled reasoning item; poisoned locks degrade to empty.
            open_reasoning_indices: std::sync::Mutex::new(
                self.open_reasoning_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            reasoning_accum: std::sync::Mutex::new(
                self.reasoning_accum
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl ResponsesWriter {
    /// Reset the per-stream `sequence_number` counter to 0. Called when the stream's opening
    /// `response.created` event is written so every stream's sequence starts from 0. The reader
    /// gates `MessageStart` on `state.started`, so exactly one reset happens per stream. The
    /// open-tool-index set is also cleared so a reused/cloned writer does not carry a stale
    /// function-call index into a fresh stream.
    fn reset_sequence_number(&self) {
        self.sequence.store(0, Ordering::Relaxed);
        if let Ok(mut set) = self.open_tool_indices.lock() {
            set.clear();
        }
        if let Ok(mut set) = self.open_text_indices.lock() {
            set.clear();
        }
        // Clear the per-stream `item_id` cache so a reused/cloned writer mints fresh opaque ids for
        // the new stream rather than replaying a previous stream's item ids.
        if let Ok(mut map) = self.item_ids.lock() {
            map.clear();
        }
        // Clear the per-stream function-call field accumulator so a reused/cloned writer does not
        // carry a previous stream's call_id/name/arguments into a new stream's `output_item.done`.
        if let Ok(mut map) = self.tool_calls.lock() {
            map.clear();
        }
        // Clear the per-stream text accumulator and the finalized-output buffer so a reused/cloned
        // writer does not leak a previous stream's text/items into a new stream's terminal `output`.
        if let Ok(mut map) = self.text_accum.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.output_items.lock() {
            map.clear();
        }
        // Clear the per-stream reasoning open-set and text accumulator so a reused/cloned writer does
        // not leak a previous stream's reasoning into a new stream's output.
        if let Ok(mut set) = self.open_reasoning_indices.lock() {
            set.clear();
        }
        if let Ok(mut map) = self.reasoning_accum.lock() {
            map.clear();
        }
        // Clear the carried `response.id` alongside the sequence counter: a reused/cloned writer
        // must not leak a previous stream's id onto a new stream's terminal events. The new id is
        // stored when this stream's `MessageStart` is written.
        if let Ok(mut id) = self.response_id.lock() {
            *id = None;
        }
        // Clear the carried `created_at` alongside the id: a reused/cloned writer must not leak a
        // previous stream's creation timestamp onto a new stream's terminal events. The new value
        // is stored when this stream's `MessageStart` is written.
        if let Ok(mut created) = self.created_at.lock() {
            *created = None;
        }
        // Clear the carried `model` alongside the id/created_at: a reused/cloned writer must not
        // leak a previous stream's model onto a new stream's terminal events. The new value is
        // stored when this stream's `MessageStart` is written.
        if let Ok(mut model) = self.model.lock() {
            *model = None;
        }
    }

    /// Store the per-stream `response.id` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then synthesizes a fresh id)
    /// rather than panicking on the request path.
    fn set_response_id(&self, id: &str) {
        if let Ok(mut slot) = self.response_id.lock() {
            *slot = Some(id.to_string());
        }
    }

    /// Return the per-stream `response.id` captured on `MessageStart`, or `None` if it was never
    /// set (a malformed stream whose terminal event preceded `MessageStart`, or a poisoned lock).
    /// The caller falls back to synthesizing a fresh id in that case.
    fn carried_response_id(&self) -> Option<String> {
        self.response_id.lock().ok().and_then(|id| id.clone())
    }

    /// Store the per-stream `created_at` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then falls back to
    /// `now_unix_secs`) rather than panicking on the request path.
    fn set_created_at(&self, created_at: u64) {
        if let Ok(mut slot) = self.created_at.lock() {
            *slot = Some(created_at);
        }
    }

    /// Return the per-stream `created_at` captured on `MessageStart`, falling back to the current
    /// unix time if it was never set (a malformed stream whose terminal event preceded
    /// `MessageStart`, or a poisoned lock). Replaying the captured value keeps every event's
    /// `created_at` identical, matching a native Responses stream.
    fn carried_created_at(&self) -> u64 {
        self.created_at
            .lock()
            .ok()
            .and_then(|c| *c)
            .unwrap_or_else(now_unix_secs)
    }

    /// Store the per-stream `model` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then falls back to
    /// `DEFAULT_MODEL`) rather than panicking on the request path.
    fn set_model(&self, model: &str) {
        if let Ok(mut slot) = self.model.lock() {
            *slot = Some(model.to_string());
        }
    }

    /// Return the per-stream `model` captured on `MessageStart`, falling back to `DEFAULT_MODEL` if
    /// it was never set (a malformed stream whose terminal event preceded `MessageStart`, or a
    /// poisoned lock). Replaying the captured value keeps every event's `model` identical and
    /// non-null, matching a native Responses stream and the SDK's required-field contract.
    fn carried_model(&self) -> String {
        self.model
            .lock()
            .ok()
            .and_then(|m| m.clone())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string())
    }

    /// Return the next `sequence_number` for this stream and advance the counter. The first call
    /// after a [`Self::reset_sequence_number`] returns 0, the next 1, and so on — matching the
    /// native monotonic-from-0 contract.
    fn next_sequence_number(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    /// Record that a function-call `output_item.added` was emitted at `index`, so the matching
    /// `BlockStop` knows to emit `output_item.done` for it. Lock poisoning degrades to a no-op
    /// rather than panicking on the request path.
    ///
    /// Applies the same cardinality discipline as `open_text_item`: a `contains` guard makes the
    /// insert idempotent (a re-marked index does not grow the set), and a `MAX_OPEN_TOOLS` cap
    /// bounds per-stream memory so a pathological backend streaming an unbounded run of distinct
    /// function-call indices cannot grow `open_tool_indices` without limit (resource exhaustion).
    fn mark_tool_open(&self, index: usize) {
        if let Ok(mut set) = self.open_tool_indices.lock() {
            if set.contains(&index) {
                return;
            }
            if set.len() >= MAX_OPEN_TOOLS {
                return;
            }
            set.insert(index);
        }
    }

    /// Return true and forget `index` if it was a previously-opened function-call item; false if no
    /// function-call item was opened at `index` (e.g. a text block, whose `BlockStop` must NOT emit
    /// `output_item.done`). Lock poisoning degrades to `false` (suppress the `done`) rather than
    /// panicking on the request path.
    fn take_tool_open(&self, index: usize) -> bool {
        self.open_tool_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Record the `call_id`/`name` for a function-call item opened at `index`, captured from the
    /// `BlockStart`'s `IrBlockMeta::ToolUse`, so the matching `output_item.done` can emit the fully
    /// finalized item. Lock poisoning degrades to a no-op (the `done` then omits these fields)
    /// rather than panicking on the request path.
    fn record_tool_meta(&self, index: usize, call_id: &str, name: &str) {
        if let Ok(mut map) = self.tool_calls.lock() {
            let entry = map.entry(index).or_default();
            entry.call_id = call_id.to_string();
            entry.name = name.to_string();
        }
    }

    /// Append a streamed `arguments` fragment for the function-call item at `index`. Native
    /// `response.output_item.done` carries the COMPLETE accumulated arguments string, so the writer
    /// concatenates the `InputJsonDelta` fragments here. Lock poisoning degrades to a no-op.
    fn append_tool_arguments(&self, index: usize, fragment: &str) {
        if let Ok(mut map) = self.tool_calls.lock() {
            map.entry(index).or_default().arguments.push_str(fragment);
        }
    }

    /// Remove and return the accumulated function-call fields for `index` (call_id, name, fully
    /// accumulated arguments) so the matching `output_item.done` emits the finalized item. Returns
    /// `None` if nothing was accumulated (e.g. a poisoned lock); the caller then emits the `done`
    /// without the accumulated fields rather than panicking on the request path.
    fn take_tool_accum(&self, index: usize) -> Option<ToolCallAccum> {
        self.tool_calls
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&index))
    }

    /// Append a streamed text fragment for the message item at `index`. The native terminal
    /// `response.output` carries the COMPLETE assembled text per message item, so the writer
    /// concatenates the `TextDelta` fragments here. Lock poisoning degrades to a no-op (the terminal
    /// item then carries empty text) rather than panicking on the request path.
    fn append_text(&self, index: usize, fragment: &str) {
        if let Ok(mut map) = self.text_accum.lock() {
            map.entry(index).or_default().push_str(fragment);
        }
    }

    /// Remove and return the accumulated text for the message item at `index`. Returns an empty
    /// string if nothing was accumulated (a text block with no deltas, or a poisoned lock).
    fn take_text_accum(&self, index: usize) -> String {
        self.text_accum
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&index))
            .unwrap_or_default()
    }

    /// Record a FINALIZED `output[]` item at `index`, captured as the matching `BlockStop`
    /// assembles it, so the terminal `response.completed`/`response.incomplete` event can emit the
    /// fully assembled `output` array (keyed by index for stable order). Lock poisoning degrades to
    /// a no-op (that item is omitted from the terminal `output`) rather than panicking.
    fn record_output_item(&self, index: usize, item: serde_json::Value) {
        if let Ok(mut map) = self.output_items.lock() {
            map.insert(index, item);
        }
    }

    /// Drain the finalized `output[]` items into an index-ordered array for the terminal event.
    /// `BTreeMap` iteration is key-ordered, so the items come out in `output_index` order, matching
    /// the order a native /v1/responses stream assembled them. A poisoned lock degrades to an empty
    /// array (the prior `[]` behavior) rather than panicking on the request path.
    fn drain_output_items(&self) -> Vec<serde_json::Value> {
        self.output_items
            .lock()
            .map(|mut map| std::mem::take(&mut *map).into_values().collect())
            .unwrap_or_default()
    }

    /// Mark a TEXT message item open at `index` IF it is not already open and there is room under
    /// the cardinality cap, returning true when this call performed the open (so the caller emits
    /// the opening `output_item.added`/`content_part.added` frames exactly once). Returns false if
    /// the index was already open (a subsequent text delta — no re-open) or the cap is reached
    /// (skip the frames; bounds per-stream memory against a pathological backend). Lock poisoning
    /// degrades to false. Mirrors the cardinality discipline of the reader's `open_tools` cap.
    fn open_text_item(&self, index: usize) -> bool {
        self.open_text_indices
            .lock()
            .map(|mut set| {
                if set.contains(&index) {
                    return false;
                }
                if set.len() >= MAX_OPEN_TOOLS {
                    return false;
                }
                set.insert(index);
                true
            })
            .unwrap_or(false)
    }

    /// Return true and forget `index` if a TEXT message item was open at it (so the matching
    /// `BlockStop` emits the text terminal frames for THIS index only). Returns false for a
    /// non-text index. Lock poisoning degrades to false.
    fn take_text_open(&self, index: usize) -> bool {
        self.open_text_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Mark a REASONING item open at `index` (H1) IF not already open and under the cardinality cap,
    /// returning true when this call performed the open (so the caller emits the `output_item.added`
    /// typed "reasoning" exactly once). Mirrors `open_text_item`'s discipline. Lock poisoning → false.
    fn open_reasoning_item(&self, index: usize) -> bool {
        self.open_reasoning_indices
            .lock()
            .map(|mut set| {
                if set.contains(&index) || set.len() >= MAX_OPEN_TOOLS {
                    return false;
                }
                set.insert(index);
                true
            })
            .unwrap_or(false)
    }

    /// Return true and forget `index` if a REASONING item was open at it (so the matching `BlockStop`
    /// emits the reasoning terminal frame for THIS index only). False for a non-reasoning index. Lock
    /// poisoning degrades to false.
    fn take_reasoning_open(&self, index: usize) -> bool {
        self.open_reasoning_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Append a streamed reasoning-text fragment for the reasoning item at `index` (H1). Lock
    /// poisoning degrades to a no-op (the terminal item then carries empty reasoning text).
    fn append_reasoning(&self, index: usize, fragment: &str) {
        if let Ok(mut map) = self.reasoning_accum.lock() {
            map.entry(index).or_default().push_str(fragment);
        }
    }

    /// Remove and return the accumulated reasoning text for the item at `index`, or an empty string
    /// if none was accumulated (a poisoned lock or a signature-only Thinking block).
    fn take_reasoning_accum(&self, index: usize) -> String {
        self.reasoning_accum
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&index))
            .unwrap_or_default()
    }

    /// Return the stream-stable opaque `item_id` for the output item identified by
    /// `(prefix, index)`, minting a fresh CSPRNG-backed token on first reference and returning the
    /// cached one thereafter. This is what keeps the `output_item.added → delta* → output_item.done`
    /// frames of a single item sharing one `item_id` (the SDK's lifecycle-correlation key) while the
    /// id itself stays opaque — no positional/sequential structure for an observer to fingerprint.
    /// A poisoned lock degrades to a freshly-minted opaque id (still structurally native, just not
    /// cached) rather than panicking on the request path.
    fn item_id_for(&self, prefix: &'static str, index: usize) -> String {
        match self.item_ids.lock() {
            Ok(mut map) => map
                .entry((prefix, index))
                .or_insert_with(|| synthesize_item_id(prefix))
                .clone(),
            Err(_) => synthesize_item_id(prefix),
        }
    }
}

impl ProtocolWriter for ResponsesWriter {
    fn upstream_path(&self) -> &str {
        "/v1/responses"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Shared warn+OMIT policy: a credential with bytes invalid for an HTTP header value is
        // dropped (with a protocol-named warn, never the key bytes) rather than emitting an empty
        // `Authorization:` tell. See `super::bearer_auth_headers`.
        super::bearer_auth_headers(VENDOR_NAME, key)
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        if !req.system.is_empty() {
            let instructions: String = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !instructions.is_empty() {
                out.insert("instructions".to_string(), serde_json::json!(instructions));
            }
        }

        let mut input_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            match msg.role {
                crate::ir::IrRole::User | crate::ir::IrRole::Assistant => {
                    let role_str = if msg.role == crate::ir::IrRole::User {
                        "user"
                    } else {
                        "assistant"
                    };

                    let mut content_arr: Vec<serde_json::Value> = Vec::new();
                    // function_call / function_call_output items are flat top-level `input`
                    // entries in the Responses API, NOT nested inside a message's `content`.
                    // Collect them separately so the enclosing assistant `message` is emitted
                    // FIRST (and only when it actually has content), with the tool items appended
                    // after it in order — matching the conversation order the assistant produced.
                    let mut tool_items: Vec<serde_json::Value> = Vec::new();
                    // Fix #6: prior-turn reasoning re-emitted as top-level `reasoning` input items,
                    // placed BEFORE the message they precede (matching how the model produced them).
                    let mut reasoning_items: Vec<serde_json::Value> = Vec::new();
                    for block in &msg.content {
                        match block {
                            crate::ir::IrBlock::Text { text, .. } => {
                                let type_str = if msg.role == crate::ir::IrRole::User {
                                    CONTENT_TYPE_INPUT_TEXT
                                } else {
                                    CONTENT_TYPE_OUTPUT_TEXT
                                };
                                content_arr.push(serde_json::json!({
                                    "type": type_str,
                                    "text": text
                                }));
                            }
                            crate::ir::IrBlock::Image { source, .. } => match source {
                                // L5: a Responses-produced vendor reference is a `file_id` — re-emit
                                // the native `input_image.file_id` form (a data URI would corrupt it).
                                crate::ir::IrImageSource::Vendor { vendor, value }
                                    if *vendor == VENDOR_NAME =>
                                {
                                    if let Some(id) = value.get("file_id").and_then(|i| i.as_str())
                                    {
                                        content_arr.push(serde_json::json!({
                                            "type": "input_image",
                                            "file_id": id
                                        }));
                                    }
                                }
                                // A foreign vendor reference (a Bedrock s3Location) has no Responses
                                // analog — drop with a warn rather than corrupt the block.
                                crate::ir::IrImageSource::Vendor { .. } => {
                                    tracing::warn!(
                                        "dropping unresolvable foreign vendor image reference on \
                                         Responses egress: no cross-vendor analog"
                                    );
                                }
                                // A URL/base64 image reconstructs the original `image_url`.
                                url_or_b64 => {
                                    if let Some(image_url) = super::image_url_from_ir(url_or_b64) {
                                        content_arr.push(serde_json::json!({
                                            "type": "input_image",
                                            "image_url": image_url
                                        }));
                                    }
                                }
                            },
                            crate::ir::IrBlock::Json(_) => {
                                // Structured-json (Bedrock tool-result content) has no Responses
                                // input-content shape; dropped here.
                            }
                            crate::ir::IrBlock::ToolUse {
                                id, name, input, ..
                            } => {
                                let args_str = crate::json::to_string(input)
                                    .unwrap_or_else(|_| "{}".to_string());
                                tool_items.push(serde_json::json!({
                                    "type": ITEM_TYPE_FUNCTION_CALL,
                                    "call_id": id,
                                    "name": name,
                                    "arguments": args_str
                                }));
                            }
                            crate::ir::IrBlock::ToolResult {
                                tool_use_id,
                                content,
                                ..
                            } => {
                                // Concatenate adjacent text blocks WITHOUT a separator: a space
                                // between fragments corrupts base64 / split JSON payloads.
                                // Mirrors `openai_chat.rs::write_request`'s tool_result concat fix.
                                let output_text = content
                                    .iter()
                                    .filter_map(|b| match b {
                                        crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                        // A non-Text ToolResult block is a Bedrock json-tool-result
                                        // sentinel with no Responses analog. Drop WITH a warn
                                        // (drop-with-warn convention) instead of vanishing silently.
                                        other => {
                                            if super::is_json_tool_result_block(other) {
                                                tracing::warn!(
                                                    "dropping structured json tool-result block on \
                                                     Responses egress: a Bedrock `{{\"json\":...}}` \
                                                     tool-result has no cross-protocol analog and is \
                                                     NOT emitted"
                                                );
                                            }
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .concat();

                                tool_items.push(serde_json::json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": output_text
                                }));
                            }
                            // Fix #6: a prior-turn Thinking block re-emits as a top-level Responses
                            // `reasoning` INPUT item (a sibling of the message, NOT a content block),
                            // so a Responses->Responses round-trip preserves reasoning and a
                            // reasoning block decoded from another protocol survives onto Responses
                            // egress. Mirrors the `write_response` reasoning item shape: a REDACTED
                            // reasoning block holds opaque encrypted bytes with no plaintext analog
                            // on the Responses surface, so it is dropped rather than leaked.
                            crate::ir::IrBlock::Thinking {
                                text,
                                signature,
                                redacted,
                                ..
                            } if !*redacted => {
                                let emit_sig = signature.as_deref();
                                // A wholly-empty reasoning block (no text, no signature) emits no item.
                                if !text.is_empty() || emit_sig.is_some() {
                                    let mut item = serde_json::Map::new();
                                    item.insert(
                                        "type".to_string(),
                                        serde_json::json!(ITEM_TYPE_REASONING),
                                    );
                                    item.insert(
                                        "id".to_string(),
                                        serde_json::json!(synthesize_item_id(ITEM_ID_PREFIX_RS)),
                                    );
                                    item.insert(
                                        "summary".to_string(),
                                        serde_json::Value::Array(Vec::new()),
                                    );
                                    item.insert(
                                        "content".to_string(),
                                        serde_json::json!([
                                            { "type": CONTENT_TYPE_REASONING_TEXT, "text": text }
                                        ]),
                                    );
                                    if let Some(sig) = emit_sig {
                                        item.insert(
                                            "encrypted_content".to_string(),
                                            serde_json::json!(sig),
                                        );
                                    }
                                    reasoning_items.push(serde_json::Value::Object(item));
                                }
                            }
                            // A REDACTED reasoning block (opaque encrypted bytes, no plaintext
                            // analog on Responses) is dropped rather than leaked as `reasoning_text`.
                            crate::ir::IrBlock::Thinking { .. } => {}
                        }
                    }

                    // Reasoning items come BEFORE the message they precede.
                    input_arr.extend(reasoning_items);

                    // Emit the assistant/user `message` wrapper only when it carries content. A
                    // turn that is purely a tool call must NOT produce a spurious
                    // `{role, content: []}` item — the Responses API rejects empty-content
                    // message items.
                    if !content_arr.is_empty() {
                        let mut msg_obj = serde_json::Map::new();
                        msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                        msg_obj
                            .insert("content".to_string(), serde_json::Value::Array(content_arr));
                        input_arr.push(serde_json::Value::Object(msg_obj));
                    }
                    // Then the flat tool items, in order, AFTER the message they belong to.
                    input_arr.extend(tool_items);
                }

                crate::ir::IrRole::Tool => {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } = block
                        {
                            // Concatenate adjacent text blocks WITHOUT a separator: a space
                            // between fragments corrupts base64 / split JSON payloads.
                            // Mirrors `openai_chat.rs::write_request`'s tool_result concat fix.
                            let output_text = content
                                .iter()
                                .filter_map(|b| match b {
                                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                    // A non-Text ToolResult block is a Bedrock json-tool-result
                                    // sentinel with no Responses analog. Drop WITH a warn
                                    // (drop-with-warn convention) instead of vanishing silently.
                                    other => {
                                        if super::is_json_tool_result_block(other) {
                                            tracing::warn!(
                                                "dropping structured json tool-result block on \
                                                 Responses egress: a Bedrock `{{\"json\":...}}` \
                                                 tool-result has no cross-protocol analog and is NOT \
                                                 emitted"
                                            );
                                        }
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .concat();

                            input_arr.push(serde_json::json!({
                                "type": "function_call_output",
                                "call_id": tool_use_id,
                                "output": output_text
                            }));
                        }
                    }
                }

                crate::ir::IrRole::System => {}
            }
        }

        if !input_arr.is_empty() {
            out.insert("input".to_string(), serde_json::Value::Array(input_arr));
        }

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                tool_obj.insert("parameters".to_string(), params);

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Emit `tool_choice` (PF-H1) in the Responses native shape when present so a forced/targeted
        // directive translated from another protocol does not silently degrade to `auto`.
        if let Some(tc) = &req.tool_choice {
            out.insert("tool_choice".to_string(), write_responses_tool_choice(tc));
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert(
                "max_output_tokens".to_string(),
                serde_json::json!(max_tokens),
            );
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling control: the Responses API supports `top_p` (but no top_k / stop), so
        // only top_p is emitted. A cross-protocol source's top_k/stop have no Responses target and
        // are dropped (documented in the reader).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        // LOW: the Responses create API models no `top_k` (only `top_p`). A cross-protocol source's
        // `top_k` has no Responses target. Rather than silently dropping it, emit a `warn!` so the
        // lossy-by-target omission is observable in logs (mirrors the `stop`-drop warn below and the
        // anthropic/bedrock writers' drop-with-warn contract). Nothing is written to `out`.
        if req.top_k.is_some() {
            tracing::warn!(
                "responses writer: the /v1/responses API models no `top_k` parameter; \
                 dropping top_k (lossy-by-target)"
            );
        }

        // SAMPLING (Phase 0): the Responses create API does NOT model `frequency_penalty`,
        // `presence_penalty`, `seed`, or `n` (verified against the official openai-python
        // `ResponseCreateParamsBase`: only `temperature`/`top_p`/`top_logprobs`/`text` are present).
        // They are lossy-by-target on this surface, so they are intentionally NOT emitted — emitting an
        // unsupported param would 400 a real `/v1/responses` call. A cross-protocol source that carried
        // them simply loses them here (a target-capability omission, not a leak).

        // M5 STOP: the Responses create API has NO `stop`/`stop_sequences` param (same verification as
        // sampling above — no stop field exists on `ResponseCreateParamsBase`). So stop sequences
        // cannot be expressed on this surface. Rather than silently dropping them, emit a `warn!` so
        // the lossy-by-target omission is observable in logs (mirrors the anthropic/bedrock writers'
        // drop-with-warn contract). Nothing is written to `out`.
        if !req.stop.is_empty() {
            tracing::warn!(
                stop_count = req.stop.len(),
                "responses writer: the /v1/responses API models no `stop` parameter; \
                 dropping {} stop sequence(s) (lossy-by-target)",
                req.stop.len()
            );
        }

        // M1 response_format → Responses `text.format`. The Responses surface carries structured-output
        // config under `text.format` (flat json_schema shape), NOT a top-level `response_format`. Build
        // the `format` value from the canonical IR shape and MERGE it into any `text` object already
        // forwarded via `extra` (e.g. one carrying `verbosity`), so a request that pairs a structured
        // output with another `text` knob keeps both. `extra` is applied FIRST (below) so this merge
        // sees the forwarded remainder; then this overwrites `text` with the merged object.
        if let Some(rf) = &req.response_format {
            let format = write_text_format(rf);
            // Start from any `text` object forwarded through extra (the format-stripped remainder the
            // reader preserved), so non-`format` sub-keys like `verbosity` survive alongside `format`.
            let mut text_obj = req
                .extra
                .get("text")
                .and_then(|t| t.as_object())
                .cloned()
                .unwrap_or_default();
            text_obj.insert("format".to_string(), format);
            out.insert("text".to_string(), serde_json::Value::Object(text_obj));
            // The extra-forwarding loop below SKIPS `text` when `response_format` is Some (see its
            // guard), so the bare extra `text` cannot clobber this merged object back to format-less.
        }

        // `stream` is a modeled key (excluded from `extra`), so it must be emitted explicitly or it
        // is silently dropped — a `stream: true` request would otherwise be answered non-streaming,
        // stalling the SSE translation loop. Mirrors the OpenAI writer.
        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // The reasoning carry in the Responses spelling: `reasoning: {effort}`. A numeric budget
        // (Anthropic/Gemini source) is bucketized through the effort table. Emitted from the typed
        // field only when `extra` does not carry a verbatim native `reasoning` object (the extra
        // overlay below would forward the original, and must win: it can carry `summary` too).
        if let Some(ask) = req.reasoning {
            if !req.extra.contains_key("reasoning") {
                let table = req
                    .reasoning_budgets
                    .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
                out.insert(
                    "reasoning".to_string(),
                    serde_json::json!({"effort": ask.to_effort(table).as_openai_reasoning_effort()}),
                );
            }
        }

        for (key, value) in &req.extra {
            // `text` from extra carries only the non-`format` remainder (verbosity, etc.). When the IR
            // carried a `response_format`, the merged `text` (remainder + format) was already inserted
            // above; do NOT let the bare extra `text` clobber it back to format-less. When the IR
            // carried NO response_format, fall through and forward the extra `text` verbatim.
            if key == "text" && req.response_format.is_some() {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        // The stream's opening event resets the per-stream `sequence_number` counter so each stream's
        // sequence starts at 0. Every event this writer emits then carries a top-level
        // `sequence_number` injected just before return (see the closing `map` below). The reader
        // gates `MessageStart` on `state.started`, so exactly one reset happens per stream.
        if matches!(ev, IrStreamEvent::MessageStart { .. }) {
            self.reset_sequence_number();
        }

        let emitted: Option<(String, serde_json::Value)> = match ev {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                // The official OpenAI Responses SDK reads `response.id`/`created_at`/`model` from the
                // opening `response.created` event to construct its Response object; a stub omitting
                // them yields null identity fields and breaks event correlation. Forward the captured
                // identity when present (same-protocol passthrough), otherwise synthesize a
                // protocol-correct `resp_` id and the current unix time (cross-protocol, where
                // `translate_event` strips these to None) so the event stays SDK-valid.
                let mut resp_obj = serde_json::Map::new();
                let id = id.clone().unwrap_or_else(synthesize_response_id);
                // Carry this stream's id forward so the terminal events (and any failure) replay
                // the SAME `response.id` — a native stream never changes its id mid-flight.
                self.set_response_id(&id);
                let created_at = created.unwrap_or_else(now_unix_secs);
                // Carry this stream's `created_at` forward so the terminal events (and any failure)
                // replay the SAME timestamp — a native stream's `created_at` is constant across
                // every event.
                self.set_created_at(created_at);
                resp_obj.insert("id".to_string(), serde_json::json!(id));
                resp_obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
                resp_obj.insert("created_at".to_string(), serde_json::json!(created_at));
                resp_obj.insert("status".to_string(), serde_json::json!(STATUS_IN_PROGRESS));
                // `Response.model` is a REQUIRED non-nullable string in the official SDK; emit it
                // unconditionally with the DEFAULT_MODEL fallback when the IR carries none (a
                // cross-protocol stream where `translate_event` strips the model to None) rather
                // than omitting the key — omission breaks strict decoders and is a proxy tell.
                let model_name = model.as_deref().unwrap_or(DEFAULT_MODEL);
                // Carry this stream's model forward so the terminal events (and any failure) replay
                // the SAME `model` — a native stream's `model` is constant across every event.
                self.set_model(model_name);
                resp_obj.insert("model".to_string(), serde_json::json!(model_name));
                // The native `response.created` carries the FULL Response skeleton, not just its
                // identity: an official SDK constructs a `Response` object from this event and reads
                // `usage`/`output`/`error` unconditionally. At stream start there are no tokens yet
                // and no failure, so emit `usage: null`, an empty `output` array, and `error: null`
                // — present-but-empty, NOT omitted. Omitting `usage` left the SDK's `Response.usage`
                // unpopulated (or crashed strict decoders) on the opening chunk.
                resp_obj.insert("output".to_string(), serde_json::json!([]));
                resp_obj.insert("error".to_string(), serde_json::Value::Null);
                resp_obj.insert("usage".to_string(), serde_json::Value::Null);
                Some((
                    EVT_RESPONSE_CREATED.to_string(),
                    serde_json::json!({ "type": EVT_RESPONSE_CREATED, "response": resp_obj }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // A native /v1/responses stream brackets a text part inside a `message` output
                    // item: `output_item.added(message)` opens it, the `output_text.delta`s carry
                    // the body, and `output_item.done(message)` closes it. The official SDK builds
                    // `response.output[]` from the added/done pair, so without an enclosing item the
                    // assembled Response has an empty output array even though deltas streamed.
                    // Previously the Text BlockStart returned None, leaving the deltas orphaned.
                    //
                    // The `ProtocolWriter` trait emits at most ONE wire frame per IR event, so the
                    // intermediate `content_part.added` sub-frame (which would need a second frame
                    // for this single BlockStart) cannot be produced here; the message item's
                    // `output_item.added`/`.done` pair is the load-bearing lifecycle the SDK reads
                    // to materialize the assistant message, and the deltas already carry
                    // `content_index: 0`. Track the open text index (capped) so the matching
                    // BlockStop emits `output_item.done` for THIS index only.
                    if !self.open_text_item(*index) {
                        return None;
                    }
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_MSG, *index);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_MESSAGE,
                                "id": item_id,
                                "role": "assistant",
                                "status": STATUS_IN_PROGRESS,
                                "content": []
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // `item_id` (a stable per-output-item id, `fc_…` for a function-call item) is
                    // carried on the native `output_item.added`/`.done` pair so a client correlates the
                    // item's lifecycle. Synthesize it deterministically from the output index so the
                    // matching `.done` (which sees only the index) reconstructs the same id.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_FC, *index);
                    // Record the open function-call index so the matching `BlockStop` emits
                    // `output_item.done` for THIS index only — a text block's BlockStop (whose
                    // BlockStart produced no `output_item.added`) must emit no `done`.
                    self.mark_tool_open(*index);
                    // Capture call_id/name now so the matching `output_item.done` can emit the
                    // fully finalized item (native `done` carries call_id/name/arguments; the IR
                    // BlockStop carries only the index).
                    self.record_tool_meta(*index, id, name);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_FUNCTION_CALL,
                                "id": item_id,
                                "call_id": id,
                                "name": name
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::Thinking => {
                    // H1 REASONING (stream): open a native Responses `reasoning` output item. The IR
                    // Thinking BlockStart carries only the index; emit `output_item.added` typed
                    // "reasoning" with a stable `rs_…` item_id (so the matching `.done` reconstructs
                    // it), tracking the open index so BlockStop closes it as a reasoning item. The
                    // prior `None` DROPPED the reasoning lifecycle entirely.
                    if !self.open_reasoning_item(*index) {
                        return None;
                    }
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_RS, *index);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_REASONING,
                                "id": item_id,
                                "summary": [],
                                "content": []
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) if !text.is_empty() => {
                    // Native `output_text.delta` carries `item_id` (the enclosing message item) and
                    // `content_index` (the index of the text part within that item). The IR delta
                    // carries only the output index; synthesize the message `item_id` deterministically
                    // from it (matching the `msg_…` part), and emit `content_index: 0` — the single
                    // text content part of the item.
                    //
                    // Accumulate the fragment so the matching `BlockStop` can assemble the message
                    // item with its COMPLETE `output_text` for the terminal `response.output` array.
                    self.append_text(*index, text);
                    Some((
                        EVT_OUTPUT_TEXT_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_TEXT_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_MSG, *index),
                            "content_index": 0,
                            "delta": text
                        }),
                    ))
                }
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    // Accumulate the arguments fragment so the matching `output_item.done` emits the
                    // COMPLETE arguments string the native event (and the SDK's `event.item.arguments`)
                    // carries.
                    self.append_tool_arguments(*index, json_str);
                    Some((
                        EVT_FUNCTION_CALL_ARGS_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_FUNCTION_CALL_ARGS_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_FC, *index),
                            "delta": json_str
                        }),
                    ))
                }
                &crate::ir::IrDelta::TextDelta(_) => None,
                crate::ir::IrDelta::ThinkingDelta(text) if !text.is_empty() => {
                    // H1 REASONING (stream): emit the native `response.reasoning_text.delta` for the
                    // reasoning item at this index, accumulating the fragment so the matching
                    // BlockStop assembles the complete reasoning item. The prior `None` DROPPED the
                    // streamed chain-of-thought. `content_index: 0` — the single reasoning content
                    // part of the item.
                    self.append_reasoning(*index, text);
                    Some((
                        EVT_REASONING_TEXT_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_REASONING_TEXT_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_RS, *index),
                            "content_index": 0,
                            "delta": text
                        }),
                    ))
                }
                // An empty ThinkingDelta carries no content (drop it), and Responses has no streaming
                // analog for a thinking `SignatureDelta` (the signature rides on the item's
                // `encrypted_content`, not a stream delta) — so both emit no frame.
                &crate::ir::IrDelta::ThinkingDelta(_)
                | crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_) => None,
                // L2-5: the Responses streaming surface has no confirmable citation/annotation
                // delta shape to map this onto, so suppress rather than synthesize one (the
                // citation stays in the IR and is re-emitted by protocols that model streaming
                // citations). No panic on this otherwise-unhandled variant.
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Responses streaming logprobs (inside `output_text` events) are out of the 1.2
                // OpenAI<->Gemini scope; dropped rather than emitted in a non-native shape.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer output index, not the block kind. A
                // native Responses stream emits `response.output_item.done` ONLY for an item it
                // previously `output_item.added`, and the `.done` type must match the `.added` type.
                // This writer opens an `output_item.added` for both message (text) and function-call
                // items, so each must close with a correctly-typed `output_item.done`. Emitting
                // `output_item.done` with a hardcoded type — as a prior revision did, always typing
                // it `type:"function_call"` — mis-typed every text item's close: an unmatched lifecycle
                // event (a `done` with no prior `added`) AND a text response mis-typed as a
                // function call, both of which break a typed Responses SDK and are deterministic
                // distinguishability tells.
                //
                // So consult the per-stream open sets: a function-call index closes with an
                // `output_item.done` typed "function_call"; a text index (opened by the Text
                // BlockStart with `output_item.added` typed "message") closes with an
                // `output_item.done` typed "message"; any other (never-opened) index emits NOTHING.
                //
                // NOTE: this arm must YIELD its `Option` as the match value (never `return` it), so
                // the closing `emitted.map(...)` tail injects the top-level `sequence_number` every
                // native Responses event carries — an early `return Some(..)` would skip it.
                if self.take_reasoning_open(*index) {
                    // H1 REASONING (stream): close the reasoning item opened by the Thinking
                    // BlockStart. Emit `output_item.done` typed "reasoning" with the SAME `rs_…`
                    // item_id and the assembled reasoning text under a `content[]` `reasoning_text`
                    // part. Record the finalized item so the terminal `response.completed` emits it in
                    // `output[]`. The prior writer dropped reasoning entirely, so a reasoning stream
                    // reassembled to an OpenAI/Anthropic client lost the chain-of-thought.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_RS, *index);
                    let text = self.take_reasoning_accum(*index);
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_REASONING,
                        "id": item_id,
                        "summary": [],
                        "content": [
                            { "type": CONTENT_TYPE_REASONING_TEXT, "text": text }
                        ]
                    });
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else if self.take_tool_open(*index) {
                    // Native `response.output_item.done` carries the SAME stable `item_id` as the
                    // matching `output_item.added` (so a client correlates the `added → done`
                    // lifecycle) plus the FULLY finalized `item` object: a typed SDK reads
                    // `event.item.call_id`/`.name`/`.arguments` off the done event to reconstruct the
                    // tool invocation. Emit all three from the per-stream accumulator (call_id/name
                    // captured on `output_item.added`, arguments concatenated from the delta frames).
                    // The function-call `output_item.added` used `item_id_for("fc", index)`, so the
                    // cached id reconstructs the matching pair here. A poisoned-lock-empty accumulator
                    // degrades to empty-string fields rather than panicking.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_FC, *index);
                    let accum = self.take_tool_accum(*index).unwrap_or_default();
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_FUNCTION_CALL,
                        "id": item_id,
                        "call_id": accum.call_id,
                        "name": accum.name,
                        "arguments": accum.arguments,
                    });
                    // Record the finalized function-call item so the terminal `response.completed`/
                    // `response.incomplete` event emits the fully assembled `output[]` array (the
                    // SDK reads `event.response.output` to materialize `Response.output`).
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else if self.take_text_open(*index) {
                    // Close the message item opened by the Text BlockStart. The same cached `msg_…`
                    // id (also carried on every `output_text.delta`) reconstructs the matching
                    // `added → done` pair the SDK uses to finalize `response.output[]`. The native
                    // `output_item.done` for a message item carries the assembled `output_text`
                    // content part with the COMPLETE text the deltas delivered (the SDK accumulates
                    // `Response.output_text` from it), so emit the accumulated text rather than an
                    // empty content array.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_MSG, *index);
                    let text = self.take_text_accum(*index);
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_MESSAGE,
                        "id": item_id,
                        "role": "assistant",
                        "status": STATUS_COMPLETED,
                        "content": [
                            { "type": CONTENT_TYPE_OUTPUT_TEXT, "text": text, "annotations": [] }
                        ]
                    });
                    // Record the finalized message item so the terminal event emits the fully
                    // assembled `output[]` array.
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else {
                    // Nothing open at this index (e.g. a repeated BlockStop, or an index whose
                    // BlockStart was suppressed by the cardinality cap): emit no frame.
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                // Map IR stop reasons to Responses statuses. An unknown/None reason defaults to
                // `completed` (the safe choice) rather than `failed`: a future IR reason (e.g. a
                // new `refusal`) that did NOT explicitly signal an error must not be misclassified
                // as a failed response, which would trigger client-side error handling for a
                // successful turn. Genuine failures arrive via IrStreamEvent::Error, not here.
                let status = stop_reason
                    .map(write_responses_status)
                    .unwrap_or(STATUS_COMPLETED);

                let mut resp_obj = serde_json::Map::new();
                // The native `response.completed`/`response.incomplete` terminal event ALWAYS
                // carries `id` (a `resp_…` string) and `created_at` (unix seconds) in its inner
                // `response` object; the official Python/Node SDK reads `event.response.id` on the
                // terminal event to finalize the `Response`, and strict typed decoders raise on a
                // missing `id`/`created_at`. A real OpenAI stream never sends a terminal event
                // without an `id`, so omitting it is also a distinguishability tell. The IR
                // `MessageDelta` carries no identity, so REPLAY the id captured on this stream's
                // opening `MessageStart` (stored in `response_id`) so `response.completed`/
                // `response.incomplete` carries the SAME `id` as `response.created` — a native
                // stream never changes its id mid-flight, and the SDK reads `event.response.id` on
                // the terminal event to finalize the `Response`. Only if the cell is unexpectedly
                // empty (a malformed stream whose terminal event preceded `MessageStart`, or a
                // poisoned lock) do we fall back to synthesizing a fresh id so the event stays
                // structurally valid.
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                resp_obj.insert("id".to_string(), serde_json::json!(response_id));
                resp_obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
                // Replay the `created_at` captured on this stream's opening `MessageStart` so the
                // terminal event carries the SAME timestamp as `response.created`. The IR
                // `MessageDelta` carries no identity, so a direct `now_unix_secs()` here would emit
                // a later wall-clock value than the opening event — a detectable proxy tell. Fall
                // back to the current time only if the cell was never populated.
                resp_obj.insert(
                    "created_at".to_string(),
                    serde_json::json!(self.carried_created_at()),
                );
                resp_obj.insert("status".to_string(), serde_json::json!(status));
                // Replay the `model` captured on this stream's opening `MessageStart` so the
                // terminal event's inner `response` carries the SAME required non-nullable `model`
                // as `response.created`. The IR `MessageDelta` carries no model, and omitting it
                // fails a strict SDK decoder and is a distinguishability tell; `carried_model`
                // falls back to DEFAULT_MODEL only if the cell was never populated.
                resp_obj.insert("model".to_string(), serde_json::json!(self.carried_model()));

                if status == STATUS_INCOMPLETE {
                    let reason = stop_reason
                        .map(write_responses_incomplete_reason)
                        .unwrap_or(INCOMPLETE_REASON_OTHER);
                    let mut incomplete_details = serde_json::Map::new();
                    incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
                    resp_obj.insert(
                        "incomplete_details".to_string(),
                        serde_json::Value::Object(incomplete_details),
                    );
                }

                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but the Responses API's `input_tokens` is a TOTAL that includes the cached
                // prefix, so add `cache_read` back.
                let input_total = usage
                    .input_tokens
                    .saturating_add(usage.cache_read_input_tokens.unwrap_or(0))
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let mut usage_map = serde_json::Map::new();
                usage_map.insert("input_tokens".to_string(), serde_json::json!(input_total));
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                // H6: surface the IR read-side cache count on the streaming terminal as the
                // Responses-native `usage.input_tokens_details.cached_tokens` (only when present), so a
                // cross-protocol stream carrying a cache hit reports it to a Responses client just as
                // the non-stream body does. Omitted when absent (no `cached_tokens: 0`).
                if let Some(cached) = usage.cache_read_input_tokens {
                    usage_map.insert(
                        "input_tokens_details".to_string(),
                        serde_json::json!({ "cached_tokens": cached }),
                    );
                }
                resp_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                // The native terminal `response.completed`/`response.incomplete` event carries the
                // FULLY assembled inner `response` object: the official Python/Node SDK reads
                // `event.response.output` to finalize the assembled `Response`, and `output` is a
                // REQUIRED field a strict typed decoder raises on when absent. The writer recorded
                // each finalized item (message text parts and function-call items) into
                // `output_items` as the matching `BlockStop` fired, so drain that index-ordered
                // buffer here — a `completed` response with nonzero `usage.output_tokens` but an
                // EMPTY `output` is a shape real OpenAI never emits and breaks SDK consumers that
                // read the assembled output off the completed event. The buffer is empty (yielding
                // `[]`) only for a genuinely output-less turn or a poisoned lock. `error` is
                // likewise REQUIRED and `null` on a non-failed terminal event (a genuine failure
                // arrives via IrStreamEvent::Error → `response.failed`, never this arm).
                resp_obj.insert(
                    "output".to_string(),
                    serde_json::Value::Array(self.drain_output_items()),
                );
                resp_obj.insert("error".to_string(), serde_json::Value::Null);

                // The terminal event's NAME and inner `type` MUST agree with the inner
                // `response.status`: a native /v1/responses stream emits `response.completed` for a
                // completed response and a DISTINCT `response.incomplete` for a truncated/safety-
                // stopped one, and the official Python/Node SDKs dispatch on the event `type`
                // (`ResponseCompletedEvent` vs `ResponseIncompleteEvent`). Emitting a
                // `response.completed` envelope around an inner `status:"incomplete"` (plus
                // `incomplete_details`) is a shape impossible from real OpenAI and mislabels a
                // max_tokens-truncated or safety-stopped generation to the client. So select the
                // envelope from `status`. `status` is only ever `completed`/`incomplete` here
                // (genuine failures arrive via IrStreamEvent::Error → `response.failed`, never this
                // arm); the match is over those two with a defensive fallback to `completed` for any
                // future status string, never a `response.failed` (which would invent a failure).
                let (event_name, event_type) = match status {
                    STATUS_INCOMPLETE => (EVT_RESPONSE_INCOMPLETE, EVT_RESPONSE_INCOMPLETE),
                    STATUS_COMPLETED => (EVT_RESPONSE_COMPLETED, EVT_RESPONSE_COMPLETED),
                    _ => (EVT_RESPONSE_COMPLETED, EVT_RESPONSE_COMPLETED),
                };
                Some((
                    event_name.to_string(),
                    serde_json::json!({ "type": event_type, "response": resp_obj }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => {
                // The native OpenAI Responses `response.failed` event wraps the error inside a
                // `response` object (`{"response":{"id":...,"status":"failed","error":{...}}}`); the
                // official Python/Node streaming decoder reads `event.response` to build the failed
                // Response, NOT a top-level `error` key. Emitting `{"error":{...}}` would leave a
                // native SDK unable to locate `event.response` and it would crash or silently
                // swallow the failure. Synthesize a `resp_` id so the SDK can correlate the failed
                // response.
                //
                // The in-band `response.error` object is the Responses-native `ResponseError` shape
                // — `{"code": <non-null string enum>, "message": <str>}` — NOT the Chat-Completions
                // `{message, type, code, param}` envelope. The official Python/Node SDK decodes
                // `event.response.error` into a typed `ResponseError` whose `code` is a required
                // non-null enum (default `"server_error"`); emitting a null `code` plus an extra
                // `type`/`param` pair is an impossible-from-real-OpenAI shape and a deterministic
                // indistinguishability tell. This protocol's OWN reader confirms the field choice:
                // it reads `response.error.code` FIRST (canonical) and only falls back to `type`.
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                // `code` MUST be a valid Responses enum, never the free-form human `provider_signal`
                // (a cross-protocol / transport-abort path carries a sentence like "The response
                // stream was interrupted." there). A recognized code round-trips; otherwise it is
                // derived from the error class. `message` keeps the human text. (found: audit c2r2.)
                let code = responses_error_code(err);
                // Replay the stream's captured `response.id` so `response.failed` correlates with
                // the opening `response.created` (the SDK reads `event.response.id` on the failure
                // event); fall back to a fresh id only if the cell is empty (failure before any
                // `MessageStart`, or a poisoned lock).
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                Some((
                    EVT_RESPONSE_FAILED.to_string(),
                    serde_json::json!({
                        "type": EVT_RESPONSE_FAILED,
                        "response": {
                            "id": response_id,
                            "object": OBJ_RESPONSE,
                            // Replay the captured `created_at` so `response.failed` carries the
                            // SAME timestamp as `response.created` (a native stream never changes
                            // it mid-flight); falls back to the current time only if the failure
                            // preceded any `MessageStart`.
                            "created_at": self.carried_created_at(),
                            // Replay the captured `model` so `response.failed`'s inner `response`
                            // carries the SAME required non-nullable `model` as `response.created`;
                            // falls back to DEFAULT_MODEL only if the failure preceded any
                            // `MessageStart`.
                            "model": self.carried_model(),
                            "status": STATUS_FAILED,
                            // A native terminal event's inner `response` always carries `output`
                            // (REQUIRED by the SDK's typed `Response`); a failed response produced
                            // no assistant items, so emit a present-but-empty array — never omit it.
                            "output": [],
                            "error": {
                                "code": code,
                                "message": message,
                            }
                        }
                    }),
                ))
            }
        };

        // EVERY native `/v1/responses` SSE event carries a top-level `sequence_number` (monotonic
        // from 0 per stream). Inject it uniformly here so no writer arm can forget it and so the
        // counter advances exactly once per emitted event. Events that produce no body
        // (`MessageStop`, empty text deltas, Image `BlockStart`) do NOT consume a
        // sequence number — only events that actually go on the wire are numbered, matching the
        // native stream where the integer counts emitted events.
        emitted.map(|(event_name, mut data)| {
            if let Some(obj) = data.as_object_mut() {
                obj.insert(
                    "sequence_number".to_string(),
                    serde_json::json!(self.next_sequence_number()),
                );
            }
            (event_name, data)
        })
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Unknown/None stop reasons default to `completed` (not `failed`): a future IR reason that
        // did not explicitly signal an error must not surface as a failed response to a Responses
        // client. Only the explicitly-mapped incomplete reasons downgrade the status.
        let status = resp
            .stop_reason
            .map(write_responses_status)
            .unwrap_or(STATUS_COMPLETED);

        // Build the `output` array in IR ENCOUNTER order, emitting one native output item per block
        // exactly as the streaming writer's `drain_output_items` does. The streaming path assigns each
        // Text/ToolUse BlockStart its own `output_index` (in arrival order) and drains them in that
        // order, so a response that interleaves text and tool blocks (e.g. text → tool → text) streams
        // those items in that sequence. A prior revision collected text separately and `insert(0)`'d a
        // single coalesced message item at the FRONT of the array — that forced text ahead of any tool
        // item and broke the order for any non-text-first or interleaved content, so the non-stream
        // body disagreed with the stream a client reassembling `response.output[]` would observe.
        // Process in order with no hardcoded index: each block appends to `output_arr` where it occurs.
        let mut output_arr: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if text.is_empty() {
                        continue;
                    }
                    // Match the native message-item shape the STREAMING `output_item.done` emits: an
                    // item-level `id` (`msg_…`), a `status`, and `annotations: []` on the `output_text`
                    // content part. Omitting them is a proxy tell — a typed SDK reading `item.id` /
                    // `item.status` / `content[0].annotations` sees missing fields on the non-stream
                    // path. Each non-empty text block becomes its OWN message item at its encounter
                    // position (mirroring the per-index message items the stream emits).
                    output_arr.push(serde_json::json!({
                        "type": ITEM_TYPE_MESSAGE,
                        "id": synthesize_item_id(ITEM_ID_PREFIX_MSG),
                        "role": "assistant",
                        "status": STATUS_COMPLETED,
                        "content": [{
                            "type": CONTENT_TYPE_OUTPUT_TEXT,
                            "text": text,
                            "annotations": []
                        }]
                    }));
                }
                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    let args_str =
                        crate::json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    output_arr.push(serde_json::json!({
                        "type": ITEM_TYPE_FUNCTION_CALL,
                        // Native function_call items carry an item-level opaque `id` (`fc_…`) DISTINCT
                        // from `call_id` — the streaming `output_item.done` emits it, so the non-stream
                        // body must too or a typed SDK reading `item.id` sees a missing field (a proxy
                        // tell). The IR has no per-item id, so synthesize one of the native shape.
                        "id": synthesize_item_id(ITEM_ID_PREFIX_FC),
                        "call_id": id,
                        "name": name,
                        "arguments": args_str
                    }));
                }
                // H1 REASONING: write an IR Thinking block back as a native Responses `reasoning`
                // output item. The prior `_ => {}`-equivalent DROPPED it, so a thinking-carrying
                // response translated from Anthropic/Bedrock lost its reasoning on the Responses
                // surface. Emit the text under a `content[]` `reasoning_text` part (the full-reasoning
                // location); when the IR carries a signature, round-trip it into Responses'
                // `encrypted_content` slot (the opaque reasoning-reuse blob) so a same-protocol hop is
                // lossless. A purely-empty Thinking block emits no item.
                crate::ir::IrBlock::Thinking {
                    text,
                    signature,
                    redacted,
                    ..
                } => {
                    // A REDACTED reasoning block (Bedrock `redactedContent`) holds opaque encrypted
                    // bytes with no plaintext analog on the Responses surface — drop it entirely
                    // rather than leak the bytes as visible `reasoning_text`.
                    if *redacted {
                        continue;
                    }
                    let emit_sig = signature.as_deref();
                    // A purely-empty Thinking block (no text and no signature) emits no item.
                    if text.is_empty() && emit_sig.is_none() {
                        continue;
                    }
                    let mut item = serde_json::Map::new();
                    item.insert("type".to_string(), serde_json::json!(ITEM_TYPE_REASONING));
                    item.insert(
                        "id".to_string(),
                        serde_json::json!(synthesize_item_id(ITEM_ID_PREFIX_RS)),
                    );
                    item.insert("summary".to_string(), serde_json::Value::Array(Vec::new()));
                    item.insert(
                        "content".to_string(),
                        serde_json::json!([{ "type": CONTENT_TYPE_REASONING_TEXT, "text": text }]),
                    );
                    if let Some(sig) = emit_sig {
                        item.insert("encrypted_content".to_string(), serde_json::json!(sig));
                    }
                    output_arr.push(serde_json::Value::Object(item));
                }
                // ToolResult and Image have no representation in a Responses API `output` array
                // (output carries assistant `message`/`function_call` items only), so they are
                // intentionally dropped here. Enumerated explicitly rather than swallowed by a
                // catch-all so a future IrBlock variant forces a compile error instead of silently
                // vanishing from Responses output.
                crate::ir::IrBlock::ToolResult { .. } => {}
                crate::ir::IrBlock::Image { .. } | crate::ir::IrBlock::Json(_) => {}
            }
        }

        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but the Responses API's `input_tokens` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back.
        let input_total = resp
            .usage
            .input_tokens
            .saturating_add(resp.usage.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("input_tokens".to_string(), serde_json::json!(input_total));
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        // H6: write the IR read-side cache count back as the Responses-native
        // `usage.input_tokens_details.cached_tokens` (ONLY when present), so a cross-protocol response
        // that carried a cache hit (e.g. from a Bedrock backend) surfaces it to a Responses client.
        // Omitted entirely when the IR carries no cache-read value — a real Responses body without
        // cache hits omits the details object rather than emitting `cached_tokens: 0`.
        if let Some(cached) = resp.usage.cache_read_input_tokens {
            usage_map.insert(
                "input_tokens_details".to_string(),
                serde_json::json!({ "cached_tokens": cached }),
            );
        }

        let mut obj = serde_json::Map::new();
        // Emit the SDK-required top-level identity. Same-protocol passthrough carries the captured
        // upstream values verbatim; cross-protocol (backend supplied none) synthesizes a
        // protocol-correct `resp_` id and the current unix time so the body stays SDK-valid.
        // `created_at` is the Responses field name (the official SDK's `Response.created_at`).
        let id = resp.id.clone().unwrap_or_else(synthesize_response_id);
        let created_at = resp.created.unwrap_or_else(now_unix_secs);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
        obj.insert("created_at".to_string(), serde_json::json!(created_at));
        obj.insert("status".to_string(), serde_json::json!(status));
        // model that served the response (preserved across cross-protocol translation). The
        // official SDK types `Response.model` as a REQUIRED non-nullable string, so emit it
        // unconditionally with the DEFAULT_MODEL fallback when the IR carries none rather than
        // omitting the key — omission breaks strict decoders and is a distinguishability tell.
        obj.insert(
            "model".to_string(),
            serde_json::json!(resp.model.as_deref().unwrap_or(DEFAULT_MODEL)),
        );
        obj.insert("output".to_string(), serde_json::Value::Array(output_arr));
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
        // The official SDK types `Response.error` as a REQUIRED nullable field present on EVERY
        // Response object: `null` on success/incomplete, a populated object on failure. The
        // streaming `response.created` skeleton already emits `error: null`; the non-streaming body
        // must match. Omitting the key breaks strict SDK/Pydantic/Zod decoders that read
        // `response.error` unconditionally and is a distinguishability tell (a real non-streaming
        // `/v1/responses` body always carries `error`). A genuine upstream failure is surfaced as
        // an error envelope via `write_error`, never through this success/incomplete body, so `null`
        // is correct here.
        obj.insert("error".to_string(), serde_json::Value::Null);

        if status == STATUS_INCOMPLETE {
            let reason = resp
                .stop_reason
                .map(write_responses_incomplete_reason)
                .unwrap_or(INCOMPLETE_REASON_OTHER);
            let mut incomplete_details = serde_json::Map::new();
            incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
            obj.insert(
                "incomplete_details".to_string(),
                serde_json::Value::Object(incomplete_details),
            );
        }

        serde_json::Value::Object(obj)
    }

    /// Native OpenAI Responses error envelope. The Responses API shares the OpenAI error shape an
    /// official SDK (`openai` Python / `openai-node`) decodes into a typed `APIError`:
    /// `{"error":{"message":<msg>,"type":<type>,"code":<code|null>,"param":<param|null>}}`, served
    /// as `application/json`. `code` and `param` are always present (null here — busbar's
    /// router/auth/forward errors are not field-level validation errors). The generic `kind` is
    /// mapped to the Responses `type` vocabulary where one exists.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map busbar's generic error `kind` to the OpenAI/Responses `error.type` vocabulary. The
        // canonical Responses/OpenAI types are `invalid_request_error`, `authentication_error`,
        // `permission_error`, `not_found_error`, `rate_limit_error`, `server_error`, and
        // `insufficient_quota`. Anything already in that vocabulary (or any unrecognized caller
        // string) is passed through verbatim rather than swallowed by a catch-all, so a precise
        // upstream type is never lost.
        let error_type = match kind {
            "invalid_request" | ERR_TYPE_INVALID_REQUEST => ERR_TYPE_INVALID_REQUEST,
            "authentication" | ERR_TYPE_AUTHENTICATION | "auth" => ERR_TYPE_AUTHENTICATION,
            "permission" | ERR_TYPE_PERMISSION | "forbidden" => ERR_TYPE_PERMISSION,
            "not_found" | ERR_TYPE_NOT_FOUND => ERR_TYPE_NOT_FOUND,
            "rate_limit" | ERR_TYPE_RATE_LIMIT => ERR_TYPE_RATE_LIMIT,
            ERR_TYPE_SERVER_ERROR | "internal" | "internal_error" => ERR_TYPE_SERVER_ERROR,
            // A 503 exhaustion/timeout is reported by forward.rs as kind `"overloaded"` (an
            // Anthropic-vocabulary token). The OpenAI/Responses error vocabulary has no
            // `overloaded` type — a 5xx is `server_error` — so without this arm `other => other`
            // would leak `{"error":{"type":"overloaded",...}}` to an OpenAI-family client on every
            // exhaustion/timeout, a non-native type and a deterministic cross-protocol tell. Map the
            // overloaded/unavailable family onto the native `server_error`. Same class as the OpenAI
            // writer's 5xx bucket.
            crate::forward::KIND_OVERLOADED
            | ERR_TYPE_OVERLOADED
            | "service_unavailable"
            | "unavailable" => ERR_TYPE_SERVER_ERROR,
            // forward.rs emits these transient/upstream-failure kinds directly to every ingress
            // writer (`timeout`/`network`/`connect` from the request-error path, `5xx`/`transient`
            // from the canonical-signal mapping, `api_error` from the generic upstream-error path).
            // None is an OpenAI/Responses error type — real OpenAI reports a transient upstream
            // failure as `server_error` — so without these arms `other => other` would leak a
            // non-native `type` such as `{"error":{"type":"timeout"}}` or `{"error":{"type":"5xx"}}`
            // to a Responses-API client: a deterministic cross-protocol tell that breaks SDK
            // consumers switching on `error.type`. Mirrors openai_chat.rs's `server_error` bucket.
            crate::forward::KIND_TIMEOUT
            | "network"
            | "connect"
            | "5xx"
            | "transient"
            | crate::forward::KIND_API_ERROR => ERR_TYPE_SERVER_ERROR,
            // A context-length overflow is surfaced by forward.rs as `context_length_exceeded`; the
            // Responses vocabulary has no dedicated type for it (as openai_chat.rs also maps it), so it
            // folds into `invalid_request_error`. `bad_request` is the same client-error class.
            crate::forward::PROVIDER_CODE_CONTEXT_LENGTH | "bad_request" => {
                ERR_TYPE_INVALID_REQUEST
            }
            "billing" | ERR_TYPE_INSUFFICIENT_QUOTA => ERR_TYPE_INSUFFICIENT_QUOTA,
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "code": bearer_error_code(error_type),
                "param": serde_json::Value::Null,
            }
        })
    }

    fn egress_user_agent(&self) -> &'static str {
        // Responses API is served by the same OpenAI SDK/UA as the Chat Completions surface.
        // Pinned — see `EGRESS_UA_OPENAI` in forward.rs.
        crate::forward::EGRESS_UA_OPENAI
    }

    fn auth_failure_message(&self) -> &'static str {
        AUTH_FAILURE_MSG
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOW (lossless-by-target): the Responses create API models no `top_k`. A request carrying
    /// `top_k` must NOT emit a `top_k` field (it would 400 a real `/v1/responses` call) — it is
    /// dropped with a `warn!` (the drop-with-warn branch is exercised here). `top_p`, which the
    /// surface DOES model, still passes through.
    #[test]
    fn write_request_drops_top_k_with_warn() {
        let mk = |top_k: Option<u32>| crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            top_p: Some(0.9),
            top_k,
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

        let writer = ResponsesWriter;
        // With top_k set: the warn-drop branch runs and NO `top_k` reaches the body.
        let with = writer.write_request(&mk(Some(40)));
        assert!(
            with.get("top_k").is_none(),
            "the Responses body must NOT carry top_k (lossy-by-target): {with}"
        );
        // top_p (a modeled param) still passes through.
        assert_eq!(with.get("top_p").and_then(|v| v.as_f64()), Some(0.9));

        // Without top_k: body shape is identical w.r.t. top_k absence (sanity baseline).
        let without = writer.write_request(&mk(None));
        assert!(without.get("top_k").is_none());
    }

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "hi".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "fc_1".to_string(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({"city": "SF"}),
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "fc_1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "sunny".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("Get weather for a location".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }),
                cache_control: None,
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7),
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

        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);

        assert_eq!(
            json.get("instructions").and_then(|v| v.as_str()),
            Some("You are helpful.")
        );

        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");

        let first_item = &input[0];
        assert_eq!(
            first_item.get("role").and_then(|r| r.as_str()),
            Some("user")
        );
        let content = first_item
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content should exist");
        assert_eq!(content.len(), 1);
        assert_eq!(
            content[0].get("type"),
            Some(&serde_json::json!("input_text")) // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("hi"));

        let func_call_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call")) // golden wire-contract literal (kept bare on purpose)
            .expect("should have function_call item");
        assert_eq!(
            func_call_item.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        let args = func_call_item
            .get("arguments")
            .and_then(|a| a.as_str())
            .expect("arguments should exist");
        assert!(args.contains("SF") || args.contains("city"));

        let func_output_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call_output"))
            .expect("should have function_call_output item");
        assert_eq!(
            func_output_item.get("call_id").and_then(|c| c.as_str()),
            Some("fc_1")
        );
        let output = func_output_item
            .get("output")
            .and_then(|o| o.as_str())
            .expect("output should exist");
        assert_eq!(output, "sunny");

        let tools = json
            .get("tools")
            .and_then(|v| v.as_array())
            .expect("tools should exist");
        assert_eq!(tools.len(), 1);
        let tool_obj = &tools[0];
        assert_eq!(tool_obj.get("type"), Some(&serde_json::json!("function")));
        assert_eq!(
            tool_obj.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        assert!(
            tool_obj.get("function").is_none(),
            "tools should be flattened"
        );

        assert_eq!(
            json.get("max_output_tokens"),
            Some(&serde_json::json!(1024))
        );
        assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
    }

    #[test]
    fn test_read_request() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "instructions": "You are helpful.",
            "input": [
                {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "What's the weather?"}]},
                {"role": "assistant", "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "Let me check that for you."}]},
                {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_1", "name": "get_weather", "arguments": "{\"city\":\"SF\"}"},
                {"type": "function_call_output", "call_id": "fc_1", "output": "Sunny, 72F"}
            ],
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
            "max_output_tokens": 1024,
            "temperature": 0.7
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.system.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
            assert_eq!(text, "You are helpful.");
        } else {
            panic!("system should be Text block");
        }

        // 2 role/content messages + function_call -> assistant + function_call_output -> tool
        assert_eq!(ir.messages.len(), 4);

        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What's the weather?");
        } else {
            panic!("first message should be Text block");
        }

        assert_eq!(ir.max_tokens, Some(1024));
        assert_eq!(ir.temperature, Some(0.7_f64));

        assert_eq!(ir.tools.len(), 1);
        let tool = &ir.tools[0];
        assert_eq!(tool.name, "get_weather");
    }

    // Regression (MED #4/#5): a `message`-item `content` that is a BARE JSON STRING (the
    // Responses shorthand) must survive. The old array-only path returned `None` from
    // `as_array()` and silently dropped the whole turn, losing a user/assistant message on a
    // cross-protocol hop. Covers BOTH the typed `"type":"message"` arm and the untyped
    // role-keyed fallback.
    #[test]
    fn test_read_request_bare_string_content_survives() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                // typed message arm, bare-string content
                {"type": ITEM_TYPE_MESSAGE, "role": "user", "content": "hello from typed"},
                // typed message arm, assistant bare-string content
                {"type": ITEM_TYPE_MESSAGE, "role": "assistant", "content": "typed assistant reply"},
                // untyped role-keyed fallback, bare-string content
                {"role": "user", "content": "hello from untyped"},
                {"role": "assistant", "content": "untyped assistant reply"}
            ]
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        // All four turns must survive (old code dropped every one).
        assert_eq!(ir.messages.len(), 4, "no turn may be dropped");

        let expect_text = |msg: &crate::ir::IrMessage, role: crate::ir::IrRole, text: &str| {
            assert_eq!(msg.role, role);
            assert_eq!(msg.content.len(), 1);
            match &msg.content[0] {
                crate::ir::IrBlock::Text { text: t, .. } => assert_eq!(t, text),
                other => panic!("expected Text block, got {other:?}"),
            }
        };

        expect_text(&ir.messages[0], crate::ir::IrRole::User, "hello from typed");
        expect_text(
            &ir.messages[1],
            crate::ir::IrRole::Assistant,
            "typed assistant reply",
        );
        expect_text(
            &ir.messages[2],
            crate::ir::IrRole::User,
            "hello from untyped",
        );
        expect_text(
            &ir.messages[3],
            crate::ir::IrRole::Assistant,
            "untyped assistant reply",
        );
    }

    #[test]
    fn test_roundtrip_identity() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Hello!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Hi there!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: Some(500),
            temperature: Some(0.7),
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

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let json = writer.write_request(&ir);
        let rt_ir = reader
            .read_request(&json)
            .expect("read round-trip should succeed");

        assert_eq!(ir, rt_ir);
    }

    #[test]
    fn test_temperature_fidelity() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "test"}]}],
            "temperature": 0.7,
            "max_output_tokens": 1024
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_auth_headers() {
        let writer = ResponsesWriter;
        let headers = writer.auth_headers("sk-test");

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");
    }

    /// Warn+OMIT policy (`proto::bearer_auth_headers`): a key with bytes invalid for an HTTP header
    /// value (embedded newline) must OMIT the header entirely (empty Vec), never emit an empty
    /// `authorization` value (a syntactically invalid header AND a fingerprinting tell). No panic.
    #[test]
    fn auth_headers_invalid_key_omits_header_no_panic() {
        let writer = ResponsesWriter;
        let headers = writer.auth_headers("sk-bad\nkey");
        assert!(
            headers.is_empty(),
            "an invalid key must omit the auth header, not emit an empty value"
        );
    }

    #[test]
    fn test_read_response_decode() {
        let json = serde_json::json!({
            "id": "resp_1",
            "object": OBJ_RESPONSE,
            "status": STATUS_COMPLETED,
            "output": [
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "The weather in SF is sunny."}]
                },
                {
                    "type": ITEM_TYPE_FUNCTION_CALL,
                    "call_id": "fc_1",
                    "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}"
                }
            ],
            "usage": {"input_tokens": 50, "output_tokens": 25}
        });

        let reader = ResponsesReader;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");

        assert_eq!(resp.content.len(), 2);
        match &resp.content[0] {
            crate::ir::IrBlock::Text { text, .. } => {
                assert_eq!(text, "The weather in SF is sunny.")
            }
            _ => panic!("first block should be Text"),
        }
        match &resp.content[1] {
            crate::ir::IrBlock::ToolUse {
                id, name, input, ..
            } => {
                assert_eq!(id, "fc_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input.get("city").and_then(|v| v.as_str()), Some("SF"));
            }
            _ => panic!("second block should be ToolUse"),
        }

        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
        assert_eq!(resp.usage.input_tokens, 50);
        assert_eq!(resp.usage.output_tokens, 25);
    }

    /// Fix #9 (lenience): a Responses `read_response` body with NO `usage` object must parse to a
    /// zero IrUsage rather than hard-erroring with a ClientError — mirroring all five sibling readers
    /// (openai_chat.rs, etc.). A missing `usage` on an otherwise valid 200 is an upstream format quirk,
    /// not a client mistake; erroring here would make forward.rs discard a valid body and 500.
    #[test]
    fn read_response_without_usage_zero_defaults_no_error() {
        let json = serde_json::json!({
            "id": "resp_no_usage",
            "object": OBJ_RESPONSE,
            "status": STATUS_COMPLETED,
            "output": [
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
                }
            ]
            // intentionally NO "usage" key
        });

        let resp = ResponsesReader
            .read_response(&json)
            .expect("absent usage must parse to zero, not error");
        assert_eq!(resp.usage.input_tokens, 0);
        assert_eq!(resp.usage.output_tokens, 0);
        assert_eq!(resp.usage.cache_read_input_tokens, None);
    }

    #[test]
    fn test_write_response_roundtrip_text_only() {
        // The writer re-emits the SDK-required top-level identity (`id`/`created_at`/`model`/`status`/
        // `error:null`) AND a CONFORMANT message output item: a native message item carries an
        // item-level opaque `id` (`msg_…`), a `status`, and `annotations: []` on the `output_text`
        // part — exactly what the streaming `output_item.done` emits. The non-stream writer must too,
        // or a typed SDK reading `item.id`/`item.status`/`content[0].annotations` sees missing fields
        // (a proxy tell). Because the synthesized item id is opaque/random (as native ids are), this
        // asserts CONFORMANCE + field preservation rather than byte-equality.
        let json = serde_json::json!({
            "id": "resp_abc123",
            "object": OBJ_RESPONSE,
            "created_at": 1_700_000_000_u64,
            "status": STATUS_COMPLETED,
            "model": "gpt-4o",
            "output": [
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "Hello world"}]
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "error": serde_json::Value::Null
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir_resp = reader.read_response(&json).expect("read should succeed");
        let out = writer.write_response(&ir_resp);

        // Top-level identity preserved verbatim.
        assert_eq!(out["id"], json["id"]);
        assert_eq!(out["object"], "response"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(out["created_at"], json["created_at"]);
        assert_eq!(out["status"], "completed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(out["model"], "gpt-4o");
        assert_eq!(out["usage"], json["usage"]);
        assert!(out["error"].is_null());

        // The message output item is conformant: native opaque id, status, and annotations.
        let item = &out["output"][0];
        assert_eq!(item["type"], "message"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(item["role"], "assistant");
        assert_eq!(item["status"], "completed"); // golden wire-contract literal (kept bare on purpose)
        let id = item["id"].as_str().expect("message item carries an id");
        assert!(
            id.starts_with("msg_") && id.len() > 4,
            "item id must be a native opaque msg_ token, got {id}"
        ); // golden wire-contract literal (kept bare on purpose)
        let part = &item["content"][0];
        assert_eq!(part["type"], "output_text"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(part["text"], "Hello world");
        assert!(
            part["annotations"].as_array().is_some_and(|a| a.is_empty()),
            "output_text part must carry annotations: [], got {part}"
        );
    }

    /// Regression (MEDIUM/conformance): the NON-streaming `write_response` function_call
    /// item must carry the item-level opaque `id` (`fc_…`, distinct from `call_id`) that the streaming
    /// `output_item.done` emits, or a typed SDK reading `item.id` sees a missing field.
    #[test]
    fn test_write_response_function_call_item_has_native_id() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            id: Some("resp_x".to_string()),
            model: Some("gpt-4o".to_string()),
            created: Some(1_700_000_000),
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_abc".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            }],
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            system_fingerprint: None,
        };
        let writer = ResponsesWriter;
        let out = writer.write_response(&resp);
        let fc = out["output"]
            .as_array()
            .and_then(|a| a.iter().find(|i| i["type"] == "function_call")) // golden wire-contract literal (kept bare on purpose)
            .expect("a function_call output item");
        assert_eq!(fc["call_id"], "call_abc", "call_id preserved");
        let id = fc["id"]
            .as_str()
            .expect("function_call item carries an item-level id");
        assert!(
            id.starts_with("fc_") && id.len() > 3,
            "function_call item id must be a native opaque fc_ token, got {id}"
        ); // golden wire-contract literal (kept bare on purpose)
    }

    /// Regression (MED #1): the NON-streaming `read_response` tool-use override must NOT clobber a
    /// truncation reason. An `incomplete` body with `incomplete_details.reason=max_output_tokens` that
    /// also carries a (partial) `function_call` item was cut off mid-output — its stop_reason must stay
    /// `max_tokens`, NOT be promoted to `tool_use`. Before the fix the override fired unconditionally on
    /// any ToolUse block, clobbering `max_tokens` and telling the client the call was complete (and
    /// denying the truncation signal to the breaker). The override is now guarded on `end_turn` only,
    /// mirroring the streaming `response.completed` arm.
    #[test]
    fn test_read_response_incomplete_with_function_call_keeps_max_tokens() {
        let json = serde_json::json!({
            "id": "resp_trunc",
            "object": OBJ_RESPONSE,
            "created_at": 1_700_000_000_u64,
            "status": STATUS_INCOMPLETE,
            "model": "gpt-4o",
            "incomplete_details": { "reason": INCOMPLETE_REASON_MAX_OUTPUT },
            "output": [
                {
                    "type": ITEM_TYPE_FUNCTION_CALL,
                    "call_id": "call_1",
                    "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}"
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });

        let reader = ResponsesReader;
        let resp = reader.read_response(&json).expect("read should succeed");

        // The tool call survived as content...
        assert!(
            resp.content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })),
            "the partial function_call must still be present as a ToolUse block"
        );
        // ...but the truncation reason must NOT have been clobbered to tool_use.
        assert_eq!(
            resp.stop_reason,
            Some(crate::ir::IrStopReason::MaxTokens),
            "an incomplete (max_output_tokens) response must keep stop_reason=max_tokens, not be \
             promoted to tool_use just because a partial function_call survived"
        );
    }

    /// Regression (refusal data-loss): a native Responses refusal rides on a
    /// `{type:"refusal", refusal:"..."}` content part with `status:"completed"`. The prior reader
    /// matched only `output_text`, so the refusal text was SILENTLY DROPPED and the turn looked like a
    /// clean empty end_turn. The refusal text must survive as assistant content AND the stop_reason
    /// must be promoted to `Refusal` (so a non-Responses client sees the refusal signal).
    #[test]
    fn read_response_refusal_part_survives_and_promotes_stop_reason() {
        let json = serde_json::json!({
            "id": "resp_refuse",
            "object": OBJ_RESPONSE,
            "created_at": 1_700_000_000_u64,
            "status": STATUS_COMPLETED,
            "model": "gpt-4o",
            "output": [
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [
                        { "type": "refusal", "refusal": "I can't help with that." }
                    ]
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });

        let reader = ResponsesReader;
        let resp = reader.read_response(&json).expect("read should succeed");

        // The refusal text survived as assistant Text (not dropped).
        assert!(
            resp.content.iter().any(|b| matches!(
                b,
                crate::ir::IrBlock::Text { text, .. } if text == "I can't help with that."
            )),
            "the refusal text must survive as assistant content, not be silently dropped: {:?}",
            resp.content
        );
        // The completed status was promoted to the typed Refusal stop_reason.
        assert_eq!(
            resp.stop_reason,
            Some(crate::ir::IrStopReason::Refusal),
            "a completed response carrying a refusal part must surface stop_reason=refusal"
        );
    }

    /// Regression (LOW #5): `write_response` must build the `output` array in IR ENCOUNTER order so it
    /// mirrors the streaming `drain_output_items` order. A prior revision `insert(0)`'d the text message
    /// item at the FRONT, so a text-AFTER-tool response emitted [message, function_call] on the
    /// non-stream path while the stream emitted [function_call, message] — a client reassembling
    /// `response.output[]` saw the two paths disagree. Order must now follow the blocks: tool, then text.
    #[test]
    fn test_write_response_preserves_text_after_tool_order() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            id: Some("resp_order".to_string()),
            model: Some("gpt-4o".to_string()),
            created: Some(1_700_000_000),
            content: vec![
                crate::ir::IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                    cache_control: None,
                },
                crate::ir::IrBlock::Text {
                    text: "Here is the weather.".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
            ],
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            system_fingerprint: None,
        };
        let writer = ResponsesWriter;
        let out = writer.write_response(&resp);
        let arr = out["output"].as_array().expect("output is an array");
        assert_eq!(arr.len(), 2, "one item per non-empty block, in order");
        // Encounter order: the tool block came first, the text block second.
        assert_eq!(
            arr[0]["type"],
            "function_call", // golden wire-contract literal (kept bare on purpose)
            "the tool block was first in IR content, so it must be output[0]"
        );
        assert_eq!(arr[0]["call_id"], "call_1");
        assert_eq!(
            arr[1]["type"],
            "message", // golden wire-contract literal (kept bare on purpose)
            "the text block came after the tool block, so it must NOT be forced to output[0]"
        );
        assert_eq!(arr[1]["content"][0]["text"], "Here is the weather.");
    }

    /// The native Responses error envelope an official SDK decodes: a JSON object whose `error`
    /// carries `message`, a Responses-vocabulary `type`, and `code`/`param` keys (null here).
    #[test]
    fn test_write_error_native_responses_envelope() {
        let writer = ResponsesWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");

        // Round-trips as JSON without panic.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

        let err = reparsed.get("error").expect("error object present");
        assert_eq!(
            err.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found")
        );
        // Generic `not_found` maps to the Responses vocabulary `not_found_error`.
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("not_found_error")
        );
        // `code` and `param` keys are present and null (Responses/OpenAI always include them).
        assert!(err.get("code").is_some(), "code key must be present");
        assert!(err.get("param").is_some(), "param key must be present");
        assert!(err.get("code").unwrap().is_null());
        assert!(err.get("param").unwrap().is_null());
    }

    /// Each generic `kind` maps to the canonical Responses `error.type`; an unrecognized kind is
    /// passed through verbatim (no catch-all swallowing of a precise upstream type).
    #[test]
    fn test_write_error_kind_mapping() {
        let writer = ResponsesWriter;
        // The `want` values are golden wire-contract literals (kept bare on purpose) — they are the
        // exact `error.type` strings busbar emits for each input kind.
        for (kind, want) in [
            ("invalid_request", "invalid_request_error"),
            ("auth", "authentication_error"),
            ("forbidden", "permission_error"),
            ("not_found", "not_found_error"),
            ("rate_limit", "rate_limit_error"),
            ("server_error", "server_error"),
            ("billing", "insufficient_quota"),
            // Already-canonical and unknown types pass through unchanged.
            ("authentication_error", "authentication_error"),
            ("some_future_type", "some_future_type"),
        ] {
            let v = writer.write_error(400, kind, "m");
            assert_eq!(
                v.get("error")
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str()),
                Some(want),
                "kind {kind} should map to {want}"
            );
        }
    }

    /// Same-protocol passthrough: `read_response` captures the upstream `id`/`created_at`, and
    /// `write_response` emits them verbatim — identity is preserved exactly, not regenerated.
    #[test]
    fn test_same_protocol_roundtrip_preserves_identity() {
        let json = serde_json::json!({
            "id": "resp_0123456789abcdef",
            "object": OBJ_RESPONSE,
            "created_at": 1_710_000_000_u64,
            "status": STATUS_COMPLETED,
            "model": "gpt-4o-2024-08-06",
            "output": [
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir = reader.read_response(&json).expect("read should succeed");
        assert_eq!(ir.id.as_deref(), Some("resp_0123456789abcdef"));
        assert_eq!(ir.created, Some(1_710_000_000));

        let out = writer.write_response(&ir);
        assert_eq!(
            out.get("id").and_then(|i| i.as_str()),
            Some("resp_0123456789abcdef"),
            "id must be preserved verbatim"
        );
        assert_eq!(
            out.get("created_at").and_then(|c| c.as_u64()),
            Some(1_710_000_000),
            "created_at must be preserved verbatim"
        );
        assert_eq!(out.get("object").and_then(|o| o.as_str()), Some("response"));
        // golden wire-contract literal (kept bare on purpose)
    }

    /// The streaming start event captures the nested `response` identity for same-protocol
    /// passthrough.
    #[test]
    fn test_stream_message_start_captures_identity() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_CREATED,
            &serde_json::json!({
                "response": {
                    "id": "resp_streamid",
                    "object": OBJ_RESPONSE,
                    "created_at": 1_720_000_000_u64,
                    "model": "gpt-4o",
                    "status": STATUS_IN_PROGRESS
                }
            }),
            &mut state,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                assert_eq!(id.as_deref(), Some("resp_streamid"));
                assert_eq!(*created, Some(1_720_000_000));
                assert_eq!(model.as_deref(), Some("gpt-4o"));
            }
            other => panic!("expected MessageStart, got {other:?}"),
        }
    }

    /// Cross-protocol: when the IR carries no identity (the backend supplied none), `write_response`
    /// synthesizes a valid `resp_`-prefixed id and a current `created_at` without panicking, and two
    /// successive synthesized ids are distinct.
    #[test]
    fn test_cross_protocol_write_synthesizes_valid_id() {
        let writer = ResponsesWriter;
        let make_ir = || crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "answer".to_string(),
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
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let out1 = writer.write_response(&make_ir());
        let id1 = out1
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id1.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
            "synthesized id must use the resp_ prefix, got {id1}"
        );
        assert!(
            out1.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );

        let out2 = writer.write_response(&make_ir());
        let id2 = out2.get("id").and_then(|i| i.as_str()).unwrap();
        assert_ne!(id1, id2, "successive synthesized ids must be unique");
    }

    #[test]
    fn test_stream_fanout() {
        let mut state = crate::ir::StreamDecodeState::default();

        // response.created → MessageStart only (first time)
        let events1 = reader_read_response_events(
            EVT_RESPONSE_CREATED,
            &serde_json::json!({"response": {"object": OBJ_RESPONSE, "status": STATUS_IN_PROGRESS}}),
            &mut state,
        );
        assert_eq!(events1.len(), 1);
        assert!(matches!(
            events1[0],
            crate::ir::IrStreamEvent::MessageStart { .. }
        ));
        // response.output_item.added for function_call → BlockStart
        let events2 = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 1,
                "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id":"fc_1","name":"get_weather"}
            }),
            &mut state,
        );
        assert_eq!(events2.len(), 1);
        assert!(matches!(
            events2[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        // response.output_text.delta ×3 → BlockStart (lazy) + BlockDelta ×3
        let delta_json = |d: &str| serde_json::json!({"output_index": 0, "delta": d});
        let events3a =
            reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("H"), &mut state);
        assert_eq!(events3a.len(), 2); // BlockStart + BlockDelta
        assert!(matches!(
            events3a[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        assert!(matches!(
            events3a[1],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3b =
            reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("i"), &mut state);
        assert_eq!(events3b.len(), 1); // BlockDelta only
        assert!(matches!(
            events3b[0],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3c =
            reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("!"), &mut state);
        assert_eq!(events3c.len(), 1); // BlockDelta only

        // response.output_item.done → BlockStop
        let events4 = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(events4.len(), 1);
        assert!(matches!(
            events4[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        // response.completed with usage. The function_call block opened at index 1 (events2) was
        // never closed by an `output_item.done`, so it is STILL OPEN at the terminal event. The
        // terminal arm must close it (BlockStop{index:1}) BEFORE MessageStop so the stream stays
        // balanced (MED #5), giving: BlockStop + MessageDelta + MessageStop.
        let completed_json = serde_json::json!({
            "response": {
                "status": STATUS_COMPLETED,
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }
        });
        let events5 =
            reader_read_response_events(EVT_RESPONSE_COMPLETED, &completed_json, &mut state);
        assert_eq!(events5.len(), 3);
        assert!(
            matches!(events5[0], crate::ir::IrStreamEvent::BlockStop { index: 1 }),
            "still-open tool block at index 1 must be closed before MessageStop, got {:?}",
            events5[0]
        );
        assert!(matches!(
            events5[1],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events5[2], crate::ir::IrStreamEvent::MessageStop));
        // response.in_progress should not emit MessageStart again (state.started=true)
        let events6 = reader_read_response_events(
            "response.in_progress",
            &serde_json::json!({"response": {"object": OBJ_RESPONSE, "status": STATUS_IN_PROGRESS}}),
            &mut state,
        );
        assert_eq!(events6.len(), 0);

        // Unknown event type → empty (no panic)
        let events7 = reader_read_response_events(
            "response.content_part.added",
            &serde_json::json!({}),
            &mut state,
        );
        assert_eq!(events7.len(), 0);
    }

    /// Regression (refusal stream data-loss): a STREAMED Responses refusal carries its text only in
    /// the terminal `response.completed` frame as an `output[].content[]` `{type:"refusal"}` part
    /// (status `completed`). The streaming reader previously handled only `output_text.delta`, so it
    /// SILENTLY DROPPED the refusal text AND left stop_reason=end_turn. It must now surface the
    /// refusal text as a Text block and promote stop_reason to Refusal (mirroring the non-stream path).
    #[test]
    fn read_response_events_streamed_refusal_surfaces_text_and_refusal_stop_reason() {
        use crate::ir::{IrDelta, IrStopReason, IrStreamEvent};
        let mut state = crate::ir::StreamDecodeState::default();
        // No output_text.delta is emitted for a refusal — only the terminal completed frame.
        let events = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({
                "response": {
                    "object": OBJ_RESPONSE,
                    "status": STATUS_COMPLETED,
                    "output": [{
                        "type": ITEM_TYPE_MESSAGE,
                        "role": "assistant",
                        "content": [{ "type": "refusal", "refusal": "I can't help with that." }]
                    }],
                    "usage": { "input_tokens": 5, "output_tokens": 3 }
                }
            }),
            &mut state,
        );

        // The refusal text surfaced as a Text BlockDelta (not dropped).
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta { delta: IrDelta::TextDelta(t), .. } if t == "I can't help with that."
            )),
            "streamed refusal text must surface as a TextDelta; got {events:?}"
        );
        // The terminal MessageDelta promoted stop_reason to Refusal (not end_turn).
        let stop = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
            _ => None,
        });
        assert_eq!(
            stop,
            Some(Some(IrStopReason::Refusal)),
            "a streamed refusal must terminate with stop_reason=Refusal; got {events:?}"
        );
        // Block open/close balance: exactly one BlockStart and one BlockStop for the refusal block.
        let starts = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        let stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count();
        assert_eq!(
            (starts, stops),
            (1, 1),
            "one Start/Stop for the refusal block; got {events:?}"
        );
    }

    #[test]
    fn test_write_response_event_blockdelta() {
        let writer = ResponsesWriter;

        // BlockDelta TextDelta("hi") → ("response.output_text.delta", delta=="hi")
        let ev1 = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };
        let (etype1, payload1) = writer.write_response_event(&ev1).expect("should emit");
        assert_eq!(etype1, "response.output_text.delta"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(payload1.get("delta").and_then(|d| d.as_str()), Some("hi"));

        // MessageDelta{end_turn} → ("response.completed", status maps to completed)
        let ev2 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype2, payload2) = writer.write_response_event(&ev2).expect("should emit");
        assert_eq!(etype2, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        let resp_obj = payload2
            .get("response")
            .expect("payload should have response");
        assert_eq!(
            resp_obj.get("status"),
            Some(&serde_json::json!("completed")) // golden wire-contract literal (kept bare on purpose)
        );
    }

    fn reader_read_response_events(
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<crate::ir::IrStreamEvent> {
        let reader = ResponsesReader;
        reader.read_response_events(event_type, data, state)
    }

    /// Regression: a text part arriving at a non-zero `output_index` must open AND write to the
    /// same block index. Previously BlockStart was hard-coded to index 0 while BlockDelta used the
    /// wire index, producing an unmatched open/write pair for downstream index-keyed consumers.
    #[test]
    fn test_text_delta_index_pairing_nonzero() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 2, "delta": "hello"}),
            &mut state,
        );
        assert_eq!(events.len(), 2, "expected lazy BlockStart + BlockDelta");
        let start_idx = match &events[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("first event should be BlockStart, got {other:?}"),
        };
        let delta_idx = match &events[1] {
            crate::ir::IrStreamEvent::BlockDelta { index, .. } => *index,
            other => panic!("second event should be BlockDelta, got {other:?}"),
        };
        assert_eq!(start_idx, 2, "BlockStart must use the wire output_index");
        assert_eq!(delta_idx, 2, "BlockDelta must use the wire output_index");
        assert_eq!(start_idx, delta_idx, "open/write indices must match");
    }

    /// Regression: an empty-delta keepalive chunk must produce no events, even when a text block is
    /// already open. Previously the guard `|| state.text_block_open` emitted a spurious zero-length
    /// TextDelta for every keepalive after the block opened.
    #[test]
    fn test_empty_delta_keepalive_emits_nothing() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a block with a real delta first.
        let opened = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "x"}),
            &mut state,
        );
        assert_eq!(opened.len(), 2);
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // Now an empty keepalive while the block is open -> nothing.
        let keepalive = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut state,
        );
        assert!(
            keepalive.is_empty(),
            "empty keepalive delta must not emit events, got {keepalive:?}"
        );
        // And an empty delta before any block is open also emits nothing.
        let mut fresh = crate::ir::StreamDecodeState::default();
        let pre = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut fresh,
        );
        assert!(pre.is_empty());
        assert!(!fresh.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    }

    /// Regression: output_item.done must clear the open TEXT index so a subsequent text part can
    /// lazily re-open its own block instead of silently reusing stale open state.
    #[test]
    fn test_done_clears_text_block_open() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        let done = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(
            !state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
            "done must clear the open text index"
        );
        // A new text part at index 1 re-opens lazily.
        let reopen = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 1, "delta": "b"}),
            &mut state,
        );
        assert_eq!(reopen.len(), 2);
        assert!(matches!(
            reopen[0],
            crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
        ));
    }

    /// Regression (MED #4): a bodyless `response.incomplete` terminal event (no nested `response`
    /// object) must NOT decode to a successful `end_turn`. With no `incomplete_details.reason`
    /// available there is no specific truncation reason, so the stop_reason must be None — masking
    /// a truncation as end_turn would lie to a downstream client. Previously the else branch
    /// hardcoded `Some("end_turn")` for every bodyless terminal regardless of event_type.
    #[test]
    fn test_bodyless_incomplete_is_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_INCOMPLETE,
            // No nested `response` object at all.
            &serde_json::json!({}),
            &mut state,
        );
        // Stream still terminates: MessageDelta + MessageStop.
        let delta_stop = events
            .iter()
            .find_map(|e| match e {
                crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
                _ => None,
            })
            .expect("bodyless incomplete must still emit a MessageDelta");
        assert_eq!(
            *delta_stop, None,
            "bodyless incomplete must surface stop_reason None, not a fabricated end_turn"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageStop)),
            "stream must still terminate with MessageStop"
        );

        // And a bodyless `completed` still maps to end_turn (the only successful terminal).
        let mut s2 = crate::ir::StreamDecodeState::default();
        let completed =
            reader_read_response_events(EVT_RESPONSE_COMPLETED, &serde_json::json!({}), &mut s2);
        let completed_reason = completed
            .iter()
            .find_map(|e| match e {
                crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
                _ => None,
            })
            .expect("bodyless completed must still emit a MessageDelta");
        assert_eq!(
            *completed_reason,
            Some(crate::ir::IrStopReason::EndTurn),
            "bodyless completed must map to end_turn"
        );
    }

    #[test]
    fn test_stream_completed_with_function_call_is_tool_use_not_end_turn() {
        // A STREAMED Responses tool call must terminate with stop_reason=tool_use, matching the
        // non-streaming read_response (which flips a completed end_turn to tool_use when the output
        // carries a function_call). Before the fix the stream said end_turn, so a cross-protocol
        // client never saw the tool-call finish signal on the streaming path.
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({
                "response": {
                    "status": STATUS_COMPLETED,
                    "output": [
                        { "type": ITEM_TYPE_FUNCTION_CALL, "id": "fc_1", "call_id": "call_1",
                          "name": "get_weather", "arguments": "{}" }
                    ]
                }
            }),
            &mut state,
        );
        let stop = events
            .iter()
            .find_map(|e| match e {
                crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
                _ => None,
            })
            .expect("terminal MessageDelta");
        assert_eq!(
            *stop,
            Some(crate::ir::IrStopReason::ToolUse),
            "a streamed completed response containing a function_call must be tool_use, not end_turn"
        );
    }

    #[test]
    fn test_stream_completed_without_function_call_stays_end_turn() {
        // No function_call in the output → still a plain end_turn (the override must not over-fire).
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({
                "response": {
                    "status": STATUS_COMPLETED,
                    "output": [
                        { "type": ITEM_TYPE_MESSAGE, "role": "assistant",
                          "content": [{ "type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi", "annotations": [] }] }
                    ]
                }
            }),
            &mut state,
        );
        let stop = events
            .iter()
            .find_map(|e| match e {
                crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
                _ => None,
            })
            .expect("terminal MessageDelta");
        assert_eq!(
            *stop,
            Some(crate::ir::IrStopReason::EndTurn),
            "text-only completed stays end_turn"
        );
    }

    /// Regression (MED #5): a terminal event arriving while a content block is STILL OPEN must
    /// close that block (BlockStop) before MessageStop. Otherwise the translated stream emits a
    /// BlockStart with no matching BlockStop — an unbalanced sequence a strict SDK rejects. This
    /// covers every terminal sub-path: bodyless completed/incomplete, body-present
    /// completed/incomplete, the body-present `failed` early-return, and the bodyless `failed`
    /// arm — each with an open text block AND an open tool block to prove both key kinds drain.
    #[test]
    fn test_terminal_closes_open_blocks_balanced() {
        // Helper: opens a text block at index 0 and a tool block at index 1, then fires `etype`
        // with `data`, and asserts every BlockStart in the WHOLE stream has a matching BlockStop.
        fn assert_balanced(etype: &str, data: serde_json::Value) {
            let mut state = crate::ir::StreamDecodeState::default();
            let mut all: Vec<crate::ir::IrStreamEvent> = Vec::new();
            // Open a text block at index 0.
            all.extend(reader_read_response_events(
                EVT_OUTPUT_TEXT_DELTA,
                &serde_json::json!({"output_index": 0, "delta": "partial"}),
                &mut state,
            ));
            // Open a tool block at index 1.
            all.extend(reader_read_response_events(
                EVT_OUTPUT_ITEM_ADDED,
                &serde_json::json!({
                    "output_index": 1,
                    "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "c1", "name": "f"}
                }),
                &mut state,
            ));
            // Sanity: both blocks are open before the terminal event.
            assert!(
                state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
                "{etype}: text block should be open"
            );
            assert!(
                state.open_tools.contains(&1),
                "{etype}: tool block should be open"
            );
            // Fire the terminal event.
            all.extend(reader_read_response_events(etype, &data, &mut state));

            // Count BlockStart vs BlockStop per index — every open index must be closed exactly
            // once and no stray closes.
            use std::collections::BTreeMap;
            let mut starts: BTreeMap<usize, usize> = BTreeMap::new();
            let mut stops: BTreeMap<usize, usize> = BTreeMap::new();
            for ev in &all {
                match ev {
                    crate::ir::IrStreamEvent::BlockStart { index, .. } => {
                        *starts.entry(*index).or_insert(0) += 1;
                    }
                    crate::ir::IrStreamEvent::BlockStop { index } => {
                        *stops.entry(*index).or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
            assert_eq!(
                starts, stops,
                "{etype}: BlockStart/BlockStop counts must balance per index (starts={starts:?} stops={stops:?})"
            );
            // Specifically index 0 (text) and index 1 (tool) were each opened once and closed once.
            assert_eq!(
                starts.get(&0).copied(),
                Some(1),
                "{etype}: text opened once"
            );
            assert_eq!(stops.get(&0).copied(), Some(1), "{etype}: text closed once");
            assert_eq!(
                starts.get(&1).copied(),
                Some(1),
                "{etype}: tool opened once"
            );
            assert_eq!(stops.get(&1).copied(), Some(1), "{etype}: tool closed once");
            // The terminal arm must have drained the open set.
            assert!(
                state.open_tools.is_empty(),
                "{etype}: open_tools must be drained after the terminal event"
            );
            // BlockStop for an index must precede MessageStop (a stop after the message-end is
            // out of order). Verify the last BlockStop comes before MessageStop.
            let msg_stop_pos = all
                .iter()
                .position(|e| matches!(e, crate::ir::IrStreamEvent::MessageStop))
                .expect("must emit MessageStop");
            let last_block_stop = all
                .iter()
                .rposition(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { .. }))
                .expect("must emit BlockStop");
            assert!(
                last_block_stop < msg_stop_pos,
                "{etype}: all BlockStop must precede MessageStop"
            );
        }

        // Bodyless terminals (no nested `response`).
        assert_balanced(EVT_RESPONSE_COMPLETED, serde_json::json!({}));
        assert_balanced(EVT_RESPONSE_INCOMPLETE, serde_json::json!({}));
        assert_balanced(EVT_RESPONSE_FAILED, serde_json::json!({}));

        // Body-present completed.
        assert_balanced(
            EVT_RESPONSE_COMPLETED,
            serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
        );
        // Body-present incomplete (truncated mid-block).
        assert_balanced(
            EVT_RESPONSE_INCOMPLETE,
            serde_json::json!({
                "response": {"status": STATUS_INCOMPLETE, "incomplete_details": {"reason": INCOMPLETE_REASON_MAX_OUTPUT}}
            }),
        );
        // Body-present failed (the early-return path).
        assert_balanced(
            EVT_RESPONSE_FAILED,
            serde_json::json!({"response": {"status": STATUS_FAILED, "error": {"code": ERR_TYPE_SERVER_ERROR}}}),
        );
    }

    /// Regression: content_part.done is also a terminal-of-part signal and must close its block.
    #[test]
    fn test_content_part_done_closes_block() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        let done = reader_read_response_events(
            "response.content_part.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    }

    /// Regression: a minimal `response.completed` lacking a nested `response` object must still
    /// terminate the stream with MessageDelta + MessageStop, not leave it hanging.
    #[test]
    fn test_completed_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events =
            reader_read_response_events(EVT_RESPONSE_COMPLETED, &serde_json::json!({}), &mut state);
        assert_eq!(events.len(), 2, "must emit MessageDelta + MessageStop");
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: same for `response.incomplete` with no nested response object.
    #[test]
    fn test_incomplete_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_INCOMPLETE,
            &serde_json::json!({}),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

        // response.failed without object still works (pre-existing behavior preserved).
        let mut s2 = crate::ir::StreamDecodeState::default();
        let failed =
            reader_read_response_events(EVT_RESPONSE_FAILED, &serde_json::json!({}), &mut s2);
        assert_eq!(failed.len(), 2);
        assert!(matches!(failed[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: an input item carrying BOTH a `type` and a `role` must be processed exactly once
    /// (by the type arm), not duplicated by the role-keyed fallback.
    #[test]
    fn test_typed_item_with_role_not_duplicated() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {
                    "type": CONTENT_TYPE_OUTPUT_TEXT,
                    "role": "assistant",
                    "text": "hello",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "DUPLICATE"}]
                }
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        // Exactly one message: the type arm produced the assistant text turn; the role fallback
        // must NOT have added a second turn from the `content` array.
        assert_eq!(ir.messages.len(), 1, "typed+role item must not duplicate");
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::Assistant);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }

    /// Regression: an assistant turn that is PURELY a tool call must emit a flat `function_call`
    /// item and NO companion empty-content assistant `message` wrapper. The Responses API rejects
    /// assistant message items with `content: []`.
    #[test]
    fn test_tool_only_assistant_turn_no_empty_message_wrapper() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "fc_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        // Exactly one item: the function_call. No empty-content assistant message.
        assert_eq!(
            input.len(),
            1,
            "tool-only turn must not emit an empty message wrapper, got {input:?}"
        );
        assert_eq!(
            input[0].get("type").and_then(|t| t.as_str()),
            Some("function_call") // golden wire-contract literal (kept bare on purpose)
        );
        // No item should be a message with an empty content array.
        for item in input {
            if item.get("role").is_some() {
                let content = item.get("content").and_then(|c| c.as_array());
                assert!(
                    content.map(|c| !c.is_empty()).unwrap_or(true),
                    "no assistant message item may have empty content"
                );
            }
        }
    }

    /// Regression: an assistant turn carrying BOTH text and a tool call must emit the assistant
    /// `message` (with the text) FIRST, then the flat `function_call` item AFTER it — preserving
    /// the conversation order the assistant produced.
    #[test]
    fn test_assistant_text_then_tool_call_order() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "Let me check.".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::ToolUse {
                        id: "fc_9".to_string(),
                        name: "lookup".to_string(),
                        input: serde_json::json!({}),
                        cache_control: None,
                    },
                ],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        assert_eq!(
            input.len(),
            2,
            "expected message + function_call, got {input:?}"
        );
        // Message first.
        assert_eq!(
            input[0].get("role").and_then(|r| r.as_str()),
            Some("assistant")
        );
        let content = input[0]
            .get("content")
            .and_then(|c| c.as_array())
            .expect("message content");
        assert_eq!(
            content[0].get("text").and_then(|t| t.as_str()),
            Some("Let me check.")
        );
        // function_call after it.
        assert_eq!(
            input[1].get("type").and_then(|t| t.as_str()),
            Some("function_call") // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(
            input[1].get("call_id").and_then(|c| c.as_str()),
            Some("fc_9")
        );
    }

    /// Regression: a streaming `response.failed` (status=="failed") must surface an
    /// IrStreamEvent::Error followed by MessageStop, NOT a successful end_turn MessageDelta that
    /// would mask the failure from a downstream client.
    #[test]
    fn test_stream_failed_status_emits_error_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_FAILED,
            &serde_json::json!({
                "response": {
                    "status": STATUS_FAILED,
                    "error": {"code": ERR_TYPE_SERVER_ERROR, "type": ERR_TYPE_SERVER_ERROR}
                }
            }),
            &mut state,
        );
        assert_eq!(
            events.len(),
            2,
            "expected Error + MessageStop, got {events:?}"
        );
        match &events[0] {
            crate::ir::IrStreamEvent::Error(err) => {
                assert_eq!(err.provider_signal.as_deref(), Some("server_error"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
        // Crucially, no MessageDelta with end_turn was emitted.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageDelta { .. })),
            "failed stream must not emit a MessageDelta"
        );
    }

    /// Regression (LOW #8): a streamed `response.failed` must classify the IrError by the captured
    /// provider signal, not a hardcoded ServerError. An `invalid_api_key` mid-stream failure is an
    /// Auth failure (HardDown breaker disposition), NOT a transient ServerError — hardcoding
    /// ServerError gave the wrong breaker disposition / failover. The provider_signal is preserved
    /// verbatim. Against the old code (class: ServerError) this asserts Auth and fails.
    #[test]
    fn test_stream_failed_invalid_api_key_classifies_as_auth() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_FAILED,
            &serde_json::json!({
                "response": {
                    "status": STATUS_FAILED,
                    "error": {"code": "invalid_api_key", "type": ERR_TYPE_AUTHENTICATION}
                }
            }),
            &mut state,
        );
        match &events[0] {
            crate::ir::IrStreamEvent::Error(err) => {
                assert_eq!(
                    err.class,
                    StatusClass::Auth,
                    "invalid_api_key mid-stream must classify as Auth, not ServerError"
                );
                // provider_signal is kept as-is (the captured error.code).
                assert_eq!(err.provider_signal.as_deref(), Some("invalid_api_key"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // The full mapping mirrors the non-stream HTTP classifier buckets.
        assert_eq!(
            class_for_response_failed("invalid_api_key"),
            StatusClass::Auth
        );
        assert_eq!(
            class_for_response_failed(ERR_TYPE_AUTHENTICATION),
            StatusClass::Auth
        );
        assert_eq!(
            class_for_response_failed(ERR_CODE_RATE_LIMIT),
            StatusClass::RateLimit
        );
        assert_eq!(
            class_for_response_failed(ERR_TYPE_INSUFFICIENT_QUOTA),
            StatusClass::RateLimit
        );
        assert_eq!(
            class_for_response_failed(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH),
            StatusClass::ContextLength
        );
        assert_eq!(
            class_for_response_failed(ERR_CODE_STRING_ABOVE_MAX),
            StatusClass::ContextLength
        );
        assert_eq!(
            class_for_response_failed(ERR_TYPE_SERVER_ERROR),
            StatusClass::ServerError
        );
        assert_eq!(
            class_for_response_failed(ERR_TYPE_OVERLOADED),
            StatusClass::ServerError
        );
        // Unrecognized signal defaults to the transient ServerError bucket.
        assert_eq!(
            class_for_response_failed("response_failed"),
            StatusClass::ServerError
        );
    }

    /// Regression (LOW #8 sibling): the NON-streaming `read_response` `status:"failed"` path must
    /// also classify by the captured provider signal rather than hardcoding ServerError. A failed
    /// body carrying `code:"context_length_exceeded"` is a ContextLength failure (fail over without
    /// penalizing the lane), NOT a transient ServerError. Against the old code this asserts
    /// ContextLength and fails.
    #[test]
    fn test_read_response_failed_body_classifies_by_signal() {
        let reader = ResponsesReader;
        let err = reader
            .read_response(&serde_json::json!({
                "status": STATUS_FAILED,
                "output": [],
                "error": {"code": crate::forward::PROVIDER_CODE_CONTEXT_LENGTH, "type": ERR_TYPE_INVALID_REQUEST}
            }))
            .expect_err("failed body must surface an IrError");
        assert_eq!(
            err.class,
            StatusClass::ContextLength,
            "context_length_exceeded failed body must classify as ContextLength, not ServerError"
        );
        assert_eq!(
            err.provider_signal.as_deref(),
            Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
        );

        // An auth-failed body classifies as Auth.
        let err_auth = reader
            .read_response(&serde_json::json!({
                "status": STATUS_FAILED,
                "output": [],
                "error": {"code": "invalid_api_key", "type": ERR_TYPE_AUTHENTICATION}
            }))
            .expect_err("failed body must surface an IrError");
        assert_eq!(err_auth.class, StatusClass::Auth);
    }

    /// Regression: an unknown terminal status must not be decoded as a successful end_turn; its
    /// stop_reason is None (terminal, but no success claim).
    #[test]
    fn test_stream_unknown_status_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({"response": {"status": "some_future_status"}}),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(*stop_reason, None, "unknown status must not claim end_turn");
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: a streaming `incomplete` status with NO `incomplete_details` must NOT decode to
    /// `stop_reason = Some("end_turn")` — that masks the truncation as a clean completion. It must
    /// be `None`, mirroring the non-streaming `read_response` path. Two fallback branches: missing
    /// `incomplete_details` entirely, and present-but-without-a-`reason`.
    #[test]
    fn test_stream_incomplete_without_details_is_none() {
        // Branch 1: no `incomplete_details` at all.
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_INCOMPLETE,
            &serde_json::json!({"response": {"status": STATUS_INCOMPLETE}}),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(
                    *stop_reason, None,
                    "incomplete with no details must not claim end_turn"
                );
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

        // Branch 2: `incomplete_details` present but carries no `reason`.
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_INCOMPLETE,
            &serde_json::json!({
                "response": {"status": STATUS_INCOMPLETE, "incomplete_details": {}}
            }),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(
                    *stop_reason, None,
                    "incomplete_details without a reason must not claim end_turn"
                );
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

        // Sanity: a known reason still maps (max_output_tokens -> max_tokens).
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            EVT_RESPONSE_INCOMPLETE,
            &serde_json::json!({
                "response": {
                    "status": STATUS_INCOMPLETE,
                    "incomplete_details": {"reason": INCOMPLETE_REASON_MAX_OUTPUT}
                }
            }),
            &mut state,
        );
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::MaxTokens));
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
    }

    /// Regression (mirrors `openai_chat.rs::write_request_tool_result_multi_text_concatenates_without_separator`):
    /// a multi-block ToolResult must concatenate its text fragments with NO separator. A `.join(" ")`
    /// injects a spurious space that corrupts base64 / split-JSON payloads. Covers BOTH the
    /// Tool-role flat path AND the Assistant-role inline-tool_result path in `write_request`.
    #[test]
    fn write_request_tool_result_multi_text_concatenates_without_separator() {
        fn text_block(s: &str) -> crate::ir::IrBlock {
            crate::ir::IrBlock::Text {
                text: s.to_string(),
                cache_control: None,
                citations: Vec::new(),
            }
        }
        let writer = ResponsesWriter;
        let multi = || crate::ir::IrBlock::ToolResult {
            tool_use_id: "call_1".to_string(),
            content: vec![text_block("AAA"), text_block("BBB")],
            is_error: false,
            cache_control: None,
        };

        // Tool-role path.
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![multi()],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let item = out["input"]
            .as_array()
            .and_then(|a| a.iter().find(|m| m["type"] == "function_call_output"))
            .expect("a function_call_output item (Tool role)");
        assert_eq!(
            item["output"], "AAABBB",
            "Tool-role multi-text ToolResult must concatenate with NO separator, got {}",
            item["output"]
        );

        // Assistant-role inline tool_result path.
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![multi()],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let item = out["input"]
            .as_array()
            .and_then(|a| a.iter().find(|m| m["type"] == "function_call_output"))
            .expect("a function_call_output item (Assistant role)");
        assert_eq!(
            item["output"], "AAABBB",
            "Assistant-role multi-text ToolResult must concatenate with NO separator, got {}",
            item["output"]
        );
    }

    /// Regression: the streaming error event nests the error inside the `response` object the
    /// official SDK streaming decoder reads via `event.response`, and the error object is the
    /// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
    /// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` (or an
    /// extra `type`/`param`) is impossible from real OpenAI and a distinguishability tell.
    #[test]
    fn test_write_error_stream_event_full_shape() {
        let writer = ResponsesWriter;
        let ev = crate::ir::IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (etype, payload) = writer
            .write_response_event(&ev)
            .expect("error event should emit");
        assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
                                              // The error is nested under `response` (SDK reads `event.response`), not top-level.
        assert!(
            payload.get("error").is_none(),
            "error must not be top-level: {payload}"
        );
        let resp = payload.get("response").expect("response object present");
        assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed")); // golden wire-contract literal (kept bare on purpose)
        let err = resp.get("error").expect("nested error object present");
        assert_eq!(err.get("message").and_then(|m| m.as_str()), Some("boom"));
        // Native ResponseError: code is the non-null enum (here carried from provider_signal).
        assert_eq!(err.get("code").and_then(|c| c.as_str()), Some("boom"));
        assert!(
            !err.as_object().unwrap().contains_key("type"),
            "Responses ResponseError carries no `type` field: {err}"
        );
        assert!(
            !err.as_object().unwrap().contains_key("param"),
            "Responses ResponseError carries no `param` field: {err}"
        );
    }

    /// Regression: an unknown/unmapped stop_reason must map to a `completed` status (not `failed`),
    /// so a future IR reason that did not signal an error is not misclassified as a failure.
    #[test]
    fn test_unknown_stop_reason_maps_to_completed() {
        let writer = ResponsesWriter;
        // Streaming MessageDelta path.
        let ev = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::Refusal),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            payload
                .get("response")
                .and_then(|r| r.get("status"))
                .and_then(|s| s.as_str()),
            Some("completed"), // golden wire-contract literal (kept bare on purpose)
            "unknown stop_reason must map to completed in stream"
        );

        // Non-streaming write_response path.
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "ok".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::Refusal),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("status").and_then(|s| s.as_str()),
            Some("completed"), // golden wire-contract literal (kept bare on purpose)
            "unknown stop_reason must map to completed in write_response"
        );
    }

    /// Regression: malformed function_call arguments must be preserved as the raw string, not
    /// dropped to Null (mirrors the OpenAI reader). Covers both the request and response readers.
    #[test]
    fn test_malformed_function_call_args_preserved() {
        let reader = ResponsesReader;

        // read_request path.
        let req_json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_1", "name": "f", "arguments": "not-json{"}
            ]
        });
        let ir = reader.read_request(&req_json).expect("read_request ok");
        let tool_use = ir
            .messages
            .iter()
            .flat_map(|m| &m.content)
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolUse { input, .. } => Some(input),
                _ => None,
            })
            .expect("tool use present");
        assert_eq!(
            tool_use.as_str(),
            Some("not-json{"),
            "malformed args must be preserved as raw string, not Null"
        );

        // read_response path.
        let resp_json = serde_json::json!({
            "id": "resp_1",
            "status": STATUS_COMPLETED,
            "output": [
                {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_2", "name": "g", "arguments": "broken]"}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let resp = reader.read_response(&resp_json).expect("read_response ok");
        match &resp.content[0] {
            crate::ir::IrBlock::ToolUse { input, .. } => {
                assert_eq!(input.as_str(), Some("broken]"));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` data URI of the canonical single-`;` shape
    /// (`data:image/png;base64,<payload>`) must parse the FULL payload, not drop it to "". The old
    /// `splitn(3, ';')` logic yielded only two fields and silently discarded every image. Covers
    /// both `read_request` and `responses_block`.
    #[test]
    fn test_input_image_base64_payload_preserved() {
        let payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let url = format!("data:image/png;base64,{payload}");

        // read_request path.
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "input_image", "image_url": url}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(ir.messages.len(), 1);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 { media_type, data },
                ..
            } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload, "full base64 payload must be preserved");
            }
            other => panic!("expected Image, got {other:?}"),
        }

        // responses_block path (e.g. a content block nested in a function_call_output).
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 { media_type, data },
                ..
            } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload);
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` must survive a same-protocol read -> write -> read
    /// round-trip with its payload intact (the writer emits `data:<mime>;base64,<payload>` which the
    /// reader must parse back to the identical pair).
    #[test]
    fn test_input_image_roundtrip_lossless() {
        let payload = "QUJDMTIzKz0=";
        let media_type = "image/jpeg";
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: media_type.to_string(),
                        data: payload.to_string(),
                    },
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let writer = ResponsesWriter;
        let reader = ResponsesReader;
        let json = writer.write_request(&ir);
        let rt = reader.read_request(&json).expect("read round-trip ok");
        match &rt.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                source:
                    crate::ir::IrImageSource::Base64 {
                        media_type: mt,
                        data,
                    },
                ..
            } => {
                assert_eq!(mt, media_type);
                assert_eq!(data, payload, "round-trip must not corrupt the payload");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a non-data (https) image URL must be stored verbatim under the `image_url`
    /// sentinel media_type — NOT mangled into a `// note: non-data URL - ...` comment — and must
    /// round-trip back to the exact original URL.
    #[test]
    fn test_input_image_https_url_sentinel_roundtrip() {
        let url = "https://example.com/cat.png";
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        let stored_url = match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(url),
                ..
            } => url,
            other => panic!("expected Image(Url), got {other:?}"),
        };
        assert_eq!(
            stored_url, url,
            "URL must be stored verbatim as the typed Url source"
        );
        assert!(
            !stored_url.starts_with("// note"),
            "must not embed a human comment in the payload"
        );

        // Round-trip through the writer reconstructs the exact original image_url.
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Url(stored_url),
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
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
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let emitted = json["input"][0]["content"][0]["image_url"]
            .as_str()
            .expect("image_url present");
        assert_eq!(emitted, url, "writer must emit the original URL verbatim");
    }

    /// Regression: `write_request` must emit the `stream` field (a modeled key excluded from
    /// `extra`); omitting it answers a `stream: true` request non-streaming and stalls SSE.
    #[test]
    fn test_write_request_emits_stream() {
        let make = |stream: bool| crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
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
            tool_choice: None,
            stream,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        assert_eq!(
            writer.write_request(&make(true)).get("stream"),
            Some(&serde_json::json!(true)),
            "stream: true must be emitted"
        );
        assert_eq!(
            writer.write_request(&make(false)).get("stream"),
            Some(&serde_json::json!(false)),
            "stream: false must be emitted explicitly"
        );
    }

    /// Regression: a typed `{"type":"message","role":...,"content":[...]}` input item (the official
    /// SDK conversation-turn shape) must be read, not silently dropped.
    #[test]
    fn test_typed_message_item_read() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": ITEM_TYPE_MESSAGE, "role": "user",
                 "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hello typed"}]},
                {"type": ITEM_TYPE_MESSAGE, "role": "assistant",
                 "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi back"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(
            ir.messages.len(),
            2,
            "both typed message turns must be read"
        );
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello typed"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
        match &ir.messages[1].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi back"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Regression: the streaming `response.created` event must carry `id`/`created_at`/`status`
    /// (and `model` when present), not a stub. Forwards captured identity for same-protocol
    /// passthrough; synthesizes a valid `resp_` id + current time when the IR carries none.
    #[test]
    fn test_message_start_emits_identity() {
        let writer = ResponsesWriter;

        // Identity present (same-protocol passthrough): forwarded verbatim.
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_streamid".to_string()),
            created: Some(1_720_000_000),
            model: Some("gpt-4o".to_string()),
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.created"); // golden wire-contract literal (kept bare on purpose)
        let resp = payload.get("response").expect("response object");
        assert_eq!(
            resp.get("id").and_then(|i| i.as_str()),
            Some("resp_streamid")
        );
        assert_eq!(
            resp.get("created_at").and_then(|c| c.as_u64()),
            Some(1_720_000_000)
        );
        assert_eq!(resp.get("model").and_then(|m| m.as_str()), Some("gpt-4o"));
        assert_eq!(
            resp.get("status").and_then(|s| s.as_str()),
            Some("in_progress") // golden wire-contract literal (kept bare on purpose)
        );

        // Identity absent (cross-protocol, stripped by translate_event): synthesized + valid.
        let ev2 = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, payload2) = writer.write_response_event(&ev2).expect("should emit");
        let resp2 = payload2.get("response").expect("response object");
        let id = resp2
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
            "synthesized id must use resp_ prefix, got {id}"
        );
        assert!(
            resp2.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );
        // `Response.model` is a REQUIRED non-nullable SDK field, so an absent IR model must emit
        // the DEFAULT_MODEL fallback — NOT omit the key (which fails a strict decoder and is a
        // proxy tell).
        assert_eq!(
            resp2.get("model").and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "absent model must fall back to DEFAULT_MODEL, not be omitted"
        );
    }

    /// Regression: synthesized response ids stay distinct even across many calls in the same second
    /// (the old `timestamp << 24 ^ counter` folding collided once the counter advanced by 2^24).
    #[test]
    fn test_synthesize_response_id_unique() {
        let n = 1000;
        let ids: std::collections::HashSet<String> =
            (0..n).map(|_| synthesize_response_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "all synthesized ids in a burst must be unique"
        );
        assert!(ids.iter().all(|id| id.starts_with("resp_"))); // golden wire-contract literal (kept bare on purpose)
    }

    /// Regression (LOW/correctness, Round 18): `synth_token<const N>` documents and now ENFORCES a
    /// `N >= 11` floor via a compile-time `const _: () = assert!(N >= 11, ...)` evaluated per
    /// monomorphization. The guard cannot be exercised from a passing runtime test (a too-small `N`
    /// fails to BUILD, which a `cargo test` body can't observe without a trybuild harness), so this
    /// test instead locks the observable contract the guard protects: every synthesized id the live
    /// callers mint carries an opaque suffix at least the documented floor wide. Both call sites use
    /// 48 (`ITEM_ID_TOKEN_LEN`/`RESPONSE_ID_TOKEN_LEN`); if a future edit narrowed a width below the
    /// floor (or someone instantiated `synth_token` with `N < 11`), the build would break before this
    /// assertion could even run.
    #[test]
    fn test_synth_token_meets_minimum_width() {
        const MIN_TOKEN_LEN: usize = 11;

        // The compile-time guard is the real enforcement; this also pins that the live callers stay
        // comfortably above the floor so a regression in the width constants surfaces here too.
        const { assert!(ITEM_ID_TOKEN_LEN >= MIN_TOKEN_LEN) };
        const { assert!(RESPONSE_ID_TOKEN_LEN >= MIN_TOKEN_LEN) };

        let resp_id = synthesize_response_id();
        let resp_suffix = resp_id
            .strip_prefix("resp_") // golden wire-contract literal (kept bare on purpose)
            .expect("synthesized response id uses resp_ prefix");
        assert!(
            resp_suffix.len() >= MIN_TOKEN_LEN,
            "synthesized resp_ suffix must be >= {MIN_TOKEN_LEN} base62 chars, got {} ({resp_id})",
            resp_suffix.len()
        );

        let item_id = synthesize_item_id("msg");
        let item_suffix = item_id
            .strip_prefix("msg_") // golden wire-contract literal (kept bare on purpose)
            .expect("synthesized item id uses the given prefix");
        assert!(
            item_suffix.len() >= MIN_TOKEN_LEN,
            "synthesized item suffix must be >= {MIN_TOKEN_LEN} base62 chars, got {} ({item_id})",
            item_suffix.len()
        );
    }

    /// Regression (LOW/conformance, Round 18 verify): the streaming `response.failed` terminal event
    /// (emitted from an IR `Error`) must carry the native non-error skeleton — specifically a
    /// present-but-empty `output` array (REQUIRED by the SDK's typed `Response`), never omitting it.
    /// A failed response produced no assistant items, so `output` is `[]`. (The `output: []` emission
    /// already lived in the Error arm before Round 18; this test locks it against future regression.)
    #[test]
    fn test_response_failed_carries_empty_output_skeleton() {
        let writer = ResponsesWriter;
        let (etype, failed) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("Error emits response.failed");
        assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
        let resp = failed
            .get("response")
            .expect("response.failed wraps an inner response object");
        let output = resp
            .get("output")
            .expect("response.failed inner response must carry output, not omit it");
        assert!(
            output.as_array().is_some_and(|a| a.is_empty()),
            "response.failed output must be a present-but-empty array, got {output}"
        );
        // The native failed skeleton also carries the other non-error required fields.
        assert_eq!(
            resp.get("status").and_then(|s| s.as_str()),
            Some("failed"), // golden wire-contract literal (kept bare on purpose)
            "response.failed inner status must be \"failed\""
        );
        assert_eq!(
            resp.get("object").and_then(|o| o.as_str()),
            Some("response"), // golden wire-contract literal (kept bare on purpose)
            "response.failed inner object must be \"response\""
        );
        assert!(
            resp.get("id").and_then(|i| i.as_str()).is_some(),
            "response.failed inner response must carry an id"
        );
        assert!(
            resp.get("error").and_then(|e| e.as_object()).is_some(),
            "response.failed inner response must carry the error object"
        );
    }

    /// Regression (MEDIUM/correctness): a top-level `metadata` object must NOT be in the modeled-key
    /// exclusion set, so it flows into `IrRequest.extra` on read and is re-emitted verbatim by
    /// `write_request`. A prior revision listed `metadata` in `modeled_keys` while never emitting it,
    /// silently dropping the caller's response tagging / billing-attribution field.
    #[test]
    fn test_metadata_round_trips_through_extra() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hi"}]}],
            "metadata": {"trace_id": "abc-123", "team": "billing"}
        });
        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir = reader.read_request(&json).expect("read_request ok");
        // metadata must have landed in extra (it is not a modeled IrRequest field).
        assert_eq!(
            ir.extra.get("metadata"),
            Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
            "metadata must flow into extra, not be dropped"
        );

        // write_request forwards extra verbatim, so metadata survives to the upstream body.
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("metadata"),
            Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
            "metadata must be forwarded to the upstream Responses backend"
        );
    }

    /// Regression (MEDIUM/conformance, class: stream-start skeleton): the opening `response.created`
    /// event must carry the FULL required Response skeleton an SDK reads unconditionally — `usage`,
    /// `output`, and `error` must be PRESENT (empty/null), not omitted. Omitting `usage` left strict
    /// SDK decoders without a `Response.usage` field on the first chunk.
    #[test]
    fn test_message_start_skeleton_carries_usage_output_error() {
        let writer = ResponsesWriter;
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.created"); // golden wire-contract literal (kept bare on purpose)
        let resp = payload.get("response").expect("response object present");

        // usage key MUST be present (null at stream start), not omitted.
        assert!(
            resp.get("usage").is_some(),
            "usage key must be present on the opening chunk: {resp}"
        );
        assert!(
            resp.get("usage").unwrap().is_null(),
            "usage must be null (no tokens yet) at stream start"
        );
        // output array present-but-empty; error present-but-null.
        assert_eq!(
            resp.get("output"),
            Some(&serde_json::json!([])),
            "output must be present as an empty array"
        );
        assert!(
            resp.get("error").map(|e| e.is_null()).unwrap_or(false),
            "error key must be present and null at stream start"
        );
    }

    /// A role-only item (no `type`) must still be processed via the role fallback.
    #[test]
    fn test_role_only_item_still_processed() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hi there"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi there"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }

    /// Regression (HIGH/correctness): an array `input` must be iterated without the prior
    /// `is_array()` + `.as_array().unwrap()` pattern. Exercises the `if let Some(arr)` path and
    /// confirms array items are still decoded into messages.
    #[test]
    fn test_read_request_array_input_no_unwrap() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": CONTENT_TYPE_INPUT_TEXT, "text": "hello"},
                {"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "world"}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("array input should decode");
        assert_eq!(ir.messages.len(), 2);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
    }

    /// Regression (HIGH/correctness): a `response.failed` terminal event with NO nested `response`
    /// object (truncated SSE frame / body-stripping proxy) must NOT be decoded as a successful
    /// end_turn. It must surface as an explicit Error + MessageStop so downstream clients see the
    /// failure and the breaker receives the failure signal.
    #[test]
    fn test_failed_event_without_body_surfaces_error() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();
        let data = serde_json::json!({});
        let events = reader.read_response_events(EVT_RESPONSE_FAILED, &data, &mut state);

        assert_eq!(
            events.len(),
            2,
            "expected Error + MessageStop, got {events:?}"
        );
        match &events[0] {
            IrStreamEvent::Error(err) => {
                assert_eq!(err.class, StatusClass::ServerError);
                assert_eq!(err.provider_signal.as_deref(), Some("response_failed"));
            }
            other => panic!("expected Error first, got {other:?}"),
        }
        assert!(
            matches!(events[1], IrStreamEvent::MessageStop),
            "expected MessageStop, got {:?}",
            events[1]
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
            "a bodyless failed event must not emit a success MessageDelta"
        );
    }

    /// A `response.completed`/`response.incomplete` terminal event with no nested `response` object
    /// must still terminate the stream with a success MessageDelta + MessageStop (must NOT become an
    /// Error — only `response.failed` does).
    #[test]
    fn test_completed_event_without_body_emits_end_turn() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();
        let data = serde_json::json!({});
        let events = reader.read_response_events(EVT_RESPONSE_COMPLETED, &data, &mut state);

        assert_eq!(events.len(), 2, "expected MessageDelta + MessageStop");
        match &events[0] {
            IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::EndTurn));
            }
            other => panic!("expected MessageDelta first, got {other:?}"),
        }
        assert!(matches!(events[1], IrStreamEvent::MessageStop));
        assert!(
            !events.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
            "a bodyless completed event must not emit an Error"
        );
    }

    /// Regression (MEDIUM/conformance): the writer's `IrStreamEvent::Error` arm must emit a
    /// `response.failed` event whose error lives inside a `response` object (the shape the official
    /// SDK streaming decoder reads via `event.response`), with a synthesized `resp_` id and
    /// `status: "failed"` — NOT a top-level `{"error":{...}}`.
    #[test]
    fn test_error_event_wraps_in_response_object() {
        let writer = ResponsesWriter;
        let ev = IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("overloaded".to_string()),
            retry_after: None,
        });
        let (etype, payload) = writer
            .write_response_event(&ev)
            .expect("error event should emit");
        assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)

        // No top-level `error` key — the SDK reads `event.response`, not `event.error`.
        assert!(
            payload.get("error").is_none(),
            "error must be nested under response, not top-level: {payload}"
        );
        let resp = payload
            .get("response")
            .expect("payload must carry a `response` object");
        let id = resp
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized resp_ id present");
        assert!(
            id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
            "synthesized id must use resp_ prefix, got {id}"
        );
        assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed")); // golden wire-contract literal (kept bare on purpose)
        let error = resp.get("error").expect("nested error object");
        assert_eq!(
            error.get("message").and_then(|m| m.as_str()),
            Some("overloaded")
        );
        // Native ResponseError shape: a non-null `code` enum (carried from the provider signal),
        // and NO Chat-style `type`/`param` fields.
        assert_eq!(
            error.get("code").and_then(|c| c.as_str()),
            Some("overloaded")
        );
        assert!(
            !error.as_object().unwrap().contains_key("type"),
            "Responses ResponseError carries no `type` field: {error}"
        );
        assert!(
            !error.as_object().unwrap().contains_key("param"),
            "Responses ResponseError carries no `param` field: {error}"
        );
    }

    /// Regression (CRITICAL/conformance, class: stream event `type` discriminator): EVERY emitted
    /// Responses SSE data body must carry a top-level `"type"` key equal to its event name. The
    /// official OpenAI Python/Node streaming decoders dispatch on `data["type"]`; a body missing it
    /// (the prior `{"response":{...}}` shape) yields None/undefined for the event type and the SDK
    /// never constructs the Response or fires event handlers. This exercises all writer arms that
    /// produce a body — response.created, response.output_item.added, response.output_text.delta,
    /// response.function_call_arguments.delta, response.output_item.done, response.completed, and
    /// response.failed — and asserts `payload["type"] == event_name` for each.
    #[test]
    fn test_every_stream_event_carries_top_level_type() {
        let writer = ResponsesWriter;
        let usage = || crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
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
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "fc_1".to_string(),
                    name: "f".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage(),
            },
            IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }),
        ];

        for ev in &events {
            let (event_name, payload) = writer
                .write_response_event(ev)
                .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
            assert_eq!(
                payload.get("type").and_then(|t| t.as_str()),
                Some(event_name.as_str()),
                "event {event_name} body must carry top-level \"type\" == event name, got {payload}"
            );
        }
    }

    /// A full single-stream sequence of emitted Responses events. The events go through the writer in
    /// the order `StreamTranslate::feed` would emit them.
    fn usage_fixture() -> crate::ir::IrUsage {
        crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        }
    }

    /// Regression (HIGH/conformance): EVERY emitted Responses SSE event must carry a top-level
    /// `sequence_number` that is monotonic from 0 within a single stream. The opening
    /// `response.created` (MessageStart) resets the per-stream counter, so a fresh stream starts at 0
    /// and increases by one per emitted event. Events that produce no body do not consume a number.
    #[test]
    fn test_sequence_number_monotonic_from_zero() {
        let writer = ResponsesWriter;
        // A representative stream: created → text deltas → completed.
        let stream = vec![
            IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("Hel".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("lo".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            },
        ];

        let mut seqs = Vec::new();
        for ev in &stream {
            if let Some((_, payload)) = writer.write_response_event(ev) {
                let n = payload
                    .get("sequence_number")
                    .and_then(|s| s.as_u64())
                    .unwrap_or_else(|| {
                        panic!("every emitted event must carry sequence_number: {payload}")
                    });
                seqs.push(n);
            }
        }

        // A TEXT block's `BlockStop` emits no body (a text part has no `output_item.added`/`.done`
        // pair — its content-part lifecycle is closed upstream), so it consumes no sequence number.
        // The numbered events are therefore: created, two text deltas, completed = four events.
        assert_eq!(
            seqs,
            vec![0, 1, 2, 3],
            "sequence_number must be 0..N monotonic within the stream, got {seqs:?}"
        );
    }

    /// Regression: a SECOND stream (its own `response.created`) must restart its `sequence_number`
    /// from 0 — the counter is per-stream, not per-process. Exercises the reset-on-MessageStart
    /// contract so one stream's numbering never bleeds into the next on the same worker.
    #[test]
    fn test_sequence_number_resets_per_stream() {
        let writer = ResponsesWriter;
        let start = || IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let delta = || IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("x".to_string()),
        };

        // Stream A: created(0), delta(1).
        let (_, a0) = writer.write_response_event(&start()).expect("emit");
        let (_, a1) = writer.write_response_event(&delta()).expect("emit");
        assert_eq!(a0.get("sequence_number").and_then(|s| s.as_u64()), Some(0));
        assert_eq!(a1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));

        // Stream B begins with its own created → counter resets to 0.
        let (_, b0) = writer.write_response_event(&start()).expect("emit");
        let (_, b1) = writer.write_response_event(&delta()).expect("emit");
        assert_eq!(
            b0.get("sequence_number").and_then(|s| s.as_u64()),
            Some(0),
            "a new stream's response.created must reset sequence_number to 0"
        );
        assert_eq!(b1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));
    }

    /// Regression: every writer arm that produces a body carries `sequence_number`, not just the
    /// deltas. Mirrors `test_every_stream_event_carries_top_level_type` but asserts the integer
    /// `sequence_number` is present (and a u64) on each emitted body.
    #[test]
    fn test_every_stream_event_carries_sequence_number() {
        let writer = ResponsesWriter;
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
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "f".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            },
            IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }),
        ];

        for ev in &events {
            let (event_name, payload) = writer
                .write_response_event(ev)
                .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
            assert!(
                payload
                    .get("sequence_number")
                    .map(|s| s.is_u64())
                    .unwrap_or(false),
                "event {event_name} body must carry a u64 sequence_number, got {payload}"
            );
        }
    }

    /// Regression: `response.output_text.delta` must carry `item_id` and `content_index` (native
    /// shape), and the `output_item.added` for a function call must carry `item_id`. The
    /// `function_call_arguments.delta` carries the matching `item_id`.
    #[test]
    fn test_delta_and_item_added_carry_item_id_and_content_index() {
        let writer = ResponsesWriter;

        // Text delta.
        let (_, text) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 2,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            })
            .expect("emit");
        let text_item = text
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("output_text.delta must carry item_id");
        assert!(
            text_item.starts_with("msg_"), // golden wire-contract literal (kept bare on purpose)
            "text delta item_id must be a msg_ id, got {text_item}"
        );
        assert_eq!(
            text.get("content_index").and_then(|c| c.as_u64()),
            Some(0),
            "output_text.delta must carry content_index"
        );

        // output_item.added for a function call.
        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_9".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("emit");
        let added_item = added
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("output_item.added must carry item_id");
        assert!(
            added_item.starts_with("fc_"), // golden wire-contract literal (kept bare on purpose)
            "function_call item_id must be an fc_ id, got {added_item}"
        );
        // The nested item id matches the top-level item_id (one logical item).
        assert_eq!(
            added
                .get("item")
                .and_then(|i| i.get("id"))
                .and_then(|i| i.as_str()),
            Some(added_item),
            "nested item.id must equal the top-level item_id"
        );

        // The function_call_arguments.delta at the same index reuses the same fc_ item_id.
        let (_, args) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 1,
                delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
            })
            .expect("emit");
        assert_eq!(
            args.get("item_id").and_then(|i| i.as_str()),
            Some(added_item),
            "arguments delta item_id must match the item's added item_id (stable per index)"
        );
    }

    /// Regression (HIGH/correctness): the `sequence_number` counter is PER-STREAM INSTANCE state,
    /// not thread-local. Two distinct writer instances model two concurrent streams sharing one
    /// worker thread. Interleave their events (A.start, B.start, A.delta, B.delta, ...) — the way a
    /// Tokio work-stealing runtime can schedule two parked stream tasks on the same thread. Each
    /// writer's sequence must stay monotonic-from-0 with NO bleed from the other stream's resets or
    /// increments. With the old thread-local cell, B's `MessageStart` reset clobbered A's in-flight
    /// counter and A's next event would restart non-monotonically; here the counters are independent.
    #[test]
    fn test_sequence_number_is_per_instance_not_thread_local() {
        let stream_a = ResponsesWriter;
        let stream_b = ResponsesWriter;
        let start = || IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let delta = || IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("x".to_string()),
        };
        let seq = |opt: Option<(String, serde_json::Value)>| {
            opt.expect("emit")
                .1
                .get("sequence_number")
                .and_then(|s| s.as_u64())
                .expect("sequence_number present")
        };

        // Interleave the two streams on the same "thread".
        let a0 = seq(stream_a.write_response_event(&start())); // A: 0
        let b0 = seq(stream_b.write_response_event(&start())); // B: 0 (must NOT touch A)
        let a1 = seq(stream_a.write_response_event(&delta())); // A: 1
        let b1 = seq(stream_b.write_response_event(&delta())); // B: 1
        let a2 = seq(stream_a.write_response_event(&delta())); // A: 2
        let b2 = seq(stream_b.write_response_event(&delta())); // B: 2

        assert_eq!(
            (a0, a1, a2),
            (0, 1, 2),
            "stream A must stay monotonic-from-0 despite stream B interleaving"
        );
        assert_eq!(
            (b0, b1, b2),
            (0, 1, 2),
            "stream B must stay monotonic-from-0 independent of stream A"
        );
    }

    /// Regression (HIGH/conformance): `response.output_item.done` must carry a stable `item_id`
    /// that matches the `response.output_item.added` for the same output index, plus a typed `item`
    /// object — an SDK reading `event.item_id`/`event.item` off the `done` event must not see
    /// `undefined`. The `added` for a function call and the `done` at the same index share the id.
    #[test]
    fn test_output_item_done_carries_matching_item_id_and_item() {
        let writer = ResponsesWriter;

        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 3,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_x".to_string(),
                    name: "f".to_string(),
                },
            })
            .expect("added emits");
        let added_id = added
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("added carries item_id")
            .to_string();

        let (etype, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 3 })
            .expect("done emits");
        assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            done.get("item_id").and_then(|i| i.as_str()),
            Some(added_id.as_str()),
            "output_item.done item_id must match the output_item.added at the same index"
        );
        // A typed `item` object is present (not undefined / not a bare {}).
        let item = done
            .get("item")
            .and_then(|i| i.as_object())
            .expect("output_item.done must carry an item object");
        assert_eq!(
            item.get("type").and_then(|t| t.as_str()),
            Some("function_call"), // golden wire-contract literal (kept bare on purpose)
            "the done item must be typed"
        );
        assert_eq!(
            item.get("id").and_then(|i| i.as_str()),
            Some(added_id.as_str()),
            "the done item.id must equal the item_id"
        );
    }

    /// Regression (MEDIUM/conformance): the in-band `response.failed` error object is the
    /// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
    /// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` is
    /// impossible from real OpenAI and a distinguishability tell.
    #[test]
    fn test_response_failed_uses_native_responseerror_shape() {
        let writer = ResponsesWriter;

        // With a provider signal: it becomes the non-null code enum AND the message.
        let (etype, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("rate_limit_exceeded".to_string()),
                retry_after: None,
            }))
            .expect("emit");
        assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
        let error = payload
            .get("response")
            .and_then(|r| r.get("error"))
            .and_then(|e| e.as_object())
            .expect("response.error object present");
        assert_eq!(
            error.get("code").and_then(|c| c.as_str()),
            Some("rate_limit_exceeded"), // golden wire-contract literal (kept bare on purpose)
            "error.code must be the non-null Responses error enum"
        );
        assert_eq!(
            error.get("message").and_then(|m| m.as_str()),
            Some("rate_limit_exceeded") // golden wire-contract literal (kept bare on purpose)
        );
        assert!(
            !error.contains_key("type"),
            "Responses ResponseError carries no `type` field"
        );
        assert!(
            !error.contains_key("param"),
            "Responses ResponseError carries no `param` field"
        );

        // Without a provider signal: code defaults to the canonical `server_error`, never null.
        let (_, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: None,
                retry_after: None,
            }))
            .expect("emit");
        let code = payload
            .get("response")
            .and_then(|r| r.get("error"))
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str());
        assert_eq!(
            code,
            Some("server_error"), // golden wire-contract literal (kept bare on purpose)
            "error.code must default to server_error, never null"
        );
    }

    /// REGRESSION (audit c2r2): on a cross-protocol / transport-abort path `provider_signal` carries
    /// a HUMAN sentence (e.g. `STREAM_ABORT_DETAIL`), NOT a Responses code enum. `error.code` must be
    /// DERIVED from the class (a valid enum an SDK can switch on), while `error.message` keeps the
    /// human text — the old code forwarded the sentence as the `code` enum, breaking typed SDKs.
    #[test]
    fn test_response_failed_code_is_enum_even_for_human_provider_signal() {
        let writer = ResponsesWriter;
        let (_, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some(crate::proto::STREAM_ABORT_DETAIL.to_string()),
                retry_after: None,
            }))
            .expect("emit");
        let error = payload
            .get("response")
            .and_then(|r| r.get("error"))
            .and_then(|e| e.as_object())
            .expect("error object");
        assert_eq!(
            error.get("code").and_then(|c| c.as_str()),
            Some("server_error"),
            "a human provider_signal must NOT leak as the code enum — derive it from the class"
        );
        assert_eq!(
            error.get("message").and_then(|m| m.as_str()),
            Some(crate::proto::STREAM_ABORT_DETAIL),
            "the human text stays in `message`"
        );

        // An auth-class transport error derives the auth code enum, not the human string.
        let (_, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::Auth,
                provider_signal: Some("connection reset by peer".to_string()),
                retry_after: None,
            }))
            .expect("emit");
        assert_eq!(
            payload
                .pointer("/response/error/code")
                .and_then(|c| c.as_str()),
            Some(ERR_TYPE_AUTHENTICATION)
        );
    }

    /// Regression (HIGH/correctness+conformance): a TEXT block's `BlockStop` must emit NOTHING from
    /// the Responses writer. The Text `BlockStart` arm emits no `output_item.added`, so emitting an
    /// `output_item.done` (with `type:"function_call"`, as a prior revision did) would be an
    /// unmatched lifecycle event AND mis-type a text response as a function call — both break a
    /// typed Responses SDK and are distinguishability tells.
    /// Regression (HIGH/conformance, Round 10): a TEXT part must be bracketed inside a `message`
    /// output item. The Text BlockStart emits `response.output_item.added` (type "message") and the
    /// Text BlockStop emits the matching `response.output_item.done` (type "message") carrying the
    /// SAME `msg_…` `item_id`. Previously the text BlockStart returned None and the BlockStop
    /// returned None, leaving the `output_text.delta`s orphaned with no parent item — so a typed SDK
    /// never materialized the assistant message in `response.output[]`.
    #[test]
    fn test_text_block_emits_message_item_lifecycle() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // Text BlockStart now opens a message item.
        let (added_et, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("text BlockStart opens a message item");
        assert_eq!(added_et, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(added["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(added["item"]["role"], "assistant");
        let added_item_id = added["item_id"]
            .as_str()
            .expect("item_id present")
            .to_string();
        assert!(added_item_id.starts_with("msg_"), "text item id is msg_…"); // golden wire-contract literal (kept bare on purpose)

        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        });

        // Text BlockStop now closes the message item with a matching done.
        let (done_et, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("text BlockStop closes the message item");
        assert_eq!(done_et, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(done["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            done["item_id"].as_str(),
            Some(added_item_id.as_str()),
            "done item_id matches the added item_id (added→done correlation)"
        );

        // A SECOND BlockStop at the (already-closed) text index must NOT re-emit a done.
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
                .is_none(),
            "a repeated BlockStop for a closed text index must not re-emit output_item.done"
        );
    }

    /// Regression (HIGH): an interleaved tool+text stream closes the tool index with a
    /// `function_call` done and the text index with a `message` done — each with its own typed
    /// item, never cross-typed. Exercises the per-stream open-index tracking so a text index is
    /// never mistaken for a function-call item and vice-versa.
    #[test]
    fn test_tool_and_text_block_stop_emit_correctly_typed_done() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // Tool at index 0, text at index 1.
        let _ = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "f".to_string(),
                },
            })
            .expect("tool added emits");
        let _ = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("text added emits");
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        });
        // Tool index closes with a function_call done.
        let (etype, tool_done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("tool BlockStop emits output_item.done");
        assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(tool_done["item"]["type"], "function_call"); // golden wire-contract literal (kept bare on purpose)
                                                                // Text index closes with a message done.
        let (text_et, text_done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .expect("text BlockStop emits output_item.done (message)");
        assert_eq!(text_et, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(text_done["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
                                                          // A SECOND BlockStop at the (already-closed) tool index 0 must not emit a duplicate done.
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
                .is_none(),
            "a repeated BlockStop for a closed tool index must not re-emit output_item.done"
        );
    }

    /// Regression (HIGH/conformance): the terminal `response.completed` event's inner `response`
    /// object must carry both `id` (a `resp_…` string) and `created_at` (a unix-seconds integer).
    /// The official SDKs read `event.response.id` on the terminal event to finalize the Response;
    /// omitting it breaks correlation and is a distinguishability tell (a real stream never sends a
    /// terminal event without an id).
    #[test]
    fn test_completed_event_carries_id_and_created_at() {
        let writer = ResponsesWriter;
        let (etype, payload) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        let resp = payload
            .get("response")
            .and_then(|r| r.as_object())
            .expect("response object present");
        let id = resp
            .get("id")
            .and_then(|i| i.as_str())
            .expect("response.completed must carry response.id");
        assert!(
            id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
            "synthesized id must be a resp_ id, got {id}"
        );
        assert!(
            resp.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "response.completed must carry an integer created_at"
        );
    }

    /// Regression (MEDIUM/conformance): `write_error` must emit `code:"invalid_api_key"` for an
    /// authentication failure (mirrors `openai_chat.rs` `write_error_emits_invalid_api_key_code_for_auth_failure`).
    /// Emitting `code:null` on auth is a deterministic proxy tell vs a real OpenAI Responses 401.
    #[test]
    fn write_error_emits_invalid_api_key_code_for_auth_failure() {
        let writer = ResponsesWriter;
        for kind in ["authentication", "authentication_error", "auth"] {
            let body = writer.write_error(401, kind, "bad key");
            assert_eq!(
                body["error"]["type"],
                serde_json::json!("authentication_error"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind} must map to authentication_error"
            );
            assert_eq!(
                body["error"]["code"],
                serde_json::json!("invalid_api_key"),
                "auth failure (kind {kind}) must carry code=invalid_api_key, not null"
            );
        }
    }

    /// Regression (MEDIUM/conformance): non-auth, non-quota error kinds keep `code:null` — the
    /// native shape when no machine-readable code applies — so only the auth and quota paths are
    /// special-cased.
    #[test]
    fn write_error_keeps_null_code_for_non_auth_errors() {
        let writer = ResponsesWriter;
        for kind in [
            "invalid_request",
            "permission",
            "not_found",
            "rate_limit",
            "server_error",
        ] {
            let body = writer.write_error(400, kind, "msg");
            assert_eq!(
                body["error"]["code"],
                serde_json::Value::Null,
                "non-auth/non-quota kind {kind} must keep code=null"
            );
        }
    }

    /// Regression (LOW/conformance): the over-quota path carries a populated machine-readable
    /// `code` — native OpenAI/Responses emits `{"type":"insufficient_quota","code":"insufficient_quota"}`
    /// — so a `code:null` here (the old behavior) would be a fingerprintable divergence. The
    /// `billing` kind (router vocabulary) is normalized to the native `insufficient_quota` type.
    #[test]
    fn write_error_insufficient_quota_keeps_type_and_sets_code() {
        let writer = ResponsesWriter;
        for kind in ["insufficient_quota", "billing"] {
            let body = writer.write_error(429, kind, "over quota");
            assert_eq!(
                body["error"]["type"],
                serde_json::json!("insufficient_quota"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind} maps to the native insufficient_quota type"
            );
            assert_eq!(
                body["error"]["code"],
                serde_json::json!("insufficient_quota"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind} must carry code=insufficient_quota, not null"
            );
        }
    }

    /// Regression (MEDIUM/correctness): a native text item is closed by BOTH `content_part.done`
    /// and `output_item.done` at the SAME `output_index`. The reader must emit EXACTLY ONE
    /// `BlockStop` for that index — the second terminal frame is a no-op — so a downstream writer
    /// does not emit a duplicate `content_block_stop`.
    #[test]
    fn test_paired_content_and_item_done_emits_single_block_stop() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a text block lazily.
        let _ = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // First terminal frame: content_part.done → one BlockStop, clears the open index.
        let first = reader_read_response_events(
            "response.content_part.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(
            first.len(),
            1,
            "content_part.done closes the text block once"
        );
        assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // Second terminal frame at the same index: output_item.done → NOTHING (already closed).
        let second = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert!(
            second.is_empty(),
            "the second terminal frame for one text item must not emit a duplicate BlockStop, got {second:?}"
        );
    }

    /// Regression (MEDIUM/correctness): a tool item opened by `output_item.added` is closed by a
    /// single `output_item.done`, and a stray second `done` at that index emits nothing.
    #[test]
    fn test_tool_item_done_emits_single_block_stop() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 2,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
            }),
            &mut state,
        );
        let first = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 2}),
            &mut state,
        );
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0],
            crate::ir::IrStreamEvent::BlockStop { index: 2 }
        ));
        let second = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 2}),
            &mut state,
        );
        assert!(
            second.is_empty(),
            "a closed tool index must not re-emit BlockStop, got {second:?}"
        );
    }

    /// Regression (CRITICAL/conformance + HIGH/correctness, Round 10): every lifecycle event in ONE
    /// stream must carry the SAME `response.id`. On a cross-protocol stream the IR strips identity
    /// (id == None), so `response.created` synthesizes a `resp_` id which MUST be replayed verbatim
    /// on `response.completed`. Before the per-stream `response_id` cell, `MessageDelta` minted a
    /// fresh id, so the terminal event's id differed from `response.created` — SDK-breaking.
    #[test]
    fn test_terminal_id_matches_created_id_cross_protocol() {
        let writer = ResponsesWriter;
        // Cross-protocol: id is None, so response.created synthesizes one.
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("MessageStart emits response.created");
        let created_id = created["response"]["id"]
            .as_str()
            .expect("created carries id")
            .to_string();
        assert!(created_id.starts_with("resp_")); // golden wire-contract literal (kept bare on purpose)

        let (etype, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits terminal");
        assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            completed["response"]["id"].as_str(),
            Some(created_id.as_str()),
            "response.completed.id must equal response.created.id (same stream, same id)"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a `response.failed` (from an IR Error) must carry
    /// the SAME `response.id` as the opening `response.created`, so an SDK correlates the failure
    /// with the in-flight Response. Before the carried-id cell, the Error arm synthesized a fresh
    /// id distinct from `response.created`.
    #[test]
    fn test_failed_id_matches_created_id_cross_protocol() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("MessageStart emits response.created");
        let created_id = created["response"]["id"].as_str().unwrap().to_string();

        let (etype, failed) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("Error emits response.failed");
        assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            failed["response"]["id"].as_str(),
            Some(created_id.as_str()),
            "response.failed.id must equal response.created.id"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a same-protocol passthrough forwards the upstream
    /// `id` on `response.created`, and that SAME id must be replayed on the terminal event.
    #[test]
    fn test_terminal_id_matches_forwarded_created_id() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_upstream123".to_string()),
                created: Some(42),
                model: None,
            })
            .expect("emit");
        assert_eq!(created["response"]["id"].as_str(), Some("resp_upstream123"));
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(
            completed["response"]["id"].as_str(),
            Some("resp_upstream123"),
            "terminal event must replay the forwarded upstream id"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a fresh stream's `response.created` REPLACES the
    /// carried id, so a reused/cloned writer never leaks the previous stream's id onto a new
    /// stream's terminal event. (`reset_sequence_number` clears the cell; `MessageStart` sets it.)
    #[test]
    fn test_carried_id_resets_per_stream() {
        let writer = ResponsesWriter;
        // Stream A.
        let (_, a_created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_A".to_string()),
                created: None,
                model: None,
            })
            .expect("emit");
        assert_eq!(a_created["response"]["id"].as_str(), Some("resp_A"));
        // Stream B begins on the same writer instance.
        let (_, b_created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_B".to_string()),
                created: None,
                model: None,
            })
            .expect("emit");
        assert_eq!(b_created["response"]["id"].as_str(), Some("resp_B"));
        let (_, b_completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(
            b_completed["response"]["id"].as_str(),
            Some("resp_B"),
            "stream B's terminal id must be B's, not A's leaked id"
        );
    }

    /// Regression (HIGH/security, Round 10): a backend that emits a `response.output_item.added`
    /// for each of many unique `output_index` values must NOT grow `state.open_tools` without
    /// bound. After feeding more than MAX_OPEN_TOOLS distinct indices, the tracked set is capped.
    #[test]
    fn test_reader_open_tools_is_capped() {
        let mut state = crate::ir::StreamDecodeState::default();
        for i in 0..(MAX_OPEN_TOOLS as u64 + 200) {
            let _ = reader_read_response_events(
                EVT_OUTPUT_ITEM_ADDED,
                &serde_json::json!({
                    "output_index": i,
                    "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
                }),
                &mut state,
            );
        }
        assert!(
            state.open_tools.len() <= MAX_OPEN_TOOLS,
            "open_tools must be capped at MAX_OPEN_TOOLS, got {}",
            state.open_tools.len()
        );
    }

    /// Regression (HIGH/security, Round 10): a crafted huge `output_index` must be clamped to
    /// MAX_OUTPUT_INDEX before the usize cast/insert, so the tracked index never exceeds the cap and
    /// downstream index arithmetic stays bounded.
    #[test]
    fn test_reader_output_index_clamped() {
        let mut state = crate::ir::StreamDecodeState::default();
        let out = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": u64::MAX,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        match out.first() {
            Some(crate::ir::IrStreamEvent::BlockStart { index, .. }) => {
                assert_eq!(*index, MAX_OUTPUT_INDEX, "u64::MAX index must clamp to cap");
            }
            other => panic!("expected a clamped BlockStart, got {other:?}"),
        }
        assert!(state.open_tools.contains(&MAX_OUTPUT_INDEX));
        assert!(!state.open_tools.iter().any(|&i| i > MAX_OUTPUT_INDEX));
    }

    /// Regression (HIGH/security, Round 10): the writer's open-text-index set is also capped so a
    /// pathological stream of unique text BlockStarts cannot grow per-stream writer memory without
    /// bound.
    #[test]
    fn test_writer_open_text_indices_capped() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let mut opened = 0usize;
        for i in 0..(MAX_OPEN_TOOLS + 200) {
            if writer
                .write_response_event(&IrStreamEvent::BlockStart {
                    index: i,
                    block: crate::ir::IrBlockMeta::Text,
                })
                .is_some()
            {
                opened += 1;
            }
        }
        assert!(
            opened <= MAX_OPEN_TOOLS,
            "writer must open at most MAX_OPEN_TOOLS text items, opened {opened}"
        );
    }

    /// Regression (LOW/resource, R21 #20): `mark_tool_open` must apply the same cardinality
    /// discipline as `open_text_item` — a `contains` guard (idempotent re-mark) plus a
    /// `MAX_OPEN_TOOLS` cap — so a pathological backend streaming an unbounded run of distinct
    /// function-call indices cannot grow `open_tool_indices` without bound (memory exhaustion).
    /// Before the fix this set grew one entry per distinct index with no ceiling.
    #[test]
    fn test_writer_open_tool_indices_capped() {
        let writer = ResponsesWriter;
        // Feed many distinct indices: re-marking is idempotent and the set is capped.
        for i in 0..(MAX_OPEN_TOOLS + 200) {
            writer.mark_tool_open(i);
        }
        // Re-mark already-tracked indices: must not grow the set further.
        for i in 0..MAX_OPEN_TOOLS {
            writer.mark_tool_open(i);
        }
        let len = writer
            .open_tool_indices
            .lock()
            .map(|s| s.len())
            .expect("lock held only by this test");
        assert!(
            len <= MAX_OPEN_TOOLS,
            "open_tool_indices must be capped at MAX_OPEN_TOOLS, got {len}"
        );
    }

    /// Regression (MED/completeness, R21 #17): production `extract_error` must synthesize the
    /// canonical `context_length_exceeded` code when an oversized-context error carries the
    /// condition only in its MESSAGE (null/generic `code`). Without this the breaker pipeline never
    /// sees `StatusClass::ContextLength` and oversized-request failover does not trigger for this
    /// protocol. Mirrors anthropic.rs's message-scan synthesis. Before the fix `provider_code` was
    /// `None` here (only the `#[cfg(test)] classify()` helper recognized the message).
    #[test]
    fn test_extract_error_synthesizes_context_length_from_message() {
        let reader = ResponsesReader;
        // A real OpenAI-shaped oversized-context body: the canonical code is absent; the signal
        // lives in the human-readable message.
        let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens. Please reduce the length of the messages.","type":"invalid_request_error","param":"messages","code":null}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"), // golden wire-contract literal (kept bare on purpose)
            "message-only context-length error must synthesize the canonical code for failover"
        );
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("invalid_request_error")
        );
    }

    /// A native body that already carries `code: "context_length_exceeded"` must pass through
    /// unchanged (the synthesis is `.or_else`, so a real code always wins).
    #[test]
    fn test_extract_error_preserves_native_context_length_code() {
        let reader = ResponsesReader;
        let body = br#"{"error":{"message":"too long","type":"invalid_request_error","code":"context_length_exceeded"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
        );
    }

    /// A non-context-length error must NOT be mislabelled as context-length (no false positives
    /// from the message scan).
    #[test]
    fn test_extract_error_unrelated_error_not_context_length() {
        let reader = ResponsesReader;
        let body = br#"{"error":{"message":"Incorrect API key provided.","type":"authentication_error","code":"invalid_api_key"}}"#;
        let raw = reader.extract_error(StatusCode::UNAUTHORIZED, body);
        assert_eq!(raw.provider_code.as_deref(), Some("invalid_api_key"));
    }

    /// Regression (MED/breaker-conformance): the message-only context-length synthesis is GATED to
    /// the oversized HTTP statuses (400/413), mirroring `OpenAiReader::extract_error`. A 429 (or 401,
    /// 5xx) whose prose happens to contain "maximum context length" must NOT synthesize
    /// `context_length_exceeded` — otherwise the breaker maps it to ContextLength and the genuine
    /// rate-limit/auth/server failure escapes fault attribution (no fault recorded). This test FAILS
    /// on the un-gated code (which synthesized the code from the message regardless of status) and
    /// passes with the status gate.
    #[test]
    fn test_extract_error_oversized_phrase_on_non_oversized_status_not_synthesized() {
        let reader = ResponsesReader;
        // A 429 whose body carries no canonical code but whose message contains the context-length
        // phrase. The gate must block synthesis so this stays a rate-limit (not ContextLength).
        let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"rate_limit_error","code":null}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            None,
            "a 429 mentioning context length must NOT be reclassified as context_length_exceeded"
        );
        // And the same body on a 401 must likewise not synthesize.
        let raw_401 = reader.extract_error(StatusCode::UNAUTHORIZED, body);
        assert_eq!(
            raw_401.provider_code.as_deref(),
            None,
            "a 401 mentioning context length must NOT be reclassified as context_length_exceeded"
        );
    }

    /// `ResponsesReader::classify` delegates to `super::openai_family::openai_classify`
    /// (single-sourced after dedup). Every other reader has a direct `classify` test, but the Responses delegate was only
    /// ever exercised through OpenAi's copy — this guards the delegation directly, mirroring
    /// `test_openai_classify`. 429 → RateLimit.
    #[test]
    fn test_responses_classify_delegates() {
        let reader = ResponsesReader;
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // After the `openai_classify` oversized-status gate fix, a 429 whose body carries the
        // context-length prose (but no canonical code) must classify as RateLimit, NOT ContextLength
        // — the gate blocks the un-gated message scan from hijacking a genuine rate-limit signal.
        let ctx_body =
            br#"{"error":{"message":"This model's maximum context length is 8192 tokens."}}"#;
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, ctx_body);
        assert_eq!(
            signal.class,
            StatusClass::RateLimit,
            "a 429 mentioning context length must stay RateLimit, not ContextLength"
        );
    }

    /// Regression (HIGH/conformance, Round 11): a max_tokens-truncated stream's terminal event must
    /// be `response.incomplete` (event name AND inner `type`), NOT `response.completed`. A native
    /// stream never wraps a `status:"incomplete"` response in a `response.completed` envelope; the
    /// SDKs dispatch on the event `type`, so the previous always-`response.completed` arm mislabelled
    /// every truncated generation.
    #[test]
    fn test_terminal_incomplete_emits_response_incomplete_for_max_tokens() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits a terminal event");
        assert_eq!(
            etype,
            "response.incomplete", // golden wire-contract literal (kept bare on purpose)
            "max_tokens truncation must use the response.incomplete event name"
        );
        assert_eq!(
            body["type"].as_str(),
            Some("response.incomplete"), // golden wire-contract literal (kept bare on purpose)
            "inner dispatch type must agree with the event name"
        );
        assert_eq!(
            body["response"]["status"].as_str(),
            Some("incomplete"), // golden wire-contract literal (kept bare on purpose)
            "inner status stays incomplete"
        );
        assert_eq!(
            body["response"]["incomplete_details"]["reason"].as_str(),
            Some("max_output_tokens"), // golden wire-contract literal (kept bare on purpose)
            "incomplete_details.reason maps max_tokens → max_output_tokens"
        );
    }

    /// Regression (HIGH/conformance, Round 11): a safety/content-filter stop is also `incomplete`,
    /// so its terminal event is `response.incomplete` with reason `content_filter`.
    #[test]
    fn test_terminal_incomplete_emits_response_incomplete_for_safety() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::Safety),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits a terminal event");
        assert_eq!(etype, "response.incomplete"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(body["type"].as_str(), Some("response.incomplete")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            body["response"]["incomplete_details"]["reason"].as_str(),
            Some("content_filter") // golden wire-contract literal (kept bare on purpose)
        );
    }

    /// Regression (HIGH/conformance, Round 11): a normally-completed stream still emits
    /// `response.completed` with inner type/status `completed` — the fix must not regress the
    /// success path. The carried id must still match `response.created`.
    #[test]
    fn test_terminal_completed_unchanged_for_end_turn() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("created");
        let created_id = created["response"]["id"].as_str().unwrap().to_string();
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal");
        assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(body["type"].as_str(), Some("response.completed")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(body["response"]["status"].as_str(), Some("completed")); // golden wire-contract literal (kept bare on purpose)
        assert!(body["response"].get("incomplete_details").is_none());
        assert_eq!(body["response"]["id"].as_str(), Some(created_id.as_str()));
    }

    /// Regression (HIGH/conformance, Round 11): write_error must NOT leak the Anthropic-vocabulary
    /// `overloaded` type to an OpenAI-family client. A 503 exhaustion/timeout (forward.rs passes
    /// kind `"overloaded"`) maps onto the native `server_error`.
    #[test]
    fn test_write_error_maps_overloaded_to_server_error() {
        let writer = ResponsesWriter;
        for kind in [
            "overloaded",
            ERR_TYPE_OVERLOADED,
            "service_unavailable",
            "unavailable",
        ] {
            let v = writer.write_error(503, kind, "upstream busy");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("server_error"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind:?} must map to server_error, never leak overloaded"
            );
            // `server_error` carries no machine-readable code in the native shape.
            assert!(v["error"]["code"].is_null(), "server_error code is null");
        }
    }

    /// Regression (MEDIUM/security, Round 11): synthesized `resp_` ids must be opaque base62 of
    /// native length with NO embedded timestamp or sequential structure, so an observer cannot
    /// fingerprint a proxied response or extract the server clock from the id.
    #[test]
    fn test_synthesize_response_id_is_opaque_native_length() {
        let id = synthesize_response_id();
        let suffix = id.strip_prefix("resp_").expect("resp_ prefix");
        assert_eq!(
            suffix.len(),
            RESPONSE_ID_TOKEN_LEN,
            "native-length suffix: {id}"
        );
        assert!(
            suffix.len() >= 38,
            "at least the native ~38-char profile: {id}"
        );
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "opaque base62 suffix only: {id}"
        );
        // Exactly one delimiter (the prefix's underscore) — no internal timestamp/counter fields.
        assert_eq!(
            id.matches('_').count(),
            1,
            "no internal field delimiter: {id}"
        );
    }

    /// Regression (MEDIUM/security, Round 11): synthesized `msg_`/`fc_` item ids must be opaque
    /// base62 of native length, NOT the old sequential `msg_00000000` positional hex.
    #[test]
    fn test_synthesize_item_id_is_opaque_native_length() {
        for prefix in ["msg", "fc"] {
            let id = synthesize_item_id(prefix);
            let suffix = id
                .strip_prefix(&format!("{prefix}_"))
                .expect("prefix present");
            assert_eq!(
                suffix.len(),
                ITEM_ID_TOKEN_LEN,
                "native-length suffix: {id}"
            );
            assert!(
                suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
                "opaque base62 suffix: {id}"
            );
            // The old form was zero-padded hex (all low chars); assert it is no longer a pure
            // zero-prefixed positional counter by requiring it differ from the sequential shape.
            assert_ne!(
                suffix,
                "0".repeat(ITEM_ID_TOKEN_LEN),
                "not all-zero positional: {id}"
            );
        }
    }

    /// Synthesized ids must be unique across calls even in a tight loop (the monotonic counter folded
    /// into the token guarantees this independent of the RNG).
    #[test]
    fn test_synthesized_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(synthesize_response_id()), "duplicate resp_ id");
            assert!(seen.insert(synthesize_item_id("msg")), "duplicate msg_ id");
        }
    }

    /// The writer's `item_id_for` cache must return the SAME opaque id for a `(prefix, index)` across
    /// the item's lifecycle (so `output_item.added`/delta/`output_item.done` correlate), distinct ids
    /// for different indices, and a fresh id for a new stream after `reset_sequence_number`.
    #[test]
    fn test_item_id_for_is_stream_stable_and_opaque() {
        let writer = ResponsesWriter;
        let a1 = writer.item_id_for("msg", 0);
        let a2 = writer.item_id_for("msg", 0);
        assert_eq!(
            a1, a2,
            "same (prefix,index) yields a stable id within a stream"
        );
        assert!(a1.starts_with("msg_")); // golden wire-contract literal (kept bare on purpose)
        let b = writer.item_id_for("msg", 1);
        assert_ne!(a1, b, "different indices get distinct ids");
        let fc = writer.item_id_for("fc", 0);
        assert_ne!(
            a1, fc,
            "different prefixes at the same index get distinct ids"
        );
        assert!(fc.starts_with("fc_")); // golden wire-contract literal (kept bare on purpose)

        // A new stream (reset) mints a fresh id for the same key.
        writer.reset_sequence_number();
        let a_after = writer.item_id_for("msg", 0);
        assert_ne!(
            a1, a_after,
            "a reused writer must not replay a previous stream's item id"
        );
    }

    /// Full streamed text item: the `output_item.added`, every `output_text.delta`, and the closing
    /// `output_item.done` must all carry the SAME `item_id` so a typed SDK correlates the lifecycle.
    #[test]
    fn test_streamed_text_item_shares_one_item_id() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("output_item.added");
        let added_id = added["item_id"].as_str().unwrap().to_string();
        assert!(added_id.starts_with("msg_")); // golden wire-contract literal (kept bare on purpose)

        let (_, delta) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
            })
            .expect("output_text.delta");
        assert_eq!(delta["item_id"].as_str(), Some(added_id.as_str()));

        let (_, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("output_item.done");
        assert_eq!(
            done["item_id"].as_str(),
            Some(added_id.as_str()),
            "added/delta/done must share one item_id"
        );
        assert_eq!(done["item"]["id"].as_str(), Some(added_id.as_str()));
    }

    /// Regression (HIGH/correctness, Round 12): the cardinality-cap guard on
    /// `response.output_item.added` was inverted (`if already_open || ...`), re-emitting a BlockStart
    /// for an index that was already open. A repeated `output_item.added` for the SAME function-call
    /// index must NOT produce a second BlockStart (only the first added opens the block); the second
    /// is a no-op. Otherwise downstream sees BlockStart→BlockStart for one block — an invalid
    /// sequence and a proxy tell.
    #[test]
    fn test_repeated_output_item_added_does_not_reemit_block_start() {
        let mut state = crate::ir::StreamDecodeState::default();
        let item = serde_json::json!({
            "output_index": 0,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
        });
        let first = reader_read_response_events(EVT_OUTPUT_ITEM_ADDED, &item, &mut state);
        assert_eq!(
            first.len(),
            1,
            "the first output_item.added opens exactly one BlockStart"
        );
        assert!(matches!(
            first.first(),
            Some(crate::ir::IrStreamEvent::BlockStart { index: 0, .. })
        ));
        // A second added for the SAME index must emit nothing (the block is already open).
        let second = reader_read_response_events(EVT_OUTPUT_ITEM_ADDED, &item, &mut state);
        assert!(
            second.is_empty(),
            "a repeated output_item.added for an open index must not re-emit BlockStart, got {second:?}"
        );
        assert_eq!(
            state.open_tools.len(),
            1,
            "the index is tracked exactly once"
        );
    }

    /// Regression (HIGH/correctness, Round 12): the fixed guard must STILL bound new distinct
    /// indices under MAX_OPEN_TOOLS — the inversion fix must not weaken the DoS cap. Beyond the cap
    /// a NEW index emits no BlockStart and is not tracked.
    #[test]
    fn test_cap_still_bounds_new_indices_after_guard_fix() {
        let mut state = crate::ir::StreamDecodeState::default();
        for i in 0..(MAX_OPEN_TOOLS as u64) {
            let out = reader_read_response_events(
                EVT_OUTPUT_ITEM_ADDED,
                &serde_json::json!({
                    "output_index": i,
                    "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
                }),
                &mut state,
            );
            assert_eq!(out.len(), 1, "each fresh in-cap index opens one BlockStart");
        }
        assert_eq!(state.open_tools.len(), MAX_OPEN_TOOLS);
        // A fresh index beyond the cap (use a distinct, un-clamped value below MAX_OUTPUT_INDEX is
        // impossible here since indices 0..128 already fill it; use a high index that clamps to a
        // value already present is not a "new" index, so instead assert no growth past the cap).
        let over = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": (MAX_OPEN_TOOLS as u64) + 50,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        // The over-cap index clamps to MAX_OUTPUT_INDEX (127), which is already open (it was inserted
        // in the loop), so by the already-open rule it emits nothing and does not grow the set.
        assert!(
            over.is_empty() || state.open_tools.len() <= MAX_OPEN_TOOLS,
            "the cap is never exceeded"
        );
        assert!(
            state.open_tools.len() <= MAX_OPEN_TOOLS,
            "open_tools must never exceed MAX_OPEN_TOOLS, got {}",
            state.open_tools.len()
        );
    }

    /// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
    /// with no open block (suppressed by the cap, or arriving with no preceding
    /// `output_item.added`) must be dropped — never an InputJsonDelta against a block that emitted
    /// no BlockStart.
    #[test]
    fn test_args_delta_dropped_for_unopened_index() {
        let mut state = crate::ir::StreamDecodeState::default();
        // No output_item.added for index 3 — the delta must be dropped.
        let out = reader_read_response_events(
            EVT_FUNCTION_CALL_ARGS_DELTA,
            &serde_json::json!({"output_index": 3, "delta": "{\"a\":1}"}),
            &mut state,
        );
        assert!(
            out.is_empty(),
            "args delta for an unopened index must be dropped, got {out:?}"
        );
    }

    /// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
    /// that DID open (via `output_item.added`) is routed as an InputJsonDelta to that index.
    #[test]
    fn test_args_delta_routed_for_opened_index() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 1,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        let out = reader_read_response_events(
            EVT_FUNCTION_CALL_ARGS_DELTA,
            &serde_json::json!({"output_index": 1, "delta": "{\"a\":1}"}),
            &mut state,
        );
        match out.first() {
            Some(crate::ir::IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::InputJsonDelta(s),
            }) => {
                assert_eq!(*index, 1);
                assert_eq!(s, "{\"a\":1}");
            }
            other => panic!("expected InputJsonDelta at index 1, got {other:?}"),
        }
    }

    /// Regression (MEDIUM/conformance, Round 12): every lifecycle event in a stream must carry the
    /// SAME `created_at` as the opening `response.created` — the terminal event must replay the
    /// captured timestamp, not a fresh `now_unix_secs()` wall-clock read.
    #[test]
    fn test_created_at_is_constant_across_stream_events() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: Some(1_700_000_000),
                model: None,
            })
            .expect("response.created");
        let created_ts = created["response"]["created_at"].as_u64();
        assert_eq!(created_ts, Some(1_700_000_000));

        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert_eq!(
            completed["response"]["created_at"].as_u64(),
            created_ts,
            "terminal created_at must match the opening event's"
        );
    }

    /// Regression (MEDIUM/conformance, Round 12): the `response.failed` event must also replay the
    /// captured `created_at`, matching `response.created`.
    #[test]
    fn test_failed_event_replays_created_at() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: Some(1_700_000_123),
                model: None,
            })
            .expect("response.created");
        let created_ts = created["response"]["created_at"].as_u64();

        let (_, failed) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("response.failed");
        assert_eq!(
            failed["response"]["created_at"].as_u64(),
            created_ts,
            "response.failed created_at must match response.created"
        );
    }

    /// Regression (MEDIUM/conformance, Round 12): the forward.rs transient/upstream error kinds
    /// (`timeout`/`network`/`connect`/`5xx`/`transient`/`api_error`) must map to the native
    /// `server_error` type, and `context_length_exceeded`/`bad_request` to `invalid_request_error`,
    /// never leaking a non-native `error.type` to a Responses client.
    #[test]
    fn test_write_error_maps_forward_transient_kinds() {
        let writer = ResponsesWriter;
        for kind in [
            "timeout",
            "network",
            "connect",
            "5xx",
            "transient",
            "api_error",
        ] {
            let v = writer.write_error(503, kind, "upstream failure");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("server_error"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind:?} must map to server_error"
            );
            assert!(v["error"]["code"].is_null(), "server_error code is null");
        }
        for kind in [crate::forward::PROVIDER_CODE_CONTEXT_LENGTH, "bad_request"] {
            let v = writer.write_error(400, kind, "bad request");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
                "kind {kind:?} must map to invalid_request_error"
            );
        }
    }

    /// Regression (MEDIUM/conformance, finding 2): the function-call `response.output_item.done`
    /// must carry the FULLY finalized item — `call_id`, `name`, AND the complete accumulated
    /// `arguments` string the SDK reads off `event.item`. Previously it emitted only
    /// `{"type":"function_call","id":…}`, an impossible-from-real-OpenAI shape.
    #[test]
    fn test_function_call_done_carries_finalized_item() {
        let writer = ResponsesWriter;
        // Open the stream so the per-stream state is initialized/reset.
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // BlockStart(ToolUse) captures call_id + name.
        let added = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_abc".to_string(),
                    name: "get_weather".to_string(),
                },
            })
            .expect("output_item.added should emit");
        assert_eq!(added.0, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)

        // Two argument fragments accumulate into the complete string.
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
        });
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
        });

        // BlockStop closes it with the fully finalized item.
        let (etype, payload) = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .expect("output_item.done should emit");
        assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        let item = &payload["item"];
        assert_eq!(item["type"].as_str(), Some("function_call")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            item["call_id"].as_str(),
            Some("call_abc"),
            "done item must carry call_id"
        );
        assert_eq!(
            item["name"].as_str(),
            Some("get_weather"),
            "done item must carry name"
        );
        assert_eq!(
            item["arguments"].as_str(),
            Some("{\"city\":\"SF\"}"),
            "done item must carry the COMPLETE accumulated arguments"
        );
        // `id` (the opaque fc_ item id) is still present and stable with the added frame.
        assert_eq!(item["id"], added.1["item"]["id"]);
    }

    /// Regression (MEDIUM/correctness, finding 3): the streaming READER must track open text blocks
    /// PER `output_index`, not with a single index-blind bool. Two message items at distinct indices
    /// must each get their OWN BlockStart and their OWN BlockStop — no orphan delta, no mismatched
    /// close.
    #[test]
    fn test_reader_multiple_text_items_distinct_indices() {
        let mut state = crate::ir::StreamDecodeState::default();
        // First text item at index 0.
        let a = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "alpha"}),
            &mut state,
        );
        assert_eq!(a.len(), 2, "first delta opens its block then writes");
        assert!(matches!(
            a[0],
            crate::ir::IrStreamEvent::BlockStart { index: 0, .. }
        ));
        // Second text item at index 1 arrives BEFORE index 0 closes — must open its OWN block,
        // never an orphan delta against an unopened block.
        let b = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 1, "delta": "beta"}),
            &mut state,
        );
        assert_eq!(b.len(), 2, "a new index must lazily open its own block");
        assert!(
            matches!(b[0], crate::ir::IrStreamEvent::BlockStart { index: 1, .. }),
            "second text index must emit its OWN BlockStart, got {:?}",
            b[0]
        );
        assert!(matches!(
            b[1],
            crate::ir::IrStreamEvent::BlockDelta { index: 1, .. }
        ));
        // Close index 0: BlockStop must pair with index 0 (not index 1).
        let close0 = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(close0.len(), 1);
        assert!(
            matches!(close0[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
            "close must pair with index 0, got {:?}",
            close0[0]
        );
        // Index 1 is still open and closes on its own terminal frame.
        let close1 = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 1}),
            &mut state,
        );
        assert_eq!(close1.len(), 1);
        assert!(matches!(
            close1[0],
            crate::ir::IrStreamEvent::BlockStop { index: 1 }
        ));
    }

    /// Regression (MEDIUM/correctness, finding 3): a tool item and a text item at DISTINCT indices
    /// in the same stream must not interfere — the tool index routes its arguments delta and closes
    /// as a tool, while the text index opens/closes independently. Confirms the disjoint key-offset
    /// keeps tool routing (`open_tools.contains(&idx)`) intact.
    #[test]
    fn test_reader_text_and_tool_indices_coexist() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Tool item opens at index 0.
        let _ = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 0,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
            }),
            &mut state,
        );
        // Text item opens at index 1.
        let t = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 1, "delta": "hi"}),
            &mut state,
        );
        assert!(matches!(
            t[0],
            crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
        ));
        // Tool arguments delta at index 0 must still route (tool index intact under raw key).
        let args = reader_read_response_events(
            EVT_FUNCTION_CALL_ARGS_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "{\"x\":1}"}),
            &mut state,
        );
        assert_eq!(args.len(), 1, "tool args delta must route to the open tool");
        assert!(matches!(
            args[0],
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(_)
            }
        ));
        // Close the tool index → tool BlockStop.
        let close_tool = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert!(matches!(
            close_tool[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));
        // Close the text index → text BlockStop.
        let close_text = reader_read_response_events(
            EVT_OUTPUT_ITEM_DONE,
            &serde_json::json!({"output_index": 1}),
            &mut state,
        );
        assert!(matches!(
            close_text[0],
            crate::ir::IrStreamEvent::BlockStop { index: 1 }
        ));
    }

    /// Regression (MEDIUM/conformance): `write_response` must emit the SDK-required non-nullable
    /// `model` even when the IR carries none (cross-protocol path, e.g. Bedrock/Anthropic →
    /// Responses). A prior revision emitted `model` only when `resp.model` was `Some`, dropping the
    /// key entirely on cross-protocol responses — a strict-decoder failure and a distinguishability
    /// tell. Absent IR model must fall back to DEFAULT_MODEL; a present model is preserved verbatim.
    #[test]
    fn test_write_response_emits_model_fallback() {
        let make_resp = |model: Option<String>| crate::ir::IrResponse {
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
            model,
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };

        // Cross-protocol: no model in the IR → DEFAULT_MODEL, never an absent key.
        let writer = ResponsesWriter;
        let out_none = writer.write_response(&make_resp(None));
        assert_eq!(
            out_none.get("model").and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "absent model must fall back to DEFAULT_MODEL, not be omitted"
        );

        // Same-protocol passthrough: the upstream model is preserved verbatim.
        let writer_some = ResponsesWriter;
        let out_some = writer_some.write_response(&make_resp(Some("gpt-4o-mini".to_string())));
        assert_eq!(
            out_some.get("model").and_then(|m| m.as_str()),
            Some("gpt-4o-mini"),
            "present model must be preserved verbatim"
        );
    }

    /// Regression (MEDIUM/conformance): on a cross-protocol stream (IR `model` is `None` on
    /// `MessageStart`), `response.created` AND every terminal lifecycle event
    /// (`response.completed`/`.incomplete`/`.failed`) must carry the same non-nullable `model`
    /// (DEFAULT_MODEL here). The terminal arms previously emitted no `model` at all — an inner
    /// `response` missing the required field, a strict-decoder failure and a proxy tell.
    #[test]
    fn test_stream_terminal_events_carry_model_fallback() {
        // --- cross-protocol completed stream: model None throughout the IR ---
        let writer = ResponsesWriter;
        let start = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, created) = writer.write_response_event(&start).expect("created event");
        assert_eq!(
            created
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "response.created must carry DEFAULT_MODEL when IR model is None"
        );

        let delta = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (ename, completed) = writer.write_response_event(&delta).expect("terminal event");
        assert_eq!(ename, "response.completed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            completed
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "response.completed must replay the required model field"
        );

        // --- same-protocol stream: the captured model is replayed onto the terminal event ---
        let writer2 = ResponsesWriter;
        let start2 = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_keep".to_string()),
            created: Some(1_720_000_000),
            model: Some("gpt-4o-mini".to_string()),
        };
        writer2
            .write_response_event(&start2)
            .expect("created event");
        let err = crate::ir::IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (ename2, failed) = writer2.write_response_event(&err).expect("failed event");
        assert_eq!(ename2, "response.failed"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            failed
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some("gpt-4o-mini"),
            "response.failed must replay the captured stream model"
        );
    }

    /// Regression (MEDIUM/conformance, Round 15): the non-streaming `write_response` body must carry
    /// the REQUIRED nullable `error` field (`null` on a non-failed response), mirroring the
    /// streaming `response.created` skeleton. A real `/v1/responses` non-streaming body always
    /// includes `error`; omitting it breaks strict SDK/Pydantic/Zod decoders that read
    /// `response.error` unconditionally and is a distinguishability tell.
    #[test]
    fn test_write_response_emits_error_null_for_completed_and_incomplete() {
        let make_resp = |stop: crate::ir::IrStopReason| crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(stop),
            usage: usage_fixture(),
            model: Some("gpt-4o-mini".to_string()),
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = ResponsesWriter;

        // Completed: error key present and explicitly null.
        let completed = writer.write_response(&make_resp(crate::ir::IrStopReason::EndTurn));
        assert_eq!(completed["status"].as_str(), Some("completed")); // golden wire-contract literal (kept bare on purpose)
        assert!(
            completed.get("error").is_some(),
            "non-streaming body must include the required error key"
        );
        assert!(
            completed["error"].is_null(),
            "error must be null on a completed response"
        );

        // Incomplete (max_tokens): error is still present and null (the failure path is the error
        // envelope, never this success/incomplete body).
        let incomplete = writer.write_response(&make_resp(crate::ir::IrStopReason::MaxTokens));
        assert_eq!(incomplete["status"].as_str(), Some("incomplete")); // golden wire-contract literal (kept bare on purpose)
        assert!(
            incomplete["error"].is_null(),
            "error must be null on an incomplete response"
        );
    }

    /// Regression (MEDIUM/correctness, Round 15; class-corrected R26/LOW #8): a non-streaming
    /// Responses body with `status:"failed"` and `output:null` is an upstream provider failure, NOT
    /// a parse error. The reader must surface it as an IrError carrying the upstream `error.code`,
    /// never misclassify it as an internal `ir_parse` ClientError. As of R26 the IrError `class` is
    /// derived from the captured signal via `class_for_response_failed` (mirroring the streaming
    /// `response.failed` arms and the HTTP classifier) rather than hardcoded ServerError: a
    /// `rate_limit_exceeded` failed body must classify as RateLimit, not a generic ServerError.
    #[test]
    fn test_read_response_failed_surfaces_upstream_error() {
        let reader = ResponsesReader;

        // status:"failed" with output:null and a populated error.code. The rate-limit signal must
        // classify as RateLimit (not the old hardcoded ServerError).
        let body = serde_json::json!({
            "id": "resp_fail",
            "object": OBJ_RESPONSE,
            "status": STATUS_FAILED,
            "output": serde_json::Value::Null,
            "error": { "code": ERR_CODE_RATE_LIMIT, "message": "slow down" },
            "usage": { "input_tokens": 1, "output_tokens": 0 },
            "model": "gpt-4o-mini"
        });
        let err = reader
            .read_response(&body)
            .expect_err("failed status must surface as an error");
        assert_eq!(
            err.class,
            StatusClass::RateLimit,
            "a rate_limit_exceeded failed body is a RateLimit, not a generic ServerError"
        );
        assert_eq!(
            err.provider_signal.as_deref(),
            Some("rate_limit_exceeded"),
            "the upstream error.code must be surfaced as the provider signal"
        );

        // error.type fallback when code is absent. `content_filter` is not one of the mapped
        // signals, so it falls to the default transient ServerError bucket.
        let body_type = serde_json::json!({
            "status": STATUS_FAILED,
            "error": { "type": INCOMPLETE_REASON_CONTENT_FILTER, "message": "blocked" },
            "usage": { "input_tokens": 1, "output_tokens": 0 }
        });
        let err_type = reader
            .read_response(&body_type)
            .expect_err("failed status must surface as an error");
        assert_eq!(err_type.class, StatusClass::ServerError);
        assert_eq!(err_type.provider_signal.as_deref(), Some("content_filter")); // golden wire-contract literal (kept bare on purpose)

        // failed with no usable error object → generic response_failed signal, default ServerError.
        let body_bare = serde_json::json!({ "status": STATUS_FAILED });
        let err_bare = reader
            .read_response(&body_bare)
            .expect_err("failed status must surface as an error");
        assert_eq!(err_bare.class, StatusClass::ServerError);
        assert_eq!(err_bare.provider_signal.as_deref(), Some("response_failed"));

        // A genuinely malformed body (no status, no output) is STILL an ir_parse ClientError — the
        // failed-status path must not swallow real parse failures.
        let body_parse = serde_json::json!({ "id": "resp_x" });
        let err_parse = reader
            .read_response(&body_parse)
            .expect_err("missing output must surface as a parse error");
        assert_eq!(err_parse.class, StatusClass::ClientError);
        assert_eq!(err_parse.provider_signal.as_deref(), Some("ir_parse")); // golden wire-contract literal (kept bare on purpose)
    }

    /// Regression (HIGH, re-audit R20): the writer emits a failed body as
    /// `{"status":"failed","output":[],"error":{...}}` — `output` is a PRESENT EMPTY array, not
    /// null/absent. Before the fix the empty array took the `if let Some(output_arr)` branch,
    /// iterated zero items, then failed the usage check and returned a ClientError `ir_parse`,
    /// MASKING the real upstream error and feeding the breaker the wrong (ClientFault, no-retry)
    /// transition. The failed-status early return must fire regardless of `output` shape.
    #[test]
    fn test_read_response_failed_with_empty_output_array_not_masked() {
        let reader = ResponsesReader;
        let body = serde_json::json!({
            "id": "resp_fail",
            "object": OBJ_RESPONSE,
            "status": STATUS_FAILED,
            "output": [],
            "error": { "code": ERR_TYPE_SERVER_ERROR, "message": "boom" },
            // No `usage` on purpose: pre-fix this body fell through to the usage check and that
            // was part of what masked the error. The failed early return must not require usage.
        });
        let err = reader
            .read_response(&body)
            .expect_err("failed status with output:[] must surface as an error, not be masked");
        assert_eq!(
            err.class,
            StatusClass::ServerError,
            "output:[] on a failed body must still be a ServerError, not a ClientError ir_parse"
        );
        assert_eq!(
            err.provider_signal.as_deref(),
            Some("server_error"),
            "the upstream error.code must be carried through even with output:[]"
        );
    }

    /// Regression (MEDIUM #5, re-audit R20): `system`/`developer` input turns carry the system
    /// prompt. The reader previously dropped them (handled by neither the typed `message` arm nor
    /// the untyped role arm), losing the system prompt on a cross-protocol hop. They must now be
    /// accumulated into `IrRequest.system`. Covers typed + untyped items, and array + bare-string
    /// content.
    #[test]
    fn test_read_request_system_and_developer_turns_feed_system() {
        let reader = ResponsesReader;
        let body = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                // typed message, system role, array content
                { "type": ITEM_TYPE_MESSAGE, "role": "system",
                  "content": [{ "type": CONTENT_TYPE_INPUT_TEXT, "text": "you are terse" }] },
                // typed message, developer role, bare-string content
                { "type": ITEM_TYPE_MESSAGE, "role": "developer", "content": "be precise" },
                // untyped item, system role, array content
                { "role": "system",
                  "content": [{ "type": CONTENT_TYPE_INPUT_TEXT, "text": "no emojis" }] },
                // a normal user turn must still land in messages
                { "type": CONTENT_TYPE_INPUT_TEXT, "text": "hello" }
            ]
        });
        let req = reader.read_request(&body).expect("request must parse");
        let system_text: Vec<&str> = req
            .system
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            system_text,
            vec!["you are terse", "be precise", "no emojis"],
            "system/developer turns (typed+untyped, array+string) must feed IrRequest.system in order"
        );
        // The user turn must NOT have been swallowed into system.
        assert_eq!(
            req.messages.len(),
            1,
            "only the user turn becomes a message"
        );
        assert!(
            matches!(req.messages[0].role, crate::ir::IrRole::User),
            "the surviving message is the user turn"
        );
    }

    /// Regression (MEDIUM #16, re-audit R20): `max_output_tokens` was read via
    /// `.as_i64()...map(|v| v as u32)`, silently truncating a value larger than `u32::MAX`. It must
    /// now drop an out-of-range value to None (matching the anthropic/bedrock readers) instead of
    /// wrapping it to a bogus small cap.
    #[test]
    fn test_read_request_max_output_tokens_out_of_range_drops_to_none() {
        let reader = ResponsesReader;

        // u32::MAX + 1 — pre-fix `as u32` would truncate this to 0, a wildly wrong cap.
        let big = u64::from(u32::MAX) + 1;
        let body_big = serde_json::json!({
            "model": "gpt-4o",
            "input": "hi",
            "max_output_tokens": big
        });
        let req_big = reader.read_request(&body_big).expect("request must parse");
        assert_eq!(
            req_big.max_tokens, None,
            "an out-of-range max_output_tokens must drop to None, not truncate"
        );

        // An in-range value still round-trips.
        let body_ok = serde_json::json!({
            "model": "gpt-4o",
            "input": "hi",
            "max_output_tokens": 4096
        });
        let req_ok = reader.read_request(&body_ok).expect("request must parse");
        assert_eq!(req_ok.max_tokens, Some(4096));
    }

    /// Regression (MEDIUM/conformance, Round 15): the terminal `response.completed`/
    /// `response.incomplete`/`response.failed` events' inner `response` object must carry the
    /// REQUIRED `output` array (present-but-empty) and (on non-failed terminals) `error: null`,
    /// mirroring the `response.created` skeleton. The SDK reads `event.response.output` to finalize
    /// the assembled Response; omitting it breaks strict decoders and is a distinguishability tell.
    #[test]
    fn test_stream_terminal_events_carry_output_and_error() {
        // --- completed terminal ---
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert!(
            completed["response"]["output"].is_array(),
            "response.completed inner response must carry an output array"
        );
        assert!(
            completed["response"]["error"].is_null(),
            "response.completed inner response must carry error: null"
        );

        // --- incomplete terminal ---
        let writer2 = ResponsesWriter;
        let _ = writer2.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, incomplete) = writer2
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert!(
            incomplete["response"]["output"].is_array(),
            "response.incomplete inner response must carry an output array"
        );
        assert!(
            incomplete["response"]["error"].is_null(),
            "response.incomplete inner response must carry error: null"
        );

        // --- failed terminal: output present-but-empty alongside the populated error object ---
        let writer3 = ResponsesWriter;
        let _ = writer3.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (ename, failed) = writer3
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("failed event");
        assert_eq!(ename, "response.failed"); // golden wire-contract literal (kept bare on purpose)
        assert!(
            failed["response"]["output"].is_array(),
            "response.failed inner response must carry an output array"
        );
        assert_eq!(
            failed["response"]["error"]["code"].as_str(),
            Some("boom"),
            "response.failed must still carry its populated error object"
        );
    }

    /// Regression (MEDIUM/conformance): the terminal `response.completed` event's inner
    /// `response.output` must carry the FULLY assembled output array (the message item with its
    /// `output_text` content, and the finalized function-call item) — NOT a hard-coded `[]`. A
    /// `completed` response with nonzero `usage.output_tokens` but an empty `output` is a shape real
    /// /v1/responses never emits and breaks SDK consumers that read `event.response.output`.
    #[test]
    fn test_terminal_output_assembles_streamed_text_and_tool_items() {
        let writer = ResponsesWriter;
        // Opening event.
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });

        // Text item at index 0: BlockStart + two deltas + BlockStop.
        let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("Hello ".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("world".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });

        // Function-call item at index 1: BlockStart(ToolUse) + arg deltas + BlockStop.
        let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_abc".to_string(),
                name: "get_weather".to_string(),
            },
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 1 });

        // Terminal.
        let (ename, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::ToolUse),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert_eq!(ename, "response.completed"); // golden wire-contract literal (kept bare on purpose)

        let output = completed["response"]["output"]
            .as_array()
            .expect("terminal output must be an array");
        assert_eq!(
            output.len(),
            2,
            "assembled output must carry both the message and the function_call item, got {output:?}"
        );

        // Items come out in output_index order: message (0) then function_call (1).
        let msg_item = &output[0];
        assert_eq!(msg_item["type"], serde_json::json!("message")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(msg_item["role"], serde_json::json!("assistant"));
        let text = msg_item["content"][0]["text"]
            .as_str()
            .expect("message item carries assembled output_text");
        assert_eq!(
            text, "Hello world",
            "the streamed text must be fully assembled"
        );

        let fc_item = &output[1];
        assert_eq!(fc_item["type"], serde_json::json!("function_call")); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(fc_item["call_id"], serde_json::json!("call_abc"));
        assert_eq!(fc_item["name"], serde_json::json!("get_weather"));
        assert_eq!(
            fc_item["arguments"],
            serde_json::json!("{\"city\":\"SF\"}"),
            "the finalized function-call item must carry the complete accumulated arguments"
        );
    }

    /// A genuinely output-less turn (no blocks streamed) still emits a present-but-empty `output`
    /// array on the terminal event — never an omitted key.
    #[test]
    fn test_terminal_output_empty_when_no_blocks_streamed() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        let output = completed["response"]["output"]
            .as_array()
            .expect("output present-but-empty, never omitted");
        assert!(
            output.is_empty(),
            "no blocks streamed -> empty output array"
        );
    }

    /// Regression (MED #2): a function_call and a text part arriving at the SAME `output_index`
    /// must NOT both open a block, and a terminal event must close that index EXACTLY once.
    ///
    /// Before the fix, `output_item.added` tracked the tool under raw key `N` while
    /// `output_text.delta` tracked text under `N + TEXT_INDEX_KEY_OFFSET`, so a tool AND a text
    /// block could both open at the same wire index. `close_open_blocks` then mapped both keys back
    /// to IR index `N` and (with no dedup) emitted TWO `BlockStop{N}` — a duplicate
    /// `content_block_stop` the Anthropic writer relays for an already-closed index.
    #[test]
    fn test_same_output_index_tool_and_text_single_open_single_close() {
        let mut state = crate::ir::StreamDecodeState::default();

        // Open a tool block at output_index 0.
        let added = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 0,
                "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "call_x", "name": "f"}
            }),
            &mut state,
        );
        let starts_after_tool = added
            .iter()
            .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { .. }))
            .count();
        assert_eq!(
            starts_after_tool, 1,
            "tool open emits exactly one BlockStart"
        );

        // A text delta arrives at the SAME output_index 0. It must NOT open a second block, and
        // must NOT route a TextDelta into the open tool block.
        let text = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "hi"}),
            &mut state,
        );
        assert!(
            text.is_empty(),
            "text delta at an index already held by a tool block must emit nothing, got {text:?}"
        );
        assert!(
            !state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
            "no text key must be opened at an index already held by a tool"
        );

        // Exactly one key is open for index 0 (the raw tool key).
        assert_eq!(
            state.open_tools.len(),
            1,
            "exactly one open marker for the shared index"
        );

        // A terminal event must close index 0 exactly ONCE.
        let completed = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
            &mut state,
        );
        let stops_at_0 = completed
            .iter()
            .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { index: 0 }))
            .count();
        assert_eq!(
            stops_at_0, 1,
            "terminal must emit EXACTLY ONE BlockStop for the shared index, got {completed:?}"
        );
    }

    /// Regression (MED #2, dedup layer): even if two open keys for the same IR index somehow
    /// coexist in `open_tools` (raw `N` and `N + TEXT_INDEX_KEY_OFFSET`), the terminal drain must
    /// collapse them to a SINGLE `BlockStop{N}`. This pins the `sort`+`dedup` in `close_open_blocks`
    /// directly: before the dedup fix this drain produced two `BlockStop{N}`.
    #[test]
    fn test_terminal_drain_dedups_colliding_keys() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Directly seed both keys for IR index 3 to exercise the drain's dedup in isolation.
        state.open_tools.insert(3);
        state.open_tools.insert(3 + TEXT_INDEX_KEY_OFFSET);

        let events = reader_read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
            &mut state,
        );
        let stops_at_3 = events
            .iter()
            .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { index: 3 }))
            .count();
        assert_eq!(
            stops_at_3, 1,
            "colliding tool+text keys for one IR index must drain to exactly one BlockStop, got {events:?}"
        );
        assert!(
            state.open_tools.is_empty(),
            "terminal drain must clear all open keys"
        );
    }

    /// Regression (MED #2, symmetric guard): a tool item must not open at an `output_index` already
    /// held by an OPEN TEXT block. Before the fix, `output_item.added` only checked the raw key, so
    /// a text block open under `N + TEXT_INDEX_KEY_OFFSET` did not block a tool open at raw `N`.
    #[test]
    fn test_tool_open_suppressed_when_text_block_open_at_index() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a TEXT block at index 0.
        let text = reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        assert_eq!(text.len(), 2);

        // A function_call item arrives at the same index 0 -> must NOT open a tool block.
        let added = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 0,
                "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "call_y", "name": "g"}
            }),
            &mut state,
        );
        assert!(
            !added
                .iter()
                .any(|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { .. })),
            "tool open at an index already held by a text block must emit no BlockStart, got {added:?}"
        );
        assert!(
            !state.open_tools.contains(&0),
            "no raw tool key may be opened at an index already held by a text block"
        );
    }

    /// Regression (LOW #9): `synth_token` must emit ONLY base62 characters, drawn uniformly via
    /// rejection sampling (no biased `byte % 62`). We assert the character class strictly, and run
    /// a targeted check of the EXACT bias `byte % 62` introduces: 256 = 4*62 + 8, so under the old
    /// reduction bytes wrap such that base62 digits at indices 0..=7 get FIVE source bytes each
    /// (`d, d+62, d+124, d+186, d+248`) while indices 8..=61 get only FOUR — a 5/4 = 1.25x
    /// over-representation of the first 8 alphabet positions. Rejection sampling drops bytes >= 248,
    /// so every index gets exactly four source bytes and the two groups have EQUAL expected
    /// frequency. We compare the mean count of the biased group (indices 0..=7) against the
    /// unbiased group (indices 8..=61) over a large sample: under the fix the ratio is ≈1.0; under
    /// the old code it is ≈1.25, far outside the tolerance band.
    #[test]
    fn test_synth_token_uniform_base62_only() {
        let alphabet: std::collections::HashSet<char> = BASE62.iter().map(|&b| b as char).collect();
        // Per-alphabet-INDEX counts (index into BASE62), so we can isolate the exact biased group.
        let mut counts = [0usize; 62];
        let char_to_index: std::collections::HashMap<char, usize> = BASE62
            .iter()
            .enumerate()
            .map(|(i, &b)| (b as char, i))
            .collect();

        // 20_000 tokens * 48 chars = 960_000 samples. With ~15.5k expected per digit, the standard
        // deviation per digit is ~124 (<1%), so a 25% group-mean gap is overwhelmingly significant.
        for _ in 0..20_000 {
            let tok = synth_token::<48>();
            assert_eq!(tok.len(), 48, "token width must be exactly N");
            for c in tok.chars() {
                assert!(
                    alphabet.contains(&c),
                    "synth_token produced a non-base62 char: {c:?}"
                );
                counts[char_to_index[&c]] += 1;
            }
        }

        // Every base62 digit must have appeared at least once.
        assert!(
            counts.iter().all(|&n| n > 0),
            "all 62 base62 digits should appear in a large uniform sample, counts={counts:?}"
        );

        // Mean frequency of the would-be-biased group (alphabet indices 0..=7) vs the rest.
        let biased_group: f64 = counts[0..8].iter().sum::<usize>() as f64 / 8.0;
        let rest_group: f64 = counts[8..62].iter().sum::<usize>() as f64 / 54.0;
        let ratio = biased_group / rest_group;
        // Fixed code: ratio ≈ 1.0. Old `byte % 62`: ratio ≈ 1.25. A 5% band cleanly separates them
        // while absorbing ordinary CSPRNG variance (the per-group means concentrate far tighter than
        // 5% at this sample size).
        assert!(
            (0.95..=1.05).contains(&ratio),
            "first-8 base62 digits must not be over-represented (group ratio={ratio:.4}; \
             ~1.25 indicates the biased `byte % 62` reduction). counts={counts:?}"
        );
    }

    // PF-H1: `tool_choice: "required"` must round-trip through the Responses reader into the IR
    // union and back out the writer — not silently degrade to `auto`/omitted on the seam.
    #[test]
    fn test_responses_tool_choice_required_roundtrips() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": "hi"}],
            "tool_choice": "required",
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request");
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
        // It must NOT also linger in `extra` (modeled key).
        assert!(!ir.extra.contains_key("tool_choice"));

        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("tool_choice").and_then(|v| v.as_str()),
            Some("required")
        );
    }

    // PF-H1: a targeted `{"type":"function","name":"X"}` (the Responses flat shape) must preserve the
    // pinned tool name through the IR and re-emit it in the same flat shape.
    #[test]
    fn test_responses_tool_choice_specific_function() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "function", "name": "get_weather"},
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request");
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        let tc = out.get("tool_choice").expect("tool_choice emitted");
        assert_eq!(tc.get("type").and_then(|v| v.as_str()), Some("function"));
        assert_eq!(tc.get("name").and_then(|v| v.as_str()), Some("get_weather"));
    }

    // A request with no `tool_choice` must yield `None` (omitted) and the writer must NOT synthesize
    // a spurious directive — preserving the "absent stays absent" contract.
    #[test]
    fn test_responses_tool_choice_absent_is_none() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": "hi"}],
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request");
        assert_eq!(ir.tool_choice, None);
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        assert!(out.get("tool_choice").is_none());
    }

    /// Build a minimal IR request for writer tests, with every Phase-0 / sampling field None/empty so
    /// individual tests can set just the one knob under test.
    fn empty_ir_request() -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: None,
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
        }
    }

    // H1 REASONING: a non-stream Responses `reasoning` output item must read into an IR Thinking block
    // (text from `content[].reasoning_text`, signature from `encrypted_content`) AND write back as a
    // `reasoning` item — a full round-trip, so reasoning survives both directions of the seam.
    #[test]
    fn test_reasoning_item_thinking_round_trip() {
        let body = serde_json::json!({
            "id": "resp_r",
            "status": STATUS_COMPLETED,
            "model": "o3",
            "output": [
                {
                    "type": ITEM_TYPE_REASONING,
                    "id": "rs_1",
                    "summary": [],
                    "content": [{"type": CONTENT_TYPE_REASONING_TEXT, "text": "let me think step by step"}],
                    "encrypted_content": "ENC_BLOB_123"
                },
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "the answer"}]
                }
            ],
            "usage": {"input_tokens": 5, "output_tokens": 7}
        });
        let reader = ResponsesReader;
        let ir = reader.read_response(&body).expect("read_response");
        // The reasoning item became a Thinking block carrying both text and the encrypted_content
        // mapped into the signature slot.
        let thinking = ir
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::Thinking {
                    text, signature, ..
                } => Some((text, signature)),
                _ => None,
            })
            .expect("a Thinking block read from the reasoning item");
        assert_eq!(thinking.0, "let me think step by step");
        assert_eq!(thinking.1.as_deref(), Some("ENC_BLOB_123"));

        // Write back: the Thinking block must re-emit a native `reasoning` output item with the text
        // under `content[].reasoning_text` and the signature back in `encrypted_content`.
        let writer = ResponsesWriter;
        let out = writer.write_response(&ir);
        let reasoning = out["output"]
            .as_array()
            .and_then(|a| a.iter().find(|i| i["type"] == "reasoning")) // golden wire-contract literal (kept bare on purpose)
            .expect("a reasoning output item written back");
        assert_eq!(
            reasoning["content"][0]["type"],
            "reasoning_text", // golden wire-contract literal (kept bare on purpose)
            "reasoning text part typed reasoning_text"
        );
        assert_eq!(
            reasoning["content"][0]["text"], "let me think step by step",
            "reasoning text round-trips"
        );
        assert_eq!(
            reasoning["encrypted_content"], "ENC_BLOB_123",
            "signature round-trips into encrypted_content"
        );
    }

    /// Fix #6 (request-input reasoning): a prior-turn `reasoning` INPUT item must read into an IR
    /// assistant Thinking block (no longer silently dropped) AND the writer must re-emit it as a
    /// top-level `reasoning` input item — a same-protocol Responses->Responses request round-trip.
    #[test]
    fn reasoning_input_item_round_trips_through_request() {
        let body = serde_json::json!({
            "model": "o3",
            "input": [
                {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "q"}]},
                {
                    "type": ITEM_TYPE_REASONING,
                    "id": "rs_in",
                    "summary": [],
                    "content": [{"type": CONTENT_TYPE_REASONING_TEXT, "text": "prior reasoning"}],
                    "encrypted_content": "ENC_IN_42"
                },
                {
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "a"}]
                }
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&body).expect("read_request");

        // The reasoning input item is preserved as an assistant Thinking block (NOT dropped).
        let thinking = ir
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .find_map(|b| match b {
                crate::ir::IrBlock::Thinking {
                    text, signature, ..
                } => Some((text, signature)),
                _ => None,
            })
            .expect("a Thinking block decoded from the reasoning input item");
        assert_eq!(thinking.0, "prior reasoning");
        assert_eq!(thinking.1.as_deref(), Some("ENC_IN_42"));

        // Writer re-emits a top-level `reasoning` input item (round-trip).
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        let reasoning = out["input"]
            .as_array()
            .and_then(|a| a.iter().find(|i| i["type"] == "reasoning")) // golden wire-contract literal (kept bare on purpose)
            .expect("a reasoning input item written back");
        assert_eq!(reasoning["content"][0]["text"], "prior reasoning");
        assert_eq!(reasoning["encrypted_content"], "ENC_IN_42");
    }

    // H6: `usage.input_tokens_details.cached_tokens` must read into the IR `cache_read_input_tokens`
    // and write back to the same nested Responses location (the Bedrock-shared cache-read field).
    #[test]
    fn test_cached_tokens_mapping() {
        let body = serde_json::json!({
            "id": "resp_c",
            "status": STATUS_COMPLETED,
            "model": "gpt-4o",
            "output": [{
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
            }],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 64}
            }
        });
        let reader = ResponsesReader;
        let ir = reader.read_response(&body).expect("read_response");
        assert_eq!(
            ir.usage.cache_read_input_tokens,
            Some(64),
            "cached_tokens read into cache_read_input_tokens"
        );

        // Write back: the cache count re-emits under usage.input_tokens_details.cached_tokens.
        let writer = ResponsesWriter;
        let out = writer.write_response(&ir);
        assert_eq!(
            out["usage"]["input_tokens_details"]["cached_tokens"], 64,
            "cache_read_input_tokens written back to cached_tokens"
        );

        // A response with NO cache details must NOT gain a spurious cached_tokens (None stays absent).
        let no_cache = serde_json::json!({
            "id": "resp_n", "status": STATUS_COMPLETED, "model": "gpt-4o",
            "output": [{"type":ITEM_TYPE_MESSAGE,"role":"assistant","content":[{"type":CONTENT_TYPE_OUTPUT_TEXT,"text":"x"}]}],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let ir2 = reader.read_response(&no_cache).expect("read_response");
        assert_eq!(ir2.usage.cache_read_input_tokens, None);
        let out2 = writer.write_response(&ir2);
        assert!(
            out2["usage"].get("input_tokens_details").is_none(),
            "no cache details => no input_tokens_details emitted"
        );
    }

    // M5 STOP: the Responses create API models no `stop` param, so the writer must NOT emit one even
    // when the IR carries stop sequences (they are warned-and-dropped, not silently leaked).
    #[test]
    fn test_stop_not_emitted_on_responses() {
        let mut req = empty_ir_request();
        req.messages.push(crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        });
        req.stop = vec!["STOP".to_string(), "END".to_string()];
        let writer = ResponsesWriter;
        let out = writer.write_request(&req);
        assert!(
            out.get("stop").is_none(),
            "/v1/responses models no stop param; it must not be emitted: {out}"
        );
        assert!(
            out.get("stop_sequences").is_none(),
            "no stop_sequences either"
        );
    }

    // SAMPLING: frequency_penalty / presence_penalty / seed / n are NOT modeled by the Responses
    // create API, so the writer must omit them even when the IR carries values (lossy-by-target).
    #[test]
    fn test_unsupported_sampling_params_omitted() {
        let mut req = empty_ir_request();
        req.messages.push(crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        });
        req.frequency_penalty = Some(0.5);
        req.presence_penalty = Some(0.3);
        req.seed = Some(42);
        req.n = Some(3);
        let writer = ResponsesWriter;
        let out = writer.write_request(&req);
        for key in ["frequency_penalty", "presence_penalty", "seed", "n"] {
            assert!(
                out.get(key).is_none(),
                "{key} is unsupported on /v1/responses and must be omitted: {out}"
            );
        }
    }

    // M1 response_format <-> text.format. A Responses `text.format` json_schema (FLAT) must read into
    // the canonical nested IR shape, and the writer must re-flatten it back under `text.format`.
    #[test]
    fn test_response_format_text_format_round_trip() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": "hi"}],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "out",
                    "schema": {"type": "object"},
                    "strict": true
                },
                "verbosity": "low"
            }
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&body).expect("read_request");
        // Canonicalized into the typed IR (no protocol-shaped Value).
        let rf = ir
            .response_format
            .as_ref()
            .expect("response_format promoted");
        assert!(rf.json);
        assert_eq!(rf.name.as_deref(), Some("out"));
        assert_eq!(
            rf.schema.as_ref().and_then(|s| s.get("type")),
            Some(&serde_json::json!("object"))
        );
        assert_eq!(rf.strict, Some(true));
        // The non-format `text` sub-key (verbosity) survives via extra.
        assert_eq!(
            ir.extra.get("text").and_then(|t| t.get("verbosity")),
            Some(&serde_json::json!("low")),
            "text.verbosity preserved in extra"
        );
        // `text` must NOT leak its format into extra (the writer rebuilds it).
        assert!(
            ir.extra.get("text").and_then(|t| t.get("format")).is_none(),
            "text.format must be promoted, not left in extra"
        );

        // Write back: text.format flat shape, merged with the preserved verbosity.
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        let fmt = &out["text"]["format"];
        assert_eq!(fmt["type"], "json_schema", "flat text.format type");
        assert_eq!(fmt["name"], "out", "name flattened beside type");
        assert_eq!(fmt["schema"]["type"], "object");
        assert_eq!(fmt["strict"], true);
        assert!(
            fmt.get("json_schema").is_none(),
            "Responses text.format is FLAT, no nested json_schema key: {fmt}"
        );
        assert_eq!(
            out["text"]["verbosity"], "low",
            "verbosity merged alongside format"
        );
    }

    // L5: a Responses `input_image` given by `file_id` (no image_url) must NOT become an empty Image
    // block — it carries the file_id faithfully and round-trips back to the `file_id` form.
    #[test]
    fn test_input_image_file_id_round_trip() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "input": [{
                "type": "input_image",
                "file_id": "file-abc123"
            }]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&body).expect("read_request");
        let file_id = ir
            .messages
            .iter()
            .flat_map(|m| &m.content)
            .find_map(|b| match b {
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor { vendor, value },
                    ..
                } if *vendor == "responses" => value
                    .get("file_id")
                    .and_then(|i| i.as_str())
                    .map(String::from),
                _ => None,
            })
            .expect("a responses-vendor Image block from the file_id image");
        assert_eq!(file_id, "file-abc123", "file_id preserved");

        // Write back: re-emits the native file_id form, not an image_url. The writer emits the
        // CANONICAL message-wrapped form (`{type:message, role, content:[{type:input_image,...}]}`),
        // so the input_image lives inside a message's `content`, not at the top of `input[]`.
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        let image_item = out["input"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("content").and_then(|c| c.as_array()))
            .flatten()
            .find(|c| c["type"] == "input_image")
            .expect("an input_image content block written back");
        assert_eq!(image_item["file_id"], "file-abc123", "file_id round-trips");
        assert!(
            image_item.get("image_url").is_none(),
            "a file_id image must not gain a spurious image_url: {image_item}"
        );
    }

    // H1 REASONING (stream): a reasoning output-item lifecycle (added/delta/done) must read into a
    // Thinking BlockStart + ThinkingDelta + BlockStop, and the writer must re-emit native reasoning
    // stream events from those IR events (`output_item.added`/`reasoning_text.delta`/`.done`).
    #[test]
    fn test_streaming_reasoning_round_trip() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // output_item.added (reasoning) at index 0 opens a Thinking BlockStart.
        let added = reader.read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 0,
                "item": {"type": ITEM_TYPE_REASONING, "id": "rs_1"}
            }),
            &mut state,
        );
        assert!(
            added.iter().any(|e| matches!(
                e,
                crate::ir::IrStreamEvent::BlockStart {
                    index: 0,
                    block: crate::ir::IrBlockMeta::Thinking
                }
            )),
            "reasoning item.added opens a Thinking block at index 0: {added:?}"
        );

        // reasoning_text.delta carries a ThinkingDelta.
        let delta = reader.read_response_events(
            EVT_REASONING_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "pondering"}),
            &mut state,
        );
        assert!(
            delta.iter().any(|e| matches!(
                e,
                crate::ir::IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: crate::ir::IrDelta::ThinkingDelta(t)
                } if t == "pondering"
            )),
            "reasoning_text.delta yields a ThinkingDelta: {delta:?}"
        );

        // Writer side: a Thinking BlockStart emits a native reasoning output_item.added.
        let writer = ResponsesWriter;
        let (etype, payload) = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Thinking,
            })
            .expect("Thinking BlockStart emits a frame");
        assert_eq!(etype, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(payload["item"]["type"], "reasoning"); // golden wire-contract literal (kept bare on purpose)

        // A ThinkingDelta emits a native reasoning_text.delta.
        let (etype2, payload2) = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta("pondering".to_string()),
            })
            .expect("ThinkingDelta emits a frame");
        assert_eq!(etype2, "response.reasoning_text.delta"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(payload2["delta"], "pondering");

        // BlockStop closes it as a reasoning output_item.done carrying the assembled text.
        let (etype3, payload3) = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .expect("Thinking BlockStop emits a frame");
        assert_eq!(etype3, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(payload3["item"]["type"], "reasoning"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(payload3["item"]["content"][0]["text"], "pondering");
    }

    // H6 (stream): a streamed terminal `response.completed` carrying
    // usage.input_tokens_details.cached_tokens must surface it on the IR MessageDelta usage, and the
    // writer's MessageDelta must re-emit it on the terminal event.
    #[test]
    fn test_streaming_cached_tokens_round_trip() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader.read_response_events(
            EVT_RESPONSE_COMPLETED,
            &serde_json::json!({
                "response": {
                    "status": STATUS_COMPLETED,
                    "usage": {
                        "input_tokens": 50,
                        "output_tokens": 5,
                        "input_tokens_details": {"cached_tokens": 32}
                    }
                }
            }),
            &mut state,
        );
        let usage = events
            .iter()
            .find_map(|e| match e {
                crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
                _ => None,
            })
            .expect("a MessageDelta with usage");
        assert_eq!(usage.cache_read_input_tokens, Some(32));

        // Writer re-emits cached_tokens on the terminal event's inner response.usage.
        let writer = ResponsesWriter;
        let (_etype, payload) = writer
            .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 50,
                    output_tokens: 5,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: Some(32),
                },
            })
            .expect("MessageDelta emits a terminal frame");
        assert_eq!(
            payload["response"]["usage"]["input_tokens_details"]["cached_tokens"], 32,
            "streamed terminal re-emits cached_tokens: {payload}"
        );
    }

    /// Non-stream `read_response` cache-token NORMALIZATION (ir.rs:457): the Responses API's
    /// `input_tokens` is a TOTAL that INCLUDES the cached prefix, so the reader SUBTRACTS
    /// `input_tokens_details.cached_tokens` to leave `input_tokens` UNCACHED and stores the cached
    /// count additively in `cache_read_input_tokens` (the OpenAI-family convention).
    #[test]
    fn read_response_subtracts_cached_prefix_from_input_tokens() {
        let body = serde_json::json!({
            "id": "resp_abc",
            "object": OBJ_RESPONSE,
            "created_at": 1_700_000_000_u64,
            "status": STATUS_COMPLETED,
            "model": "gpt-4o",
            "output": [{
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
            }],
            "usage": {
                "input_tokens": 150,
                "output_tokens": 5,
                "input_tokens_details": {"cached_tokens": 100}
            }
        });
        let resp = ResponsesReader.read_response(&body).expect("read_response");
        assert_eq!(
            resp.usage.input_tokens, 50,
            "input_tokens must be wire input(150) MINUS cached(100) = 50 (uncached)"
        );
        assert_eq!(resp.usage.cache_read_input_tokens, Some(100));
        assert_eq!(resp.usage.output_tokens, 5);
        // billable re-sums to the original wire input total (50 + 100) + output 5 = 155.
        assert_eq!(resp.usage.billable_tokens(), 155);
    }

    /// The write side RECONSTRUCTS the wire shape: it ADDS the cached prefix BACK onto the uncached IR
    /// `input_tokens` to re-derive the Responses TOTAL `input_tokens`, and re-emits the FLAT
    /// `input_tokens_details.cached_tokens`. Pins the exact inverse of the read normalization.
    #[test]
    fn write_response_reconstructs_input_tokens_total_with_cached_details() {
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
                input_tokens: 50,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: Some(100),
            },
            model: Some("gpt-4o".to_string()),
            id: Some("resp_abc".to_string()),
            created: Some(1_700_000_000),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = ResponsesWriter;
        let out = writer.write_response(&resp);
        assert_eq!(
            out["usage"]["input_tokens"],
            serde_json::json!(150),
            "input_tokens must re-add the cached prefix: uncached(50) + cached(100) = 150"
        );
        assert_eq!(out["usage"]["output_tokens"], serde_json::json!(5));
        assert_eq!(
            out["usage"]["input_tokens_details"]["cached_tokens"],
            serde_json::json!(100)
        );
    }

    /// `incomplete_details.reason` normalization must be EXHAUSTIVE (ir.rs:186): `max_output_tokens`→
    /// MaxTokens, `content_filter`→Safety, `refusal`→Refusal, and any unknown/future reason→Other (no
    /// String payload). Pins the whole codec plus its egress inverse (MaxTokens/Safety render the turn
    /// `incomplete`; everything else is `completed`).
    #[test]
    fn incomplete_reason_codec_is_exhaustive() {
        use crate::ir::IrStopReason as S;
        assert_eq!(
            read_responses_incomplete_reason(INCOMPLETE_REASON_MAX_OUTPUT),
            S::MaxTokens
        );
        assert_eq!(
            read_responses_incomplete_reason(INCOMPLETE_REASON_CONTENT_FILTER),
            S::Safety
        );
        assert_eq!(read_responses_incomplete_reason("refusal"), S::Refusal);
        assert_eq!(
            read_responses_incomplete_reason("some_future_reason"),
            S::Other
        );

        // Egress: only MaxTokens/Safety render `incomplete`; the reason projects to the native token.
        assert_eq!(write_responses_status(S::MaxTokens), STATUS_INCOMPLETE);
        assert_eq!(write_responses_status(S::Safety), STATUS_INCOMPLETE);
        assert_eq!(write_responses_status(S::ToolUse), STATUS_COMPLETED);
        assert_eq!(write_responses_status(S::EndTurn), STATUS_COMPLETED);
        assert_eq!(
            write_responses_incomplete_reason(S::MaxTokens),
            INCOMPLETE_REASON_MAX_OUTPUT
        );
        assert_eq!(
            write_responses_incomplete_reason(S::Safety),
            INCOMPLETE_REASON_CONTENT_FILTER
        );
        assert_eq!(
            write_responses_incomplete_reason(S::Other),
            INCOMPLETE_REASON_OTHER
        );
    }

    /// A full `read_response` with `status:"incomplete"` + `incomplete_details.reason:"content_filter"`
    /// surfaces `IrStopReason::Safety`, and a `max_output_tokens` reason surfaces `MaxTokens` — the
    /// truncation/moderation signal lives in `incomplete_details`, not the flat status.
    #[test]
    fn read_response_incomplete_details_promote_stop_reason() {
        let mk = |reason: &str| {
            serde_json::json!({
                "id": "resp_x",
                "object": OBJ_RESPONSE,
                "created_at": 1,
                "status": STATUS_INCOMPLETE,
                "model": "gpt-4o",
                "incomplete_details": {"reason": reason},
                "output": [{
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "partial"}]
                }],
                "usage": {"input_tokens": 3, "output_tokens": 1}
            })
        };
        assert_eq!(
            ResponsesReader
                .read_response(&mk(INCOMPLETE_REASON_CONTENT_FILTER))
                .expect("read")
                .stop_reason,
            Some(crate::ir::IrStopReason::Safety)
        );
        assert_eq!(
            ResponsesReader
                .read_response(&mk(INCOMPLETE_REASON_MAX_OUTPUT))
                .expect("read")
                .stop_reason,
            Some(crate::ir::IrStopReason::MaxTokens)
        );
    }

    /// A `response_format` json_schema round-trips read→IR→write through the Responses FLAT
    /// `text.format` shape (name/schema/strict/description sit BESIDE `type`, not nested under
    /// `json_schema` like OpenAI Chat). The IR canonicalizes it so the two OpenAI-family wire shapes
    /// stay isolated and neither leaks cross-protocol (ir.rs:348).
    #[test]
    fn text_format_json_schema_flat_round_trips() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"]
        });
        let body = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "text": {"format": {
                "type": "json_schema",
                "name": "Answer",
                "schema": schema,
                "strict": true,
                "description": "an answer"
            }}
        });
        let ir = ResponsesReader.read_request(&body).expect("read_request");
        let rf = ir
            .response_format
            .as_ref()
            .expect("text.format canonicalizes into the typed IR");
        assert!(rf.json);
        assert_eq!(rf.name.as_deref(), Some("Answer"));
        assert_eq!(rf.strict, Some(true));
        assert_eq!(rf.description.as_deref(), Some("an answer"));
        assert_eq!(rf.schema.as_ref(), Some(&schema));

        // WRITE re-emits the FLAT Responses text.format shape (fields beside type, not nested).
        let writer = ResponsesWriter;
        let out = writer.write_request(&ir);
        let fmt = out
            .pointer("/text/format")
            .expect("text.format must be emitted");
        assert_eq!(
            fmt.get("type").and_then(|t| t.as_str()),
            Some("json_schema")
        );
        assert_eq!(fmt.get("name").and_then(|n| n.as_str()), Some("Answer"));
        assert_eq!(fmt.get("schema"), Some(&schema));
        assert_eq!(fmt.get("strict").and_then(|s| s.as_bool()), Some(true));
        // The FLAT shape must NOT nest under a json_schema key (that is the Chat-Completions shape).
        assert!(
            fmt.get("json_schema").is_none(),
            "Responses text.format is FLAT — must not nest under json_schema: {out}"
        );
    }
}
