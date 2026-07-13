// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI Responses API protocol reader/writer implementation.

use super::openai_family::{
    bearer_error_code, CODE_INVALID_API_KEY, ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA,
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
const VENDOR_NAME: &str = crate::proto::PROTO_RESPONSES;

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
        CODE_INVALID_API_KEY | ERR_TYPE_AUTHENTICATION => StatusClass::Auth,
        ERR_CODE_RATE_LIMIT | ERR_TYPE_INSUFFICIENT_QUOTA => StatusClass::RateLimit,
        crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH | ERR_CODE_STRING_ABOVE_MAX => {
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
            crate::proxy::KIND_OVERLOADED
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
            crate::proxy::KIND_TIMEOUT
            | "network"
            | "connect"
            | "5xx"
            | "transient"
            | crate::proxy::KIND_API_ERROR => ERR_TYPE_SERVER_ERROR,
            // A context-length overflow is surfaced by forward.rs as `context_length_exceeded`; the
            // Responses vocabulary has no dedicated type for it (as openai_chat.rs also maps it), so it
            // folds into `invalid_request_error`. `bad_request` is the same client-error class.
            crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH | "bad_request" => ERR_TYPE_INVALID_REQUEST,
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
        crate::proxy::EGRESS_UA_OPENAI
    }

    fn auth_failure_message(&self) -> &'static str {
        AUTH_FAILURE_MSG
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
