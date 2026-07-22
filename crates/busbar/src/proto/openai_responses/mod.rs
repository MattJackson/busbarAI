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

/// Build the Responses API `usage` object from the neutral [`crate::ir::IrUsage`] with ALL fields the
/// official SDKs require (Finding 6). `openai-python`'s `ResponseUsage` and `openai-node`'s
/// `ResponseUsage` type `total_tokens`, `input_tokens_details` (with `cached_tokens`), and
/// `output_tokens_details` (with `reasoning_tokens`) as REQUIRED, non-nullable fields - a strict
/// Pydantic/Zod decoder RAISES when any is omitted, and a real Responses body always carries them (as
/// `0` when there is nothing to report). The prior writer emitted only `input_tokens`/`output_tokens`
/// and an `input_tokens_details` gated on a cache hit, so a client on the official SDK got a
/// `ValidationError` and the missing-detail-objects shape was a distinguishability tell.
///
/// SCHEMA FIDELITY (round-3 fix R3-C): the REAL Responses usage schema defines EXACTLY
/// `input_tokens_details.cached_tokens` and `output_tokens_details.reasoning_tokens` - there is NO
/// `cache_write_tokens` field (unlike the Chat Completions `prompt_tokens_details`, the Responses
/// detail objects carry only `cached_tokens`). The round-1 fix fabricated a non-native
/// `cache_write_tokens` inside `input_tokens_details`, an EXTRA key a native Responses body never
/// emits - itself a distinguishability tell and a decode surprise for a strict `extra="forbid"`
/// model. It is removed here; cache-creation tokens still fold into the `input_tokens` TOTAL below.
///
/// The IR stores UNCACHED input, but the Responses `input_tokens` is a TOTAL that includes the cached
/// prefix, so `cache_read` (+ `cache_creation`) are added back. `cached_tokens` mirrors the cache-read
/// count (`0` when absent - not omitted, matching the required-field contract). The IR does not model
/// reasoning tokens separately, so `reasoning_tokens` is `0` (the correct value for the non-reasoning
/// case and the SDK-required default otherwise). `total_tokens` = `input_total` + `output_tokens`.
fn build_responses_usage(usage: &crate::ir::IrUsage) -> serde_json::Value {
    let cache_read = usage.cache_read_input_tokens.unwrap_or(0);
    let cache_write = usage.cache_creation_input_tokens.unwrap_or(0);
    let input_total = usage
        .input_tokens
        .saturating_add(cache_read)
        .saturating_add(cache_write);
    let total = input_total.saturating_add(usage.output_tokens);
    serde_json::json!({
        "input_tokens": input_total,
        "input_tokens_details": {
            "cached_tokens": cache_read,
        },
        "output_tokens": usage.output_tokens,
        "output_tokens_details": {
            "reasoning_tokens": 0,
        },
        "total_tokens": total,
    })
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

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

mod reader;
mod writer;
