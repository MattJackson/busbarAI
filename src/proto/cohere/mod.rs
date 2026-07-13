// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cohere v2 protocol reader/writer implementation.

use super::*;
use std::sync::OnceLock;

/// Upstream URL path for the Cohere v2 chat endpoint. Mirrors the `PATH_UPSTREAM` pattern used by
/// openai_chat.rs and anthropic.rs — single source of truth for the string that was previously
/// hard-coded in `upstream_path()`.
const PATH_UPSTREAM: &str = "/v2/chat";

/// Hard cap on the number of distinct tool-call frame indices recorded in `state.open_tools` for a
/// single stream. The set is intentionally never shrunk (so each tool's IR block index stays stable
/// for its lifetime — see `cohere_lookup_tool_ir_index`), which means a malicious or buggy upstream
/// that streams an unbounded number of distinct `tool-call-start` frame indices would grow it
/// without bound. No legitimate Cohere v2 stream approaches this many parallel tool calls; past the
/// cap we stop recording new frames so memory stays bounded. The cap leaves every realistic stream
/// untouched.
const MAX_TRACKED_TOOL_FRAMES: usize = 4096;

/// Reserved sentinel recorded in `state.open_tools` the first time a text content block opens on a
/// Cohere stream. It encodes the otherwise-unrecoverable fact that "a text block has occupied IR
/// index 0 at some point this stream", which the tool-index assignment needs to keep tool blocks off
/// index 0 EVEN AFTER the text block has closed (`text_block_open` reverts to false on
/// `content-end`, so that live flag cannot answer the question on its own).
///
/// `usize::MAX` is used because every genuine tool entry recorded in `open_tools` is a small
/// bit-PACKED `(frame_idx, ir_index)` value (see `pack_tool_entry`), bounded far below `usize::MAX`
/// by `MAX_TRACKED_TOOL_FRAMES`; a packed entry of `usize::MAX` can never occur in practice, so the
/// sentinel never collides with a genuine tool entry and is trivially excluded from every scan
/// below. Recording it in the existing `open_tools` set keeps the fix entirely within this protocol
/// module (the shared `StreamDecodeState` carries no text-high-water field).
///
/// The wire `index` is upstream-controlled, so a hostile/buggy backend could send a huge value; the
/// frame component of every packed entry is clamped to `MAX_TOOL_FRAME_INDEX` (see
/// `clamp_frame_index`), so no real entry can ever reach the sentinel.
const TEXT_BLOCK_SEEN_SENTINEL: usize = usize::MAX;

/// Upper bound applied to the upstream-controlled stream-frame `index` at every tool-call read
/// site. The wire value is attacker-controllable; clamping to a small bounded cap (matching
/// `MAX_TRACKED_TOOL_FRAMES`) keeps the packed `(frame_idx, ir_index)` entries far below the
/// `TEXT_BLOCK_SEEN_SENTINEL`, while leaving every realistic stream (small sequential indices)
/// untouched. Mirrors the OpenAI reader's `MAX_TOOL_INDEX` clamp.
const MAX_TOOL_FRAME_INDEX: u64 = MAX_TRACKED_TOOL_FRAMES as u64;

/// Number of low bits each packed `open_tools` entry reserves for the assigned IR block index; the
/// remaining high bits hold the wire `frame_idx`. Both fields are bounded well below
/// `MAX_TRACKED_TOOL_FRAMES` (4096 < 2^13 < 2^20), so 20 bits per field cannot overflow and the
/// largest possible packed value (`MAX_TOOL_FRAME_INDEX << 20 | mask` ≈ 2^32) stays far below the
/// `TEXT_BLOCK_SEEN_SENTINEL` (`usize::MAX`, ≥ 2^64 on every supported target).
const TOOL_ENTRY_IR_BITS: u32 = 20;

/// Low-bit mask isolating the assigned IR index from a packed `open_tools` entry.
const TOOL_ENTRY_IR_MASK: usize = (1usize << TOOL_ENTRY_IR_BITS) - 1;

// ── Cohere v2 stream event-type tokens ────────────────────────────────────────
/// Cohere v2 stream `type` field value for the message-start event.
const ET_MESSAGE_START: &str = "message-start";
/// Cohere v2 stream `type` field value for the message-end event.
const ET_MESSAGE_END: &str = "message-end";
/// Cohere v2 stream `type` field value for the content-start event.
const ET_CONTENT_START: &str = "content-start";
/// Cohere v2 stream `type` field value for the content-delta event.
const ET_CONTENT_DELTA: &str = "content-delta";
/// Cohere v2 stream `type` field value for the content-end event.
const ET_CONTENT_END: &str = "content-end";
/// Cohere v2 stream `type` field value for the tool-call-start event.
const ET_TOOL_CALL_START: &str = "tool-call-start";
/// Cohere v2 stream `type` field value for the tool-call-delta event.
const ET_TOOL_CALL_DELTA: &str = "tool-call-delta";
/// Cohere v2 stream `type` field value for the tool-call-end event.
const ET_TOOL_CALL_END: &str = "tool-call-end";

// ── Cohere v2 finish_reason tokens ────────────────────────────────────────────
/// Cohere v2 `finish_reason` for a normal end-of-turn completion.
const COHERE_FINISH_COMPLETE: &str = "COMPLETE";
/// Cohere v2 `finish_reason` for a content-moderation stop.
const COHERE_FINISH_ERROR_TOXIC: &str = "ERROR_TOXIC";
/// Cohere v2 `finish_reason` for an infrastructure/generic error stop.
const COHERE_FINISH_ERROR: &str = "ERROR";
/// Cohere v2 `finish_reason` for a stop-sequence stop.
const COHERE_FINISH_STOP_SEQUENCE: &str = "STOP_SEQUENCE";
/// Cohere v2 `finish_reason` for a tool-call stop.
const COHERE_FINISH_TOOL_CALL: &str = "TOOL_CALL";
/// Cohere v2 `finish_reason` for a max-tokens stop.
const COHERE_FINISH_MAX_TOKENS: &str = "MAX_TOKENS";

// ── Cohere v2 tool_choice tokens ──────────────────────────────────────────────
/// Cohere v2 `tool_choice` value requiring at least one tool call.
const COHERE_TOOL_CHOICE_REQUIRED: &str = "REQUIRED";
/// Cohere v2 `tool_choice` value forbidding all tool calls.
const COHERE_TOOL_CHOICE_NONE: &str = "NONE";

/// Pack a tool call's wire `frame_idx` and the IR block index ASSIGNED to it at `tool-call-start`
/// into a single `usize` recorded in `state.open_tools`. The IR index lives in the low
/// `TOOL_ENTRY_IR_BITS`; the frame index in the high bits. Storing BOTH is what makes the IR index
/// immutable for the tool's lifetime: it is assigned once on start and looked up verbatim on
/// delta/end (see `cohere_lookup_tool_ir_index`), so a non-monotonic upstream `frame_idx` can no
/// longer perturb a live rank and shift a tool's index mid-lifecycle.
fn pack_tool_entry(frame_idx: usize, ir_index: usize) -> usize {
    (frame_idx << TOOL_ENTRY_IR_BITS) | (ir_index & TOOL_ENTRY_IR_MASK)
}

/// The wire `frame_idx` component of a packed `open_tools` entry. Caller must exclude the
/// `TEXT_BLOCK_SEEN_SENTINEL` before calling.
fn tool_entry_frame(entry: usize) -> usize {
    entry >> TOOL_ENTRY_IR_BITS
}

/// The assigned IR block index component of a packed `open_tools` entry. Caller must exclude the
/// `TEXT_BLOCK_SEEN_SENTINEL` before calling.
fn tool_entry_ir_index(entry: usize) -> usize {
    entry & TOOL_ENTRY_IR_MASK
}

/// Read the upstream-controlled stream-frame `index`, defaulting to 0 when absent/non-numeric, and
/// clamp it to `MAX_TOOL_FRAME_INDEX` so the packed entry can never collide with the sentinel.
fn clamp_frame_index(data: &serde_json::Value) -> usize {
    data.get("index")
        .and_then(|i| i.as_u64())
        .unwrap_or(0)
        .min(MAX_TOOL_FRAME_INDEX) as usize
}

/// Normalize Cohere v2's native `tool_choice` (a top-level enum STRING) into the IR's tool-choice
/// union so a forced directive survives the cross-protocol seam instead of degrading to `auto`
/// (PF-H1). Cohere v2 models only `REQUIRED` (must call some tool) and `NONE` (no tool); it has no
/// `auto` literal (auto is the default when omitted) and no way to pin ONE specific tool. So an
/// unrecognized/absent value yields `None` (omitted), and the targeted-tool case is handled lossily
/// on the WRITE side (degraded to `REQUIRED`). The reader can only ever observe `REQUIRED`/`NONE`.
fn read_cohere_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    match val?.as_str()? {
        COHERE_TOOL_CHOICE_REQUIRED => Some(crate::ir::IrToolChoice::Required),
        COHERE_TOOL_CHOICE_NONE => Some(crate::ir::IrToolChoice::None),
        _ => None,
    }
}

/// Clamp a temperature to Cohere v2's native `[0.0, 1.0]` range, returning `(clamped, was_clamped)`
/// where `was_clamped` is `true` iff the clamp ACTUALLY changed the value (PF-M1 clamp + non-silent
/// signal, mirroring `anthropic::clamp_temperature_for_anthropic` /
/// `bedrock::clamp_temperature_for_bedrock`). OpenAI / Responses accept temperature up to 2.0, so a
/// cross-protocol request can carry a value Cohere's API rejects with a hard 400 ValidationException;
/// the writer forwards the closest valid value instead of bouncing a 400, and uses `was_clamped` to
/// emit a `warn!` so the mutation is NOT silent (previously the Cohere writer clamped SILENTLY).
/// Factored out so the non-silent-on-change contract is unit-testable without a tracing subscriber.
fn clamp_temperature_for_cohere(temperature: f64) -> (f64, bool) {
    // Guard against non-finite input (NaN/±Inf): `f64::clamp` panics on a NaN bound but not a NaN
    // value, yet a NaN/Inf temperature is not a "real value clamped from range" — return it unchanged
    // with was_clamped=false so the helper is total. This is confirmed unreachable via valid JSON
    // (the parser rejects NaN/Inf), so it is a defensive no-op, not a behavior change.
    if !temperature.is_finite() {
        return (temperature, false);
    }
    let clamped = temperature.clamp(0.0, 1.0);
    (clamped, clamped != temperature)
}

/// Read a Cohere v2 `response_format` into the protocol-agnostic [`crate::ir::IrResponseFormat`]. The
/// ONLY code that knows Cohere's structured-output wire shape: `{"type":"text"}`,
/// `{"type":"json_object"}`, or `{"type":"json_object","json_schema":<schema>}` (the schema sits
/// DIRECTLY under `json_schema`, not nested under `.schema` as in OpenAI).
fn read_cohere_response_format(v: &serde_json::Value) -> Option<crate::ir::IrResponseFormat> {
    let o = v.as_object()?;
    match o.get("type").and_then(|t| t.as_str()) {
        Some("text") => Some(crate::ir::IrResponseFormat {
            json: false,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        // `json_object` may carry the schema directly under `json_schema`. An unrecognized `type` is
        // treated as free-form JSON (safe default).
        Some(_) => Some(crate::ir::IrResponseFormat {
            json: true,
            schema: o
                .get("json_schema")
                .filter(|s| s.is_object())
                .cloned()
                .or_else(|| o.get("schema").cloned()),
            name: None,
            strict: None,
            description: None,
        }),
        None => None,
    }
}

/// Project the agnostic [`crate::ir::IrResponseFormat`] into Cohere v2's native `response_format`. The
/// ONLY code that builds Cohere's structured-output wire shape.
fn write_cohere_response_format(rf: &crate::ir::IrResponseFormat) -> serde_json::Value {
    if !rf.json {
        return serde_json::json!({ "type": "text" });
    }
    match &rf.schema {
        Some(schema) => serde_json::json!({ "type": "json_object", "json_schema": schema }),
        None => serde_json::json!({ "type": "json_object" }),
    }
}

/// Cohere v2 native `finish_reason` → canonical [`crate::ir::IrStopReason`]. The ONLY place that knows
/// Cohere's finish vocabulary on the read side; an unmodeled token maps to `Other`.
fn read_cohere_stop_reason(token: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match token {
        COHERE_FINISH_COMPLETE => S::EndTurn,
        COHERE_FINISH_MAX_TOKENS => S::MaxTokens,
        COHERE_FINISH_TOOL_CALL => S::ToolUse,
        COHERE_FINISH_STOP_SEQUENCE => S::StopSequence,
        // `ERROR_TOXIC` is the content-moderation stop; generic `ERROR` is an infra failure.
        COHERE_FINISH_ERROR_TOXIC => S::Safety,
        COHERE_FINISH_ERROR => S::Error,
        _ => S::Other,
    }
}

/// Map a canonical IR stop reason to a valid Cohere v2 `finish_reason`. `ERROR` IS folded into the
/// canonical set (reader `ERROR`→`S::Error`, writer `S::Error`→`ERROR`), so it round-trips as a
/// first-class mapping. The reader lowercases only the native tokens it does NOT model
/// (`ERROR_LIMIT`→`error_limit`, `USER_CANCEL`→`user_cancel`); those reach the writer as `S::Other`
/// and degrade to `COMPLETE` below (a strict client rejects an unmodeled token). A foreign token from another protocol (e.g. `refusal` from the
/// Responses reader) upper-cases to `REFUSAL`, which is NOT a member of Cohere's `finish_reason`
/// enum and a strict client rejects; such reasons degrade to the SDK-safe terminal `COMPLETE`.
/// EXHAUSTIVE: a reason with no Cohere analog (`refusal`, `pause_turn`, `other`) also falls back to
/// `COMPLETE`.
fn write_cohere_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn => COHERE_FINISH_COMPLETE,
        S::StopSequence => COHERE_FINISH_STOP_SEQUENCE,
        S::MaxTokens => COHERE_FINISH_MAX_TOKENS,
        S::ToolUse => COHERE_FINISH_TOOL_CALL,
        S::Safety => COHERE_FINISH_ERROR_TOXIC,
        S::Error => COHERE_FINISH_ERROR,
        S::Refusal | S::PauseTurn | S::Other => COHERE_FINISH_COMPLETE,
    }
}

/// The request keys this reader models explicitly (and therefore must NOT echo back through
/// `extra`). Built once per process via `OnceLock` instead of being reconstructed on every
/// `read_request` call — the rebuild was a pointless per-request allocation on the Cohere ingress
/// hot path (also avoided in the Gemini/Bedrock readers).
fn cohere_modeled_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        [
            "model",
            "messages",
            "tools",
            "tool_choice",
            "max_tokens",
            "temperature",
            "p",
            "k",
            "stop_sequences",
            "stream",
            // Phase 0 sampling/output controls now modeled into the IR (so they translate the
            // cross-protocol seam) — must be excluded from `extra` or a same-protocol passthrough
            // would double-emit them (once from the modeled writer path, once echoed via extra).
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "response_format",
        ]
        .into_iter()
        .collect()
    })
}

/// Format 16 bytes as a UUID-shaped (8-4-4-4-12 lowercase hex) token. Real Cohere v2 chat response
/// ids are bare RFC-4122 UUIDv4s (e.g. `c14c80c3-18eb-4519-9460-6c92edd8cfb4` — note the version
/// nibble `4` opening the 3rd group and the variant nibble `9` (`10xx`) opening the 4th), with NO
/// literal prefix, so a synthesized id must match that layout to stay shape-indistinguishable from
/// a native one. The caller is responsible for having already stamped the version/variant bits.
fn format_uuid_layout(bytes: &[u8; 16]) -> String {
    // One allocation for the 32-char lowercase hex string (no per-byte `format!`).
    let s = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

/// Synthesize a Cohere-shaped response id for the cross-protocol case where the backend supplied
/// none. Native Cohere v2 ids are bare RFC-4122 UUIDv4s (8-4-4-4-12 hex, no prefix), so we emit a
/// PROPER v4: all 128 bits seeded from the OS CSPRNG (`getrandom`), with the version nibble forced
/// to `4` and the variant bits forced to `10xx`. A client (or any observer) that validates the id
/// as a UUIDv4 — Cohere's are — sees a well-formed value, so this is no longer a proxy tell, and no
/// timestamp is embedded (the earlier `secs << 32` layout leaked the server clock in the first
/// group). A native UUIDv4 is fully random in its 122 free bits (~5.3e36 values), so there is NO
/// monotonic-counter overlay: a counter folded into any fixed region leaves those bytes
/// predictable/low-entropy, a structural tell a native random v4 never carries, and a 122-bit random
/// id is collision-free in practice for a per-process id stream. Never panics on the request path:
/// on the near-impossible `getrandom` failure the buffer stays zeroed and the version/variant
/// stamping still yields a well-formed (if non-random) v4.
fn synthesize_cohere_id() -> String {
    let mut bytes = [0u8; 16];
    // OS CSPRNG. Ignore failure (no unwrap/expect/panic on the request path): the version/variant
    // stamping below still produces a valid v4 even if the buffer stays all-zero.
    let _ = getrandom::fill(&mut bytes);

    // RFC-4122 v4: high nibble of byte 6 (the 3rd group's first nibble) = 4; top two bits of byte 8
    // (the 4th group's first nibble) = 10.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format_uuid_layout(&bytes)
}

/// Whether a mid-stream `IrError`'s `provider_signal` names a CONTENT-MODERATION stop (so the
/// Cohere-ingress writer should terminate with `ERROR_TOXIC` rather than the generic `ERROR`).
///
/// The IR `Error` arrives from any upstream protocol, so the signal text is not Cohere-specific. We
/// recognise the canonical moderation tokens busbar's readers normalise to (`safety`, the IR stop
/// reason) plus the native Cohere `ERROR_TOXIC` and the common provider words for a moderation/
/// content-policy stop. Anything else is an infrastructure-class error and maps to `ERROR`. This is
/// an exhaustive boolean classifier — there is no catch-all hiding an unhandled case; the `else`
/// branch is the explicit "not a moderation stop" disposition.
fn cohere_error_is_content_moderation(signal: &str) -> bool {
    let s = signal.to_ascii_lowercase();
    s.contains("toxic")
        || s.contains("safety")
        || s.contains("moderation")
        || s.contains("content_policy")
        || s.contains("content-policy")
        || s.contains("content_filter")
}

/// Number of genuine tool frames currently recorded in `state.open_tools` (excludes the
/// `TEXT_BLOCK_SEEN_SENTINEL`). `open_tools` may also carry the text sentinel, so the raw `len()` is
/// NOT the tool count.
fn cohere_tracked_tool_count(state: &crate::ir::StreamDecodeState) -> usize {
    state
        .open_tools
        .iter()
        .filter(|&&e| e != TEXT_BLOCK_SEEN_SENTINEL)
        .count()
}

/// Look up the IMMUTABLE IR block index previously ASSIGNED to the tool call whose wire `frame_idx`
/// was recorded at `tool-call-start`, or `None` if that frame was never tracked (a duplicate-free
/// frame past the cap, or an end/delta with no matching start). The index is read verbatim from the
/// packed `open_tools` entry — it is NOT recomputed from a live rank — so start, delta(s), and end
/// for a given tool always resolve to the SAME IR index even when the upstream streams frame indices
/// out of order (a non-monotonic frame index would otherwise perturb a recomputed rank and shift a
/// tool's index mid-lifecycle).
fn cohere_lookup_tool_ir_index(
    state: &crate::ir::StreamDecodeState,
    frame_idx: usize,
) -> Option<usize> {
    state
        .open_tools
        .iter()
        .find(|&&e| e != TEXT_BLOCK_SEEN_SENTINEL && tool_entry_frame(e) == frame_idx)
        .map(|&e| tool_entry_ir_index(e))
}

/// Record a `tool-call-start` for wire `frame_idx`, ASSIGNING it a stable IR block index, and return
/// that index. Returns `None` (emit nothing) when the frame is a duplicate of one already open, or
/// when the per-stream cap is reached.
///
/// The assigned IR index is `base + tracked_tool_count`, where `base` is 1 if a text block has ever
/// occupied IR index 0 this stream (recorded via `TEXT_BLOCK_SEEN_SENTINEL`) else 0. Keying the base
/// on the persistent sentinel — not the live `text_block_open` flag, which `content-end` resets to
/// false before tools arrive — keeps tool blocks off the text block's index 0.
/// Keying the per-tool offset on INSERTION ORDER (the count of already-tracked tools) rather than the
/// wire-index rank makes the assignment independent of monotonic wire indices and immutable once
/// made: a later tool with a SMALLER wire `frame_idx` no longer retroactively shifts an earlier
/// tool's index. `state.open_tools` is never shrunk for the stream's lifetime, so a
/// recorded entry — and the IR index packed into it — survives until the stream ends.
fn cohere_assign_tool_ir_index(
    state: &mut crate::ir::StreamDecodeState,
    frame_idx: usize,
) -> Option<usize> {
    // Duplicate tool-call-start for a frame already open: no-op (do not re-assign or re-emit).
    if cohere_lookup_tool_ir_index(state, frame_idx).is_some() {
        return None;
    }
    let tracked = cohere_tracked_tool_count(state);
    // New frame past the cap: not tracked, emit nothing (bounds per-stream memory).
    if tracked >= MAX_TRACKED_TOOL_FRAMES {
        return None;
    }
    let base = usize::from(state.open_tools.contains(&TEXT_BLOCK_SEEN_SENTINEL));
    let ir_index = base + tracked;
    state
        .open_tools
        .insert(pack_tool_entry(frame_idx, ir_index));
    Some(ir_index)
}

/// Resolve the IR block index the text content block claims for THIS stream, assigning it on first
/// appearance and returning the same value verbatim thereafter. The index is claimed BY ORDER OF
/// FIRST APPEARANCE — the count of tool blocks already tracked this stream — NOT a hardcoded 0, so a
/// `tool-call-start` that arrives BEFORE the first `content-start`/`content-delta` (which claims IR
/// index 0 via `cohere_assign_tool_ir_index` when no text has been seen) does not collide with the
/// text block: the tool keeps 0 and the text block takes the next free slot. This mirrors the Gemini
/// reader's `state.text_index` index-by-first-appearance scheme (gemini.rs), reusing the same shared
/// `StreamDecodeState.text_index` field. Once `state.text_index` is `Some`, it is immutable for the
/// stream's lifetime (so the matching `BlockStop` on `content-end` closes the index that was
/// actually opened, even after later tools push the tracked count up). The persistent
/// `TEXT_BLOCK_SEEN_SENTINEL` still gates the TOOL base offset (so a tool opened after the text block
/// stays off the text index even after `content-end` clears the live flag); this
/// helper governs only the TEXT block's own index (the tool-before-text collision).
fn cohere_text_ir_index(state: &mut crate::ir::StreamDecodeState) -> usize {
    let ti = state
        .text_index
        .unwrap_or_else(|| cohere_tracked_tool_count(state));
    state.text_index = Some(ti);
    state.open_tools.insert(TEXT_BLOCK_SEEN_SENTINEL);
    ti
}

#[derive(Clone)]
pub(crate) struct CohereReader;

impl CohereReader {
    /// True when the upstream error body carries Cohere v2's oversized-request ("context length
    /// exceeded") phrasing. Cohere has no structured context-length code/type, so this is a
    /// case-insensitive substring scan of the raw body. The phrases mirror the ones the
    /// `#[cfg(test)] classify()` helper recognizes ("too many tokens", "maximum"+"tokens") plus the
    /// broader provider wording ("input too long", "exceeds maximum context",
    /// "token limit" — matched via the "too long" / "exceeds"+"context" substrings), so production
    /// `extract_error` synthesizes the canonical
    /// `context_length_exceeded` code that the breaker maps to `StatusClass::ContextLength`.
    fn body_signals_context_length(body: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(body).to_lowercase();
        lower.contains("too many tokens")
            // `too long` is co-constrained to a token/context/input qualifier so it only fires on a
            // genuine oversized-request error. A bare `contains("too long")` over-matched ANY
            // upstream message containing "too long" (e.g. "request URL too long", "value too long
            // for column"), mis-synthesizing the canonical `context_length_exceeded` code and
            // triggering a no-penalty ContextLength failover for an unrelated client error.
            || (lower.contains("too long")
                && (lower.contains("token")
                    || lower.contains("context")
                    || lower.contains("input")))
            || lower.contains("token limit")
            || (lower.contains("exceeds") && lower.contains("context"))
            || (lower.contains("maximum") && lower.contains("token"))
    }
}

impl ProtocolReader for CohereReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body exactly once and derive both fields from the single binding — the Gemini
        // and Bedrock readers do the same, preserving the "parse once" invariant. Parsing twice
        // paid a pointless 2x CPU cost on every error response.
        let json = crate::json::parse::<serde_json::Value>(body).ok();
        let provider_code = json
            .as_ref()
            .and_then(|j| j.get("message"))
            .and_then(|m| m.as_str())
            .map(String::from);
        let structured_type = json
            .as_ref()
            .and_then(|j| j.get("error_type"))
            .and_then(|e| e.as_str())
            .map(String::from);

        // Cohere v2 signals an oversized request via the error MESSAGE only — it has no distinct
        // structured code/type for context-length (its `error_type` is the generic
        // `invalid_request_error`, and the `message` is free text like "too many tokens" /
        // "...exceeds the maximum ... tokens"). Without normalization, `provider_code` would carry
        // that raw message string, which the breaker cannot recognize, so an oversized-request
        // failure would be classified by HTTP 400 as a plain ClientError and NEVER fail over. The
        // `#[cfg(test)] classify()` helper above synthesized the canonical `context_length_exceeded`
        // code, but that helper does not run in production — only `extract_error` does. Mirror
        // `AnthropicReader::extract_error`: scan the body for Cohere's context-length phrasing and,
        // when it matches, OVERRIDE `provider_code` with the canonical `context_length_exceeded`
        // code. The breaker (breaker.rs `normalize_raw_error`) recognizes that code →
        // `StatusClass::ContextLength` → fail over without penalty (the lane is healthy). Unlike the
        // Anthropic reader's `or_else` (its `provider_code` is `None` when context-length triggers),
        // Cohere always populates `provider_code` from `message`, so the canonical code must REPLACE
        // it rather than only fill an empty slot.
        // Gate the body-scan override on a request-SIZE status. A 401/403/429 whose free-text body
        // happens to mention token counts must NOT be reclassified as the no-penalty ContextLength
        // class — that would let an auth/rate-limit failure escape the breaker (no cooldown, no
        // failover penalty). Cohere signals an oversized request with HTTP 400 (and, for some
        // gateways, 413); only on those statuses does the phrasing carry context-length meaning.
        let provider_code = if (status == StatusCode::BAD_REQUEST
            || status == StatusCode::PAYLOAD_TOO_LARGE)
            && Self::body_signals_context_length(body)
        {
            Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
        } else {
            provider_code
        };

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

        // Mirror the production `extract_error` gate: rate-limit / auth / server statuses are
        // classified by status FIRST, so a free-text body that mentions token counts on a 429/401/403
        // can never be reclassified as the no-penalty ContextLength class. The context-length phrasing
        // is honored ONLY on a request-size status (400 / 413).
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

        if (status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE)
            && (lower.contains("too many tokens")
                || (lower.contains("maximum") && lower.contains("tokens")))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
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
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            })?;

            for msg_val in msgs_arr {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");
                let role = match role_str {
                    "system" => crate::ir::IrRole::System,
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    "tool" => crate::ir::IrRole::Tool,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                            retry_after: None,
                        })
                    }
                };

                // System content is canonicalized into IrRequest.system (matching the other
                // protocols), not carried as a System-role message — so it survives translation
                // to a protocol whose writer reads req.system.
                if role == crate::ir::IrRole::System {
                    if let Some(content_val) = msg_val.get("content") {
                        if let Some(s) = content_val.as_str() {
                            system_blocks.push(crate::ir::IrBlock::Text {
                                text: s.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = content_val.as_array() {
                            for block_val in arr {
                                if let Some(bo) = block_val.as_object() {
                                    if bo.get("type").and_then(|t| t.as_str()) == Some("text") {
                                        if let Some(text) = bo.get("text").and_then(|t| t.as_str())
                                        {
                                            system_blocks.push(crate::ir::IrBlock::Text {
                                                text: text.to_string(),
                                                cache_control: None,
                                                citations: Vec::new(),
                                            });
                                        }
                                    } else {
                                        // Cohere's system message is text-only natively, so a
                                        // non-text block in the system array has no representation and
                                        // is dropped. Keep the drop, but surface it: a silent loss of
                                        // a system instruction block is otherwise invisible.
                                        tracing::warn!(
                                            block_type = bo
                                                .get("type")
                                                .and_then(|t| t.as_str())
                                                .unwrap_or("<missing>"),
                                            "dropping non-text block in cohere system array (cohere \
                                             system is text-only)"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                let mut msg_content = Vec::new();
                // The generic top-level content loop must NOT run for the Tool role: native Cohere
                // v2 tool content is NOT a free-text message field — it is consumed below by the
                // dedicated Tool branch into the ToolResult's inner content. Running this loop for
                // a Tool message ALSO decoded the same `content` into stray top-level Text blocks,
                // so one tool message produced both a top-level Text block AND a ToolResult holding
                // the identical text. On egress CohereWriter's Tool branch then folds that leftover
                // text into the first ToolResult, duplicating it. Skip the generic parse here — the
                // Tool branch owns a tool message's content exclusively (mirrors the System early
                // `continue` above, which keeps System content out of this loop too).
                if role != crate::ir::IrRole::Tool {
                    if let Some(content_val) = msg_val.get("content") {
                        if content_val.is_string() {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: content_val.as_str().unwrap_or("").to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = content_val.as_array() {
                            for block_val in arr {
                                if let Some(block_obj) = block_val.as_object() {
                                    match block_obj.get("type").and_then(|t| t.as_str()) {
                                        Some("text") => {
                                            if let Some(text) =
                                                block_obj.get("text").and_then(|t| t.as_str())
                                            {
                                                msg_content.push(crate::ir::IrBlock::Text {
                                                    text: text.to_string(),
                                                    cache_control: None,
                                                    citations: Vec::new(),
                                                });
                                            }
                                        }
                                        // Cohere v2 multimodal input: an image content part is
                                        // `{"type":"image_url","image_url":{"url":"<data-uri|https>"}}`
                                        // — the SAME shape OpenAI v1 chat uses (Cohere adopted the
                                        // OpenAI-compatible part for its vision models). Decode it into
                                        // `IrBlock::Image` via the shared `parse_image_url` seam, which
                                        // splits a `data:<mime>;base64,<payload>` URI into
                                        // (media_type, data) and otherwise preserves the raw URL under
                                        // the "image_url" sentinel — the SAME (media_type, data) IR
                                        // contract the Anthropic/OpenAI readers populate, so a Cohere
                                        // image round-trips and translates losslessly. ASSUMPTION (see
                                        // report): the wire shape is OpenAI-style `image_url`; no
                                        // Cohere v2 image fixture exists in-repo to confirm it.
                                        Some("image_url") => {
                                            if let Some(url) = block_obj
                                                .get("image_url")
                                                .and_then(|iu| iu.get("url"))
                                                .and_then(|u| u.as_str())
                                            {
                                                msg_content.push(crate::ir::IrBlock::Image {
                                                    source: super::parse_image_url(url),
                                                    cache_control: None,
                                                });
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }

                if role == crate::ir::IrRole::Assistant {
                    if let Some(tool_calls) = msg_val.get("tool_calls") {
                        if let Some(tc_arr) = tool_calls.as_array() {
                            for tc_val in tc_arr {
                                if let Some(func_obj) = tc_val.get("function") {
                                    let id = tc_val
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let name = func_obj
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let arguments = func_obj
                                        .get("arguments")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("{}");
                                    let input = crate::json::parse_str(arguments).unwrap_or(
                                        serde_json::Value::String(arguments.to_string()),
                                    );
                                    msg_content.push(crate::ir::IrBlock::ToolUse {
                                        id,
                                        name,
                                        input,
                                        cache_control: None,
                                    });
                                }
                            }
                        }
                    }
                }

                if role == crate::ir::IrRole::Tool {
                    let tool_call_id = msg_val
                        .get("tool_call_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let content_text = if let Some(content_val) = msg_val.get("content") {
                        if let Some(arr) = content_val.as_array() {
                            // Cohere v2 tool content is an array. Bare strings are accepted, but
                            // the native (SDK-emitted) shape is an array of typed objects, e.g.
                            // `[{"type":"text","text":"..."}]` or
                            // `[{"type":"document","document":{...}}]`. Mirror the user/assistant
                            // text-block decoding above: pull `text` from `type:"text"` blocks and
                            // JSON-serialize any other typed object block (document, etc.) so its
                            // content is preserved rather than silently dropped.
                            arr.iter()
                                .filter_map(|b| {
                                    if let Some(s) = b.as_str() {
                                        Some(s.to_string())
                                    } else if let Some(bo) = b.as_object() {
                                        if bo.get("type").and_then(|t| t.as_str()) == Some("text") {
                                            bo.get("text")
                                                .and_then(|t| t.as_str())
                                                .map(String::from)
                                        } else {
                                            // Preserve non-text typed blocks (document, etc.)
                                            // verbatim rather than dropping them.
                                            crate::json::to_string(b).ok()
                                        }
                                    } else {
                                        // Non-string, non-object array element: serialize it so no
                                        // content is lost.
                                        crate::json::to_string(b).ok()
                                    }
                                })
                                .collect::<Vec<_>>()
                                // Concatenate with NO separator: the OpenAI/Anthropic writers
                                // concatenate text blocks with `""`, so a space here would corrupt
                                // content split across blocks on a Cohere->OpenAI->Cohere round-trip
                                // (re-reading the now-joined string back as a single block, with a
                                // phantom space inserted at each former block boundary).
                                .join("")
                        } else if let Some(s) = content_val.as_str() {
                            s.to_string()
                        } else {
                            crate::json::to_string(content_val).unwrap_or_default()
                        }
                    } else {
                        String::new()
                    };
                    msg_content.push(crate::ir::IrBlock::ToolResult {
                        tool_use_id: tool_call_id,
                        content: vec![crate::ir::IrBlock::Text {
                            text: content_text,
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    });
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        } else {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_arr) = obj.get("tools").and_then(|v| v.as_array()) {
            for tool_val in tools_arr {
                if let Some(func_obj) = tool_val.get("function") {
                    let name = func_obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let description = func_obj
                        .get("description")
                        .and_then(|v| v.as_str().map(String::from));
                    let input_schema = func_obj
                        .get("parameters")
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
        }

        // Narrow with `u32::try_from` (NOT a bare `as u32`): a `max_tokens` above `u32::MAX`
        // silently wraps under `as` to a small nonsense cap that is then forwarded to Cohere,
        // diverging from a direct Cohere call. `try_from` drops an out-of-range value to `None`
        // instead, matching the hardened Gemini reader (gemini.rs). The `v > 0` filter still
        // rejects zero/negative caps first.
        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        // Cohere v2 chat names its sampling controls `p` (top_p), `k` (top_k), `stop_sequences`.
        let top_p = obj.get("p").and_then(|v| v.as_f64());
        // Narrow with `u32::try_from` (NOT a bare `as u32`), matching the hardened `max_tokens`
        // path above: a `k` (top_k) above `u32::MAX` silently wraps under `as` to a small nonsense
        // sampling cap (e.g. 4294967296 -> 0, 4294967297 -> 1) that is then forwarded to Cohere,
        // diverging from a direct Cohere call with the same JSON. `try_from` drops an out-of-range
        // value to `None` instead, so the proxy forwards no cap rather than a wrapped one.
        let top_k = obj
            .get("k")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let stop = crate::ir::read_stop_sequences(obj.get("stop_sequences"));
        // Cohere v2 `tool_choice` is a top-level enum string (REQUIRED/NONE). Promote it to the IR
        // union so a forced directive survives the cross-protocol seam (PF-H1).
        let tool_choice = read_cohere_tool_choice(obj.get("tool_choice"));
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Cohere v2 chat models `frequency_penalty`/`presence_penalty` (top-level floats) natively,
        // with the SAME names/shape as OpenAI — promote them to the IR so a forced penalty survives
        // the cross-protocol seam instead of being dropped (they are modeled keys, so they are NOT
        // re-echoed via `extra`).
        let frequency_penalty = obj.get("frequency_penalty").and_then(|v| v.as_f64());
        let presence_penalty = obj.get("presence_penalty").and_then(|v| v.as_f64());
        // Cohere v2 chat supports a top-level integer `seed` for reproducible sampling (same name as
        // OpenAI/Responses), so promote it to the IR. `i64` to carry the full JSON integer range
        // losslessly, matching the IR field type. (If a future Cohere API revision drops `seed`, this
        // read is a harmless no-op when the key is absent.)
        let seed = obj.get("seed").and_then(|v| v.as_i64());
        // Cohere v2 chat models `response_format` (json_object / json_schema structured output) at the
        // top level. Carry the raw object verbatim into the IR so it round-trips and translates.
        let response_format = obj
            .get("response_format")
            .and_then(read_cohere_response_format);

        // M4: Cohere-native `documents` (RAG grounding) has NO cross-protocol analog and is NOT
        // modeled in the IR — it stays in `extra`. On a SAME-protocol Cohere->Cohere hop it survives
        // byte-exact (it is echoed through `extra`). On a CROSS-protocol hop, `extra` is CLEARED at
        // the translation seam, so the `documents` grounding is silently DROPPED — and the Cohere
        // writer never runs to observe the loss. So warn HERE, at the reader, where the inbound
        // `documents` is still visible, whenever the request carries one. We intentionally do NOT
        // invent an IR field for it (no faithful target mapping exists); the warn makes the
        // potential cross-protocol loss non-silent so an operator can detect grounding that will not
        // reach a non-Cohere backend.
        if obj.contains_key("documents") {
            tracing::warn!(
                "cohere: request carries native `documents` (RAG grounding) with no cross-protocol \
                 analog; it survives a same-protocol Cohere->Cohere hop but is DROPPED when this \
                 request is translated to a non-Cohere backend (extra is cleared at the seam)"
            );
        }

        // Built once per process and reused across every request rather than rebuilt on each
        // read_request call (the per-request allocation/hashing was wasted work on the ingress hot
        // path — same fix the Gemini/Bedrock readers want). The set is immutable, so a OnceLock is
        // safe to share across threads.
        for (key, value) in obj.iter() {
            if !cohere_modeled_keys().contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        Ok(crate::ir::IrRequest {
            reasoning: None,
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
            top_k,
            stop,
            tool_choice,
            stream,
            frequency_penalty,
            presence_penalty,
            seed,
            // `n` (candidate count) is intentionally omitted: the Cohere v2 `/v2/chat` API has NO
            // `num_generations`/`n` parameter (it was a v1 Generate-API field, removed in v2 — the
            // documented way to get N candidates is to call chat N times). So there is nothing native
            // to read here, and the writer emits nothing — same as Anthropic/Bedrock/Responses. (An
            // earlier ir.rs docstring wrongly claimed Cohere `num_generations` support; corrected.)
            n: None,
            response_format,
            extra,
        })
    }

    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();
        if data.as_str() == Some(crate::proto::SSE_DONE_SENTINEL) || !data.is_object() {
            return out;
        }

        let event_type_val = data.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type_val {
            ET_MESSAGE_START => {
                if !state.started {
                    state.started = true;
                    // Cohere v2 streams carry the response `id` on the top-level message-start
                    // frame. Capture it for same-protocol stream passthrough; synthesize a
                    // shape-valid id when the upstream omitted it. Cohere has no stream `created`.
                    let id = data
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or_else(|| Some(synthesize_cohere_id()));
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created: None,
                        model: None,
                    });
                }
            }
            ET_CONTENT_START => {
                // The text content block claims a DYNAMIC IR index by order of first appearance
                // (`cohere_text_ir_index`), NOT a hardcoded 0: a `tool-call-start` that arrived
                // before any content frame already took 0, and forcing text to 0 here produced two
                // BlockStart frames at the same IR index (the tool/text collision).
                // `cohere_text_ir_index` also records the persistent TEXT_BLOCK_SEEN_SENTINEL so a
                // tool opened AFTER the text block stays off the text index even after content-end
                // clears the live flag. The raw upstream wire `index` is still
                // never forwarded into the IR stream.
                if !state.text_block_open {
                    state.text_block_open = true;
                    let ti = cohere_text_ir_index(state);
                    out.push(IrStreamEvent::BlockStart {
                        index: ti,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
            }
            ET_CONTENT_DELTA => {
                // The text content block claims a DYNAMIC IR index by order of first appearance
                // (`cohere_text_ir_index`) — see content-start — NOT a hardcoded 0, so a tool that
                // opened ahead of the first content frame (and took 0) does not collide with the
                // text block. The raw upstream wire `index` is never forwarded;
                // every text BlockStart/Delta below uses the assigned `text_idx`. `cohere_text_ir_index`
                // also records the persistent sentinel so a later tool stays off the text index.
                let text_idx = cohere_text_ir_index(state);
                if !state.text_block_open {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: text_idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }

                if let Some(delta_obj) = data.get("delta") {
                    if let Some(content_obj) =
                        delta_obj.get("message").and_then(|m| m.get("content"))
                    {
                        if let Some(text) = content_obj.as_str() {
                            if !text.is_empty() {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: text_idx,
                                    delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                });
                            }
                        } else if let Some(block_obj) = content_obj.as_object() {
                            // Cohere v2 content-delta object shape. REAL Cohere streams
                            // `{ "text": "<chunk>" }` with NO `type` field (only content-start
                            // carries `type`); this file's writer emits `{ "type": "text",
                            // "text": … }`. Accept BOTH: requiring `type == "text"` (the old
                            // check) silently dropped every streamed chunk from a real Cohere
                            // backend — a lossy reader that only round-tripped its own writer.
                            // Reject only an object that declares a DIFFERENT type.
                            let ty = block_obj.get("type").and_then(|t| t.as_str());
                            if ty.is_none() || ty == Some("text") {
                                if let Some(text) = block_obj.get("text").and_then(|t| t.as_str()) {
                                    if !text.is_empty() {
                                        out.push(IrStreamEvent::BlockDelta {
                                            index: text_idx,
                                            delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                        });
                                    }
                                }
                            }
                        } else if let Some(content_arr) = content_obj.as_array() {
                            for block_val in content_arr {
                                if let Some(block_obj) = block_val.as_object() {
                                    if block_obj.get("type").and_then(|t| t.as_str())
                                        == Some("text")
                                    {
                                        if let Some(text) =
                                            block_obj.get("text").and_then(|t| t.as_str())
                                        {
                                            out.push(IrStreamEvent::BlockDelta {
                                                index: text_idx,
                                                delta: crate::ir::IrDelta::TextDelta(
                                                    text.to_string(),
                                                ),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ET_CONTENT_END => {
                // content-end closes the text content block at the IR index it actually CLAIMED on
                // first appearance (`state.text_index`), NOT a hardcoded 0 — a tool may have taken 0
                // ahead of it (the tool/text collision), so closing 0 here would leave
                // the real text block open and stop a phantom one. The raw wire `index` is never
                // forwarded. Only emit the stop if a text block is actually open, so a stray
                // content-end never produces an unbalanced BlockStop. `state.text_index` is NOT
                // cleared (mirroring how the tool entries stay recorded in `open_tools` for the
                // stream's lifetime): keeping the claimed index immutable means a re-opened text
                // block resolves to the SAME slot and a tool opened after content-end still derives
                // its base off the persistent TEXT_BLOCK_SEEN_SENTINEL, so neither can collide with
                // the text index.
                if state.text_block_open {
                    state.text_block_open = false;
                    let ti = state.text_index.unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
            }
            ET_MESSAGE_END => {
                let raw_finish_reason = data
                    .get("delta")
                    .and_then(|d| d.get("finish_reason"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let stop_reason = if raw_finish_reason.is_empty() {
                    None
                } else {
                    Some(read_cohere_stop_reason(raw_finish_reason))
                };

                let usage = data
                    .get("delta")
                    .and_then(|d| d.get("usage"))
                    .map(|u| {
                        let tokens_map: serde_json::Map<String, serde_json::Value> = u
                            .get("tokens")
                            .and_then(|t| t.as_object())
                            .cloned()
                            .unwrap_or_default();
                        crate::ir::IrUsage {
                            input_tokens: tokens_map
                                .get("input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            output_tokens: tokens_map
                                .get("output_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        }
                    })
                    .unwrap_or(crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    });

                out.push(IrStreamEvent::MessageDelta {
                    stop_reason,
                    // Cohere has no stop_sequence analog in its stream.
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
            }
            // Cohere v2 streams a tool call as a tool-call-start / tool-call-delta(s) /
            // tool-call-end sequence carrying the call under `delta.message.tool_calls`. Map them
            // onto the IR block lifecycle (BlockStart{ToolUse} / BlockDelta{InputJsonDelta} /
            // BlockStop) exactly as the OpenAI and Gemini readers do, so streaming tool use is not
            // silently discarded. Tool blocks occupy IR indices after any open text block.
            //
            // IR-index assignment must be STABLE for a tool's whole lifetime. Cohere v2 closes each
            // tool (tool-call-end) BEFORE opening the next (tool-call-start). A scheme that derived
            // the IR index from the LIVE rank of `frame_idx` was unstable two ways: derived from a
            // set that shrank on end it collapsed later tools onto the first tool's index, and even
            // from a never-shrunk set a NON-MONOTONIC upstream `frame_idx` (a later tool with a
            // smaller wire index) retroactively shifted an earlier tool's rank between its start and
            // its end. Instead the IR index is ASSIGNED ONCE at tool-call-start by
            // insertion order (`cohere_assign_tool_ir_index`), PACKED alongside the frame index into
            // `state.open_tools`, and looked up VERBATIM on delta/end
            // (`cohere_lookup_tool_ir_index`). `open_tools` is never shrunk, so the assignment
            // survives the stream and start/delta/end for a tool all resolve to the same IR index
            // regardless of wire-index ordering.
            ET_TOOL_CALL_START => {
                let frame_idx = clamp_frame_index(data);
                let tc = data
                    .get("delta")
                    .and_then(|d| d.get("message"))
                    .and_then(|m| m.get("tool_calls"));
                let id = tc
                    .and_then(|t| t.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = tc
                    .and_then(|t| t.get("function"))
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Assign (and record) the tool's immutable IR index. Returns None for a DUPLICATE
                // start (block already open — re-emitting BlockStart would push a spurious second
                // opening frame) or a genuinely new frame past the cap (not tracked — its
                // delta/end would be dropped, so emitting a BlockStart now would orphan it). Only
                // emit when the frame is freshly tracked.
                if let Some(ir_idx) = cohere_assign_tool_ir_index(state, frame_idx) {
                    out.push(IrStreamEvent::BlockStart {
                        index: ir_idx,
                        block: crate::ir::IrBlockMeta::ToolUse { id, name },
                    });
                    // Cohere may include initial argument text on the start frame.
                    if let Some(args) = tc
                        .and_then(|t| t.get("function"))
                        .and_then(|f| f.get("arguments"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        out.push(IrStreamEvent::BlockDelta {
                            index: ir_idx,
                            delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                        });
                    }
                }
            }
            ET_TOOL_CALL_DELTA => {
                let frame_idx = clamp_frame_index(data);
                // Only forward deltas for a frame we actually tracked (and therefore opened a
                // BlockStart for); resolve its immutable, ASSIGNED IR index. A frame past
                // MAX_TRACKED_TOOL_FRAMES was never recorded and `cohere_lookup_tool_ir_index`
                // returns None, so its delta is dropped rather than corrupting another block's
                // arguments. Mirrors the tool-call-end guard.
                if let Some(ir_idx) = cohere_lookup_tool_ir_index(state, frame_idx) {
                    if let Some(args) = data
                        .get("delta")
                        .and_then(|d| d.get("message"))
                        .and_then(|m| m.get("tool_calls"))
                        .and_then(|t| t.get("function"))
                        .and_then(|f| f.get("arguments"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        out.push(IrStreamEvent::BlockDelta {
                            index: ir_idx,
                            delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                        });
                    }
                }
            }
            ET_TOOL_CALL_END => {
                let frame_idx = clamp_frame_index(data);
                // Only close a tool we actually opened; resolve its immutable, ASSIGNED IR index. We
                // do NOT remove the frame's entry from `open_tools` — the recorded packed entry is
                // what keeps each tool's IR index stable for the stream's lifetime, and removing it
                // would let a later tool reuse a freed insertion slot.
                if let Some(ir_idx) = cohere_lookup_tool_ir_index(state, frame_idx) {
                    out.push(IrStreamEvent::BlockStop { index: ir_idx });
                }
            }
            // Genuinely unknown event types are intentionally ignored: the Cohere v2 stream may add
            // frames (e.g. citation/debug) that carry no IR-representable content. This is a named,
            // documented no-op arm — not a blanket `_ =>` that would also swallow tool-call frames.
            other => {
                debug_assert!(
                    !other.is_empty(),
                    "unexpected empty Cohere stream event type"
                );
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
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;
        let message_val = obj.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(content_arr) = message_val.get("content").and_then(|c| c.as_array()) {
            for block_val in content_arr {
                if let Some(block_obj) = block_val.as_object() {
                    if block_obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                        if let Some(text) = block_obj.get("text").and_then(|t| t.as_str()) {
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

        if let Some(tool_calls_arr) = message_val.get("tool_calls").and_then(|t| t.as_array()) {
            for tc_val in tool_calls_arr {
                if let Some(func_obj) = tc_val.get("function") {
                    let id = tc_val
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = func_obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let arguments = func_obj
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    let input = crate::json::parse_str(arguments)
                        .unwrap_or(serde_json::Value::String(arguments.to_string()));
                    content.push(crate::ir::IrBlock::ToolUse {
                        id,
                        name,
                        input,
                        cache_control: None,
                    });
                }
            }
        }

        let raw_finish_reason = obj
            .get("finish_reason")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        let stop_reason = if raw_finish_reason.is_empty() {
            None
        } else {
            Some(read_cohere_stop_reason(raw_finish_reason))
        };

        // Treat an absent `usage` object leniently — fall back to zero counts rather than hard-
        // erroring. A missing `usage` is an upstream response-format quirk (a mock/staging/proxy
        // Cohere-compatible backend that omits it), NOT a client mistake, so returning a
        // `ClientError` here mislabels the cause and breaks retry logic; the Bedrock and Gemini
        // readers tolerate the same condition with a zero-usage fallback. `usage_val` is an
        // `Option`, so each token lookup below already defaults to 0.
        let usage_val = obj.get("usage");
        let tokens_val = usage_val.and_then(|u| u.get("tokens"));
        let usage = crate::ir::IrUsage {
            input_tokens: tokens_val
                .and_then(|t| t.as_object())
                .and_then(|t_obj| t_obj.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: tokens_val
                .and_then(|t| t.as_object())
                .and_then(|t_obj| t_obj.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response identity so same-protocol (Cohere → Cohere) passthrough
        // preserves it exactly. Cohere v2 chat responses carry an opaque UUID-like `id`; if the
        // upstream omitted it, synthesize a shape-valid one rather than carrying `None` (so a
        // native SDK reading `.id` always sees a string). Cohere v2 has no `created`,
        // `system_fingerprint`, or `stop_sequence` field — those stay `None`.
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| Some(synthesize_cohere_id()));

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
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
}

pub(crate) struct CohereWriter {
    /// IR block indices for which this writer emitted a `tool-call-start` frame. The IR
    /// `BlockStop` carries only the integer index (no block kind), but a native Cohere v2 stream
    /// closes a tool-call block with `tool-call-end` and a text-content block with `content-end`.
    /// Emitting `content-end` for ALL `BlockStop` events — as a prior revision did — closed a
    /// tool-call block with the text-content close event, so a native Cohere SDK that distinguishes
    /// content events from tool-call events by type mis-decoded the stream. Track
    /// the tool-call opens here so `BlockStop` emits `tool-call-end` for a tool index and
    /// `content-end` for a text (or any non-tool) index. Per-stream INSTANCE state, mirroring the
    /// Responses writer's `open_tool_indices`: a `Mutex` keeps the writer `Sync` as the
    /// `ProtocolWriter` trait requires, and a stream is single-threaded at any instant so
    /// `Relaxed`-equivalent access is fine. Lock poisoning degrades to a no-op / `false` rather than
    /// panicking on the request path.
    open_tool_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Per-stream set of text-block indices that emitted a `content-start` frame, so the matching
    /// `BlockStop` emits `content-end` ONLY for a block that actually opened. Cross-protocol blocks
    /// that carry no opening frame (Thinking / Image — see the `BlockStart` arm, which maps them to
    /// `None`) are never recorded here, so their `BlockStop` emits NOTHING rather than an orphan
    /// `content-end` with no matching `content-start`. Mirrors the Gemini writer's
    /// no-frame-for-untracked-index behavior. Same `Mutex` / poison-degrades-to-no-op discipline as
    /// `open_tool_indices`.
    open_text_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
}

/// Value-namespace constructor for [`CohereWriter`]. A `const` and a struct may share a name (they
/// live in the value and type namespaces respectively), so `Protocol::cohere()` can keep writing
/// the bare `CohereWriter` literal while the type now carries per-stream state. Each USE of the
/// const inlines a fresh `CohereWriter` with an empty open-tool set, so every `Protocol::cohere()`
/// call mints independent per-stream state — exactly the per-stream scoping the open/close pairing
/// needs. `Mutex::new`/`BTreeSet::new` are const fns, so this is valid in const context.
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is
/// inlined per use rather than shared. That per-use fresh instance is PRECISELY the semantics we
/// need: a `static` would share ONE open-tool set across every stream in the process, letting one
/// stream's tool index leak into another. So the lint's suggestion is wrong for this site and is
/// suppressed deliberately (mirrors the Responses writer's identically-shaped const).
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const CohereWriter: CohereWriter = CohereWriter {
    open_tool_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    open_text_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
};

impl Clone for CohereWriter {
    fn clone(&self) -> Self {
        // Carry the open-tool-index set across a clone so a mid-stream `Protocol::clone` keeps the
        // in-flight tool-call open/close correlation; a poisoned lock degrades to an empty set
        // rather than panicking on the request path.
        CohereWriter {
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
        }
    }
}

impl CohereWriter {
    /// Record that a `tool-call-start` frame was emitted at IR block `index`, so the matching
    /// `BlockStop` closes it with `tool-call-end` rather than `content-end`. Lock poisoning degrades
    /// to a no-op rather than panicking on the request path.
    fn mark_tool_open(&self, index: usize) {
        if let Ok(mut set) = self.open_tool_indices.lock() {
            set.insert(index);
        }
    }

    /// Return true and forget `index` if it was a previously-opened tool-call block; false if no
    /// tool-call block was opened at `index` (e.g. a text block, whose `BlockStop` must emit
    /// `content-end`). Lock poisoning degrades to `false` (treat as a text close) rather than
    /// panicking on the request path.
    fn take_tool_open(&self, index: usize) -> bool {
        self.open_tool_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Record that a `content-start` frame was emitted for text block `index`, so the matching
    /// `BlockStop` emits `content-end` for it. Cross-protocol blocks that emit no opening frame
    /// (Thinking / Image) are never recorded, so their `BlockStop` stays silent. Lock poisoning
    /// degrades to a no-op rather than panicking on the request path.
    fn mark_text_open(&self, index: usize) {
        if let Ok(mut set) = self.open_text_indices.lock() {
            set.insert(index);
        }
    }

    /// Return true and forget `index` if a `content-start` was emitted for that text block; false if
    /// no text block opened at `index` (e.g. a Thinking block that carried no opening frame, whose
    /// `BlockStop` must emit nothing). Lock poisoning degrades to `false` (emit nothing) rather than
    /// panicking on the request path.
    fn take_text_open(&self, index: usize) -> bool {
        self.open_text_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }
}

impl ProtocolWriter for CohereWriter {
    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Shared warn+OMIT policy: a credential with bytes invalid for an HTTP header value is
        // dropped (with a protocol-named warn, never the key bytes) rather than emitting an empty
        // `Authorization:` tell. See `super::bearer_auth_headers`.
        super::bearer_auth_headers("cohere", key)
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        // The reasoning carry has no Cohere shape in this pass; dropped observably (matching
        // the penalties/top_k convention) rather than silently.
        if req.reasoning.is_some() {
            tracing::warn!(
                "dropping cross-protocol reasoning/thinking ask: no Cohere mapping in this release"
            );
        }
        let mut out = serde_json::Map::new();
        let mut messages_arr: Vec<serde_json::Value> = Vec::new();

        // Cohere v2 carries the system prompt as a leading system-role message.
        let system_text: String = req
            .system
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::Text { text, .. } = b {
                    Some(text.as_str())
                } else {
                    // A non-text system block (image/thinking/tool/…) has no Cohere v2 analog — the
                    // system prompt carries text only. WARN on the drop so the loss is operator-
                    // visible in observability, mirroring the Gemini writer's warn for the same case
                    // (the Gemini writer's comment even claims cohere already warns). (audit c2r3.)
                    tracing::warn!(
                        "dropping non-text system block on Cohere egress: Cohere v2 system prompt carries text only"
                    );
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !system_text.is_empty() {
            messages_arr.push(serde_json::json!({ "role": "system", "content": system_text }));
        }

        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::System => "system",
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
            };

            // Build content from the text blocks actually present. A single text block is sent as
            // a bare string (Cohere's preferred shape); multiple text blocks become a text-part
            // array. A message whose only block(s) are non-Text (e.g. a sole ToolUse, surfaced
            // separately via `tool_calls`) must NOT emit `content: []` — Cohere may reject that —
            // so we omit the `content` key entirely in that case.
            let text_blocks: Vec<&String> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Text { text, .. } = b {
                        Some(text)
                    } else {
                        None
                    }
                })
                .collect();

            // Cohere v2 multimodal output: an image block is written as an
            // `{"type":"image_url","image_url":{"url":"<data-uri|https>"}}` content part — the SAME
            // shape OpenAI v1 chat uses and this file's reader consumes. `image_url_from_ir` re-wraps
            // the IR (media_type, data) pair into the original URL (a base64 image becomes a
            // `data:<mime>;base64,<payload>` URI; an "image_url"-sentinel image emits its raw URL
            // verbatim). When ANY image is present the message MUST use the array content shape (a
            // bare string cannot carry an image part). ASSUMPTION (see report): the wire shape is
            // OpenAI-style `image_url`; no Cohere v2 image fixture exists in-repo to confirm it.
            let image_parts: Vec<serde_json::Value> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Image { source, .. } = b {
                        // A URL/base64 image projects to an `image_url`; a Responses `file_id` or
                        // Bedrock `s3Location` reference has no Cohere projection (returns None) and
                        // is skipped with a warn rather than corrupting the block.
                        match super::image_url_from_ir(source) {
                            Some(url) => Some(serde_json::json!({
                                "type": "image_url", "image_url": { "url": url }
                            })),
                            None => {
                                tracing::warn!(
                                    "dropping unresolvable vendor-scoped image reference on Cohere \
                                     egress: a file_id / s3Location has no cross-vendor analog"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
                .collect();

            let content_val: Option<serde_json::Value> = if image_parts.is_empty() {
                match text_blocks.as_slice() {
                    [] => None,
                    [single] => Some(serde_json::Value::String((*single).clone())),
                    many => Some(serde_json::Value::Array(
                        many.iter()
                            .map(|text| serde_json::json!({ "type": "text", "text": text }))
                            .collect(),
                    )),
                }
            } else {
                // Mixed/image content: emit a parts array with text parts first (preserving the
                // existing ordering of text before media), then the image parts.
                let mut parts: Vec<serde_json::Value> = text_blocks
                    .iter()
                    .map(|text| serde_json::json!({ "type": "text", "text": text }))
                    .collect();
                parts.extend(image_parts);
                Some(serde_json::Value::Array(parts))
            };

            if msg.role == crate::ir::IrRole::Tool {
                // Tool-role messages emit one Cohere tool message per ToolResult block. Any plain
                // text carried alongside the tool results (and the degenerate case of a Tool turn
                // with NO ToolResult block at all) must NOT be silently dropped: fold that text in
                // — onto the first tool message if there is one, otherwise as a standalone tool
                // message — so the turn is never lossy.
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let mut tool_result_obj = serde_json::Map::new();
                        tool_result_obj.insert("role".to_string(), serde_json::json!("tool"));
                        tool_result_obj.insert(
                            "tool_call_id".to_string(),
                            serde_json::Value::String(tool_use_id.clone()),
                        );
                        let mut text_parts: Vec<String> = content
                            .iter()
                            .filter_map(|b| {
                                if let crate::ir::IrBlock::Text { text, .. } = b {
                                    Some(text.clone())
                                } else {
                                    // A non-Text ToolResult block is a Bedrock json-tool-result
                                    // sentinel with no Cohere analog. Drop WITH a warn (drop-with-warn
                                    // convention) instead of vanishing silently.
                                    if super::is_json_tool_result_block(b) {
                                        tracing::warn!(
                                            "dropping structured json tool-result block on Cohere \
                                             egress: a Bedrock `{{\"json\":...}}` tool-result has no \
                                             cross-protocol analog and is NOT emitted"
                                        );
                                    }
                                    None
                                }
                            })
                            .collect();
                        // Prepend any message-level text onto the first tool result so it survives.
                        if !emitted_tool_result {
                            for t in text_blocks.iter().rev() {
                                text_parts.insert(0, (*t).clone());
                            }
                        }
                        tool_result_obj.insert(
                            "content".to_string(),
                            // Concatenate with NO separator, matching `read_request`'s `.join("")`:
                            // a block boundary is not a semantic space, and a " " here inserts a
                            // phantom space at each former boundary on a Cohere->X->Cohere round-trip
                            // (corrupting base64 / split-JSON tool-result payloads).
                            serde_json::Value::String(text_parts.join("")),
                        );
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                        emitted_tool_result = true;
                    }
                }
                // Degenerate Tool turn with text but no ToolResult: emit the text as a tool message
                // rather than dropping it entirely. Cohere tool message `content` must be a string,
                // so we stringify the text blocks (join with "") exactly like the ToolResult path —
                // forwarding `content_val` here would emit a JSON array for multi-block turns,
                // producing an invalid Cohere request.
                if !emitted_tool_result && !text_blocks.is_empty() {
                    let mut tool_obj = serde_json::Map::new();
                    tool_obj.insert("role".to_string(), serde_json::json!("tool"));
                    tool_obj.insert(
                        "content".to_string(),
                        serde_json::Value::String(
                            text_blocks
                                .iter()
                                .map(|t| t.as_str())
                                .collect::<Vec<&str>>()
                                .join(""),
                        ),
                    );
                    messages_arr.push(serde_json::Value::Object(tool_obj));
                }
                continue;
            }

            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            if let Some(content_val) = content_val {
                msg_obj.insert("content".to_string(), content_val);
            }

            if msg.role == crate::ir::IrRole::Assistant {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        let args_str =
                            crate::json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                        tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                    }
                }
                if !tool_calls_arr.is_empty() {
                    msg_obj.insert(
                        "tool_calls".to_string(),
                        serde_json::Value::Array(tool_calls_arr),
                    );
                }
            }

            messages_arr.push(serde_json::Value::Object(msg_obj));
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_arr),
        );

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut func_obj = serde_json::Map::new();
                func_obj.insert("name".to_string(), serde_json::json!(tool.name));
                if let Some(desc) = &tool.description {
                    func_obj.insert("description".to_string(), serde_json::json!(desc));
                }
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                func_obj.insert("parameters".to_string(), params);
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("function".to_string(), serde_json::Value::Object(func_obj));
                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Cohere v2 `tool_choice` is a top-level enum string with only REQUIRED/NONE — there is NO
        // single-tool targeting in the Cohere v2 API. `Auto` is Cohere's default (omit the field).
        //
        // A targeted single tool (`IrToolChoice::Tool { name }`) therefore has NO faithful Cohere
        // representation, so we degrade it to REQUIRED — force *some* tool — rather than silently
        // dropping to `auto`: this preserves the caller's "must call a tool" intent, which is the
        // load-bearing half of the request. What is lost is the *target* (the specific tool name):
        // Cohere may pick any tool, not the one the caller named. This is the ONE documented
        // tool_choice degradation in the codebase — lossy-by-target, intentional, and unavoidable
        // until/unless the Cohere v2 API gains a named-tool choice (PF-H1).
        if let Some(tc) = &req.tool_choice {
            let v = match tc {
                crate::ir::IrToolChoice::Required | crate::ir::IrToolChoice::Tool { .. } => {
                    Some(COHERE_TOOL_CHOICE_REQUIRED)
                }
                crate::ir::IrToolChoice::None => Some(COHERE_TOOL_CHOICE_NONE),
                crate::ir::IrToolChoice::Auto => None,
            };
            if let Some(s) = v {
                out.insert("tool_choice".to_string(), serde_json::json!(s));
            }
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            // Clamp to Cohere's native [0.0, 1.0] (PF-M1) — see `clamp_temperature_for_cohere`.
            // NON-SILENT clamp (the M2 fidelity fix): the writer previously clamped SILENTLY, exactly
            // the lossy mutation busbar exists to avoid. We keep the clamp (Cohere 400s on >1.0) but
            // emit a `warn!` whenever it ACTUALLY changes the value so an operator can detect the
            // divergence in logs. Mirrors the anthropic/bedrock writers' non-silent clamp.
            let (clamped, was_clamped) = clamp_temperature_for_cohere(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "clamping temperature to Cohere's [0.0, 1.0] range; the requested value was \
                     outside it (e.g. an OpenAI/Responses value up to 2.0) and would 400 — the \
                     forwarded value diverges from the caller's request"
                );
            }
            out.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Promoted sampling controls in Cohere v2's native names: `p` (top_p), `k` (top_k),
        // `stop_sequences`. Emitted before the `extra` overlay (the reader pulled these keys out of
        // extra, so there is no double-emit on a same-protocol passthrough).
        if let Some(top_p) = req.top_p {
            out.insert("p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            out.insert("k".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            out.insert("stop_sequences".to_string(), serde_json::json!(req.stop));
        }
        // Phase 0 sampling/output controls in Cohere v2's native (OpenAI-shaped) names. Emitted
        // before the `extra` overlay (the reader pulled these keys out of extra, so there is no
        // double-emit on a same-protocol passthrough).
        if let Some(frequency_penalty) = req.frequency_penalty {
            out.insert(
                "frequency_penalty".to_string(),
                serde_json::json!(frequency_penalty),
            );
        }
        if let Some(presence_penalty) = req.presence_penalty {
            out.insert(
                "presence_penalty".to_string(),
                serde_json::json!(presence_penalty),
            );
        }
        // Cohere v2 chat supports a top-level integer `seed`. Emit it when present so deterministic
        // sampling survives the seam (the reader models it as a modeled key, so no double-emit).
        if let Some(seed) = req.seed {
            out.insert("seed".to_string(), serde_json::json!(seed));
        }
        // `response_format` (structured output): a Cohere-native object passes through verbatim; a
        // foreign shape (OpenAI `type:"json_schema"` with a nested `json_schema.schema`, or Gemini
        // `responseMimeType`/`responseSchema`) is mapped into Cohere's native `{type:"json_object",
        // json_schema:<schema>}` so a Cohere backend accepts it instead of 400-ing on the off-shape.
        if let Some(response_format) = &req.response_format {
            out.insert(
                "response_format".to_string(),
                write_cohere_response_format(response_format),
            );
        }
        // M4: Cohere-native `documents` (RAG grounding) has no cross-protocol analog and is not
        // modeled in the IR; on a same-protocol hop it flows through `extra` byte-exact below. The
        // non-silent loss warn for the cross-protocol case lives in `read_request` (the only Cohere
        // site that still sees an inbound `documents` before `extra` is cleared at the seam).
        // Only emit `stream` when streaming is requested. A native Cohere client omitting `stream`
        // (relying on the `false` default) produces a body WITHOUT the field; always injecting
        // `"stream": false` is a proxy tell and a same-protocol passthrough fidelity break (the
        // reader treats `stream` as a modeled key, so it is never echoed via `extra`). The Gemini
        // writer likewise never emits `stream` in the body.
        if req.stream {
            out.insert("stream".to_string(), serde_json::json!(true));
        }
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, id, .. } => {
                let cohere_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::System
                    | crate::ir::IrRole::User
                    | crate::ir::IrRole::Tool => return None,
                };
                // Cohere v2 streams carry the response `id` on the message-start frame. Preserve a
                // captured id; synthesize a shape-valid one for the cross-protocol case so the
                // emitted stream is indistinguishable from a native Cohere stream.
                let id = id.clone().unwrap_or_else(synthesize_cohere_id);
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "id": id,
                        "type": ET_MESSAGE_START,
                        "delta": { "message": { "role": cohere_role } }
                    }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // Record the open text index so its matching `BlockStop` emits `content-end`. A
                    // cross-protocol block that carries NO opening frame (Thinking / Image, below)
                    // is never recorded, so its `BlockStop` stays silent rather than emitting an
                    // orphan `content-end` — see `open_text_indices`.
                    self.mark_text_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_CONTENT_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "content": { "type": "text", "text": "" }
                                }
                            }
                        }),
                    ))
                }
                // Cross-protocol streaming tool use (e.g. Anthropic/Gemini → Cohere-ingress) must
                // surface a native `tool-call-start` frame mirroring the shape this file's own
                // reader consumes (delta.message.tool_calls.{id,type,function.{name,arguments}}).
                // Omitting it made streamed tool calls invisible to a Cohere client. The reader
                // expects `function.arguments` to be a (possibly empty) string and accumulates
                // tool-call-delta argument fragments onto it, so we open with an empty string.
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Record the open tool index so the matching `BlockStop` closes it with
                    // `tool-call-end` (the native Cohere v2 close event for a tool block) rather
                    // than `content-end` (the text-block close event) — see `open_tool_indices`.
                    self.mark_tool_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_TOOL_CALL_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "tool_calls": {
                                        "id": id,
                                        "type": "function",
                                        "function": { "name": name, "arguments": "" }
                                    }
                                }
                            }
                        }),
                    ))
                }
                // Cohere v2 has no streamed thinking/image block shape. Emitting a fabricated frame
                // would be a non-native proxy tell, so these IR block kinds carry no opening frame.
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    // Native Cohere v2 content-delta frames carry the text at
                    // delta.message.content.text (an object), matching the content-start shape and
                    // this reader's object path. A bare string here is non-native and a client that
                    // reads content.text would accumulate nothing.
                    serde_json::json!({
                        "type": ET_CONTENT_DELTA,
                        "index": index,
                        "delta": { "message": { "content": { "type": "text", "text": text } } }
                    }),
                )),
                // Streamed tool-call argument fragments map to a native `tool-call-delta` frame
                // carrying the argument chunk at delta.message.tool_calls.function.arguments — the
                // exact path this file's reader reads. Without this arm, cross-protocol tool-call
                // arguments never reached a Cohere-ingress client.
                crate::ir::IrDelta::InputJsonDelta(args) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_TOOL_CALL_DELTA,
                        "index": index,
                        "delta": {
                            "message": {
                                "tool_calls": { "function": { "arguments": args } }
                            }
                        }
                    }),
                )),
                // Cohere v2 streams carry no thinking/signature delta shape; suppress rather than
                // emit a non-native frame.
                crate::ir::IrDelta::ThinkingDelta(_) => None,
                crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_) => None,
                // L2-5: Cohere v2 streams carry no citation delta shape; suppress rather than emit
                // a non-native frame. The citation is preserved in the IR for protocols that model
                // streaming citations.
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Cohere v2 has no cross-protocol logprobs shape (token IDs only); dropped.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer index, not the block kind. A native
                // Cohere v2 stream closes a tool-call block with `tool-call-end` and a text-content
                // block with `content-end`. Emitting `content-end` for BOTH — as a prior revision
                // did — closed a tool-call block with the text close event, so a native Cohere SDK
                // (which keys on event type to track tool-call state) mis-decoded the stream and the
                // tool block was never properly terminated. So consult the
                // per-stream open-tool set: a tool-call index (recorded by its `tool-call-start`)
                // closes with `tool-call-end`, consuming the marker; any other index (a text block)
                // closes with `content-end`.
                // A tool-call index (recorded by its `tool-call-start`) closes with `tool-call-end`,
                // consuming its marker. A text index (recorded by its `content-start`) closes with
                // `content-end`, consuming its marker. An UNTRACKED index — a cross-protocol block
                // that emitted no opening frame (Thinking / Image, whose `BlockStart` maps to `None`)
                // — emits NOTHING: previously it fell through to an unconditional `content-end`,
                // producing an orphan close with no matching `content-start`. This
                // mirrors the Gemini writer's no-frame-for-untracked-index behavior.
                if self.take_tool_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_TOOL_CALL_END, "index": index }),
                    ))
                } else if self.take_text_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_CONTENT_END, "index": index }),
                    ))
                } else {
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let cohere_finish_reason = stop_reason
                    .map(write_cohere_stop_reason)
                    .unwrap_or(COHERE_FINISH_COMPLETE);
                // Native Cohere v2 message-end frames carry token usage inside
                // delta.usage.tokens.{input_tokens,output_tokens}. Surface it so a Cohere SDK
                // client tracking billing/rate-limit data from the stream is not silently zeroed.
                // IrUsage is always present (not Option); when upstream supplied nothing it is
                // zero-valued, which serializes here as a safe `{input_tokens:0,output_tokens:0}`.
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": cohere_finish_reason,
                            "usage": {
                                "tokens": {
                                    "input_tokens": usage.input_tokens,
                                    "output_tokens": usage.output_tokens
                                }
                            }
                        }
                    }),
                ))
            }

            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                // Cohere v2 has NO `type: "error"` out-of-band stream event. A native v2 stream
                // signals a mid-stream error by terminating with a `message-end` frame whose
                // `finish_reason` is `ERROR` (infrastructure failure) or `ERROR_TOXIC` (content
                // moderation). Emitting a `type: "error"` frame was both non-native (a strict Cohere
                // SDK ignores or rejects an unknown event type, silently dropping the error) and a
                // protocol-indistinguishability tell. We therefore emit the native `message-end`
                // termination instead. The reader maps `ERROR_TOXIC` back to IR `safety` and the
                // generic `ERROR` to IR `error` (the lowercase passthrough), so this round-trips: a
                // content-moderation signal in the provider_signal maps to `ERROR_TOXIC`, everything
                // else to the generic `ERROR`.
                let toxic = err
                    .provider_signal
                    .as_deref()
                    .is_some_and(cohere_error_is_content_moderation);
                let finish_reason = if toxic {
                    COHERE_FINISH_ERROR_TOXIC
                } else {
                    COHERE_FINISH_ERROR
                };
                // Emit the native `message-end` shape EXACTLY — `type` + `delta.{finish_reason,
                // usage}` — and nothing else. A native Cohere v2 `message-end` frame (the one the
                // normal MessageDelta arm above produces) carries ONLY `type` and `delta`; it never
                // carries a top-level `message`, and it ALWAYS includes `delta.usage`. A prior
                // revision added a top-level `"message": <detail>` field and omitted `delta.usage`,
                // both of which diverge from the native wire shape and let a client (or passive
                // observer) fingerprint the proxy — and a strict v2 SDK may reject the unexpected
                // field. The load-bearing discriminant is
                // `finish_reason` (`ERROR`/`ERROR_TOXIC`), which the reader maps back to IR
                // (`error`/`safety` respectively), so the detail string carries no protocol value on
                // the wire; surface it server-side instead so operators are not left with an opaque
                // error.
                if let Some(detail) = err.provider_signal.as_deref() {
                    tracing::warn!(
                        finish_reason,
                        detail,
                        "cohere: mid-stream error terminating with native message-end frame"
                    );
                }
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": finish_reason,
                            "usage": {
                                "tokens": { "input_tokens": 0, "output_tokens": 0 }
                            }
                        }
                    }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let mut content_arr: Vec<serde_json::Value> = Vec::new();
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                }
                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    let args_str =
                        crate::json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    // Accumulate every tool call. Inserting per-iteration would overwrite the
                    // key and silently drop all but the last call on parallel tool use.
                    tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                crate::ir::IrBlock::Image { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Json(_) => {}
            }
        }

        let cohere_finish_reason = resp
            .stop_reason
            .map(write_cohere_stop_reason)
            .unwrap_or(COHERE_FINISH_COMPLETE);

        // Cohere format: usage.tokens.input_tokens, usage.tokens.output_tokens
        let mut tokens_map = serde_json::Map::new();
        tokens_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        tokens_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        // Emit the response identity. Same-protocol passthrough preserves the captured upstream
        // `id` exactly; the cross-protocol case (a non-Cohere backend that never supplied one)
        // hits `None` and we synthesize a shape-valid Cohere id so a native SDK always reads a
        // non-empty `.id` string.
        let id = resp.id.clone().unwrap_or_else(synthesize_cohere_id);
        out.insert("id".to_string(), serde_json::Value::String(id));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out.insert("model".to_string(), serde_json::json!(model));
        }
        out.insert(
            "finish_reason".to_string(),
            serde_json::json!(cohere_finish_reason),
        );
        // Native Cohere v2 carries tool calls INSIDE the message object (response.message
        // .tool_calls) — exactly where this file's own read_response reads them from. Nesting them
        // here (rather than at the top level) keeps the body native for a real Cohere SDK and lets
        // a Cohere -> Cohere passthrough round-trip every parallel tool call.
        let mut message_obj = serde_json::Map::new();
        message_obj.insert("role".to_string(), serde_json::json!("assistant"));
        message_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
        if !tool_calls_arr.is_empty() {
            message_obj.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls_arr),
            );
        }
        out.insert(
            "message".to_string(),
            serde_json::Value::Object(message_obj),
        );
        // Wrap tokens under "tokens" key per Cohere API spec
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("tokens".to_string(), serde_json::Value::Object(tokens_map));
        out.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(out)
    }

    /// NATIVE Cohere v2 error envelope. The Cohere v2 chat API conveys the error *category* via the
    /// HTTP status (400/401/404/429/5xx) and carries only a human-readable `{"message": <detail>}`
    /// body — it has no typed `error.type`/`code` field the way OpenAI/Anthropic do. So the generic
    /// `kind` is intentionally NOT surfaced in the body (it would be a field a native SDK never
    /// sees); it is dropped here and conveyed solely by the caller's HTTP status. Real Cohere v2
    /// error bodies are a bare `{"message": "..."}` and do NOT carry a synthesized id; this reader's
    /// own `extract_error` reads only `message`/`error_type` and never `id`, so emitting an `id`
    /// here was both a proxy tell and internally inconsistent with the reader. Served as
    /// `application/json` per the trait contract.
    ///
    /// This is a LIVE production code path, not test-only scaffolding: it is reached at runtime via
    /// the `ProtocolWriter` trait object on every Cohere-ingress error response (e.g. route.rs,
    /// forward.rs, and auth.rs all dispatch `p.writer().write_error(...)`). It carries no
    /// `allow(dead_code)` suppression — matching every other protocol writer — because the
    /// dead-code lint never fires on vtable-dispatched trait method implementations.
    fn write_error(&self, _status: u16, _kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "message": message,
        })
    }

    fn egress_user_agent(&self) -> &'static str {
        // Cohere Python SDK UA shape — pinned, see `EGRESS_UA_COHERE` in forward.rs.
        crate::proxy::EGRESS_UA_COHERE
    }

    fn auth_failure_message(&self) -> &'static str {
        "invalid api token"
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
