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

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

mod reader;
mod writer;
