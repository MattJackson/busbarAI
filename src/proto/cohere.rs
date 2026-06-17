// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Cohere v2 protocol reader/writer implementation.

use super::*;
use std::sync::OnceLock;

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
/// `content-end`, so that live flag cannot answer the question — see the HIGH finding this fixes).
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

/// Pack a tool call's wire `frame_idx` and the IR block index ASSIGNED to it at `tool-call-start`
/// into a single `usize` recorded in `state.open_tools`. The IR index lives in the low
/// `TOOL_ENTRY_IR_BITS`; the frame index in the high bits. Storing BOTH is what makes the IR index
/// immutable for the tool's lifetime: it is assigned once on start and looked up verbatim on
/// delta/end (see `cohere_lookup_tool_ir_index`), so a non-monotonic upstream `frame_idx` can no
/// longer perturb a live rank and shift a tool's index mid-lifecycle (the LOW finding this fixes).
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

/// The request keys this reader models explicitly (and therefore must NOT echo back through
/// `extra`). Built once per process via `OnceLock` instead of being reconstructed on every
/// `read_request` call — the rebuild was a pointless per-request allocation on the Cohere ingress
/// hot path (the MEDIUM/performance finding, shared with the Gemini/Bedrock readers).
/// Normalize Cohere v2's native `tool_choice` (a top-level enum STRING) into the IR's tool-choice
/// union so a forced directive survives the cross-protocol seam instead of degrading to `auto`
/// (PF-H1). Cohere v2 models only `REQUIRED` (must call some tool) and `NONE` (no tool); it has no
/// `auto` literal (auto is the default when omitted) and no way to pin ONE specific tool. So an
/// unrecognized/absent value yields `None` (omitted), and the targeted-tool case is handled lossily
/// on the WRITE side (degraded to `REQUIRED`). The reader can only ever observe `REQUIRED`/`NONE`.
fn read_cohere_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    match val?.as_str()? {
        "REQUIRED" => Some(crate::ir::IrToolChoice::Required),
        "NONE" => Some(crate::ir::IrToolChoice::None),
        _ => None,
    }
}

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
    let _ = getrandom::getrandom(&mut bytes);

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
/// out of order (the LOW finding: a non-monotonic frame index used to perturb the recomputed rank
/// and shift a tool's index mid-lifecycle).
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
/// false before tools arrive — keeps tool blocks off the text block's index 0 (the HIGH finding).
/// Keying the per-tool offset on INSERTION ORDER (the count of already-tracked tools) rather than the
/// wire-index rank makes the assignment independent of monotonic wire indices and immutable once
/// made: a later tool with a SMALLER wire `frame_idx` no longer retroactively shifts an earlier
/// tool's index (the LOW finding). `state.open_tools` is never shrunk for the stream's lifetime, so a
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
/// stays off the text index even after `content-end` clears the live flag — the HIGH finding); this
/// helper governs only the TEXT block's own index (the LOW collision finding: tool-before-text).
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
    /// broader provider wording the audit calls out ("input too long", "exceeds maximum context",
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
        let json = serde_json::from_slice::<serde_json::Value>(body).ok();
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
            Some("context_length_exceeded".to_string())
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
                provider_signal: Some("context_length_exceeded".to_string()),
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

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
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
                            provider_signal: Some("ir_parse".to_string()),
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
                                    if block_obj.get("type").and_then(|t| t.as_str())
                                        == Some("text")
                                    {
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
                                    let input = serde_json::from_str(arguments).unwrap_or(
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
                                            serde_json::to_string(b).ok()
                                        }
                                    } else {
                                        // Non-string, non-object array element: serialize it so no
                                        // content is lost.
                                        serde_json::to_string(b).ok()
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(" ")
                        } else if let Some(s) = content_val.as_str() {
                            s.to_string()
                        } else {
                            serde_json::to_string(content_val).unwrap_or_default()
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
                provider_signal: Some("ir_parse".to_string()),
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
        if data.as_str() == Some("[DONE]") || !data.is_object() {
            return out;
        }

        let event_type_val = data.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type_val {
            "message-start" => {
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
            "content-start" => {
                // The text content block claims a DYNAMIC IR index by order of first appearance
                // (`cohere_text_ir_index`), NOT a hardcoded 0: a `tool-call-start` that arrived
                // before any content frame already took 0, and forcing text to 0 here produced two
                // BlockStart frames at the same IR index (the LOW tool/text collision finding).
                // `cohere_text_ir_index` also records the persistent TEXT_BLOCK_SEEN_SENTINEL so a
                // tool opened AFTER the text block stays off the text index even after content-end
                // clears the live flag (the HIGH finding). The raw upstream wire `index` is still
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
            "content-delta" => {
                // The text content block claims a DYNAMIC IR index by order of first appearance
                // (`cohere_text_ir_index`) — see content-start — NOT a hardcoded 0, so a tool that
                // opened ahead of the first content frame (and took 0) does not collide with the
                // text block (the LOW finding). The raw upstream wire `index` is never forwarded;
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
                            // Native Cohere v2 content-delta shape: `content` is a single
                            // `{ "type": "text", "text": "<chunk>" }` object (the exact shape this
                            // file's writer emits at delta.message.content). Without this branch the
                            // object falls through both the string and array arms and the streamed
                            // text is silently dropped — a writer→reader roundtrip break and data
                            // loss on a real Cohere v2 backend stream.
                            if block_obj.get("type").and_then(|t| t.as_str()) == Some("text") {
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
            "content-end" => {
                // content-end closes the text content block at the IR index it actually CLAIMED on
                // first appearance (`state.text_index`), NOT a hardcoded 0 — a tool may have taken 0
                // ahead of it (the LOW tool/text collision finding), so closing 0 here would leave
                // the real text block open and stop a phantom one. The raw wire `index` is never
                // forwarded. Only emit the stop if a text block is actually open, so a stray
                // content-end never produces an unbalanced BlockStop. `state.text_index` is NOT
                // cleared (mirroring how the tool entries stay recorded in `open_tools` for the
                // stream's lifetime): keeping the claimed index immutable means a re-opened text
                // block resolves to the SAME slot and a tool opened after content-end still derives
                // its base off the persistent TEXT_BLOCK_SEEN_SENTINEL, so neither can collide with
                // the text index (the HIGH finding).
                if state.text_block_open {
                    state.text_block_open = false;
                    let ti = state.text_index.unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
            }
            "message-end" => {
                let raw_finish_reason = data
                    .get("delta")
                    .and_then(|d| d.get("finish_reason"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let stop_reason = match raw_finish_reason {
                    "COMPLETE" => Some("end_turn".to_string()),
                    "MAX_TOKENS" => Some("max_tokens".to_string()),
                    "TOOL_CALL" => Some("tool_use".to_string()),
                    "STOP_SEQUENCE" => Some("stop_sequence".to_string()),
                    // Only `ERROR_TOXIC` (content-moderated output) is the moderation/`safety`
                    // signal. The generic `ERROR` is an infrastructure failure and must NOT be
                    // folded into `safety`: doing so turned a Cohere->Cohere passthrough of a
                    // server error into a fabricated content-moderation stop. Let `ERROR` fall
                    // through to the generic lowercase arm (-> IR `"error"`), which the writers
                    // round-trip back to the native `ERROR` via their `reason.to_uppercase()` arm.
                    "ERROR_TOXIC" => Some("safety".to_string()),
                    other if !other.is_empty() => Some(other.to_lowercase()),
                    _ => None,
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
            // its end (the LOW finding). Instead the IR index is ASSIGNED ONCE at tool-call-start by
            // insertion order (`cohere_assign_tool_ir_index`), PACKED alongside the frame index into
            // `state.open_tools`, and looked up VERBATIM on delta/end
            // (`cohere_lookup_tool_ir_index`). `open_tools` is never shrunk, so the assignment
            // survives the stream and start/delta/end for a tool all resolve to the same IR index
            // regardless of wire-index ordering.
            "tool-call-start" => {
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
            "tool-call-delta" => {
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
            "tool-call-end" => {
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
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;
        let message_val = obj.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
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
                    let input = serde_json::from_str(arguments)
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
        let stop_reason = match raw_finish_reason {
            "COMPLETE" => Some("end_turn".to_string()),
            "MAX_TOKENS" => Some("max_tokens".to_string()),
            "TOOL_CALL" => Some("tool_use".to_string()),
            "STOP_SEQUENCE" => Some("stop_sequence".to_string()),
            // Only `ERROR_TOXIC` (content-moderated output) is the moderation/`safety` signal. The
            // generic `ERROR` is an infrastructure failure and must NOT be folded into `safety`:
            // doing so turned a Cohere->Cohere passthrough of a server error into a fabricated
            // content-moderation stop. Let `ERROR` fall through to the generic lowercase arm (-> IR
            // `"error"`), which the writers round-trip back to the native `ERROR` via their
            // `reason.to_uppercase()` arm.
            "ERROR_TOXIC" => Some("safety".to_string()),
            other if !other.is_empty() => Some(other.to_lowercase()),
            _ => None,
        };

        // Treat an absent `usage` object leniently — fall back to zero counts rather than hard-
        // erroring. A missing `usage` is an upstream response-format quirk (a mock/staging/proxy
        // Cohere-compatible backend that omits it), NOT a client mistake, so returning a
        // `ClientError` here mislabels the cause and breaks retry logic; the Bedrock and Gemini
        // readers tolerate the same condition with a zero-usage fallback (the MEDIUM/correctness
        // finding). `usage_val` is an `Option`, so each token lookup below already defaults to 0.
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
    /// content events from tool-call events by type mis-decoded the stream (the HIGH finding). Track
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
        "/v2/chat"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Shared warn+OMIT policy: a credential with bytes invalid for an HTTP header value is
        // dropped (with a protocol-named warn, never the key bytes) rather than emitting an empty
        // `Authorization:` tell. See `super::bearer_auth_headers`.
        super::bearer_auth_headers("cohere", key)
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
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

            let content_val: Option<serde_json::Value> = match text_blocks.as_slice() {
                [] => None,
                [single] => Some(serde_json::Value::String((*single).clone())),
                many => Some(serde_json::Value::Array(
                    many.iter()
                        .map(|text| serde_json::json!({ "type": "text", "text": text }))
                        .collect(),
                )),
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
                        is_error: _,
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
                            serde_json::Value::String(text_parts.join(" ")),
                        );
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                        emitted_tool_result = true;
                    }
                }
                // Degenerate Tool turn with text but no ToolResult: emit the text as a tool message
                // rather than dropping it entirely. Cohere tool message `content` must be a string,
                // so we stringify the text blocks (join with " ") exactly like the ToolResult path —
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
                                .join(" "),
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
                            serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
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
                    Some("REQUIRED")
                }
                crate::ir::IrToolChoice::None => Some("NONE"),
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
            // Clamp to Cohere's native [0.0, 1.0] (PF-M1). OpenAI / Responses accept temperature up to
            // 2.0, so a cross-protocol request can carry a value Cohere's API rejects with a hard 400
            // ValidationException; clamping forwards the closest valid value instead.
            let clamped = temperature.clamp(0.0, 1.0);
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
                        "type": "message-start",
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
                            "type": "content-start",
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
                            "type": "tool-call-start",
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
                        "type": "content-delta",
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
                        "type": "tool-call-delta",
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
                crate::ir::IrDelta::SignatureDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer index, not the block kind. A native
                // Cohere v2 stream closes a tool-call block with `tool-call-end` and a text-content
                // block with `content-end`. Emitting `content-end` for BOTH — as a prior revision
                // did — closed a tool-call block with the text close event, so a native Cohere SDK
                // (which keys on event type to track tool-call state) mis-decoded the stream and the
                // tool block was never properly terminated (the HIGH finding). So consult the
                // per-stream open-tool set: a tool-call index (recorded by its `tool-call-start`)
                // closes with `tool-call-end`, consuming the marker; any other index (a text block)
                // closes with `content-end`.
                // A tool-call index (recorded by its `tool-call-start`) closes with `tool-call-end`,
                // consuming its marker. A text index (recorded by its `content-start`) closes with
                // `content-end`, consuming its marker. An UNTRACKED index — a cross-protocol block
                // that emitted no opening frame (Thinking / Image, whose `BlockStart` maps to `None`)
                // — emits NOTHING: previously it fell through to an unconditional `content-end`,
                // producing an orphan close with no matching `content-start` (the MED finding). This
                // mirrors the Gemini writer's no-frame-for-untracked-index behavior.
                if self.take_tool_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": "tool-call-end", "index": index }),
                    ))
                } else if self.take_text_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": "content-end", "index": index }),
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
                let cohere_finish_reason = match stop_reason.as_deref() {
                    Some("end_turn") => "COMPLETE".to_string(),
                    // A stop sequence firing is a DISTINCT native Cohere stop condition from a
                    // normal end-of-turn; write back the native `STOP_SEQUENCE` so the reader's
                    // `STOP_SEQUENCE` -> IR `stop_sequence` mapping round-trips symmetrically and a
                    // Cohere client inspecting `finish_reason` sees the real stop condition instead
                    // of a masked `COMPLETE` (the conformance finding).
                    Some("stop_sequence") => "STOP_SEQUENCE".to_string(),
                    Some("max_tokens") => "MAX_TOKENS".to_string(),
                    Some("tool_use") => "TOOL_CALL".to_string(),
                    // IR `safety` is Cohere's content-moderation stop. The reader normalises BOTH
                    // native `ERROR_TOXIC` (content-moderated output) and `ERROR` (infrastructure
                    // failure) to `safety`, but only `ERROR_TOXIC` is the content-moderation signal,
                    // so write that back: it round-trips a Cohere->Cohere `ERROR_TOXIC` cleanly and
                    // is the closest native analog for a cross-protocol `safety` arriving from a
                    // non-Cohere source. Writing `ERROR` here mislabelled a moderation stop as a
                    // server error (the finding).
                    Some("safety") => "ERROR_TOXIC".to_string(),
                    Some(reason) => reason.to_uppercase(),
                    None => "COMPLETE".to_string(),
                };
                // Native Cohere v2 message-end frames carry token usage inside
                // delta.usage.tokens.{input_tokens,output_tokens}. Surface it so a Cohere SDK
                // client tracking billing/rate-limit data from the stream is not silently zeroed.
                // IrUsage is always present (not Option); when upstream supplied nothing it is
                // zero-valued, which serializes here as a safe `{input_tokens:0,output_tokens:0}`.
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": "message-end",
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
                let finish_reason = if toxic { "ERROR_TOXIC" } else { "ERROR" };
                // Emit the native `message-end` shape EXACTLY — `type` + `delta.{finish_reason,
                // usage}` — and nothing else. A native Cohere v2 `message-end` frame (the one the
                // normal MessageDelta arm above produces) carries ONLY `type` and `delta`; it never
                // carries a top-level `message`, and it ALWAYS includes `delta.usage`. A prior
                // revision added a top-level `"message": <detail>` field and omitted `delta.usage`,
                // both of which diverge from the native wire shape and let a client (or passive
                // observer) fingerprint the proxy — and a strict v2 SDK may reject the unexpected
                // field (the MEDIUM/conformance findings). The load-bearing discriminant is
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
                        "type": "message-end",
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
                        serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    // Accumulate every tool call. Inserting per-iteration would overwrite the
                    // key and silently drop all but the last call on parallel tool use.
                    tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                crate::ir::IrBlock::Image { .. } | crate::ir::IrBlock::ToolResult { .. } => {}
            }
        }

        let cohere_finish_reason = match resp.stop_reason.as_deref() {
            Some("end_turn") => "COMPLETE".to_string(),
            // A stop sequence firing is a DISTINCT native Cohere stop condition from a normal
            // end-of-turn; write back the native `STOP_SEQUENCE` so the reader's `STOP_SEQUENCE`
            // -> IR `stop_sequence` mapping round-trips symmetrically and a Cohere client inspecting
            // `finish_reason` sees the real stop condition instead of a masked `COMPLETE` (the
            // conformance finding).
            Some("stop_sequence") => "STOP_SEQUENCE".to_string(),
            Some("max_tokens") => "MAX_TOKENS".to_string(),
            Some("tool_use") => "TOOL_CALL".to_string(),
            // See the streaming path: IR `safety` writes back as `ERROR_TOXIC` (the native
            // content-moderation stop), which round-trips cleanly and never mislabels a moderation
            // stop as a server-side `ERROR`.
            Some("safety") => "ERROR_TOXIC".to_string(),
            Some(reason) => reason.to_uppercase(),
            None => "COMPLETE".to_string(),
        };

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
        // Cohere Python SDK UA shape — pinned, see `EGRESS_UA_COHERE` audit note in forward.rs.
        crate::forward::EGRESS_UA_COHERE
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
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
                        id: "t1".to_string(),
                        name: "f".to_string(),
                        input: serde_json::json!({"x": 1}),
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "result text".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "f".to_string(),
                description: Some("..".to_string()),
                input_schema: serde_json::json!({}),
                cache_control: None,
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7),
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let json = writer.write_request(&ir);

        assert!(json.get("messages").is_some());
        let msgs = json.get("messages").unwrap().as_array().unwrap();
        // system prompt (from IrRequest.system) is prepended as a leading system message
        assert_eq!(msgs[0].get("role"), Some(&serde_json::json!("system")));
        assert_eq!(
            msgs[0].get("content"),
            Some(&serde_json::json!("You are helpful."))
        );
        assert_eq!(msgs[1].get("role"), Some(&serde_json::json!("user")));
        assert_eq!(msgs[2].get("role"), Some(&serde_json::json!("assistant")));

        let tool_calls = msgs[2].get("tool_calls").unwrap().as_array().unwrap();
        assert_eq!(
            tool_calls[0]
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str()),
            Some("f")
        );

        let tools_arr = json.get("tools").unwrap().as_array().unwrap();
        assert_eq!(
            tools_arr[0]
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str()),
            Some("f")
        );

        assert_eq!(json.get("max_tokens"), Some(&serde_json::json!(1024)));
        assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
    }

    #[test]
    fn test_read_request_roundtrip() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "user msg".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "assistant msg".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: vec![],
            max_tokens: Some(512),
            temperature: Some(0.7),
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: true,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let reader = CohereReader;
        let json = writer.write_request(&ir);
        let ir2 = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir, ir2);
    }

    #[test]
    fn test_read_response() {
        let json = serde_json::json!({
            "id": "msg_123",
            "finish_reason": "TOOL_CALL",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "tool_use", "id": "t1", "name": "get_weather", "input": {"location": "SF"}}
                ]
            },
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        });

        let reader = CohereReader;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.stop_reason, Some("tool_use".to_string()));
        assert_eq!(resp.usage.input_tokens, 10);
        // The upstream `id` is captured verbatim into the IR (same-protocol identity fidelity).
        assert_eq!(resp.id.as_deref(), Some("msg_123"));
    }

    #[test]
    fn test_write_response_roundtrip() {
        // Carries a real upstream id; same-protocol read→write must preserve it byte-identically.
        let json = serde_json::json!({
            "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
            "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        });

        let reader = CohereReader;
        let writer = CohereWriter;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");
        let json2 = writer.write_response(&resp);

        assert_eq!(json, json2);
    }

    #[test]
    fn test_stream_fanout() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // message-start
        let evs = reader.read_response_events("", &serde_json::json!({"type": "message-start", "delta": {"message": {"role": "assistant"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::MessageStart { .. }
        ));

        // content-start
        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}), &mut state);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ));

        // content-delta x2
        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": "he"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        if let crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(ref t),
        } = &evs[0]
        {
            assert_eq!(t, "he");
        }

        let evs = reader.read_response_events("", &serde_json::json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": "llo"}}}), &mut state);
        assert_eq!(evs.len(), 1);
        if let crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(ref t),
        } = &evs[0]
        {
            assert_eq!(t, "llo");
        }

        // content-end
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-end", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));

        // message-end with usage
        let evs = reader.read_response_events("", &serde_json::json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE", "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}}}), &mut state);
        assert_eq!(evs.len(), 2);
        if let crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(ref s),
            ref usage,
            ..
        } = &evs[0]
        {
            assert_eq!(s, "end_turn");
            assert_eq!(usage.input_tokens, 10);
        }
        assert!(matches!(evs[1], crate::ir::IrStreamEvent::MessageStop));
    }

    #[test]
    fn test_cross_protocol_system_prompt_preserved_to_cohere() {
        // An Anthropic request carries its system prompt in the top-level `system` field, which
        // the reader canonicalizes into IrRequest.system. Cohere's writer must re-emit it as a
        // leading system-role message — otherwise the system prompt is silently dropped when
        // translating Anthropic → Cohere.
        let anthropic_body = serde_json::json!({
            "model": "x",
            "system": "You are terse.",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 10
        });
        let ir = AnthropicReader
            .read_request(&anthropic_body)
            .expect("anthropic read_request");
        assert!(
            !ir.system.is_empty(),
            "anthropic system must land in IrRequest.system"
        );
        let writer = CohereWriter;
        let cohere = writer.write_request(&ir);
        let msgs = cohere.get("messages").unwrap().as_array().unwrap();
        assert_eq!(
            msgs[0].get("role").and_then(|r| r.as_str()),
            Some("system"),
            "Cohere must emit the system prompt as a leading system message"
        );
        assert_eq!(
            msgs[0].get("content").and_then(|c| c.as_str()),
            Some("You are terse.")
        );
        assert_eq!(msgs[1].get("role").and_then(|r| r.as_str()), Some("user"));
    }

    #[test]
    fn test_write_response_event() {
        let writer = CohereWriter;

        // BlockDelta TextDelta("hi") → content-delta frame
        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, data) = result.unwrap();
        assert_eq!(
            data.get("type").and_then(|t| t.as_str()),
            Some("content-delta")
        );
        // content-delta carries the text at delta.message.content.text (an object), matching the
        // native Cohere v2 stream and the content-start shape.
        assert_eq!(
            data.get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str()),
            Some("hi")
        );
        assert_eq!(
            data.get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.get("type"))
                .and_then(|t| t.as_str()),
            Some("text")
        );
    }

    /// Regression: a response carrying several parallel `ToolUse` blocks must surface ALL of them
    /// in `tool_calls`. The previous per-iteration `out.insert(...)` overwrote the key and silently
    /// dropped every call but the last.
    #[test]
    fn test_write_response_preserves_parallel_tool_calls() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                    cache_control: None,
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t2".to_string(),
                    name: "get_time".to_string(),
                    input: serde_json::json!({"tz": "PST"}),
                    cache_control: None,
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t3".to_string(),
                    name: "get_news".to_string(),
                    input: serde_json::json!({}),
                    cache_control: None,
                },
            ],
            stop_reason: Some("tool_use".to_string()),
            usage: crate::ir::IrUsage {
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

        let writer = CohereWriter;
        let json = writer.write_response(&resp);
        // tool_calls are nested under the `message` object (native Cohere v2 shape).
        let tool_calls = json
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|v| v.as_array())
            .expect("tool_calls array must be present under message");
        assert_eq!(tool_calls.len(), 3, "all parallel tool calls must survive");
        let ids: Vec<&str> = tool_calls
            .iter()
            .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, ["t1", "t2", "t3"]);
    }

    /// Regression: an assistant message whose only block is a `ToolUse` (surfaced via `tool_calls`)
    /// must NOT emit `content: []`. The `content` key should be omitted entirely.
    #[test]
    fn test_write_request_sole_tooluse_omits_empty_content() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "f".to_string(),
                    input: serde_json::json!({"x": 1}),
                    cache_control: None,
                }],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let json = writer.write_request(&ir);
        let msgs = json.get("messages").unwrap().as_array().unwrap();
        let assistant = &msgs[0];
        assert!(
            assistant.get("content").is_none(),
            "sole-ToolUse message must omit content rather than emit []"
        );
        assert!(
            assistant.get("tool_calls").is_some(),
            "the tool call must still be present"
        );
    }

    /// Multiple text blocks in one message must serialize as a text-part array (not be collapsed),
    /// while a single text block stays a bare string.
    #[test]
    fn test_write_request_text_block_shapes() {
        let single = crate::ir::IrRequest {
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
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = CohereWriter;
        let j = writer.write_request(&single);
        assert_eq!(
            j.get("messages").unwrap().as_array().unwrap()[0].get("content"),
            Some(&serde_json::json!("hi"))
        );

        let multi = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "a".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Text {
                        text: "b".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                ],
            }],
            ..single
        };
        let j = writer.write_request(&multi);
        let content = j.get("messages").unwrap().as_array().unwrap()[0]
            .get("content")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("a"));
        assert_eq!(content[1].get("text").and_then(|t| t.as_str()), Some("b"));
    }

    /// `read_request` must not allocate a temporary empty Vec when `tools` is absent, and must
    /// produce no tools either way.
    #[test]
    fn test_read_request_missing_tools() {
        let json = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = CohereReader
            .read_request(&json)
            .expect("read_request should succeed");
        assert!(ir.tools.is_empty());
    }

    /// The NATIVE Cohere v2 error envelope is a bare `{"message": <detail>}` — NOT the generic
    /// `{"error":{"message","type"}}`, and NOT carrying a synthesized `id`. The generic `kind` must
    /// NOT leak into the body (a native SDK never reads a typed error category from a Cohere body;
    /// it reads `message`), and no `id` field must be emitted (real Cohere error bodies carry none,
    /// and this reader's `extract_error` never reads `id`).
    #[test]
    fn test_write_error_native_cohere_envelope() {
        let writer = CohereWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");

        // Serializes (no panic) and re-parses as valid JSON.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

        assert_eq!(
            reparsed.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found"),
            "native Cohere error carries the detail under top-level `message`"
        );
        assert!(
            reparsed.get("error").is_none(),
            "must NOT use the generic `error` wrapper"
        );
        assert!(
            reparsed.get("type").is_none() && reparsed.get("code").is_none(),
            "Cohere conveys the error category via HTTP status, not a typed body field"
        );
        assert!(
            reparsed.get("id").is_none(),
            "real Cohere error bodies carry no synthesized id"
        );
        // The body must be exactly the single `message` key.
        assert_eq!(
            reparsed.as_object().map(|o| o.len()),
            Some(1),
            "native Cohere error body is a bare {{\"message\": ...}}"
        );
    }

    /// Same-protocol (Cohere → Cohere) passthrough must preserve the upstream response `id` exactly
    /// — capturing it on read and re-emitting the identical value on write.
    #[test]
    fn test_same_protocol_roundtrip_preserves_id() {
        let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
        let json = serde_json::json!({
            "id": upstream_id,
            "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": {"tokens": {"input_tokens": 3, "output_tokens": 1}}
        });

        let resp = CohereReader
            .read_response(&json)
            .expect("read_response should succeed");
        assert_eq!(
            resp.id.as_deref(),
            Some(upstream_id),
            "upstream id captured verbatim into the IR"
        );

        let writer = CohereWriter;
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("id").and_then(|i| i.as_str()),
            Some(upstream_id),
            "the same id must be re-emitted on write (same-protocol fidelity)"
        );
    }

    /// Same-protocol stream passthrough preserves the message-start `id`.
    #[test]
    fn test_same_protocol_stream_roundtrip_preserves_id() {
        let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events(
            "",
            &serde_json::json!({
                "id": upstream_id,
                "type": "message-start",
                "delta": {"message": {"role": "assistant"}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        let captured = match &evs[0] {
            crate::ir::IrStreamEvent::MessageStart { id, .. } => id.clone(),
            other => panic!("expected MessageStart, got {other:?}"),
        };
        assert_eq!(captured.as_deref(), Some(upstream_id));

        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&evs[0])
            .expect("message-start must serialize");
        assert_eq!(
            frame.get("id").and_then(|i| i.as_str()),
            Some(upstream_id),
            "stream message-start id must round-trip verbatim"
        );
    }

    /// Cross-protocol write (the backend supplied NO id — `IrResponse.id == None`) must SYNTHESIZE a
    /// valid, non-empty Cohere id without panicking, so a native Cohere SDK still reads a string.
    #[test]
    fn test_cross_protocol_write_synthesizes_valid_id() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hello".to_string(),
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
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let writer = CohereWriter;
        let out = writer.write_response(&resp);
        let id = out
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id must be present as a string");
        assert!(!id.is_empty(), "synthesized id must be non-empty");
        assert!(
            is_uuid_shaped(id),
            "synthesized id must be a bare UUID (no `cohere-` prefix), got {id}"
        );
    }

    /// Test helper: validate the 8-4-4-4-12 lowercase-hex UUID layout that native Cohere ids use.
    fn is_uuid_shaped(s: &str) -> bool {
        let groups: Vec<&str> = s.split('-').collect();
        let expected_lens = [8usize, 4, 4, 4, 12];
        groups.len() == 5
            && groups.iter().zip(expected_lens.iter()).all(|(g, &len)| {
                g.len() == len
                    && g.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
    }

    /// Test helper: validate that a UUID string is a proper RFC-4122 UUIDv4 — version nibble `4`
    /// (first char of the 3rd group) and variant nibble in `{8,9,a,b}` (`10xx`, first char of the
    /// 4th group). Real Cohere ids are v4, so a synthesized id must satisfy this.
    fn is_uuid_v4(s: &str) -> bool {
        if !is_uuid_shaped(s) {
            return false;
        }
        let groups: Vec<&str> = s.split('-').collect();
        let version_ok = groups[2].starts_with('4');
        let variant_ok = matches!(
            groups[3].bytes().next(),
            Some(b'8') | Some(b'9') | Some(b'a') | Some(b'b')
        );
        version_ok && variant_ok
    }

    /// Regression (MEDIUM/conformance): the synthesized id must be a bare UUID (8-4-4-4-12 hex),
    /// indistinguishable from a native Cohere id — NOT a `cohere-<secs>-<counter>` token, which a
    /// client comparing against the documented UUID shape could use as a proxy tell.
    #[test]
    fn test_synthesized_id_is_uuid_shaped() {
        let id = synthesize_cohere_id();
        assert!(
            is_uuid_shaped(&id),
            "synthesized id must match the UUID layout, got {id}"
        );
        assert!(
            !id.starts_with("cohere-"),
            "synthesized id must NOT carry a literal prefix, got {id}"
        );
    }

    /// Regression (HIGH/conformance): the synthesized id must be a PROPER RFC-4122 UUIDv4 — version
    /// nibble `4` and variant bits `10xx` — because real Cohere ids are v4. The previous
    /// `secs << 32 ^ counter` layout almost never landed `4` in the version position and left the
    /// variant unconstrained, so a client validating the id as a UUIDv4 saw an invalid value (a
    /// deterministic proxy tell). Sample many ids: the stamping is deterministic, so EVERY one must
    /// pass regardless of the random/counter bits underneath.
    #[test]
    fn test_synthesized_id_is_valid_uuid_v4() {
        for _ in 0..1000 {
            let id = synthesize_cohere_id();
            assert!(
                is_uuid_v4(&id),
                "synthesized id must be a valid RFC-4122 UUIDv4 (version nibble 4, variant 10xx), \
                 got {id}"
            );
        }
    }

    /// Regression (HIGH/security): the synthesized id must NOT embed the server clock. The previous
    /// layout placed `secs << 32` in the high 32 bits, so the first UUID group leaked the unix
    /// second. Mint two ids and assert their first groups differ from a unix-second-derived value —
    /// more robustly, assert the first group is not equal to the current/last-second seconds in hex
    /// (the old code produced exactly that). With CSPRNG seeding the first group is random.
    #[test]
    fn test_synthesized_id_does_not_leak_timestamp() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The old leaky layout put `(secs as u32)` straight into the first 8 hex chars.
        let leaked_prefix = format!("{:08x}", secs as u32);
        // Sample several: a single random collision is astronomically unlikely, but sampling makes
        // the intent (no deterministic clock prefix) unambiguous.
        let mut matched = 0u32;
        for _ in 0..256 {
            let id = synthesize_cohere_id();
            let first_group = id.split('-').next().unwrap_or("");
            if first_group == leaked_prefix {
                matched += 1;
            }
        }
        assert_eq!(
            matched, 0,
            "first UUID group must not deterministically equal the unix-second hex {leaked_prefix} \
             (server-clock leak)"
        );
    }

    /// Synthesized ids are unique across a burst by virtue of CSPRNG entropy alone — `synthesize_
    /// cohere_id` is a PURE RFC-4122 UUIDv4 (122 random bits, ~5.3e36 values) with NO monotonic
    /// counter overlay (a counter folded into any fixed region would be a low-entropy structural
    /// tell a native random v4 never carries — see the fn doc-comment). This test therefore asserts
    /// what the code actually guarantees: a burst of ids are all distinct AND every one is a
    /// well-formed UUIDv4. It does NOT assert a counter backstop, because none exists by design.
    #[test]
    fn test_synthesized_ids_are_unique() {
        const N: usize = 4096;
        let mut seen = std::collections::HashSet::with_capacity(N);
        for _ in 0..N {
            let id = synthesize_cohere_id();
            assert!(
                is_uuid_v4(&id),
                "each synthesized id must be a well-formed UUIDv4, got {id}"
            );
            assert!(
                seen.insert(id.clone()),
                "CSPRNG-seeded synthesized ids must be unique across a burst; collision on {id}"
            );
        }
    }

    /// A well-formed credential produces a single `Authorization: Bearer <key>` header.
    #[test]
    fn test_auth_headers_valid_key_emits_bearer() {
        let writer = CohereWriter;
        let headers = writer.auth_headers("valid-key-123");
        assert_eq!(headers.len(), 1, "exactly one auth header");
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(
            headers[0].1.to_str().expect("valid header bytes"),
            "Bearer valid-key-123"
        );
    }

    /// Regression (MEDIUM/security): a credential carrying bytes `HeaderValue::from_str` rejects
    /// (e.g. a newline injected by a config system) must OMIT the header entirely — NOT emit an
    /// empty `Authorization: ` value. The empty-Bearer form silently 401s the lane with no operator
    /// signal and is a backend-detectable tell. Mirrors
    /// `gemini.rs::test_auth_headers_invalid_key_omits_header_no_empty_value`.
    #[test]
    fn test_auth_headers_invalid_key_omits_header_no_empty_value() {
        let writer = CohereWriter;
        let headers = writer.auth_headers("bad\nkey");
        assert!(
            headers.is_empty(),
            "an invalid credential must omit the auth header entirely, got {headers:?}"
        );
    }

    /// A NUL control byte in the credential is also rejected and the header omitted (not emitted as
    /// an empty value).
    #[test]
    fn test_auth_headers_control_byte_key_omits_header() {
        let writer = CohereWriter;
        let headers = writer.auth_headers("key\u{0000}bad");
        assert!(
            headers.is_empty(),
            "a control-byte credential must omit the auth header entirely, got {headers:?}"
        );
    }

    /// Regression (MEDIUM/conformance): a Cohere->Cohere passthrough where the upstream returned
    /// `ERROR_TOXIC` (content-moderation stop) must NOT be downgraded to `ERROR` (infrastructure
    /// failure). The reader normalises `ERROR_TOXIC` to IR `safety`; the writer must map `safety`
    /// back to `ERROR_TOXIC` so the moderation signal round-trips. Covers both the non-streaming
    /// `write_response` and the streaming `message-end` paths.
    #[test]
    fn test_safety_finish_reason_writes_error_toxic_non_stream() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "moderated".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("safety".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("r1".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = CohereWriter;
        let body = writer.write_response(&resp);
        assert_eq!(
            body.get("finish_reason").and_then(|v| v.as_str()),
            Some("ERROR_TOXIC"),
            "IR safety must write back as the native content-moderation stop ERROR_TOXIC"
        );

        // Round-trips: ERROR_TOXIC reads back to IR safety (the reader normalises only ERROR_TOXIC
        // to safety; the generic ERROR is NOT a moderation signal — see the ERROR round-trip test).
        let back = CohereReader
            .read_response(&body)
            .expect("read self-written body");
        assert_eq!(back.stop_reason.as_deref(), Some("safety"));
    }

    #[test]
    fn test_safety_finish_reason_writes_error_toxic_stream() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("safety".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("message-end must serialize");
        assert_eq!(
            frame
                .get("delta")
                .and_then(|d| d.get("finish_reason"))
                .and_then(|v| v.as_str()),
            Some("ERROR_TOXIC"),
            "streamed safety stop must emit ERROR_TOXIC, not ERROR"
        );
    }

    /// Regression (MED #8): the readers must NOT fold the generic `ERROR` finish_reason into the
    /// content-moderation `safety` bucket. Only `ERROR_TOXIC` is the moderation signal; a generic
    /// `ERROR` (infrastructure failure) must fall through to the lowercase passthrough (-> IR
    /// `error`), and round-trip back to the native `ERROR` via the writer's `to_uppercase` arm.
    /// Before the fix BOTH `ERROR` and `ERROR_TOXIC` mapped to `safety`, so a Cohere->Cohere
    /// passthrough silently rewrote a server error as a fabricated content-moderation stop. Covers
    /// both readers (streaming `message-end` and non-streaming `read_response`) and both write-back
    /// paths.
    #[test]
    fn test_generic_error_does_not_fold_into_safety_and_round_trips() {
        let reader = CohereReader;

        // --- Non-streaming reader (read_response) ---
        // ERROR must read back as IR `error`, NOT `safety`.
        let err_body = serde_json::json!({
            "finish_reason": "ERROR",
            "message": { "content": [] },
            "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
        });
        let err_ir = reader.read_response(&err_body).expect("read ERROR body");
        assert_eq!(
            err_ir.stop_reason.as_deref(),
            Some("error"),
            "generic ERROR must read back as IR `error`, not `safety`"
        );
        // ERROR_TOXIC still reads back as `safety`.
        let toxic_body = serde_json::json!({
            "finish_reason": "ERROR_TOXIC",
            "message": { "content": [] },
            "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
        });
        let toxic_ir = reader
            .read_response(&toxic_body)
            .expect("read ERROR_TOXIC body");
        assert_eq!(
            toxic_ir.stop_reason.as_deref(),
            Some("safety"),
            "ERROR_TOXIC must still read back as IR `safety`"
        );

        // Write-back round-trips: IR `error` -> native `ERROR`; IR `safety` -> native `ERROR_TOXIC`.
        let writer = CohereWriter;
        let err_resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: Vec::new(),
            stop_reason: Some("error".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("e1".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let err_out = writer.write_response(&err_resp);
        assert_eq!(
            err_out.get("finish_reason").and_then(|v| v.as_str()),
            Some("ERROR"),
            "IR `error` must write back as the native generic `ERROR`, not `ERROR_TOXIC`"
        );

        // --- Streaming reader (message-end) ---
        let mut state = crate::ir::StreamDecodeState::default();
        let err_frame = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "ERROR", "usage": { "tokens": {} } }
        });
        let evs = reader.read_response_events("", &err_frame, &mut state);
        assert!(
            evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::MessageDelta { stop_reason, .. }
                    if stop_reason.as_deref() == Some("error")
            )),
            "streamed generic ERROR must decode to IR `error`, not `safety`, got {evs:?}"
        );
        let mut state2 = crate::ir::StreamDecodeState::default();
        let toxic_frame = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "ERROR_TOXIC", "usage": { "tokens": {} } }
        });
        let toxic_evs = reader.read_response_events("", &toxic_frame, &mut state2);
        assert!(
            toxic_evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::MessageDelta { stop_reason, .. }
                    if stop_reason.as_deref() == Some("safety")
            )),
            "streamed ERROR_TOXIC must still decode to IR `safety`, got {toxic_evs:?}"
        );
    }

    /// Regression (MED #9): an upstream-controlled stream tool-call frame `index` of `usize::MAX`
    /// (or any huge value) must NOT collide with `TEXT_BLOCK_SEEN_SENTINEL` (== `usize::MAX`) and
    /// corrupt tool tracking. Every read site clamps the wire index to `MAX_TOOL_FRAME_INDEX`, well
    /// below the sentinel, so a tool block still opens at a real IR index and the sentinel's
    /// text-high-water meaning is preserved. Before the fix, a `usize::MAX` frame_idx was inserted
    /// into `open_tools`, became indistinguishable from the sentinel, and broke `cohere_tool_ir_index`.
    #[test]
    fn test_huge_tool_frame_index_clamped_below_sentinel() {
        let reader = CohereReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // A tool-call-start whose wire index is usize::MAX (the sentinel value).
        let huge = u64::MAX;
        let start = serde_json::json!({
            "type": "tool-call-start",
            "index": huge,
            "delta": { "message": { "tool_calls": {
                "id": "call_huge",
                "type": "function",
                "function": { "name": "f", "arguments": "{}" }
            }}}
        });
        let evs = reader.read_response_events("", &start, &mut state);

        // The clamp must keep the recorded frame index strictly below the sentinel so it is never
        // confused with the text-high-water marker.
        assert!(
            !state.open_tools.contains(&TEXT_BLOCK_SEEN_SENTINEL),
            "a huge wire index must never be recorded as the sentinel value"
        );
        assert!(
            state
                .open_tools
                .iter()
                .filter(|&&e| e != TEXT_BLOCK_SEEN_SENTINEL)
                .all(|&e| tool_entry_frame(e) <= MAX_TOOL_FRAME_INDEX as usize),
            "every recorded tool frame index must be clamped to MAX_TOOL_FRAME_INDEX, got {:?}",
            state.open_tools
        );

        // The clamped frame still opens exactly one tool BlockStart (no corruption / no drop).
        let starts = evs
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        assert_eq!(
            starts, 1,
            "a clamped huge-index tool-call-start must open exactly one block, got {evs:?}"
        );

        // The whole tool lifecycle (delta + end at the same huge index) resolves to the SAME IR
        // index and closes cleanly — proving the clamp is applied consistently at all three sites.
        let delta = serde_json::json!({
            "type": "tool-call-delta",
            "index": huge,
            "delta": { "message": { "tool_calls": {
                "function": { "arguments": "more" }
            }}}
        });
        let delta_evs = reader.read_response_events("", &delta, &mut state);
        assert_eq!(
            delta_evs
                .iter()
                .filter(|e| matches!(e, IrStreamEvent::BlockDelta { .. }))
                .count(),
            1,
            "a clamped tool-call-delta must forward to the open block, got {delta_evs:?}"
        );
        let end = serde_json::json!({ "type": "tool-call-end", "index": huge });
        let end_evs = reader.read_response_events("", &end, &mut state);
        assert_eq!(
            end_evs
                .iter()
                .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
                .count(),
            1,
            "a clamped tool-call-end must close the open block, got {end_evs:?}"
        );
    }

    /// Regression (MEDIUM/correctness): a mid-stream `IrStreamEvent::Error` on a Cohere-ingress
    /// stream must terminate with the NATIVE Cohere v2 error shape — a `message-end` frame whose
    /// `finish_reason` is `ERROR` — NOT a non-native `type: "error"` out-of-band frame (which a
    /// strict Cohere SDK ignores or rejects, silently dropping the error, and which is a
    /// protocol-indistinguishability tell). A content-moderation signal maps to `ERROR_TOXIC`; any
    /// other signal maps to the generic `ERROR`. The emitted frame must round-trip through this
    /// protocol's OWN reader back to the IR `safety` stop reason.
    #[test]
    fn test_stream_error_emits_native_message_end_not_error_event() {
        let writer = CohereWriter;

        // Generic infrastructure error -> ERROR.
        let infra = IrStreamEvent::Error(crate::proto::IrError {
            class: crate::breaker::StatusClass::ServerError,
            provider_signal: Some("internal_server_error".to_string()),
            retry_after: None,
        });
        let (event_type, frame) = writer
            .write_response_event(&infra)
            .expect("Error must serialize to a native frame");
        // The SSE `event:` field is empty for Cohere v2 (the type lives in the JSON `type` key).
        assert_eq!(event_type, "");
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("message-end"),
            "Cohere v2 has no `type: error` event; a mid-stream error terminates with message-end"
        );
        assert_ne!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "the non-native `type: error` frame must not be emitted"
        );
        // The native message-end frame carries ONLY `type` + `delta`; a top-level `message` field
        // is a proxy fingerprint a genuine Cohere v2 stream never emits (the MEDIUM/conformance
        // finding). Assert its absence explicitly.
        assert!(
            frame.get("message").is_none(),
            "error message-end must not carry a top-level `message` field (proxy fingerprint), \
             got {frame:?}"
        );
        assert_eq!(
            frame.get("delta").and_then(|d| d.as_object()).map(|d| {
                let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
                keys.sort_unstable();
                keys
            }),
            Some(vec!["finish_reason", "usage"]),
            "error message-end `delta` must carry exactly `finish_reason` and `usage`, \
             mirroring the native MessageDelta shape"
        );
        // Native message-end always includes delta.usage.tokens.{input_tokens,output_tokens}; the
        // error frame must too (an absent usage is itself a fingerprint).
        let err_tokens = frame
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
            .expect("error message-end must carry delta.usage.tokens");
        assert_eq!(
            err_tokens.get("input_tokens").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            err_tokens.get("output_tokens").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            frame
                .get("delta")
                .and_then(|d| d.get("finish_reason"))
                .and_then(|v| v.as_str()),
            Some("ERROR"),
            "an infrastructure error maps to the native ERROR finish_reason"
        );
        // Round-trips through the reader back to IR `error` (the generic infra-failure passthrough).
        // The reader maps ONLY `ERROR_TOXIC` to `safety`; a generic `ERROR` must NOT be folded into
        // the moderation bucket (MED #8) — it falls through to the lowercase passthrough -> `error`.
        let mut state = crate::ir::StreamDecodeState::default();
        let decoded = CohereReader.read_response_events("", &frame, &mut state);
        assert!(
            decoded.iter().any(|e| matches!(
                e,
                IrStreamEvent::MessageDelta { stop_reason, .. }
                    if stop_reason.as_deref() == Some("error")
            )),
            "emitted message-end must decode back to a generic `error` stop, got {decoded:?}"
        );

        // Content-moderation signal -> ERROR_TOXIC.
        let toxic = IrStreamEvent::Error(crate::proto::IrError {
            class: crate::breaker::StatusClass::ClientError,
            provider_signal: Some("content_filter_safety".to_string()),
            retry_after: None,
        });
        let (_, toxic_frame) = writer
            .write_response_event(&toxic)
            .expect("Error must serialize");
        assert_eq!(
            toxic_frame
                .get("delta")
                .and_then(|d| d.get("finish_reason"))
                .and_then(|v| v.as_str()),
            Some("ERROR_TOXIC"),
            "a content-moderation signal maps to the native ERROR_TOXIC finish_reason"
        );
        assert!(
            toxic_frame.get("message").is_none(),
            "toxic error message-end must not carry a top-level `message` field"
        );

        // An absent provider_signal still produces a native ERROR termination (never `type: error`).
        let bare = IrStreamEvent::Error(crate::proto::IrError {
            class: crate::breaker::StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        });
        let (_, bare_frame) = writer
            .write_response_event(&bare)
            .expect("Error must serialize");
        assert_eq!(
            bare_frame.get("type").and_then(|v| v.as_str()),
            Some("message-end")
        );
        assert_eq!(
            bare_frame
                .get("delta")
                .and_then(|d| d.get("finish_reason"))
                .and_then(|v| v.as_str()),
            Some("ERROR")
        );
        assert!(
            bare_frame.get("message").is_none(),
            "bare error message-end must not carry a top-level `message` field"
        );
    }

    /// Regression (MEDIUM/correctness): `read_response` must tolerate a missing `usage` object,
    /// falling back to zero counts rather than hard-erroring with a `ClientError`. A
    /// Cohere-compatible backend (mock/staging/proxy) that omits `usage` is an upstream
    /// response-format quirk, not a caller mistake; Bedrock and Gemini both handle this leniently.
    #[test]
    fn test_read_response_missing_usage_defaults_to_zero() {
        let json = serde_json::json!({
            "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
            "finish_reason": "COMPLETE",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}]
            }
            // NOTE: no `usage` key at all.
        });
        let resp = CohereReader
            .read_response(&json)
            .expect("missing usage must not hard-error (zero-usage fallback)");
        assert_eq!(resp.usage.input_tokens, 0);
        assert_eq!(resp.usage.output_tokens, 0);
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));

        // A present-but-empty usage object (no `tokens`) is also tolerated.
        let json_empty_usage = serde_json::json!({
            "finish_reason": "COMPLETE",
            "message": { "role": "assistant", "content": [{"type": "text", "text": "hi"}] },
            "usage": {}
        });
        let resp2 = CohereReader
            .read_response(&json_empty_usage)
            .expect("empty usage object must not hard-error");
        assert_eq!(resp2.usage.input_tokens, 0);
        assert_eq!(resp2.usage.output_tokens, 0);
    }

    /// Regression (HIGH/conformance): `write_response` must nest `tool_calls` INSIDE the `message`
    /// object (native Cohere v2 shape, `response.message.tool_calls`) — not at the top level. The
    /// emitted body must round-trip through this protocol's OWN `read_response`, which reads tool
    /// calls from `message.tool_calls`, so a Cohere -> Cohere passthrough keeps every parallel call.
    #[test]
    fn test_write_response_tool_calls_nested_and_roundtrip() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "calling tools".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                    cache_control: None,
                },
                crate::ir::IrBlock::ToolUse {
                    id: "t2".to_string(),
                    name: "get_time".to_string(),
                    input: serde_json::json!({"tz": "PST"}),
                    cache_control: None,
                },
            ],
            stop_reason: Some("tool_use".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 4,
                output_tokens: 6,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("resp-1".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };

        let writer = CohereWriter;
        let body = writer.write_response(&resp);

        // tool_calls live under message, NOT at the top level.
        assert!(
            body.get("tool_calls").is_none(),
            "tool_calls must NOT be at the top level"
        );
        let nested = body
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
            .expect("tool_calls must be nested under message");
        assert_eq!(nested.len(), 2, "both parallel tool calls survive");

        // Round-trips through this protocol's own reader: every tool call comes back.
        let back = CohereReader
            .read_response(&body)
            .expect("read_response of self-written body");
        let tool_uses: Vec<(&str, &str)> = back
            .content
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::ToolUse { id, name, .. } = b {
                    Some((id.as_str(), name.as_str()))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            tool_uses,
            [("t1", "get_weather"), ("t2", "get_time")],
            "Cohere -> Cohere tool-call passthrough must preserve every call"
        );
        assert_eq!(back.stop_reason.as_deref(), Some("tool_use"));
    }

    /// Regression (MEDIUM/conformance): the streaming `content-delta` frame must carry text at
    /// `delta.message.content.text` (an object), matching `content-start` and the native Cohere v2
    /// stream — not a bare string. A native SDK reads `content.text`.
    #[test]
    fn test_write_response_event_content_delta_is_object() {
        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("chunk".to_string()),
        };
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("content-delta must serialize");
        let content = frame
            .get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("content"))
            .expect("content present");
        assert!(
            content.is_object(),
            "content-delta content must be an object, got {content}"
        );
        assert_eq!(content.get("type").and_then(|t| t.as_str()), Some("text"));
        assert_eq!(content.get("text").and_then(|t| t.as_str()), Some("chunk"));
    }

    /// Regression (HIGH/correctness): the content-delta WRITER emits `delta.message.content` as a
    /// `{type:text, text:…}` object (the native Cohere v2 shape), so the READER must decode that
    /// exact object back to a TextDelta. Before the object branch was added, the reader handled only
    /// the bare-string and array forms, so the writer's own frame round-tripped to ZERO events —
    /// streamed assistant text was silently dropped on the Cohere read/proxy path. Lock the
    /// writer→reader symmetry.
    #[test]
    fn test_content_delta_writer_reader_roundtrip_object_shape() {
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            })
            .expect("content-delta must serialize");
        // Sanity: the writer really emitted the object shape this test guards.
        assert!(
            frame
                .pointer("/delta/message/content")
                .is_some_and(|c| c.is_object()),
            "writer must emit object-shaped content: {frame}"
        );
        // Feed the writer's own frame back through the reader.
        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events("", &frame, &mut state);
        let decoded_text: Option<String> = evs.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::TextDelta(t),
                ..
            } => Some(t.clone()),
            _ => None,
        });
        assert_eq!(
            decoded_text.as_deref(),
            Some("hi"),
            "object-shaped content-delta must round-trip to the original text, got events: {evs:?}"
        );
    }

    /// Regression (LOW/correctness): a streaming tool call (tool-call-start / tool-call-delta /
    /// tool-call-end) must NOT be swallowed by a catch-all — it maps onto the IR block lifecycle.
    #[test]
    fn test_stream_tool_call_events_mapped() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // start
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "tool-call-start must emit a BlockStart");
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, name },
            } => {
                assert_eq!(*index, 0);
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        }

        // delta (streamed arguments)
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 0,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"city\":"}}}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(args),
            } => assert_eq!(args, "{\"city\":"),
            other => panic!("expected InputJsonDelta, got {other:?}"),
        }

        // end
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));
        // tool-call-end emits the BlockStop but intentionally does NOT remove the frame's entry
        // from `open_tools`: the recorded packed entry is what keeps each tool's ASSIGNED IR index
        // stable for its lifetime (and the insertion slot of any LATER tool stable), so the set
        // grows monotonically across the stream.
        assert_eq!(
            cohere_lookup_tool_ir_index(&state, 0),
            Some(0),
            "the closed tool's assigned IR index is retained to keep later tool indices stable"
        );
    }

    /// Regression (LOW #12 + #13): a `tool-call-start` that arrives BEFORE any text content frame
    /// must NOT collide with the text block on IR index 0. Before the fix the text block was
    /// hardcoded to IR index 0, so a tool that opened first (and legitimately claimed 0 via
    /// `cohere_assign_tool_ir_index` when no text had been seen) and the later text block BOTH
    /// emitted a `BlockStart` at index 0 — two open frames at the same index, which a downstream
    /// ingress writer mis-correlates. The text block now claims a DYNAMIC index by order of first
    /// appearance (`state.text_index`, mirroring the Gemini reader): the tool keeps index 0 and the
    /// text block takes index 1. Asserts the tool gets 0, text gets 1, the indices never overlap, and
    /// the text block closes at the index it actually opened (1, not a hardcoded 0).
    #[test]
    fn test_stream_tool_before_text_no_index_collision() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // Tool opens FIRST — claims IR index 0 (no text seen yet).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "tool-call-start emits one BlockStart");
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, name },
            } => {
                assert_eq!(*index, 0, "the first-arriving tool claims IR index 0");
                assert_eq!(id, "call_1");
                assert_eq!(name, "lookup");
            }
            other => panic!("expected tool BlockStart, got {other:?}"),
        }

        // Text content opens AFTER the tool — must take the NEXT free index (1), not collide on 0.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-start", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "content-start emits one text BlockStart");
        let text_idx = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::Text,
            } => *index,
            other => panic!("expected text BlockStart, got {other:?}"),
        };
        assert_eq!(
            text_idx, 1,
            "the text block must claim index 1 (off the tool-claimed 0), not collide on 0"
        );
        assert_ne!(
            text_idx, 0,
            "text must never reuse the tool-claimed IR index 0"
        );

        // A text delta rides the SAME dynamic index, not a hardcoded 0.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "content-delta",
                "index": 0,
                "delta": {"message": {"content": {"type": "text", "text": "hi"}}}
            }),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "content-delta emits one text delta");
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::TextDelta(t),
            } => {
                assert_eq!(*index, 1, "the text delta rides the assigned index 1");
                assert_eq!(t, "hi");
            }
            other => panic!("expected text BlockDelta, got {other:?}"),
        }

        // content-end closes the text block at the index it actually opened (1), not 0.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-end", "index": 0}),
            &mut state,
        );
        assert_eq!(evs.len(), 1, "content-end emits one BlockStop");
        assert!(
            matches!(evs[0], crate::ir::IrStreamEvent::BlockStop { index: 1 }),
            "the text block closes at its assigned index 1, not a hardcoded 0; got {:?}",
            evs[0]
        );

        // The tool's index 0 is still independently resolvable — no overlap occurred.
        assert_eq!(
            cohere_lookup_tool_ir_index(&state, 0),
            Some(0),
            "the tool retains its distinct IR index 0"
        );

        // And the canonical text-before-tool ordering still keeps text at 0 / tool at 1 on a fresh
        // stream (the fix must not regress the common case).
        let mut state2 = crate::ir::StreamDecodeState::default();
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-start", "index": 0}),
            &mut state2,
        );
        assert!(matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ));
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "c2", "type": "function",
                    "function": {"name": "f", "arguments": ""}
                }}}
            }),
            &mut state2,
        );
        match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => assert_eq!(
                *index, 1,
                "text-before-tool: text keeps 0, tool takes 1 (no regression)"
            ),
            other => panic!("expected tool BlockStart, got {other:?}"),
        }
    }

    /// An unknown Cohere stream event type is a documented no-op (no events, no panic) — the named
    /// fallthrough arm must not break the stream.
    #[test]
    fn test_stream_unknown_event_is_noop() {
        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events(
            "",
            &serde_json::json!({"type": "citation-start", "index": 0}),
            &mut state,
        );
        assert!(evs.is_empty(), "unknown event types produce no IR events");
    }

    /// Regression (MEDIUM/performance): `extract_error` derives both fields from a SINGLE parse.
    /// Behavioral check that both fields are still populated from one body.
    #[test]
    fn test_extract_error_single_parse_both_fields() {
        let body = br#"{"message": "boom", "error_type": "invalid_request"}"#;
        let err = CohereReader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(err.provider_code.as_deref(), Some("boom"));
        assert_eq!(err.structured_type.as_deref(), Some("invalid_request"));
        assert_eq!(err.http_status, 400);
    }

    /// Regression (PLUS #17, med-completeness): production `extract_error` must synthesize the
    /// canonical `context_length_exceeded` provider code for an oversized-request error so the
    /// breaker (`normalize_raw_error`) classifies it as `StatusClass::ContextLength` and fails over
    /// without penalty. Before the fix `extract_error` carried the raw `message` string as the
    /// provider code (the breaker could not recognize it → plain 400 ClientError, no failover); only
    /// the `#[cfg(test)] classify()` helper — which does not run in production — recognized the
    /// signal. This test feeds real Cohere v2 oversized-context error bodies and asserts the
    /// production path yields `context_length_exceeded`, AND that the breaker then routes it to
    /// ContextLength.
    #[test]
    fn test_extract_error_synthesizes_context_length_in_production() {
        let reader = CohereReader;

        // Several real-shaped Cohere v2 oversized-request error bodies (free-text `message`, generic
        // `error_type`). Each must normalize to the canonical code in PRODUCTION extract_error.
        let bodies: &[&[u8]] = &[
            br#"{"message": "too many tokens: the request exceeds the model's context window", "error_type": "invalid_request_error"}"#,
            br#"{"message": "the input is too long for the requested model; please reduce the prompt"}"#,
            br#"{"message": "requested 200000 tokens but the maximum is 128000 tokens for this model"}"#,
            br#"{"message": "prompt exceeds the maximum context length"}"#,
        ];

        let empty_map = std::collections::HashMap::new();
        for body in bodies {
            let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
            assert_eq!(
                raw.provider_code.as_deref(),
                Some("context_length_exceeded"),
                "production extract_error must synthesize the canonical context-length code for body {}",
                String::from_utf8_lossy(body)
            );

            // The breaker must then route the canonical code to ContextLength (fail over, no penalty)
            // rather than treating the 400 as a plain ClientError.
            let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
            assert_eq!(
                signal.class,
                crate::breaker::StatusClass::ContextLength,
                "breaker must map the synthesized code to ContextLength for body {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// A non-context-length Cohere error body must NOT be misclassified as context-length: the raw
    /// `message` is preserved as the provider code and the breaker does not route it to
    /// ContextLength (guards against the substring scan over-matching).
    #[test]
    fn test_extract_error_non_context_length_message_preserved() {
        let reader = CohereReader;
        let body = br#"{"message": "invalid api key", "error_type": "invalid_request_error"}"#;
        let raw = reader.extract_error(StatusCode::UNAUTHORIZED, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("invalid api key"),
            "a non-context-length message must be carried verbatim"
        );
        let signal = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
        assert_ne!(
            signal.class,
            crate::breaker::StatusClass::ContextLength,
            "a non-context-length error must not be classified as ContextLength"
        );
    }

    /// Regression (MED #8): the `too long` arm of `body_signals_context_length` must be
    /// co-constrained to a token/context/input qualifier. A bare `contains("too long")` over-matched
    /// ANY message containing "too long" (e.g. "request URL too long", "value too long for column")
    /// and mis-synthesized the canonical `context_length_exceeded` code — triggering a no-penalty
    /// ContextLength failover for an unrelated client error. This asserts the generic "too long"
    /// bodies are NOT classified ContextLength, while genuine oversized-context "too long" bodies
    /// still are.
    #[test]
    fn test_too_long_only_classifies_context_length_when_qualified() {
        let reader = CohereReader;
        let empty = std::collections::HashMap::new();

        // Generic "too long" errors with NO token/context/input qualifier: must NOT be ContextLength.
        let non_context: &[&[u8]] = &[
            br#"{"message": "the requested URL is too long", "error_type": "invalid_request_error"}"#,
            br#"{"message": "value too long for column name", "error_type": "invalid_request_error"}"#,
            br#"{"message": "the password you provided is too long"}"#,
        ];
        for body in non_context {
            let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
            assert_ne!(
                raw.provider_code.as_deref(),
                Some("context_length_exceeded"),
                "a generic 'too long' message must not synthesize the context-length code: {}",
                String::from_utf8_lossy(body)
            );
            let signal = crate::breaker::normalize_raw_error(&raw, &empty);
            assert_ne!(
                signal.class,
                crate::breaker::StatusClass::ContextLength,
                "a generic 'too long' message must not classify as ContextLength: {}",
                String::from_utf8_lossy(body)
            );
        }

        // Genuine oversized-context "too long" errors (qualified by token/context/input): still
        // classified ContextLength so the no-penalty failover still fires.
        let context: &[&[u8]] = &[
            br#"{"message": "the input is too long for the requested model"}"#,
            br#"{"message": "your prompt is too long: it exceeds the model context window"}"#,
            br#"{"message": "message too long, too many tokens"}"#,
        ];
        for body in context {
            let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
            assert_eq!(
                raw.provider_code.as_deref(),
                Some("context_length_exceeded"),
                "a qualified 'too long' (context) message must synthesize the context-length code: {}",
                String::from_utf8_lossy(body)
            );
            let signal = crate::breaker::normalize_raw_error(&raw, &empty);
            assert_eq!(
                signal.class,
                crate::breaker::StatusClass::ContextLength,
                "a qualified 'too long' (context) message must classify as ContextLength: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// Regression (MEDIUM/conformance): a non-streaming request must OMIT the `stream` key entirely
    /// (matching a native client relying on the `false` default), and a streaming request must emit
    /// `"stream": true`. Always injecting `"stream": false` was a proxy tell and a same-protocol
    /// passthrough fidelity break.
    #[test]
    fn test_write_request_stream_field_conditional() {
        let base = crate::ir::IrRequest {
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
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = CohereWriter;
        let non_streaming = writer.write_request(&base);
        assert!(
            non_streaming.get("stream").is_none(),
            "non-streaming request must omit the `stream` key, got {non_streaming}"
        );

        let streaming = writer.write_request(&crate::ir::IrRequest {
            stream: true,
            ..base
        });
        assert_eq!(
            streaming.get("stream"),
            Some(&serde_json::json!(true)),
            "streaming request must emit `\"stream\": true`"
        );
    }

    /// Regression (MEDIUM/conformance): a non-streaming Cohere -> Cohere passthrough must NOT GAIN a
    /// `stream` field the native client never sent. Reading a body without `stream` then writing it
    /// must yield a body still without `stream`.
    #[test]
    fn test_stream_field_roundtrip_omitted() {
        let native = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = CohereReader
            .read_request(&native)
            .expect("read_request should succeed");
        assert!(!ir.stream, "absent `stream` reads as false");
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert!(
            out.get("stream").is_none(),
            "round-trip must not inject a `stream` field, got {out}"
        );
    }

    /// Regression (MEDIUM/conformance): the streaming `message-end` frame must carry token usage at
    /// `delta.usage.tokens.{input_tokens,output_tokens}` (native Cohere v2 shape) so a Cohere SDK
    /// client tracking billing/rate-limit data is not silently zeroed.
    #[test]
    fn test_write_response_event_message_end_carries_usage() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 42,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("message-end must serialize");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("message-end")
        );
        let tokens = frame
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
            .expect("delta.usage.tokens must be present");
        assert_eq!(
            tokens.get("input_tokens").and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            tokens.get("output_tokens").and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    /// Regression (MEDIUM/conformance): when upstream usage is zero (no data), the message-end frame
    /// still emits the `tokens` object with zero values rather than omitting the key.
    #[test]
    fn test_write_response_event_message_end_zero_usage_present() {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("message-end must serialize");
        let tokens = frame
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
            .expect("delta.usage.tokens must be present even with zero usage");
        assert_eq!(tokens.get("input_tokens").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            tokens.get("output_tokens").and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    /// The message-end stream frame round-trips usage through this protocol's own reader: the usage
    /// written into `delta.usage.tokens` is read back identically.
    #[test]
    fn test_message_end_usage_stream_roundtrip() {
        let usage = crate::ir::IrUsage {
            input_tokens: 11,
            output_tokens: 3,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage.clone(),
            })
            .expect("message-end must serialize");

        let mut state = crate::ir::StreamDecodeState::default();
        let evs = CohereReader.read_response_events("", &frame, &mut state);
        let back = evs
            .iter()
            .find_map(|e| {
                if let IrStreamEvent::MessageDelta { usage, .. } = e {
                    Some(usage.clone())
                } else {
                    None
                }
            })
            .expect("a MessageDelta must come back");
        assert_eq!(back.input_tokens, 11);
        assert_eq!(back.output_tokens, 3);
    }

    /// Regression (LOW/correctness): a Tool-role message carrying plain text ALONGSIDE a ToolResult
    /// must not silently drop the text — it is folded into the emitted tool message content.
    #[test]
    fn test_tool_role_text_alongside_result_not_dropped() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "note".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "result".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    },
                ],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 1, "one tool message emitted");
        let content = msgs[0].get("content").and_then(|c| c.as_str()).unwrap();
        assert!(
            content.contains("note") && content.contains("result"),
            "both the message-level text and the tool result text must survive, got {content}"
        );
        assert_eq!(
            msgs[0].get("tool_call_id").and_then(|v| v.as_str()),
            Some("t1")
        );
    }

    /// Regression (LOW/correctness): a degenerate Tool-role message with text but NO ToolResult
    /// block must still emit its text rather than producing nothing at all.
    #[test]
    fn test_tool_role_text_without_result_not_dropped() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::Text {
                    text: "orphan tool text".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "a Tool turn with text but no ToolResult must still emit a message"
        );
        assert_eq!(msgs[0].get("role").and_then(|r| r.as_str()), Some("tool"));
        assert_eq!(
            msgs[0].get("content").and_then(|c| c.as_str()),
            Some("orphan tool text")
        );
    }

    /// Regression (LOW #11/correctness): a degenerate Tool-role message with MULTIPLE text blocks
    /// but NO ToolResult must emit `content` as a joined STRING, not a JSON text-part array. The old
    /// code forwarded `content_val` (a JSON array for >1 text block), producing an invalid Cohere
    /// tool message; the fix stringifies the blocks like the ToolResult path.
    #[test]
    fn test_tool_role_multi_text_without_result_is_string() {
        let ir = crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "a".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Text {
                        text: "b".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                ],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "a Tool turn with multiple text blocks but no ToolResult must emit one message"
        );
        assert_eq!(msgs[0].get("role").and_then(|r| r.as_str()), Some("tool"));
        assert_eq!(
            msgs[0].get("content").and_then(|c| c.as_str()),
            Some("a b"),
            "multi-block degenerate Tool content must be a joined string, not a JSON array"
        );
    }

    /// Regression (HIGH/dead-code): `write_error` is a LIVE vtable-dispatched trait method, not
    /// test-only scaffolding. Reaching it via a `&dyn ProtocolWriter` (the exact runtime path used
    /// at the Cohere-ingress error sites) must produce the native bare `{"message": ...}` envelope.
    #[test]
    fn test_write_error_via_trait_object_is_live_path() {
        let writer: Box<dyn ProtocolWriter> = Box::new(CohereWriter);
        let v = writer.write_error(401, "authentication_error", "bad key");
        assert_eq!(
            v.get("message").and_then(|m| m.as_str()),
            Some("bad key"),
            "the vtable-dispatched write_error must emit the native Cohere envelope"
        );
        assert_eq!(
            v.as_object().map(|o| o.len()),
            Some(1),
            "native Cohere error body is a bare single-key {{\"message\": ...}}"
        );
    }

    /// Regression (MEDIUM/conformance): a Cohere v2 `tool`-role message whose `content` is the
    /// native object-array shape (`[{"type":"text","text":...}]`, plus a typed `document` block)
    /// must NOT be silently dropped. The previous `filter_map(|b| b.as_str())` returned None for
    /// every object element, yielding empty tool-result content and corrupting the conversation on
    /// passthrough/egress.
    #[test]
    fn test_read_request_tool_content_object_array_preserved() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": [
                        {"type": "text", "text": "first part"},
                        {"type": "text", "text": "second part"},
                        {"type": "document", "document": {"id": "d1", "data": "doc body"}}
                    ]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == crate::ir::IrRole::Tool)
            .expect("tool message present");
        let tool_result = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
            .expect("ToolResult block present");
        let text = match tool_result.first() {
            Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
            other => panic!("expected text block in tool result, got {other:?}"),
        };
        assert!(
            text.contains("first part"),
            "text block text must be preserved: {text}"
        );
        assert!(
            text.contains("second part"),
            "all text blocks must be joined: {text}"
        );
        assert!(
            text.contains("doc body"),
            "non-text typed (document) block must be serialized, not dropped: {text}"
        );
    }

    /// Regression (MEDIUM/conformance): the bare-string tool-content array shape must keep working
    /// alongside the new object-array handling.
    #[test]
    fn test_read_request_tool_content_string_array_still_works() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_2",
                    "content": ["alpha", "beta"]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == crate::ir::IrRole::Tool)
            .expect("tool message present");
        let tool_result = tool_msg
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
            .expect("ToolResult block present");
        let text = match tool_result.first() {
            Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
            other => panic!("expected text block in tool result, got {other:?}"),
        };
        assert_eq!(text, "alpha beta");
    }

    /// Regression (HIGH/correctness): Cohere v2 streams each tool call as a complete
    /// start/delta(s)/end sequence, closing the first tool BEFORE starting the second. The IR block
    /// index assigned to each tool must stay distinct and stable for the tool's whole lifetime. The
    /// prior scheme derived the index from the live rank of `frame_idx` in a set that shrank on
    /// `tool-call-end`, so the second tool-call-start saw `len()==0` and reused the first tool's IR
    /// index — silently merging two distinct tool calls onto one block. Feed two full sequences and
    /// assert two DISTINCT BlockStart indices that match their deltas/stops.
    #[test]
    fn test_stream_two_sequential_tool_calls_get_distinct_indices() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // --- Tool 1: start (frame index 0) ---
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {
                    "id": "call_a",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        let idx1 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            } => {
                assert_eq!(id, "call_a");
                *index
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        };

        // Tool 1 delta + end (closing the first tool BEFORE the second starts — the trigger).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 0,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"a\":1}"}}}}
            }),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx1
        ));
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index } if *index == idx1
        ));

        // --- Tool 2: start (frame index 1), AFTER tool 1 closed ---
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 1,
                "delta": {"message": {"tool_calls": {
                    "id": "call_b",
                    "type": "function",
                    "function": {"name": "get_time", "arguments": ""}
                }}}
            }),
            &mut state,
        );
        let idx2 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            } => {
                assert_eq!(id, "call_b");
                *index
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        };

        // The core assertion: the two tool calls occupy DISTINCT IR block indices.
        assert_ne!(
            idx1, idx2,
            "two sequential streamed tool calls must get distinct IR block indices"
        );

        // Tool 2's delta and end resolve to ITS index, not tool 1's.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-delta",
                "index": 1,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"b\":2}"}}}}
            }),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx2
        ));
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 1}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index } if *index == idx2
        ));
    }

    /// Regression (LOW #9): a tool call's IR block index is ASSIGNED at `tool-call-start` and is
    /// IMMUTABLE for the tool's whole lifetime — it must NOT change because a LATER tool arrives
    /// with a smaller (non-monotonic) wire `frame_idx`. The prior scheme RECOMPUTED the index as the
    /// live rank of `frame_idx` among recorded frames, so a second tool whose wire index sorts
    /// BEFORE an earlier still-tracked tool retroactively bumped that earlier tool's rank: its
    /// `tool-call-end` then resolved to a different IR index than its `tool-call-start`/`delta`,
    /// emitting BlockStop for a block that was never opened and leaving the real block unclosed.
    ///
    /// Feed two interleaved tool calls where the SECOND tool's wire index (5) is LARGER but the
    /// THIRD's (2) is SMALLER than the first (10), all opened before any closes, and assert that each
    /// tool's start, delta, and end frames all resolve to the SAME IR index the start was assigned.
    #[test]
    fn test_stream_tool_ir_index_stable_under_non_monotonic_frame_indices() {
        let reader = CohereReader;
        let mut state = crate::ir::StreamDecodeState::default();

        let start = |wire: u64, id: &str| {
            serde_json::json!({
                "type": "tool-call-start",
                "index": wire,
                "delta": {"message": {"tool_calls": {
                    "id": id,
                    "type": "function",
                    "function": {"name": "f", "arguments": ""}
                }}}
            })
        };
        let start_idx = |evs: &[IrStreamEvent]| match evs.first() {
            Some(IrStreamEvent::BlockStart { index, .. }) => *index,
            other => panic!("expected a BlockStart, got {other:?}"),
        };

        // Open three tools with DELIBERATELY non-monotonic wire indices: 10, then 5, then 2.
        let a_idx = start_idx(&reader.read_response_events("", &start(10, "call_a"), &mut state));
        let b_idx = start_idx(&reader.read_response_events("", &start(5, "call_b"), &mut state));
        let c_idx = start_idx(&reader.read_response_events("", &start(2, "call_c"), &mut state));

        // Assignment is by INSERTION ORDER, so the three tools get distinct, contiguous indices
        // regardless of their (descending) wire indices.
        assert_eq!(
            (a_idx, b_idx, c_idx),
            (0, 1, 2),
            "tool IR indices must be assigned by insertion order, not wire-index rank"
        );

        // For each tool, its delta and end (resolved LATER, after the out-of-order siblings were
        // recorded) must still land on the SAME index its start was assigned. Under the old
        // live-rank scheme, tool A (wire 10) would have ranked 0 at start but 2 by end (because
        // wires 5 and 2 were inserted below it), shifting its close to the wrong block.
        for (wire, expected) in [(10u64, a_idx), (5, b_idx), (2, c_idx)] {
            let delta = serde_json::json!({
                "type": "tool-call-delta",
                "index": wire,
                "delta": {"message": {"tool_calls": {"function": {"arguments": "{}"}}}}
            });
            let devs = reader.read_response_events("", &delta, &mut state);
            assert!(
                matches!(devs.first(), Some(IrStreamEvent::BlockDelta { index, .. }) if *index == expected),
                "delta for wire {wire} must resolve to its assigned IR index {expected}, got {devs:?}"
            );

            let end = serde_json::json!({ "type": "tool-call-end", "index": wire });
            let eevs = reader.read_response_events("", &end, &mut state);
            assert!(
                matches!(eevs.first(), Some(IrStreamEvent::BlockStop { index }) if *index == expected),
                "end for wire {wire} must close its assigned IR index {expected}, got {eevs:?}"
            );
        }
    }

    /// A leading text block must push tool blocks to IR index 1+ while keeping each tool distinct.
    #[test]
    fn test_stream_tool_indices_offset_by_open_text_block() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // Open a text block at index 0.
        reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            &mut state,
        );

        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {"id": "c1", "type": "function", "function": {"name": "f1", "arguments": ""}}}}
            }),
            &mut state,
        );
        let idx1 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("expected BlockStart, got {other:?}"),
        };
        assert_eq!(idx1, 1, "first tool follows the open text block at index 0");

        reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );

        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 1,
                "delta": {"message": {"tool_calls": {"id": "c2", "type": "function", "function": {"name": "f2", "arguments": ""}}}}
            }),
            &mut state,
        );
        let idx2 = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("expected BlockStart, got {other:?}"),
        };
        assert_eq!(
            idx2, 2,
            "second tool gets the next distinct index after the first"
        );
        assert_ne!(idx1, idx2);
    }

    /// Regression (HIGH/correctness): a text content block that has CLOSED before the first
    /// tool-call-start must still reserve IR index 0 — the tool block must NOT reuse index 0. Native
    /// Cohere v2 emits the full text block (content-start/delta/end) before any tool call, so by the
    /// time the tool arrives `text_block_open` is already false; keying the tool base offset on that
    /// live flag previously collapsed the first tool back onto index 0, emitting two BlockStart
    /// frames at index 0 on a normal text-then-tool turn. The base must instead reflect that a text
    /// block was EVER opened this stream.
    #[test]
    fn test_stream_tool_after_closed_text_block_does_not_reuse_index_zero() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;

        // Text block: start at index 0 ...
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ));

        // ... and CLOSE it before any tool arrives (the trigger for the defect).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "content-end", "index": 0}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));
        assert!(
            !state.text_block_open,
            "content-end must clear the live text_block_open flag"
        );

        // Now the first tool starts. It must land at IR index 1, NOT reuse the closed text block's 0.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": {"message": {"tool_calls": {"id": "call_a", "type": "function", "function": {"name": "f", "arguments": ""}}}}
            }),
            &mut state,
        );
        let tool_idx = match &evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { .. },
            } => *index,
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        };
        assert_eq!(
            tool_idx, 1,
            "a tool following a CLOSED text block must not reuse the text block's IR index 0"
        );

        // The tool's delta and end resolve to the same index 1, never back to 0.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": "tool-call-end", "index": 0}),
            &mut state,
        );
        assert!(matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStop { index: 1 }
        ));
    }

    /// Regression (MEDIUM/performance): the modeled-key set is built once and shared, and still
    /// contains exactly the keys this reader models — so request fields like those stay out of
    /// `extra` while unknown keys are preserved. Calling it twice returns the same backing set.
    #[test]
    fn test_modeled_keys_built_once_and_complete() {
        let a = cohere_modeled_keys();
        let b = cohere_modeled_keys();
        assert!(
            std::ptr::eq(a, b),
            "modeled-key set must be a shared singleton"
        );
        for k in [
            "model",
            "messages",
            "tools",
            "max_tokens",
            "temperature",
            "stream",
        ] {
            assert!(a.contains(k), "{k} must be a modeled key");
        }
        // An unknown key is NOT modeled (so it round-trips through `extra`).
        assert!(!a.contains("unknown_passthrough_key"));
    }

    /// Regression (MEDIUM/conformance): a cross-protocol stream delivering tool calls to a
    /// Cohere-ingress client must emit native `tool-call-start` / `tool-call-delta` frames. The
    /// writer previously returned None for BlockStart{ToolUse} and BlockDelta{InputJsonDelta}, so a
    /// Cohere client watching for streaming tool calls received nothing.
    #[test]
    fn test_write_response_event_emits_tool_call_frames() {
        let writer = CohereWriter;

        // BlockStart{ToolUse} → tool-call-start carrying id/name and an empty-string arguments.
        let start = IrStreamEvent::BlockStart {
            index: 2,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_x".to_string(),
                name: "get_weather".to_string(),
            },
        };
        let (_, frame) = writer
            .write_response_event(&start)
            .expect("BlockStart ToolUse must emit a frame");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("tool-call-start")
        );
        assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
        let tc = frame
            .get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("tool_calls"))
            .expect("tool_calls present");
        assert_eq!(tc.get("id").and_then(|v| v.as_str()), Some("call_x"));
        assert_eq!(tc.get("type").and_then(|v| v.as_str()), Some("function"));
        assert_eq!(
            tc.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str()),
            Some("get_weather")
        );
        assert_eq!(
            tc.get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str()),
            Some(""),
            "the reader accumulates argument deltas onto this opening empty string"
        );

        // BlockDelta{InputJsonDelta} → tool-call-delta carrying the argument fragment.
        let delta = IrStreamEvent::BlockDelta {
            index: 2,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
        };
        let (_, frame) = writer
            .write_response_event(&delta)
            .expect("BlockDelta InputJsonDelta must emit a frame");
        assert_eq!(
            frame.get("type").and_then(|t| t.as_str()),
            Some("tool-call-delta")
        );
        assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
        assert_eq!(
            frame
                .get("delta")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.get("function"))
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str()),
            Some("{\"city\":\"SF\"}")
        );
    }

    /// The writer's emitted tool-call-start/delta frames round-trip through this protocol's OWN
    /// reader: a BlockStart{ToolUse} + BlockDelta(args) re-read yields the same id/name/arguments.
    #[test]
    fn test_writer_tool_call_frames_roundtrip_through_reader() {
        let writer = CohereWriter;
        let (_, start_frame) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_z".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("start frame");
        let (_, delta_frame) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
            })
            .expect("delta frame");

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;
        let start_evs = reader.read_response_events("", &start_frame, &mut state);
        match &start_evs[0] {
            crate::ir::IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { id, name },
                ..
            } => {
                assert_eq!(id, "call_z");
                assert_eq!(name, "lookup");
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        }
        let delta_evs = reader.read_response_events("", &delta_frame, &mut state);
        match &delta_evs[0] {
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::InputJsonDelta(args),
                ..
            } => assert_eq!(args, "{\"q\":1}"),
            other => panic!("expected InputJsonDelta, got {other:?}"),
        }
    }

    /// Thinking/Image stream blocks have no native Cohere v2 frame shape, so the writer suppresses
    /// them (returns None) rather than emitting a fabricated non-native frame.
    #[test]
    fn test_write_response_event_thinking_and_image_blocks_suppressed() {
        let writer = CohereWriter;
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Thinking,
            })
            .is_none());
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Image,
            })
            .is_none());
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta("x".to_string()),
            })
            .is_none());
    }

    /// Regression (HIGH/correctness): a Cohere `tool`-role message's `content` must be decoded
    /// EXACTLY ONCE — into the ToolResult's inner content — and NOT also into a stray top-level
    /// Text block. The generic top-level content loop previously ran for every non-system role
    /// (including Tool), so one tool message produced both a top-level Text block AND a ToolResult
    /// holding the identical text. Assert the IR carries a single ToolResult and no top-level Text.
    #[test]
    fn test_read_request_tool_content_not_double_decoded() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": [{"type": "text", "text": "the result"}]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let tool_msg = ir
            .messages
            .iter()
            .find(|m| m.role == crate::ir::IrRole::Tool)
            .expect("tool message present");

        // No stray top-level Text block on the Tool message.
        let stray_text = tool_msg
            .content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::Text { .. }));
        assert!(
            !stray_text,
            "tool message must NOT carry a top-level Text block (content belongs to the ToolResult)"
        );

        // Exactly one ToolResult, carrying the text once.
        let tool_results: Vec<&Vec<crate::ir::IrBlock>> = tool_msg
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
            .collect();
        assert_eq!(tool_results.len(), 1, "exactly one ToolResult block");
        let inner = match tool_results[0].first() {
            Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
            other => panic!("expected text in tool result, got {other:?}"),
        };
        assert_eq!(inner, "the result");
    }

    /// Regression (HIGH/correctness): a Cohere -> Cohere round-trip of a tool message must NOT
    /// duplicate the tool-result text. The double-decode caused the egress writer (whose Tool
    /// branch folds leftover top-level text into the first ToolResult) to emit the same text twice
    /// in the outgoing `content` string. Assert the text appears exactly once after a full
    /// read_request -> write_request cycle.
    #[test]
    fn test_tool_message_roundtrip_no_duplicate_text() {
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": [{"type": "text", "text": "UNIQUEMARKER"}]
                }
            ]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        let msgs = out.get("messages").unwrap().as_array().unwrap();
        let tool_msg = msgs
            .iter()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
            .expect("a tool message must be emitted");
        let content = tool_msg
            .get("content")
            .and_then(|c| c.as_str())
            .expect("tool content string");
        assert_eq!(
            content.matches("UNIQUEMARKER").count(),
            1,
            "tool-result text must appear exactly once (no double-decode duplication), got {content}"
        );
        assert_eq!(
            tool_msg.get("tool_call_id").and_then(|v| v.as_str()),
            Some("call_1")
        );
    }

    /// Regression (MEDIUM/correctness): `max_tokens` must be narrowed with `u32::try_from`, NOT a
    /// bare `as u32`. A value above `u32::MAX` previously wrapped to a small nonsense cap and was
    /// forwarded to Cohere; it must now drop to `None` (no cap) rather than a truncated wrap. A
    /// valid in-range value still parses, and a zero/negative value is still rejected.
    #[test]
    fn test_read_request_max_tokens_out_of_range_drops_to_none() {
        let reader = CohereReader;

        // u32::MAX + 1 must NOT wrap to 0 (or any truncated value): it drops to None.
        let over = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": (u32::MAX as i64) + 1
        });
        let ir = reader
            .read_request(&over)
            .expect("read_request should succeed");
        assert_eq!(
            ir.max_tokens, None,
            "an out-of-range max_tokens must drop to None, not wrap under `as u32`"
        );

        // A far-larger value likewise drops rather than truncating into the valid u32 range.
        let huge = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": i64::MAX
        });
        let ir = reader
            .read_request(&huge)
            .expect("read_request should succeed");
        assert_eq!(ir.max_tokens, None);

        // The exact u32::MAX boundary is in range and preserved.
        let max_in_range = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": u32::MAX as i64
        });
        let ir = reader
            .read_request(&max_in_range)
            .expect("read_request should succeed");
        assert_eq!(ir.max_tokens, Some(u32::MAX));

        // A normal value still parses through unchanged.
        let normal = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1024
        });
        let ir = reader
            .read_request(&normal)
            .expect("read_request should succeed");
        assert_eq!(ir.max_tokens, Some(1024));

        // Zero/negative are still rejected by the `v > 0` filter (unchanged behavior).
        let zero = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 0
        });
        assert_eq!(
            reader.read_request(&zero).expect("ok").max_tokens,
            None,
            "zero max_tokens is rejected"
        );
        let neg = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": -5
        });
        assert_eq!(
            reader.read_request(&neg).expect("ok").max_tokens,
            None,
            "negative max_tokens is rejected"
        );
    }

    /// Regression (MEDIUM/correctness): `k` (top_k) must be narrowed with `u32::try_from`, NOT a
    /// bare `as u32`. A value above `u32::MAX` previously wrapped to a small nonsense sampling cap
    /// (e.g. 4294967296 -> 0, 4294967297 -> 1) that was forwarded to Cohere, diverging from a
    /// direct Cohere call; it must now drop to `None` (no cap forwarded) instead of wrapping. A
    /// valid in-range value, including the exact `u32::MAX` boundary, is preserved.
    #[test]
    fn test_read_request_top_k_out_of_range_drops_to_none() {
        let reader = CohereReader;

        // u32::MAX + 1 must NOT wrap to 0: it drops to None.
        let over = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "k": (u32::MAX as u64) + 1
        });
        assert_eq!(
            reader.read_request(&over).expect("ok").top_k,
            None,
            "an out-of-range top_k must drop to None, not wrap under `as u32`"
        );

        // u32::MAX + 2 must NOT wrap to 1 either.
        let over2 = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "k": (u32::MAX as u64) + 2
        });
        assert_eq!(reader.read_request(&over2).expect("ok").top_k, None);

        // A far-larger value likewise drops rather than truncating into the valid u32 range.
        let huge = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "k": u64::MAX
        });
        assert_eq!(reader.read_request(&huge).expect("ok").top_k, None);

        // The exact u32::MAX boundary is in range and preserved.
        let max_in_range = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "k": u32::MAX as u64
        });
        assert_eq!(
            reader.read_request(&max_in_range).expect("ok").top_k,
            Some(u32::MAX)
        );

        // A normal value still parses through unchanged.
        let normal = serde_json::json!({
            "model": "command",
            "messages": [{"role": "user", "content": "hi"}],
            "k": 40
        });
        assert_eq!(reader.read_request(&normal).expect("ok").top_k, Some(40));
    }

    /// Regression (LOW/robustness): `state.open_tools` is never shrunk, so an upstream streaming an
    /// unbounded number of distinct `tool-call-start` frame indices must not grow it without bound.
    /// Past `MAX_TRACKED_TOOL_FRAMES` new frames stop being recorded, keeping the set capped while
    /// every realistic stream (a handful of tools) is unaffected.
    #[test]
    fn test_open_tools_growth_is_capped() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;
        for frame_idx in 0..(MAX_TRACKED_TOOL_FRAMES + 50) {
            reader.read_response_events(
                "",
                &serde_json::json!({
                    "type": "tool-call-start",
                    "index": frame_idx,
                    "delta": {"message": {"tool_calls": {
                        "id": format!("call_{frame_idx}"),
                        "type": "function",
                        "function": {"name": "f", "arguments": ""}
                    }}}
                }),
                &mut state,
            );
        }
        assert!(
            state.open_tools.len() <= MAX_TRACKED_TOOL_FRAMES,
            "open_tools must be capped at MAX_TRACKED_TOOL_FRAMES, got {}",
            state.open_tools.len()
        );
    }

    /// Regression (HIGH/conformance): a `BlockStop` that closes a TOOL-CALL block (one opened by a
    /// `tool-call-start` frame) must emit `tool-call-end`, NOT `content-end`. A native Cohere v2 SDK
    /// distinguishes content events from tool-call events by type; closing a tool block with the
    /// text `content-end` event leaves the tool call never terminated and breaks cross-protocol
    /// streaming tool use.
    #[test]
    fn test_block_stop_closes_tool_block_with_tool_call_end() {
        let writer = CohereWriter;
        // Open a tool-call block at index 0.
        let (_, start) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string(),
                },
            })
            .expect("tool-call-start must emit");
        assert_eq!(
            start.get("type").and_then(|t| t.as_str()),
            Some("tool-call-start")
        );
        // Closing it must use tool-call-end at the SAME index.
        let (_, stop) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("tool block stop must emit");
        assert_eq!(
            stop.get("type").and_then(|t| t.as_str()),
            Some("tool-call-end"),
            "a tool-call block must close with tool-call-end, not content-end"
        );
        assert_eq!(stop.get("index").and_then(|i| i.as_u64()), Some(0));
    }

    /// Regression (HIGH/conformance): a `BlockStop` that closes a TEXT block (one opened by a
    /// `content-start`/text `BlockStart`) must still emit `content-end`. Only tool-call blocks use
    /// `tool-call-end`.
    #[test]
    fn test_block_stop_closes_text_block_with_content_end() {
        let writer = CohereWriter;
        // Open a text block at index 0.
        let (_, start) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("content-start must emit");
        assert_eq!(
            start.get("type").and_then(|t| t.as_str()),
            Some("content-start")
        );
        let (_, stop) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("text block stop must emit");
        assert_eq!(
            stop.get("type").and_then(|t| t.as_str()),
            Some("content-end"),
            "a text block must close with content-end"
        );
        assert_eq!(stop.get("index").and_then(|i| i.as_u64()), Some(0));
    }

    /// Regression (HIGH/conformance): a mixed stream (text block at index 0, then a tool-call block
    /// at index 1) must close EACH block with its own correct end event — `content-end` for the text
    /// index and `tool-call-end` for the tool index — based on which kind opened that index.
    #[test]
    fn test_block_stop_mixed_text_and_tool_close_events() {
        let writer = CohereWriter;
        // Text block at index 0.
        writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("text start");
        // Tool block at index 1.
        writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_2".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("tool start");

        let (_, stop_text) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("text stop");
        assert_eq!(
            stop_text.get("type").and_then(|t| t.as_str()),
            Some("content-end"),
            "index 0 (text) must close with content-end"
        );

        let (_, stop_tool) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .expect("tool stop");
        assert_eq!(
            stop_tool.get("type").and_then(|t| t.as_str()),
            Some("tool-call-end"),
            "index 1 (tool) must close with tool-call-end"
        );
    }

    /// The writer's tool open/close pair round-trips through this protocol's OWN reader: a
    /// BlockStart{ToolUse} followed by a BlockStop emits `tool-call-start` then `tool-call-end`,
    /// which the reader maps back to a BlockStart{ToolUse} then a BlockStop.
    #[test]
    fn test_tool_block_open_close_roundtrip_through_reader() {
        let writer = CohereWriter;
        let (_, start_frame) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_z".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("start frame");
        let (_, stop_frame) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("stop frame");
        assert_eq!(
            stop_frame.get("type").and_then(|t| t.as_str()),
            Some("tool-call-end")
        );

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = CohereReader;
        let start_evs = reader.read_response_events("", &start_frame, &mut state);
        assert!(matches!(
            &start_evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { .. },
                ..
            }
        ));
        let stop_evs = reader.read_response_events("", &stop_frame, &mut state);
        assert!(
            matches!(&stop_evs[0], crate::ir::IrStreamEvent::BlockStop { .. }),
            "tool-call-end must map back to a BlockStop, got {stop_evs:?}"
        );
    }

    /// A tool index is consumed on close: a second `BlockStop` at the same index (an over-eager or
    /// duplicate close) must NOT re-report `tool-call-end`. After the open-text-tracking fix (MED #4)
    /// an index that is tracked by NEITHER the open-tool set NOR the open-text set emits no frame at
    /// all, rather than falling through to an orphan `content-end` with no matching `content-start`.
    #[test]
    fn test_block_stop_tool_index_consumed_on_close() {
        let writer = CohereWriter;
        writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 3,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "c".to_string(),
                    name: "f".to_string(),
                },
            })
            .expect("start");
        let (_, first) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 3 })
            .expect("first stop");
        assert_eq!(
            first.get("type").and_then(|t| t.as_str()),
            Some("tool-call-end")
        );
        // The tool marker was consumed and no text block was ever opened at index 3, so a second
        // close is an untracked index → no frame (no orphan content-end).
        let second = writer.write_response_event(&IrStreamEvent::BlockStop { index: 3 });
        assert!(
            second.is_none(),
            "a tool index consumed on first close must emit no frame on a duplicate close, got {second:?}"
        );
    }

    /// Regression (MEDIUM/conformance): the non-streaming `write_response` path must write IR
    /// `stop_reason = "stop_sequence"` back as the native `STOP_SEQUENCE`, NOT `COMPLETE`. The
    /// reader maps `STOP_SEQUENCE` -> IR `stop_sequence` and `COMPLETE` -> IR `end_turn`, so
    /// collapsing both IR reasons onto `COMPLETE` made the round-trip asymmetric and masked a
    /// stop-sequence stop as a normal end-of-turn for a Cohere client.
    #[test]
    fn test_write_response_stop_sequence_maps_to_stop_sequence() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("stop_sequence".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("c14c80c3-18eb-4519-9460-6c92edd8cfb4".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = CohereWriter;
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("finish_reason").and_then(|r| r.as_str()),
            Some("STOP_SEQUENCE"),
            "IR stop_sequence must serialize as native STOP_SEQUENCE, not COMPLETE"
        );
    }

    /// Companion: IR `end_turn` still maps to `COMPLETE` (the split must not regress the normal
    /// end-of-turn case).
    #[test]
    fn test_write_response_end_turn_maps_to_complete() {
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
            model: None,
            id: Some("c14c80c3-18eb-4519-9460-6c92edd8cfb4".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = CohereWriter;
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("finish_reason").and_then(|r| r.as_str()),
            Some("COMPLETE")
        );
    }

    /// Regression (MEDIUM/conformance): the streaming `MessageDelta` path must likewise write IR
    /// `stop_sequence` back as native `STOP_SEQUENCE` (not `COMPLETE`) in the message-end frame.
    #[test]
    fn test_stream_message_delta_stop_sequence_maps_to_stop_sequence() {
        let writer = CohereWriter;
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("stop_sequence".to_string()),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 2,
                    output_tokens: 3,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            })
            .expect("message-end frame");
        assert_eq!(
            frame
                .get("delta")
                .and_then(|d| d.get("finish_reason"))
                .and_then(|r| r.as_str()),
            Some("STOP_SEQUENCE"),
            "streamed IR stop_sequence must serialize as native STOP_SEQUENCE, not COMPLETE"
        );
    }

    /// Full round-trip: a native Cohere `STOP_SEQUENCE` read into IR must write back as
    /// `STOP_SEQUENCE` through both response paths — proving the reader/writer mapping is now
    /// symmetric for stop-sequence stops (the asymmetry the finding flagged).
    #[test]
    fn test_stop_sequence_roundtrips_symmetrically() {
        let reader = CohereReader;
        let native = serde_json::json!({
            "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
            "finish_reason": "STOP_SEQUENCE",
            "message": { "role": "assistant", "content": [{ "type": "text", "text": "x" }] },
            "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
        });
        let ir = reader.read_response(&native).expect("read native response");
        assert_eq!(ir.stop_reason.as_deref(), Some("stop_sequence"));

        let writer = CohereWriter;
        let out = writer.write_response(&ir);
        assert_eq!(
            out.get("finish_reason").and_then(|r| r.as_str()),
            Some("STOP_SEQUENCE"),
            "STOP_SEQUENCE must survive a Cohere -> IR -> Cohere round-trip unchanged"
        );
    }

    /// Test helper: count `BlockStart` events whose IR index equals `idx`.
    fn count_block_starts_at(evs: &[IrStreamEvent], idx: usize) -> usize {
        evs.iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { index, .. } if *index == idx))
            .count()
    }

    /// Regression (LOW #17): a DUPLICATE `tool-call-start` for a frame index that is already open
    /// must be a no-op. The pre-fix code emitted a fresh `BlockStart` unconditionally on every
    /// `tool-call-start`, so a backend that re-sent the start frame for an already-open tool block
    /// produced two `BlockStart` events at the same IR index — a spurious second opening frame for
    /// one block. After the fix the second start emits nothing.
    #[test]
    fn test_duplicate_tool_call_start_is_noop() {
        let reader = CohereReader;
        let mut state = crate::ir::StreamDecodeState::default();

        let start = serde_json::json!({
            "type": "tool-call-start",
            "index": 0,
            "delta": { "message": { "tool_calls": {
                "id": "call_1",
                "type": "function",
                "function": { "name": "get_weather", "arguments": "" }
            }}}
        });

        let first = reader.read_response_events("", &start, &mut state);
        // First start opens the block exactly once (text never appeared, so tool IR index is 0).
        assert_eq!(
            count_block_starts_at(&first, 0),
            1,
            "first tool-call-start must open the block once"
        );

        let second = reader.read_response_events("", &start, &mut state);
        assert_eq!(
            count_block_starts_at(&second, 0),
            0,
            "a duplicate tool-call-start for an already-open frame must emit no BlockStart"
        );
        assert!(
            second.is_empty(),
            "a duplicate tool-call-start must be a complete no-op, got {second:?}"
        );
    }

    /// Regression (LOW #18): a `tool-call-start` for a frame BEYOND `MAX_TRACKED_TOOL_FRAMES` must
    /// emit NO tool block events. The pre-fix code skipped *recording* the over-cap frame but still
    /// computed an IR index via `cohere_tool_ir_index` and emitted a `BlockStart` for it. Because
    /// the frame was never recorded, that index equalled the rank of the highest *tracked* tool —
    /// a collision producing a second `BlockStart` at an already-used IR index. After the fix an
    /// untracked frame emits nothing (and its later delta/end are likewise dropped).
    #[test]
    fn test_over_cap_tool_call_start_emits_no_block() {
        let reader = CohereReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Saturate the tracked set with distinct frame indices [0, MAX_TRACKED_TOOL_FRAMES).
        for f in 0..MAX_TRACKED_TOOL_FRAMES {
            let start = serde_json::json!({
                "type": "tool-call-start",
                "index": f,
                "delta": { "message": { "tool_calls": {
                    "id": format!("call_{f}"),
                    "type": "function",
                    "function": { "name": "f", "arguments": "" }
                }}}
            });
            let _ = reader.read_response_events("", &start, &mut state);
        }
        assert_eq!(state.open_tools.len(), MAX_TRACKED_TOOL_FRAMES);

        // A genuinely new frame past the cap: must produce NO events and not collide with the
        // highest tracked tool's IR index (MAX_TRACKED_TOOL_FRAMES - 1).
        let over = serde_json::json!({
            "type": "tool-call-start",
            "index": MAX_TRACKED_TOOL_FRAMES + 5,
            "delta": { "message": { "tool_calls": {
                "id": "call_over",
                "type": "function",
                "function": { "name": "f", "arguments": "abc" }
            }}}
        });
        let evs = reader.read_response_events("", &over, &mut state);
        assert!(
            evs.is_empty(),
            "an over-cap tool-call-start must emit no block events, got {evs:?}"
        );
        assert_eq!(
            count_block_starts_at(&evs, MAX_TRACKED_TOOL_FRAMES - 1),
            0,
            "an over-cap tool-call-start must not collide with the highest tracked tool's index"
        );
    }

    /// Regression (LOW #19): content-start / content-delta / content-end must NORMALIZE the text
    /// block to IR index 0 regardless of the raw upstream wire `index`. The pre-fix code forwarded
    /// the wire `index` verbatim, so a backend that numbered its single text block at (say) wire
    /// index 2 produced a text `BlockStart`/`BlockDelta`/`BlockStop` at IR index 2 — while a tool
    /// block (which assumes text is at IR index 0) takes IR index 1 after it, leaving index 0 unused
    /// and the text/tool indices misaligned. After the fix the text block is always at IR index 0
    /// and the tool block lands at IR index 1.
    #[test]
    fn test_text_block_normalized_to_ir_index_zero() {
        let reader = CohereReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Backend numbers the text content block at a NON-ZERO wire index.
        let cs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "content-start",
                "index": 2,
                "delta": { "message": { "content": { "type": "text", "text": "" } } }
            }),
            &mut state,
        );
        match cs.as_slice() {
            [IrStreamEvent::BlockStart { index, block }] => {
                assert_eq!(
                    *index, 0,
                    "text BlockStart must be normalized to IR index 0"
                );
                assert!(matches!(block, crate::ir::IrBlockMeta::Text));
            }
            other => panic!("expected one text BlockStart, got {other:?}"),
        }

        let cd = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "content-delta",
                "index": 2,
                "delta": { "message": { "content": { "type": "text", "text": "hi" } } }
            }),
            &mut state,
        );
        match cd.as_slice() {
            [IrStreamEvent::BlockDelta { index, delta }] => {
                assert_eq!(
                    *index, 0,
                    "text BlockDelta must be normalized to IR index 0"
                );
                assert!(matches!(delta, crate::ir::IrDelta::TextDelta(t) if t == "hi"));
            }
            other => panic!("expected one text BlockDelta, got {other:?}"),
        }

        let ce = reader.read_response_events(
            "",
            &serde_json::json!({ "type": "content-end", "index": 2 }),
            &mut state,
        );
        match ce.as_slice() {
            [IrStreamEvent::BlockStop { index }] => {
                assert_eq!(*index, 0, "text BlockStop must be normalized to IR index 0");
            }
            other => panic!("expected one text BlockStop, got {other:?}"),
        }

        // A tool block that follows the (now-closed) text block must take IR index 1, NOT reuse the
        // wire index 2 the text block carried.
        let ts = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "tool-call-start",
                "index": 0,
                "delta": { "message": { "tool_calls": {
                    "id": "t1",
                    "type": "function",
                    "function": { "name": "f", "arguments": "" }
                }}}
            }),
            &mut state,
        );
        assert_eq!(
            count_block_starts_at(&ts, 1),
            1,
            "the tool block must open at IR index 1 (after the text block at index 0)"
        );
        assert_eq!(
            count_block_starts_at(&ts, 2),
            0,
            "the tool block must NOT reuse the text block's non-zero wire index"
        );
    }

    /// Regression (MED #3 / LOW #11): a non-request-size status (e.g. 429) whose free-text body
    /// mentions token counts must NOT be reclassified as the no-penalty `ContextLength` class. The
    /// body-scan override in `extract_error` is now gated on a request-size status (400 / 413), so a
    /// rate-limit failure keeps its `RateLimit` disposition and stays subject to the breaker. Against
    /// the old (ungated) code this stream reclassified to ContextLength and escaped the breaker.
    #[test]
    fn test_rate_limit_body_mentioning_tokens_is_not_context_length() {
        let reader = CohereReader;
        // A 429 whose message free-text mentions a maximum token count (the exact phrasing the
        // context-length scan keys on) must stay a rate-limit failure.
        let body = br#"{"message":"You have exceeded the maximum number of tokens per minute for your trial key"}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);

        // The override must NOT fire: provider_code keeps the raw message, not the canonical
        // context-length code.
        assert_ne!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 429 body mentioning tokens must not be reclassified as context_length_exceeded"
        );

        // End-to-end through the breaker: the canonical class is RateLimit, not ContextLength.
        let sig = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
        assert_eq!(
            sig.class,
            StatusClass::RateLimit,
            "a 429 body mentioning tokens must normalize to RateLimit so the breaker penalizes the lane"
        );

        // The `#[cfg(test)] classify()` helper must agree (status checked before the phrasing).
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(signal.class, StatusClass::RateLimit);
    }

    /// A genuine oversized-request failure (HTTP 400 with context-length phrasing) must still
    /// override to the canonical `context_length_exceeded` code and normalize to `ContextLength`.
    /// Guards that the status gate did not break the real context-length path.
    #[test]
    fn test_bad_request_body_mentioning_tokens_is_context_length() {
        let reader = CohereReader;
        let body =
            br#"{"message":"too many tokens: the request exceeds the maximum context length"}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 400 oversized-request body must still override to the canonical code"
        );
        let sig = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
        assert_eq!(sig.class, StatusClass::ContextLength);

        let signal = reader.classify(StatusCode::BAD_REQUEST, body);
        assert_eq!(signal.class, StatusClass::ContextLength);
    }

    /// Regression (MED #4): a cross-protocol `Thinking` block carries NO opening frame on the Cohere
    /// stream (its `BlockStart` maps to `None`), so its `BlockStop` must emit NOTHING — not an orphan
    /// `content-end` with no matching `content-start`. Against the old code the `BlockStop` fell
    /// through to an unconditional `content-end`.
    #[test]
    fn test_thinking_blockstop_emits_no_orphan_content_end() {
        let writer = CohereWriter;

        // Thinking BlockStart → no frame.
        let start = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Thinking,
        });
        assert!(
            start.is_none(),
            "a Thinking BlockStart must not emit an opening frame"
        );

        // Thinking BlockStop → no frame (the orphan-content-end defect).
        let stop = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });
        assert!(
            stop.is_none(),
            "a Thinking BlockStop must emit no frame (no orphan content-end)"
        );
    }

    /// A normal Text block still emits a balanced `content-start` / `content-end` pair — the
    /// open-text tracking must not suppress legitimate text closes.
    #[test]
    fn test_text_block_emits_balanced_content_start_and_end() {
        let writer = CohereWriter;

        let start = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        });
        let (_, start_data) = start.expect("Text BlockStart must emit a content-start frame");
        assert_eq!(
            start_data.get("type").and_then(|t| t.as_str()),
            Some("content-start")
        );

        let stop = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });
        let (_, stop_data) = stop.expect("Text BlockStop must emit a content-end frame");
        assert_eq!(
            stop_data.get("type").and_then(|t| t.as_str()),
            Some("content-end")
        );
    }

    /// Minimal IR request carrying a single tool and an explicit `tool_choice`, for the PF-H1
    /// round-trip tests below.
    fn ir_with_tool_choice(tc: Option<crate::ir::IrToolChoice>) -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                cache_control: None,
            }],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: tc,
            stream: false,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn test_cohere_tool_choice_required_roundtrips() {
        // REQUIRED reads into the IR union and re-emits as the native enum string (PF-H1).
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": "REQUIRED"
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));

        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("tool_choice").and_then(|v| v.as_str()),
            Some("REQUIRED")
        );
    }

    #[test]
    fn test_cohere_tool_choice_none() {
        // NONE round-trips to the IR `None` variant (forbid tools), distinct from omission.
        let body = serde_json::json!({
            "model": "command-r",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": "NONE"
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::None));

        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("tool_choice").and_then(|v| v.as_str()),
            Some("NONE")
        );
    }

    #[test]
    fn test_cohere_tool_choice_specific_degrades_to_required() {
        // Cohere cannot pin ONE tool; a targeted IrToolChoice::Tool (e.g. translated from an OpenAI
        // `tool_choice:{type:function,...}`) must degrade to REQUIRED — force *some* tool — NOT
        // silently drop to auto. This is the load-bearing PF-H1 behavior on a lossy-by-target hop.
        let ir = ir_with_tool_choice(Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string(),
        }));
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("tool_choice").and_then(|v| v.as_str()),
            Some("REQUIRED"),
            "a forced specific tool must degrade to REQUIRED, never to auto"
        );
    }

    #[test]
    fn test_cohere_tool_choice_auto_omitted() {
        // Auto is Cohere's default — the writer must omit the field entirely (emitting "auto" would
        // be invalid for Cohere v2), and an absent inbound tool_choice reads as None (the Option).
        let ir = ir_with_tool_choice(Some(crate::ir::IrToolChoice::Auto));
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert!(
            out.get("tool_choice").is_none(),
            "Auto must omit tool_choice (it is Cohere's default)"
        );

        let body = serde_json::json!({
            "model": "command-r",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ir = CohereReader
            .read_request(&body)
            .expect("read_request should succeed");
        assert_eq!(ir.tool_choice, None);
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert!(out.get("tool_choice").is_none());
    }

    // PF-M1: OpenAI/Responses ingress accepts temperature up to 2.0, but Cohere's native range is
    // [0.0, 1.0] and rejects >1 with a hard 400 ValidationException. The writer must clamp.
    #[test]
    fn test_cohere_writer_clamps_temperature_above_one() {
        let mut ir = ir_with_tool_choice(None);
        ir.temperature = Some(1.8);
        let writer = CohereWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("temperature").and_then(|v| v.as_f64()),
            Some(1.0),
            "an OpenAI-ingress temperature of 1.8 must clamp to 1.0 on the Cohere writer; got {out}"
        );
    }
}
