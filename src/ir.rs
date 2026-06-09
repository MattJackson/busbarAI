// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The superset intermediate representation (IR) — request and response/stream sides — that every
//! protocol's Reader/Writer maps to and from, so any ingress protocol can reach any backend
//! losslessly. (See `docs/adr/0005-ir-fidelity.md` for the fidelity contract.)

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrRequest {
    pub system: Vec<IrBlock>,
    pub messages: Vec<IrMessage>,
    pub tools: Vec<IrTool>,
    pub max_tokens: Option<u32>,
    // f64 (not ADR-0005's f32): JSON numbers are f64; an f32 round-trip silently mutates a
    // caller's temperature (0.7 → 0.699999988) — the exact lossiness busbar exists to avoid.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff (`top_p`). A first-class IR field — NOT left in `extra` — because it
    /// is a UNIVERSALLY-modeled sampling control with a clean native shape in every protocol busbar
    /// speaks (OpenAI `top_p`, Anthropic `top_p`, Gemini `generationConfig.topP`, Bedrock
    /// `inferenceConfig.topP`, Cohere `p`). `extra` is cleared on the cross-protocol seam to stop
    /// source-only key leakage; a control that should TRANSLATE must be modeled here or it would be
    /// silently dropped on every cross-protocol hop. `f64` for the same lossless-number reason as
    /// `temperature`. `None` when the caller omitted it. Each reader populates it from its native
    /// shape; each writer emits it in its native shape when present.
    pub top_p: Option<f64>,
    /// Top-k sampling cutoff (`top_k`). First-class for the same reason as `top_p`: it has a real
    /// cross-protocol mapping in the protocols that model it (Anthropic `top_k`, Gemini
    /// `generationConfig.topK`, Cohere `k`, Bedrock via `additionalModelRequestFields`). OpenAI has
    /// NO top_k knob, so the OpenAI writer omits it (and its reader never sets it) — a lossy-by-target
    /// omission, not a leak. `u32`: top_k is a non-negative integer count. `None` when omitted.
    pub top_k: Option<u32>,
    /// Stop sequences (`stop`). First-class because every protocol models it (OpenAI `stop` —
    /// string OR array; Anthropic `stop_sequences`; Gemini `generationConfig.stopSequences`; Bedrock
    /// `inferenceConfig.stopSequences`; Cohere `stop_sequences`). Normalized to a `Vec<String>` (the
    /// common shape); a writer whose native form is a bare string for the single-element case still
    /// round-trips because the SDKs accept the array form. Empty `Vec` == omitted (no `stop` field
    /// emitted), so a request that never carried stops does not gain an empty array on translation.
    pub stop: Vec<String>,
    pub stream: bool,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Normalize a protocol's native stop-sequence field into the IR's `Vec<String>`.
///
/// Stop sequences arrive in two native shapes across busbar's protocols: a bare string (OpenAI's
/// `stop` accepts a single string) or an array of strings (Anthropic `stop_sequences`, Gemini
/// `stopSequences`, Bedrock `stopSequences`, Cohere `stop_sequences`, and OpenAI's array form). This
/// collapses both into the IR's normalized `Vec<String>`: a string becomes a one-element vec, an
/// array keeps its string elements (non-string elements are skipped — a malformed entry should not
/// abort the whole request), and absent/`null`/any other type yields an empty vec (== omitted). Used
/// by every reader so the cross-protocol seam carries stops uniformly.
pub(crate) fn read_stop_sequences(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IrStreamEvent {
    MessageStart {
        role: IrRole,
        usage: Option<IrUsage>,
        /// Stream identity, carried through from the egress backend's stream-start metadata so a
        /// writer can emit the SDK-required top-level identity fields a native stream carries
        /// (Anthropic `message_start.message.id`; OpenAI `chat.completion.chunk` top-level
        /// `id`/`created`/`model`). Default `None`; populated per-protocol in a later wave (and
        /// synthesized when the backend supplies none).
        ///
        /// Synthesized-ID contract: on a CROSS-PROTOCOL stream the foreign-format identity is stripped
        /// (`StreamTranslate::translate_event` sets `id`/`created`/`model` to `None`) so the ingress
        /// writer mints a NATIVE-format id rather than leaking the backend's `chatcmpl-…`/`msg_…` to a
        /// different-protocol client. A same-protocol round-trip is untouched and stays byte-exact.
        id: Option<String>,
        /// Unix epoch seconds for the stream's creation time (OpenAI chunk top-level `created`).
        created: Option<u64>,
        /// The model that served the stream (OpenAI chunk top-level `model`; Anthropic
        /// `message_start.message.model`). Mirrors `IrResponse::model`.
        model: Option<String>,
    },
    BlockStart {
        index: usize,
        block: IrBlockMeta,
    },
    BlockDelta {
        index: usize,
        delta: IrDelta,
    },
    BlockStop {
        index: usize,
    },
    MessageDelta {
        stop_reason: Option<String>,
        /// Anthropic's streaming `message_delta.delta.stop_sequence` — the matched stop string, or
        /// `None` when no stop sequence matched (or the source protocol has no analog). Only the
        /// Anthropic reader populates it and only the Anthropic writer emits it (and only when the
        /// source carried it), so a same-protocol Anthropic passthrough stays byte-faithful while
        /// other protocols' output is unchanged.
        stop_sequence: Option<String>,
        usage: IrUsage,
    },
    MessageStop,
    Error(crate::proto::IrError),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrResponse {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
    pub stop_reason: Option<String>,
    pub usage: IrUsage,
    /// The model that actually served the response, as reported by the upstream. Preserved across
    /// cross-protocol translation so a pool route's response still names the member that served it
    /// (same as a direct route). `None` if the upstream body carried no model field.
    pub model: Option<String>,
    /// Response identity, carried through from the egress backend's `read_response` so a writer can
    /// emit the SDK-required identity field a native response carries (OpenAI `id` =
    /// `"chatcmpl-..."`, Anthropic `id` = `"msg_..."`). Default `None`; populated per-protocol in a
    /// later wave (and synthesized when the backend supplies none, so the shape stays SDK-valid).
    ///
    /// Synthesized-ID contract: on a CROSS-PROTOCOL non-stream response the foreign-format `id` is
    /// stripped (`forward.rs` sets `ir.id = None`) and the ingress writer mints a NATIVE-format id
    /// when `created` is `Some` (the cross-boundary signal) — so e.g. an OpenAI backend's
    /// `chatcmpl-…` id never reaches an Anthropic client. A same-protocol response preserves the
    /// native id verbatim.
    pub id: Option<String>,
    /// Unix epoch seconds for the response creation time (OpenAI `created`). Default `None`.
    pub created: Option<u64>,
    /// OpenAI's `system_fingerprint` (opaque backend config marker). Default `None`.
    pub system_fingerprint: Option<String>,
    /// Anthropic's `stop_sequence` (the matched stop string, or `null`). Default `None`.
    pub stop_sequence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IrBlock {
    Text {
        text: String,
        cache_control: Option<CacheControl>,
        citations: Vec<Value>,
    },
    Thinking {
        text: String,
        signature: Option<String>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
    },
    Image {
        media_type: String,
        data: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CacheControl {
    pub kind: CacheKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheKind {
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IrBlockMeta {
    Text,
    Thinking,
    ToolUse { id: String, name: String },
    Image,
}

#[derive(Debug, Clone, PartialEq)]
// Every variant is live on the production egress path: `read_response_events` emits `IrDelta`s
// inside `IrStreamEvent::BlockDelta`, and `StreamTranslate::feed` → `write_response_event` consumes
// them (see proto/{bedrock,gemini,cohere}.rs). The `enum_variant_names` allow stays because all
// variants share the `Delta` suffix by design (they mirror the wire delta-event names).
#[allow(clippy::enum_variant_names)]
pub(crate) enum IrDelta {
    TextDelta(String),
    ThinkingDelta(String),
    InputJsonDelta(String),
    SignatureDelta(String),
}

/// Per-request decode state for stateful stream fan-out.
/// Anthropic events are 1:1 and ignore this; OpenAI's flat stream uses it to synthesize the
/// IR's block boundaries (one chunk → 0..n events): whether MessageStart was emitted, whether
/// the text/thinking blocks are open, and which OpenAI tool_call indices have been opened.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamDecodeState {
    pub started: bool,
    pub text_block_open: bool,
    pub open_tools: std::collections::BTreeSet<usize>,
    /// Set once a reasoning (chain-of-thought) delta is seen on the OpenAI stream. When true, the
    /// thinking block occupies IR index 0 and the text/tool block indices shift up by one so the
    /// thinking block precedes the answer (used by the OpenAI reader only).
    pub reasoning_seen: bool,
    /// Whether the reasoning Thinking block (index 0) is currently open.
    pub thinking_block_open: bool,
    /// Stop reason buffered across two Bedrock stream frames. Native Bedrock ConverseStream splits
    /// the stop reason (`messageStop` frame) from the token usage (a following `metadata` frame). To
    /// emit ONE combined `MessageDelta{stop_reason, usage}` (so a cross-protocol ingress sees the
    /// single `message_delta`/usage event a native non-Bedrock stream carries, not two) the Bedrock
    /// reader stashes the `messageStop` stop_reason here and pairs it with the usage when `metadata`
    /// arrives. Used by the Bedrock reader only; other protocols leave it `None`.
    pub pending_stop_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_usage_default_is_zero() {
        // IrUsage has no derived Default; construct the documented zero baseline explicitly and
        // assert the token fields read as zero / None, so a future field addition is caught here.
        let u = IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.output_tokens, 0);
        assert_eq!(u.cache_creation_input_tokens, None);
        assert_eq!(u.cache_read_input_tokens, None);
    }

    #[test]
    fn test_stream_decode_state_default() {
        // The OpenAI flat-stream synthesizer relies on these initial values: nothing started, no
        // blocks open, no tool indices, no reasoning yet.
        let st = StreamDecodeState::default();
        assert!(!st.started);
        assert!(!st.text_block_open);
        assert!(st.open_tools.is_empty());
        assert!(!st.reasoning_seen);
        assert!(!st.thinking_block_open);
        assert!(st.pending_stop_reason.is_none());
    }

    #[test]
    fn test_ir_role_partial_eq_distinguishes_variants() {
        // PartialEq/Eq must treat all four roles as distinct (role confusion would mis-map
        // system/user/assistant/tool turns across protocols).
        let all = [
            IrRole::System,
            IrRole::User,
            IrRole::Assistant,
            IrRole::Tool,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(a == b, i == j, "role eq mismatch at ({i},{j})");
            }
        }
    }

    #[test]
    fn test_ir_delta_variants_distinct() {
        // Two different delta variants carrying the same string are NOT equal — the variant carries
        // semantic meaning (text vs thinking vs tool-input-json vs signature) on the egress path.
        assert_ne!(
            IrDelta::TextDelta("x".into()),
            IrDelta::ThinkingDelta("x".into())
        );
        assert_ne!(
            IrDelta::InputJsonDelta("x".into()),
            IrDelta::SignatureDelta("x".into())
        );
        assert_eq!(
            IrDelta::TextDelta("x".into()),
            IrDelta::TextDelta("x".into())
        );
    }
}
