// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The superset intermediate representation (IR) — request and response/stream sides — that every
//! protocol's Reader/Writer maps to and from, so any ingress protocol can reach any backend
//! losslessly. (See `docs/adr/0005-ir-fidelity.md` for the fidelity contract.)

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct IrRequest {
    pub(crate) system: Vec<IrBlock>,
    pub(crate) messages: Vec<IrMessage>,
    pub(crate) tools: Vec<IrTool>,
    pub(crate) max_tokens: Option<u32>,
    // f64 (not ADR-0005's f32): JSON numbers are f64; an f32 round-trip silently mutates a
    // caller's temperature (0.7 → 0.699999988) — the exact lossiness busbar exists to avoid.
    pub(crate) temperature: Option<f64>,
    /// Nucleus-sampling cutoff (`top_p`). A first-class IR field — NOT left in `extra` — because it
    /// is a UNIVERSALLY-modeled sampling control with a clean native shape in every protocol busbar
    /// speaks (OpenAI `top_p`, Anthropic `top_p`, Gemini `generationConfig.topP`, Bedrock
    /// `inferenceConfig.topP`, Cohere `p`). `extra` is cleared on the cross-protocol seam to stop
    /// source-only key leakage; a control that should TRANSLATE must be modeled here or it would be
    /// silently dropped on every cross-protocol hop. `f64` for the same lossless-number reason as
    /// `temperature`. `None` when the caller omitted it. Each reader populates it from its native
    /// shape; each writer emits it in its native shape when present.
    pub(crate) top_p: Option<f64>,
    /// Top-k sampling cutoff (`top_k`). First-class for the same reason as `top_p`: it has a real
    /// cross-protocol mapping in the protocols that model it (Anthropic `top_k`, Gemini
    /// `generationConfig.topK`, Cohere `k`, Bedrock via `additionalModelRequestFields`). OpenAI has
    /// NO top_k knob, so the OpenAI writer omits it (and its reader never sets it) — a lossy-by-target
    /// omission, not a leak. `u32`: top_k is a non-negative integer count. `None` when omitted.
    pub(crate) top_k: Option<u32>,
    /// Repetition penalty by token frequency (`frequency_penalty`). A cross-protocol-preserved
    /// sampling control: written only by protocols that natively model it (OpenAI/Responses/Cohere).
    /// `f64` for the same lossless-number reason as `temperature`. `None` == absent — never emitted.
    pub(crate) frequency_penalty: Option<f64>,
    /// Repetition penalty by token presence (`presence_penalty`). A cross-protocol-preserved
    /// sampling control: written only by protocols that natively model it (OpenAI/Responses/Cohere).
    /// `f64` for the same lossless-number reason as `temperature`. `None` == absent — never emitted.
    pub(crate) presence_penalty: Option<f64>,
    /// Deterministic-sampling seed (`seed`). A cross-protocol-preserved sampling control: written
    /// only by protocols that natively model it (OpenAI/Responses, Gemini, Mistral). `i64` to carry
    /// the full JSON integer range losslessly. `None` == absent — never emitted.
    pub(crate) seed: Option<i64>,
    /// Number of candidate completions to generate (`n`). A cross-protocol-preserved output control:
    /// written only by protocols that natively model it (OpenAI `n`, Gemini `candidateCount`). NOT
    /// Cohere: the v2 `/v2/chat` API has NO `num_generations`/`n` parameter (it was a v1 Generate-API
    /// field, removed in v2 — the documented way to get N candidates is to call chat N times), so the
    /// Cohere reader/writer correctly omit `n` (like Anthropic/Bedrock/Responses). `u32`: a
    /// non-negative count. `None` == absent — never emitted.
    pub(crate) n: Option<u32>,
    /// Structured-output / response-format directive (`response_format`). A cross-protocol-preserved
    /// output control carrying the raw response_format / structured-output object verbatim; mapped
    /// per-protocol later. Written only by protocols that natively model it. `None` == absent —
    /// never emitted.
    pub(crate) response_format: Option<serde_json::Value>,
    /// Stop sequences (`stop`). First-class because every protocol models it (OpenAI `stop` —
    /// string OR array; Anthropic `stop_sequences`; Gemini `generationConfig.stopSequences`; Bedrock
    /// `inferenceConfig.stopSequences`; Cohere `stop_sequences`). Normalized to a `Vec<String>` (the
    /// common shape); a writer whose native form is a bare string for the single-element case still
    /// round-trips because the SDKs accept the array form. Empty `Vec` == omitted (no `stop` field
    /// emitted), so a request that never carried stops does not gain an empty array on translation.
    pub(crate) stop: Vec<String>,
    /// Tool-selection directive (`tool_choice`). First-class — NOT left in `extra` — because it is a
    /// load-bearing, behavior-changing control that EVERY protocol busbar speaks models, just in a
    /// different native shape (OpenAI `tool_choice`, Anthropic `tool_choice`, Gemini
    /// `toolConfig.functionCallingConfig`, Bedrock `toolConfig.toolChoice`, Cohere/Responses
    /// `tool_choice`). `extra` is cleared on the cross-protocol seam, so leaving forced/targeted tool
    /// use in `extra` silently degrades it to the target's default (`auto`) on every cross-protocol
    /// hop — directly undercutting the lossless contract. Each reader normalizes its native shape into
    /// this union; each writer re-emits the union in its native shape when present. `None` when the
    /// caller omitted it (no `tool_choice` emitted, so a request that never carried one does not gain
    /// a spurious `auto` on translation).
    pub(crate) tool_choice: Option<IrToolChoice>,
    pub(crate) stream: bool,
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

/// Normalized cross-protocol tool-selection directive (`tool_choice`). Models the union every wire
/// protocol expresses, so forced/targeted tool use ROUND-TRIPS instead of degrading to `auto`:
///
/// | Variant    | OpenAI / Responses (Cohere)        | Anthropic                    | Gemini (`functionCallingConfig`)            | Bedrock (`toolChoice`) |
/// |------------|------------------------------------|------------------------------|---------------------------------------------|------------------------|
/// | `Auto`     | `"auto"` (Cohere: omit — default)  | `{type:"auto"}`              | `{mode:"AUTO"}`                             | `{auto:{}}`            |
/// | `None`     | `"none"` (Cohere: `"NONE"`)        | `{type:"none"}`*             | `{mode:"NONE"}`                             | (omit — no native)*    |
/// | `Required` | `"required"` (Cohere: `"REQUIRED"`)| `{type:"any"}`              | `{mode:"ANY"}`                             | `{any:{}}`             |
/// | `Tool{n}`  | `{type:"function",function:{name}}`| `{type:"tool",name:n}`      | `{mode:"ANY",allowedFunctionNames:[n]}`    | `{tool:{name:n}}`      |
///
/// *Anthropic gained `{type:"none"}` (2024-10+); older targets without a native "none" fall back to
/// omitting `tool_choice`. A reader maps an unknown/novel native value to `Auto` (the safe default)
/// rather than dropping the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IrToolChoice {
    /// Model decides whether to call a tool. The universal default.
    Auto,
    /// Model must NOT call a tool (text only).
    None,
    /// Model MUST call SOME tool (any of the provided), but the caller does not pin which.
    /// (OpenAI/Cohere/Responses `"required"`, Anthropic `"any"`, Gemini `ANY`, Bedrock `any`.)
    Required,
    /// Model MUST call this SPECIFIC tool by name.
    Tool { name: String },
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
///
/// Empty-string elements are dropped in both arms: an empty stop sequence is meaningless (no protocol
/// matches on it) and would otherwise leave a one-element vec that defeats the "empty `Vec` ==
/// omitted" contract — a degenerate input of `""` or `[""]` collapses to an empty vec (== omitted)
/// rather than emitting a spurious `stop: [""]` on translation.
pub(crate) fn read_stop_sequences(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
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
        /// `id`/`created`/`model`). Default `None`; populated per-protocol by each reader and
        /// synthesized by the writer when the backend supplies none (see the synthesized-ID contract
        /// below).
        ///
        /// Synthesized-ID contract: on a CROSS-PROTOCOL stream the foreign-format identity is stripped
        /// (`StreamTranslate::translate_event` sets ONLY `id` and `created` to `None`) so the ingress
        /// writer mints a NATIVE-format id rather than leaking the backend's `chatcmpl-…`/`msg_…` to a
        /// different-protocol client. `model` is DELIBERATELY PRESERVED: it is the format-neutral lane
        /// model name, and ingress writers use a populated `model` as the anchor for synthesizing the
        /// full native stream-start skeleton — clearing it produced a degenerate Anthropic
        /// `message_start` (missing `id`/`type`/`content`/`stop_reason`/`stop_sequence`) and a Gemini
        /// frame missing `modelVersion` (see the explanation at `proto/mod.rs` `translate_event`). A
        /// same-protocol round-trip is untouched and stays byte-exact.
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
    pub(crate) role: IrRole,
    pub(crate) content: Vec<IrBlock>,
    pub(crate) stop_reason: Option<String>,
    pub(crate) usage: IrUsage,
    /// The model that actually served the response, as reported by the upstream. Preserved across
    /// cross-protocol translation so a pool route's response still names the member that served it
    /// (same as a direct route). `None` if the upstream body carried no model field.
    pub(crate) model: Option<String>,
    /// Response identity, carried through from the egress backend's `read_response` so a writer can
    /// emit the SDK-required identity field a native response carries (OpenAI `id` =
    /// `"chatcmpl-..."`, Anthropic `id` = `"msg_..."`). Default `None`; populated per-protocol by
    /// each reader and synthesized by the writer when the backend supplies none, so the shape stays
    /// SDK-valid (see the synthesized-ID contract below).
    ///
    /// Synthesized-ID contract: on a CROSS-PROTOCOL non-stream response the foreign-format `id` is
    /// stripped (`forward.rs` sets `ir.id = None`) and the ingress writer mints a NATIVE-format id
    /// when `created` is `Some` (the cross-boundary signal) — so e.g. an OpenAI backend's
    /// `chatcmpl-…` id never reaches an Anthropic client. A same-protocol response preserves the
    /// native id verbatim.
    pub(crate) id: Option<String>,
    /// Unix epoch seconds for the response creation time (OpenAI `created`). Default `None`.
    pub(crate) created: Option<u64>,
    /// OpenAI's `system_fingerprint` (opaque backend config marker). Default `None`.
    pub(crate) system_fingerprint: Option<String>,
    /// Anthropic's `stop_sequence` (the matched stop string, or `null`). Default `None`.
    pub(crate) stop_sequence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrMessage {
    pub(crate) role: IrRole,
    pub(crate) content: Vec<IrBlock>,
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
        citations: Vec<IrCitation>,
    },
    Thinking {
        text: String,
        signature: Option<String>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
        /// Anthropic tool-use cache breakpoint (`cache_control`). First-class so an Anthropic cache
        /// breakpoint placed ON a tool_use block survives the seam instead of silently vanishing
        /// (cost/latency regression). Only the Anthropic reader populates it and only the Anthropic
        /// writer emits it; other protocols have no native analog and leave it `None`.
        cache_control: Option<CacheControl>,
    },
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
        /// Anthropic tool-result cache breakpoint (`cache_control`). Same rationale as the
        /// `ToolUse` field — Anthropic places breakpoints on tool_result blocks to cache the
        /// (often large) result content; without an IR field that breakpoint is lost cross-hop.
        cache_control: Option<CacheControl>,
    },
    Image {
        media_type: String,
        data: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CacheControl {
    pub(crate) kind: CacheKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheKind {
    Ephemeral,
}

/// Neutral, cross-protocol citation IR for grounding / web-search CITATIONS carried on a `Text`
/// block (L2). Before this type the field was `Vec<serde_json::Value>` holding RAW Anthropic-shaped
/// citation objects: only Anthropic read/wrote them, Gemini's `citationMetadata` was never read, and
/// every other protocol left the vec empty — so a citation was LOST the moment it crossed a protocol
/// boundary. `IrCitation` captures the UNION of the protocol-native citation shapes so a citation can
/// be projected both ways.
///
/// ANTHROPIC FIDELITY (the load-bearing invariant): an Anthropic citation must round-trip BYTE-EXACT
/// on the same-protocol path. The Anthropic citation schema is a tagged union (`type` discriminator)
/// — `char_location`, `page_location`, `content_block_location`, and the web-search
/// `web_search_result_location` — each with its own field set, and the API may add fields/variants.
/// Rather than risk a lossy field-by-field reconstruction, the Anthropic READER stashes the source
/// object VERBATIM in [`IrCitation::raw`] (alongside the neutral fields it also fills), and the
/// Anthropic WRITER, whenever `raw` is present, re-emits it UNCHANGED. So Anthropic→IR→Anthropic is
/// guaranteed byte-exact regardless of how the neutral fields map. Only on a CROSS-protocol egress
/// (where `raw` is a foreign shape or absent) does the writer synthesize an Anthropic object from the
/// neutral fields — best-effort, never a regression to the same-protocol path.
///
/// Neutral fields are the intersection that travels cross-protocol: a human-readable `kind` tag plus
/// the location/source coordinates both Anthropic and Gemini expose.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrCitation {
    /// Citation-type discriminator. For Anthropic this is the `type` tag verbatim (`char_location`,
    /// `page_location`, `content_block_location`, `web_search_result_location`); for a Gemini
    /// `citationSources[]` entry it is `web_search_result_location` (a grounding source is a URL
    /// reference). `None` only if a source carried no recognizable type.
    pub(crate) kind: Option<String>,
    /// The quoted span of source text the citation refers to (Anthropic `cited_text`). Gemini
    /// `citationSources[]` carry no quoted text, so this is `None` for Gemini-sourced citations.
    pub(crate) cited_text: Option<String>,
    /// Human title of the cited document / web result (Anthropic `document_title` for the document
    /// location variants, `title` for `web_search_result_location`; Gemini has no title field today —
    /// reserved for forward compat).
    pub(crate) title: Option<String>,
    /// Source URL — Anthropic `web_search_result_location.url`, Gemini `citationSources[].uri`.
    pub(crate) url: Option<String>,
    /// Index of the cited document in the request's `documents` array (Anthropic
    /// `document_index`, present on the three document-location variants). Gemini: `None`.
    pub(crate) document_index: Option<i64>,
    /// Inclusive/exclusive start offset, interpreted per `kind`: char index (`char_location`), page
    /// number (`page_location`), or block index (`content_block_location`). For a Gemini
    /// `citationSources[]` this carries `startIndex` (a character offset into the response text).
    pub(crate) start_index: Option<i64>,
    /// End offset, paired with `start_index` per `kind` (end char / end page / end block; Gemini
    /// `endIndex`).
    pub(crate) end_index: Option<i64>,
    /// Anthropic web-search `encrypted_index` — an opaque cursor token. Carried so the web-search
    /// citation variant round-trips even on a cross-protocol synthesize-from-neutral path.
    pub(crate) encrypted_index: Option<String>,
    /// VERBATIM source citation object, for byte-exact same-protocol re-emission. The Anthropic
    /// reader stores the original Anthropic citation here; the Anthropic writer re-emits it unchanged
    /// when present (the no-regression guarantee). The Gemini reader stores the original
    /// `citationSources[]` entry here so a same-protocol Gemini path could re-emit it faithfully.
    /// `None` for a citation synthesized purely from neutral fields.
    pub(crate) raw: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrTool {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) input_schema: Value,
    /// Anthropic tool-definition cache breakpoint (`cache_control`). Anthropic lets a `cache_control`
    /// marker sit on a tool definition to cache the (often large) tool schemas as a prefix; that
    /// breakpoint was being dropped on every hop. First-class so it survives the seam. Only the
    /// Anthropic reader populates it / writer emits it; other protocols leave it `None`.
    pub(crate) cache_control: Option<CacheControl>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrUsage {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_creation_input_tokens: Option<u64>,
    pub(crate) cache_read_input_tokens: Option<u64>,
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
    /// L2-5 STREAMING grounding/web-search citations. ADDITIVE variant (no existing variant changed
    /// — 1.0-freeze-safe): a streamed citation that arrives mid-block is carried as a
    /// [`crate::ir::IrCitation`] (neutral fields + the byte-exact `raw` escape hatch) rather than
    /// dropped. The Anthropic reader maps a `citations_delta` content_block_delta here (one citation
    /// per delta, wrapped in the vec); the Gemini reader maps a late chunk's `citationMetadata`
    /// (which can carry several sources) here. Writers that model streaming citations (Anthropic
    /// `citations_delta`, Gemini `citationMetadata`) re-emit it; protocols with no streaming-citation
    /// shape simply don't emit it (no panic, no corrupt output). Carried inside
    /// `IrStreamEvent::BlockDelta`, attached to the active text block's index.
    CitationsDelta(Vec<IrCitation>),
}

/// Per-request decode state for stateful stream fan-out.
/// Anthropic events are 1:1 and ignore this; OpenAI's flat stream uses it to synthesize the
/// IR's block boundaries (one chunk → 0..n events): whether MessageStart was emitted, whether
/// the text/thinking blocks are open, and which OpenAI tool_call indices have been opened.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamDecodeState {
    pub(crate) started: bool,
    pub(crate) text_block_open: bool,
    /// The IR block index the Gemini reader assigned to the text block, by order of FIRST appearance
    /// (not hardcoded 0). Gemini emits text and `functionCall` parts in any order across chunks; a
    /// block claims the next free index when it first opens, so text and tools never collide on an
    /// index regardless of arrival order (tool-only streams stay contiguous from 0; a tool that opens
    /// before text takes 0 and text takes the next slot). `None` until the text block opens. Gemini
    /// reader only; other readers leave it `None`.
    pub(crate) text_index: Option<usize>,
    pub(crate) open_tools: std::collections::BTreeSet<usize>,
    /// Set once a reasoning (chain-of-thought) delta is seen on the OpenAI stream. When true, the
    /// thinking block occupies IR index 0 and the text/tool block indices shift up by one so the
    /// thinking block precedes the answer (used by the OpenAI reader only).
    pub(crate) reasoning_seen: bool,
    /// Whether the reasoning Thinking block (index 0) is currently open.
    pub(crate) thinking_block_open: bool,
    /// Stop reason buffered across two Bedrock stream frames. Native Bedrock ConverseStream splits
    /// the stop reason (`messageStop` frame) from the token usage (a following `metadata` frame). To
    /// emit ONE combined `MessageDelta{stop_reason, usage}` (so a cross-protocol ingress sees the
    /// single `message_delta`/usage event a native non-Bedrock stream carries, not two) the Bedrock
    /// reader stashes the `messageStop` stop_reason here and pairs it with the usage when `metadata`
    /// arrives. Used by the Bedrock reader only; other protocols leave it `None`.
    pub(crate) pending_stop_reason: Option<String>,
    /// OpenAI-only: maps each opened OpenAI tool_call `index` (the `oai_idx`) to the IR block index
    /// its `BlockStart` was emitted with. The OpenAI flat stream lets text arrive AFTER tool calls,
    /// and the text block's presence shifts the tool index base — so the IR index a tool's BlockStart
    /// claimed at OPEN time can diverge from a value RECOMPUTED at finish/close time (where text is
    /// now `Some`). Recording the emitted IR index here and replaying it verbatim at close guarantees
    /// every tool `BlockStop` pairs with the SAME index as its `BlockStart`, regardless of later text
    /// arrival. Empty for every other reader (which assign IR indices 1:1 or via `open_tools`/
    /// `text_index` directly and never recompute a divergent base). Keyed by `oai_idx` so it tracks
    /// `open_tools` one-for-one.
    pub(crate) tool_ir_index: std::collections::BTreeMap<usize, usize>,
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
        assert!(st.text_index.is_none());
        assert!(st.open_tools.is_empty());
        assert!(!st.reasoning_seen);
        assert!(!st.thinking_block_open);
        assert!(st.pending_stop_reason.is_none());
        assert!(st.tool_ir_index.is_empty());
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
    fn test_read_stop_sequences_drops_empty_strings() {
        // "Empty Vec == omitted" contract: a degenerate input that carries only empty stop
        // sequences must collapse to an empty Vec, not a one-element vec holding "", so it never
        // emits a spurious `stop: [""]` on cross-protocol translation.
        let bare_empty = Value::String(String::new());
        assert!(
            read_stop_sequences(Some(&bare_empty)).is_empty(),
            "bare empty string should collapse to empty Vec (== omitted)"
        );

        let arr_empty = Value::Array(vec![Value::String(String::new())]);
        assert!(
            read_stop_sequences(Some(&arr_empty)).is_empty(),
            "[\"\"] should collapse to empty Vec (== omitted)"
        );

        // Empty elements are dropped from a mixed array while real stops survive in order.
        let mixed = Value::Array(vec![
            Value::String("STOP".into()),
            Value::String(String::new()),
            Value::Null,
            Value::String("END".into()),
        ]);
        assert_eq!(
            read_stop_sequences(Some(&mixed)),
            vec!["STOP".to_string(), "END".to_string()],
            "empty/non-string elements dropped; real stops kept in order"
        );

        // Non-empty inputs are unaffected.
        let bare = Value::String("HALT".into());
        assert_eq!(read_stop_sequences(Some(&bare)), vec!["HALT".to_string()]);
        assert!(read_stop_sequences(None).is_empty());
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

    // PF-L5: `IrToolChoice` is the protocol-neutral pivot for every reader/writer's tool_choice
    // mapping, so its variant identity must be precise — distinct variants are never equal, a
    // targeted `Tool` is keyed on its name, and clone preserves the variant.
    #[test]
    fn test_ir_tool_choice_variant_equality() {
        // Distinct directives are never conflated.
        assert_ne!(IrToolChoice::Auto, IrToolChoice::None);
        assert_ne!(IrToolChoice::Auto, IrToolChoice::Required);
        assert_ne!(IrToolChoice::None, IrToolChoice::Required);
        assert_ne!(
            IrToolChoice::Required,
            IrToolChoice::Tool { name: "f".into() }
        );
        // A targeted tool is keyed on its name.
        assert_eq!(
            IrToolChoice::Tool {
                name: "get_weather".into()
            },
            IrToolChoice::Tool {
                name: "get_weather".into()
            }
        );
        assert_ne!(
            IrToolChoice::Tool { name: "a".into() },
            IrToolChoice::Tool { name: "b".into() }
        );
        // Clone is a faithful round-trip of the variant.
        let tc = IrToolChoice::Tool { name: "x".into() };
        assert_eq!(tc.clone(), tc);
    }
}
