// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gemini protocol reader/writer implementation.

use super::openai_family::{
    ERR_TYPE_AUTHENTICATION, ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT,
};
use super::*;

/// Router-internal shim key the gemini ingress route injects into the request body when the client
/// sent a streaming `:streamGenerateContent` request WITHOUT `?alt=sse` (so the response must be the
/// JSON-array streaming format, not SSE). It rides alongside the `model`/`stream` shims. Single
/// source of truth shared by the route injection (`ingress`), the forward-layer strip
/// (`proxy::strip_router_shim_keys`), and the Gemini reader's `modeled_keys` exclusion so it never
/// reaches a backend on any path. A leading `__busbar` makes a collision with a real provider field
/// impossible. Defined here and referenced at this owning path, so the route/forward sites reach it
/// via `crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY`.
pub(crate) const GEMINI_JSON_ARRAY_SHIM_KEY: &str = "__busbar_gemini_json_array";

/// The canonical Gemini bad-API-key message text (`google.rpc.Status.message` a real Generative
/// Language API 400/INVALID_ARGUMENT carries on an invalid key). Single-sourced here: the auth-failure
/// path returns it via `GeminiWriter::auth_failure_message`, and `write_error` matches on it to gate
/// the `details[].reason == "API_KEY_INVALID"` ErrorInfo array onto exactly that bad-key 400.
pub(crate) const GEMINI_BAD_KEY_MESSAGE: &str = "API key not valid. Please pass a valid API key.";

/// Hard cap on the number of distinct tool-call block indices recorded in `state.open_tools` for a
/// single Gemini SSE stream. The set is only drained when a `finishReason` chunk arrives (the
/// terminal frame closes every open tool block), so a hostile or buggy upstream that streams an
/// unbounded run of `functionCall` parts WITHOUT ever emitting `finishReason` would grow it without
/// bound — one inserted index per part — until the process is OOM-killed. No legitimate Gemini
/// response approaches this many parallel tool calls in a single turn; past the cap we stop both
/// recording new tool frames and emitting their BlockStart/BlockDelta events, so per-request heap
/// stays bounded. The cap leaves every realistic stream untouched. Mirrors the Cohere reader's
/// `MAX_TRACKED_TOOL_FRAMES`.
const MAX_GEMINI_TOOL_FRAMES: usize = 4096;

// ── finishReason value tokens ─────────────────────────────────────────────────
/// Gemini `FinishReason.STOP` — normal/tool-call end.
const GEMINI_FINISH_STOP: &str = "STOP";
/// Gemini `FinishReason.MAX_TOKENS` — output truncated by token cap.
const GEMINI_FINISH_MAX_TOKENS: &str = "MAX_TOKENS";
/// Gemini `FinishReason.SAFETY` — content-safety stop.
const GEMINI_FINISH_SAFETY: &str = "SAFETY";
/// Gemini `FinishReason.OTHER` — unenumerated stop reason.
const GEMINI_FINISH_OTHER: &str = "OTHER";
/// Gemini `FinishReason.MALFORMED_FUNCTION_CALL` — model produced an unparseable tool call.
const GEMINI_FINISH_MALFORMED_FUNCTION_CALL: &str = "MALFORMED_FUNCTION_CALL";
/// Gemini `FinishReason.RECITATION` — verbatim recitation stop (maps to `safety` in the IR).
const GEMINI_FINISH_RECITATION: &str = "RECITATION";
/// Gemini `FinishReason.PROHIBITED_CONTENT` — content-policy block (maps to `safety`).
const GEMINI_FINISH_PROHIBITED_CONTENT: &str = "PROHIBITED_CONTENT";

/// Upstream URL path prefix shared by all Gemini Generative Language API endpoints. The
/// per-request path appends `/{model}:{method}` (and optionally `?alt=sse`) via
/// `upstream_path_for` / `upstream_path_for_stream`. Single source of truth for the four
/// sites that previously hard-coded the string literal.
const GEMINI_PATH_BASE: &str = "/v1beta/models";

// ── usageMetadata field names ─────────────────────────────────────────────────
/// JSON key for Gemini's top-level usage wrapper (`usageMetadata`).
const FIELD_USAGE_METADATA: &str = "usageMetadata";
/// JSON key for the prompt (input) token count inside `usageMetadata`.
const FIELD_PROMPT_TOKEN_COUNT: &str = "promptTokenCount";
/// JSON key for the candidates (output) token count inside `usageMetadata`.
const FIELD_CANDIDATES_TOKEN_COUNT: &str = "candidatesTokenCount";
/// JSON key for the total token count inside `usageMetadata`.
const FIELD_TOTAL_TOKEN_COUNT: &str = "totalTokenCount";
/// JSON key for the context-cache token count inside `usageMetadata`.
const FIELD_CACHED_CONTENT_TOKEN_COUNT: &str = "cachedContentTokenCount";

// ── response identity field names ─────────────────────────────────────────────
/// JSON key for the opaque response identifier emitted at the top level.
const FIELD_RESPONSE_ID: &str = "responseId";
/// JSON key for the serving model name emitted at the top level.
const FIELD_MODEL_VERSION: &str = "modelVersion";

// ── gRPC / google.rpc.Code status name tokens ────────────────────────────────
/// google.rpc.Code name for a malformed/bad-argument request.
const GRPC_INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
/// google.rpc.Code name for a quota/rate-limit failure.
const GRPC_RESOURCE_EXHAUSTED: &str = "RESOURCE_EXHAUSTED";
/// google.rpc.Code name for a service-overload / temporarily unavailable failure.
const GRPC_UNAVAILABLE: &str = "UNAVAILABLE";
/// google.rpc.Code name for a missing or invalid credential.
const GRPC_UNAUTHENTICATED: &str = "UNAUTHENTICATED";
/// google.rpc.Code name for a permission / billing failure.
const GRPC_PERMISSION_DENIED: &str = "PERMISSION_DENIED";
/// google.rpc.Code name for an internal server error.
const GRPC_INTERNAL: &str = "INTERNAL";
/// google.rpc.Code name for a deadline / timeout failure.
const GRPC_DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
/// google.rpc.Code name for a resource not found.
const GRPC_NOT_FOUND: &str = "NOT_FOUND";
/// google.rpc.Code name for an unimplemented / not-supported operation.
const GRPC_UNIMPLEMENTED: &str = "UNIMPLEMENTED";
/// Busbar/Anthropic internal error kind for an overloaded upstream (maps to GRPC_UNAVAILABLE).
const ERR_TYPE_OVERLOADED: &str = super::openai_family::ERR_TYPE_OVERLOADED;

// ── ErrorInfo tokens ──────────────────────────────────────────────────────────
/// The machine-readable `reason` value carried in `google.rpc.ErrorInfo` for an invalid API key.
const GEMINI_ERROR_REASON_API_KEY_INVALID: &str = "API_KEY_INVALID";
/// The protobuf type URL for `google.rpc.ErrorInfo` (carried in `details[].@type`).
const GEMINI_ERROR_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.ErrorInfo";

// ── structured-output + generation field keys ─────────────────────────────────
/// JSON key for the MIME type of the response format inside `generationConfig`.
const FIELD_RESPONSE_MIME_TYPE: &str = "responseMimeType";
/// MIME type value for JSON structured output.
const MIME_APPLICATION_JSON: &str = "application/json";
/// JSON key for a `functionCall` content part.
const FIELD_FUNCTION_CALL: &str = "functionCall";
/// JSON key for the finish reason on a candidate.
const FIELD_FINISH_REASON: &str = "finishReason";

/// The set of top-level Gemini request keys the reader models into typed `IrRequest` fields (any
/// OTHER key is swept verbatim into `extra` for round-trip fidelity). This set is a compile-time
/// constant, so it is built ONCE into a process-global `OnceLock` and shared by every
/// `read_request` call instead of being re-allocated and re-hashed per request on the ingress hot
/// path. Every member is a `&'static str`, so the cached set borrows nothing request-scoped.
fn modeled_request_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        // NB: `generationConfig` is deliberately ABSENT. The reader promotes 5 of its sub-fields
        // (`maxOutputTokens`/`temperature`/`topP`/`topK`/`stopSequences`) into typed IR fields, but
        // a native Gemini client may also send unmodeled sub-fields (`responseMimeType` for JSON
        // mode, `thinkingConfig` for extended thinking, `candidateCount`, `seed`,
        // `presence/frequencyPenalty`, `responseModalities`, `speechConfig`, …). Were
        // `generationConfig` modeled-out of `extra`, the writer — which rebuilds it from only the 5
        // typed fields — would SILENTLY DROP every unmodeled sub-field on cross-protocol ingress.
        // Keeping the raw `generationConfig` object in `extra` lets the writer OVERLAY the 5 typed
        // fields onto the original object (the same pattern `BedrockWriter` uses for
        // `inferenceConfig`), preserving unknown sub-fields. Same-protocol Gemini→Gemini is
        // unaffected (byte-identical), and the cross-protocol seam (`proxy engine ir.extra.clear()`)
        // still prevents foreign Gemini sub-fields from leaking onto a non-Gemini backend.
        [
            "contents",
            "tools",
            "systemInstruction",
            "model",
            crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY,
        ]
        .into_iter()
        .collect()
    })
}

#[derive(Clone)]
pub(crate) struct GeminiReader;

/// Lowercase+uppercase+digit base62 alphabet — the mixed-case alphanumeric character class a native
/// Gemini `responseId` draws from (e.g. `PXmFaPzVMI…`). Carries no `-`/`_`, so no separator or
/// hyphen leaks the synthetic boundary the old `{:x}-{:x}` form exposed.
/// Base62 alphabet for the synthesized `responseId` — the shared single-source-of-truth atom (see
/// `crate::proto::BASE62_ALPHABET`), aliased locally so the generator below reads naturally.
const RESPONSE_ID_ALPHABET: &[u8; 62] = crate::proto::BASE62_ALPHABET;

/// Width of a synthesized Gemini `responseId`. Native Gemini bodies/streams carry a short opaque
/// base64url-style token (~11–16 chars) with NO positional structure; 16 base62 chars stays in that
/// length/entropy profile so a client that length-checks or regex-validates `responseId` cannot
/// fingerprint it as non-native.
const RESPONSE_ID_TOKEN_LEN: usize = 16;

/// Rejection-sampling threshold for the base62 reduction in `synth_response_id`: the largest multiple
/// of 62 that fits in a `u8` is `4 * 62 = 248`. Any random byte `>= 248` is in the partial final
/// block (`248..=255` → residues `0..=7`) that would otherwise be over-represented by a bare
/// `byte % 62`, so we reject and resample those to keep the symbol distribution uniform.
const RESPONSE_ID_REJECT_THRESHOLD: u8 = crate::proto::BASE62_REJECT_THRESHOLD;

/// Mint a Gemini-shaped `responseId` for the cross-protocol path where the backend supplied none.
///
/// A native Gemini `responseId` is an opaque, mixed-case alphanumeric base64url-style token with NO
/// embedded structure (no hyphen, no lowercase-hex-only restriction, no embedded timestamp). The
/// previous `format!("{:x}-{:x}", unix_now_secs(), seq)` form was structurally distinguishable on two
/// counts: (a) the `-` separator plus `[0-9a-f]`-only character class is a shape no native id has,
/// and (b) the leading hex segment leaked the proxy host's wall-clock second to anyone holding a
/// response id. This mints an opaque CSPRNG-backed base62 token of native length instead: the WHOLE
/// token is filled from `getrandom` with NO counter overlay. A counter overlaid into any fixed
/// region of the token leaves those characters predictable/low-entropy (the counter stays small, so
/// its high base62 digits are constant '0') — a structural tell at whatever position it occupies. A
/// 16-char base62 token is ~95 bits of entropy, collision-free in practice for a per-process id
/// stream, so no counter backstop is needed and every position stays fully random like a native id.
/// No embedded clock, no separator, no new dependency. Never panics on the request path: on entropy
/// failure the buffer stays the base62 zero char.
///
/// The byte→base62 reduction uses REJECTION SAMPLING, not a bare `byte % 62`. `256 % 62 != 0`, so a
/// plain modulo over a uniform `u8` is biased: residues `0..=7` (reachable by the 8 extra byte values
/// `248..=255`) occur slightly more often than `8..=61`. We instead reject any byte `>=
/// RESPONSE_ID_REJECT_THRESHOLD` (the largest multiple of 62 that fits in a `u8`, i.e. `4*62 = 248`)
/// and resample, so every surviving byte maps uniformly across the 62 symbols. Rejected bytes are
/// simply skipped and more random bytes are drawn as needed.
fn synth_response_id() -> String {
    let mut token = [b'0'; RESPONSE_ID_TOKEN_LEN];
    let mut filled = 0usize;
    // Bound the number of refill rounds so a stuck/zero entropy source can never spin forever on the
    // request path; ~4/256 of bytes are rejected, so a handful of rounds covers the token with margin
    // and the `'0'`-prefilled buffer is the panic-free fallback if entropy never arrives.
    let mut rounds = 0u32;
    const MAX_ROUNDS: u32 = 8;
    while filled < RESPONSE_ID_TOKEN_LEN && rounds < MAX_ROUNDS {
        rounds += 1;
        // Draw a generous batch so a single getrandom call typically fills the whole token even after
        // rejections (RESPONSE_ID_TOKEN_LEN*2 bytes leave ample headroom for the ~1.6% reject rate).
        let mut batch = [0u8; RESPONSE_ID_TOKEN_LEN * 2];
        if getrandom::fill(&mut batch).is_err() {
            break;
        }
        for &byte in batch.iter() {
            if filled >= RESPONSE_ID_TOKEN_LEN {
                break;
            }
            if byte >= RESPONSE_ID_REJECT_THRESHOLD {
                // Biased residue region — reject and resample rather than fold it in.
                continue;
            }
            token[filled] = RESPONSE_ID_ALPHABET[(byte % 62) as usize];
            filled += 1;
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards an
    // impossible non-ASCII byte and keeps the path panic-free (no unwrap/expect on the request path).
    String::from_utf8(token.to_vec()).unwrap_or_else(|_| "0".repeat(RESPONSE_ID_TOKEN_LEN))
}

/// Synthesize a stable, non-empty tool-call id for a Gemini `functionCall`.
///
/// The Gemini wire format carries no tool-call id on `functionCall` parts, so reading them with
/// `id: String::new()` (the old behavior) produced an empty `tool_use_id`/`id` on cross-protocol
/// egress (Anthropic / OpenAI), both of which REQUIRE a non-empty id to correlate the later
/// `tool_result`/`tool` message. With an empty id, two tool calls sharing a function name could not
/// be told apart and `tool_result` routing broke.
///
/// We derive a deterministic id from `(call_index, function_name)` via the stdlib
/// `std::collections::hash_map::DefaultHasher` (SipHash-1-3; no new dependency). Determinism within a
/// run is all we need here — `DefaultHasher::new()` seeds from fixed constants (it is NOT the
/// per-process randomized `RandomState` used by `HashMap`), so the same `(index, name)` always hashes
/// to the same id. The id only needs to be stable WITHIN a single request so the
/// synthesized `tool_result` (which the reader keys by function name — Gemini's only correlation
/// handle) and the `tool_use` agree; including the call index disambiguates repeated function
/// names. The `call_` prefix keeps it visibly synthetic and matches no native id shape we must
/// preserve. An empty `name` still yields a non-empty id (the index disambiguates).
fn synth_tool_call_id(call_index: usize, function_name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    call_index.hash(&mut hasher);
    function_name.hash(&mut hasher);
    format!("call_{:016x}", hasher.finish())
}

/// Gemini's `logprobsResult` — two PARALLEL arrays, `chosenCandidates[i]` (the generated token at
/// position i) and `topCandidates[i].candidates[]` (the alternatives at that position) — zipped
/// into the neutral IR entries. Gemini carries no byte arrays (`bytes: None`; an OpenAI writer
/// synthesizes them from UTF-8).
fn read_gemini_logprobs(v: Option<&serde_json::Value>) -> Vec<crate::ir::IrTokenLogprob> {
    let chosen = match v
        .and_then(|lr| lr.get("chosenCandidates"))
        .and_then(|c| c.as_array())
    {
        Some(c) => c,
        None => return Vec::new(),
    };
    let tops = v
        .and_then(|lr| lr.get("topCandidates"))
        .and_then(|c| c.as_array());
    chosen
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            Some(crate::ir::IrTokenLogprob {
                token: c.get("token")?.as_str()?.to_string(),
                logprob: c.get("logProbability")?.as_f64()?,
                bytes: None,
                top: tops
                    .and_then(|t| t.get(i))
                    .and_then(|t| t.get("candidates"))
                    .and_then(|c| c.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| {
                                Some(crate::ir::IrTopLogprob {
                                    token: t.get("token")?.as_str()?.to_string(),
                                    logprob: t.get("logProbability")?.as_f64()?,
                                    bytes: None,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Neutral IR logprobs → Gemini's `logprobsResult` (chosen + top parallel arrays). `topCandidates`
/// is emitted only when at least one position carries alternatives, matching Gemini's own omission
/// of the array when `logprobs` (the top-count) was not requested.
fn write_gemini_logprobs_result(lps: &[crate::ir::IrTokenLogprob]) -> serde_json::Value {
    let chosen: Vec<serde_json::Value> = lps
        .iter()
        .map(|lp| serde_json::json!({"token": lp.token, "logProbability": lp.logprob}))
        .collect();
    let mut obj = serde_json::json!({ "chosenCandidates": chosen });
    if lps.iter().any(|lp| !lp.top.is_empty()) {
        let tops: Vec<serde_json::Value> = lps
            .iter()
            .map(|lp| {
                serde_json::json!({
                    "candidates": lp
                        .top
                        .iter()
                        .map(|t| serde_json::json!({"token": t.token, "logProbability": t.logprob}))
                        .collect::<Vec<serde_json::Value>>()
                })
            })
            .collect();
        obj["topCandidates"] = serde_json::json!(tops);
    }
    obj
}

/// Normalize Gemini's native `toolConfig.functionCallingConfig` into the IR `tool_choice` union
/// (PF-H1).
///
/// Mapping: `AUTO` → `Auto`; `NONE` → `None`; `ANY` with no `allowedFunctionNames` → `Required`
/// (must call some tool); `ANY` + `allowedFunctionNames:[X, …]` → the targeted `Tool{name:X}` (the
/// IR models a single targeted tool, so the FIRST allowed name is used). An absent `toolConfig`,
/// absent `functionCallingConfig`/`mode`, or an unrecognized mode yields `None` (the `Option`) so a
/// request that never carried a directive does not gain a spurious one on translation. Takes the
/// whole `toolConfig` object so the caller can pass `obj.get("toolConfig")` directly.
fn read_gemini_tool_choice(
    tool_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrToolChoice> {
    let fcc = tool_config?.get("functionCallingConfig")?;
    let mode = fcc.get("mode").and_then(|m| m.as_str())?;
    match mode.to_uppercase().as_str() {
        "AUTO" => Some(crate::ir::IrToolChoice::Auto),
        "NONE" => Some(crate::ir::IrToolChoice::None),
        "ANY" => {
            // `allowedFunctionNames` is a LIST in Gemini, but the IR's `Tool` variant models a
            // SINGLE targeted tool. The IR cannot express "call one of this SUBSET". A single name
            // maps cleanly to `Tool{name}`. With N>1 names, fabricating `Tool{name: first}` would
            // INVENT a stricter constraint (force exactly one specific tool) the request never made;
            // instead degrade to `Required` (call SOME tool) — a true superset of the allow-list —
            // and warn that the subset restriction is lost on this (cross-protocol) hop.
            let names = fcc.get("allowedFunctionNames").and_then(|a| a.as_array());
            match names {
                Some(arr) if arr.len() > 1 => {
                    tracing::warn!(
                        allowed_count = arr.len(),
                        "gemini allowedFunctionNames subset restriction is not representable in the \
                         IR; relaxing to Required (call some tool)"
                    );
                    Some(crate::ir::IrToolChoice::Required)
                }
                _ => match names.and_then(|a| a.first()).and_then(|n| n.as_str()) {
                    Some(name) => Some(crate::ir::IrToolChoice::Tool {
                        name: name.to_string(),
                    }),
                    None => Some(crate::ir::IrToolChoice::Required),
                },
            }
        }
        _ => None,
    }
}

/// Emit the IR `tool_choice` union as a Gemini `functionCallingConfig` object (PF-H1).
fn write_gemini_tool_choice(tc: &crate::ir::IrToolChoice) -> serde_json::Value {
    match tc {
        crate::ir::IrToolChoice::Auto => serde_json::json!({"mode": "AUTO"}),
        crate::ir::IrToolChoice::None => serde_json::json!({"mode": "NONE"}),
        crate::ir::IrToolChoice::Required => serde_json::json!({"mode": "ANY"}),
        crate::ir::IrToolChoice::Tool { name } => {
            serde_json::json!({"mode": "ANY", "allowedFunctionNames": [name]})
        }
    }
}

/// Default a possibly-absent Gemini `functionCall.args` to an empty JSON OBJECT (`{}`), not `null`.
///
/// A zero-argument Gemini `functionCall` either OMITS the `args` field or sends an empty object.
/// The args field models a tool-call argument MAP, so the correct empty value is `{}` — serializing
/// `null` instead leaked `"input": null` / `"arguments": "null"` onto cross-protocol Anthropic /
/// OpenAI egress, an invalid tool-input shape strict SDKs reject (they require an object). An
/// EXPLICITLY-present value (including an explicit `null`, which a native client could send) is kept
/// verbatim — we only synthesize the empty object for the truly-absent case.
fn empty_object_if_absent(args: Option<&serde_json::Value>) -> serde_json::Value {
    match args {
        Some(v) => v.clone(),
        None => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Coerce an `IrBlock::ToolUse.input` into a valid Gemini `functionCall.args` value.
///
/// Gemini's `functionCall.args` is a protobuf Struct: it MUST be a JSON OBJECT. A cross-protocol
/// reader (Anthropic/OpenAI/Bedrock/Cohere) can hand us a `ToolUse.input` that is NOT an object — a
/// JSON array (`[1,2]`), a bare scalar (`42`/`true`/`"text"`), a `null`, or an unparseable raw string
/// — and emitting any of those verbatim under `args` produces a request the backend rejects (400).
/// This mirrors the `ToolResult.response` coercion below: an object passes through byte-identical (so
/// the same-protocol Gemini→Gemini round-trip stays lossless), a `null` becomes an empty-but-valid
/// `{}`, and any other non-object (array/scalar) is wrapped under `{"args": <value>}` so its content
/// survives. A raw JSON string is parsed first, then the SAME coercion is applied to the parse result;
/// an unparseable string is treated as a scalar and wrapped.
fn coerce_tool_args(input: &serde_json::Value) -> serde_json::Value {
    // Resolve the candidate value: a string is a serialized payload — parse it, falling back to the
    // string itself (a scalar) when it does not parse as JSON. Any non-string value is used as-is.
    let candidate: serde_json::Value = match input.as_str() {
        Some(s) => crate::json::parse_str(s).unwrap_or_else(|_| input.clone()),
        None => input.clone(),
    };
    if candidate.is_object() {
        candidate
    } else if candidate.is_null() {
        serde_json::json!({})
    } else {
        serde_json::json!({ "args": candidate })
    }
}

/// L2: map a Gemini candidate's `citationMetadata.citationSources[]` → neutral
/// [`crate::ir::IrCitation`]s. A Gemini citation source is a grounding/web-search reference carrying
/// `startIndex`/`endIndex` (character offsets into the response text), `uri`, `title`, and `license`.
/// We project it onto the neutral fields (uri→url, indices→start/end, title→title) and stash the
/// source object verbatim in `raw` so a same-protocol Gemini path could re-emit it. The neutral
/// `kind` is `web_search_result_location` — a grounding source IS a URL reference, which is also the
/// Anthropic variant a cross-protocol Anthropic egress synthesizes for it. Returns empty when the
/// candidate has no citation metadata.
fn read_gemini_citations(candidate: &serde_json::Value) -> Vec<crate::ir::IrCitation> {
    let sources = candidate
        .get("citationMetadata")
        .and_then(|m| m.get("citationSources"))
        .and_then(|s| s.as_array());
    let Some(sources) = sources else {
        return Vec::new();
    };
    sources
        .iter()
        .map(|src| crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title: src
                .get("title")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            url: src.get("uri").and_then(|v| v.as_str()).map(str::to_string),
            document_index: None,
            start_index: src.get("startIndex").and_then(|v| v.as_i64()),
            end_index: src.get("endIndex").and_then(|v| v.as_i64()),
            encrypted_index: None,
            raw: Some(src.clone()),
        })
        .collect()
}

/// L2: map a neutral [`crate::ir::IrCitation`] → a Gemini `citationSources[]` entry.
///
/// SAME-PROTOCOL FIDELITY: when `raw` is present AND it is a Gemini citation source (has a `uri` or
/// the Gemini index fields), re-emit it verbatim so a Gemini→IR→Gemini path is byte-exact. A `raw`
/// from a FOREIGN protocol (e.g. an Anthropic citation object on an Anthropic→Gemini hop) would not
/// be a valid Gemini source, so we ignore it and BUILD a Gemini source from the neutral fields.
fn write_gemini_citation(c: &crate::ir::IrCitation) -> serde_json::Value {
    if let Some(raw) = &c.raw {
        if raw.get("uri").is_some()
            || raw.get("startIndex").is_some()
            || raw.get("endIndex").is_some()
        {
            return raw.clone();
        }
    }
    let mut obj = serde_json::Map::new();
    if let Some(s) = c.start_index {
        obj.insert("startIndex".to_string(), serde_json::json!(s));
    }
    if let Some(e) = c.end_index {
        obj.insert("endIndex".to_string(), serde_json::json!(e));
    }
    if let Some(u) = &c.url {
        obj.insert("uri".to_string(), serde_json::json!(u));
    }
    if let Some(t) = &c.title {
        obj.insert("title".to_string(), serde_json::json!(t));
    }
    serde_json::Value::Object(obj)
}

/// True when a Gemini response/stream chunk carries NO usable `candidates` (absent, non-array, OR an
/// EMPTY array). Used to distinguish a prompt-block / error-only envelope from a normal
/// candidate-bearing chunk.
///
/// An EMPTY `candidates: []` is treated the SAME as a missing array: a native Gemini envelope that
/// rejects the PROMPT (e.g. `{"candidates":[],"promptFeedback":{"blockReason":"SAFETY"}}`) carries an
/// empty candidates array alongside the top-level `promptFeedback.blockReason`. Keying only on
/// array-PRESENCE (the old behavior) let that empty-array shape slip past the prompt-block arm in both
/// the streaming reader and `read_response`, so the streaming path emitted a bare un-terminated stream
/// and the non-streaming path hard-failed `candidates.is_empty()` into a spurious `ir_parse` error —
/// dropping a legitimate content-policy block. Broadening to treat `[]` as absent routes both into the
/// existing prompt-block / terminal arms. A genuinely empty array with NO block reason still falls
/// through to the existing handling below those arms (unchanged).
fn candidates_absent(data: &serde_json::Value) -> bool {
    match data.get("candidates").and_then(|c| c.as_array()) {
        Some(arr) => arr.is_empty(),
        None => true,
    }
}

/// Extract a top-level `promptFeedback.blockReason` (the PROMPT-level content block signal) if the
/// envelope carries one, e.g. `{"promptFeedback":{"blockReason":"SAFETY"}}`. Returns the raw reason
/// string (SAFETY / BLOCKLIST / PROHIBITED_CONTENT / OTHER / …) so the caller can map it to a
/// canonical stop reason. `None` when absent or not a non-empty string.
fn prompt_block_reason(data: &serde_json::Value) -> Option<&str> {
    data.get("promptFeedback")
        .and_then(|pf| pf.get("blockReason"))
        .and_then(|r| r.as_str())
        .filter(|s| !s.is_empty())
}

/// Map a Gemini candidate `finishReason` to a canonical IR stop reason (PF-M2).
///
/// `STOP`/`MAX_TOKENS`/`SAFETY` map to their direct canonical siblings (`end_turn`/`max_tokens`/
/// `safety`). The remaining Gemini-only reasons — `RECITATION`, `IMAGE_SAFETY`, `SPII`,
/// `BLOCKLIST`, `PROHIBITED_CONTENT` (content-policy stops) → `safety`; `MALFORMED_FUNCTION_CALL`
/// (the model emitted an UNPARSEABLE tool call — generation FAILED, there is NO valid call to run)
/// → `error`, NOT `tool_use`: `tool_use` would tell the client to execute and continue a tool call
/// that does not exist, so it would search for a tool_use block, find none/garbage and break; `OTHER`,
/// `LANGUAGE`, and any unknown future reason → the canonical `Other` variant (`_ => S::Other`) — were
/// previously passed through `to_lowercase()` VERBATIM, producing values (`recitation`,
/// `malformed_function_call`, `spii`, …) that NO downstream SDK enum recognizes. Mapping them to the
/// canonical IR set the Anthropic/OpenAI writers already translate (`safety`→Anthropic `safety`/OpenAI
/// `content_filter`; `error`→`end_turn`/`stop`; `Other`→each writer's natural-stop default) keeps the
/// translation lossless instead of leaking an unrecognized Gemini token to a non-Gemini client. A
/// Gemini→Gemini round-trip is unaffected: the writer emits `Other` back as the native `OTHER`
/// finishReason (`write_gemini_stop_reason`: `Other => GEMINI_FINISH_OTHER`) and `safety` back as
/// `SAFETY`, so a Gemini `OTHER` stop round-trips OTHER→Other→OTHER unchanged; these stops are terminal
/// — the body is not replayed. (Do NOT "simplify" the `_ => S::Other` arm to `S::EndTurn`: that would
/// silently convert a Gemini→Gemini `OTHER` stop into `STOP`.)
fn map_gemini_finish_reason(finish_reason: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match finish_reason {
        GEMINI_FINISH_STOP => S::EndTurn,
        GEMINI_FINISH_MAX_TOKENS => S::MaxTokens,
        GEMINI_FINISH_SAFETY
        | GEMINI_FINISH_RECITATION
        | "IMAGE_SAFETY"
        | "SPII"
        | "BLOCKLIST"
        | GEMINI_FINISH_PROHIBITED_CONTENT => S::Safety,
        // The model produced an invalid function call: an abnormal stop with no runnable tool call.
        GEMINI_FINISH_MALFORMED_FUNCTION_CALL => S::Error,
        // OTHER / LANGUAGE / any novel future reason.
        _ => S::Other,
    }
}

/// Map a Gemini `promptFeedback.blockReason` to a canonical IR stop reason. A prompt block is a
/// content-policy refusal of the input, so it surfaces as `safety` (matching the candidate-level
/// `finishReason: SAFETY` → `safety` mapping) for the well-known content-policy reasons; any other
/// reason is lowercased so a novel block reason is still surfaced rather than dropped.
fn prompt_block_stop_reason(block_reason: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match block_reason {
        // RECITATION maps to Safety at the candidate level (and per GEMINI_FINISH_RECITATION's own
        // doc); classify a prompt-level RECITATION block the same way, not Other.
        GEMINI_FINISH_SAFETY
        | "BLOCKLIST"
        | GEMINI_FINISH_PROHIBITED_CONTENT
        | GEMINI_FINISH_RECITATION => S::Safety,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → Gemini native `finishReason`. EXHAUSTIVE: Gemini's enum has NO
/// TOOL_USE member (a tool-call turn ends with STOP), so EndTurn/StopSequence/ToolUse → STOP;
/// MaxTokens → MAX_TOKENS; Safety → SAFETY; any other reason → the native `OTHER` member (a valid enum
/// value that honestly signals an unenumerated stop, never an off-spec upper-cased token).
fn write_gemini_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn | S::StopSequence | S::ToolUse => GEMINI_FINISH_STOP,
        S::MaxTokens => GEMINI_FINISH_MAX_TOKENS,
        S::Safety => GEMINI_FINISH_SAFETY,
        S::Refusal | S::Error | S::PauseTurn | S::Other => GEMINI_FINISH_OTHER,
    }
}

/// Read Gemini's structured-output directive out of `generationConfig` into the protocol-agnostic
/// [`crate::ir::IrResponseFormat`]. The ONLY code that knows Gemini's structured-output wire shape:
/// `generationConfig.responseMimeType` (e.g. `"application/json"`) plus an optional `responseSchema`
/// — Gemini has no single `response_format` key. Returns `None` when NEITHER sub-field is present, so
/// a plain request never gains a spurious directive.
fn read_gemini_response_format(
    gen_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrResponseFormat> {
    let gc = gen_config?;
    let mime = gc.get(FIELD_RESPONSE_MIME_TYPE).and_then(|m| m.as_str());
    let schema = gc.get("responseSchema");
    if mime.is_none() && schema.is_none() {
        return None;
    }
    Some(crate::ir::IrResponseFormat {
        json: schema.is_some() || mime == Some(MIME_APPLICATION_JSON),
        schema: schema.cloned(),
        name: None,
        strict: None,
        description: None,
    })
}

/// Project the agnostic [`crate::ir::IrResponseFormat`] into a Gemini `generationConfig` map. The ONLY
/// code that builds Gemini's structured-output wire shape: a JSON directive emits
/// `responseMimeType:"application/json"` plus the sanitized `responseSchema` (schema keywords Gemini
/// rejects are stripped). A non-JSON directive emits nothing — Gemini's default is plain text.
fn write_gemini_response_format(
    gen_config: &mut serde_json::Map<String, serde_json::Value>,
    rf: &crate::ir::IrResponseFormat,
) {
    if !rf.json {
        return;
    }
    gen_config.insert(
        FIELD_RESPONSE_MIME_TYPE.to_string(),
        serde_json::json!(MIME_APPLICATION_JSON),
    );
    if let Some(schema) = &rf.schema {
        gen_config.insert("responseSchema".to_string(), sanitize_gemini_schema(schema));
    }
}

/// JSON-Schema keywords Gemini's `OpenAPI`-subset schema validator REJECTS with a 400 when present in
/// a `responseSchema` or a tool's `parameters`. Gemini accepts a strict OpenAPI 3.0 `Schema` subset,
/// NOT full JSON Schema, so draft keywords a foreign protocol (OpenAI/Anthropic) routinely emits on a
/// tool/structured-output schema hard-fail the request. Stripping them (recursively) lets a
/// cross-protocol tool/structured-output definition survive instead of 400-ing (L3 / M1). Kept as one
/// list so both `responseSchema` and tool `parameters` sanitize identically.
const GEMINI_SCHEMA_REJECTED_KEYS: &[&str] = &[
    "$schema",
    "$id",
    "$ref",
    "$defs",
    "definitions",
    "additionalProperties",
    "additionalItems",
    "patternProperties",
    "unevaluatedProperties",
    "const",
    "examples",
    "$comment",
];

/// Recursively strip the JSON-Schema keywords Gemini rejects (`GEMINI_SCHEMA_REJECTED_KEYS`) from a
/// schema value so a cross-protocol tool / `responseSchema` definition does not hard-fail with a 400
/// (L3). Walks objects and arrays; non-container values are returned unchanged. Returns a cleaned
/// clone — the source IR value is left intact (only the egress wire copy is sanitized), so the
/// stripped keys still round-trip same-protocol via the preserved raw object in `extra` where
/// applicable.
fn sanitize_gemini_schema(schema: &serde_json::Value) -> serde_json::Value {
    match schema {
        serde_json::Value::Object(map) => {
            let mut cleaned = serde_json::Map::new();
            for (k, v) in map {
                if GEMINI_SCHEMA_REJECTED_KEYS.contains(&k.as_str()) {
                    continue;
                }
                cleaned.insert(k.clone(), sanitize_gemini_schema(v));
            }
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_gemini_schema).collect())
        }
        other => other.clone(),
    }
}

/// Parse a Gemini `usageMetadata` block into `IrUsage`, defaulting every counter to 0 when the
/// field (or an individual counter) is absent. Shared by the streaming and prompt-block paths so
/// usage accounting stays identical regardless of how a response terminates.
///
/// H6 cache tokens: Gemini reports context-cache hits as `usageMetadata.cachedContentTokenCount`
/// (the google-genai SDK's `cached_content_token_count`). Map it into the IR's
/// `cache_read_input_tokens` — the SAME field Bedrock's `cacheReadInputTokens` and Anthropic's
/// `cache_read_input_tokens` populate — so cached-prompt accounting survives the cross-protocol seam
/// instead of being dropped. `None` when absent (no cache hit / older response).
fn gemini_usage(data: &serde_json::Value) -> crate::ir::IrUsage {
    let u = data.get(FIELD_USAGE_METADATA);
    let prompt = u
        .and_then(|u| u.get(FIELD_PROMPT_TOKEN_COUNT))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cached = u
        .and_then(|u| u.get(FIELD_CACHED_CONTENT_TOKEN_COUNT))
        .and_then(|v| v.as_u64());
    crate::ir::IrUsage {
        // NORMALIZE to the additive-cache convention: Gemini's `promptTokenCount` is a TOTAL that
        // already INCLUDES `cachedContentTokenCount`, so subtract the cached tokens to leave only
        // the uncached input. `saturating_sub` guards an odd upstream where cached > prompt.
        input_tokens: prompt.saturating_sub(cached.unwrap_or(0)),
        output_tokens: u
            .and_then(|u| u.get(FIELD_CANDIDATES_TOKEN_COUNT))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        cache_creation_input_tokens: None,
        cache_read_input_tokens: cached,
    }
}

/// Map a canonical `StatusClass` onto the `(HTTP code, google.rpc.Code name)` pair Gemini uses in
/// its `google.rpc.Status` error envelope. Exhaustive over `StatusClass` (no `_ =>` catch-all) so
/// a new class forces a conscious choice here rather than silently degrading to INTERNAL.
fn gemini_stream_error_code_status(class: StatusClass) -> (u16, &'static str) {
    match class {
        StatusClass::RateLimit => (429, GRPC_RESOURCE_EXHAUSTED),
        StatusClass::Overloaded => (503, GRPC_UNAVAILABLE),
        StatusClass::ServerError => (500, GRPC_INTERNAL),
        StatusClass::Timeout => (504, GRPC_DEADLINE_EXCEEDED),
        StatusClass::Network => (503, GRPC_UNAVAILABLE),
        StatusClass::Auth => (401, GRPC_UNAUTHENTICATED),
        StatusClass::Billing => (403, GRPC_PERMISSION_DENIED),
        StatusClass::ClientError => (400, GRPC_INVALID_ARGUMENT),
        StatusClass::ContextLength => (400, GRPC_INVALID_ARGUMENT),
    }
}

/// Map an inline google.rpc.Status `(status name, code)` — as delivered in a 200-status SSE error
/// chunk's `error` object — onto a canonical `StatusClass`. This is the read-side inverse of
/// `gemini_stream_error_code_status` (which maps `StatusClass` back onto `(code, name)` for the
/// writer): an inline upstream error is mapped to a class so the downstream ingress writer can
/// terminate the stream with a protocol-shaped error frame.
///
/// Preference order: the UPPER_SNAKE google.rpc.Code `status` string when present (the authoritative
/// field a native Gemini SDK branches on), falling back to the numeric HTTP `code` when `status` is
/// absent or unrecognized. The `status` arm is exhaustive over the google.rpc.Code names the real
/// Generative Language API emits; an unrecognized string falls through to the numeric-code mapping,
/// and a name we do not model is bound to a NAMED arm (not a `_` wildcard that silently degrades —
/// per the no-catch-all rule; `&str`/`Option<&str>` matches are never type-exhaustive so a named
/// fallback is the explicit-choice equivalent here). An absent/unknown code defaults to
/// `ServerError` — the safe class for an unclassified upstream failure (it is retryable and trips
/// the breaker, never masking a real failure as success).
fn gemini_error_status_class(status: Option<&str>, code: Option<u64>) -> StatusClass {
    if let Some(name) = status {
        match name {
            GRPC_RESOURCE_EXHAUSTED => return StatusClass::RateLimit,
            GRPC_UNAVAILABLE => return StatusClass::Overloaded,
            GRPC_DEADLINE_EXCEEDED => return StatusClass::Timeout,
            GRPC_UNAUTHENTICATED => return StatusClass::Auth,
            GRPC_PERMISSION_DENIED => return StatusClass::Billing,
            GRPC_INVALID_ARGUMENT
            | "FAILED_PRECONDITION"
            | "OUT_OF_RANGE"
            | GRPC_NOT_FOUND
            | "ALREADY_EXISTS"
            | "ABORTED"
            | "CANCELLED" => return StatusClass::ClientError,
            GRPC_INTERNAL | "UNKNOWN" | "DATA_LOSS" | GRPC_UNIMPLEMENTED => {
                return StatusClass::ServerError
            }
            // An UPPER_SNAKE status string outside the modeled google.rpc.Code set: fall through to
            // the numeric `code` mapping below rather than guessing. Named (not `_`) per the
            // no-catch-all rule; `other` is intentionally unused beyond falling through.
            other => {
                let _ = other;
            }
        }
    }
    match code {
        Some(429) => StatusClass::RateLimit,
        Some(503) => StatusClass::Overloaded,
        Some(504) => StatusClass::Timeout,
        Some(401) => StatusClass::Auth,
        Some(403) => StatusClass::Billing,
        Some(c) if (400..500).contains(&c) => StatusClass::ClientError,
        // Any 5xx, or an absent/unknown code: ServerError is the safe, breaker-tripping default for
        // an unclassified upstream failure rather than masking it as a client error.
        Some(_) | None => StatusClass::ServerError,
    }
}

/// Gemini writer implementation.
///
/// Carries one piece of per-stream state: the open streaming tool calls. A native Gemini SSE stream
/// emits a tool call as a SINGLE `functionCall` part `{name, args}`. The IR, however, carries the
/// tool NAME only on the `BlockStart` (`IrBlockMeta::ToolUse{name}`) and the arguments only on the
/// following `InputJsonDelta(String)` fragment(s) — and a cross-protocol backend (OpenAI / Anthropic)
/// commonly streams the `arguments` JSON across MULTIPLE partial-JSON fragments (`{"lo`, `c":"SF"}`),
/// each surfaced as its OWN `InputJsonDelta`. A stateless writer that emits one IR event at a time
/// therefore produced N parts on the wire — a `{name, args:{}}` BlockStart frame plus one nameless
/// `{args}` delta frame PER fragment, each parsing a partial fragment that fails (so `args:{}`) — a
/// split-and-data-loss shape a native google-genai client never sees (and where a strict client
/// reading `part.function_call.name` sees an empty name and lost arguments).
///
/// To emit the native single `{name, args}` shape REGARDLESS of fragmentation we BUFFER per open tool
/// block: the name from its `BlockStart` and every `InputJsonDelta` fragment CONCATENATED into one
/// arg string. We emit nothing on the BlockStart or the deltas; on `BlockStop` we parse the fully
/// reassembled arg string ONCE and emit a single `{name, args}` part. A zero-argument tool call (no
/// delta at all) flushes `{name, args:{}}` the same way, so the call is never lost.
///
/// The buffer is a `Vec` keyed by IR block index, NOT a single slot: a cross-protocol backend may
/// open several parallel tool blocks (OpenAI streams `tool_calls` index 0 and 1; the OpenAI reader
/// emits BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2) at finish —
/// the BlockStarts are NOT strictly interleaved with their own BlockStop). A single-slot buffer would
/// be clobbered by the second BlockStart, dropping the first tool's name and args. The per-index Vec
/// lets every open tool accumulate independently.
///
/// `StreamTranslate::new` builds a FRESH `Protocol::gemini()` (hence a fresh `GeminiWriter` with an
/// empty buffer) for each stream, so this state is stream-scoped by construction — exactly the
/// precedent `ResponsesWriter`'s per-stream `sequence`/`response_id` fields established.
pub(crate) struct GeminiWriter {
    /// The currently open streaming tool calls, one `(index, name, args)` tuple per OPEN tool block:
    /// - `index` is the IR block index from the opening `BlockStart`, used to match subsequent
    ///   `BlockDelta`/`BlockStop` events to THE RIGHT tool block (parallel tool calls share no slot).
    /// - `name` is the function name buffered off the `BlockStart`.
    /// - `args` is every `InputJsonDelta` fragment for this block CONCATENATED, so a multi-chunk
    ///   streamed `arguments` JSON reassembles into one string parsed once on `BlockStop`. An empty
    ///   string (no delta arrived) flushes `args:{}` for a zero-argument tool call.
    ///
    /// A `Vec` (not a map) keeps the dependency surface nil and the common case (0–2 open tools)
    /// trivially cheap; lookups are a linear scan over the open set, which is bounded by the upstream
    /// reader's own tool-frame cap.
    ///
    /// `Mutex` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires; a
    /// stream is single-threaded at any instant so contention is nil, and a poisoned lock degrades
    /// to the stateless behavior rather than panicking on the request path.
    open_tools: std::sync::Mutex<Vec<(usize, String, String)>>,
}

/// Value-namespace constructor for [`GeminiWriter`]. A `const` and a struct may share a name (they
/// live in the value and type namespaces respectively), so every existing site that writes the bare
/// `GeminiWriter` literal — `Protocol::gemini()` and the tests — keeps compiling unchanged while the
/// type now carries per-stream state. Each USE of the const inlines a FRESH `GeminiWriter` with an
/// empty `open_tool` buffer, so every `Protocol::gemini()` call mints an independent buffer — the
/// per-stream scoping the single-frame functionCall fix needs. `Mutex::new`/`None` are const, so
/// this is valid in const context.
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is inlined
/// per use rather than shared. That per-use fresh instance is PRECISELY the semantics we need: a
/// `static` would share ONE buffer across every stream in the process, bleeding one stream's open
/// tool name into another. So the lint's suggestion is wrong for this site and is suppressed
/// deliberately — mirroring `ResponsesWriter`.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const GeminiWriter: GeminiWriter = GeminiWriter {
    open_tools: std::sync::Mutex::new(Vec::new()),
};

impl Clone for GeminiWriter {
    fn clone(&self) -> Self {
        // Preserve the in-flight open tool calls across a mid-stream `Protocol::clone` so the
        // functionCall name/args correlation survives; a poisoned lock degrades to an empty buffer
        // (stateless behavior) rather than panicking on the request path.
        GeminiWriter {
            open_tools: std::sync::Mutex::new(
                self.open_tools
                    .lock()
                    .map(|t| t.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

/// Re-frame a Gemini SSE response stream as the JSON-ARRAY streaming format a native
/// `:streamGenerateContent` request WITHOUT `?alt=sse` expects: a leading `[`, the per-chunk
/// `GenerateContentResponse` JSON objects separated by `,`, and a trailing `]`. (The SSE variant —
/// `?alt=sse` — emits `data:`-framed chunks instead; busbar always requests `?alt=sse` UPSTREAM, so
/// the bytes reaching this framer are Gemini SSE frames either way, whether the egress is gemini
/// same-protocol passthrough or a cross-protocol `StreamTranslate` whose ingress writer is gemini.)
///
/// This framer is the JSON-array sibling of [`StreamTranslate`]'s SSE path: it consumes the SSE
/// bytes (already in the gemini ingress wire shape), strips the `data:` framing, and re-emits the
/// payloads as one streaming JSON array. The output is ALWAYS a syntactically valid JSON array
/// (`finish` emits `]`, or `[]` when no chunk was seen) so a client that buffers and `JSON.parse`s
/// the whole body still succeeds.
pub(crate) struct GeminiJsonArrayFramer {
    buf: Vec<u8>,
    /// How far into `buf` the SSE terminator scan has already advanced (keeps `feed` linear; mirrors
    /// `StreamTranslate::scanned`).
    scanned: usize,
    /// Whether the opening `[` (and, for every object after the first, the separating `,`) has been
    /// emitted yet.
    started: bool,
    /// Set once `finish` has emitted the closing `]`, so a second `finish` is a no-op.
    finished: bool,
    /// Abandon the stream if the reassembly buffer grows past the cap with no complete frame.
    aborted: bool,
}

impl GeminiJsonArrayFramer {
    // `pub(crate)` so the framer's tests in `mod.rs` (which exercise the buffer-overflow abort path)
    // can size a payload off the cap; it stays an internal cap, not part of the wire surface.
    pub(crate) const MAX_BUF: usize = crate::eventstream::MAX_FRAME_BYTES;

    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            started: false,
            finished: false,
            aborted: false,
        }
    }

    /// Feed a chunk of GEMINI SSE bytes; return JSON-array bytes for whatever complete SSE frames are
    /// now available (empty if only a partial frame is buffered, or if the buffered frames carried no
    /// data payload yet). Each emitted object is preceded by `[` (first) or `,` (subsequent).
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.aborted || self.finished {
            return Vec::new();
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();
        // FRONT cursor (mirrors `StreamTranslate::feed`): advance `consumed` per complete frame and
        // reclaim the prefix in ONE shift after the loop, instead of `drain(..end)` per frame (which
        // shifted the whole tail once per frame → O(n^2) on a buffer of many small frames). The search
        // floor is `consumed` — never below it, or the just-consumed terminator is re-found (infinite
        // loop); the 3-byte straddle backup and the `scanned` skip apply only above that floor.
        let mut consumed = 0usize;
        loop {
            let search_from = self
                .scanned
                .saturating_sub(3)
                .max(consumed)
                .min(self.buf.len());
            match find_frame_terminator(&self.buf[search_from..]) {
                Some((rel, term_len)) => {
                    let end = search_from + rel + term_len;
                    let frame = &self.buf[consumed..end];
                    consumed = end;
                    self.scanned = end;
                    let Some((_event_type, data_str)) = parse_sse_frame(frame) else {
                        continue; // no data: line — keepalive/comment frame
                    };
                    if data_str.is_empty() || data_str == crate::proto::SSE_DONE_SENTINEL {
                        continue; // egress terminator/keepalive — the array close is finish()'s job
                    }
                    // Validate the payload is JSON before forwarding so a malformed frame cannot
                    // corrupt the array; re-serialize from the parsed Value to normalize whitespace.
                    let Ok(data) = crate::json::parse_str::<serde_json::Value>(&data_str) else {
                        continue;
                    };
                    if self.started {
                        out.push(b',');
                    } else {
                        out.push(b'[');
                        self.started = true;
                    }
                    out.extend_from_slice(data.to_string().as_bytes());
                }
                None => {
                    self.scanned = self.buf.len();
                    break;
                }
            }
        }
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        if self.buf.len() > Self::MAX_BUF {
            self.aborted = true;
            self.buf.clear();
            self.buf.shrink_to_fit();
            self.scanned = 0;
        }
        out
    }

    /// Call once at end-of-stream. Emits the closing `]` (and the opening `[` too, as `[]`, when the
    /// stream carried no chunk) so the body is always a complete, parseable JSON array. When the
    /// framer ABORTED (the reassembly buffer overran `MAX_BUF` without a frame terminator), the
    /// stream was silently truncated — so instead of a bare `]` that would make the partial array
    /// look complete, append a Gemini-shaped `google.rpc.Status` error element so a parsing client
    /// can see the stream ended abnormally (then close the array).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        if self.aborted {
            return self.finish_with_error(
                500,
                GRPC_INTERNAL,
                // Client-facing wire body: must carry NO product/internal vocabulary (the
                // protocol-indistinguishability promise). "upstream" is busbar-internal routing
                // vocabulary no real Gemini API ever emits — a fingerprintable tell. Mirror Gemini's
                // own canonical 500 status message text instead (the `google.rpc.Status.message` a
                // real Generative Language API 500 carries), so substring-matching clients can't
                // distinguish the proxy.
                "Internal error encountered.",
            );
        }
        self.finished = true;
        if self.started {
            b"]".to_vec()
        } else {
            b"[]".to_vec()
        }
    }

    /// Close the array at end-of-stream when this framer sits DOWNSTREAM of a cross-protocol
    /// [`StreamTranslate`] (gemini ingress, non-gemini egress). Identical to [`finish`] except it ALSO
    /// surfaces an abort that happened on the TRANSLATE side: when the translate's reassembly buffer
    /// overflowed `MAX_BUF` it stopped feeding this framer and its SSE terminal-error frame is
    /// discarded by the caller (an SSE error cannot ride inside a JSON-array body), so this framer's
    /// own `aborted` flag stays clear and a plain [`finish`] would emit a bare `]` — a SILENT
    /// truncation indistinguishable from a successful short completion. Pass
    /// `translate_aborted = StreamTranslate::aborted()`; when EITHER side aborted, emit the
    /// Gemini-shaped error element + `]` (mirroring the SSE-ingress terminal-error path in
    /// `StreamTranslate::finish`) instead of the bare close. Idempotent via the shared `finished` flag.
    ///
    /// [`finish`]: Self::finish
    ///
    /// Production wiring lives in `proxy engine`: the `FirstByteBody` `Poll::Ready(None)` JSON-array
    /// close arm calls this with `translate.aborted()` (captured before draining the translate's SSE
    /// terminator) instead of discarding `translate.finish()` then calling plain `framer.finish()`.
    pub(crate) fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        if translate_aborted || self.aborted {
            return self.finish_with_error(
                500,
                GRPC_INTERNAL,
                // Same client-facing wire body as the framer-side abort in `finish`: a native
                // Gemini 500 `google.rpc.Status.message`, carrying no busbar-internal vocabulary
                // (the protocol-indistinguishability promise).
                "Internal error encountered.",
            );
        }
        self.finish()
    }

    /// Terminate the array with a trailing Gemini-shaped error element, then the closing `]`. Used on
    /// a mid-stream upstream transport failure (and on internal abort): a native Gemini JSON-array
    /// body is `application/json`, so the in-band error MUST itself be a valid array element — a
    /// `{"error":{"code","message","status"}}` object matching Gemini's `google.rpc.Status` envelope
    /// (the same shape `GeminiWriter::write_error` emits). Emitting raw SSE `event:`/`data:` text here
    /// (the bug this replaces) spliced non-JSON into the array, yielding an unparseable body and a
    /// protocol tell (a native Gemini JSON-array stream never contains SSE framing). Idempotent.
    pub(crate) fn finish_with_error(&mut self, code: u16, status: &str, message: &str) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let err = serde_json::json!({
            "error": { "code": code, "message": message, "status": status }
        });
        let mut out: Vec<u8> = Vec::new();
        if self.started {
            out.push(b',');
        } else {
            out.push(b'[');
            self.started = true;
        }
        out.extend_from_slice(err.to_string().as_bytes());
        out.push(b']');
        out
    }
}

impl crate::proto::JsonArrayFramer for GeminiJsonArrayFramer {
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        GeminiJsonArrayFramer::feed(self, chunk)
    }

    fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8> {
        GeminiJsonArrayFramer::finish_for_translate(self, translate_aborted)
    }

    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8> {
        // The implementor owns the wire shape: a native Gemini server error is HTTP 500 / gRPC
        // `INTERNAL`. The agnostic caller passes only the message, so proxy engine names no Gemini value.
        GeminiJsonArrayFramer::finish_with_error(self, 500, GRPC_INTERNAL, message)
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/logprobs_carry_tests.rs"]
mod logprobs_carry_tests;

mod reader;
mod writer;
