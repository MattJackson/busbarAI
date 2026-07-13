// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI protocol reader/writer implementation.

use super::openai_family::{
    bearer_error_code, openai_context_length_prose_scan, ERR_TYPE_AUTHENTICATION,
    ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED,
    ERR_TYPE_PERMISSION, ERR_TYPE_RATE_LIMIT, ERR_TYPE_SERVER_ERROR, OPENAI_FAMILY_DEFAULT_MODEL,
    OPENAI_FAMILY_MAX_OPEN_TOOLS,
};
use super::*;

/// Largest upstream `tool_calls[].index` we accept in a streaming chunk. OpenAI documents at most
/// 128 parallel tool calls, so any larger index is malformed; we clamp to this value before it
/// reaches the IR index arithmetic (`oai_idx + 1 + offset`) so a crafted `u64::MAX` index can never
/// overflow the `usize` cast or the addition. Chosen as the highest valid 0-based index (127).
const MAX_TOOL_INDEX: u64 = 127;

/// Hard cap on the number of DISTINCT tool-call indices we track per stream (`open_tools`). Bounds
/// per-request memory and the number of synthesized BlockStart events against a pathological backend
/// emitting unbounded unique indices. Matches OpenAI's documented parallel-tool-call limit (128).
const MAX_OPEN_TOOLS: usize = OPENAI_FAMILY_MAX_OPEN_TOOLS;

/// Fallback `model` string stamped onto a cross-protocol OpenAI response when the egress backend
/// supplied none. The native OpenAI `chat.completion` / `chat.completion.chunk` schemas define
/// `model` as a REQUIRED non-nullable string, and the official `openai-python` (>=1.0) Pydantic
/// models raise `ValidationError` when it is absent. A backend whose `read_response` yields
/// `model: None` (e.g. Bedrock egress -> OpenAI ingress, where `read_response` sets `model: None`)
/// would otherwise produce a model-less first chunk / completion — both an SDK deserialisation
/// failure and a proxy tell (a real OpenAI endpoint never omits `model`). A current, widely-served
/// model id keeps the synthesized value plausible.
const DEFAULT_MODEL: &str = OPENAI_FAMILY_DEFAULT_MODEL;

/// Busbar-internal sentinel key for `max_completion_tokens` source tracking. The reader folds BOTH `max_tokens` and the
/// modern `max_completion_tokens` into the single IR `max_tokens` field so a caller's output-token
/// cap survives the cross-protocol seam. But OpenAI's o1/o3 reasoning models REJECT `max_tokens` and
/// require `max_completion_tokens`; an OpenAI->OpenAI passthrough to such a model that arrived as
/// `max_completion_tokens` must re-emit `max_completion_tokens`, not `max_tokens`. The reader records
/// the source spelling under this sentinel in `extra` so the writer can re-emit the SAME key on a
/// same-protocol passthrough. `extra` is cleared on the cross-protocol seam, so the sentinel
/// naturally vanishes there and a cross-protocol egress emits the canonical `max_tokens` — exactly
/// the desired scope (other protocols have no `max_completion_tokens`). The `__busbar` prefix never
/// collides with a real OpenAI field, and the writer consumes (does not leak) it.
const MAX_COMPLETION_TOKENS_SENTINEL: &str = "__busbar_max_completion_tokens";

// ── OpenAI wire-format named constants ──────────────────────────────────────
//
// Every magic string the ChatCompletions / streaming protocol needs, in one
// place.  Replace bare literals everywhere EXCEPT (a) these const-def lines
// and (b) golden output-contract assertions that pin busbar's own emitted wire
// byte (those keep the literal and are annotated with the comment below).

/// `object` field value on a non-streaming completion response.
const OBJ_COMPLETION: &str = "chat.completion";
/// `object` field value on every streaming chunk.
const OBJ_CHUNK: &str = "chat.completion.chunk";

/// OpenAI `finish_reason` wire token for a normal end-of-turn.
const FINISH_STOP: &str = "stop";
/// OpenAI `finish_reason` wire token for a max-tokens truncation.
const FINISH_LENGTH: &str = "length";
/// OpenAI `finish_reason` wire token emitted when the model called a tool.
const FINISH_TOOL_CALLS: &str = "tool_calls";
/// OpenAI `finish_reason` wire token emitted when content was filtered.
const FINISH_CONTENT_FILTER: &str = "content_filter";
/// Legacy OpenAI `finish_reason` wire token for function-calling (pre-tool_calls era).
const FINISH_FUNCTION_CALL: &str = "function_call";

/// `response_format.type` value for plain-text output.
const RESP_FORMAT_TEXT: &str = "text";
/// `response_format.type` value for a schema-constrained JSON output.
const RESP_FORMAT_JSON_SCHEMA: &str = "json_schema";
/// `response_format.type` value for unstructured JSON output.
const RESP_FORMAT_JSON_OBJECT: &str = "json_object";

/// Tool `type` field value for all Chat Completions function tools.
const TOOL_TYPE_FUNCTION: &str = "function";

/// Fallback `json_schema.name` synthesized when the IR carries none.
/// OpenAI REQUIRES this field and the SDK rejects it when absent.
const JSON_SCHEMA_DEFAULT_NAME: &str = "response";

/// Prefix of every native OpenAI chat-completion id (`chatcmpl-<24 base62 chars>`).
const COMPLETION_ID_PREFIX: &str = "chatcmpl-";

/// Upstream URL path for OpenAI Chat Completions.
const PATH_UPSTREAM: &str = "/v1/chat/completions";

/// The human-readable message busbar returns on a bad-key 401, matching the
/// exact phrasing the official OpenAI API uses so SDK `is_auth_error` helpers
/// that key on the message string still fire.
const AUTH_FAILURE_MSG: &str = "Incorrect API key provided.";

// ────────────────────────────────────────────────────────────────────────────

/// Resolve the `model` to emit on an OpenAI response: the upstream-supplied value when present,
/// otherwise the [`DEFAULT_MODEL`] fallback so the required non-nullable `model` field is never
/// omitted on a cross-protocol response. Never panics on the request path.
fn model_or_default(model: Option<&str>) -> &str {
    model.unwrap_or(DEFAULT_MODEL)
}

/// OpenAI native `finish_reason` token → canonical [`crate::ir::IrStopReason`]. The ONLY place that
/// knows OpenAI's finish vocabulary on the read side.
fn read_openai_stop_reason(token: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match token {
        FINISH_STOP => S::EndTurn,
        FINISH_LENGTH => S::MaxTokens,
        FINISH_TOOL_CALLS | FINISH_FUNCTION_CALL => S::ToolUse,
        FINISH_CONTENT_FILTER => S::Safety,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → OpenAI native `finish_reason`. EXHAUSTIVE: OpenAI's enum is
/// {stop,length,tool_calls,content_filter}; any reason with no OpenAI analog (`refusal`, `error`,
/// `pause_turn`, `other`) degrades to the SDK-safe `stop` rather than leak an off-enum value a strict
/// SDK rejects.
fn write_openai_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn | S::StopSequence => FINISH_STOP,
        S::MaxTokens => FINISH_LENGTH,
        S::ToolUse => FINISH_TOOL_CALLS,
        S::Safety => FINISH_CONTENT_FILTER,
        S::Refusal | S::Error | S::PauseTurn | S::Other => FINISH_STOP,
    }
}

/// Read an OpenAI Chat Completions `response_format` object into the protocol-agnostic
/// [`crate::ir::IrResponseFormat`]. This is the ONLY code that knows OpenAI's structured-output wire
/// shape (`{type:"json_schema", json_schema:{name,schema,strict,description}}` / `{type:"json_object"}`
/// / `{type:"text"}`). Returns `None` for a non-object or absent directive.
fn read_openai_response_format(v: &serde_json::Value) -> Option<crate::ir::IrResponseFormat> {
    let o = v.as_object()?;
    match o.get("type").and_then(|t| t.as_str()) {
        Some(RESP_FORMAT_TEXT) => Some(crate::ir::IrResponseFormat {
            json: false,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        Some(RESP_FORMAT_JSON_SCHEMA) => {
            let js = o.get("json_schema");
            Some(crate::ir::IrResponseFormat {
                json: true,
                schema: js.and_then(|j| j.get("schema")).cloned(),
                name: js
                    .and_then(|j| j.get("name"))
                    .and_then(|n| n.as_str())
                    .map(String::from),
                strict: js.and_then(|j| j.get("strict")).and_then(|s| s.as_bool()),
                description: js
                    .and_then(|j| j.get("description"))
                    .and_then(|d| d.as_str())
                    .map(String::from),
            })
        }
        // `json_object` carries no schema; an unrecognized `type` is treated as free-form JSON (the
        // safe non-rejecting default) rather than dropped.
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

/// Project the agnostic [`crate::ir::IrResponseFormat`] into OpenAI's native `response_format`. The
/// ONLY code that builds OpenAI's structured-output wire shape.
fn write_openai_response_format(rf: &crate::ir::IrResponseFormat) -> serde_json::Value {
    if !rf.json {
        return serde_json::json!({"type": RESP_FORMAT_TEXT});
    }
    match &rf.schema {
        Some(schema) => {
            let mut js = serde_json::Map::new();
            // OpenAI REQUIRES `json_schema.name`; synthesize a valid one when the source had none.
            js.insert(
                "name".to_string(),
                serde_json::json!(rf.name.as_deref().unwrap_or(JSON_SCHEMA_DEFAULT_NAME)),
            );
            js.insert("schema".to_string(), schema.clone());
            if let Some(s) = rf.strict {
                js.insert("strict".to_string(), serde_json::json!(s));
            }
            if let Some(d) = &rf.description {
                js.insert("description".to_string(), serde_json::json!(d));
            }
            serde_json::json!({"type": RESP_FORMAT_JSON_SCHEMA, "json_schema": js})
        }
        None => serde_json::json!({"type": RESP_FORMAT_JSON_OBJECT}),
    }
}

/// Width of a native OpenAI chat-completion id's random suffix: the `chatcmpl-` prefix is followed
/// by exactly 24 base62 characters (total 33 chars), the shape every native `chat.completion` /
/// `chat.completion.chunk` id carries. Matching this length AND alphabet is what keeps the
/// synthesized id structurally indistinguishable from a native one to any client that length-checks
/// or regex-validates `id` (SDK validators, logging/dedup tooling).
const COMPLETION_ID_TOKEN_LEN: usize = 24;

/// Base62 alphabet native OpenAI completion ids draw their suffix from — the shared
/// single-source-of-truth atom (see `crate::proto::BASE62_ALPHABET`), aliased locally. Used by
/// [`synth_completion_id`].
const BASE62: &[u8; 62] = crate::proto::BASE62_ALPHABET;

/// Synthesize a protocol-correct OpenAI completion id (`"chatcmpl-<24 base62 chars>"`) for
/// cross-protocol responses where the backend supplied none. Native OpenAI chat-completion ids are
/// `chatcmpl-` plus a fixed-width 24-char base62 token (33 chars total); the official SDKs treat
/// `id` as opaque, but tooling that length-checks or regex-validates the id immediately fingerprints
/// a too-short or wrong-alphabet value as non-native. The previous base-36 form produced a
/// variable-width ~7-char little-endian suffix (~16 chars total) — both too short and non-canonical.
///
/// The 24-char suffix is filled ENTIRELY from the OS CSPRNG (mirroring `synth_anthropic_request_id`
/// in `proto::anthropic` / `synth_amzn_request_id` in `proto::bedrock`), giving native-looking
/// entropy at EVERY position. A
/// 24-char base62 token is ~142 bits of entropy; the birthday bound on a collision is ~2^71 draws,
/// so pure CSPRNG output is collision-free in practice and needs no monotonic-counter backstop. We
/// deliberately do NOT overlay a process counter: a counter overlaid into any fixed region of the
/// token makes those characters predictable/low-entropy (the counter stays small, so its high
/// base62 digits are constant '0'), which is itself a structural fingerprint a native vendor id —
/// which is fully random across all positions — never carries. Native vendor ids ARE fully random,
/// so we are too. Never panics on the request path: on the near-impossible `getrandom` failure the
/// buffer stays the base62 zero char rather than `?`-ing out.
///
/// Mapping CSPRNG bytes into base62 uses REJECTION SAMPLING, not `byte % 62`. A raw modulo is biased
/// because 256 is not a multiple of 62 (256 = 4*62 + 8): the eight residues 0..=7 each receive one
/// extra source byte (5/256 probability vs 4/256 for residues 8..=61), so the first eight alphabet
/// characters ('0'..='7') would appear ~25% more often than the rest. A native vendor id is uniform
/// over the alphabet, so a skewed character histogram is itself a statistical fingerprint. We accept
/// only bytes below 248 (= 4*62, the largest multiple of 62 that fits in a byte) and discard the rest,
/// which yields an exactly-uniform draw over 0..62. Discards are rare (8/256 ≈ 3.1%), so we refill the
/// entropy buffer on demand rather than over-allocating up front; on a `getrandom` failure the loop
/// stops and the remaining slots keep their '0' fill, preserving the panic-free contract.
/// OpenAI's `logprobs` object (`{content: [{token, logprob, bytes, top_logprobs[]}]}`) → the
/// neutral IR entries. `bytes` is preserved verbatim when present (a token can be a partial UTF-8
/// fragment, so the byte array is the only faithful carrier).
pub(crate) fn read_openai_logprobs(
    v: Option<&serde_json::Value>,
) -> Vec<crate::ir::IrTokenLogprob> {
    let entries = match v
        .and_then(|lp| lp.get("content"))
        .and_then(|c| c.as_array())
    {
        Some(a) => a,
        None => return Vec::new(),
    };
    let read_bytes = |e: &serde_json::Value| -> Option<Vec<u8>> {
        e.get("bytes")?.as_array().map(|arr| {
            arr.iter()
                .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect()
        })
    };
    entries
        .iter()
        .filter_map(|e| {
            Some(crate::ir::IrTokenLogprob {
                token: e.get("token")?.as_str()?.to_string(),
                logprob: e.get("logprob")?.as_f64()?,
                bytes: read_bytes(e),
                top: e
                    .get("top_logprobs")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| {
                                Some(crate::ir::IrTopLogprob {
                                    token: t.get("token")?.as_str()?.to_string(),
                                    logprob: t.get("logprob")?.as_f64()?,
                                    bytes: read_bytes(t),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Neutral IR logprobs → OpenAI's `logprobs` object. `bytes` is synthesized from the token's UTF-8
/// encoding when the source protocol (Gemini) carries none — the same value OpenAI itself returns
/// for a whole-token UTF-8 string.
pub(crate) fn write_openai_logprobs(lps: &[crate::ir::IrTokenLogprob]) -> serde_json::Value {
    let content: Vec<serde_json::Value> = lps
        .iter()
        .map(|lp| {
            let bytes = lp
                .bytes
                .clone()
                .unwrap_or_else(|| lp.token.as_bytes().to_vec());
            let top: Vec<serde_json::Value> = lp
                .top
                .iter()
                .map(|t| {
                    let b = t
                        .bytes
                        .clone()
                        .unwrap_or_else(|| t.token.as_bytes().to_vec());
                    serde_json::json!({"token": t.token, "logprob": t.logprob, "bytes": b})
                })
                .collect();
            serde_json::json!({
                "token": lp.token,
                "logprob": lp.logprob,
                "bytes": bytes,
                "top_logprobs": top
            })
        })
        .collect();
    serde_json::json!({ "content": content })
}

fn synth_completion_id() -> String {
    // Largest multiple of 62 that fits in a u8; bytes >= this are rejected to keep the draw uniform.
    const BASE62_REJECT_FLOOR: u8 = crate::proto::BASE62_REJECT_THRESHOLD; // 4 * 62
    let mut token = [b'0'; COMPLETION_ID_TOKEN_LEN];
    let mut filled = 0usize;
    // Pull entropy in batches and consume only the in-range bytes. If a batch yields too few usable
    // bytes we draw another; on an entropy failure (getrandom errors) we stop and leave '0' fill.
    'outer: while filled < COMPLETION_ID_TOKEN_LEN {
        let mut batch = [0u8; COMPLETION_ID_TOKEN_LEN];
        if getrandom::fill(&mut batch).is_err() {
            // Near-impossible entropy failure: keep the remaining '0' fill rather than panic.
            break 'outer;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            token[filled] = BASE62[(byte % 62) as usize];
            filled += 1;
            if filled == COMPLETION_ID_TOKEN_LEN {
                break 'outer;
            }
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards
    // against an impossible non-ASCII byte and keeps the path panic-free.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("{COMPLETION_ID_PREFIX}{token}")
}

/// The set of top-level OpenAI Chat-Completions request keys the reader models into typed
/// `IrRequest` fields (any OTHER key is swept verbatim into `extra` for round-trip fidelity). This
/// set is a compile-time constant, so it is built ONCE into a process-global `OnceLock` and shared
/// by every `read_request` call instead of being re-allocated and re-hashed per request on the
/// ingress hot path. Every member is a `&'static str`, so the cached set borrows nothing
/// request-scoped.
fn modeled_request_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        [
            "model",
            "messages",
            "tools",
            "max_tokens",
            // `max_completion_tokens` is now modeled via the IR `max_tokens` field, so it must be
            // excluded from `extra` like `max_tokens` is. Leaving it in `extra` would make the
            // writer emit BOTH the promoted cap AND a verbatim `max_completion_tokens`, and on a
            // same-protocol passthrough also re-emit `max_tokens` alongside it — a conflicting
            // duplicate that reasoning models (which reject `max_tokens`) would 400 on.
            "max_completion_tokens",
            "temperature",
            "top_p",
            "stop",
            "stream",
            "tool_choice",
            // Phase 0: these are now promoted to first-class IR fields, so they must be excluded
            // from `extra` — otherwise the writer would emit BOTH the promoted field AND a verbatim
            // copy from `extra`, and the cross-protocol seam would clear the `extra` copy.
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "n",
            "response_format",
            // Carried cross-protocol to their Anthropic analogs (`metadata.user_id` /
            // `tool_choice.disable_parallel_tool_use`), so they must not ALSO ride `extra`.
            "user",
            "parallel_tool_calls",
            // Carried cross-protocol to Gemini's `generationConfig.responseLogprobs`/`logprobs`.
            "logprobs",
            "top_logprobs",
            // Carried cross-protocol to Anthropic/Gemini thinking budgets (gated per lane).
            "reasoning_effort",
        ]
        .into_iter()
        .collect()
    })
}

/// OpenAI reader implementation.
#[derive(Clone)]
pub(crate) struct OpenAiReader;

impl ProtocolReader for OpenAiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body exactly once and derive both fields from the single tree, mirroring
        // the single-parse pattern in AnthropicReader::extract_error. The previous code parsed the
        // same bytes twice (once per field), doubling alloc/CPU on every non-2xx response.
        let json = crate::json::parse::<serde_json::Value>(body).ok();
        let error_obj = json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_object());
        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get("code"))
            .and_then(|c| c.as_str())
            .map(String::from);
        let structured_type = error_obj
            .and_then(|e_obj| e_obj.get("type"))
            .and_then(|t| t.as_str())
            .map(String::from);

        // Make the derivation MESSAGE-AWARE, mirroring openai_responses.rs / anthropic.rs. OpenAI (and many
        // OpenAI-compatible backends) signal a context-length overflow with a structured
        // `code: "context_length_exceeded"`, which the parse above captures. But some upstreams send
        // a null/absent `code` and carry the condition only in the prose `message` — e.g.
        // `This model's maximum context length is 8192 tokens, however you requested 9000 tokens...`.
        // Without a message scan that body would normalize to a generic client error and PENALIZE the
        // lane instead of triggering oversized-request failover. When no canonical code was parsed,
        // scan the lowercased message for the context-length signal and synthesize the canonical code.
        //
        // The scan must be PRECISE. A naive `(token|context) && (too long|exceeds|maximum)`
        // OR-of-weak-tokens misclassifies unrelated errors — e.g. a quota body like
        // `You have reached the maximum number of tokens allowed per day` (rate-limit, not oversized)
        // pairs a stray `maximum` with a stray `token` and would falsely fail over with no penalty.
        // Require a CO-LOCATED context-length phrase, mirroring the openai_responses.rs / anthropic.rs
        // siblings: either a self-contained canonical phrase, or `exceeds` paired specifically with
        // `context`/`token limit` (not a bare `token`/`maximum`). Gate to the HTTP statuses OpenAI
        // actually uses for an oversized request (400 invalid_request_error; 413 payload-too-large)
        // so a 429/5xx that happens to mention tokens can never be reclassified as ContextLength.
        let provider_code = provider_code.or_else(|| {
            let oversized_status =
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
            if !oversized_status {
                return None;
            }
            let message = error_obj
                .and_then(|e_obj| e_obj.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_lowercase();
            if openai_context_length_prose_scan(&message) {
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
        // Identical to ResponsesReader::classify — both emit the same OpenAI error envelope, so the
        // mapping is single-sourced in `super::openai_family::openai_classify`.
        super::openai_family::openai_classify(status, body)
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        // Extract scalar fields and extra
        let _model = obj.get("model").and_then(|v| v.as_str()).map(String::from);

        // Read the caller's output-token cap. `max_tokens` is the legacy field; `max_completion_tokens`
        // is the current Chat Completions parameter and is MANDATORY for reasoning models (o1/o3/...),
        // which REJECT `max_tokens`. Fall back to `max_completion_tokens` when `max_tokens` is absent so
        // a request carrying only the modern field still populates the modeled IR `max_tokens`. Without
        // this, the value stays only in `extra` and is stripped at the cross-protocol seam (extra is
        // cleared there), silently dropping the caller's explicit limit on e.g. OpenAI -> Anthropic.
        // Narrow with `u32::try_from` (NOT a bare `as u32`): a value above `u32::MAX` (or negative)
        // would otherwise wrap/truncate silently into a tiny or nonsensical token cap. `as_u64`
        // already rejects negatives and non-integers, `try_from` rejects > u32::MAX, and the final
        // `> 0` filter rejects a zero cap (an invalid limit, not a real bound). This matches the
        // hardened sibling readers (gemini/anthropic/cohere/bedrock) while preserving the existing
        // non-positive-rejection contract.
        let max_tokens = obj
            .get("max_tokens")
            .or_else(|| obj.get("max_completion_tokens"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&v| v > 0);
        // Remember whether the cap arrived as `max_completion_tokens` (and NOT `max_tokens`) so a
        // same-protocol OpenAI passthrough to an o1/o3 reasoning model re-emits `max_completion_tokens`
        // (which those models require) rather than the canonical `max_tokens` (which they 400 on). Only
        // record when `max_tokens` is genuinely absent — if both are present the writer's canonical
        // `max_tokens` is correct. The sentinel rides `extra` and is cleared on the cross-protocol seam,
        // so it scopes to same-protocol exactly.
        let max_completion_tokens_was_source =
            !obj.contains_key("max_tokens") && obj.contains_key("max_completion_tokens");
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        // Phase 0 first-class sampling/output controls now promoted out of `extra` to first-class IR
        // fields (read in OpenAI's native top-level shape). `frequency_penalty`/`presence_penalty` are
        // floats; `seed`/`n` are integers; `response_format` is the raw object (json_object / json_schema),
        // stored verbatim so the writer can re-emit it unchanged.
        let frequency_penalty = obj.get("frequency_penalty").and_then(|v| v.as_f64());
        let presence_penalty = obj.get("presence_penalty").and_then(|v| v.as_f64());
        let seed = obj.get("seed").and_then(|v| v.as_i64());
        let n = obj
            .get("n")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let response_format = obj
            .get("response_format")
            .and_then(read_openai_response_format);
        // OpenAI's `stop` is a string OR an array of strings; normalize to the IR's Vec<String>.
        // OpenAI has NO top_k knob, so `top_k` stays None (its writer omits it too).
        let stop = crate::ir::read_stop_sequences(obj.get("stop"));
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Handle messages array
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            let msgs_arr = messages_val.as_array().ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            })?;

            for msg_val in msgs_arr.iter() {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");
                let content_val = msg_val.get("content");

                let role = match role_str {
                    // OpenAI's o1/o3 reasoning models replace "system" with "developer" (the
                    // Responses API reader already treats them as equivalent). Map both to the IR
                    // System role so a developer-role turn flows through the existing
                    // System-promotion path below rather than being 400ed by the catch-all.
                    "developer" | "system" => crate::ir::IrRole::System,
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

                // Promote EVERY system-role message to the top-level system field, regardless of
                // position. OpenAI permits system turns anywhere in the array, but Anthropic (and
                // the IR contract) require system content to live in the top-level `system` field —
                // a System-role IrMessage placed inside the messages array would be rendered as
                // `"role": "system"` by the Anthropic writer and rejected with a 400. We therefore
                // never push a System IrMessage; we accumulate its content into system_blocks.
                if role == crate::ir::IrRole::System {
                    let blocks_before = system_blocks.len();
                    if let Some(content) = content_val {
                        if let Some(text) = content.as_str() {
                            system_blocks.push(crate::ir::IrBlock::Text {
                                text: text.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(arr) = content.as_array() {
                            for block_val in arr {
                                system_blocks.push(read_openai_block(block_val)?);
                            }
                        }
                    }
                    // A present-but-degenerate system message (e.g. content omitted, null, or an
                    // empty array) must not silently vanish: emit an empty Text block so the system
                    // turn is preserved rather than dropped. `content_val.is_none()` (key absent)
                    // also lands here, which matches treating an empty system turn as present.
                    if system_blocks.len() == blocks_before {
                        system_blocks.push(crate::ir::IrBlock::Text {
                            text: String::new(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                } else {
                    let mut msg_content = Vec::new();

                    // For a Tool-role message the `content` payload is the tool RESULT: it is
                    // captured below as the `ToolResult` block's inner content (mirroring the native
                    // shape). Pushing it ALSO as a standalone Text block here duplicated the tool
                    // output into two IR blocks — and on a Tool->OpenAI write that surfaced as a
                    // spurious extra `{"role":"tool"}` message carrying the same text. So skip the
                    // standalone-content projection for Tool-role messages; the ToolResult path owns
                    // the tool content. User/assistant/system content is projected as before.
                    if role != crate::ir::IrRole::Tool {
                        if let Some(cv) = content_val {
                            if let Some(text) = cv.as_str() {
                                msg_content.push(crate::ir::IrBlock::Text {
                                    text: text.to_string(),
                                    cache_control: None,
                                    citations: Vec::new(),
                                });
                            } else if let Some(arr) = cv.as_array() {
                                for block_val in arr {
                                    let block = read_openai_block(block_val)?;
                                    msg_content.push(block);
                                }
                            }
                        }
                    }

                    // Handle tool_calls for assistant messages
                    if role == crate::ir::IrRole::Assistant {
                        if let Some(tool_calls) = msg_val.get("tool_calls") {
                            if let Some(tc_arr) = tool_calls.as_array() {
                                for tc_val in tc_arr {
                                    let id = tc_val
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let func = tc_val.get("function").ok_or(IrError {
                                        class: StatusClass::ClientError,
                                        provider_signal: Some(
                                            crate::proto::SIGNAL_IR_PARSE.to_string(),
                                        ),
                                        retry_after: None,
                                    })?;
                                    let name = func
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let arguments = func
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

                    // Handle tool results
                    if role == crate::ir::IrRole::Tool {
                        let tool_call_id = msg_val
                            .get("tool_call_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        // OpenAI tool-message `content` may be EITHER a plain string OR an array of
                        // content parts (e.g. `[{"type":"text","text":"..."}]`), both legal per the
                        // current Chat Completions spec. The prior `as_str().unwrap_or("")` handled
                        // only the string form and silently collapsed array-form tool output to an
                        // empty string, dropping the tool result on the cross-protocol path. We now
                        // mirror the user/assistant content handling: a string is used verbatim; an
                        // array is parsed part-by-part via `read_openai_block` and its text parts are
                        // concatenated. Non-text parts (which carry no textual payload) contribute
                        // nothing, matching how a native backend would render the same array.
                        let content_text = match content_val {
                            Some(serde_json::Value::String(s)) => s.clone(),
                            Some(serde_json::Value::Array(parts)) => {
                                let mut acc = String::new();
                                for part in parts {
                                    if let Ok(crate::ir::IrBlock::Text { text, .. }) =
                                        read_openai_block(part)
                                    {
                                        acc.push_str(&text);
                                    }
                                }
                                acc
                            }
                            Some(_) | None => String::new(),
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
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_openai_tool(tool_val)?);
            }
        }

        // Collect unmodeled top-level keys into extra (excluding modeled ones). The fields the IR
        // models as first-class — model, messages, tools, max_tokens, temperature, top_p, stop, stream,
        // tool_choice, and (Phase 0) frequency_penalty, presence_penalty, seed, n, response_format — are
        // excluded; everything else (logit_bias, …) flows through `extra` verbatim so a SAME-protocol
        // OpenAI passthrough reaches the upstream unchanged.
        //
        // Phase 0: frequency_penalty / presence_penalty / seed / n / response_format are now promoted to
        // first-class IR fields (read above) and excluded here, so they no longer linger in `extra` —
        // otherwise the writer would double-emit them (once from the typed field, once from the extra
        // sweep). Cross-protocol mapping of these to Gemini/Anthropic/Bedrock analogs is handled by the
        // translate seam (`forward.rs`).
        //
        // The set is a compile-time constant, so it is built ONCE into a process-global `OnceLock`
        // and shared by every `read_request` call instead of being re-allocated and re-hashed per
        // request on the ingress hot path.
        let modeled_keys = modeled_request_keys();

        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        // Stamp the source-key sentinel when the cap arrived as `max_completion_tokens` (and
        // only when it produced a usable value, so we never claim a phantom cap). Same-protocol only:
        // `extra` is cleared on the cross-protocol seam.
        if max_completion_tokens_was_source && max_tokens.is_some() {
            extra.insert(
                MAX_COMPLETION_TOKENS_SENTINEL.to_string(),
                serde_json::Value::Bool(true),
            );
        }

        // `tool_choice` is a first-class IR control so a forced/targeted directive survives
        // the cross-protocol seam instead of degrading to `auto`. Read it from the native shape here.
        let tool_choice = read_openai_tool_choice(obj.get("tool_choice"));

        // Cross-protocol carries with an Anthropic analog: `user` <-> `metadata.user_id`,
        // `parallel_tool_calls` <-> `!tool_choice.disable_parallel_tool_use`.
        let user = obj
            .get("user")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let parallel_tool_calls = obj.get("parallel_tool_calls").and_then(|v| v.as_bool());

        // The reasoning ASK in chat-completions spelling: a top-level `reasoning_effort` word.
        // Promoted so it carries to Anthropic/Gemini thinking budgets via the effort table.
        let reasoning = obj
            .get("reasoning_effort")
            .and_then(|v| v.as_str())
            .and_then(crate::ir::IrReasoningEffort::parse)
            .map(crate::ir::IrReasoningAsk::Effort);

        // Logprobs ask, carried first-class so it reaches a Gemini backend as
        // `generationConfig.responseLogprobs`/`logprobs` (and back).
        let logprobs = obj.get("logprobs").and_then(|v| v.as_bool());
        let top_logprobs = obj
            .get("top_logprobs")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        Ok(crate::ir::IrRequest {
            reasoning,
            reasoning_budgets: None,
            logprobs,
            top_logprobs,
            user,
            parallel_tool_calls,
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k: None,
            stop,
            tool_choice,
            stream,
            frequency_penalty,
            presence_penalty,
            seed,
            n,
            response_format,
            extra,
        })
    }

    /// OpenAI's flat stream → IR block-structured events. One chat.completion.chunk
    /// may carry role + content + finish at once → up to several IR events. State synthesizes the
    /// block boundaries OpenAI doesn't have.
    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        // [DONE] sentinel (or any non-object) carries no IR events.
        if data.as_str() == Some(crate::proto::SSE_DONE_SENTINEL) {
            return out;
        }

        // 1. MessageStart exactly once (on the first chunk, regardless of delta.role). Capture the
        //    chunk's top-level identity (`id` = "chatcmpl-...", `created` = unix secs, `model`) so a
        //    same-protocol passthrough stream re-emits it verbatim. Every OpenAI chunk carries these;
        //    we read them off whichever chunk happens to be first.
        if !state.started {
            state.started = true;
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: data.get("id").and_then(|v| v.as_str()).map(String::from),
                created: data.get("created").and_then(|v| v.as_u64()),
                model: data.get("model").and_then(|v| v.as_str()).map(String::from),
            });
        }

        let choice0 = data
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first());
        let delta = choice0.and_then(|c| c.get("delta"));

        // 2. Reasoning (chain-of-thought) → a Thinking block at index 0, ahead of the answer. When
        //    present it shifts the text/tool indices up by one (`offset`) so the thinking block
        //    precedes them. Reasoning streams before content on these models.
        //
        //    GATE: only honor a reasoning delta as a Thinking-at-index-0 block while the answer phase
        //    has NOT started (no text block and no tool blocks opened yet). A late reasoning delta
        //    arriving after text/tools have opened would otherwise flip `reasoning_seen`, bumping
        //    `offset` from 0 to 1 and retroactively shifting the IR index of ALREADY-OPENED blocks —
        //    corrupting BlockStart/BlockStop pairing downstream. Once the answer phase is underway,
        //    index 0 is no longer available for a thinking block, so the stray reasoning is dropped.
        if let Some(reasoning) = delta
            .and_then(|d| d.get("reasoning_content").or_else(|| d.get("reasoning")))
            .and_then(|r| r.as_str())
            .filter(|_| !state.text_block_open && state.open_tools.is_empty())
        {
            if !reasoning.is_empty() {
                state.reasoning_seen = true;
                if !state.thinking_block_open {
                    state.thinking_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: 0,
                        block: crate::ir::IrBlockMeta::Thinking,
                    });
                }
                out.push(IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: crate::ir::IrDelta::ThinkingDelta(reasoning.to_string()),
                });
            }
        }

        // Index offset: a thinking block (when present) owns index 0, so text/tools shift up by one.
        let offset = usize::from(state.reasoning_seen);
        // Where text lands. Two arrival orders must both stay collision-free and stable:
        //   - text-FIRST (no tools open yet): `offset + 0` == `offset` — index 0 (or 1 behind a
        //     thinking block), exactly as before, so existing text-first tests are unchanged.
        //   - tool-FIRST (tools already open): text cannot reuse a slot a tool already claimed, so it
        //     lands just PAST the open tools (`offset + open_tools.len()`).
        // Once the text block has actually opened, `state.text_index` is `Some` and pins the slot for
        // the rest of the stream (via `unwrap_or`), so the finish-path `BlockStop{index: text_index}`
        // still pairs with the open-time `BlockStart` even though more tools may open afterward.
        let text_index = state.text_index.unwrap_or(offset + state.open_tools.len());

        // 3. Text content → close any open thinking block first, then open the text block + a
        //    TextDelta. Text owns index `offset` (0 normally, 1 when a thinking block precedes it).
        if let Some(content) = delta
            .and_then(|d| d.get("content"))
            .and_then(|c| c.as_str())
        {
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            if !state.text_block_open {
                state.text_block_open = true;
                // Persist that a text block now occupies `text_index` (the slot just past any
                // thinking block). Tool-call indices key off `state.text_index.is_some()` so they
                // reserve a slot for text ONLY when text actually appears — see the `text_base`
                // derivation below.
                state.text_index = Some(text_index);
                out.push(IrStreamEvent::BlockStart {
                    index: text_index,
                    block: crate::ir::IrBlockMeta::Text,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: text_index,
                delta: crate::ir::IrDelta::TextDelta(content.to_string()),
            });
        }

        // 3b. Per-chunk logprobs ride the CHOICE (not the delta): `choices[].logprobs.content[]`
        //     alongside the content delta. Carry them as a LogprobsDelta on the text block's index
        //     so a foreign-dialect stream (e.g. a Gemini client) can re-emit them natively. A
        //     logprobs-only chunk (no content) still opens the text block so the delta has a block
        //     to attach to.
        let lp_entries = read_openai_logprobs(choice0.and_then(|c| c.get("logprobs")));
        if !lp_entries.is_empty() {
            if !state.text_block_open {
                // Close any still-open thinking block FIRST (a logprobs-only chunk can arrive while
                // the thinking block is open — e.g. a reasoning backend that streams logprobs). Without
                // this the text block opens at `text_index` while the thinking block at 0 stays open,
                // leaving two blocks open and an unbalanced IR stream — the same guard steps 3 and 4 have.
                if state.thinking_block_open {
                    state.thinking_block_open = false;
                    out.push(IrStreamEvent::BlockStop { index: 0 });
                }
                state.text_block_open = true;
                state.text_index = Some(text_index);
                out.push(IrStreamEvent::BlockStart {
                    index: text_index,
                    block: crate::ir::IrBlockMeta::Text,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: state.text_index.unwrap_or(text_index),
                delta: crate::ir::IrDelta::LogprobsDelta(lp_entries),
            });
        }

        // 4. Tool calls → IR block index = oai_idx + text_base + offset. `offset` (0/1) is the
        //    thinking slot; `text_base` (0/1) reserves index for the text block ONLY when text has
        //    actually appeared. Mirrors the Gemini reader: a tool-only stream (no text) yields
        //    0-based tool indices instead of the prior unconditional +1, which left tool indices
        //    1-based and broke cross-protocol tool-call ordering (Anthropic/OpenAI writers key on
        //    index). BlockStart on first sight (id+name present), InputJsonDelta for streamed
        //    arguments.
        if let Some(tcs) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(|t| t.as_array())
        {
            // 0 when no text block has opened, 1 once one has (then the text block owns the slot
            // just below the tools).
            let text_base = usize::from(state.text_index.is_some());
            // A tool call means the answer phase has begun; close any still-open thinking block.
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            for tc in tcs {
                // Bound the upstream-supplied tool-call index before it touches our index
                // arithmetic. A crafted/proxied chunk can carry `"index": u64::MAX`; casting that
                // raw to `usize` and computing `oai_idx + text_base + offset` overflows — panicking on the
                // request path in debug builds and silently wrapping to a near-zero index in release
                // (corrupting the IR block sequence delivered downstream). OpenAI documents at most
                // 128 parallel tool calls, so any larger index is malformed; clamp to MAX_TOOL_INDEX
                // and compute the IR index with checked arithmetic, skipping the chunk if it still
                // would not fit (never reachable at this cap, but keeps the path panic-free).
                let oai_idx = tc
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .map_or(0, |v| v.min(MAX_TOOL_INDEX) as usize);
                let ir_idx = match oai_idx
                    .checked_add(text_base)
                    .and_then(|n| n.checked_add(offset))
                {
                    Some(idx) => idx,
                    None => continue,
                };
                let func = tc.get("function");
                if let Some(name) = func.and_then(|f| f.get("name")).and_then(|n| n.as_str()) {
                    // Cap the number of DISTINCT open tool calls per stream. Without this, a
                    // pathological backend emitting unbounded unique indices would grow `open_tools`
                    // (and the emitted BlockStart count) without limit — a per-request memory-
                    // exhaustion DoS. The cap matches OpenAI's documented parallel-tool-call limit;
                    // an index beyond it that is not already open is treated as argument deltas for
                    // an already-open block (its BlockStart is suppressed) rather than opening a new
                    // one. An already-open index is always honored so in-flight blocks keep flowing.
                    let already_open = state.open_tools.contains(&oai_idx);
                    if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                        let id = tc
                            .get("id")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();
                        state.open_tools.insert(oai_idx);
                        // Record the IR index this tool's BlockStart was emitted with so the
                        // finish-path BlockStop replays it VERBATIM. `text_base` is derived from
                        // `state.text_index.is_some()` at open time and can change once text arrives
                        // after this tool; recomputing the base at close would diverge. Persisting the
                        // exact emitted index keeps every BlockStop paired with its BlockStart.
                        state.tool_ir_index.insert(oai_idx, ir_idx);
                        out.push(IrStreamEvent::BlockStart {
                            index: ir_idx,
                            block: crate::ir::IrBlockMeta::ToolUse {
                                id,
                                name: name.to_string(),
                            },
                        });
                    }
                }
                if let Some(args) = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(|a| a.as_str())
                {
                    // Only route argument deltas to indices we actually opened a BlockStart for;
                    // otherwise an over-cap index would emit a delta against a block that was never
                    // started, corrupting the downstream stream.
                    if state.open_tools.contains(&oai_idx) {
                        // C3: emit the arg delta at the IR index this tool's BlockStart was recorded
                        // with (`tool_ir_index`), NOT the freshly recomputed `ir_idx`. The OpenAI flat
                        // stream lets text arrive AFTER a tool opens; once text is present the tool's
                        // recomputed base shifts by one, so emitting at `ir_idx` here would point the
                        // arg JSON delta at the WRONG block (corrupting tool-call JSON cross-protocol).
                        // Replaying the recorded BlockStart index keeps every delta paired with its
                        // block. Falls back to `ir_idx` only if (impossibly) no index was recorded.
                        let index = state.tool_ir_index.get(&oai_idx).copied().unwrap_or(ir_idx);
                        out.push(IrStreamEvent::BlockDelta {
                            index,
                            delta: crate::ir::IrDelta::InputJsonDelta(args.to_string()),
                        });
                    }
                }
            }
        }

        // Read top-level `usage` INDEPENDENTLY of finish_reason. With
        // `stream_options: {include_usage: true}` the OpenAI API emits usage in a SEPARATE trailing
        // chunk whose `choices` array is EMPTY and which carries NO finish_reason — for that chunk
        // `choice0` is None, so the finish_reason branch below never runs. Reading usage here (rather
        // than only inside the finish_reason block, as the prior code did) ensures the trailing
        // usage chunk is not silently discarded, preserving token accounting across translated /
        // passthrough OpenAI streams that follow the spec'd trailing-usage convention.
        //
        // CRITICAL: under `include_usage` the OpenAI API sets `usage: null` on EVERY non-final chunk.
        // `serde_json::Value::get("usage")` returns `Some(Value::Null)` for a present-but-null key,
        // so a naive `.map(...)` would synthesize `Some(IrUsage{0,0,..})` on every content chunk and
        // (via the trailing-usage branch below) emit a spurious mid-stream `MessageDelta` per chunk.
        // Filter to a real usage OBJECT so `usage: null` reads as `None`.
        let chunk_usage = data.get("usage").filter(|u| u.is_object()).map(|u| {
            let prompt_tokens = u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            let cached = u
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64());
            IrUsage {
                // NORMALIZE to the additive-cache convention: OpenAI's `prompt_tokens` is a
                // TOTAL that already INCLUDES the cached prefix, so subtract the cached tokens
                // to leave only the uncached input. `saturating_sub` guards a hostile/odd
                // upstream where `cached_tokens > prompt_tokens` (would otherwise underflow).
                input_tokens: prompt_tokens.saturating_sub(cached.unwrap_or(0)),
                output_tokens: u
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cache_creation_input_tokens: None,
                cache_read_input_tokens: cached,
            }
        });

        // 5. finish_reason → close open blocks (text first, then tools ascending), MessageDelta, MessageStop.
        let finish_reason = choice0
            .and_then(|c| c.get("finish_reason"))
            .and_then(|r| r.as_str());
        if let Some(fr) = finish_reason {
            // Close in order: thinking (0, if it never yielded to text), then text, then tools.
            if state.thinking_block_open {
                state.thinking_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: 0 });
            }
            if state.text_block_open {
                state.text_block_open = false;
                out.push(IrStreamEvent::BlockStop { index: text_index });
            }
            // Replay each tool's BlockStop at the EXACT IR index its BlockStart was emitted with,
            // read back from `tool_ir_index`. Recomputing the index here (as the prior code did, from
            // a `text_index.is_some()` base) diverged whenever text arrived AFTER a tool opened: the
            // tool's BlockStart used the base captured at open time (text absent → 0), but the close
            // base would then read 1 (text now present), so BlockStop pointed at the wrong index.
            // The recorded map is keyed by `oai_idx` exactly like `open_tools`; fall back to the
            // open-time arithmetic only for the impossible case of an open tool with no recorded
            // index (keeps the path total without a catch-all panic).
            let tool_ir_index = std::mem::take(&mut state.tool_ir_index);
            for oai_idx in std::mem::take(&mut state.open_tools) {
                let index = tool_ir_index.get(&oai_idx).copied().unwrap_or_else(|| {
                    let text_base = usize::from(state.text_index.is_some());
                    oai_idx.saturating_add(text_base).saturating_add(offset)
                });
                out.push(IrStreamEvent::BlockStop { index });
            }
            let stop_reason = Some(read_openai_stop_reason(fr));
            let usage = chunk_usage.unwrap_or(IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            });
            out.push(IrStreamEvent::MessageDelta {
                stop_reason,
                // OpenAI has no stop_sequence analog in its stream.
                stop_sequence: None,
                usage,
            });
            out.push(IrStreamEvent::MessageStop);
        } else if let Some(usage) = chunk_usage {
            // Trailing usage-only chunk (include_usage convention): no finish_reason and (per the
            // null-filter above) a REAL top-level `usage` object with an EMPTY `choices` array. Emit a
            // MessageDelta carrying the late usage so consumers that fold it (Bedrock ingress builds
            // its single `metadata` frame from this) see real token counts instead of zeros.
            //
            // `choice0.is_none()` guards the genuine usage-only chunk shape: a normal content chunk
            // (which still carries a finish-less choice) never reaches this branch even if some
            // non-standard intermediary attached a real usage object to it. This reader is ingress-
            // AGNOSTIC, so it always emits the faithful IR; the cross-protocol ORDERING concern (this
            // delta arrives after the finish chunk's MessageStop, which would be an invalid
            // `message_delta`-after-`message_stop` frame for non-Bedrock SSE ingress) is handled where
            // the ingress IS known — `StreamTranslate::translate_event` drops a terminal-class
            // MessageDelta that arrives after MessageStop for non-eventstream ingress.
            if choice0.is_none() {
                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence: None,
                    usage,
                });
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
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;

        // Get choices array
        let choices_val = obj.get("choices").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;
        let choices = choices_val.as_array().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;

        if choices.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
                retry_after: None,
            });
        }

        let choice = &choices[0];

        // Parse role (should be "assistant")
        let message_val = choice.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;
        let _role_str = message_val
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("");

        // Parse content (may be null)
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();

        // Reasoning models on OpenAI-compatible providers (e.g. GLM, DeepSeek) emit the
        // chain-of-thought in a separate `reasoning_content` (or `reasoning`) field. Map it to a
        // Thinking block — ahead of the answer — so it survives translation to protocols that have
        // one (e.g. Anthropic). (Protocols without a thinking concept drop it on write, as before.)
        for key in ["reasoning_content", "reasoning"] {
            if let Some(r) = message_val.get(key).and_then(|v| v.as_str()) {
                if !r.is_empty() {
                    content.push(crate::ir::IrBlock::Thinking {
                        text: r.to_string(),
                        signature: None,
                        redacted: false,
                        cache_control: None,
                    });
                    break;
                }
            }
        }

        if let Some(content_val) = message_val.get("content") {
            if let Some(text) = content_val.as_str() {
                if !text.is_empty() {
                    content.push(crate::ir::IrBlock::Text {
                        text: text.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                }
            } else if let Some(arr) = content_val.as_array() {
                for block_val in arr {
                    let block = read_openai_block(block_val)?;
                    // Only include text blocks from array content (OpenAI image_url not supported in response)
                    if !matches!(block, crate::ir::IrBlock::Image { .. }) {
                        content.push(block);
                    }
                }
            }
        }

        // Parse tool_calls
        if let Some(tool_calls_val) = message_val.get("tool_calls") {
            if let Some(tc_arr) = tool_calls_val.as_array() {
                for tc_val in tc_arr {
                    let id = tc_val
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let func = tc_val.get("function").ok_or(IrError {
                        class: StatusClass::ClientError,
                        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
                        retry_after: None,
                    })?;
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let arguments = func
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

        // Parse finish_reason → stop_reason mapping
        let finish_reason = choice
            .get("finish_reason")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        let stop_reason = if finish_reason.is_empty() {
            None
        } else {
            Some(read_openai_stop_reason(finish_reason))
        };

        // Parse usage. Treat an absent `usage` object leniently — fall back to zero counts rather
        // than hard-erroring. A missing `usage` is an upstream response-format quirk (a
        // mock/staging/proxy OpenAI-compatible backend that omits it on an otherwise valid 200
        // completion), NOT a client mistake: returning a `ClientError` here mislabels the cause and
        // makes forward.rs discard a valid 200 body and emit a spurious 500. The sibling Gemini and
        // Cohere readers tolerate the same condition with a zero-usage fallback. `usage_val` is an
        // `Option`, so each token lookup below already defaults to 0.
        let usage_val = obj.get("usage");
        let cache_read_input_tokens = usage_val
            .and_then(|u| u.get("prompt_tokens_details"))
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64());

        let usage = crate::ir::IrUsage {
            // NORMALIZE to the additive-cache convention: OpenAI's `prompt_tokens` is a TOTAL that
            // already INCLUDES the cached prefix, so subtract the cached tokens to leave only the
            // uncached input. `saturating_sub` guards an odd upstream where cached > prompt_tokens.
            input_tokens: usage_val
                .and_then(|u| u.get("prompt_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .saturating_sub(cache_read_input_tokens.unwrap_or(0)),
            output_tokens: usage_val
                .and_then(|u| u.get("completion_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None, // OpenAI doesn't provide this split
            cache_read_input_tokens,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream's response identity so same-protocol (OpenAI→OpenAI) passthrough
        // preserves it exactly: `id` ("chatcmpl-..."), `created` (unix secs), `system_fingerprint`.
        // (`object` is fixed "chat.completion" and re-emitted by the writer; `usage.total_tokens` is
        // derivable from prompt+completion, so it is recomputed on write rather than stored.)
        let id = obj.get("id").and_then(|v| v.as_str()).map(String::from);
        let created = obj.get("created").and_then(|v| v.as_u64());
        let system_fingerprint = obj
            .get("system_fingerprint")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Per-token logprobs from the first choice, carried neutrally so a foreign-dialect caller
        // (e.g. Gemini) receives them in its own shape.
        let logprobs = read_openai_logprobs(choices[0].get("logprobs"));

        Ok(crate::ir::IrResponse {
            logprobs,
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint,
            stop_sequence: None,
        })
    }
}

/// Render an IR ToolUse `input` value as the OpenAI `function.arguments` string.
///
/// OpenAI carries tool-call arguments as a *string* of JSON. The reader stores well-formed
/// arguments as a parsed `Value`, but falls back to `Value::String(raw)` when the upstream sent
/// arguments that are not valid JSON (a streaming-partial or malformed tool call). Re-serializing
/// such a `Value::String` via `crate::json::to_string` would JSON-encode the string a second time —
/// emitting an escaped, quoted blob on the wire (double-encoding). Emit a `Value::String` verbatim
/// so the original argument text round-trips unchanged; any other `Value` is serialized normally.
fn tool_arguments_to_string(input: &serde_json::Value) -> String {
    match input {
        serde_json::Value::String(s) => s.clone(),
        other => crate::json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    }
}

/// Read an OpenAI-format block from JSON.
fn read_openai_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "text" => {
            let text_val = obj.get("text");
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        "image_url" => {
            let image_obj = obj.get("image_url").ok_or(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            })?;
            let url = image_obj.get("url").and_then(|v| v.as_str()).unwrap_or("");
            // The IR `Image` contract (set by the Anthropic reader) is: `media_type` = a real MIME
            // type (e.g. "image/png") and `data` = the raw base64 payload. The Anthropic writer
            // renders that as a `{"type":"base64", "media_type":..., "data":...}` source. The prior
            // code stored `media_type: "image"` (a literal, not a MIME type) and `data: <the full
            // url>`, which the Anthropic writer then emitted as a base64 source whose data was a
            // URL — an invalid Anthropic request. For a `data:<mime>;base64,<payload>` URI we now
            // split out the real MIME type and payload so the cross-protocol image is valid.
            Ok(crate::ir::IrBlock::Image {
                source: super::parse_image_url(url),
                cache_control: None,
            })
        }
        // OpenAI gpt-4o-and-later responses carry `refusal` content parts; a client replaying its
        // OpenAI conversation history through busbar will include them. Map a refusal to a Text block
        // carrying the refusal string so the turn survives translation rather than being rejected with
        // a 400 (the prior `_ => Err` behavior turned legitimate replayed history into a hard error).
        "refusal" => {
            let text = obj
                .get("refusal")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        // Forward-compatibility: an unknown/future content-part type (one OpenAI adds after this
        // build) must not break otherwise-valid conversation history. Degrade gracefully to an empty
        // Text block — preserving the part's position in the turn without injecting foreign data —
        // rather than failing the whole request with a ClientError. This is a content-shape match, not
        // a disposition/breaker match, so a named graceful-degradation arm is correct here.
        other => {
            let _ = other;
            Ok(crate::ir::IrBlock::Text {
                text: String::new(),
                cache_control: None,
                citations: Vec::new(),
            })
        }
    }
}

/// Read an OpenAI-format tool from JSON.
fn read_openai_tool(tool_val: &serde_json::Value) -> Result<crate::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
        retry_after: None,
    })?;

    // OpenAI nests the tool definition under `function` ({"type":"function","function":{...}}).
    // Read from there, falling back to the top level so a flattened/native-shaped tool still works.
    let src = obj
        .get("function")
        .and_then(|f| f.as_object())
        .unwrap_or(obj);

    let name = src
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = src
        .get("description")
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = src
        .get("parameters")
        .or_else(|| src.get("input_schema"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(crate::ir::IrTool {
        name,
        description,
        input_schema,
        cache_control: None,
    })
}

/// Read an OpenAI-format `tool_choice` into the IR union. Shapes: the strings `"auto"` /
/// `"none"` / `"required"`, or `{"type":"function","function":{"name":"X"}}` for a forced specific
/// tool. Absent or any unrecognized shape yields `None` (the safe default — no directive emitted).
fn read_openai_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    match val? {
        serde_json::Value::String(s) => match s.as_str() {
            "auto" => Some(crate::ir::IrToolChoice::Auto),
            "none" => Some(crate::ir::IrToolChoice::None),
            "required" => Some(crate::ir::IrToolChoice::Required),
            _ => None,
        },
        serde_json::Value::Object(o) => {
            if o.get("type").and_then(|t| t.as_str()) == Some(TOOL_TYPE_FUNCTION) {
                o.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
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

/// The OpenAI stream-start identity replayed onto every `chat.completion.chunk` (see
/// `OpenAiStreamFraming`). Captured from the opening chunk the OpenAI writer emits for the IR
/// `MessageStart` (which already synthesizes a stable `id`/`created` when the cross-protocol backend
/// supplied none), so the whole stream shares ONE identity.
#[derive(Clone)]
struct OpenAiChunkIdentity {
    id: serde_json::Value,
    created: serde_json::Value,
    model: Option<serde_json::Value>,
}

/// OpenAI-INGRESS per-stream framing. Holds the latched stream identity and applies the two
/// OpenAI-only client-facing wire quirks the shared `StreamTranslate` translator must NOT name itself:
/// (1) the real OpenAI API repeats the top-level `id`/`created`/`model` on EVERY
/// `chat.completion.chunk`, but the writer emits them only on the opening (role) chunk — so this latches
/// them off the first chunk and replays them onto every later one; and (2) the native `include_usage`
/// convention emits token usage on a SEPARATE trailing chunk AFTER the finish_reason chunk, never folded
/// onto it — but the 1:1 writer FOLDS `usage` onto the finish chunk, so this un-folds it. Built per
/// stream via [`OpenAiWriter::new_stream_framing`]; its reframing runs only on the cross-protocol path
/// (the same-protocol path re-emits frames verbatim and never invokes it).
#[derive(Default)]
struct OpenAiStreamFraming {
    /// The stream-start identity, latched from the first `chat.completion.chunk` that carries an `id`
    /// (the opening role chunk) and replayed onto every later chunk. `None` until that first chunk.
    chunk_identity: Option<OpenAiChunkIdentity>,
}

impl super::StreamFraming for OpenAiStreamFraming {
    fn on_egress_chunk(&mut self, chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
        // (a) Identity replay, then (b) the include_usage un-fold — in this order, because the trailing
        // chunk's identity is read off `chunk` AFTER the identity has been populated onto it, so both
        // frames share ONE stream identity. The `[DONE]` sentinel is a separate `finish()` literal and
        // never routed here.
        self.apply_chunk_identity(chunk);
        split_openai_trailing_usage(chunk)
    }
}

impl OpenAiStreamFraming {
    /// Capture-or-replay the OpenAI stream identity on a `chat.completion.chunk` body. On the first
    /// chunk that carries an `id` (the opening role chunk), latch `id`/`created`/`model`; on every
    /// subsequent chunk (which the writer emits WITHOUT them), inject the latched values.
    fn apply_chunk_identity(&mut self, chunk: &mut serde_json::Value) {
        let Some(obj) = chunk.as_object_mut() else {
            return;
        };
        // Only `chat.completion.chunk` bodies carry stream identity. An in-band error envelope
        // (`{"error":{...}}`) the writer may emit has no `object` field — leave it untouched.
        if obj.get("object").and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
            return;
        }
        match &self.chunk_identity {
            None => {
                // First chunk: latch its identity (the writer put id/created on the role chunk, and
                // model when the lane supplied one).
                if obj.contains_key("id") {
                    self.chunk_identity = Some(OpenAiChunkIdentity {
                        id: obj.get("id").cloned().unwrap_or(serde_json::Value::Null),
                        created: obj
                            .get("created")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        model: obj.get("model").cloned(),
                    });
                }
            }
            Some(identity) => {
                // Subsequent chunk: replay the latched identity (the writer omitted it).
                obj.entry("id".to_string())
                    .or_insert_with(|| identity.id.clone());
                obj.entry("created".to_string())
                    .or_insert_with(|| identity.created.clone());
                if let Some(model) = &identity.model {
                    obj.entry("model".to_string())
                        .or_insert_with(|| model.clone());
                }
            }
        }
    }
}

/// Split a folded-usage OpenAI finish chunk into (finish-chunk-without-usage, trailing
/// usage-only chunk). Returns `Some(trailing_chunk)` when `chunk` is a `chat.completion.chunk` that
/// carries BOTH a folded top-level `usage` object AND a terminal `finish_reason` (the shape the
/// OpenAI writer produces when it cannot emit two events); in that case the folded `usage` is
/// REMOVED from `chunk` in place and re-homed onto a fresh trailing chunk shaped exactly like a
/// native include_usage trailer: same `id`/`created`/`model`/`object`, an EMPTY `choices` array,
/// and the `usage` object. Returns `None` (leaving `chunk` untouched) for any chunk that is not a
/// usage-bearing finish chunk — non-finish chunks, finish chunks without usage, or non-chunk
/// bodies (e.g. an in-band error envelope) — so the common path is a no-op. The trailing chunk's
/// identity is read off `chunk` itself (which `OpenAiStreamFraming::apply_chunk_identity` has already
/// populated with the latched id/created/model), so both frames share ONE stream identity.
fn split_openai_trailing_usage(chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
    let obj = chunk.as_object_mut()?;
    if obj.get("object").and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
        return None;
    }
    // A native include_usage trailer carries usage ONLY on a chunk with no active choice; the
    // writer folds it onto the FINISH chunk, which has a non-null `finish_reason`. Require both a
    // present `usage` object and a terminal finish_reason so a non-finish chunk that somehow
    // carried usage is left alone (defensive — the writer only folds onto the finish chunk).
    if !obj.contains_key("usage") {
        return None;
    }
    let has_finish = obj
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c0| c0.get("finish_reason"))
        .map(|fr| !fr.is_null())
        .unwrap_or(false);
    if !has_finish {
        return None;
    }
    let usage = obj.remove("usage")?;
    // Build the trailing usage-only chunk mirroring the finish chunk's stream identity. `choices`
    // is an EMPTY array — the native include_usage trailer carries no choice. Fields absent on the
    // source chunk are simply omitted (kept faithful to what the stream already carries).
    let mut trailing = serde_json::Map::new();
    if let Some(id) = obj.get("id") {
        trailing.insert("id".to_string(), id.clone());
    }
    trailing.insert(
        "object".to_string(),
        serde_json::Value::String(OBJ_CHUNK.to_string()),
    );
    if let Some(created) = obj.get("created") {
        trailing.insert("created".to_string(), created.clone());
    }
    if let Some(model) = obj.get("model") {
        trailing.insert("model".to_string(), model.clone());
    }
    trailing.insert("choices".to_string(), serde_json::Value::Array(Vec::new()));
    trailing.insert("usage".to_string(), usage);
    Some(serde_json::Value::Object(trailing))
}

/// OpenAI writer implementation.
#[derive(Clone)]
pub(crate) struct OpenAiWriter;

impl ProtocolWriter for OpenAiWriter {
    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Shared warn+OMIT policy: a credential with bytes invalid for an HTTP header value is
        // dropped (with a protocol-named warn, never the key bytes) rather than emitting an empty
        // `Authorization:` tell. See `super::bearer_auth_headers`.
        super::bearer_auth_headers("openai", key)
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut messages_array: Vec<serde_json::Value> = Vec::new();

        // Prepend system message as first message if present. OpenAI system messages carry plain
        // text only, so every system block is projected to text EXPLICITLY here rather than via a
        // silent `if let Text` that would drop non-text blocks without a trace (the prior behavior).
        // Text and Thinking both carry textual system guidance and are forwarded; the structurally
        // text-less variants (ToolUse / ToolResult / Image) have no OpenAI system representation and
        // are projected to empty text — a documented lossy projection, not a silent drop. The match
        // is exhaustive (no `_ =>` catch-all) so a future IrBlock variant forces a compile error.
        for block in &req.system {
            let text: &str = match block {
                crate::ir::IrBlock::Text { text, .. } => text,
                crate::ir::IrBlock::Thinking { text, .. } => text,
                crate::ir::IrBlock::ToolUse { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Image { .. }
                | crate::ir::IrBlock::Json(_) => "",
            };
            messages_array.push(serde_json::json!({
                "role": "system",
                "content": text
            }));
        }

        // Add regular messages
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
                crate::ir::IrRole::System => "system",
            };

            let content_val: serde_json::Value = if msg.content.is_empty() {
                serde_json::json!("")
            } else {
                let mut content_arr: Vec<serde_json::Value> = Vec::new();

                for block in &msg.content {
                    match block {
                        crate::ir::IrBlock::Text { text, .. } => {
                            content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                        }
                        crate::ir::IrBlock::Image { source, .. } => {
                            // A URL is emitted verbatim, a base64 image re-wrapped as a data URI. A
                            // Responses `file_id` / Bedrock `s3Location` reference has no `image_url`
                            // projection (image_url_from_ir returns None) — SKIP it with a warn rather
                            // than corrupt the block.
                            match super::image_url_from_ir(source) {
                                Some(url) => content_arr.push(serde_json::json!({
                                    "type": "image_url",
                                    "image_url": { "url": url }
                                })),
                                None => tracing::warn!(
                                    "dropping unresolvable vendor-scoped image reference on OpenAI \
                                     egress: a Responses input_image.file_id or a Bedrock s3Location \
                                     has no cross-vendor analog; the block is NOT emitted"
                                ),
                            }
                        }
                        crate::ir::IrBlock::ToolUse { .. } => {
                            // ToolUse is not OpenAI message content; it is surfaced via the
                            // `tool_calls` array built for this message below (any role).
                        }
                        crate::ir::IrBlock::ToolResult { .. } => {
                            // ToolResult is not OpenAI message *content*; for a Tool-role message it
                            // is rendered as a standalone `{"role":"tool","tool_call_id":...}` entry
                            // by the tool-result path below. On a non-tool message it has no OpenAI
                            // content representation, so it is intentionally not emitted here.
                        }
                        crate::ir::IrBlock::Thinking { .. } => {
                            // Lossy-by-necessity: OpenAI Chat Completions has no thinking/reasoning
                            // content block on request input, so a Thinking block is dropped here.
                        }
                        crate::ir::IrBlock::Json(_) => {
                            // Structured-json (a Bedrock tool-result content member) has no OpenAI
                            // message-content shape; dropped here.
                        }
                    }
                }

                // A message carrying only ToolUse blocks (a tool-call-only assistant turn) yields an
                // empty content_arr: ToolUse is surfaced via `tool_calls`, not `content`. The OpenAI
                // Chat Completions API expects such messages to have `content: null`, not `[]` — some
                // validators reject an empty array alongside `tool_calls`. Emit Null in that case.
                if content_arr.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Array(content_arr)
                }
            };

            let mut msg_obj = serde_json::json!({
                "role": role_str,
                "content": content_val,
            });

            // Emit tool_calls for ANY message carrying ToolUse blocks, not only assistant ones.
            // A ToolUse on a non-assistant role is unusual but legal in the IR; gating this on the
            // assistant role silently dropped such tool calls. Building tool_calls for the block's
            // own message is non-lossy and keeps the id/arguments round-tripping.
            {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        // Serialize input to JSON string
                        let args_str = tool_arguments_to_string(input);
                        // Preserve the original tool_call id verbatim — it must round-trip so the
                        // assistant tool_call correlates with the tool-result `tool_call_id`.
                        tool_calls_arr.push(serde_json::json!({
                            "type": TOOL_TYPE_FUNCTION,
                            "id": id,
                            "function": {
                                "name": name,
                                "arguments": args_str
                            }
                        }));
                    }
                }

                if !tool_calls_arr.is_empty() {
                    msg_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
                }
            }

            // Handle tool results. Emit a flat `{"role":"tool",...}` entry for ANY message whose
            // content carries ToolResult blocks, REGARDLESS of the message role — not only
            // IrRole::Tool. A Gemini `functionResponse` decodes to an IrRole::User message carrying a
            // ToolResult block (and an Anthropic tool_result lives on a User-role message too); gating
            // this on IrRole::Tool SILENTLY DROPPED that tool result on Gemini→OpenAI / Anthropic→OpenAI
            // (the ToolResult arm in the content loop above is a no-op, and `tool_calls` only carries
            // ToolUse). Keying on the presence of a ToolResult block — the writer-side, source-agnostic
            // fix — surfaces it correctly for every source protocol.
            let has_tool_result = msg
                .content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolResult { .. }));
            if has_tool_result {
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let mut tool_result_obj = serde_json::json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": "",
                        });

                        // Concatenate text content with NO separator, matching the OpenAI READ path
                        // (which uses `push_str` with no separator at the symmetric site). Joining
                        // with a space injected spurious spaces between adjacent text blocks on an
                        // Anthropic→OpenAI ToolResult hop (`["A","B"]` → `"A B"`), corrupting content
                        // that is boundary-sensitive (base64, JSON split across blocks). `concat()`
                        // keeps the cross-protocol round-trip lossless.
                        if !content.is_empty() {
                            let text_parts: Vec<String> = content
                                .iter()
                                .filter_map(|b| {
                                    if let crate::ir::IrBlock::Text { text, .. } = b {
                                        Some(text.clone())
                                    } else {
                                        // A non-Text ToolResult block is a Bedrock json-tool-result
                                        // sentinel (structured `{"json":...}` data) with no OpenAI
                                        // analog. Drop it WITH a warn so the loss is observable
                                        // (matches the drop-with-warn convention) rather than vanishing
                                        // silently.
                                        if super::is_json_tool_result_block(b) {
                                            tracing::warn!(
                                                "dropping structured json tool-result block on \
                                                 OpenAI egress: a Bedrock `{{\"json\":...}}` \
                                                 tool-result has no cross-protocol analog and is NOT \
                                                 emitted"
                                            );
                                        }
                                        None
                                    }
                                })
                                .collect();

                            tool_result_obj["content"] = serde_json::json!(text_parts.concat());
                        }

                        messages_array.push(tool_result_obj);
                        emitted_tool_result = true;
                    }
                }

                // A well-formed tool-result message carries ONLY ToolResult blocks, each emitted
                // above as a standalone `{"role":"tool",...}` entry; `msg_obj` is intentionally NOT
                // added for that case. But the message can ALSO carry non-ToolResult content (Text/
                // Image projected into `content_val`, or ToolUse projected into `msg_obj["tool_calls"]`)
                // — e.g. a Gemini turn that pairs a functionResponse with narration text. Previously
                // that content was silently dropped because `msg_obj` was never pushed on this path.
                // Surface it instead: push `msg_obj` when it carries any non-ToolResult payload
                // (non-null `content` or a `tool_calls` array), or when the message had NO ToolResult
                // block at all (so an otherwise-empty message is not lost). This never duplicates a
                // ToolResult — those are the standalone entries above and never appear in `content_val`.
                let msg_has_payload = msg_obj.get("content").is_some_and(|c| !c.is_null())
                    || msg_obj.get("tool_calls").is_some();
                if msg_has_payload || !emitted_tool_result {
                    messages_array.push(msg_obj);
                }
            } else {
                // No ToolResult content: add the message to the array directly (tool results are
                // handled in the branch above, keyed on the presence of a ToolResult block).
                messages_array.push(msg_obj);
            }
        }

        let mut out = serde_json::Map::new();

        // Add model from extra if present (since IrRequest doesn't have a model field)
        if let Some(model_val) = req.extra.get("model") {
            out.insert("model".to_string(), model_val.clone());
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );

        // Emit the modeled output-token cap. The reader promotes BOTH `max_tokens` and the modern
        // `max_completion_tokens` into this one IR field (so a caller's limit survives the
        // cross-protocol seam). Re-emit under the SOURCE spelling when the sentinel says the cap
        // arrived as `max_completion_tokens` — OpenAI's o1/o3 reasoning models REQUIRE
        // `max_completion_tokens` and 400 on `max_tokens`, so an OpenAI->OpenAI passthrough to such a
        // model must preserve the modern key. The sentinel only survives the same-protocol path (extra
        // is cleared cross-protocol), so a cross-protocol egress falls back to the canonical
        // `max_tokens` (other protocols have no `max_completion_tokens`). For the common
        // (non-reasoning) same-protocol case the sentinel is absent and we emit `max_tokens`.
        if let Some(max_tokens) = req.max_tokens {
            let key = if req
                .extra
                .get(MAX_COMPLETION_TOKENS_SENTINEL)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "max_completion_tokens"
            } else {
                "max_tokens"
            };
            out.insert(key.to_string(), serde_json::json!(max_tokens));
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        // Promoted sampling controls: emit `top_p` and `stop` in OpenAI's native shape. OpenAI has NO
        // top_k parameter, so `req.top_k` is intentionally NOT emitted (lossy-by-target — a source
        // protocol's top_k cannot be honored by the OpenAI API). `stop` serializes as the array form
        // (OpenAI accepts both a string and an array; the array is always valid).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if !req.stop.is_empty() {
            out.insert("stop".to_string(), serde_json::json!(req.stop));
        }

        // Phase 0 first-class sampling/output controls. Emitted in OpenAI's native top-level shape and
        // omitted entirely when None. `response_format` is written back verbatim (the raw Value read in).
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
        if let Some(seed) = req.seed {
            out.insert("seed".to_string(), serde_json::json!(seed));
        }
        if let Some(n) = req.n {
            out.insert("n".to_string(), serde_json::json!(n));
        }
        // The Anthropic-analog carries, re-emitted in OpenAI's native spelling (an Anthropic
        // `metadata.user_id` arrives here as `user`; `disable_parallel_tool_use` arrives inverted).
        if let Some(user) = &req.user {
            out.insert("user".to_string(), serde_json::json!(user));
        }
        // OpenAI rejects `parallel_tool_calls` when no tools are present ("only allowed when 'tools'
        // are specified"). An Anthropic source can carry the flag (via `disable_parallel_tool_use`)
        // on a tool-less request, so gate the emission on tools — matching the Anthropic writer,
        // which only emits its equivalent when tools are present.
        if let (Some(parallel), false) = (req.parallel_tool_calls, req.tools.is_empty()) {
            out.insert(
                "parallel_tool_calls".to_string(),
                serde_json::json!(parallel),
            );
        }
        // The reasoning carry in chat-completions spelling: `reasoning_effort`. A numeric budget
        // (Anthropic/Gemini source) is bucketized through the effort table.
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
            out.insert(
                "reasoning_effort".to_string(),
                serde_json::json!(ask.to_effort(table).as_openai_reasoning_effort()),
            );
        }
        // The logprobs ask in OpenAI's native spelling (a Gemini `responseLogprobs`/`logprobs`
        // arrives here via the IR).
        // OpenAI requires `logprobs: true` for `top_logprobs` to be valid. Force the enabling flag
        // whenever the count is present, even if the source protocol only carried the count (a
        // Gemini request with `logprobs: N` but no `responseLogprobs`) — otherwise OpenAI 400s.
        if let Some(top_logprobs) = req.top_logprobs {
            out.insert("logprobs".to_string(), serde_json::json!(true));
            out.insert("top_logprobs".to_string(), serde_json::json!(top_logprobs));
        } else if let Some(logprobs) = req.logprobs {
            out.insert("logprobs".to_string(), serde_json::json!(logprobs));
        }
        if let Some(response_format) = &req.response_format {
            out.insert(
                "response_format".to_string(),
                write_openai_response_format(response_format),
            );
        }

        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // Add tools if present. The Chat Completions API requires the NESTED tool shape
        // `{"type":"function","function":{"name":...,"description":...,"parameters":...}}` — name,
        // description, and parameters live INSIDE the `function` sub-object, not at the top level.
        // Emitting the flat `{"type":"function","name":...,"parameters":...}` shape is rejected with a
        // 400 by every native Chat Completions backend and SDK since late 2023, and the off-spec shape
        // is itself a proxy tell. `read_openai_tool` already reads from the nested `function` object,
        // so this writer is the inverse of the reader.
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut function_obj = serde_json::Map::new();
                function_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    function_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                // Map OpenAI's "parameters" to our input_schema
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                function_obj.insert("parameters".to_string(), params);

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!(TOOL_TYPE_FUNCTION));
                tool_obj.insert(
                    "function".to_string(),
                    serde_json::Value::Object(function_obj),
                );

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Emit `tool_choice` in OpenAI's native shape when present so a forced/targeted tool
        // directive translated from another protocol round-trips instead of degrading to `auto`.
        if let Some(tc) = &req.tool_choice {
            let v = match tc {
                crate::ir::IrToolChoice::Auto => serde_json::json!("auto"),
                crate::ir::IrToolChoice::None => serde_json::json!("none"),
                crate::ir::IrToolChoice::Required => serde_json::json!("required"),
                crate::ir::IrToolChoice::Tool { name } => {
                    serde_json::json!({"type": TOOL_TYPE_FUNCTION, "function": {"name": name}})
                }
            };
            out.insert("tool_choice".to_string(), v);
        }

        // Add extra fields
        for (key, value) in &req.extra {
            // The max-completion-tokens sentinel is a busbar-internal marker consumed above
            // (it selected the cap's emitted key); it is NOT a real OpenAI field, so skip it here so
            // it never leaks onto the wire (which would be an invalid body and a proxy tell).
            if key == MAX_COMPLETION_TOKENS_SENTINEL {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                id,
                created,
                model,
                ..
            } => {
                let openai_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::User
                    | crate::ir::IrRole::System
                    | crate::ir::IrRole::Tool => return None,
                };
                let delta_obj = serde_json::json!({ "role": openai_role });
                // The opening chunk carries the stream's identity (`id`, `created`, `model`); an
                // official OpenAI stream repeats these on every chunk, but emitting them on the first
                // (role) chunk is sufficient for the SDKs, which latch the id/created/model from the
                // first chunk that supplies them. When the backend supplied none (cross-protocol),
                // SYNTHESIZE a protocol-correct id/created so a native SDK accepts the stream.
                let chunk_id = id.clone().unwrap_or_else(synth_completion_id);
                let chunk_created = created.unwrap_or_else(crate::store::now);
                // `model` is REQUIRED and non-nullable in the OpenAI chunk schema. A cross-protocol
                // backend (e.g. Bedrock) whose IR carries `model: None` must not yield a model-less
                // first chunk — that fails strict SDK (Pydantic) deserialisation and is a proxy tell —
                // so fall back to DEFAULT_MODEL rather than omitting the field.
                let chunk_model = model_or_default(model.as_deref());
                let chunk = serde_json::json!({
                    "id": chunk_id,
                    "object": OBJ_CHUNK,
                    "created": chunk_created,
                    "model": chunk_model,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": null
                    }]
                });
                Some(("".to_string(), chunk))
            }
            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => None,
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Use the IR block index (canonical) so parallel tool calls keep distinct,
                    // stable indices. OpenAI SDKs route streaming argument fragments by
                    // `tool_calls[n].index`; the BlockStart and its BlockDeltas must carry the
                    // same value or the reconstructed arguments collide at index 0.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
                            "id": id,
                            "type": TOOL_TYPE_FUNCTION,
                            "function": { "name": name, "arguments": "" }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },
            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => {
                    let delta_obj = serde_json::json!({ "content": text });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrDelta::InputJsonDelta(json) => {
                    // Mirror the index emitted by the matching BlockStart so argument
                    // fragments are routed to the correct parallel tool call.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
                            "function": { "arguments": json }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                crate::ir::IrDelta::ThinkingDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no thinking stream equivalent.
                    None
                }
                crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no signature/redacted-reasoning stream analog.
                    None
                }
                crate::ir::IrDelta::CitationsDelta(_) => {
                    // L2-5: OpenAI chat-completions streaming has no citation delta shape; suppress
                    // rather than emit a non-native frame. The citation is preserved in the IR and
                    // re-emitted by any protocol that models streaming citations.
                    None
                }
                crate::ir::IrDelta::LogprobsDelta(lps) => {
                    // Streamed logprobs (e.g. a Gemini backend's per-chunk `logprobsResult`) in
                    // OpenAI's native chunk shape: `choices[].logprobs.content[]` alongside an
                    // empty delta. The SDK accumulates logprobs from chunks independently of
                    // content text, so a logprobs-only chunk parses cleanly. An empty vec carries
                    // nothing and emits no chunk.
                    if lps.is_empty() {
                        None
                    } else {
                        let chunk_obj = serde_json::json!({
                            "object": OBJ_CHUNK,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "logprobs": write_openai_logprobs(lps),
                                "finish_reason": null
                            }]
                        });
                        Some(("".to_string(), chunk_obj))
                    }
                }
            },
            IrStreamEvent::BlockStop { .. } => None,
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                // Map the IR stop_reason onto OpenAI's finish_reason enum. A non-terminal delta with
                // no stop_reason must serialize finish_reason as JSON `null` — NOT the empty string.
                // OpenAI chat.completion.chunk uses null for in-progress chunks and a valid enum
                // string ("stop"/"length"/"tool_calls"/"content_filter") only on the final chunk; an
                // empty string is not a valid enum value and fails strict SDK (Pydantic) validation.
                // A non-terminal delta carries no stop_reason → finish_reason is JSON `null` (an empty
                // string is not a valid enum value and fails strict SDK validation). A terminal delta
                // projects the typed reason into OpenAI's closed enum via the codec.
                let finish_reason: serde_json::Value = match stop_reason {
                    Some(r) => serde_json::json!(write_openai_stop_reason(*r)),
                    None => serde_json::Value::Null,
                };
                let delta_obj = serde_json::json!({});
                let mut chunk_obj = serde_json::json!({
                    "object": OBJ_CHUNK,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": finish_reason
                    }]
                });
                // Carry real token usage on the terminal chunk. On a cross-protocol egress (e.g.
                // Anthropic/Bedrock -> OpenAI ingress) the IR's terminal MessageDelta holds the true
                // prompt/completion counts; the prior code discarded `usage` entirely, so an
                // OpenAI-ingress client that requested `stream_options:{include_usage:true}` received
                // ZERO usage data — both a token-accounting loss and a distinguishability tell, since a
                // native include_usage stream ALWAYS ends with a usage-bearing chunk. We attach a
                // top-level `usage:{prompt_tokens, completion_tokens, total_tokens}` object here.
                //
                // Native OpenAI carries this on a SEPARATE trailing `{choices:[], usage:{...}}` chunk
                // after the finish chunk; emitting that second chunk would require returning two events
                // from this 1:1 `write_response_event`, which the `ProtocolWriter` trait (shared, not
                // owned here) does not allow. So we FOLD `usage` onto the finish chunk here, and the
                // framing seam (`StreamTranslate::emit_ir_event` via `split_openai_trailing_usage`)
                // UN-folds it back into a native-shape trailing usage-only chunk — that seam can
                // append two frames where this 1:1 writer cannot. Folding here recovers the accounting
                // even on any path that bypasses the seam, and the SDK still surfaces `chunk.usage`.
                // We emit it only when a count is
                // nonzero (a same-protocol passthrough without include_usage carries zeroed usage in
                // the IR; suppressing the field there avoids stamping a usage object onto a stream that
                // never asked for one). `total_tokens` is the prompt+completion sum, the native shape.
                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but OpenAI's `prompt_tokens` is a TOTAL that includes the cached prefix, so
                // add `cache_read` back. Emit `prompt_tokens_details.cached_tokens` only when a cache
                // read is present (matching the native shape — no spurious details object otherwise).
                let cache_read = usage.cache_read_input_tokens.unwrap_or(0);
                // cache_creation is ALSO part of OpenAI's TOTAL prompt count (it is None on every
                // same-protocol OpenAI path; present only on cross-protocol Anthropic/Bedrock ingress).
                let prompt_tokens = usage
                    .input_tokens
                    .saturating_add(cache_read)
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let completion_tokens = usage.output_tokens;
                if prompt_tokens != 0 || completion_tokens != 0 {
                    if let Some(obj) = chunk_obj.as_object_mut() {
                        let mut usage_obj = serde_json::json!({
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens.saturating_add(completion_tokens),
                        });
                        if usage.cache_read_input_tokens.is_some() {
                            if let Some(uo) = usage_obj.as_object_mut() {
                                uo.insert(
                                    "prompt_tokens_details".to_string(),
                                    serde_json::json!({ "cached_tokens": cache_read }),
                                );
                            }
                        }
                        obj.insert("usage".to_string(), usage_obj);
                    }
                }
                Some(("".to_string(), chunk_obj))
            }
            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                // Map the IR error class onto OpenAI's enumerated error `type` vocabulary. The prior
                // hardcoded "error" is not a valid OpenAI error type — SDK clients that switch on
                // `error.type` would fall through to an unhandled default, and the bogus value is a
                // detectable proxy tell. The match is exhaustive over StatusClass (no `_ =>`), so a
                // new class forces an explicit decision; `server_error` is the safe fallback bucket.
                let error_type = match err.class {
                    crate::breaker::StatusClass::RateLimit => ERR_TYPE_RATE_LIMIT,
                    crate::breaker::StatusClass::Auth => ERR_TYPE_AUTHENTICATION,
                    // Billing exhaustion is OpenAI's `insufficient_quota` (HTTP 429), NOT
                    // `permission_error`. Real OpenAI reserves `permission_error` for access-control
                    // denials (feature/org restrictions); an over-quota error carries
                    // `type:"insufficient_quota"` AND `code:"insufficient_quota"`. Emitting
                    // `permission_error` for a billing class made a client switch-casing on
                    // `error.type` misroute quota errors as permission denials, and is a detectable
                    // protocol tell. `bearer_error_code` pairs the matching `code` below. This mirrors
                    // the non-stream `write_error` path, which already maps the `"insufficient_quota"`
                    // kind to this type + code.
                    crate::breaker::StatusClass::Billing => ERR_TYPE_INSUFFICIENT_QUOTA,
                    crate::breaker::StatusClass::ContextLength
                    | crate::breaker::StatusClass::ClientError => ERR_TYPE_INVALID_REQUEST,
                    crate::breaker::StatusClass::Overloaded
                    | crate::breaker::StatusClass::ServerError
                    | crate::breaker::StatusClass::Timeout
                    | crate::breaker::StatusClass::Network => ERR_TYPE_SERVER_ERROR,
                };
                // Include `code` and `param` as JSON null, matching BOTH the native OpenAI error
                // shape and this writer's own non-stream `write_error` envelope. Omitting them made
                // an in-stream error structurally different from a non-stream error (a detectable
                // proxy tell) and broke clients that destructure `error.code` / `error.param`.
                let error_obj = serde_json::json!({
                    "error": {
                        "message": message,
                        "type": error_type,
                        "code": bearer_error_code(error_type),
                        "param": serde_json::Value::Null,
                    }
                });
                Some(("".to_string(), error_obj))
            }
        }
    }

    fn egress_user_agent(&self) -> &'static str {
        // OpenAI Python SDK UA shape — pinned, see `EGRESS_UA_OPENAI` in forward.rs.
        crate::proxy::EGRESS_UA_OPENAI
    }

    fn emits_sse_done_terminator(&self) -> bool {
        // OpenAI Chat Completions SSE ends with a literal `data: [DONE]` frame; busbar reproduces it
        // when emitting an openai-format stream to an openai-ingress client.
        true
    }

    fn new_stream_framing(&self) -> Box<dyn super::StreamFraming> {
        // OpenAI INGRESS per-stream framing: replays the latched stream identity onto every
        // `chat.completion.chunk` and un-folds the include_usage trailing-usage chunk. Lives here, in
        // the OpenAI module, so the agnostic translator names no OpenAI wire shape.
        Box::<OpenAiStreamFraming>::default()
    }

    fn auth_failure_message(&self) -> &'static str {
        AUTH_FAILURE_MSG
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    /// Native OpenAI error envelope, served as `application/json`:
    /// `{"error":{"message":<msg>,"type":<type>,"param":null,"code":null}}`. This is the exact shape
    /// the official OpenAI SDKs decode (`openai.APIError` reads `error.message`/`error.type`/
    /// `error.code`/`error.param`), so a client on the native SDK gets a typed exception rather than
    /// an undecodable body. The generic `kind` is mapped onto OpenAI's own error-`type` vocabulary
    /// where one exists; otherwise it is passed through verbatim (still a valid string `type`).
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map the protocol-agnostic `kind` onto OpenAI's documented error `type` values. OpenAI's
        // vocabulary: "invalid_request_error", "authentication_error", "permission_error",
        // "not_found_error", "rate_limit_error", "server_error", "api_error". HTTP 401/403/404/429
        // categories and common generic kinds are normalized; anything unrecognized falls back to a
        // status-derived bucket (4xx → invalid_request_error, 5xx → server_error) so the emitted
        // `type` is always a real OpenAI type. No `_ =>` catch-all on the kind match: each known
        // kind is listed, with the status-based fallback handled explicitly afterwards.
        let error_type = match kind {
            ERR_TYPE_INVALID_REQUEST | "invalid_request" | "bad_request" => {
                ERR_TYPE_INVALID_REQUEST
            }
            ERR_TYPE_AUTHENTICATION | "unauthorized" | "auth" => ERR_TYPE_AUTHENTICATION,
            ERR_TYPE_PERMISSION | "permission_denied" | "forbidden" => ERR_TYPE_PERMISSION,
            ERR_TYPE_NOT_FOUND => ERR_TYPE_NOT_FOUND,
            ERR_TYPE_RATE_LIMIT | "rate_limit" | "too_many_requests" => ERR_TYPE_RATE_LIMIT,
            ERR_TYPE_SERVER_ERROR | "internal_error" | "internal_server_error" => {
                ERR_TYPE_SERVER_ERROR
            }
            crate::proxy::KIND_API_ERROR => crate::proxy::KIND_API_ERROR,
            // Quota exhaustion is a first-class native OpenAI type (HTTP 429); preserve it so the
            // over-budget governance path keeps the real `insufficient_quota` type AND its matching
            // `code` (set in `bearer_error_code`).
            ERR_TYPE_INSUFFICIENT_QUOTA => ERR_TYPE_INSUFFICIENT_QUOTA,
            // The all-lanes-exhausted 503 path and the request-timeout 503 path pass the
            // Anthropic-vocabulary kind `overloaded` to EVERY ingress writer. `overloaded` is not an
            // OpenAI error type — real OpenAI reports a 503 / transient upstream failure as
            // `server_error` — so emitting `type:"overloaded"` is both a conformance break (the
            // official SDK's typed-exception mapping fails on an unknown type) and a cross-protocol
            // vocabulary leak. Map every transient/unavailable spelling onto OpenAI's native 5xx type.
            crate::proxy::KIND_OVERLOADED
            | ERR_TYPE_OVERLOADED
            | "service_unavailable"
            | "unavailable"
            | "transient"
            | "timeout"
            | "network"
            | "5xx" => ERR_TYPE_SERVER_ERROR,
            crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH => ERR_TYPE_INVALID_REQUEST,
            // Empty kind: derive a valid OpenAI type from the HTTP status bucket rather than emitting
            // an empty `type`, so the SDK still sees a real error type.
            "" => {
                if (500..600).contains(&status) {
                    ERR_TYPE_SERVER_ERROR
                } else {
                    ERR_TYPE_INVALID_REQUEST
                }
            }
            // Any other caller-supplied kind (including the generic `not_found`) is passed through
            // verbatim: OpenAI has no single canonical `type` for it (model-not-found is reported as
            // `invalid_request_error` + `code: "model_not_found"` on some endpoints and
            // `not_found_error` on others), so we preserve the caller's token rather than guess.
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "param": serde_json::Value::Null,
                "code": bearer_error_code(error_type),
            }
        })
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // Collect the assistant text parts exactly once: their presence decides whether
        // `content` is null, and their join is the content string. (Previously a parallel Vec of
        // discarded JSON objects was built solely to test emptiness — a dead allocation that
        // duplicated the extraction logic.)
        let text_parts: Vec<&str> = resp
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();

        // ToolUse blocks become tool_calls (not in content)
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            if let crate::ir::IrBlock::ToolUse {
                id, name, input, ..
            } = block
            {
                // Serialize input to JSON string
                let args_str = tool_arguments_to_string(input);
                tool_calls_arr.push(serde_json::json!({
                    "type": TOOL_TYPE_FUNCTION,
                    "id": id,
                    "function": {
                        "name": name,
                        "arguments": args_str
                    }
                }));
            }
        }

        // Thinking blocks are DROPPED on OpenAI write (lossy-by-necessity; OpenAI has no thinking)
        // They are not collapsed into content.

        let mut message_obj = serde_json::json!({
            "role": "assistant",
            "content": if text_parts.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(text_parts.concat())
            },
        });

        // Add tool_calls only if present
        if !tool_calls_arr.is_empty() {
            message_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
        }

        let mut choices_array: Vec<serde_json::Value> = Vec::new();
        // The OpenAI chat.completion spec requires `finish_reason` to ALWAYS be present in a choice
        // object — a valid enum string ("stop"/"length"/"tool_calls"/...) or JSON `null` when the
        // upstream provided no stop reason (e.g. a cross-protocol Bedrock response whose
        // `read_response` yields `stop_reason: None`). The prior code mapped `None` to "" and then
        // omitted the key entirely; a missing `finish_reason` is not a valid choice shape and the
        // Python SDK's Pydantic model raises a validation error on it. Emit null instead.
        let finish_reason: serde_json::Value = match resp.stop_reason {
            Some(r) => serde_json::json!(write_openai_stop_reason(r)),
            None => serde_json::Value::Null,
        };

        let mut choice_obj = serde_json::Map::new();
        choice_obj.insert("index".to_string(), serde_json::json!(0));
        choice_obj.insert("message".to_string(), message_obj);
        // Carried per-token logprobs (e.g. from a Gemini backend's `logprobsResult`) in OpenAI's
        // native choice shape. Only emitted when the backend actually produced them: an absent
        // `logprobs` key matches what OpenAI returns when they were not requested.
        if !resp.logprobs.is_empty() {
            choice_obj.insert(
                "logprobs".to_string(),
                write_openai_logprobs(&resp.logprobs),
            );
        }
        choice_obj.insert("finish_reason".to_string(), finish_reason);
        choices_array.push(serde_json::Value::Object(choice_obj));

        // Identity fields, in the order an official OpenAI chat.completion object carries them
        // ({"id","object","created","model","system_fingerprint","choices","usage"}). The Python and
        // Node SDKs require `id` (str), `object` == "chat.completion", `created` (int), `model` (str),
        // `choices`, and `usage`; `system_fingerprint` is optional. When the IR field is `None`
        // (cross-protocol: the backend never minted one) we SYNTHESIZE a protocol-correct value so a
        // native SDK can't tell this was translated.
        let id = resp.id.clone().unwrap_or_else(synth_completion_id);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!(OBJ_COMPLETION));
        let created = resp.created.unwrap_or_else(crate::store::now);
        obj.insert("created".to_string(), serde_json::json!(created));
        // model that served the response. `model` is a REQUIRED non-nullable string in the OpenAI
        // chat.completion schema; a cross-protocol backend whose `read_response` yields `model: None`
        // (e.g. Bedrock egress -> OpenAI ingress) would otherwise produce a model-less completion that
        // fails strict SDK deserialisation and is a proxy tell. Preserve the upstream value on a
        // same-protocol passthrough; fall back to DEFAULT_MODEL when none was supplied.
        obj.insert(
            "model".to_string(),
            serde_json::json!(model_or_default(resp.model.as_deref())),
        );
        // system_fingerprint is only emitted when the upstream supplied one (same-protocol
        // passthrough); we do not fabricate an opaque backend marker on cross-protocol responses.
        if let Some(ref fp) = resp.system_fingerprint {
            obj.insert("system_fingerprint".to_string(), serde_json::json!(fp));
        }
        obj.insert(
            "choices".to_string(),
            serde_json::Value::Array(choices_array),
        );

        // Build usage, including the `total_tokens` an SDK expects (prompt + completion).
        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but OpenAI's `prompt_tokens` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back. Emit `prompt_tokens_details.cached_tokens` only when a cache read is
        // present (matching the native shape — no spurious details object otherwise).
        let cache_read = resp.usage.cache_read_input_tokens.unwrap_or(0);
        // cache_creation is ALSO part of OpenAI's TOTAL prompt count (None on same-protocol OpenAI;
        // present only on cross-protocol Anthropic/Bedrock ingress).
        let prompt_tokens = resp
            .usage
            .input_tokens
            .saturating_add(cache_read)
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "prompt_tokens".to_string(),
            serde_json::json!(prompt_tokens),
        );
        usage_map.insert(
            "completion_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        usage_map.insert(
            "total_tokens".to_string(),
            serde_json::json!(prompt_tokens.saturating_add(resp.usage.output_tokens)),
        );
        if resp.usage.cache_read_input_tokens.is_some() {
            usage_map.insert(
                "prompt_tokens_details".to_string(),
                serde_json::json!({ "cached_tokens": cache_read }),
            );
        }
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
