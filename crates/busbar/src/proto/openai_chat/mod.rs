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

/// Render an IR ToolUse `input` value as the OpenAI `function.arguments` string.
///
/// OpenAI carries tool-call arguments as a *string* of JSON. The reader stores well-formed
/// arguments as a parsed `Value`, but falls back to `Value::String(raw)` when the upstream sent
/// arguments that are not valid JSON (a streaming-partial or malformed tool call). Re-serializing
/// such a `Value::String` via `crate::json::to_string` would JSON-encode the string a second time —
/// emitting an escaped, quoted blob on the wire (double-encoding). Emit a `Value::String` verbatim
/// so the original argument text round-trips unchanged; any other `Value` is serialized normally.
pub(crate) fn tool_arguments_to_string(input: &serde_json::Value) -> String {
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
        hosted: None,
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
    /// Raw IR-block-index → 0-based tool-call ordinal map (Finding 1). The writer stamps the CANONICAL
    /// IR block index onto `tool_calls[].index`, but a source stream can open a tool_use at a non-zero
    /// block index (e.g. an Anthropic stream with text at block 0 and the first tool_use at block 1).
    /// OpenAI's streaming contract requires `tool_calls[].index` to ENUMERATE the tool calls starting
    /// at 0 and incrementing per tool call — SDK argument accumulators (openai-python/openai-node) key
    /// their per-call buffers on that index, so a first tool call arriving at index 1 lands in a
    /// never-flushed slot and the call is dropped. This map assigns each distinct raw index the next
    /// 0-based ordinal on first sight and replays it for that call's argument-fragment chunks. Keeps
    /// PARALLEL tool calls distinct (each raw index → its own ordinal) while guaranteeing the first
    /// call is index 0. Populated lazily; empty on a tool-less stream.
    tool_call_index: std::collections::BTreeMap<u64, u64>,
    /// Did the ORIGINAL client request carry `stream_options.include_usage == true`? (Findings 2+3.)
    /// Busbar always injects `include_usage` UPSTREAM so it can bill streaming calls, which makes the
    /// upstream emit token usage; but a native OpenAI stream only surfaces a trailing usage-only chunk
    /// to the CLIENT when the client opted in. When this is `false`, `on_egress_chunk` STRIPS the
    /// folded usage instead of un-folding it, so a client that did not opt in never receives an
    /// unsolicited `{choices:[], usage}` chunk (which would `choices[0]` IndexError). Default `false`
    /// (opt-in, matching native OpenAI); the engine sets it from the client body via
    /// `set_client_include_usage`.
    client_include_usage: bool,
}

impl super::StreamFraming for OpenAiStreamFraming {
    fn on_egress_chunk(&mut self, chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
        // (a) Identity replay, then (b) the 0-based tool-call index remap, then (c) the include_usage
        // handling — in this order, because the trailing chunk's identity is read off `chunk` AFTER the
        // identity has been populated onto it, so both frames share ONE stream identity. The `[DONE]`
        // sentinel is a separate `finish()` literal and never routed here.
        self.apply_chunk_identity(chunk);
        self.remap_tool_call_index(chunk);
        if self.client_include_usage {
            // Client opted in: un-fold the folded usage into a native separate trailing usage-only
            // chunk, exactly as real OpenAI does under `stream_options.include_usage:true`.
            split_openai_trailing_usage(chunk)
        } else {
            // Client did NOT opt in: STRIP the folded usage entirely so the finish chunk stays
            // usage-free and NO trailing usage-only chunk is emitted — matching a native OpenAI stream
            // without include_usage. Billing is unaffected (it reads the IR-side `last_usage` A-tap,
            // captured before this seam). This closes Finding 2: an opted-out client never receives the
            // unsolicited `{choices:[], usage}` chunk that trips `choices[0]`.
            strip_folded_usage(chunk);
            None
        }
    }

    // OpenAI ingress UN-folds (or strips) usage in `on_egress_chunk`, so the translator must NOT
    // defer/fold the terminal usage itself.
    fn folds_terminal_usage(&self) -> bool {
        false
    }

    fn set_client_include_usage(&mut self, include: bool) {
        self.client_include_usage = include;
    }

    /// SAME-PROTOCOL verbatim strip (R3-A-b). On OpenAI->OpenAI the translator re-emits upstream
    /// frames byte-for-byte and never calls `on_egress_chunk`, so the opted-out `include_usage` strip
    /// above cannot fire. Busbar forces `include_usage` UPSTREAM (to bill), so the OpenAI upstream
    /// emits a NATIVE trailing usage-only chunk - `object == "chat.completion.chunk"`, a real top-level
    /// `usage` OBJECT, and an EMPTY `choices` array. When the CLIENT did not opt in, suppress exactly
    /// that frame from the verbatim client bytes so a strict SDK never `choices[0]`-IndexErrors; the
    /// A-tap already captured its usage for billing. A normal content/finish chunk (non-empty
    /// `choices`) is never suppressed, and the opted-in case re-emits it verbatim.
    fn suppress_same_proto_frame(&self, data: &serde_json::Value) -> bool {
        if self.client_include_usage {
            return false;
        }
        let Some(obj) = data.as_object() else {
            return false;
        };
        if obj.get("object").and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
            return false;
        }
        let has_usage_obj = obj.get("usage").is_some_and(|u| u.is_object());
        let choices_empty = obj
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|arr| arr.is_empty());
        has_usage_obj && choices_empty
    }

    /// SAME-PROTOCOL intermediate `usage:null` strip (indistinguishability fix). On OpenAI->OpenAI the
    /// translator re-emits frames byte-for-byte, so the opted-out `strip_folded_usage` in
    /// `on_egress_chunk` never runs. Busbar forces `include_usage` UPSTREAM (to bill), so the OpenAI
    /// upstream stamps `"usage":null` on EVERY intermediate content chunk (and the finish chunk) - a key
    /// a native opted-out OpenAI stream never carries, hence a wire-shape tell. When the CLIENT did not
    /// opt in, request a byte-level strip of the top-level `usage` member from any content/finish chunk
    /// that carries a `usage` FIELD alongside a NON-EMPTY `choices` array.
    ///
    /// The predicate deliberately does NOT require `object == "chat.completion.chunk"`. An
    /// OpenAI-COMPATIBLE upstream may omit the `object` field (or use a variant) on its content chunks
    /// while still stamping the forced-`include_usage` `"usage":null` tell; requiring the exact `object`
    /// value would let that tell leak to an opted-out client. A frame with a NON-EMPTY `choices` array
    /// and a top-level `usage` key is a content/finish chunk regardless of `object`, so that pairing is
    /// sufficient. The trailing usage-ONLY chunk (EMPTY `choices`, a usage OBJECT) is dropped whole by
    /// `suppress_same_proto_frame` instead, so it is deliberately NOT matched here (the non-empty
    /// `choices` gate excludes it). The opted-in case returns `false` (the client asked for usage;
    /// re-emit verbatim), so a usage the client legitimately requested is never stripped. The A-tap
    /// already captured usage for billing before this seam.
    fn strip_same_proto_usage(&self, data: &serde_json::Value) -> bool {
        if self.client_include_usage {
            return false;
        }
        let Some(obj) = data.as_object() else {
            return false;
        };
        // A content/finish chunk carries a NON-EMPTY `choices` array. This gate (not `object`) is what
        // distinguishes a content/finish chunk from the empty-choices usage-only trailer, and it works
        // for compatible upstreams that omit or vary `object`.
        let choices_non_empty = obj
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|arr| !arr.is_empty());
        // Only act when a top-level `usage` key is actually present (the forced-include_usage tell).
        obj.contains_key("usage") && choices_non_empty
    }
}

impl OpenAiStreamFraming {
    /// Remap every `choices[].delta.tool_calls[].index` on a `chat.completion.chunk` from the writer's
    /// CANONICAL raw IR-block index to a 0-based per-tool-call ordinal (Finding 1). The FIRST distinct
    /// raw index seen becomes ordinal 0, the next distinct raw index becomes 1, and so on; a raw index
    /// seen again (the tool call's argument-fragment chunks) replays its assigned ordinal. This makes
    /// the first tool call arrive at `index: 0` even when the source stream opened it at a non-zero
    /// block index (e.g. text at block 0, first tool_use at block 1), which is what the OpenAI SDKs
    /// require to route streamed `function.arguments` fragments into the right accumulator. A chunk
    /// with no tool_calls is a no-op.
    fn remap_tool_call_index(&mut self, chunk: &mut serde_json::Value) {
        let Some(obj) = chunk.as_object_mut() else {
            return;
        };
        if obj.get("object").and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
            return;
        }
        let Some(choices) = obj.get_mut("choices").and_then(|c| c.as_array_mut()) else {
            return;
        };
        for choice in choices {
            let Some(tool_calls) = choice
                .get_mut("delta")
                .and_then(|d| d.get_mut("tool_calls"))
                .and_then(|tc| tc.as_array_mut())
            else {
                continue;
            };
            for tc in tool_calls {
                let Some(raw) = tc.get("index").and_then(|i| i.as_u64()) else {
                    continue;
                };
                // Assign the next ordinal on first sight of this raw index; replay it thereafter.
                let next = self.tool_call_index.len() as u64;
                let ordinal = *self.tool_call_index.entry(raw).or_insert(next);
                if let Some(tc_obj) = tc.as_object_mut() {
                    tc_obj.insert("index".to_string(), serde_json::json!(ordinal));
                }
            }
        }
    }

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

/// Remove a folded top-level `usage` object from a `chat.completion.chunk` in place, WITHOUT emitting
/// any replacement trailing chunk (Finding 2). This is the opt-OUT twin of `split_openai_trailing_usage`:
/// a client that did not send `stream_options.include_usage` must see a stream that carries NO usage at
/// all, exactly like a native OpenAI stream without include_usage. Only strips when both a folded `usage`
/// and a terminal `finish_reason` are present (the shape the writer folds onto), so a non-finish chunk is
/// never touched. The removed usage was only ever a client-facing echo — billing sources the IR-side
/// `last_usage` A-tap, which is captured upstream of this seam and is unaffected.
fn strip_folded_usage(chunk: &mut serde_json::Value) {
    let Some(obj) = chunk.as_object_mut() else {
        return;
    };
    if obj.get("object").and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
        return;
    }
    if !obj.contains_key("usage") {
        return;
    }
    let has_finish = obj
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c0| c0.get("finish_reason"))
        .map(|fr| !fr.is_null())
        .unwrap_or(false);
    if has_finish {
        obj.remove("usage");
    }
}

/// OpenAI writer implementation.
#[derive(Clone)]
pub(crate) struct OpenAiWriter;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

mod reader;
mod writer;
