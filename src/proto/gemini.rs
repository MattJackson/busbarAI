// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Gemini protocol reader/writer implementation.

use super::*;

/// Router-internal shim key the gemini ingress route injects into the request body when the client
/// sent a streaming `:streamGenerateContent` request WITHOUT `?alt=sse` (so the response must be the
/// JSON-array streaming format, not SSE). It rides alongside the `model`/`stream` shims. Single
/// source of truth shared by the route injection (`route.rs`), the forward-layer strip
/// (`forward::strip_router_shim_keys`), and the Gemini reader's `modeled_keys` exclusion so it never
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
const ERR_TYPE_OVERLOADED: &str = "overloaded_error";

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
        // unaffected (byte-identical), and the cross-protocol seam (`forward.rs ir.extra.clear()`)
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

impl ProtocolReader for GeminiReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body once; both `provider_code` and `structured_type` are derived from the
        // same parsed value to avoid deserializing the JSON twice on every error response.
        let json = crate::json::parse::<serde_json::Value>(body).ok();
        let error_obj = json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_object());

        // The real Gemini REST API returns `error.code` as a JSON INTEGER (the HTTP status, per
        // google.rpc.Status), e.g. `"code": 429`. `serde_json::Value::as_str()` returns None on a
        // number, so reading it as a string silently dropped the numeric code and fell back to the
        // gRPC status name — breaking any breaker/metrics comparison against numeric strings. Read
        // the integer first and stringify it; tolerate a string-typed `code` (some proxies emit one)
        // as a secondary path; fall back to `status` only when `code` is absent entirely.
        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get("code"))
            .and_then(|c| {
                c.as_u64()
                    .map(|n| n.to_string())
                    .or_else(|| c.as_str().map(String::from))
            })
            .or_else(|| {
                error_obj
                    .and_then(|e_obj| e_obj.get("status"))
                    .and_then(|s| s.as_str())
                    .map(String::from)
            });

        let structured_type = error_obj
            .and_then(|e_obj| e_obj.get("status"))
            .and_then(|t| t.as_str())
            .map(String::from);

        // Gemini signals context-length-exceeded as a 400 `INVALID_ARGUMENT` whose MESSAGE carries
        // the token-overflow text (there is NO distinct google.rpc.Code for it — `INVALID_ARGUMENT`
        // also covers every other malformed-request 400). The raw `provider_code` derived above is
        // therefore the bare HTTP status int (`"400"`) / status name, which the breaker classifies as
        // a generic ClientError that PENALIZES the lane instead of failing over. Detect the canonical
        // context-length signal here and OVERRIDE `provider_code` with the canonical
        // `context_length_exceeded` string the breaker recognizes (breaker.rs) →
        // StatusClass::ContextLength → fail over to a larger-context model WITHOUT penalty. Without
        // this, oversized-request failover never triggered for the Gemini protocol in production
        // (only the `#[cfg(test)]` `classify()` helper recognized the pattern). Mirrors
        // `AnthropicReader::extract_error`, which surfaces the same canonical code from its own
        // message heuristic. Scan the lowercased raw body so the match is independent of which
        // structured field carried the text. The substring set mirrors `classify()` above.
        let provider_code = {
            // C4: STATUS-GATE the context-length override (mirroring `AnthropicReader::extract_error`,
            // which gates on 400/413). Gemini signals context-length-exceeded ONLY as a 400
            // `INVALID_ARGUMENT` (or, for some deployments, a 413). A 429 (rate limit) or 5xx whose
            // body happens to contain token-overflow phrasing — e.g. a retry-after message that quotes
            // the request's token count — must NOT be reclassified to ContextLength: that would
            // disposition a genuine rate-limit/server fault as a (non-faulting) ContextLength failover,
            // so the breaker never records the fault and the lane is never benched. Only on 400/413 do
            // we treat the token-phrased body as the canonical context-length signal. `or_else` (not an
            // unconditional shadow) so an already-derived `provider_code` is preserved when the
            // heuristic does not fire.
            let st = status.as_u16();
            if st == 400 || st == 413 {
                let lower = String::from_utf8_lossy(body).to_lowercase();
                if lower.contains("input is longer than the maximum number of tokens")
                    || (lower.contains("maximum-tokens") && lower.contains("requested"))
                    || (lower.contains("token count")
                        && (lower.contains("exceeds") || lower.contains("exceed"))
                        && lower.contains("maximum"))
                    || (lower.contains("exceeds the maximum")
                        && (lower.contains("token") || lower.contains("context")))
                {
                    Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
                } else {
                    provider_code
                }
            } else {
                provider_code
            }
        };

        // Gemini signals a DEAD egress credential (revoked/wrong/expired key, or a key lacking
        // access to the Generative Language API) as an HTTP 400 `INVALID_ARGUMENT` — or a 403
        // `PERMISSION_DENIED` — carrying the google.rpc.ErrorInfo `reason: API_KEY_INVALID` and a
        // message like "API key not valid. Please pass a valid API key." A bare 400 maps to
        // StatusClass::ClientError → ClientFault, which records NOTHING, never benches/fails over the
        // lane, and relays the upstream body verbatim — so a lane wired to a dead key keeps being
        // picked and serves a guaranteed auth rejection on every request. Detect the bad-key signal
        // here and re-shape the raw error so the breaker classifies it as Auth → HardDown (park the
        // lane, fail over to a sibling). 401 is the canonical Auth-classifying HTTP status in
        // `breaker::normalize_raw_error` (operator-error-map-INDEPENDENT, unlike a `provider_code`
        // that would only map via a configured entry the shipped Gemini error_map lacks); overriding
        // `http_status` is safe because the forwarder relays the INGRESS-native auth status to the
        // client (forward.rs `auth_failure_status_and_kind`), never this raw value — it is consumed
        // ONLY for breaker classification. `provider_code` is also set to the canonical `"auth"`
        // string (`breaker::status_class_from_str`) so an operator who DOES map it is reinforced.
        //
        // PRECISION: the override fires ONLY on an explicit api-key-invalid signal — the documented
        // `API_KEY_INVALID` reason (ErrorInfo `details[].reason` or the same token anywhere in the
        // body) OR an "api key (not / in)valid / expired" message — and NEVER on a generic
        // `INVALID_ARGUMENT` field-validation 400 (e.g. a bad `contents[0].role`), which must stay a
        // lane-healthy ClientFault. A bare `PERMISSION_DENIED`/`INVALID_ARGUMENT` with no api-key text
        // is left untouched.
        let (http_status, provider_code) = {
            let lower = String::from_utf8_lossy(body).to_lowercase();
            // The documented machine-readable reason wins on its own (it is unambiguous), regardless
            // of which status name accompanied it.
            let has_api_key_invalid_reason = lower.contains("api_key_invalid");
            // A prose api-key-invalid message: an explicit "api key" reference paired with a SPECIFIC
            // bad-key signal. The earlier heuristic accepted a BARE "invalid" token, which fired on any
            // INVALID_ARGUMENT field-validation 400 whose prose happened to also name an "api key"
            // (e.g. a malformed `x-goog-api-key`-shaped field reference) — benching a HEALTHY lane on a
            // pure client error. Pin to the documented Gemini bad-key phrasings instead: "API key not
            // valid" / "API key … expired" (and the explicit "invalid api key" / "api key is invalid"
            // orderings the API/SDK use). A generic validation 400 that merely contains the word
            // "invalid" no longer matches and stays a lane-healthy ClientFault.
            let api_key_message = lower.contains("api key not valid")
                || lower.contains("api-key not valid")
                || lower.contains("invalid api key")
                || lower.contains("invalid api-key")
                || lower.contains("api key is invalid")
                || lower.contains("api-key is invalid")
                || lower.contains("api key expired")
                || lower.contains("api-key expired")
                || lower.contains("api key has expired")
                || lower.contains("api-key has expired");
            // Only consider the auth heuristic on the google.rpc.Code statuses Gemini actually uses
            // for an auth/permission failure, so an unrelated status carrying the words by accident
            // cannot trip it. The documented reason is authoritative on its own; the prose message is
            // only trusted under one of these statuses.
            let status_is_auth_shaped = matches!(
                structured_type.as_deref(),
                Some(GRPC_INVALID_ARGUMENT)
                    | Some(GRPC_PERMISSION_DENIED)
                    | Some(GRPC_UNAUTHENTICATED)
            );
            if has_api_key_invalid_reason || (status_is_auth_shaped && api_key_message) {
                (401u16, Some("auth".to_string()))
            } else {
                (status.as_u16(), provider_code)
            }
        };

        crate::breaker::RawUpstreamError {
            http_status,
            provider_code,
            structured_type,
            retry_after_secs: None,
        }
    }

    #[cfg(test)]
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);
        let lower = text.to_lowercase();

        // context-length-exceeded via message pattern
        if lower.contains("input is longer than the maximum number of tokens")
            || (lower.contains("maximum-tokens") && lower.contains("requested"))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(crate::forward::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
                retry_after: None,
            };
        }

        // 429 → RateLimit
        if status == StatusCode::TOO_MANY_REQUESTS {
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429".to_string()),
                retry_after: None,
            };
        }

        // 401/403 → Auth
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: Some("auth".to_string()),
                retry_after: None,
            };
        }

        // 5xx → ServerError
        if status.is_server_error() {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        // 4xx (other) → ClientError
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

        // Per-request tool-call index. Gemini `functionCall` parts carry no id, so we synthesize a
        // deterministic, non-empty one (see `synth_tool_call_id`). The index makes each synthesized
        // id distinct even when two calls in the same request share a function name, so a downstream
        // Anthropic/OpenAI egress block gets a unique, non-empty `id`/`tool_use_id`.
        let mut tool_call_index: usize = 0;

        // Handle systemInstruction (Gemini uses this for system content)
        if let Some(sys_instr) = obj.get("systemInstruction") {
            if let Some(parts_arr) = sys_instr.get("parts").and_then(|p| p.as_array()) {
                for part in parts_arr {
                    if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                        system_blocks.push(crate::ir::IrBlock::Text {
                            text: text_val.to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                }
            }
        }

        // Handle contents array (messages)
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(contents_arr) = obj.get("contents").and_then(|c| c.as_array()) {
            for content_val in contents_arr {
                let role_str = content_val
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let role = match role_str {
                    // Gemini's Content.role is optional; an absent/empty role is an
                    // implicit user turn per the GenerateContentRequest schema and the
                    // official SDK. Match the streaming reader's leniency.
                    "user" | "" => crate::ir::IrRole::User,
                    "model" => crate::ir::IrRole::Assistant,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                            retry_after: None,
                        })
                    }
                };

                let mut msg_content = Vec::new();
                // Track functionResponse names seen IN THIS TURN: Gemini correlates a tool result
                // only by `name`, which we map to `tool_use_id`. Two results with the same name in
                // one turn collide into a duplicate `tool_use_id`, making cross-protocol correlation
                // ambiguous. We do NOT synthesize disambiguating ids (that would break Gemini->Gemini
                // passthrough, which round-trips the name verbatim) — we only warn.
                let mut seen_func_resp_names: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                if let Some(parts_arr) = content_val.get("parts").and_then(|p| p.as_array()) {
                    for part in parts_arr {
                        // Thinking part (H2): a `thought: true` part carries reasoning text + an
                        // opaque `thoughtSignature`; read it as IrBlock::Thinking (not plain Text) so
                        // a prior-turn reasoning block in the request survives with its signature.
                        // Checked first because a thought part also carries a `text` field.
                        if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                            let text = part
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            let signature = part
                                .get("thoughtSignature")
                                .and_then(|s| s.as_str())
                                // The signature is accepted verbatim; no scrub is needed. `redacted`
                                // is hardcoded `false` below, so a Gemini client can never forge a
                                // redacted reasoning block via this path regardless of the signature
                                // it sends (redacted-ness is a typed flag, not a signature string).
                                .map(String::from);
                            msg_content.push(crate::ir::IrBlock::Thinking {
                                text,
                                signature,
                                redacted: false,
                                cache_control: None,
                            });
                        }
                        // Text part
                        else if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text_val.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        }
                        // FunctionCall (ToolUse)
                        else if let Some(func_call) = part.get(FIELD_FUNCTION_CALL) {
                            let name = func_call
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            // Zero-arg functionCall → empty JSON OBJECT, not `null` (the tool-call
                            // input is an argument map; a no-arg call is `{}`). Keeps the request
                            // reader consistent with the response readers' args handling.
                            let args = empty_object_if_absent(func_call.get("args"));
                            // Gemini carries no tool-call id; synthesize a stable, non-empty one
                            // keyed by (index, name). The Gemini writer ignores the ToolUse `id`
                            // (it round-trips `name`), so this is safe for same-protocol passthrough
                            // and gives cross-protocol Anthropic/OpenAI egress a non-empty id.
                            let id = synth_tool_call_id(tool_call_index, &name);
                            tool_call_index += 1;
                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id,
                                name,
                                input: args,
                                cache_control: None,
                            });
                        }
                        // FunctionResponse (ToolResult)
                        else if let Some(func_resp) = part.get("functionResponse") {
                            let name = func_resp
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let response_val = func_resp
                                .get("response")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);
                            // Convert response to string representation for content
                            let response_text = crate::json::to_string(&response_val)
                                .unwrap_or_else(|_| "unknown".to_string());
                            // ACCEPTED GEMINI-PROTOCOL LIMITATION: a Gemini `functionResponse`
                            // carries only a `name` (no call id). We set `tool_use_id` to the
                            // function name — the only correlation handle Gemini provides on the
                            // RESULT side. This is deliberate and load-bearing for SAME-PROTOCOL
                            // (Gemini→Gemini) passthrough: the writer round-trips `tool_use_id`
                            // straight back into `functionResponse.name`, so it MUST stay the name
                            // (NOT the synthetic id we mint for the `functionCall` ToolUse above —
                            // the writer ignores the ToolUse `id`, so synthesizing it there is safe,
                            // but it must not leak onto the result name here). Cross-protocol egress
                            // that correlates strictly by id is the pre-existing Gemini limitation:
                            // the result still carries the name as its handle.
                            if !name.is_empty() && !seen_func_resp_names.insert(name.clone()) {
                                tracing::warn!(
                                    tool_name = %name,
                                    "duplicate gemini functionResponse name in one turn yields a \
                                     duplicate tool_use_id; cross-protocol correlation is ambiguous"
                                );
                            }
                            msg_content.push(crate::ir::IrBlock::ToolResult {
                                tool_use_id: name,
                                content: vec![crate::ir::IrBlock::Text {
                                    text: response_text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                                is_error: false,
                                cache_control: None,
                            });
                        }
                        // InlineData (Image, base64)
                        else if let Some(inline_data) = part.get("inlineData") {
                            let mime_type = inline_data
                                .get("mimeType")
                                .and_then(|m| m.as_str())
                                .unwrap_or("")
                                .to_string();
                            let data = inline_data
                                .get("data")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();
                            msg_content.push(crate::ir::IrBlock::Image {
                                source: crate::ir::IrImageSource::Base64 {
                                    media_type: mime_type,
                                    data,
                                },
                                cache_control: None,
                            });
                        }
                        // FileData (Image by URI) → a remote URL reference, carried as the typed
                        // `Url` source so it survives into the IR exactly as the OpenAI/Responses
                        // readers store a remote image URL.
                        else if let Some(file_data) = part.get("fileData") {
                            let uri = file_data
                                .get("fileUri")
                                .and_then(|u| u.as_str())
                                .unwrap_or("")
                                .to_string();
                            msg_content.push(crate::ir::IrBlock::Image {
                                source: crate::ir::IrImageSource::Url(uri),
                                cache_control: None,
                            });
                        }
                    }
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        }

        // Handle tools array (functionDeclarations)
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_arr) = obj.get("tools").and_then(|t| t.as_array()) {
            for tool_val in tools_arr {
                // Gemini has functionDeclarations inside tools
                if let Some(func_decls) = tool_val
                    .get("functionDeclarations")
                    .and_then(|f| f.as_array())
                {
                    for func_decl in func_decls {
                        let name = func_decl
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = func_decl
                            .get("description")
                            .and_then(|d| d.as_str().map(String::from));
                        let parameters = func_decl
                            .get("parameters")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);

                        tools.push(crate::ir::IrTool {
                            name,
                            description,
                            input_schema: parameters,
                            cache_control: None,
                        });
                    }
                }
            }
        }

        // Extract scalar fields and extra. `maxOutputTokens` is read as i64 and converted with a
        // BOUNDS-CHECKED `u32::try_from` rather than a bare `as u32`: a pathological/garbage value
        // above `u32::MAX` (e.g. `5_000_000_000`) would silently TRUNCATE under `as u32` (wrapping to
        // a small token cap the caller never asked for), so an out-of-range value is dropped to `None`
        // instead — the request then carries no `maxOutputTokens` and the backend applies its default,
        // which is strictly safer than forwarding a silently-mangled cap.
        let max_tokens = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("maxOutputTokens"))
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("temperature"))
            .and_then(|v| v.as_f64());
        // Promoted sampling controls live under `generationConfig`: topP, topK, stopSequences.
        let top_p = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("topP"))
            .and_then(|v| v.as_f64());
        let top_k = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("topK"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let stop = crate::ir::read_stop_sequences(
            obj.get("generationConfig")
                .and_then(|gc| gc.get("stopSequences")),
        );
        // Promoted sampling controls under `generationConfig` (cross-protocol survival): Gemini
        // models `frequencyPenalty`/`presencePenalty`/`seed`/`candidateCount` natively. Promote them
        // into the typed IR fields so they survive the cross-protocol seam (where `extra` — which
        // still holds the raw `generationConfig` for same-protocol byte-identity — is cleared)
        // instead of degrading to the target's default. `candidateCount` → `n` (Gemini's name for the
        // OpenAI `n` / Cohere `num_generations` candidate count). Each is bounds-checked the same way
        // `topK`/`maxOutputTokens` are: an out-of-range value drops to `None` rather than truncating.
        let frequency_penalty = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("frequencyPenalty"))
            .and_then(|v| v.as_f64());
        let presence_penalty = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("presencePenalty"))
            .and_then(|v| v.as_f64());
        let seed = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("seed"))
            .and_then(|v| v.as_i64());
        let n = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("candidateCount"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // response_format (M1): Gemini expresses structured output as
        // `generationConfig.responseMimeType` (+ optional `responseSchema`). There is no single
        // native key, so the IR carries a NORMALIZED object `{responseMimeType, responseSchema?}`
        // preserving each present sub-field verbatim. This is best-effort and INTENTIONALLY lossy in
        // shape (the cross-protocol writers map it to their own structured-output shape — OpenAI's
        // `response_format`, etc.); the raw sub-fields ALSO survive same-protocol via the preserved
        // `generationConfig` in `extra`, so Gemini→Gemini stays byte-identical regardless. `None`
        // when neither sub-field is present so a plain request gains no spurious response_format.
        let response_format = read_gemini_response_format(obj.get("generationConfig"));
        // Logprobs ask, promoted like seed/penalties above: Gemini spells the boolean
        // `generationConfig.responseLogprobs` and the top-count `generationConfig.logprobs`
        // (0-20). Carried first-class so an OpenAI backend receives `logprobs`/`top_logprobs`.
        let logprobs = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("responseLogprobs"))
            .and_then(|v| v.as_bool());
        let top_logprobs = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("logprobs"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // The thinking ASK: `generationConfig.thinkingConfig.thinkingBudget` (a token count; -1 =
        // "model decides"), promoted so it carries to Anthropic's budget_tokens (straight number
        // copy) or OpenAI's reasoning_effort (bucketized). The raw thinkingConfig ALSO survives
        // same-protocol via the preserved generationConfig in extra; the writer overlays a fresh
        // thinkingConfig from the typed field on cross-protocol egress.
        let reasoning = obj
            .get("generationConfig")
            .and_then(|gc| gc.get("thinkingConfig"))
            .and_then(|tc| tc.get("thinkingBudget"))
            .and_then(|v| v.as_i64())
            .and_then(|n| match n {
                -1 => Some(crate::ir::IrReasoningAsk::Dynamic),
                n if n > 0 => u32::try_from(n).ok().map(crate::ir::IrReasoningAsk::Budget),
                _ => None, // 0 = thinking off; absent ask carries "off" faithfully
            });
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        // Promote Gemini's native `toolConfig.functionCallingConfig` into the IR `tool_choice` union
        // (PF-H1) so a forced / targeted directive survives the cross-protocol seam instead of
        // degrading to `auto`. The raw `toolConfig` is ALSO preserved in `extra` (it is not in
        // `modeled_keys`, like `generationConfig`), so a same-protocol Gemini→Gemini passthrough stays
        // byte-identical; the writer overlays a fresh `functionCallingConfig` from this typed field.
        let tool_choice = read_gemini_tool_choice(obj.get("toolConfig"));

        // Collect unmodeled top-level keys into extra (excluding modeled ones). `model` is in the
        // set so the loop below does NOT re-insert it: it is preserved in `extra` exactly once via
        // the explicit pre-insert below (preventing the silent duplicate insert the loop used to
        // perform, which would be discarded the moment the two writes ever diverged).
        //
        // `stream` is NOT in `modeled_keys`: when the SOURCE body carries it, it is preserved through
        // `extra` and echoed back by the writer — mirroring how `model` (also captured into a typed
        // field) round-trips, so a read→write of a body that carried `stream` stays byte-identical
        // (the `test_gemini_roundtrip_identity` invariant). `IrRequest.stream` (captured above) is the
        // source of truth for path selection (`upstream_path_for_stream`); the `extra` copy is purely
        // for round-trip fidelity. The router-injected `stream`/shim NEVER reach a real backend
        // because `forward::strip_router_shim_keys` now runs UNCONDITIONALLY (same- AND cross-protocol)
        // before the upstream call.
        //
        // The router-internal `__busbar_gemini_json_array` shim IS in `modeled_keys`, so it never
        // enters `extra` and can never be re-emitted onto a cross-protocol upstream body by a
        // downstream writer. Unlike `stream` it is not a caller field with any round-trip meaning (a
        // native Gemini request never carries it), so excluding it costs no fidelity. Previously it
        // was absent from the set, so the CROSS-protocol path (which rebuilds the body via
        // read/write_request, bypassing the same-protocol-only strip that existed before this fix)
        // swept it into `extra` and every egress writer re-emitted this router fingerprint onto a
        // foreign OpenAI/Anthropic/Cohere/Bedrock backend. Both the unconditional forward-layer strip
        // and this exclusion now guard that leak (defense in depth).
        //
        // The set is a compile-time constant, so it is built ONCE into a process-global `OnceLock`
        // rather than re-allocated and re-hashed on every ingress `read_request` (it was previously
        // rebuilt per request — heap churn + hashing on the hot path under load). All members are
        // `&'static str` (`GEMINI_JSON_ARRAY_SHIM_KEY` is a `&'static str` const), so the cached set
        // borrows nothing request-scoped and is cache-hot after first call. Mirrors the lazy-static
        // pattern used elsewhere for per-request constant lookups.
        let modeled_keys = modeled_request_keys();

        // model is modeled but we preserve it in extra for round-trip identity. Done once here;
        // the loop skips it because `model` is in `modeled_keys`.
        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
        }

        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        Ok(crate::ir::IrRequest {
            reasoning,
            reasoning_budgets: None,
            logprobs,
            top_logprobs,
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
            n,
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

        // 0. Inline error envelope. A native Gemini `streamGenerateContent?alt=sse` stream can
        // deliver a `{"error":{"code","message","status"}}` (google.rpc.Status) object as a
        // 200-status SSE data chunk mid-stream (e.g. an upstream RESOURCE_EXHAUSTED that surfaces
        // after the connection is established). The chunk is a JSON object (not `[DONE]`) carrying
        // NO `candidates`, so without this arm the reader would emit a bare `MessageStart` and then
        // EOF — no `IrStreamEvent::Error`, no terminal MessageDelta/MessageStop — silently swallowing
        // the failure and leaving the downstream client (or cross-protocol ingress writer) on a
        // hung/non-terminated stream while the breaker/observability never see it. forward.rs only
        // converts HTTP-status-level errors, so an inline 200-status error object bypasses that path
        // entirely. Mirror the Bedrock reader's inline `*Exception` surfacing (bedrock.rs)
        // and the Cohere terminal `ERROR` mapping (cohere.rs): map `error.status`/`error.code`
        // to a canonical `StatusClass` and push a single `IrStreamEvent::Error` so the downstream
        // writer terminates the stream with a native error frame. This is handled BEFORE the
        // MessageStart/candidates block so an error-only chunk never emits a stray MessageStart.
        if let Some(error_obj) = data.get("error").and_then(|e| e.as_object()) {
            let status_str = error_obj.get("status").and_then(|s| s.as_str());
            let code = error_obj.get("code").and_then(|c| c.as_u64());
            let class = gemini_error_status_class(status_str, code);
            let message = error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .map(String::from)
                .or_else(|| status_str.map(String::from));
            out.push(IrStreamEvent::Error(crate::proto::IrError {
                class,
                provider_signal: message,
                retry_after: None,
            }));
            return out;
        }

        // 0b. Prompt-blocked envelope. A native Gemini `generateContent`/`streamGenerateContent`
        // can reject the PROMPT itself (not the candidate) — the chunk carries a top-level
        // `promptFeedback.blockReason` (e.g. SAFETY/BLOCKLIST/PROHIBITED_CONTENT/OTHER), NO
        // `candidates`, and NO `error` envelope. Without this arm the reader would emit only a bare
        // `MessageStart` (from the block below) and then EOF — no `finishReason`, so no closing
        // `MessageDelta`/`MessageStop` — leaving the downstream client on a hung, non-terminated
        // stream with an empty response and the breaker/observability never seeing the block.
        // Surface it as a proper terminal sequence (MessageStart once, then a `safety`
        // MessageDelta + MessageStop) so the stream terminates cleanly with a content-policy stop.
        // Guarded on candidates-ABSENT so a normal chunk that happens to also carry promptFeedback
        // alongside candidates is still processed by the candidate path below. Handled before the
        // MessageStart/candidates block.
        if candidates_absent(data) {
            if let Some(block_reason) = prompt_block_reason(data) {
                if !state.started {
                    state.started = true;
                    let id = data
                        .get(FIELD_RESPONSE_ID)
                        .and_then(|i| i.as_str())
                        .map(String::from);
                    let model = data
                        .get(FIELD_MODEL_VERSION)
                        .or_else(|| data.get("model"))
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created: None,
                        model,
                    });
                }
                // Close any blocks opened by earlier chunks in this stream before the terminal
                // MessageDelta — a mid-stream prompt-block can land after a normal text/tool chunk
                // already pushed BlockStart(s). Mirror the finishReason path (~793-802) exactly so
                // the IR stream stays balanced; without this the open BlockStart events never get a
                // matching BlockStop, producing an unbalanced stream downstream.
                if state.thinking_block_open {
                    state.thinking_block_open = false;
                    out.push(IrStreamEvent::BlockStop { index: 0 });
                }
                if state.text_block_open {
                    state.text_block_open = false;
                    let ti = state.text_index.take().unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
                for oai_idx in std::mem::take(&mut state.open_tools) {
                    out.push(IrStreamEvent::BlockStop { index: oai_idx });
                }
                let usage = gemini_usage(data);
                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: Some(prompt_block_stop_reason(block_reason)),
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
                return out;
            }
        }

        // 1. MessageStart exactly once on first chunk. Capture the stream identity from the first
        // chunk so same-protocol passthrough preserves it: streamed Gemini chunks carry the same
        // `responseId`/`modelVersion` as the whole-response body. Gemini streams carry no `created`
        // timestamp, so it stays `None` (the writer omits it rather than fabricate one).
        if !state.started {
            state.started = true;
            let id = data
                .get(FIELD_RESPONSE_ID)
                .and_then(|i| i.as_str())
                .map(String::from);
            let model = data
                .get(FIELD_MODEL_VERSION)
                .or_else(|| data.get("model"))
                .and_then(|m| m.as_str())
                .map(String::from);
            out.push(IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id,
                created: None,
                model,
            });
        }

        let candidates = data.get("candidates").and_then(|c| c.as_array());

        // Process ONLY the first candidate, mirroring the non-streaming `read_response` (which reads
        // `candidates[0]`). Gemini's `streamGenerateContent` honors
        // `generationConfig.candidateCount > 1`, so a chunk may carry N candidates each with its own
        // `finishReason`. Iterating EVERY candidate (the old behavior) emitted a full terminal
        // sequence — close text/tool blocks, then MessageDelta + MessageStop — once PER candidate, so
        // a downstream Anthropic/OpenAI ingress writer produced multiple `message_stop`/
        // `message_delta` frames on a single stream (a protocol violation a strict SDK rejects, and a
        // detectable proxy tell), and `state.open_tools` was drained N times with the tool-index
        // bookkeeping resetting per candidate. Collapsing to the first candidate makes the streaming
        // and non-streaming paths agree and guarantees exactly one terminal sequence per stream.
        if let Some(candidate) = candidates.and_then(|cands| cands.first()) {
            // 2. Process content parts (text + functionCall)
            if let Some(content) = candidate.get("content") {
                let role_val = content.get("role").and_then(|r| r.as_str()).unwrap_or("");

                if role_val == "model" || role_val.is_empty() {
                    if let Some(parts_arr) = content.get("parts").and_then(|p| p.as_array()) {
                        // A text block, when one opens this stream, owns IR index 0; tool blocks
                        // then take indices 1..n. A tool-only stream reserves nothing for text and
                        // starts its tools at index 0 (see the tool branch below). The next tool
                        // index is derived from persistent state (`open_tools`) rather than a
                        // per-chunk local, so indices stay stable across the multiple SSE chunks of
                        // a single response.
                        for part in parts_arr {
                            // A `thought: true` part is streamed REASONING, not answer text (the
                            // same D4 rule the buffered reader applies). Route it to a Thinking
                            // block at index 0 ahead of the answer, mirroring the OpenAI reader's
                            // reasoning handling — without this arm a Gemini backend's thinking
                            // LEAKED INTO THE ANSWER TEXT on every cross-protocol stream (caught by
                            // the harness's reasoning-STREAM rows). Same gate as the OpenAI reader:
                            // once the answer phase has begun, index 0 is taken and a stray late
                            // thought part is dropped rather than corrupting block pairing.
                            if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                    if !text.is_empty()
                                        && !state.text_block_open
                                        && state.open_tools.is_empty()
                                    {
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
                                            delta: crate::ir::IrDelta::ThinkingDelta(
                                                text.to_string(),
                                            ),
                                        });
                                        if let Some(sig) = part
                                            .get("thoughtSignature")
                                            .and_then(|v| v.as_str())
                                        {
                                            out.push(IrStreamEvent::BlockDelta {
                                                index: 0,
                                                delta: crate::ir::IrDelta::SignatureDelta(
                                                    sig.to_string(),
                                                ),
                                            });
                                        }
                                    }
                                }
                                continue;
                            }

                            // Text block. The text block claims the next free IR index BY ORDER OF
                            // FIRST APPEARANCE (a thinking block when present owns 0, then the
                            // count of tool blocks already opened), NOT a hardcoded 0. A tool that
                            // arrives before the first text part takes the first free slot and
                            // text takes the next, so blocks never collide on an index regardless
                            // of Gemini's part ordering; the index is then stable for the stream.
                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                if !text.is_empty() {
                                    let offset = usize::from(state.reasoning_seen);
                                    let ti = state
                                        .text_index
                                        .unwrap_or(offset + state.open_tools.len());
                                    if state.thinking_block_open {
                                        state.thinking_block_open = false;
                                        out.push(IrStreamEvent::BlockStop { index: 0 });
                                    }
                                    if !state.text_block_open {
                                        state.text_block_open = true;
                                        state.text_index = Some(ti);
                                        out.push(IrStreamEvent::BlockStart {
                                            index: ti,
                                            block: crate::ir::IrBlockMeta::Text,
                                        });
                                    }
                                    out.push(IrStreamEvent::BlockDelta {
                                        index: ti,
                                        delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                    });
                                }
                            }

                            // FunctionCall (ToolUse) - Gemini sends whole args, not streamed
                            if let Some(func_call) = part.get(FIELD_FUNCTION_CALL) {
                                let name_val = func_call
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                // Bound `state.open_tools` so an adversarial/buggy upstream that
                                // streams an unbounded run of `functionCall` parts without ever
                                // emitting `finishReason` (the only event that drains the set)
                                // cannot grow per-request heap without bound. Past the cap we
                                // skip recording the frame AND emitting its BlockStart/BlockDelta
                                // — the next index is derived from `open_tools.len()`, so a
                                // recorded-but-uncapped frame would also produce duplicate
                                // indices once growth stalled. No legitimate Gemini turn carries
                                // this many parallel tool calls. Mirrors the Cohere reader's cap.
                                if !name_val.is_empty()
                                    && state.open_tools.len() < MAX_GEMINI_TOOL_FRAMES
                                {
                                    // A tool block claims the next free IR index by order of first
                                    // appearance: the count of tool blocks already opened, plus 1 iff
                                    // the text block has ALREADY claimed a slot this stream
                                    // (`text_index.is_some()`, a PERSISTENT marker — not the live
                                    // `text_block_open` flag). Keying on the persistent marker keeps a
                                    // tool-only stream contiguous from 0 while guaranteeing text and
                                    // tools never collide on an index regardless of arrival order:
                                    // tool-before-text → tool takes 0, text takes the next slot;
                                    // text-before-tool → text takes 0, tools take 1.. . Recorded in
                                    // `open_tools` so the finishReason handler emits a matching
                                    // BlockStop for every tool block.
                                    let offset = usize::from(state.reasoning_seen);
                                    let text_base = usize::from(state.text_index.is_some());
                                    let ir_idx = offset + text_base + state.open_tools.len();
                                    state.open_tools.insert(ir_idx);

                                    // A zero-arg Gemini `functionCall` either omits `args` or sends
                                    // `{}`. Default the MISSING case to an empty JSON OBJECT, not
                                    // `null`: the args field models a tool-call argument map, so a
                                    // no-arg call is the empty object `{}`. Serializing `null` instead
                                    // produced `"input": null` / `"arguments": "null"` on cross-protocol
                                    // Anthropic/OpenAI egress — an invalid tool-call input shape a strict
                                    // SDK rejects (it expects an object). `empty_object_if_absent` keeps
                                    // an explicitly-present `args` (even an explicit `null`) verbatim.
                                    let args = empty_object_if_absent(func_call.get("args"));

                                    // Gemini streams carry no tool-call id; synthesize a stable,
                                    // non-empty one keyed by (tool-position, name) so the
                                    // Anthropic/OpenAI stream writers emit a non-empty id on the
                                    // content_block_start. Tool blocks occupy indices
                                    // `text_base..text_base+n`, so `ir_idx - text_base` is the
                                    // 0-based tool position.
                                    let id = synth_tool_call_id(ir_idx - text_base, &name_val);
                                    out.push(IrStreamEvent::BlockStart {
                                        index: ir_idx,
                                        block: crate::ir::IrBlockMeta::ToolUse {
                                            id,
                                            name: name_val.clone(),
                                        },
                                    });

                                    // Emit the whole args as InputJsonDelta (Gemini doesn't stream functionCall)
                                    let args_str =
                                        crate::json::to_string(&args).unwrap_or_default();
                                    out.push(IrStreamEvent::BlockDelta {
                                        index: ir_idx,
                                        delta: crate::ir::IrDelta::InputJsonDelta(args_str),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 2b. L2-5 STREAMING citations. Gemini delivers grounding/web-search citations at the
            // CANDIDATE level (`candidates[].citationMetadata.citationSources[]`), typically on a
            // late chunk (often the same chunk that carries `finishReason`), not per content-part.
            // Reuse `read_gemini_citations` so each source's neutral fields + byte-exact `raw` are
            // filled (same as the non-stream path), then carry them as ONE `IrDelta::CitationsDelta`
            // attached to the active text block's index. The IR's delta model keys a BlockDelta to a
            // block index; a grounding citation annotates the answer text, so we open/own the text
            // block's index (`state.text_index`, or the next free slot if no text part has appeared
            // yet) and emit the citations delta against it BEFORE the finishReason path closes the
            // block below. Without this arm a streamed Gemini citation was silently dropped.
            let citations = read_gemini_citations(candidate);
            if !citations.is_empty() {
                let ti = state.text_index.unwrap_or(state.open_tools.len());
                if !state.text_block_open {
                    state.text_block_open = true;
                    state.text_index = Some(ti);
                    out.push(IrStreamEvent::BlockStart {
                        index: ti,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
                out.push(IrStreamEvent::BlockDelta {
                    index: ti,
                    delta: crate::ir::IrDelta::CitationsDelta(citations),
                });
            }

            // 2c. STREAMING logprobs. Gemini carries a chunk's per-token logprobs at the candidate
            // level (`candidates[].logprobsResult`), parallel to the content parts of that chunk.
            // Same anchoring rule as the citations arm above: the delta attaches to the active text
            // block's index (opening it if no text part has arrived yet) so an OpenAI-dialect
            // stream can re-emit them as `choices[].logprobs.content[]`.
            let stream_logprobs = read_gemini_logprobs(candidate.get("logprobsResult"));
            if !stream_logprobs.is_empty() {
                let ti = state.text_index.unwrap_or(state.open_tools.len());
                if !state.text_block_open {
                    state.text_block_open = true;
                    state.text_index = Some(ti);
                    out.push(IrStreamEvent::BlockStart {
                        index: ti,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
                out.push(IrStreamEvent::BlockDelta {
                    index: ti,
                    delta: crate::ir::IrDelta::LogprobsDelta(stream_logprobs),
                });
            }

            // 3. finishReason → close blocks + MessageDelta + MessageStop
            if let Some(finish_reason_val) =
                candidate.get(FIELD_FINISH_REASON).and_then(|r| r.as_str())
            {
                // PF-M2: map Gemini's full FinishReason set to the canonical IR stop reasons (no
                // verbatim-lowercased Gemini-only token leaks to a non-Gemini client).
                let mut stop_reason = map_gemini_finish_reason(finish_reason_val);

                // Gemini's `FinishReason` enum has NO TOOL_USE member: a tool-call turn ends with
                // STOP, mapped to `end_turn` above. But this turn emitted `functionCall` parts (tracked
                // in `state.open_tools`, still populated here — it is drained just below), and every
                // other protocol reader emits the canonical `tool_use` stop reason for a tool-call
                // turn. Promote `end_turn` → `tool_use` so the streamed terminal reason matches the
                // tool blocks; cross-protocol egress (Anthropic relays `tool_use`; OpenAI maps it to
                // `"tool_calls"`) then carries the right value. The Gemini writer maps
                // `Some("tool_use")` back to STOP, keeping same-protocol streaming lossless. Only a
                // bare `end_turn` is promoted; a tool-call truncated/blocked mid-flight keeps its
                // stronger `max_tokens`/`safety` reason.
                if stop_reason == crate::ir::IrStopReason::EndTurn && !state.open_tools.is_empty() {
                    stop_reason = crate::ir::IrStopReason::ToolUse;
                }

                // Close a still-open thinking block first (a thinking-only stream never opens a
                // text block, so the finish path is the only closer).
                if state.thinking_block_open {
                    state.thinking_block_open = false;
                    out.push(IrStreamEvent::BlockStop { index: 0 });
                }
                // Close text block next if open, at the index it actually claimed (not a hardcoded
                // 0 — a thinking block or tool may have taken 0 ahead of it).
                if state.text_block_open {
                    state.text_block_open = false;
                    let ti = state.text_index.take().unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }

                // Close tools in ascending order (track via open_tools)
                for oai_idx in std::mem::take(&mut state.open_tools) {
                    out.push(IrStreamEvent::BlockStop { index: oai_idx });
                }

                // Parse usageMetadata if present
                let usage = gemini_usage(data);

                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: Some(stop_reason),
                    // Gemini has no stop_sequence analog in its stream.
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
            }
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        // Prompt-blocked envelope. A native Gemini `generateContent` can reject the PROMPT itself
        // (not a candidate): the body carries a top-level `promptFeedback.blockReason` (e.g.
        // SAFETY/BLOCKLIST/PROHIBITED_CONTENT/OTHER), NO `candidates`, and NO `error` envelope.
        // Hard-failing the absent-candidates path below turned this legitimate content-policy block
        // into a spurious `ir_parse` ClientError (→ a confusing 4xx with no surfaced reason) instead
        // of a clean empty response carrying a `safety` stop. Detect it here — candidates ABSENT plus
        // a `promptFeedback.blockReason` — and return an empty-content response with the mapped stop
        // reason, mirroring the streaming reader's prompt-block terminal sequence and the
        // SAFETY-filtered-candidate tolerance below. Usage is still surfaced when present.
        if candidates_absent(body) {
            if let Some(block_reason) = prompt_block_reason(body) {
                let usage = gemini_usage(body);
                let model = obj
                    .get(FIELD_MODEL_VERSION)
                    .or_else(|| obj.get("model"))
                    .and_then(|m| m.as_str())
                    .map(String::from);
                let id = obj
                    .get(FIELD_RESPONSE_ID)
                    .and_then(|i| i.as_str())
                    .map(String::from);
                return Ok(crate::ir::IrResponse {
                    logprobs: Vec::new(),
                    role: crate::ir::IrRole::Assistant,
                    content: Vec::new(),
                    stop_reason: Some(prompt_block_stop_reason(block_reason)),
                    usage,
                    model,
                    id,
                    created: None,
                    system_fingerprint: None,
                    stop_sequence: None,
                });
            }
        }

        // Parse candidates array - must have at least one
        let candidates_val = obj.get("candidates").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;
        let candidates = candidates_val.as_array().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        if candidates.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let candidate = &candidates[0];

        // Parse content → IrResponse.content. `content` is ABSENT on a safety/recitation-filtered
        // candidate: a native Gemini response with `finishReason: SAFETY` (or RECITATION, etc.)
        // carries only `finishReason` + `safetyRatings` and NO `content` field. Treat missing content
        // as an empty content list and continue to the `finishReason` mapping below — mirroring the
        // STREAMING reader, which guards content with `if let Some(content)` and skips it when absent.
        // Hard-failing here turned a legitimate filtered response into a spurious 500.
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        // Per-response tool-call index feeding `synth_tool_call_id` (Gemini carries no tool id).
        let mut tool_call_index: usize = 0;
        if let Some(parts_arr) = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
        {
            for part in parts_arr {
                // Thinking part (H2) → IrBlock::Thinking. Gemini DOES surface reasoning: a content
                // part flagged `thought: true` carries the model's chain-of-thought `text` plus an
                // opaque `thoughtSignature` (the resumable-reasoning token the google-genai SDK
                // exposes as `Part.thought_signature`). Read it into the IR Thinking block (with its
                // signature) rather than as plain Text, so reasoning survives the cross-protocol seam
                // (Anthropic `thinking` / OpenAI reasoning) and the signature round-trips on
                // same-protocol Gemini→Gemini. Checked BEFORE the plain-text arm because a thought
                // part also has a `text` field.
                if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                    let text = part
                        .get("text")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    let signature = part
                        .get("thoughtSignature")
                        .and_then(|s| s.as_str())
                        .map(String::from);
                    content.push(crate::ir::IrBlock::Thinking {
                        text,
                        signature,
                        redacted: false,
                        cache_control: None,
                    });
                }
                // Text part → IrBlock::Text
                else if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    if !text.is_empty() {
                        content.push(crate::ir::IrBlock::Text {
                            text: text.to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        });
                    }
                }

                // FunctionCall → IrBlock::ToolUse. Gemini carries no id, so synthesize a stable,
                // non-empty one keyed by (index, name) — the writer ignores the ToolUse `id`, and
                // cross-protocol Anthropic/OpenAI egress requires a non-empty id for correlation.
                if let Some(func_call) = part.get(FIELD_FUNCTION_CALL) {
                    let name_val = func_call
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    // Zero-arg functionCall → empty JSON OBJECT, not `null` (see the streaming
                    // reader's note): the tool-call input is an argument map, so a no-arg call is `{}`.
                    let args = empty_object_if_absent(func_call.get("args"));

                    let id = synth_tool_call_id(tool_call_index, &name_val);
                    tool_call_index += 1;
                    content.push(crate::ir::IrBlock::ToolUse {
                        id,
                        name: name_val,
                        input: args,
                        cache_control: None,
                    });
                }
            }
        }

        // L2: grounding/web-search citations. Gemini reports them at the CANDIDATE level
        // (`candidates[].citationMetadata.citationSources[]`), not per content-part, whereas the IR
        // carries citations ON a Text block. Attach the mapped citations to the FIRST Text block of
        // the candidate so they survive the seam (cross-protocol Anthropic egress re-emits them, and
        // a same-protocol Gemini path re-emits them at candidate level). If the candidate has no Text
        // block (e.g. a tool-only turn) there is nothing to anchor them to — Gemini does not emit
        // citations for such turns in practice, so dropping is faithful.
        let gemini_citations = read_gemini_citations(candidate);
        if !gemini_citations.is_empty() {
            if let Some(crate::ir::IrBlock::Text { citations, .. }) = content
                .iter_mut()
                .find(|b| matches!(b, crate::ir::IrBlock::Text { .. }))
            {
                *citations = gemini_citations;
            }
        }

        // Parse finishReason → stop_reason (map Gemini→canonical)
        let stop_reason = candidate
            .get(FIELD_FINISH_REASON)
            .and_then(|r| r.as_str())
            // PF-M2: canonical-map the full Gemini FinishReason set (see
            // `map_gemini_finish_reason`) so a Gemini-only reason never reaches a non-Gemini
            // client as an unrecognized lowercased token.
            .map(map_gemini_finish_reason);

        // Gemini's `FinishReason` enum has NO TOOL_USE member: a tool-call turn ends with STOP, which
        // maps to `end_turn` above. But the IR carries `ToolUse` blocks in `content`, and every other
        // protocol reader emits the canonical `tool_use` stop reason for a tool-call turn. Promote
        // `end_turn` → `tool_use` whenever a `ToolUse` block is present so the canonical IR is correct
        // and cross-protocol egress (Anthropic relays `tool_use`; OpenAI maps it to `"tool_calls"`)
        // matches the content. The Gemini writer maps `Some("tool_use")` back to STOP, so the
        // same-protocol Gemini→Gemini round-trip stays lossless. Only a bare `end_turn` is promoted;
        // `max_tokens`/`safety`/etc. (a tool-call truncated/blocked mid-flight) keep their stronger
        // terminal reason.
        let stop_reason = match stop_reason {
            Some(crate::ir::IrStopReason::EndTurn)
                if content
                    .iter()
                    .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })) =>
            {
                Some(crate::ir::IrStopReason::ToolUse)
            }
            other => other,
        };

        // Parse usageMetadata: promptTokenCount→input_tokens, candidatesTokenCount→output_tokens
        let usage = gemini_usage(body);

        // Gemini reports the serving model as `modelVersion` (fall back to `model`).
        let model = obj
            .get(FIELD_MODEL_VERSION)
            .or_else(|| obj.get("model"))
            .and_then(|m| m.as_str())
            .map(String::from);

        // Capture the upstream response identity so same-protocol (Gemini→Gemini) passthrough
        // preserves it byte-for-byte. The native generateContent body carries an opaque
        // `responseId` (surfaced by the official `google-genai` SDK as
        // `GenerateContentResponse.response_id`); Gemini bodies carry NO `created`/timestamp field,
        // so `created` stays `None` here and the writer omits it (synthesizing one would be a
        // fabricated field a native client never sees). `system_fingerprint`/`stop_sequence` have
        // no Gemini analogue and remain `None`.
        let id = obj
            .get(FIELD_RESPONSE_ID)
            .and_then(|i| i.as_str())
            .map(String::from);

        // Per-token logprobs from the candidate's `logprobsResult`, carried neutrally so an
        // OpenAI-dialect caller receives them as `choices[].logprobs.content[]`.
        let logprobs = read_gemini_logprobs(candidate.get("logprobsResult"));

        Ok(crate::ir::IrResponse {
            logprobs,
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

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

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
/// `LANGUAGE`, and any unknown future reason → `end_turn` (a benign natural stop) — were previously
/// passed through `to_lowercase()` VERBATIM, producing values (`recitation`, `malformed_function_call`,
/// `spii`, …) that NO downstream SDK enum recognizes. Mapping them to the canonical IR set the
/// Anthropic/OpenAI writers already translate (`safety`→Anthropic `safety`/OpenAI `content_filter`;
/// `error`/`end_turn`→`end_turn`/`stop`) keeps the translation lossless instead of leaking an
/// unrecognized Gemini token to a non-Gemini client. A Gemini→Gemini round-trip is unaffected: the
/// writer's reverse map turns `end_turn` back into `STOP` and `safety` back into `SAFETY` (the
/// dominant cases), and these stops are terminal — the body is not replayed.
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
        GEMINI_FINISH_SAFETY | "BLOCKLIST" | GEMINI_FINISH_PROHIBITED_CONTENT => S::Safety,
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

impl ProtocolWriter for GeminiWriter {
    fn upstream_path(&self) -> &str {
        // Model-independent fallback; the real per-request path comes from upstream_path_for().
        GEMINI_PATH_BASE
    }

    /// Gemini's URL embeds the model AND the stream mode. Streaming requests go to
    /// `:streamGenerateContent?alt=sse` (the gemini reader already decodes those SSE chunks);
    /// non-streaming to `:generateContent`.
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        if stream {
            // SSE streaming endpoint. `alt=sse` yields `data:`-framed chunks the gemini
            // reader's read_response_events already decodes.
            format!("{GEMINI_PATH_BASE}/{model}:streamGenerateContent?alt=sse")
        } else {
            format!("{GEMINI_PATH_BASE}/{model}:generateContent")
        }
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("{GEMINI_PATH_BASE}/{model}:generateContent")
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Validate the credential against the HTTP header-value byte rules (`HeaderValue::from_str`
        // rejects ASCII control bytes such as a newline or NUL). A mis-encoded key — e.g. a stray
        // newline injected by a config system — would otherwise be SILENTLY swallowed into an empty
        // `x-goog-api-key` value, and every request to the lane would get a Google-side 401 with NO
        // proxy-side signal
        // (the operator cannot tell a bad credential from a bad encoding). Instead, surface a
        // `tracing::warn!` and OMIT the header entirely (empty vec) — mirroring bedrock's
        // misconfigured-credential path, which returns no signature rather than a meaningless empty
        // one. The request is still sent (the trait can't refuse it here) and Google answers 401, but
        // the warn line tells the operator the lane's credential bytes are invalid. The key itself is
        // NEVER logged (it is the secret); only the fact that it is malformed.
        match HeaderValue::from_str(key) {
            Ok(value) => vec![(HeaderName::from_static("x-goog-api-key"), value)],
            Err(_) => {
                tracing::warn!(
                    "gemini: x-goog-api-key credential contains invalid header bytes (ASCII \
                     control character); omitting auth header — upstream will reject with 401"
                );
                Vec::new()
            }
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        // systemInstruction.parts[] from IrRequest.system
        if !req.system.is_empty() {
            let parts: Vec<_> = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        Some(serde_json::json!({ "text": text }))
                    }
                    // Gemini's systemInstruction.parts carries text only. Drop any non-Text system
                    // block WITH a warn (matching cohere's warn for the same case) rather than
                    // vanishing silently — a system array with a non-text block is degenerate.
                    _ => {
                        tracing::warn!(
                            "dropping non-text system block on Gemini egress: systemInstruction \
                             carries text only"
                        );
                        None
                    }
                })
                .collect();
            if !parts.is_empty() {
                out.insert(
                    "systemInstruction".to_string(),
                    serde_json::json!({ "parts": parts }),
                );
            }
        }

        // Cross-protocol tool-id → function-name map for `functionResponse.name` correlation.
        //
        // Gemini correlates a `functionResponse` to its `functionCall` strictly BY NAME — the wire
        // format carries no call ids. On a SAME-protocol (Gemini→Gemini) turn the reader already sets
        // each ToolResult's `tool_use_id` to the function name (Gemini's only result-side handle), so
        // round-tripping it straight into `functionResponse.name` is correct. But on a CROSS-protocol
        // seam (Anthropic/OpenAI ingress → Gemini egress) the IR's ToolUse blocks carry a SYNTHETIC
        // `call_<hash>` id and the matching ToolResult's `tool_use_id` carries that SAME synthetic id
        // — NOT the real function name. Emitting that hash as `functionResponse.name` while
        // `functionCall.name` stays the real `get_weather` left the backend unable to correlate, so
        // every cross-protocol→Gemini multi-turn tool call broke.
        //
        // Build a `tool_use_id -> function_name` map from ALL ToolUse blocks across the whole request
        // (a later turn's result references an earlier turn's call), then resolve the real name in the
        // ToolResult arm below, FALLING BACK to the `tool_use_id` itself when it is not in the map —
        // which preserves the same-protocol case where `tool_use_id` already IS the function name.
        let mut tool_name_by_id: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for msg in &req.messages {
            for block in &msg.content {
                if let crate::ir::IrBlock::ToolUse { id, name, .. } = block {
                    if !id.is_empty() {
                        tool_name_by_id.insert(id.as_str(), name.as_str());
                    }
                }
            }
        }

        // messages → contents (Assistant→"model", User→"user")
        let mut contents_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "model",
                // A Tool-role IR message carries `ToolResult` blocks, emitted below as Gemini
                // `functionResponse` parts. In the native Gemini GenerateContentRequest schema a
                // `functionResponse` MUST be sent under a `user`-side turn: the `model` role is
                // exclusively the assistant's turn (which produces `functionCall`s, never
                // `functionResponse`s). Emitting a `functionResponse` under `role:"model"` is a
                // non-native shape the real Gemini API / google-genai SDK rejects. Map Tool →
                // "user" (matching the Bedrock writer's `toolResult` handling).
                crate::ir::IrRole::Tool => "user",
                crate::ir::IrRole::System => continue, // Already in systemInstruction
            };

            let mut parts_arr: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        parts_arr.push(serde_json::json!({ "text": text }))
                    }
                    crate::ir::IrBlock::ToolUse {
                        id: _, name, input, ..
                    } => {
                        // ToolUse → functionCall{name, args}. `args` MUST be a JSON OBJECT (Gemini
                        // Struct); coerce any non-object input (array/scalar/null/unparseable string)
                        // the same way `functionResponse.response` is coerced below.
                        let args_val = coerce_tool_args(input);
                        let mut fc_obj = serde_json::Map::new();
                        fc_obj.insert("name".to_string(), serde_json::json!(name));
                        fc_obj.insert("args".to_string(), args_val);
                        let mut part_obj = serde_json::Map::new();
                        part_obj.insert(
                            FIELD_FUNCTION_CALL.to_string(),
                            serde_json::Value::Object(fc_obj),
                        );
                        parts_arr.push(serde_json::Value::Object(part_obj))
                    }
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } => {
                        // ToolResult → functionResponse{name, response}. Resolve the REAL function
                        // name from the cross-protocol id→name map built above so the emitted
                        // `functionResponse.name` matches the `functionCall.name` Gemini correlates
                        // against. Fall back to the `tool_use_id` itself when it is not a synthetic
                        // mapped id — that preserves the same-protocol Gemini→Gemini case where
                        // `tool_use_id` already equals the function name.
                        let name: &str = tool_name_by_id
                            .get(tool_use_id.as_str())
                            .copied()
                            .unwrap_or(tool_use_id.as_str());
                        let response_text = content
                            .iter()
                            .filter_map(|b| match b {
                                crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                // A non-Text ToolResult block is a Bedrock json-tool-result sentinel
                                // with no Gemini analog. Drop WITH a warn (drop-with-warn convention)
                                // instead of vanishing silently.
                                other => {
                                    if super::is_json_tool_result_block(other) {
                                        tracing::warn!(
                                            "dropping structured json tool-result block on Gemini \
                                             egress: a Bedrock `{{\"json\":...}}` tool-result has no \
                                             cross-protocol analog and is NOT emitted"
                                        );
                                    }
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(" ");
                        // If the joined text is valid JSON, forward it as the structured response.
                        // Otherwise (e.g. multiple plain-text chunks) wrap the raw text in
                        // `{"output": <text>}` — the Gemini functionResponse convention for
                        // plain-text tool output — rather than silently discarding the content
                        // with an empty `{}` object.
                        //
                        // Gemini's `functionResponse.response` is a protobuf Struct: it MUST be a JSON
                        // OBJECT. A non-object parse result — a JSON `null` (e.g. upstream omitted the
                        // response object and a literal "null" arrived), a bare scalar ("42", "true",
                        // "\"text\""), or an array ("[1,2]") — would be emitted verbatim and rejected by
                        // the backend (400). Coerce any non-object parsed value into a valid Struct:
                        // `null` becomes `{}` (an empty-but-valid response), and any other non-object
                        // scalar/array is wrapped under `{"output": <value>}` so its content survives.
                        let parsed: serde_json::Value = crate::json::parse_str(&response_text)
                            .unwrap_or_else(|_| serde_json::json!({ "output": response_text }));
                        let response_val: serde_json::Value = if parsed.is_object() {
                            parsed
                        } else if parsed.is_null() {
                            serde_json::json!({})
                        } else {
                            serde_json::json!({ "output": parsed })
                        };
                        parts_arr.push(serde_json::json!({
                            "functionResponse": { "name": name, "response": response_val }
                        }))
                    }
                    crate::ir::IrBlock::Image { source, .. } => match source {
                        // A remote URL → Gemini's native `fileData{fileUri}` (URL reference, not base64).
                        crate::ir::IrImageSource::Url(uri) => parts_arr.push(serde_json::json!({
                            "fileData": { "fileUri": uri }
                        })),
                        // Inline base64 → `inlineData{mimeType, data}`.
                        crate::ir::IrImageSource::Base64 { media_type, data } => {
                            parts_arr.push(serde_json::json!({
                                "inlineData": { "mimeType": media_type, "data": data }
                            }))
                        }
                        // A Responses `file_id` / Bedrock `s3Location` reference has no Gemini
                        // projection — emitting it would corrupt the part. Drop with a warn.
                        crate::ir::IrImageSource::Vendor { .. } => {
                            tracing::warn!(
                                "dropping unresolvable vendor-scoped image reference on Gemini \
                                 egress: a file_id / s3Location has no cross-vendor analog"
                            );
                        }
                    },
                    crate::ir::IrBlock::Json(_) => {
                        // Structured-json (Bedrock tool-result content) has no Gemini part shape.
                    }
                    // A REDACTED reasoning block holds opaque encrypted bytes with no Gemini analog —
                    // drop it (its `text` is not plaintext reasoning).
                    crate::ir::IrBlock::Thinking { redacted: true, .. } => {}
                    crate::ir::IrBlock::Thinking {
                        text, signature, ..
                    } => {
                        // Thinking → Gemini `{text, thought:true, thoughtSignature?}` (H2). Gemini
                        // DOES carry reasoning parts; round-trip the text and the opaque resumable
                        // `thoughtSignature`. `thoughtSignature` is emitted only when present.
                        let mut part = serde_json::Map::new();
                        part.insert("text".to_string(), serde_json::json!(text));
                        part.insert("thought".to_string(), serde_json::json!(true));
                        if let Some(sig) = signature {
                            part.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                        }
                        parts_arr.push(serde_json::Value::Object(part));
                    }
                }
            }

            // A turn whose IR blocks were ALL non-representable here leaves `parts_arr` empty.
            // SKIPPING the whole contents entry drops the turn and can break Gemini's strict
            // user/model alternation — two same-role turns then land adjacent and the API rejects the
            // request with 400 INVALID_ARGUMENT. Mirror the Bedrock writer (bedrock.rs, empty
            // `content_arr` → minimal placeholder): substitute an empty text part so the turn survives
            // the seam and alternation is preserved. System-role messages never reach here (they
            // `continue` during role mapping).
            if parts_arr.is_empty() {
                parts_arr.push(serde_json::json!({ "text": "" }));
            }
            let mut content_obj = serde_json::Map::new();
            content_obj.insert("role".to_string(), serde_json::json!(role_str));
            content_obj.insert("parts".to_string(), serde_json::Value::Array(parts_arr));
            contents_arr.push(serde_json::Value::Object(content_obj));
        }

        // Write contents to output after building all messages
        if !contents_arr.is_empty() {
            out.insert(
                "contents".to_string(),
                serde_json::Value::Array(contents_arr),
            );
        }

        // tools → tools[0].functionDeclarations[]
        if !req.tools.is_empty() {
            let func_decls: Vec<_> = req
                .tools
                .iter()
                .map(|tool| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("name".to_string(), serde_json::json!(tool.name));
                    if let Some(desc) = &tool.description {
                        obj.insert("description".to_string(), serde_json::json!(desc));
                    }
                    // L3: Gemini's tool `parameters` accept only a strict OpenAPI-3.0 Schema subset,
                    // NOT full JSON Schema. A cross-protocol tool def (OpenAI/Anthropic) routinely
                    // carries draft keywords (`$schema`, `additionalProperties`, `$ref`, …) that
                    // Gemini 400-rejects. Strip them recursively so the tool def survives the seam
                    // instead of hard-failing; same-protocol Gemini schemas (which never carry these)
                    // are unaffected.
                    obj.insert(
                        "parameters".to_string(),
                        sanitize_gemini_schema(&tool.input_schema),
                    );
                    serde_json::Value::Object(obj)
                })
                .collect();
            out.insert(
                "tools".to_string(),
                serde_json::json!([{"functionDeclarations": func_decls}]),
            );
        }

        // toolConfig{functionCallingConfig{mode, allowedFunctionNames}} (PF-H1).
        //
        // Start from the RAW `toolConfig` the reader preserved in `extra` (same-protocol Gemini→Gemini
        // byte-identity), then OVERLAY a fresh `functionCallingConfig` built from the typed
        // `req.tool_choice`. Same map key, so the overlay REPLACES (never duplicates) any preserved
        // `functionCallingConfig`. On cross-protocol egress `extra` is already cleared, so this object
        // holds only the typed `functionCallingConfig` and no foreign Gemini sub-field leaks. Mirrors
        // the `generationConfig` overlay below. Emitted only when there is something to say.
        let mut tool_config = req
            .extra
            .get("toolConfig")
            .and_then(|tc| tc.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(tc) = &req.tool_choice {
            tool_config.insert(
                "functionCallingConfig".to_string(),
                write_gemini_tool_choice(tc),
            );
        }
        if !tool_config.is_empty() {
            out.insert(
                "toolConfig".to_string(),
                serde_json::Value::Object(tool_config),
            );
        }

        // generationConfig{maxOutputTokens, temperature, topP, topK, stopSequences, …}
        //
        // Start from the RAW `generationConfig` the reader preserved in `extra` (if any) so any
        // unmodeled sub-field — `responseMimeType` (JSON mode), `thinkingConfig` (extended-thinking
        // budget), `candidateCount`, `seed`, `presencePenalty`, `frequencyPenalty`,
        // `responseModalities`, `speechConfig`, `routingConfig`, … — survives, then OVERLAY the 5
        // typed IR fields on top. This mirrors `BedrockWriter`'s `inferenceConfig` overlay. On
        // same-protocol Gemini→Gemini the overlay reproduces the original values byte-for-byte; on
        // cross-protocol egress `extra` is already cleared at the forward seam, so this object holds
        // only the 5 typed fields and no foreign Gemini sub-field leaks to a non-Gemini backend.
        let mut gen_config = req
            .extra
            .get("generationConfig")
            .and_then(|gc| gc.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(max_tokens) = req.max_tokens {
            gen_config.insert("maxOutputTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            gen_config.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling controls in Gemini's native generationConfig shape.
        if let Some(top_p) = req.top_p {
            gen_config.insert("topP".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            gen_config.insert("topK".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            gen_config.insert("stopSequences".to_string(), serde_json::json!(req.stop));
        }
        // Promoted sampling controls in Gemini's native generationConfig shape (cross-protocol
        // survival, inverse of the reader's promotion). `n` → `candidateCount` (Gemini's name).
        // Omitted when None so a request that never carried them gains nothing.
        if let Some(frequency_penalty) = req.frequency_penalty {
            gen_config.insert(
                "frequencyPenalty".to_string(),
                serde_json::json!(frequency_penalty),
            );
        }
        // The logprobs ask in Gemini's native spellings (an OpenAI `logprobs`/`top_logprobs`
        // arrives here via the IR): boolean `responseLogprobs`, top-count `logprobs`.
        if let Some(logprobs) = req.logprobs {
            gen_config.insert("responseLogprobs".to_string(), serde_json::json!(logprobs));
        }
        if let Some(top_logprobs) = req.top_logprobs {
            gen_config.insert("logprobs".to_string(), serde_json::json!(top_logprobs));
        }
        // The reasoning carry in Gemini's native spelling: `thinkingConfig.thinkingBudget`.
        // Dynamic round-trips as Gemini's own -1; effort words go through the table. (Only present
        // when the seam's per-lane capability gate allowed the ask through.)
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
            let budget: i64 = match ask {
                crate::ir::IrReasoningAsk::Dynamic => -1,
                other => i64::from(other.to_budget(table)),
            };
            gen_config.insert(
                "thinkingConfig".to_string(),
                serde_json::json!({"thinkingBudget": budget}),
            );
        }
        if let Some(presence_penalty) = req.presence_penalty {
            gen_config.insert(
                "presencePenalty".to_string(),
                serde_json::json!(presence_penalty),
            );
        }
        if let Some(seed) = req.seed {
            gen_config.insert("seed".to_string(), serde_json::json!(seed));
        }
        if let Some(n) = req.n {
            gen_config.insert("candidateCount".to_string(), serde_json::json!(n));
        }
        // response_format (M1): map the IR's normalized object back into Gemini's
        // `responseMimeType` / `responseSchema` (overlaying any raw copy preserved in `extra`). The
        // schema is sanitized of JSON-Schema keywords Gemini rejects so a cross-protocol structured
        // output definition does not 400.
        if let Some(rf) = &req.response_format {
            write_gemini_response_format(&mut gen_config, rf);
        }
        if !gen_config.is_empty() {
            out.insert(
                "generationConfig".to_string(),
                serde_json::Value::Object(gen_config),
            );
        }

        // NB: the native Gemini GenerateContentRequest schema has NO top-level `stream` field —
        // streaming is selected entirely by the URL endpoint (`:generateContent` vs
        // `:streamGenerateContent?alt=sse`, produced by `upstream_path_for_stream`). This writer
        // therefore NEVER synthesizes a `stream` member from `req.stream`; the streaming intent is
        // read only by path selection. The ONLY way a `stream` key appears on the egress body is if
        // the SOURCE request carried one and it was preserved verbatim through `extra` (the reader
        // does NOT model `stream`, mirroring how it round-trips `model` for byte-identity). For a
        // NATIVE Gemini request `extra` carries no `stream`, so the egress body carries none either.
        // On same-protocol passthrough `forward::strip_router_shim_keys` removes any router-injected
        // `stream` before the upstream call. (An earlier version of this comment wrongly claimed the
        // reader excludes `stream` via `modeled_keys`; it does not — the accurate behavior is here.)

        // Merge extra fields (may override, but that's expected behavior). `generationConfig` is
        // SKIPPED here: its raw `extra` copy was already folded into the typed-overlay `gen_config`
        // object emitted above, so re-inserting the raw copy would clobber the merge and drop the 5
        // typed overlays. Every OTHER unmodeled top-level key still round-trips verbatim.
        for (key, value) in &req.extra {
            if key == "generationConfig" {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    /// Native Gemini error envelope: `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`.
    /// This mirrors the google.rpc.Status shape every Gemini/Google AI Generative Language API error
    /// uses (and that `extract_error` above already parses on the read side: `error.code` /
    /// `error.status`). The official `google-genai` SDK raises `APIError` whose `.code`/`.status`
    /// read straight off these fields, so a native client gets its typed exception. Served as
    /// application/json (the trait contract; every vendor error envelope is JSON).
    ///
    /// `status` is mapped to the canonical google.rpc.Code name for the HTTP status; the generic
    /// `kind` is mapped onto that vocabulary where a known busbar/router category exists, otherwise
    /// the HTTP-status-derived name wins (so an unrecognized `kind` never produces a non-canonical
    /// `status` string a native SDK would choke on). No `_ =>` catch-all is used on `kind`; the
    /// final fallback is the explicit HTTP-status mapping.
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // google.rpc.Code name for an HTTP status (the canonical Generative Language API mapping).
        fn status_name_for_http(status: u16) -> &'static str {
            match status {
                400 => GRPC_INVALID_ARGUMENT,
                401 => GRPC_UNAUTHENTICATED,
                403 => GRPC_PERMISSION_DENIED,
                404 => GRPC_NOT_FOUND,
                409 => "ABORTED",
                429 => GRPC_RESOURCE_EXHAUSTED,
                499 => "CANCELLED",
                500 => GRPC_INTERNAL,
                501 => GRPC_UNIMPLEMENTED,
                503 => GRPC_UNAVAILABLE,
                504 => GRPC_DEADLINE_EXCEEDED,
                s if (400..500).contains(&s) => GRPC_INVALID_ARGUMENT,
                s if (500..600).contains(&s) => GRPC_INTERNAL,
                _ => "UNKNOWN",
            }
        }

        // Map busbar/router `kind` categories onto google.rpc.Code names where one exists. An
        // unknown `kind` yields `None` so the HTTP-status mapping (always defined) is authoritative.
        // `overloaded` (no `_error` suffix) is the bare alias `forward.rs::cross_protocol_error_kind`
        // emits for a relayed upstream 503 — it MUST map to UNAVAILABLE alongside `overloaded_error`,
        // otherwise a cross-protocol 503 fell through to `None` and (when the status arm below was
        // bypassed) could surface the wrong code/status pairing.
        fn status_name_for_kind(kind: &str) -> Option<&'static str> {
            match kind {
                "invalid_request_error" | "invalid_argument" | "bad_request" => {
                    Some(GRPC_INVALID_ARGUMENT)
                }
                "authentication_error" | "unauthenticated" | "auth" => Some(GRPC_UNAUTHENTICATED),
                "permission_error" | "permission_denied" | "forbidden" => {
                    Some(GRPC_PERMISSION_DENIED)
                }
                "not_found_error" | "not_found" => Some(GRPC_NOT_FOUND),
                "rate_limit_error" | "resource_exhausted" | "rate_limit" => {
                    Some(GRPC_RESOURCE_EXHAUSTED)
                }
                ERR_TYPE_OVERLOADED | crate::forward::KIND_OVERLOADED | "unavailable" => {
                    Some(GRPC_UNAVAILABLE)
                }
                "deadline_exceeded" | crate::forward::KIND_TIMEOUT => Some(GRPC_DEADLINE_EXCEEDED),
                crate::forward::KIND_API_ERROR | "internal" | crate::forward::KIND_SERVER_ERROR => {
                    Some(GRPC_INTERNAL)
                }
                "unimplemented" | "not_implemented" => Some(GRPC_UNIMPLEMENTED),
                _ => None,
            }
        }

        // Canonical HTTP status a google.rpc.Code name pairs with — the inverse of
        // `status_name_for_http`. Used to detect a code/status DISAGREEMENT: the real Generative
        // Language API never emits, e.g., `code:503` with `status:INTERNAL` (INTERNAL pairs with
        // 500; UNAVAILABLE pairs with 503). Exhaustive over the names `status_name_for_kind` can
        // return (no `_ =>` collapse) so a new kind→name arm forces a conscious choice here.
        fn http_for_status_name(name: &str) -> Option<u16> {
            match name {
                GRPC_INVALID_ARGUMENT => Some(400),
                GRPC_UNAUTHENTICATED => Some(401),
                GRPC_PERMISSION_DENIED => Some(403),
                GRPC_NOT_FOUND => Some(404),
                GRPC_RESOURCE_EXHAUSTED => Some(429),
                GRPC_UNAVAILABLE => Some(503),
                GRPC_DEADLINE_EXCEEDED => Some(504),
                GRPC_INTERNAL => Some(500),
                GRPC_UNIMPLEMENTED => Some(501),
                _ => None,
            }
        }

        // Prefer the `kind`-derived google.rpc.Code name ONLY when it is internally CONSISTENT with
        // the emitted `code` (the HTTP status). On a cross-protocol upstream 5xx the relay collapses
        // distinct subtypes onto a single `kind` (e.g. a 503 relayed as `api_error`→INTERNAL), which
        // would emit a `code:503 / status:INTERNAL` pair the real API never produces — a
        // distinguishability tell. When the kind-derived name's canonical HTTP status disagrees with
        // `status`, the HTTP status drives the code/status pairing so the two always stay consistent.
        let status_str = match status_name_for_kind(kind) {
            Some(name) if http_for_status_name(name) == Some(status) => name,
            _ => status_name_for_http(status),
        };

        // The real Generative Language API's bad/missing-key 400 ALWAYS carries an
        // `error.details[]` array with a single google.rpc.ErrorInfo whose `reason` is
        // `API_KEY_INVALID` (domain `googleapis.com`, service metadata
        // `generativelanguage.googleapis.com`). The `google-genai` SDK and many clients key their
        // auth-error handling off `details[].reason == "API_KEY_INVALID"`, so omitting the array on
        // our auth-failure envelope (produced by `auth.rs::unauthorized_response` for a
        // Gemini-inferred path) is a deterministic proxy tell on exactly the auth-failure surface.
        //
        // The Gemini auth-failure path (`auth.rs::auth_failure_status_and_kind`) calls this with
        // status 400, kind `invalid_request_error` (→ INVALID_ARGUMENT), and the distinctive
        // canonical bad-key message `"API key not valid. Please pass a valid API key."`
        // (`proto::vendor_auth_failure_message("gemini")`). We gate the `details[]` array on that
        // exact triple so ONLY the bad-key 400 grows the ErrorInfo — a generic malformed-request
        // 400/INVALID_ARGUMENT (which carries a DIFFERENT message and does NOT carry API_KEY_INVALID
        // at real Google) is left untouched, so we neither under-fill the auth surface nor over-fill
        // an unrelated 400 with a reason it should not carry.
        let is_auth_bad_key = status == 400
                && status_str == "INVALID_ARGUMENT" // golden wire-contract literal (kept bare on purpose)
                && message == GEMINI_BAD_KEY_MESSAGE;
        if is_auth_bad_key {
            serde_json::json!({
                "error": {
                    "code": status,
                    "message": message,
                    "status": status_str,
                    "details": [{
                        "@type": GEMINI_ERROR_INFO_TYPE_URL,
                        "reason": GEMINI_ERROR_REASON_API_KEY_INVALID,
                        "domain": "googleapis.com",
                        "metadata": {
                            "service": "generativelanguage.googleapis.com"
                        }
                    }]
                }
            })
        } else {
            serde_json::json!({
                "error": {
                    "code": status,
                    "message": message,
                    "status": status_str,
                }
            })
        }
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            // MessageStart → a leading identity-bearing chunk, ALWAYS emitted (this arm never returns
            // `None`). Native Gemini SSE chunks carry top-level `responseId`/`modelVersion`; the
            // official `google-genai` SDK reads `chunk.response_id`/`chunk.model_version` off the
            // stream. A native Gemini stream ALWAYS carries `responseId` on its first chunk, so we
            // always emit a leading frame that carries one: when the egress captured an `id` we pass it
            // through (a Gemini→Gemini stream is indistinguishable on that field); when `id` is `None`
            // (the post-strip state on a cross-protocol stream — `StreamTranslate` zeroes the foreign
            // id) we SYNTHESIZE a native-shaped `responseId` via `synth_response_id()` rather than
            // omitting it, matching the non-stream `write_response` synth-on-strip behavior. `model`,
            // when present, is added as `modelVersion`; when `None` it is simply omitted, so a `(None,
            // None)` MessageStart still emits a frame carrying a synthesized `responseId` and no
            // `modelVersion`. `created` has no Gemini stream analogue and is never emitted.
            IrStreamEvent::MessageStart { id, model, .. } => {
                let mut frame = serde_json::Map::new();
                match (id, model) {
                    (Some(id), _) => {
                        frame.insert(FIELD_RESPONSE_ID.to_string(), serde_json::json!(id));
                    }
                    // Cross-protocol stream: `StreamTranslate` strips the foreign `id` to `None`
                    // before this writer runs (it does NOT strip `model` — that is the lane's model
                    // name, emitted as `modelVersion` below). A native google-genai SDK reads
                    // `chunk.response_id` off the FIRST chunk (for observability/tracing), so emitting
                    // no identity frame at all is a detectable fidelity gap from a native Gemini stream
                    // (which always carries `responseId` in the first chunk). Synthesize one —
                    // matching the non-stream `write_response` behavior — rather than dropping it.
                    (None, _) => {
                        frame.insert(
                            FIELD_RESPONSE_ID.to_string(),
                            serde_json::json!(synth_response_id()),
                        );
                    }
                }
                // A native Gemini SSE stream ALWAYS carries `modelVersion` in the first chunk (the
                // official google-genai SDK reads `chunk.model_version`). `StreamTranslate` now
                // preserves the lane's `model` across the cross-protocol boundary, so this is
                // populated on cross-protocol streams (not just same-protocol passthrough) and the
                // SDK no longer sees an empty model on every cross-protocol response.
                if let Some(model) = model {
                    frame.insert(FIELD_MODEL_VERSION.to_string(), serde_json::json!(model));
                }
                Some(("".to_string(), serde_json::Value::Object(frame)))
            }

            // BlockStart → for a tool block, OPEN a buffer holding the tool name and an empty args
            // accumulator, and emit NO frame. A native Gemini SSE stream carries a tool call as a
            // SINGLE `functionCall` part `{name, args}`; the IR carries the name here and the
            // arguments on the following InputJsonDelta fragment(s). We accumulate name + every arg
            // fragment per block and emit the one native `{name, args}` part on BlockStop, so a
            // multi-chunk streamed `arguments` JSON reassembles into one valid functionCall (and a
            // zero-arg tool call still flushes `{name, args:{}}`). Re-opening the SAME index resets
            // its accumulator; a NEW index appends a fresh entry so parallel tool blocks (whose
            // BlockStarts are not strictly interleaved with their BlockStops) never clobber each
            // other. Text blocks have no Gemini block-start frame (inline parts) → None.
            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::ToolUse { name, .. } => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        match guard.iter_mut().find(|(idx, _, _)| idx == index) {
                            Some(entry) => {
                                entry.1 = name.clone();
                                entry.2.clear();
                            }
                            None => guard.push((*index, name.clone(), String::new())),
                        }
                    }
                    None
                }
                crate::ir::IrBlockMeta::Text
                | crate::ir::IrBlockMeta::Thinking
                | crate::ir::IrBlockMeta::Image => None,
            },

            // TextDelta → chunk with text part
            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": text}]
                            }
                        }]
                    }),
                )),

                // InputJsonDelta → ACCUMULATE this fragment into the open tool block's arg buffer and
                // emit NO frame. A cross-protocol backend streams `arguments` as MULTIPLE partial-JSON
                // fragments (`{"lo`, `c":"SF"}`); parsing each fragment independently here (as before)
                // failed on the partials (→ `args:{}`) AND emitted one nameless/partial `functionCall`
                // part per fragment — data loss plus a multi-part split a native Gemini client never
                // sees. Concatenating the fragments and emitting once on BlockStop yields the single
                // native `{name, args}` part with the FULLY reassembled arguments. If no matching open
                // block is tracked (no tool BlockStart seen, or a poisoned lock) the fragment is
                // dropped silently rather than panicking on the request path — the same degraded
                // outcome the stateless arm produced, never a crash.
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        if let Some((_, _, args)) =
                            guard.iter_mut().find(|(idx, _, _)| idx == index)
                        {
                            args.push_str(json_str);
                        }
                    }
                    None
                }

                // ThinkingDelta → a streamed Gemini thought part `{text, thought:true}` (D4). Gemini
                // models reasoning as a `thought:true` content part (see the non-stream
                // read/write_response handling), and its stream framing carries each incremental
                // reasoning fragment as exactly such a part in a `candidates[].content.parts[]` chunk —
                // the same per-chunk shape used for a `TextDelta`, just flagged `thought:true`. So we
                // emit one chunk per fragment, mirroring the non-stream `{text, thought:true}` shape.
                // Previously this returned None, silently dropping a cross-protocol reasoning stream.
                crate::ir::IrDelta::ThinkingDelta(thinking) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": thinking, "thought": true}]
                            }
                        }]
                    }),
                )),

                // SignatureDelta → a streamed thought part carrying the opaque resumable
                // `thoughtSignature` (D4). Gemini attaches the signature to a `thought:true` part
                // (non-stream emits `{text, thought:true, thoughtSignature}`); on the stream the
                // signature arrives as its own IR delta, so emit a minimal thought part bearing the
                // signature (empty text, `thought:true`) — the closest faithful streamed form, since a
                // bare signature has no accompanying incremental text. Previously dropped (None).
                crate::ir::IrDelta::SignatureDelta(sig) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": "", "thought": true, "thoughtSignature": sig}]
                            }
                        }]
                    }),
                )),
                // A streamed redacted-reasoning delta (opaque encrypted bytes) has no Gemini analog —
                // drop it rather than emit a non-native part.
                crate::ir::IrDelta::RedactedReasoningDelta(_) => None,

                // L2-5 STREAMING citations → emit a candidate-level `citationMetadata.citationSources`
                // chunk, mirroring the non-stream `read_response`/`write_response` shape (Gemini
                // carries citations at the candidate level, not per part). `write_gemini_citation`
                // re-emits a byte-exact Gemini source verbatim when `raw` is Gemini-shaped (uri /
                // startIndex / endIndex present — the same-protocol path) and synthesizes one from the
                // neutral fields otherwise (e.g. an Anthropic-sourced citation on an Anthropic→Gemini
                // hop), so a foreign `raw` never leaks through this writer. An EMPTY citation vec
                // carries nothing → emit no chunk (None) rather than a stray empty `citationMetadata`.
                crate::ir::IrDelta::CitationsDelta(citations) => {
                    if citations.is_empty() {
                        None
                    } else {
                        let sources: Vec<serde_json::Value> =
                            citations.iter().map(write_gemini_citation).collect();
                        Some((
                            "".to_string(),
                            serde_json::json!({
                                "candidates": [{
                                    "citationMetadata": { "citationSources": sources }
                                }]
                            }),
                        ))
                    }
                }
                crate::ir::IrDelta::LogprobsDelta(lps) => {
                    // Streamed logprobs (e.g. an OpenAI backend's per-chunk `logprobs.content[]`)
                    // in Gemini's native chunk shape: a candidate carrying only `logprobsResult`.
                    // An empty vec carries nothing and emits no frame.
                    if lps.is_empty() {
                        None
                    } else {
                        Some((
                            "".to_string(),
                            serde_json::json!({
                                "candidates": [{
                                    "logprobsResult": write_gemini_logprobs_result(lps)
                                }]
                            }),
                        ))
                    }
                }
            },

            // BlockStop → FLUSH the open tool block as a single native `{name, args}` part. This is
            // the ONLY point a functionCall frame is written: by here every arg fragment has been
            // accumulated, so the buffered arg string is the COMPLETE `arguments` JSON and parses
            // once into the args object (a multi-chunk stream reassembles correctly; a zero-arg call
            // — empty buffer — flushes `args:{}`, so the call is never lost). A non-tool BlockStop
            // (text block, or an index with no tracked tool) finds no entry and emits no frame. The
            // matched entry is REMOVED so parallel tool blocks each flush exactly once. A poisoned
            // lock degrades to no frame rather than panicking on the request path.
            IrStreamEvent::BlockStop { index } => {
                let flushed = match self.open_tools.lock() {
                    Ok(mut guard) => guard
                        .iter()
                        .position(|(idx, _, _)| idx == index)
                        .map(|pos| {
                            let (_, name, args) = guard.remove(pos);
                            (name, args)
                        }),
                    Err(_) => None,
                };
                flushed.map(|(name, args_str)| {
                    // Parse the fully reassembled arg string. An empty buffer (zero-arg call) or an
                    // unparseable accumulation degrades to `{}` rather than panicking — the args are
                    // best-effort, but the single-part `{name, ...}` shape and the name are always
                    // preserved.
                    let args: serde_json::Value = if args_str.is_empty() {
                        serde_json::json!({})
                    } else {
                        crate::json::parse_str(&args_str).unwrap_or_else(|_| serde_json::json!({}))
                    };
                    let mut fc_obj = serde_json::Map::new();
                    fc_obj.insert("name".to_string(), serde_json::json!(name));
                    fc_obj.insert("args".to_string(), args);
                    let mut part_obj = serde_json::Map::new();
                    part_obj.insert(
                        FIELD_FUNCTION_CALL.to_string(),
                        serde_json::Value::Object(fc_obj),
                    );
                    (
                        "".to_string(),
                        serde_json::json!({
                            "candidates": [{
                                "content": {
                                    "role": "model",
                                    "parts": [serde_json::Value::Object(part_obj)]
                                }
                            }]
                        }),
                    )
                })
            }

            // MessageDelta → chunk with finishReason + usageMetadata
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let finish_reason = stop_reason
                    .map(write_gemini_stop_reason)
                    .unwrap_or(GEMINI_FINISH_STOP);

                // Native Gemini SSE carries `usageMetadata` (incl. `totalTokenCount`) on the final
                // chunk; a strict google-genai client computing totals reads `totalTokenCount`.
                // Emit it (= prompt + candidates, saturating) alongside the component counts so the
                // streamed usage frame matches the native final-chunk shape. This path runs only on
                // cross-protocol egress (same-protocol Gemini streams pass through byte-for-byte and
                // never reach this writer), so emitting the total here cannot disturb a same-protocol
                // round-trip. Saturating add avoids an overflow panic on the request path for
                // pathological/garbage counts.
                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but Gemini's `promptTokenCount` is a TOTAL that includes the cached prefix,
                // so add `cache_read` back. Emit `cachedContentTokenCount` only when a cache read is
                // present (native shape — no spurious field otherwise). `totalTokenCount` is the
                // full prompt total + candidates.
                let cache_read = usage.cache_read_input_tokens.unwrap_or(0);
                // cache_creation is ALSO part of the TOTAL prompt count (cross-protocol ingress only).
                let prompt_total = usage
                    .input_tokens
                    .saturating_add(cache_read)
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let total = prompt_total.saturating_add(usage.output_tokens);
                let mut usage_metadata = serde_json::Map::new();
                usage_metadata.insert(
                    FIELD_PROMPT_TOKEN_COUNT.to_string(),
                    serde_json::json!(prompt_total),
                );
                usage_metadata.insert(
                    FIELD_CANDIDATES_TOKEN_COUNT.to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                usage_metadata.insert(
                    FIELD_TOTAL_TOKEN_COUNT.to_string(),
                    serde_json::json!(total),
                );
                if usage.cache_read_input_tokens.is_some() {
                    usage_metadata.insert(
                        FIELD_CACHED_CONTENT_TOKEN_COUNT.to_string(),
                        serde_json::json!(cache_read),
                    );
                }
                let mut candidate_obj = serde_json::Map::new();
                candidate_obj.insert(
                    FIELD_FINISH_REASON.to_string(),
                    serde_json::json!(finish_reason),
                );
                let mut out_obj = serde_json::Map::new();
                out_obj.insert(
                    "candidates".to_string(),
                    serde_json::Value::Array(vec![serde_json::Value::Object(candidate_obj)]),
                );
                out_obj.insert(
                    FIELD_USAGE_METADATA.to_string(),
                    serde_json::Value::Object(usage_metadata),
                );
                Some(("".to_string(), serde_json::Value::Object(out_obj)))
            }

            // MessageStop → None (no frame needed)
            IrStreamEvent::MessageStop => None,

            // Error → full google.rpc.Status envelope `{"error":{"code","message","status"}}`.
            // Real Gemini stream errors carry an HTTP `code` (int) and an UPPER_SNAKE `status`
            // (e.g. INTERNAL, UNAVAILABLE, RESOURCE_EXHAUSTED); a Gemini SDK branches on
            // `error.status`/`error.code`. Emitting only `message` (as before) was detectable and
            // left SDK retry-decision code reading null. We derive `code`/`status` from the
            // canonical `StatusClass`; an untyped/unknown class falls back to 500 / INTERNAL.
            IrStreamEvent::Error(err) => {
                let (code, status_name) = gemini_stream_error_code_status(err.class);
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "error": {
                            "code": code,
                            "message": message,
                            "status": status_name,
                        }
                    }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Build candidates array (Gemini whole-response format)
        let mut parts_arr: Vec<serde_json::Value> = Vec::new();

        // L2: collect citations from every Text block to re-emit at the candidate level
        // (`candidates[].citationMetadata.citationSources[]`) — Gemini carries citations there, not
        // per content-part. The reader anchors them to a Text block; here we hoist them back out.
        let mut citation_sources: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text {
                    text, citations, ..
                } => {
                    for c in citations {
                        citation_sources.push(write_gemini_citation(c));
                    }
                    if !text.is_empty() {
                        parts_arr.push(serde_json::json!({"text": text}));
                    }
                }

                // ToolUse → functionCall{name, args}. `args` MUST be a JSON OBJECT (Gemini Struct);
                // coerce any non-object input (array/scalar/null/unparseable string) the same way
                // `write_request` does.
                crate::ir::IrBlock::ToolUse {
                    id: _, name, input, ..
                } => {
                    let args_val = coerce_tool_args(input);
                    let mut fc_obj = serde_json::Map::new();
                    fc_obj.insert("name".to_string(), serde_json::json!(name));
                    fc_obj.insert("args".to_string(), args_val);
                    let mut part_obj = serde_json::Map::new();
                    part_obj.insert(
                        FIELD_FUNCTION_CALL.to_string(),
                        serde_json::Value::Object(fc_obj),
                    );
                    parts_arr.push(serde_json::Value::Object(part_obj));
                }

                // Thinking → Gemini `{text, thought:true, thoughtSignature?}` (H2). Gemini DOES
                // surface reasoning as a `thought:true` content part with an opaque resumable
                // `thoughtSignature`; emit it so reasoning + signature round-trip on the response
                // path instead of being dropped.
                // A REDACTED reasoning block holds opaque encrypted bytes with no Gemini analog —
                // drop it (emitting its `text` would leak the encrypted bytes as visible reasoning).
                crate::ir::IrBlock::Thinking { redacted: true, .. } => {}
                crate::ir::IrBlock::Thinking {
                    text, signature, ..
                } => {
                    let mut part = serde_json::Map::new();
                    part.insert("text".to_string(), serde_json::json!(text));
                    part.insert("thought".to_string(), serde_json::json!(true));
                    if let Some(sig) = signature {
                        part.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                    }
                    parts_arr.push(serde_json::Value::Object(part));
                }

                // Image/ToolResult not supported in response output (lossy)
                crate::ir::IrBlock::Image { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Json(_) => {}
            }
        }

        let finish_reason = resp
            .stop_reason
            .map(write_gemini_stop_reason)
            .unwrap_or(GEMINI_FINISH_STOP);

        // A native Gemini `generateContent` response ALWAYS carries
        // `usageMetadata.totalTokenCount` (= promptTokenCount + candidatesTokenCount); the
        // google-genai SDK surfaces it as `usage_metadata.total_token_count` for billing/accounting.
        // On the CROSS-protocol egress path a native Gemini client therefore expects the sum, and the
        // value is a faithfully DERIVED total from the IR counts — not a fabricated field — so we emit
        // it (mirroring the stream final-chunk frame), closing a concrete token-accounting gap and a
        // distinguishability tell. `saturating_add` avoids an overflow panic on the request path.
        //
        // We gate emission on a cross-protocol BOUNDARY signal: `resp.created.is_some()` OR
        // `resp.model.is_some()`. Gemini bodies carry no `created`, so a populated `created` means a
        // non-Gemini backend reader set it (the OpenAI reader does) — but the Anthropic, Bedrock, and
        // Cohere readers all return `created: None`, so `created` ALONE missed three of the five
        // foreign backends, dropping `totalTokenCount` for a Gemini client routed to them (the
        // google-genai SDK then read `usage_metadata.total_token_count` as None, breaking billing).
        // The Anthropic and Cohere readers DO populate `model` from the upstream body (a real
        // Anthropic `Message` / Cohere response always names its model), so OR-ing `model.is_some()`
        // closes the gap for those two as well. Bedrock's Converse body carries no body-level model
        // or timestamp, so its IR was identity-field-empty here — the residual that this gate alone
        // could not distinguish from a minimal native body. That residual is now closed UPSTREAM at
        // the cross-protocol seam (`forward.rs`), which stamps a synthesized `created` on any
        // identity-empty egress IR before this writer runs, so a Bedrock→Gemini hop arrives with
        // `created.is_some()` and emits `totalTokenCount` here just like the other backends. The OR
        // on `model` stays as defense-in-depth for any caller of this writer that bypasses the seam.
        //
        // This still keeps a SAME-protocol read→write idempotent on the in-IR identity invariant that
        // `src/proto/mod.rs::test_gemini_read_write_response_roundtrip` guards: that fixture is a
        // native Gemini body with neither `modelVersion` nor a timestamp, so `model`/`created` are
        // BOTH `None` and no `totalTokenCount` is injected — the round-trip stays byte-identical.
        // (`write_response` only ever runs on cross-protocol egress in production — same-protocol
        // passthrough is byte-exact and bypasses the writer — so this gate is conservative there.)
        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but Gemini's `promptTokenCount` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back. Emit `cachedContentTokenCount` only when a cache read is present (native
        // shape — no spurious field on a no-cache roundtrip).
        let cache_read = resp.usage.cache_read_input_tokens.unwrap_or(0);
        // cache_creation is ALSO part of the TOTAL prompt count (cross-protocol ingress only).
        let prompt_total = resp
            .usage
            .input_tokens
            .saturating_add(cache_read)
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_metadata = serde_json::Map::new();
        usage_metadata.insert(
            FIELD_PROMPT_TOKEN_COUNT.to_string(),
            serde_json::json!(prompt_total),
        );
        usage_metadata.insert(
            FIELD_CANDIDATES_TOKEN_COUNT.to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        if resp.usage.cache_read_input_tokens.is_some() {
            usage_metadata.insert(
                FIELD_CACHED_CONTENT_TOKEN_COUNT.to_string(),
                serde_json::json!(cache_read),
            );
        }
        if resp.created.is_some() || resp.model.is_some() {
            let total = prompt_total.saturating_add(resp.usage.output_tokens);
            usage_metadata.insert(
                FIELD_TOTAL_TOKEN_COUNT.to_string(),
                serde_json::json!(total),
            );
        }
        let mut candidate = serde_json::json!({
            "content": {
                "role": "model",
                "parts": parts_arr
            }
        });
        candidate[FIELD_FINISH_REASON] = serde_json::json!(finish_reason);
        // L2: re-emit candidate-level citationMetadata when the IR carried citations (grounding /
        // web-search). Only emitted when non-empty so a normal response stays byte-identical.
        if !citation_sources.is_empty() {
            candidate["citationMetadata"] = serde_json::json!({
                "citationSources": citation_sources
            });
        }
        // Carried per-token logprobs (e.g. from an OpenAI backend's `choices[].logprobs`) in
        // Gemini's native candidate shape. Only emitted when the backend produced them, matching
        // Gemini's own omission when `responseLogprobs` was not requested.
        if !resp.logprobs.is_empty() {
            candidate["logprobsResult"] = write_gemini_logprobs_result(&resp.logprobs);
        }
        let mut out = serde_json::json!({
            "candidates": [candidate]
        });
        out[FIELD_USAGE_METADATA] = serde_json::Value::Object(usage_metadata);
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out[FIELD_MODEL_VERSION] = serde_json::json!(model);
        }
        // Response identity. This mirrors the Anthropic writer's id rule, keying synthesis off
        // "did we cross a protocol boundary" (proxied by `created` being populated) rather than off
        // `id` alone, so same-protocol round-trips stay idempotent. Three cases:
        //   * Same-protocol passthrough: the Gemini reader set `id` from the upstream `responseId`
        //     (and `created == None`, since Gemini bodies carry no timestamp), so it is re-emitted
        //     verbatim — `(Some(id), _)`.
        //   * Cross-protocol with a foreign id present: the non-Gemini backend reader set `id` to
        //     that protocol's response id (OpenAI `chatcmpl-…`, Anthropic `msg_…`); the id is opaque
        //     to the Gemini SDK (Gemini ids carry no documented prefix it could reject), so we
        //     surface it verbatim — `(Some(id), _)`.
        //   * Cross-protocol with NO foreign id: `forward.rs` strips `id` to `None` on every
        //     cross-protocol response but LEAVES `created` populated as the boundary signal, so
        //     `(None, Some(_))` — synthesize a Gemini-shaped `responseId` so a native `google-genai`
        //     client reading `GenerateContentResponse.response_id` always sees a value (real Gemini
        //     responses carry one). Previously this case omitted `responseId` on EVERY
        //     cross-protocol response, a distinguishability signal; the old comment wrongly claimed a
        //     value was "always present", contradicting `forward.rs` which sets `ir.id = None`.
        //   * Minimal same-protocol IR with neither id nor created: a native body that legitimately
        //     omitted `responseId` yields `(None, None)` — omit it rather than fabricate, since
        //     `responseId` is `Optional` in the Gemini schema / SDK and fabricating one would make a
        //     read→write round-trip distinguishable from the native response.
        // Gemini bodies carry no `created`, so none is emitted in the wire shape.
        match (&resp.id, resp.created) {
            (Some(id), _) => {
                out[FIELD_RESPONSE_ID] = serde_json::json!(id);
            }
            (None, Some(_)) => {
                out[FIELD_RESPONSE_ID] = serde_json::json!(synth_response_id());
            }
            (None, None) => {}
        }
        out
    }

    fn egress_user_agent(&self) -> &'static str {
        // Google GenAI SDK UA shape — pinned, see `EGRESS_UA_GEMINI` in forward.rs.
        crate::forward::EGRESS_UA_GEMINI
    }

    fn has_model_in_url(&self) -> bool {
        // Gemini encodes the model in the URL path (`/v1beta/models/{model}:generateContent`),
        // NOT the body. The body `model` field must be stripped on the same-protocol passthrough
        // path so the native generateContent backend does not see an unexpected field.
        true
    }

    fn auth_failure_status_and_kind(&self) -> (axum::http::StatusCode, &'static str) {
        // The Generative Language API does NOT return 401/UNAUTHENTICATED for a bad API key;
        // it returns HTTP 400 with `error.status: "INVALID_ARGUMENT"`. The gemini writer maps
        // `invalid_request_error` → INVALID_ARGUMENT and echoes `code: 400`, so a 401 body
        // would be a tell the google-genai SDK never sees from real Google on the bad-key path.
        (axum::http::StatusCode::BAD_REQUEST, "invalid_request_error")
    }

    fn uses_array_stream_shim(&self) -> bool {
        // Gemini clients that send `:streamGenerateContent` WITHOUT `?alt=sse` expect a JSON-array
        // streamed body, not SSE. The route layer signals this via the GEMINI_JSON_ARRAY_SHIM_KEY;
        // this predicate gates the shim so only genuine Gemini ingress enables it — preventing a
        // body-model client from smuggling the key to force JSON-array reframing of its SSE stream.
        true
    }

    fn make_array_stream_framer(&self) -> Option<Box<dyn crate::proto::JsonArrayFramer>> {
        // Gemini `:streamGenerateContent` WITHOUT `?alt=sse` expects a JSON-array streamed body; this
        // builds the framer that reframes the (gemini-shape) SSE bytes into that array. The forward
        // path engages it only when `uses_array_stream_shim()` AND `wants_array_stream(body)` hold.
        Some(Box::new(GeminiJsonArrayFramer::new()))
    }

    fn wants_array_stream(&self, body: &serde_json::Value) -> bool {
        // The gemini ingress route injects `GEMINI_JSON_ARRAY_SHIM_KEY: true` when the client sent a
        // streaming `:streamGenerateContent` request WITHOUT `?alt=sse`. Read it here (the only site
        // that knows this shim key) so the forward core stays shim-key-agnostic.
        body.get(GEMINI_JSON_ARRAY_SHIM_KEY)
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
    }

    fn array_stream_shim_key(&self) -> Option<&'static str> {
        Some(GEMINI_JSON_ARRAY_SHIM_KEY)
    }

    fn has_native_path_not_found(&self) -> bool {
        // Gemini native NOT_FOUND responses carry a structured message naming the resource path
        // and API version (e.g. "Invalid resource path: models/{rest} is not found for API
        // version {api_version}."). All other protocols use the canonical OpenAI-shape NOT_FOUND.
        true
    }

    fn auth_failure_message(&self) -> &'static str {
        GEMINI_BAD_KEY_MESSAGE
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
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
    /// Production wiring lives in `forward.rs`: the `FirstByteBody` `Poll::Ready(None)` JSON-array
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
        // `INTERNAL`. The agnostic caller passes only the message, so forward.rs names no Gemini value.
        GeminiJsonArrayFramer::finish_with_error(self, 500, GRPC_INTERNAL, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, StreamDecodeState};

    fn collect_stream(chunks: &[serde_json::Value]) -> Vec<IrStreamEvent> {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(reader.read_response_events("", chunk, &mut state));
        }
        events
    }

    /// Regression: a streamed functionCall MUST produce a matching BlockStop for its tool block.
    /// Previously the tool index was never recorded in `state.open_tools`, so the finishReason
    /// drain (which is the only thing that closes tool blocks) left an orphaned BlockStart.
    #[test]
    fn test_stream_tool_block_is_closed() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);

        // Find the tool BlockStart and capture its index.
        let tool_start_idx = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { name, .. },
            } if name == "get_weather" => Some(*index),
            _ => None,
        });
        let idx = tool_start_idx.expect("tool BlockStart must be emitted");

        // The same index MUST be closed by a BlockStop.
        let closed = events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx));
        assert!(
            closed,
            "tool block {idx} was opened but never closed: {events:?}"
        );

        // Balance check: every BlockStart has a matching BlockStop.
        let starts = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        let stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count();
        assert_eq!(starts, stops, "unbalanced block events: {events:?}");
    }

    /// Regression: a Gemini stream chunk with `candidateCount > 1` (multiple candidates each
    /// carrying their own `finishReason`) MUST still produce EXACTLY ONE terminal sequence —
    /// one MessageDelta and one MessageStop — not one per candidate. The reader previously looped
    /// over every candidate and emitted a full close+MessageDelta+MessageStop sequence per
    /// candidate, so a downstream ingress writer saw duplicate `message_stop`/`message_delta`
    /// frames on a single stream (a protocol violation). The reader now mirrors the non-streaming
    /// `read_response`, which reads `candidates[0]` only.
    #[test]
    fn test_stream_multiple_candidates_emit_single_terminal_sequence() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [
                {
                    "content": {"role": "model", "parts": [{"text": "first"}]},
                    "finishReason": GEMINI_FINISH_STOP
                },
                {
                    "content": {"role": "model", "parts": [{"text": "second"}]},
                    "finishReason": GEMINI_FINISH_STOP
                },
                {
                    "content": {"role": "model", "parts": [{"text": "third"}]},
                    "finishReason": GEMINI_FINISH_MAX_TOKENS
                }
            ]
        })]);

        let message_stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStop))
            .count();
        assert_eq!(
            message_stops, 1,
            "exactly one MessageStop expected regardless of candidateCount: {events:?}"
        );

        let message_deltas = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
            .count();
        assert_eq!(
            message_deltas, 1,
            "exactly one MessageDelta expected regardless of candidateCount: {events:?}"
        );

        // Only the first candidate's text is surfaced; the others are ignored entirely.
        let text: String = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::TextDelta(t),
                    ..
                } => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "first", "only candidates[0] text should be emitted");

        // The single MessageStop must be the LAST event in the stream.
        assert!(
            matches!(events.last(), Some(IrStreamEvent::MessageStop)),
            "MessageStop must terminate the stream: {events:?}"
        );

        // Block events stay balanced (no per-candidate index churn).
        let starts = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        let stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count();
        assert_eq!(starts, stops, "unbalanced block events: {events:?}");
    }

    /// Regression: text + tool in the same response use distinct, stable indices (text=0, tool=1)
    /// and BOTH are closed.
    #[test]
    fn test_stream_text_and_tool_indices_stable_and_closed() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "hello"},
                        {"functionCall": {"name": "f", "args": {}}}
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);

        let text_start = events.iter().any(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                }
            )
        });
        assert!(text_start, "text block must open at index 0");

        let tool_start = events.iter().any(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse { .. }
                }
            )
        });
        assert!(tool_start, "tool block must open at index 1");

        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 })),
            "text block (0) must be closed"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 1 })),
            "tool block (1) must be closed"
        );
    }

    /// Regression (verification of the R20 #6 fix): a functionCall part BEFORE the first text part
    /// must NOT collide on IR index 0. The fix keyed the tool base on the live `text_block_open` flag,
    /// which is false at tool time in this ordering, so the tool took 0 AND text later took 0 — two
    /// BlockStart frames at index 0 (a protocol violation a strict Anthropic SDK rejects). Index-by-
    /// first-appearance: the tool takes 0, text takes the next free slot (1); each index opened and
    /// closed exactly once.
    #[test]
    fn test_stream_tool_before_text_no_index_collision() {
        // Both intra-chunk (functionCall before text in the same parts array) AND inter-chunk.
        for chunks in [
            vec![serde_json::json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [
                        {"functionCall": {"name": "f", "args": {}}},
                        {"text": "hello"}
                    ]},
                    "finishReason": GEMINI_FINISH_STOP
                }]
            })],
            vec![
                serde_json::json!({"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]}}]}),
                serde_json::json!({"candidates":[{"content":{"role":"model","parts":[{"text":"hello"}]},"finishReason": GEMINI_FINISH_STOP}]}),
            ],
        ] {
            let events = collect_stream(&chunks);
            // Exactly one BlockStart per index; no two BlockStarts share an index.
            let mut start_indices: Vec<usize> = events
                .iter()
                .filter_map(|e| match e {
                    IrStreamEvent::BlockStart { index, .. } => Some(*index),
                    _ => None,
                })
                .collect();
            let n = start_indices.len();
            start_indices.sort_unstable();
            start_indices.dedup();
            assert_eq!(
                start_indices.len(),
                n,
                "no two BlockStart frames may share an index; got duplicate in {events:?}"
            );
            // Tool took index 0 (it appeared first); text took index 1.
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    IrStreamEvent::BlockStart {
                        index: 0,
                        block: IrBlockMeta::ToolUse { .. }
                    }
                )),
                "tool (first to appear) must take index 0: {events:?}"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    IrStreamEvent::BlockStart {
                        index: 1,
                        block: IrBlockMeta::Text
                    }
                )),
                "text (after the tool) must take index 1: {events:?}"
            );
            // Both blocks are closed at their own index.
            assert!(events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 })));
            assert!(events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 1 })));
        }
    }

    /// Regression: tool block indices stay stable when the functionCall arrives in a different
    /// chunk than the finishReason (per-chunk local reset previously corrupted this).
    #[test]
    fn test_stream_tool_index_stable_across_chunks() {
        let events = collect_stream(&[
            serde_json::json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{"functionCall": {"name": "f", "args": {"a": 1}}}]
                    }
                }]
            }),
            serde_json::json!({
                "candidates": [{ "finishReason": GEMINI_FINISH_STOP }]
            }),
        ]);

        let start_idx = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        });
        let idx = start_idx.expect("tool BlockStart must be emitted");
        // No text block opened this stream, so the tool owns index 0 (contiguous from 0);
        // reserving 0 for an absent text block would leave a permanent hole.
        assert_eq!(idx, 0, "tool-only stream: tool block must take index 0");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
            "tool block opened in chunk 1 must be closed by finishReason in chunk 2: {events:?}"
        );
    }

    /// Regression: two functionCalls in a tool-only response get distinct, contiguous indices
    /// (0 and 1 — no text block opened, so nothing reserves index 0) and both close.
    #[test]
    fn test_stream_two_tools_distinct_indices() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"functionCall": {"name": "a", "args": {}}},
                        {"functionCall": {"name": "b", "args": {}}}
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);

        let mut tool_indices: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::ToolUse { .. },
                } => Some(*index),
                _ => None,
            })
            .collect();
        tool_indices.sort_unstable();
        assert_eq!(
            tool_indices,
            vec![0, 1],
            "tool-only stream: two tools must take contiguous indices 0,1"
        );

        for idx in [0usize, 1usize] {
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
                "tool block {idx} must be closed"
            );
        }
    }

    /// Regression for MED #6: a tool-only streaming response must produce content block indices
    /// contiguous from 0. Previously the first tool index was `1 + open_tools.len()`, which reserved
    /// index 0 for a text block that never opened — leaving IR index 0 permanently empty and content
    /// indices non-contiguous (0 hole, then 1..n). Now the base is keyed on whether a text block
    /// actually opened (`usize::from(state.text_block_open)`), so a tool-only stream starts at 0.
    #[test]
    fn test_stream_tool_only_indices_contiguous_from_zero() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"functionCall": {"name": "a", "args": {}}},
                        {"functionCall": {"name": "b", "args": {}}}
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);

        // No text block must open: a tool-only response carries no text part.
        assert!(
            !events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: IrBlockMeta::Text,
                    ..
                }
            )),
            "tool-only stream must not open a text block: {events:?}"
        );

        let mut tool_indices: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::ToolUse { .. },
                } => Some(*index),
                _ => None,
            })
            .collect();
        tool_indices.sort_unstable();
        assert_eq!(
            tool_indices,
            vec![0, 1],
            "tool-only stream: content indices must be contiguous from 0 (no reserved-but-empty 0): {events:?}"
        );

        // Both tool blocks must be closed at their own indices.
        for idx in [0usize, 1usize] {
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
                "tool block {idx} must be closed: {events:?}"
            );
        }
    }

    /// Regression for MED #6 (interleaving): when a text block DOES open, the reserved index 0
    /// must still hold, and tool blocks follow at 1..n — the fix must not regress text+tool order.
    #[test]
    fn test_stream_text_then_tool_keeps_text_at_zero() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "hi"},
                        {"functionCall": {"name": "a", "args": {}}},
                        {"functionCall": {"name": "b", "args": {}}}
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);

        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                }
            )),
            "text block must open at index 0: {events:?}"
        );

        let mut tool_indices: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::ToolUse { .. },
                } => Some(*index),
                _ => None,
            })
            .collect();
        tool_indices.sort_unstable();
        assert_eq!(
            tool_indices,
            vec![1, 2],
            "text+tool stream: tools must follow text at indices 1,2: {events:?}"
        );
    }

    /// Regression: the tool BlockStart now BUFFERS the name and emits NO frame; a native Gemini
    /// stream carries a tool call as a single `functionCall` part, so the name must NOT appear in a
    /// separate opening frame (that produced a two-part split a native client never sees).
    #[test]
    fn test_writer_tool_blockstart_emits_no_frame() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        };
        assert!(
            writer.write_response_event(&ev).is_none(),
            "tool BlockStart must buffer the name and emit no separate frame"
        );
    }

    /// The text BlockStart still produces no frame (Gemini inlines text parts).
    #[test]
    fn test_writer_text_blockstart_is_none() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Text,
        };
        assert!(writer.write_response_event(&ev).is_none());
    }

    /// HIGH (asymmetric twin of the file_id leak): a Bedrock S3-source image (IMAGE_S3_SENTINEL
    /// media_type, `data` = serialized s3Location JSON) reaching the Gemini egress must be SKIPPED,
    /// NOT emitted as a corrupt `inlineData{mimeType:"image_s3"}` part that leaks the s3Location JSON
    /// + a busbar fingerprint onto the Gemini wire.
    #[test]
    fn test_write_request_image_s3_dropped_not_corrupted() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "describe this".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Vendor {
                            vendor: "bedrock",
                            value: serde_json::json!({ "format": "png", "s3Location": { "uri": "s3://bucket/key.png" } }),
                        },
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
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("image_s3")
                && !wire.contains("s3://bucket/key.png")
                && !wire.contains("s3Location"),
            "an image_s3 image must not leak onto the Gemini wire (no corrupt inlineData part); \
             got {wire}"
        );
        assert!(
            !wire.contains("inlineData") && !wire.contains("fileData"),
            "no inlineData/fileData part may be emitted for an image_s3 image; got {wire}"
        );
        assert!(
            wire.contains("describe this"),
            "the text part must still survive; got {wire}"
        );
    }

    /// Helper: drive a sequence of IR events through ONE GeminiWriter (preserving its per-stream
    /// tool buffer) and return only the emitted `functionCall` parts (the `{name, args}` objects),
    /// in wire order. This is the shape a native google-genai client decodes off the stream.
    fn collect_function_calls(events: &[IrStreamEvent]) -> Vec<serde_json::Value> {
        let writer = GeminiWriter;
        let mut calls = Vec::new();
        for ev in events {
            if let Some((_, chunk)) = writer.write_response_event(ev) {
                if let Some(parts) = chunk
                    .pointer("/candidates/0/content/parts")
                    .and_then(|p| p.as_array())
                {
                    for part in parts {
                        if let Some(fc) = part.get(FIELD_FUNCTION_CALL) {
                            calls.push(fc.clone());
                        }
                    }
                }
            }
        }
        calls
    }

    /// Regression: a tool BlockStart + one whole-JSON InputJsonDelta + BlockStop emits EXACTLY ONE
    /// native `functionCall` part carrying BOTH the buffered name and the args. The part is written
    /// on BlockStop (the flush point), not on the BlockStart or the delta.
    #[test]
    fn test_writer_tool_call_emits_single_name_and_args_part() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
        ]);
        assert_eq!(
            calls.len(),
            1,
            "tool call must emit exactly one functionCall part: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "part must carry the buffered name: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/city").and_then(|c| c.as_str()),
            Some("SF"),
            "part must carry the args: {calls:?}"
        );
    }

    /// Regression: the `arguments` JSON arrives SPLIT across MULTIPLE partial-
    /// JSON InputJsonDelta fragments (the normal OpenAI/Anthropic streaming behavior — the reader
    /// emits one InputJsonDelta per upstream `arguments` fragment, none coalesced). The fragments
    /// individually do NOT parse (`{"lo`, `c":"SF","u":1}`); the writer MUST reassemble them and emit
    /// EXACTLY ONE functionCall part whose `args` is the fully reassembled object — not one (empty-
    /// args) part per fragment.
    #[test]
    fn test_writer_tool_call_reassembles_split_json_args() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"lo".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("c\":\"SF\",\"unit".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("\":\"C\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
        ]);
        assert_eq!(
            calls.len(),
            1,
            "multi-fragment args must still emit exactly ONE functionCall part: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "part name must be non-empty after reassembly: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/loc").and_then(|c| c.as_str()),
            Some("SF"),
            "args must be the FULLY reassembled object, not a partial fragment: {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/unit").and_then(|c| c.as_str()),
            Some("C"),
            "every reassembled arg key must survive: {calls:?}"
        );
    }

    /// Regression: TWO parallel tool blocks in one stream, with their
    /// BlockStarts NOT strictly interleaved with their own BlockStops (the OpenAI reader emits
    /// BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2)). The
    /// single-slot buffer this replaced would clobber tool 1 when tool 2's BlockStart arrived. Each
    /// tool must flush its OWN name + args as a distinct functionCall part.
    #[test]
    fn test_writer_parallel_tool_calls_keep_distinct_names_and_args() {
        let calls = collect_function_calls(&[
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            },
            IrStreamEvent::BlockStart {
                index: 2,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_time".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 2,
                delta: IrDelta::InputJsonDelta("{\"tz\":\"UTC\"}".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("\"SF\"}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 1 },
            IrStreamEvent::BlockStop { index: 2 },
        ]);
        assert_eq!(
            calls.len(),
            2,
            "two parallel tool calls must emit two functionCall parts: {calls:?}"
        );
        // Tool 1 flushed on its BlockStop (emitted first).
        assert_eq!(
            calls[0].pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "first flushed part must keep tool 1's name (not clobbered by tool 2): {calls:?}"
        );
        assert_eq!(
            calls[0].pointer("/args/city").and_then(|c| c.as_str()),
            Some("SF"),
            "tool 1's interleaved split args must reassemble: {calls:?}"
        );
        assert_eq!(
            calls[1].pointer("/name").and_then(|n| n.as_str()),
            Some("get_time"),
            "second flushed part must keep tool 2's name: {calls:?}"
        );
        assert_eq!(
            calls[1].pointer("/args/tz").and_then(|c| c.as_str()),
            Some("UTC"),
            "tool 2's args must survive: {calls:?}"
        );
    }

    /// Regression: a zero-argument tool call (BlockStart then BlockStop with NO InputJsonDelta) must
    /// still emit one `{name, args:{}}` part on the BlockStop flush — the call is never lost.
    #[test]
    fn test_writer_tool_call_empty_args_flushed_on_stop() {
        let writer = GeminiWriter;
        assert!(writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "ping".to_string(),
                },
            })
            .is_none());
        let (_, chunk) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .expect("zero-arg tool call must flush a functionCall frame on BlockStop");
        let func = chunk
            .pointer("/candidates/0/content/parts/0/functionCall")
            .expect("functionCall part");
        assert_eq!(
            func.pointer("/name").and_then(|n| n.as_str()),
            Some("ping"),
            "flushed frame must carry the name: {chunk}"
        );
        assert!(
            func.get("args").map(|a| a.is_object()).unwrap_or(false),
            "flushed frame must carry an (empty) args object: {chunk}"
        );
    }

    /// Regression: neither the BlockStart nor the args delta emits a frame — the functionCall part
    /// is written ONCE, on BlockStop. Guards against re-introducing a per-fragment emit.
    #[test]
    fn test_writer_tool_call_no_frame_before_block_stop() {
        let writer = GeminiWriter;
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse {
                        id: String::new(),
                        name: "get_weather".to_string(),
                    },
                })
                .is_none(),
            "tool BlockStart must emit no frame"
        );
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
                })
                .is_none(),
            "args delta must accumulate, not emit a frame"
        );
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
                .is_some(),
            "BlockStop must flush the single functionCall frame"
        );
    }

    /// extract_error parses the body once and derives both the provider code and structured type.
    /// The real Gemini API returns `error.code` as a JSON INTEGER (google.rpc.Status), so the
    /// fixture uses `429` (not `"429"`); `provider_code` must be the stringified integer.
    #[test]
    fn test_extract_error_single_parse_fields() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.http_status, 429);
        assert_eq!(raw.provider_code.as_deref(), Some("429"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some(GRPC_RESOURCE_EXHAUSTED)
        );
        // classify()/extract_error do not see headers, so retry_after is sourced elsewhere.
        assert_eq!(raw.retry_after_secs, None);
    }

    /// Regression (R5): an integer `error.code` (the real Gemini shape) must be stringified into
    /// `provider_code` — NOT silently dropped to the gRPC status name. Previously `code` was read
    /// via `.as_str()`, which returns None on a number, so a real 429 surfaced as
    /// "RESOURCE_EXHAUSTED" and broke breaker/metrics comparisons against numeric strings.
    #[test]
    fn test_extract_error_integer_code_is_stringified() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":503,"status":"UNAVAILABLE","message":"overloaded"}}"#;
        let raw = reader.extract_error(StatusCode::SERVICE_UNAVAILABLE, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("503"),
            "integer code must be stringified, not fall back to status"
        );
        assert_eq!(raw.structured_type.as_deref(), Some(GRPC_UNAVAILABLE));
    }

    /// A string-typed `code` (some proxies emit one) is still accepted as the secondary path.
    #[test]
    fn test_extract_error_string_code_still_accepted() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":"429","status":"RESOURCE_EXHAUSTED"}}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.provider_code.as_deref(), Some("429"));
    }

    /// When `code` is absent, extract_error falls back to `status` for the provider code.
    #[test]
    fn test_extract_error_status_fallback() {
        let reader = GeminiReader;
        let body = br#"{"error":{"status":"PERMISSION_DENIED"}}"#;
        let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
        assert_eq!(raw.provider_code.as_deref(), Some(GRPC_PERMISSION_DENIED));
        assert_eq!(raw.structured_type.as_deref(), Some(GRPC_PERMISSION_DENIED));
    }

    /// Regression (R21 #17, ContextLength reachability): a real Gemini oversized-context error is a
    /// 400 `INVALID_ARGUMENT` whose MESSAGE carries the token-overflow text — there is no distinct
    /// google.rpc.Code for it. `extract_error` (the PRODUCTION path; `classify` is `#[cfg(test)]`
    /// only) must synthesize the canonical `context_length_exceeded` provider code so the breaker
    /// (breaker.rs) maps it to StatusClass::ContextLength and fails over WITHOUT penalty,
    /// instead of treating the bare `"400"` code as a lane-penalizing ClientError. Before the fix
    /// `provider_code` was the bare HTTP-status int and this assertion failed.
    #[test]
    fn test_extract_error_oversized_context_yields_canonical_code() {
        let reader = GeminiReader;
        // Native Gemini token-overflow envelope (google.rpc.Status, INVALID_ARGUMENT 400).
        let body = br#"{"error":{"code":400,"message":"The input token count (1050000) exceeds the maximum number of tokens allowed (1048576).","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.http_status, 400);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "oversized-context 400 must synthesize the canonical code so the breaker fails over"
        );
        // The structured google.rpc.Code name is preserved unchanged.
        assert_eq!(raw.structured_type.as_deref(), Some(GRPC_INVALID_ARGUMENT));
    }

    /// A second real-world phrasing the official API emits ("input is longer than the maximum number
    /// of tokens") must also synthesize the canonical code — mirroring the `classify()` substring set.
    #[test]
    fn test_extract_error_oversized_context_alternate_phrasing() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":400,"message":"input is longer than the maximum number of tokens","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded")
        );
    }

    /// A NON-context-length 400 (e.g. a malformed field) must NOT be misclassified as context-length:
    /// the canonical override fires only on the token-overflow text, so an unrelated INVALID_ARGUMENT
    /// keeps its bare status code (here `"400"`) and stays a lane-penalizing ClientError. Guards the
    /// override against over-broad matching.
    #[test]
    fn test_extract_error_unrelated_invalid_argument_keeps_status_code() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":400,"message":"Invalid value at 'contents[0].role'.","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("400"),
            "a non-context-length 400 must not be misclassified as context_length_exceeded"
        );
    }

    /// Regression (R24 MED #3, dead-credential failover): a Gemini bad EGRESS key surfaces as an
    /// HTTP 400 `INVALID_ARGUMENT` carrying `reason: API_KEY_INVALID` (google.rpc.ErrorInfo) plus an
    /// "API key not valid" message. A bare 400 normalizes to ClientFault — records nothing, never
    /// benches/fails over the lane — so a lane wired to a dead key keeps serving guaranteed
    /// auth-rejections. `extract_error` must re-shape it so the breaker classifies it as
    /// Auth → HardDown (park + fail over). Asserted end-to-end through `normalize_raw_error` +
    /// `classify` against an EMPTY error_map (the shipped Gemini map has no auth entry), proving the
    /// fix is operator-config-independent.
    #[test]
    fn test_extract_error_bad_api_key_classifies_as_auth_harddown() {
        let reader = GeminiReader;
        // Native Gemini bad-key envelope: 400 INVALID_ARGUMENT, ErrorInfo reason API_KEY_INVALID.
        let body = br#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com"}]}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        // Re-shaped to the canonical Auth-classifying HTTP status so the breaker benches the lane.
        assert_eq!(
            raw.http_status, 401,
            "a dead Gemini key must re-shape to the Auth-classifying status, not relay 400"
        );
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("auth"),
            "bad-key 400 must synthesize the canonical auth provider_code"
        );
        // Normalize against an EMPTY error_map → must still land on Auth → HardDown.
        let empty_map = std::collections::HashMap::new();
        let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert!(
            matches!(sig.class, StatusClass::Auth),
            "bad Gemini key must classify as Auth, got {:?}",
            sig.class
        );
        assert!(
            matches!(
                crate::breaker::classify(&sig),
                crate::breaker::Disposition::HardDown
            ),
            "a dead credential must HardDown the lane so it parks and fails over"
        );
    }

    /// The documented machine-readable `API_KEY_INVALID` reason can also accompany a 403
    /// `PERMISSION_DENIED` (a key lacking access). It must classify the same way.
    #[test]
    fn test_extract_error_bad_api_key_permission_denied_is_auth() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":403,"message":"Permission denied: API key not valid.","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}"#;
        let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
        assert_eq!(raw.http_status, 401);
        assert_eq!(raw.provider_code.as_deref(), Some("auth"));
        let empty_map = std::collections::HashMap::new();
        let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert!(matches!(sig.class, StatusClass::Auth));
    }

    /// PRECISION GUARD: a GENERIC `INVALID_ARGUMENT` 400 (a real field-validation error, no api-key
    /// signal) must NOT be misclassified as auth — it stays a lane-healthy ClientFault that records
    /// nothing and relays verbatim. Without a precise heuristic the override would bench healthy lanes
    /// on every malformed caller request.
    #[test]
    fn test_extract_error_generic_invalid_argument_stays_client_fault() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":400,"message":"Invalid value at 'contents[0].role' (TYPE_ENUM), \"banana\"","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        // Untouched: real 400, bare status code, no auth synthesis.
        assert_eq!(
            raw.http_status, 400,
            "a generic validation 400 must NOT be re-shaped to the auth status"
        );
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("400"),
            "a generic INVALID_ARGUMENT must keep its bare status code, not become auth"
        );
        let empty_map = std::collections::HashMap::new();
        let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert!(
            matches!(sig.class, StatusClass::ClientError),
            "a generic validation 400 must stay ClientError, got {:?}",
            sig.class
        );
        assert!(
            matches!(
                crate::breaker::classify(&sig),
                crate::breaker::Disposition::ClientFault
            ),
            "a generic validation 400 must stay a no-penalty ClientFault"
        );
    }

    /// PRECISION GUARD: a bare `PERMISSION_DENIED` with NO api-key text (e.g. the existing
    /// status-fallback fixture shape) must NOT be re-shaped — the prose heuristic requires an explicit
    /// "api key" + invalid/expired signal, so a permission error without that text stays as-is and is
    /// classified by HTTP status alone.
    #[test]
    fn test_extract_error_bare_permission_denied_not_treated_as_bad_key() {
        let reader = GeminiReader;
        let body = br#"{"error":{"status":"PERMISSION_DENIED"}}"#;
        let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
        // http_status is the real 403, provider_code falls back to the status name — unchanged.
        assert_eq!(raw.http_status, 403);
        assert_eq!(raw.provider_code.as_deref(), Some(GRPC_PERMISSION_DENIED));
    }

    /// Malformed (non-JSON) error bodies yield None fields without panicking.
    #[test]
    fn test_extract_error_non_json_body() {
        let reader = GeminiReader;
        let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, b"upstream exploded");
        assert_eq!(raw.http_status, 500);
        assert_eq!(raw.provider_code, None);
        assert_eq!(raw.structured_type, None);
    }

    /// The native Gemini error envelope is google.rpc.Status-shaped:
    /// `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`. `code` is the HTTP status
    /// int, `status` is the canonical google.rpc.Code name. A known `kind` maps to the matching
    /// name; the body is valid JSON the official SDK can decode into `APIError.code`/`.status`.
    #[test]
    fn test_write_error_native_gemini_envelope() {
        let writer = GeminiWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");
        // Round-trips as JSON (no panic).
        let serialized = serde_json::to_string(&v).expect("write_error must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error must be valid JSON");
        assert_eq!(reparsed["error"]["code"], serde_json::json!(404));
        assert_eq!(
            reparsed["error"]["message"],
            serde_json::json!("model 'x' not found")
        );
        assert_eq!(reparsed["error"]["status"], serde_json::json!("NOT_FOUND"));
        // The generic envelope's `type` field must NOT appear (this is the native shape).
        assert!(
            reparsed["error"].get("type").is_none(),
            "native gemini envelope must not carry an OpenAI-style `type`: {v}"
        );
    }

    /// `kind` is mapped onto the google.rpc.Code vocabulary (e.g. rate-limit → RESOURCE_EXHAUSTED).
    #[test]
    fn test_write_error_kind_maps_to_status_vocabulary() {
        let writer = GeminiWriter;
        let v = writer.write_error(429, "rate_limit_error", "slow down");
        assert_eq!(v["error"]["code"], serde_json::json!(429));
        assert_eq!(
            v["error"]["status"],
            serde_json::json!("RESOURCE_EXHAUSTED") // golden wire-contract literal (kept bare on purpose)
        );

        let v = writer.write_error(400, "invalid_request_error", "bad");
        assert_eq!(v["error"]["status"], serde_json::json!("INVALID_ARGUMENT"));
        // golden wire-contract literal (kept bare on purpose)
    }

    /// An unrecognized `kind` falls back to the HTTP-status-derived google.rpc.Code name (never a
    /// non-canonical `status` string a native SDK would choke on). Exercises the no-catch-all path.
    #[test]
    fn test_write_error_unknown_kind_falls_back_to_http_status() {
        let writer = GeminiWriter;
        let v = writer.write_error(403, "totally_made_up_kind", "nope");
        assert_eq!(v["error"]["status"], serde_json::json!("PERMISSION_DENIED")); // golden wire-contract literal (kept bare on purpose)
                                                                                  // A 5xx with an unknown kind maps to INTERNAL.
        let v = writer.write_error(502, "totally_made_up_kind", "bad gateway");
        assert_eq!(v["error"]["status"], serde_json::json!("INTERNAL")); // golden wire-contract literal (kept bare on purpose)
    }

    /// Regression (R15): the emitted `code`/`status` pair must always be an INTERNALLY CONSISTENT
    /// google.rpc.Status pairing — the real Generative Language API never emits `code:503` with
    /// `status:INTERNAL`. On a cross-protocol upstream 503 the relay collapses the subtype onto a
    /// generic 5xx `kind` (`api_error`→INTERNAL); when that kind-derived name's canonical HTTP status
    /// disagrees with the actual `code`, the HTTP status drives the pairing (503→UNAVAILABLE) so the
    /// two stay consistent. The bare `overloaded` alias `cross_protocol_error_kind` emits for a 503
    /// also resolves to UNAVAILABLE.
    #[test]
    fn test_write_error_code_status_pair_stays_consistent() {
        let writer = GeminiWriter;

        // 503 relayed as the generic `api_error` kind (would have been INTERNAL) → HTTP status wins.
        let v = writer.write_error(503, "api_error", "upstream overloaded");
        assert_eq!(v["error"]["code"], serde_json::json!(503));
        assert_eq!(
            v["error"]["status"],
            serde_json::json!("UNAVAILABLE"), // golden wire-contract literal (kept bare on purpose)
            "code:503 must pair with UNAVAILABLE, never INTERNAL: {v}"
        );

        // The bare `overloaded` alias (cross_protocol_error_kind's 503 kind) maps to UNAVAILABLE.
        let v = writer.write_error(503, "overloaded", "upstream overloaded");
        assert_eq!(v["error"]["status"], serde_json::json!("UNAVAILABLE")); // golden wire-contract literal (kept bare on purpose)

        // A genuine 500 with `api_error` stays INTERNAL (consistent: INTERNAL pairs with 500).
        let v = writer.write_error(500, "api_error", "boom");
        assert_eq!(v["error"]["code"], serde_json::json!(500));
        assert_eq!(v["error"]["status"], serde_json::json!("INTERNAL")); // golden wire-contract literal (kept bare on purpose)

        // A 504 relayed as `timeout` stays DEADLINE_EXCEEDED (canonical 504 == 504).
        let v = writer.write_error(504, "timeout", "slow");
        assert_eq!(v["error"]["status"], serde_json::json!("DEADLINE_EXCEEDED")); // golden wire-contract literal (kept bare on purpose)

        // A kind whose canonical status disagrees with the code (auth→401 vs code 403) lets the HTTP
        // status drive so the pair stays a real google.rpc pairing (403→PERMISSION_DENIED).
        let v = writer.write_error(403, "auth", "denied");
        assert_eq!(v["error"]["code"], serde_json::json!(403));
        assert_eq!(v["error"]["status"], serde_json::json!("PERMISSION_DENIED"));
        // golden wire-contract literal (kept bare on purpose)
    }

    /// Same-protocol (Gemini→Gemini) passthrough preserves the upstream `responseId` and
    /// `modelVersion` exactly: read_response captures them, write_response emits them verbatim.
    #[test]
    fn test_response_identity_roundtrip_preserves_id_and_model() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let upstream = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1},
            "modelVersion": "gemini-1.5-pro-002",
            "responseId": "abc-XYZ-123_opaque"
        });
        let ir = reader.read_response(&upstream).expect("read_response");
        assert_eq!(ir.id.as_deref(), Some("abc-XYZ-123_opaque"));
        assert_eq!(ir.model.as_deref(), Some("gemini-1.5-pro-002"));

        let wire = writer.write_response(&ir);
        assert_eq!(
            wire[FIELD_RESPONSE_ID],
            serde_json::json!("abc-XYZ-123_opaque"),
            "responseId must be preserved verbatim on same-protocol passthrough: {wire}"
        );
        assert_eq!(
            wire[FIELD_MODEL_VERSION],
            serde_json::json!("gemini-1.5-pro-002"),
            "modelVersion must be preserved verbatim: {wire}"
        );
        // Gemini bodies carry no `created`; we must not fabricate one.
        assert!(
            wire.get("created").is_none(),
            "must not synthesize a `created` field Gemini never emits: {wire}"
        );
    }

    /// F2 conformance: a foreign / novel IR stop_reason (`refusal` from Responses, `error` from
    /// Cohere) must NOT upper-case-leak into `finishReason` (e.g. "REFUSAL"/"ERROR" are outside
    /// Gemini's `FinishReason` enum and a strict google-genai client rejects them). It maps to the
    /// native `OTHER` member, on both the whole-body and streamed paths.
    #[test]
    fn foreign_stop_reason_maps_to_other_not_verbatim() {
        use crate::ir::IrStopReason as S;
        let writer = GeminiWriter;
        for foreign in [S::Refusal, S::Error, S::Other] {
            let ir = crate::ir::IrResponse {
                logprobs: Vec::new(),
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Text {
                    text: "x".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
                stop_reason: Some(foreign),
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
            let wire = writer.write_response(&ir);
            assert_eq!(
                wire["candidates"][0]["finishReason"],
                serde_json::json!("OTHER"), // golden wire-contract literal (kept bare on purpose)
                "whole-body: foreign stop_reason {foreign:?} must map to OTHER: {wire}"
            );
            let ev = IrStreamEvent::MessageDelta {
                stop_reason: Some(foreign),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let (_, frame) = writer
                .write_response_event(&ev)
                .expect("MessageDelta must emit a frame");
            assert_eq!(
                frame["candidates"][0]["finishReason"],
                serde_json::json!("OTHER"), // golden wire-contract literal (kept bare on purpose)
                "streamed: foreign stop_reason {foreign:?} must map to OTHER: {frame}"
            );
        }
    }

    /// Cross-protocol write where a non-Gemini backend reader DID set a response id (the normal
    /// cross-protocol case — OpenAI `chatcmpl-…`, Anthropic `msg_…`) emits it as `responseId`, so a
    /// native `google-genai` SDK reading `GenerateContentResponse.response_id` always sees a value.
    /// No panic; the emitted value matches the IR id verbatim.
    #[test]
    fn test_response_identity_cross_protocol_emits_foreign_id() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hello".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("chatcmpl-abc123".to_string()),
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire[FIELD_RESPONSE_ID],
            serde_json::json!("chatcmpl-abc123"),
            "a cross-protocol response id must surface as responseId: {wire}"
        );
    }

    /// Fidelity guard: when the IR carries NO id (a native Gemini body that omitted `responseId`, or
    /// a backend with no identity at all), `write_response` must NOT fabricate one — emitting a
    /// `responseId` would make a native passthrough distinguishable from the real response. The
    /// field is optional in the Gemini schema, so omission is SDK-valid. No panic.
    #[test]
    fn test_response_identity_none_id_is_omitted_not_fabricated() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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
        let wire = writer.write_response(&ir);
        assert!(
            wire.get(FIELD_RESPONSE_ID).is_none(),
            "must not fabricate a responseId when the IR carries none: {wire}"
        );
    }

    /// The streaming reader captures the stream identity from the first chunk into MessageStart,
    /// and the streaming writer emits it back (synthesizing when absent) — same-protocol fidelity.
    #[test]
    fn test_stream_message_start_captures_and_emits_identity() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]}
            }],
            "modelVersion": "gemini-1.5-flash",
            "responseId": "stream-abc-1"
        })]);
        let start = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageStart { id, model, .. } => Some((id.clone(), model.clone())),
                _ => None,
            })
            .expect("MessageStart emitted");
        assert_eq!(start.0.as_deref(), Some("stream-abc-1"));
        assert_eq!(start.1.as_deref(), Some("gemini-1.5-flash"));

        // The writer emits a leading identity frame carrying the captured responseId.
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: start.0.clone(),
                created: None,
                model: start.1.clone(),
            })
            .expect("MessageStart must emit an identity frame");
        assert_eq!(
            frame.1[FIELD_RESPONSE_ID],
            serde_json::json!("stream-abc-1"),
            "stream MessageStart frame must carry responseId: {}",
            frame.1
        );
    }

    /// Cross-protocol fidelity (stream): a MessageStart with NO identity (the post-strip state on a
    /// cross-protocol Gemini-ingress stream — `StreamTranslate` clears the foreign id/model) must
    /// still SYNTHESIZE a `responseId`, because a native google-genai SDK reads `chunk.response_id`
    /// off the first chunk. Emitting no frame (the old behavior) left the client with no responseId on
    /// any cross-protocol Gemini stream — a detectable fidelity gap. Mirrors the non-stream
    /// `write_response` synthesis. (Same-protocol Gemini streams never reach this writer — they pass
    /// through byte-for-byte — so this only affects the cross-protocol path.)
    #[test]
    fn test_stream_message_start_no_identity_synthesizes_response_id() {
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("a synthesized-identity MessageStart must emit a frame");
        assert!(
            frame
                .1
                .get(FIELD_RESPONSE_ID)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "post-strip MessageStart must synthesize a responseId: {}",
            frame.1
        );
    }

    /// Regression: `write_request` must NOT inject a top-level `stream` field. The native Gemini
    /// GenerateContentRequest has no such field (streaming is URL-selected); injecting it makes the
    /// request non-native and can trigger INVALID_ARGUMENT on the real API.
    #[test]
    fn test_write_request_omits_stream_field() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: true,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert!(
            wire.get("stream").is_none(),
            "write_request must not serialise a top-level `stream` field: {wire}"
        );
    }

    /// Regression: a NATIVE request (which never carries `stream`) must produce a body with no
    /// `stream` member — i.e. the writer no longer injects one unconditionally. The streaming
    /// intent (`IrRequest.stream == true`) must NOT leak into the body even when set.
    #[test]
    fn test_native_request_without_stream_stays_streamless() {
        let reader = GeminiReader;
        // Native Gemini request — no `stream` field.
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let mut ir = reader.read_request(&body).expect("read_request");
        // Caller wants streaming (URL-selected), but it must not reach the body.
        ir.stream = true;
        assert!(
            !ir.extra.contains_key("stream"),
            "a native request carries no stream in extra: {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert!(
            wire.get("stream").is_none(),
            "stream intent must not be serialised into the body: {wire}"
        );
    }

    /// Regression (R25 LOW #10, REFINE the R24 bad-key heuristic): an `INVALID_ARGUMENT` 400 whose
    /// prose contains the bare word "invalid" AND names an "api key" but is NOT a bad-key error
    /// (a field-validation message that references an api-key-shaped field) must stay a lane-healthy
    /// ClientFault. The earlier heuristic accepted a bare "invalid" token, so it would have benched a
    /// HEALTHY lane on this. The refined heuristic requires a SPECIFIC bad-key phrase.
    #[test]
    fn test_extract_error_invalid_word_near_api_key_stays_client_fault() {
        let reader = GeminiReader;
        // A generic validation 400: "invalid" + "api key" both present, but no bad-key phrase.
        let body = br#"{"error":{"code":400,"message":"Invalid value at 'request.api key field' (TYPE_STRING)","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.http_status, 400,
            "a generic validation 400 that merely mentions 'invalid' near 'api key' must NOT re-shape to auth"
        );
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("400"),
            "the bare status code must be preserved, not synthesized to auth"
        );
        let empty_map = std::collections::HashMap::new();
        let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert!(
            matches!(sig.class, StatusClass::ClientError),
            "must stay ClientError, got {:?}",
            sig.class
        );
        assert!(
            matches!(
                crate::breaker::classify(&sig),
                crate::breaker::Disposition::ClientFault
            ),
            "must stay a no-penalty ClientFault"
        );
    }

    /// Companion to the refinement: an EXPIRED-key prose message ("API key expired") with no
    /// machine-readable reason must STILL be detected as auth — the refined phrase set covers it.
    #[test]
    fn test_extract_error_expired_api_key_prose_is_auth() {
        let reader = GeminiReader;
        let body = br#"{"error":{"code":400,"message":"API key expired. Please renew the API key.","status":"INVALID_ARGUMENT"}}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.http_status, 401,
            "an 'API key expired' prose message must re-shape to the auth status"
        );
        assert_eq!(raw.provider_code.as_deref(), Some("auth"));
    }

    /// Regression (R25 MED #2, updated for H2): a thinking-only assistant turn must NOT vanish from
    /// `contents` — dropping it would collapse user/model alternation (two user turns adjacent) and
    /// 400 the real Gemini API. Post-H2 the Thinking block is now emitted as a native `thought:true`
    /// part (reasoning is no longer dropped), so the model turn survives by carrying that thought part
    /// rather than the old empty-text placeholder. The alternation invariant (3 surviving turns) is
    /// what this guards.
    #[test]
    fn test_write_request_thinking_only_turn_survives_with_placeholder() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "first".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Thinking {
                        text: "internal reasoning".to_string(),
                        signature: None,
                        redacted: false,
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "second".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let contents = wire
            .get("contents")
            .and_then(|v| v.as_array())
            .expect("contents array must exist");
        // All THREE turns must survive — the thinking-only model turn must not be dropped.
        assert_eq!(
            contents.len(),
            3,
            "thinking-only model turn must survive so user/model alternation is preserved: {wire}"
        );
        let model_turn = &contents[1];
        assert_eq!(
            model_turn.get("role").and_then(|v| v.as_str()),
            Some("model"),
            "the surviving turn must carry the model role: {model_turn}"
        );
        let parts = model_turn
            .get("parts")
            .and_then(|v| v.as_array())
            .expect("the surviving turn must carry a parts array");
        assert_eq!(
            parts.len(),
            1,
            "thinking-only turn carries exactly one part: {model_turn}"
        );
        // Post-H2: the Thinking block emits a native thought part (not dropped → not a placeholder).
        assert_eq!(
            parts[0].get("text").and_then(|v| v.as_str()),
            Some("internal reasoning"),
            "the thought part must carry the reasoning text: {model_turn}"
        );
        assert_eq!(
            parts[0].get("thought"),
            Some(&serde_json::json!(true)),
            "the surviving part must be a thought part: {model_turn}"
        );
    }

    /// Regression (R25 LOW #11): a tool result that parses to JSON `null` (the upstream omitted the
    /// response object) must NOT be emitted as `functionResponse.response: null`. Gemini's
    /// `response` is a protobuf Struct and requires a JSON OBJECT; a null is rejected (400). The
    /// writer must coerce a null parse result to an empty Struct `{}`.
    #[test]
    fn test_write_request_null_tool_result_coerced_to_struct() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "get_weather".to_string(),
                    // A literal "null" payload — valid JSON that parses to Value::Null.
                    content: vec![crate::ir::IrBlock::Text {
                        text: "null".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let response = wire
            .get("contents")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.get("parts"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.get("functionResponse"))
            .and_then(|fr| fr.get("response"))
            .expect("functionResponse.response must exist");
        assert!(
            response.is_object(),
            "a null tool-result payload must be coerced to a Struct (object), got: {response}"
        );
        assert!(
            !response.is_null(),
            "functionResponse.response must never be null: {wire}"
        );
    }

    /// A bare-scalar tool result ("42") must likewise be coerced to a Struct — wrapped under
    /// `{"output": <value>}` so the content survives — never emitted as a raw scalar.
    #[test]
    fn test_write_request_scalar_tool_result_coerced_to_struct() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "compute".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "42".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let response = wire
            .get("contents")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.get("parts"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.get("functionResponse"))
            .and_then(|fr| fr.get("response"))
            .expect("functionResponse.response must exist");
        assert!(
            response.is_object(),
            "a scalar tool-result payload must be coerced to a Struct, got: {response}"
        );
        assert_eq!(
            response.get("output").and_then(|v| v.as_i64()),
            Some(42),
            "the scalar value must survive under the `output` key: {response}"
        );
    }

    /// Regression: Gemini's `Content.role` is OPTIONAL. A single-turn request that omits `role`
    /// (a common native shape, accepted by the real API and the official SDK as an implicit user
    /// turn) must NOT be hard-rejected. Previously `read_request` mapped any non-`user`/`model`
    /// role (including absent/empty) to a `ClientError`, 400ing a request the real API serves —
    /// and diverging from the streaming reader, which already treats an empty role as a model turn.
    #[test]
    fn test_read_request_absent_role_defaults_to_user() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"parts": [{"text": "hi"}]}]
        });
        let ir = reader
            .read_request(&body)
            .expect("a role-less content must be accepted as a user turn, not rejected");
        assert_eq!(ir.messages.len(), 1, "one message expected: {ir:?}");
        assert_eq!(
            ir.messages[0].role,
            crate::ir::IrRole::User,
            "an absent role must default to user: {ir:?}"
        );
    }

    /// An explicitly EMPTY role string (`"role": ""`) is likewise treated as a user turn, matching
    /// the absent-role case and the streaming reader's `role_val.is_empty()` leniency.
    #[test]
    fn test_read_request_empty_role_defaults_to_user() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "", "parts": [{"text": "hi"}]}]
        });
        let ir = reader
            .read_request(&body)
            .expect("an empty role must be accepted as a user turn, not rejected");
        assert_eq!(
            ir.messages[0].role,
            crate::ir::IrRole::User,
            "an empty role must default to user: {ir:?}"
        );
    }

    /// A genuinely unexpected NON-EMPTY role string is still a hard client error — the leniency is
    /// scoped to the absent/empty case (the real API's optional-role default), not to arbitrary
    /// role values.
    #[test]
    fn test_read_request_unknown_nonempty_role_still_rejected() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "function", "parts": [{"text": "hi"}]}]
        });
        assert!(
            reader.read_request(&body).is_err(),
            "an unexpected non-empty role must still be rejected"
        );
    }

    /// Regression: `model` is preserved in `extra` exactly once (no duplicate insert) and survives
    /// the read path because it is excluded from the loop via `modeled_keys`.
    #[test]
    fn test_read_request_model_preserved_in_extra_once() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "model": "gemini-1.5-pro"
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.extra.get("model"),
            Some(&serde_json::json!("gemini-1.5-pro")),
            "model must be preserved in extra: {:?}",
            ir.extra
        );
    }

    /// Regression: a ToolResult whose content is multi-part PLAIN TEXT (not JSON) must be wrapped in
    /// `{"output": <text>}` rather than silently discarded as an empty `{}` object.
    #[test]
    fn test_write_request_tool_result_plaintext_wrapped_not_dropped() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "get_weather".to_string(),
                    content: vec![
                        crate::ir::IrBlock::Text {
                            text: "sunny".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                        crate::ir::IrBlock::Text {
                            text: "and warm".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                    ],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let resp = wire
            .pointer("/contents/0/parts/0/functionResponse/response")
            .expect("functionResponse.response must be present");
        assert_ne!(
            resp,
            &serde_json::json!({}),
            "plain-text tool result must not be discarded as empty object: {wire}"
        );
        assert_eq!(
            resp.get("output").and_then(|o| o.as_str()),
            Some("sunny and warm"),
            "plain-text tool result must be wrapped as {{\"output\": text}}: {wire}"
        );
    }

    /// A ToolResult whose joined text IS valid JSON is forwarded structurally (not wrapped).
    #[test]
    fn test_write_request_tool_result_json_passthrough() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "f".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "{\"temp\":21}".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let temp = wire
            .pointer("/contents/0/parts/0/functionResponse/response/temp")
            .and_then(|v| v.as_i64());
        assert_eq!(temp, Some(21), "JSON tool result must pass through: {wire}");
    }

    /// Regression: a cross-protocol response with NO foreign id but a populated `created` (the
    /// boundary signal `forward.rs` leaves intact after stripping `id`) must SYNTHESIZE a
    /// Gemini-shaped `responseId` so a native SDK always sees a value. Previously omitted entirely.
    #[test]
    fn test_response_identity_cross_protocol_synthesizes_id_when_created_set() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: Some(1_700_000_000),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        let synth = wire
            .get(FIELD_RESPONSE_ID)
            .and_then(|v| v.as_str())
            .expect("cross-protocol response (created set, id none) must synthesize responseId");
        assert!(
            !synth.is_empty(),
            "synthesized responseId must be non-empty: {wire}"
        );
    }

    /// Regression: the in-stream Error frame emits the FULL google.rpc.Status envelope
    /// (`code` int + UPPER_SNAKE `status` + message), not a message-only object, so a Gemini SDK
    /// can branch on `error.status`/`error.code`. Class → code/status is exhaustive (no catch-all).
    #[test]
    fn test_stream_error_emits_full_google_rpc_status() {
        let writer = GeminiWriter;
        let err = crate::proto::IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        };
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("Error event must emit a frame");
        assert_eq!(
            frame.pointer("/error/code"),
            Some(&serde_json::json!(429)),
            "frame: {frame}"
        );
        assert_eq!(
            frame.pointer("/error/status").and_then(|s| s.as_str()),
            Some("RESOURCE_EXHAUSTED"), // golden wire-contract literal (kept bare on purpose)
            "frame: {frame}"
        );
        assert_eq!(
            frame.pointer("/error/message").and_then(|m| m.as_str()),
            Some("slow down"),
            "frame: {frame}"
        );
    }

    /// A server-error class maps to 500/INTERNAL in the stream error envelope.
    #[test]
    fn test_stream_error_server_error_maps_internal() {
        let writer = GeminiWriter;
        let err = crate::proto::IrError {
            class: StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        };
        let (_, frame) = writer
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("Error event must emit a frame");
        assert_eq!(frame.pointer("/error/code"), Some(&serde_json::json!(500)));
        assert_eq!(
            frame.pointer("/error/status").and_then(|s| s.as_str()),
            Some("INTERNAL") // golden wire-contract literal (kept bare on purpose)
        );
        // No provider_signal → default message, no panic.
        assert_eq!(
            frame.pointer("/error/message").and_then(|m| m.as_str()),
            Some("error")
        );
    }

    /// A cross-protocol stream that carries only a model (no id) surfaces `modelVersion` AND a
    /// synthesized `responseId` on the leading frame — a native SDK reads both `chunk.model_version`
    /// and `chunk.response_id` off the first chunk.
    #[test]
    fn test_stream_message_start_model_only_emits_model_version() {
        let writer = GeminiWriter;
        let frame = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: Some("gemini-1.5-pro".to_string()),
            })
            .expect("a model-bearing MessageStart must emit a frame");
        assert_eq!(
            frame.1[FIELD_MODEL_VERSION],
            serde_json::json!("gemini-1.5-pro"),
            "frame must carry modelVersion: {}",
            frame.1
        );
        assert!(
            frame
                .1
                .get(FIELD_RESPONSE_ID)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "no id → responseId synthesized so the SDK still sees one: {}",
            frame.1
        );
    }

    // --- Round 3 fix 1: functionCall ToolUse blocks must carry a non-empty, stable id ---

    /// Regression: a Gemini `functionCall` in `read_request` must produce a NON-EMPTY tool-use id
    /// (Gemini carries none). Previously `id: String::new()` made cross-protocol Anthropic/OpenAI
    /// egress emit an empty `id`/`tool_use_id`, which those APIs reject / mis-correlate.
    #[test]
    fn test_read_request_functioncall_gets_nonempty_id() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let id = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        });
        let id = id.expect("ToolUse block must be present");
        assert!(!id.is_empty(), "synthesized tool-use id must be non-empty");
    }

    /// Regression: two `functionCall`s sharing the SAME function name in one request must get
    /// DISTINCT non-empty ids (the call index disambiguates) so `tool_result` routing cannot
    /// collapse them on cross-protocol egress.
    #[test]
    fn test_read_request_same_name_tool_calls_get_distinct_ids() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [
                    {"functionCall": {"name": "search", "args": {"q": "a"}}},
                    {"functionCall": {"name": "search", "args": {"q": "b"}}}
                ]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let ids: Vec<String> = ir.messages[0]
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2, "two tool-use blocks expected");
        assert!(ids.iter().all(|i| !i.is_empty()), "ids must be non-empty");
        assert_ne!(
            ids[0], ids[1],
            "repeated function name must still yield distinct ids: {ids:?}"
        );
    }

    /// Regression: the synthesized id is DETERMINISTIC for a given (index, name) — two reads of the
    /// same request body produce the same ids (stable within a request lifetime).
    #[test]
    fn test_read_request_tool_call_id_is_deterministic() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "model",
                "parts": [{"functionCall": {"name": "f", "args": {}}}]
            }]
        });
        let id_of = |r: &GeminiReader| {
            r.read_request(&body).unwrap().messages[0]
                .content
                .iter()
                .find_map(|b| match b {
                    crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(id_of(&reader), id_of(&reader), "id must be deterministic");
    }

    /// Regression: the same-protocol ToolResult correlation key stays the function NAME (the writer
    /// round-trips it into `functionResponse.name`), NOT the synthetic ToolUse id. Guards against a
    /// regression where the synth id leaks onto the result name and breaks Gemini→Gemini passthrough.
    #[test]
    fn test_read_request_functionresponse_tool_use_id_is_name() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"functionResponse": {"name": "get_weather", "response": {"t": 21}}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let tid = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolResult { tool_use_id, .. } => Some(tool_use_id.clone()),
            _ => None,
        });
        assert_eq!(
            tid.as_deref(),
            Some("get_weather"),
            "result correlation key must remain the function name for same-protocol round-trip"
        );
    }

    /// Regression: a `functionCall` in `read_response` (non-stream) must also carry a non-empty id.
    #[test]
    fn test_read_response_functioncall_gets_nonempty_id() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "f", "args": {}}}]
                },
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let ir = reader.read_response(&body).expect("read_response");
        let id = ir.content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        });
        assert!(
            id.is_some_and(|i| !i.is_empty()),
            "response ToolUse must carry a non-empty id"
        );
    }

    /// Regression (MEDIUM/correctness): a SAFETY-filtered Gemini candidate carries only
    /// `finishReason` + `safetyRatings` and NO `content` field. `read_response` must decode it as an
    /// empty-content response with the mapped stop reason, NOT hard-fail (which forward.rs turned into
    /// a spurious 500). Mirrors the streaming reader's `if let Some(content)` tolerance.
    #[test]
    fn test_read_response_safety_filtered_candidate_no_content_is_ok() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "finishReason": GEMINI_FINISH_SAFETY,
                "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}]
            }],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 0}
        });
        let ir = reader
            .read_response(&body)
            .expect("safety-filtered candidate (no content) must decode, not error");
        assert!(
            ir.content.is_empty(),
            "filtered candidate has no content blocks, got {:?}",
            ir.content
        );
        assert!(
            ir.stop_reason.is_some(),
            "the SAFETY finishReason must still map to a stop_reason"
        );
    }

    /// Regression (MED, completeness): a PROMPT-blocked Gemini stream chunk carries a top-level
    /// `promptFeedback.blockReason`, NO `candidates`, and NO `error`. The reader must surface it as a
    /// PROPER TERMINAL SEQUENCE — MessageStart, then a `safety` MessageDelta + MessageStop — not a
    /// bare MessageStart followed by EOF (which left the downstream client on a hung, non-terminated
    /// stream with an empty response). Old code emitted only MessageStart and never terminated.
    #[test]
    fn test_stream_prompt_block_emits_terminal_sequence() {
        let events = collect_stream(&[serde_json::json!({
            "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
        })]);

        // Exactly one MessageStart, one MessageDelta, one MessageStop — a complete terminal stream.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, IrStreamEvent::MessageStart { .. }))
                .count(),
            1,
            "prompt-block stream must emit exactly one MessageStart: {events:?}"
        );
        let stop_reason = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
            _ => None,
        });
        assert_eq!(
            stop_reason,
            Some(crate::ir::IrStopReason::Safety),
            "prompt-block must surface a `safety` stop_reason: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(IrStreamEvent::MessageStop)),
            "the stream must terminate with MessageStop: {events:?}"
        );
        // No stray content blocks for a blocked prompt.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStart { .. })),
            "a blocked prompt must not open any content block: {events:?}"
        );
    }

    /// Regression (LOW #10, bug): a MID-STREAM prompt-block arm must close any blocks opened by
    /// earlier chunks before emitting its terminal MessageDelta/MessageStop. A normal text chunk
    /// opens a content block (BlockStart{0}); a following `promptFeedback.blockReason` SAFETY chunk
    /// (NO candidates) previously emitted the terminal MessageDelta/MessageStop WITHOUT closing that
    /// open block, leaving an unbalanced IR stream (orphaned BlockStart). The fixed arm mirrors the
    /// finishReason path: the second chunk must emit exactly [BlockStop{0}, MessageDelta{safety},
    /// MessageStop].
    #[test]
    fn test_stream_mid_stream_prompt_block_closes_open_text_block() {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();

        // Chunk 1: a normal text chunk opens a content block.
        let first = reader.read_response_events(
            "",
            &serde_json::json!({
                "candidates": [{
                    "content": {"parts": [{"text": "hello"}], "role": "model"}
                }]
            }),
            &mut state,
        );
        assert!(
            first
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStart { index: 0, .. })),
            "first chunk must open block 0: {first:?}"
        );
        assert!(
            state.text_block_open,
            "text block must remain open after the first chunk: {first:?}"
        );

        // Chunk 2: a mid-stream prompt-block (NO candidates) must close block 0, then terminate.
        let second = reader.read_response_events(
            "",
            &serde_json::json!({
                "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
                "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
            }),
            &mut state,
        );

        let stop_reason = second.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
            _ => None,
        });
        assert!(
            matches!(
                second.as_slice(),
                [
                    IrStreamEvent::BlockStop { index: 0 },
                    IrStreamEvent::MessageDelta { .. },
                    IrStreamEvent::MessageStop,
                ]
            ),
            "mid-stream prompt-block must emit [BlockStop{{0}}, MessageDelta, MessageStop]: {second:?}"
        );
        assert_eq!(
            stop_reason,
            Some(crate::ir::IrStopReason::Safety),
            "the terminal MessageDelta must carry a `safety` stop_reason: {second:?}"
        );
        assert!(
            !state.text_block_open,
            "the open text block flag must be cleared after the prompt-block close: {second:?}"
        );
    }

    /// Regression (MED, completeness): a PROMPT-blocked NON-STREAMING Gemini body (top-level
    /// `promptFeedback.blockReason`, NO `candidates`, NO `error`) must decode to an empty-content
    /// response with a `safety` stop reason, NOT hard-fail with `ir_parse` (which the old
    /// absent-candidates arm did → a spurious client error with no surfaced reason).
    #[test]
    fn test_read_response_prompt_block_is_safety_stop_not_error() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "promptFeedback": {
                "blockReason": GEMINI_FINISH_PROHIBITED_CONTENT,
                "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}]
            },
            "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 0}
        });
        let ir = reader
            .read_response(&body)
            .expect("prompt-blocked body must decode, not error");
        assert!(
            ir.content.is_empty(),
            "a blocked prompt has no content blocks, got {:?}",
            ir.content
        );
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::Safety),
            "a blocked prompt must surface a `safety` stop_reason"
        );
        assert_eq!(ir.usage.input_tokens, 9, "usage must still be surfaced");
    }

    /// Regression: a candidates-absent body with NEITHER an error NOR a promptFeedback.blockReason is
    /// still a malformed envelope and MUST hard-fail — the prompt-block arm must not swallow it.
    #[test]
    fn test_read_response_candidates_absent_without_block_still_errors() {
        let reader = GeminiReader;
        let body = serde_json::json!({"usageMetadata": {"promptTokenCount": 1}});
        assert!(
            reader.read_response(&body).is_err(),
            "a candidates-absent body with no block reason must still error"
        );
    }

    /// Regression (LOW, bug): a STREAMING zero-arg `functionCall` (no `args` field) must emit an
    /// empty JSON OBJECT `{}` as its InputJsonDelta, NOT `null`. Serializing `null` produced an
    /// invalid tool-input shape on cross-protocol egress.
    #[test]
    fn test_stream_zero_arg_function_call_emits_empty_object_not_null() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"functionCall": {"name": "ping"}}]},
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);
        let args_json = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::InputJsonDelta(s),
                ..
            } => Some(s.clone()),
            _ => None,
        });
        assert_eq!(
            args_json.as_deref(),
            Some("{}"),
            "zero-arg streamed functionCall must serialize to `{{}}`, not `null`: {events:?}"
        );
    }

    /// Regression (LOW, bug): a NON-STREAMING zero-arg `functionCall` (no `args` field) must decode
    /// to an empty-object `input` (`{}`), NOT `null`.
    #[test]
    fn test_read_response_zero_arg_function_call_input_is_empty_object_not_null() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"functionCall": {"name": "ping"}}]},
                "finishReason": GEMINI_FINISH_STOP
            }]
        });
        let ir = reader.read_response(&body).expect("read_response");
        let input = ir.content.iter().find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { input, .. } => Some(input.clone()),
            _ => None,
        });
        assert_eq!(
            input,
            Some(serde_json::Value::Object(serde_json::Map::new())),
            "zero-arg functionCall input must be `{{}}`, not null: {:?}",
            ir.content
        );
    }

    /// Regression: the streaming `BlockStart` for a tool block must carry a non-empty synthesized
    /// id (Gemini streams carry none) so the Anthropic/OpenAI stream writers emit a usable id.
    #[test]
    fn test_stream_tool_blockstart_id_is_nonempty() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "f", "args": {}}}]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);
        let id = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart {
                block: IrBlockMeta::ToolUse { id, .. },
                ..
            } => Some(id.clone()),
            _ => None,
        });
        assert!(
            id.is_some_and(|i| !i.is_empty()),
            "stream tool BlockStart must carry a non-empty id"
        );
    }

    // --- Round 3 fix 2: `stream` round-trip semantics + accurate comment ---

    /// Regression / documentation guard for the corrected `stream` comment. A source `stream` is
    /// captured into the typed `IrRequest.stream` (used only by path selection) AND preserved in
    /// `extra` for byte-identical round-trip (exactly like `model`), so the writer echoes it back.
    /// This is the behavior `src/proto/mod.rs::test_gemini_roundtrip_identity` (a non-owned test)
    /// enforces. The Round-3 finding's prescribed "drop stream from extra" would break that
    /// byte-identity invariant; the real defect (a FALSE comment claiming stream was excluded from
    /// extra) is fixed by making the comment accurate instead.
    #[test]
    fn test_read_request_source_stream_round_trips_via_extra() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "stream": true
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert!(ir.stream, "stream must be captured into IrRequest.stream");
        assert_eq!(
            ir.extra.get("stream"),
            Some(&serde_json::json!(true)),
            "a source `stream` is preserved in extra for round-trip identity (like model): {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.get("stream"),
            Some(&serde_json::json!(true)),
            "source `stream` round-trips onto the egress body via extra: {wire}"
        );
    }

    /// Regression: a NATIVE Gemini request carries no `stream`, so neither `extra` nor the egress
    /// body gains one even when the caller wants streaming (URL-selected). Guards the writer's
    /// "never synthesizes a stream member from req.stream" invariant.
    #[test]
    fn test_read_request_native_no_stream_stays_absent() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let mut ir = reader.read_request(&body).expect("read_request");
        ir.stream = true; // caller wants streaming; must not reach the body
        assert!(
            !ir.extra.contains_key("stream"),
            "native request carries no stream in extra: {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert!(
            wire.get("stream").is_none(),
            "stream intent must not be synthesized onto a native body: {wire}"
        );
    }

    /// Regression (R6, class D — integer-overflow on a cast): a `maxOutputTokens` above `u32::MAX`
    /// must NOT silently truncate (wrap) into a tiny token cap. The bounds-checked `u32::try_from`
    /// drops an out-of-range value to `None`, so the request carries no cap and the backend applies
    /// its default — never a mangled one. A bare `as u32` would have wrapped `5_000_000_000` to
    /// `705_032_704`, a cap the caller never asked for.
    #[test]
    fn test_read_request_max_output_tokens_overflow_drops_to_none() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 5_000_000_000i64}
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.max_tokens, None,
            "an out-of-u32-range maxOutputTokens must drop to None, not truncate"
        );

        // An in-range value still round-trips faithfully.
        let body_ok = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 1024}
        });
        let ir_ok = reader.read_request(&body_ok).expect("read_request");
        assert_eq!(
            ir_ok.max_tokens,
            Some(1024),
            "in-range cap must be preserved"
        );
    }

    // --- Round 3 fix 3: bogus snake_case `tool_config` removed; native `toolConfig` round-trips ---

    /// Regression: native Gemini `toolConfig` (camelCase) is NOT in `modeled_keys`, so it
    /// round-trips through `extra` and back onto the wire unchanged. The old bogus snake_case
    /// `tool_config` modeled-key entry (which matched no real field) has been removed.
    #[test]
    fn test_read_request_native_tool_config_round_trips_via_extra() {
        let reader = GeminiReader;
        let tool_config = serde_json::json!({
            "functionCallingConfig": {"mode": "ANY"}
        });
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "toolConfig": tool_config.clone()
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.extra.get("toolConfig"),
            Some(&tool_config),
            "native toolConfig must round-trip through extra: {:?}",
            ir.extra
        );
        let writer = GeminiWriter;
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.get("toolConfig"),
            Some(&tool_config),
            "toolConfig must be re-emitted on the wire: {wire}"
        );
    }

    /// Regression (R15): unmodeled `generationConfig` sub-fields (`responseMimeType` for JSON mode,
    /// `thinkingConfig` for extended thinking, `candidateCount`, `seed`, …) MUST survive read→write
    /// instead of being silently dropped. The reader keeps the raw `generationConfig` in `extra`; the
    /// writer overlays the 5 typed fields onto it. Both the typed fields AND every unmodeled sub-field
    /// must appear on the re-emitted body.
    #[test]
    fn test_generation_config_unmodeled_subfields_survive_roundtrip() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {
                "maxOutputTokens": 256,
                "temperature": 0.3,
                "responseMimeType": MIME_APPLICATION_JSON,
                "thinkingConfig": {"thinkingBudget": 1024},
                "candidateCount": 2,
                "seed": 42
            }
        });

        let ir = reader.read_request(&body).expect("read_request");
        // The raw generationConfig is preserved in extra (not modeled-out).
        assert!(
            ir.extra.contains_key("generationConfig"),
            "raw generationConfig must be preserved in extra: {:?}",
            ir.extra
        );
        // The 5 typed sub-fields are still promoted.
        assert_eq!(ir.max_tokens, Some(256));
        assert_eq!(ir.temperature, Some(0.3));

        let wire = writer.write_request(&ir);
        let gc = wire
            .get("generationConfig")
            .and_then(|g| g.as_object())
            .expect("generationConfig must be emitted");
        // Typed overlays present.
        assert_eq!(gc.get("maxOutputTokens"), Some(&serde_json::json!(256)));
        assert_eq!(gc.get("temperature"), Some(&serde_json::json!(0.3)));
        // Unmodeled sub-fields preserved (the defect was silently dropping these).
        assert_eq!(
            gc.get(FIELD_RESPONSE_MIME_TYPE),
            Some(&serde_json::json!(MIME_APPLICATION_JSON)),
            "responseMimeType (JSON mode) must survive: {wire}"
        );
        assert_eq!(
            gc.get("thinkingConfig"),
            Some(&serde_json::json!({"thinkingBudget": 1024})),
            "thinkingConfig (extended thinking) must survive: {wire}"
        );
        assert_eq!(gc.get("candidateCount"), Some(&serde_json::json!(2)));
        assert_eq!(gc.get("seed"), Some(&serde_json::json!(42)));
        // The raw generationConfig must NOT also appear as a duplicate top-level extra echo (the
        // writer skips it in the extra merge loop).
        assert_eq!(
            wire.as_object()
                .map(|o| o.keys().filter(|k| *k == "generationConfig").count()),
            Some(1),
            "generationConfig must appear exactly once: {wire}"
        );
    }

    /// Regression (R15): the typed IR fields OVERLAY the raw extra copy — if the IR's typed
    /// `max_tokens` differs from the raw `generationConfig.maxOutputTokens` (e.g. a cross-protocol
    /// edit), the typed value wins, mirroring BedrockWriter's inferenceConfig overlay.
    #[test]
    fn test_generation_config_typed_fields_override_raw_extra() {
        let writer = GeminiWriter;
        let mut extra = serde_json::Map::new();
        extra.insert(
            "generationConfig".to_string(),
            serde_json::json!({"maxOutputTokens": 100, "responseMimeType": "text/plain"}),
        );
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: Some(999),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: Vec::new(),
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra,
        };
        let wire = writer.write_request(&ir);
        let gc = wire
            .get("generationConfig")
            .and_then(|g| g.as_object())
            .expect("generationConfig must be emitted");
        assert_eq!(
            gc.get("maxOutputTokens"),
            Some(&serde_json::json!(999)),
            "typed max_tokens must overlay the raw extra value: {wire}"
        );
        assert_eq!(
            gc.get(FIELD_RESPONSE_MIME_TYPE),
            Some(&serde_json::json!("text/plain")),
            "unmodeled sub-field must survive the overlay: {wire}"
        );
    }

    // --- Round 3 fix 4: streamed and whole-body usageMetadata include totalTokenCount ---

    /// Regression: the streamed `MessageDelta` usage frame must include `totalTokenCount`
    /// (= prompt + candidates), matching the native final-chunk shape.
    #[test]
    fn test_stream_message_delta_includes_total_token_count() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 7,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(12)),
            "streamed usage must carry totalTokenCount = prompt + candidates: {frame}"
        );
        assert_eq!(
            frame.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(7))
        );
        assert_eq!(
            frame.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(5))
        );
    }

    /// The streamed total saturates (never overflow-panics) on pathological counts — guards the
    /// `saturating_add` on the request path.
    #[test]
    fn test_stream_message_delta_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {frame}"
        );
    }

    /// Regression (R5): on the CROSS-protocol egress path (signalled by a populated `created` — the
    /// boundary marker a non-Gemini backend reader leaves, since Gemini bodies carry no timestamp)
    /// the whole-body `write_response` usageMetadata MUST include `totalTokenCount` (= prompt +
    /// candidates). A native Gemini `generateContent` body always carries the sum, and the value is a
    /// faithfully derived total (not a fabricated field). Earlier it was omitted, leaving the
    /// google-genai SDK's `total_token_count` at None/0 for cross-protocol callers.
    #[test]
    fn test_write_response_includes_total_token_count_cross_protocol() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 5,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: Some(1_700_000_000), // cross-protocol boundary signal
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(8)),
            "cross-protocol usage must carry totalTokenCount = prompt + candidates: {wire}"
        );
        assert_eq!(
            wire.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(5))
        );
        assert_eq!(
            wire.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(3))
        );
    }

    /// Fidelity guard: a SAME-protocol read→write (no `created` — native Gemini bodies carry no
    /// timestamp) must NOT inject `totalTokenCount` the upstream omitted, so the round-trip stays
    /// byte-identical. (Production same-protocol passthrough bypasses the writer entirely; this
    /// guards the in-IR read→write identity invariant `test_gemini_read_write_response_roundtrip`
    /// in mod.rs depends on.)
    #[test]
    fn test_write_response_omits_total_token_count_same_protocol() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 5,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None, // same-protocol: no boundary signal
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert!(
            wire.pointer("/usageMetadata/totalTokenCount").is_none(),
            "same-protocol round-trip must omit totalTokenCount for byte-identity: {wire}"
        );
    }

    /// The cross-protocol whole-body total saturates (never overflow-panics) on pathological counts.
    #[test]
    fn test_write_response_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: Vec::new(),
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: Some(1_700_000_000), // cross-protocol
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {wire}"
        );
    }

    // --- Round 9 fix (conformance): totalTokenCount also emits when the boundary signal is `model`
    //     (not just `created`), so Anthropic/Cohere backends — whose readers return `created: None`
    //     but DO populate `model` — no longer drop the total for a Gemini client. ---

    /// Regression (R9): a cross-protocol response from a backend whose reader sets `created: None`
    /// but `model: Some(..)` (the Anthropic and Cohere shape) MUST still carry
    /// `usageMetadata.totalTokenCount`. Before R9 the gate keyed on `created` alone, so these three-
    /// of-five backends produced a usageMetadata block lacking the total, leaving the google-genai
    /// SDK's `total_token_count` at None and breaking client-side billing.
    #[test]
    fn test_write_response_includes_total_token_count_when_only_model_present() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 11,
                output_tokens: 4,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            // Anthropic/Cohere cross-protocol shape: model survives, created/id are None.
            model: Some("claude-opus-4-8".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(15)),
            "model-only cross-protocol boundary must still carry totalTokenCount: {wire}"
        );
        assert_eq!(
            wire.pointer("/usageMetadata/promptTokenCount"),
            Some(&serde_json::json!(11))
        );
        assert_eq!(
            wire.pointer("/usageMetadata/candidatesTokenCount"),
            Some(&serde_json::json!(4))
        );
    }

    /// The model-only cross-protocol total saturates (never overflow-panics) on pathological counts,
    /// guarding the `saturating_add` on this newly-reachable branch of the request path.
    #[test]
    fn test_write_response_model_only_total_token_count_saturates() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: Vec::new(),
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("command-r".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/usageMetadata/totalTokenCount"),
            Some(&serde_json::json!(u64::MAX)),
            "totalTokenCount must saturate, not wrap/panic: {wire}"
        );
    }

    // --- Round 9 fix (performance): modeled_keys is hoisted to a process-global OnceLock. ---

    /// Regression (R9): the modeled-key set is a stable process-global — repeated calls return the
    /// SAME backing allocation (proving it is built once, not per request) and the set's membership
    /// is exactly the modeled top-level keys, so unmodeled keys still flow to `extra`.
    #[test]
    fn test_modeled_request_keys_is_stable_singleton() {
        let a = modeled_request_keys();
        let b = modeled_request_keys();
        assert!(
            std::ptr::eq(a, b),
            "modeled_request_keys must return the same cached set, not rebuild per call"
        );
        for k in [
            "contents",
            "tools",
            "systemInstruction",
            "model",
            crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY,
        ] {
            assert!(a.contains(k), "modeled key set must contain {k}");
        }
        // An arbitrary caller field is NOT modeled, so the reader sweeps it into `extra`.
        assert!(!a.contains("toolConfig"), "toolConfig must not be modeled");
        // `generationConfig` is INTENTIONALLY not modeled-out of `extra`: the reader keeps the raw
        // object so the writer can overlay the 5 typed fields and preserve unmodeled sub-fields.
        assert!(
            !a.contains("generationConfig"),
            "generationConfig must NOT be modeled-out of extra (raw object is preserved for overlay)"
        );
    }

    /// Regression (R9): hoisting the set must not change read behavior — an unmodeled top-level key
    /// still round-trips through `extra`, and the modeled `model` key is preserved exactly once.
    #[test]
    fn test_read_request_unmodeled_key_still_flows_to_extra_after_hoist() {
        let reader = GeminiReader;
        let j = serde_json::json!({
            "model": "gemini-pro",
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}}
        });
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert_eq!(
            ir.extra.get("toolConfig"),
            Some(&serde_json::json!({"functionCallingConfig": {"mode": "AUTO"}})),
            "unmodeled toolConfig must be preserved in extra"
        );
        assert_eq!(
            ir.extra.get("model"),
            Some(&serde_json::json!("gemini-pro")),
            "modeled `model` is preserved in extra exactly once for round-trip identity"
        );
        assert!(
            !ir.extra.contains_key("contents"),
            "modeled `contents` must NOT leak into extra"
        );
    }

    // --- Round 5 fix: tool_use stop reason maps to STOP (Gemini has no TOOL_USE enum member) ---

    /// Regression: a buffered `write_response` with stop_reason=tool_use (the canonical value every
    /// other protocol's reader emits for a tool-call turn) must emit finishReason "STOP", NOT the
    /// invalid "TOOL_USE" the old upper-casing fallback produced.
    #[test]
    fn test_write_response_tool_use_maps_to_stop() {
        let writer = GeminiWriter;
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            }],
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
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
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire.pointer("/candidates/0/finishReason")
                .and_then(|f| f.as_str()),
            Some("STOP"), // golden wire-contract literal (kept bare on purpose)
            "tool_use must map to STOP, never TOOL_USE: {wire}"
        );
    }

    /// Regression: the streamed `MessageDelta` with stop_reason=tool_use also emits finishReason
    /// "STOP" (matching native Gemini, whose FinishReason enum has no TOOL_USE member).
    #[test]
    fn test_stream_message_delta_tool_use_maps_to_stop() {
        let writer = GeminiWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame
                .pointer("/candidates/0/finishReason")
                .and_then(|f| f.as_str()),
            Some("STOP"), // golden wire-contract literal (kept bare on purpose)
            "streamed tool_use must map to STOP, never TOOL_USE: {frame}"
        );
    }

    // --- Round 5 fix: image_url sentinel emitted as native fileData URI, not corrupt base64 ---

    /// Regression: an IR Image carrying the `"image_url"` media_type SENTINEL (a remote https URL
    /// stored verbatim by the OpenAI/Responses readers) must be emitted as Gemini `fileData{fileUri}`
    /// — the native URL reference — NOT as `inlineData` with the URL stuffed into the base64 `data`
    /// field and a bogus `mimeType: "image_url"`.
    #[test]
    fn test_write_request_image_url_sentinel_emits_file_data() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Url(
                        "https://example.com/cat.png".to_string(),
                    ),
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri")
                .and_then(|u| u.as_str()),
            Some("https://example.com/cat.png"),
            "image_url sentinel must emit native fileData.fileUri: {wire}"
        );
        assert!(
            wire.pointer("/contents/0/parts/0/inlineData").is_none(),
            "sentinel URL must NOT be emitted as base64 inlineData: {wire}"
        );
    }

    /// A real base64 image (a genuine mimeType) still emits as `inlineData` — the sentinel branch
    /// must not divert legitimate base64 payloads.
    #[test]
    fn test_write_request_base64_image_still_inline_data() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: "image/png".to_string(),
                        data: "aGVsbG8=".to_string(),
                    },
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/inlineData/mimeType")
                .and_then(|m| m.as_str()),
            Some("image/png"),
            "base64 image must stay inlineData: {wire}"
        );
        assert_eq!(
            wire.pointer("/contents/0/parts/0/inlineData/data")
                .and_then(|d| d.as_str()),
            Some("aGVsbG8="),
        );
    }

    /// Round-trip: a native Gemini `fileData{fileUri}` part reads into the typed `Url` image source
    /// and the writer re-emits it as `fileData{fileUri}` verbatim (same-protocol fidelity).
    #[test]
    fn test_file_data_image_round_trips_via_url() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"fileData": {"fileUri": "gs://bucket/img.jpg"}}]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let url = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(url),
                ..
            } => Some(url.clone()),
            _ => None,
        });
        assert_eq!(
            url.as_deref(),
            Some("gs://bucket/img.jpg"),
            "fileData must read into the typed Url source: {ir:?}"
        );
        let wire = writer.write_request(&ir);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri")
                .and_then(|u| u.as_str()),
            Some("gs://bucket/img.jpg"),
            "fileData must round-trip verbatim: {wire}"
        );
    }

    // --- Round 14 fix: synth_response_id is an opaque CSPRNG token of native Gemini shape ---

    /// Regression (HIGH/conformance): a synthesized `responseId` must be a native-shaped opaque
    /// token — mixed-case alphanumeric base62 of native length, with NO hyphen separator and NO
    /// lowercase-hex-only restriction. The old `format!("{:x}-{:x}", unix_now_secs(), seq)` form was
    /// structurally distinguishable (the `-` plus `[0-9a-f]`-only class is a shape no native id has)
    /// AND leaked the proxy host clock in its leading hex segment. Assert the shape never regresses.
    #[test]
    fn test_synth_response_id_is_opaque_native_shape() {
        let id = synth_response_id();
        assert_eq!(
            id.len(),
            RESPONSE_ID_TOKEN_LEN,
            "synthesized responseId must be exactly the native token length: {id}"
        );
        assert!(
            !id.contains('-'),
            "synthesized responseId must carry NO hyphen separator (a non-native tell): {id}"
        );
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric()),
            "synthesized responseId must be mixed-case alphanumeric (no `-`/`_`): {id}"
        );
        // A lowercase-hex-only token (`[0-9a-f]*`) is the old timestamp-hex tell. Across a batch the
        // synthesized ids must NOT be confinable to that class — at least one carries an uppercase
        // letter or a digit/letter outside `[0-9a-f]`, proving the wider base62 character class.
        let saw_non_hex = (0..64).map(|_| synth_response_id()).any(|s| {
            s.chars()
                .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        });
        assert!(
            saw_non_hex,
            "synthesized responseIds must draw from mixed-case base62, not lowercase-hex only"
        );
    }

    /// The synthesized id must embed NO unix-second prefix: the old form's leading segment WAS the
    /// server clock. Mint two ids and assert neither equals the hex of the current unix second (the
    /// old leading segment), and that they are not hyphen-delimited time+counter pairs.
    #[test]
    fn test_synth_response_id_leaks_no_timestamp() {
        let now_hex = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        for _ in 0..16 {
            let id = synth_response_id();
            assert!(
                !id.starts_with(&now_hex),
                "synthesized responseId must not lead with the unix-second hex (clock leak): {id}"
            );
            assert!(
                !id.contains('-'),
                "synthesized responseId must not be a hyphenated time-counter pair: {id}"
            );
        }
    }

    /// Two consecutive synthesized ids differ because the whole 16-char base62 token is drawn from
    /// `getrandom` (~95 bits of entropy) — guards the collision-free per-process uniqueness property.
    #[test]
    fn test_synth_response_id_distinct_consecutive() {
        let a = synth_response_id();
        let b = synth_response_id();
        assert_ne!(a, b, "consecutive synthesized ids must differ: {a} vs {b}");
    }

    /// Regression (LOW/quality, R18): the base62 reduction must be UNBIASED. The old body mapped each
    /// random byte with a bare `byte % 62`; because `256 % 62 != 0`, the 8 symbols reachable from the
    /// partial final block (bytes `248..=255` → residues `0..=7`) were drawn at 5/256 while the other
    /// 54 symbols were drawn at 4/256 — a ~25% over-representation of those 8 symbols. Rejection
    /// sampling (reject bytes `>= 248`) flattens that. Draw a large burst, tally per-symbol frequency,
    /// and assert the over-represented class is NOT systematically inflated: the mean frequency of the
    /// 8 formerly-hot symbols must stay close to the mean of the other 54. Under the OLD biased code
    /// the hot/cold ratio is ~1.25 and this assertion fails; under rejection sampling it is ~1.0.
    #[test]
    fn test_synth_response_id_base62_is_unbiased() {
        use std::collections::HashMap;
        // Symbols reachable from residues 0..=7 (the formerly over-represented class).
        let hot: Vec<char> = RESPONSE_ID_ALPHABET[..8]
            .iter()
            .map(|&b| b as char)
            .collect();

        let mut counts: HashMap<char, u64> = HashMap::new();
        let mut total: u64 = 0;
        for _ in 0..40_000 {
            for c in synth_response_id().chars() {
                *counts.entry(c).or_insert(0) += 1;
                total += 1;
            }
        }
        assert!(total > 0, "burst produced no symbols");

        let hot_sum: u64 = hot.iter().map(|c| *counts.get(c).unwrap_or(&0)).sum();
        let cold_sum: u64 = counts
            .iter()
            .filter(|(c, _)| !hot.contains(c))
            .map(|(_, n)| *n)
            .sum();
        // Per-symbol means: 8 hot symbols vs 54 cold symbols.
        let hot_mean = hot_sum as f64 / hot.len() as f64;
        let cold_count = 62 - hot.len();
        let cold_mean = cold_sum as f64 / cold_count as f64;
        assert!(cold_mean > 0.0, "no cold-symbol samples observed");
        let ratio = hot_mean / cold_mean;
        // Unbiased ≈ 1.0; old biased code ≈ 1.25. A generous window catches the bias while tolerating
        // ordinary sampling noise over ~640k symbols.
        assert!(
            (0.90..=1.10).contains(&ratio),
            "base62 reduction is biased: hot/cold per-symbol frequency ratio {ratio:.4} \
             (hot_mean {hot_mean:.1}, cold_mean {cold_mean:.1}) — expected ~1.0 from unbiased \
             rejection sampling, ~1.25 indicates the old `byte % 62` bias regressed"
        );
    }

    /// Uniqueness burst (R18): a large run of synthesized ids must be collision-free in practice (each
    /// is ~95 bits). Mint a burst and assert every id is distinct and native-shaped.
    #[test]
    fn test_synth_response_id_uniqueness_burst() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for _ in 0..50_000 {
            let id = synth_response_id();
            assert_eq!(id.len(), RESPONSE_ID_TOKEN_LEN, "non-native length: {id}");
            assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric()),
                "non-base62 char in id: {id}"
            );
            assert!(
                seen.insert(id.clone()),
                "synthesized responseId collided: {id}"
            );
        }
    }

    /// Regression (HIGH/performance): `state.open_tools` is only drained on a `finishReason` chunk,
    /// so an upstream that streams an unbounded run of `functionCall` parts WITHOUT a finishReason
    /// must not grow it without bound. Past `MAX_GEMINI_TOOL_FRAMES` new tool frames stop being
    /// recorded (and their events suppressed), keeping the set capped while every realistic stream
    /// (a handful of tools) is unaffected. Mirrors the Cohere reader's cap regression.
    #[test]
    fn test_stream_open_tools_growth_is_capped() {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        // Feed many functionCall parts across many chunks, never sending a finishReason so the
        // drain path never runs — the only thing that can keep the set bounded is the cap.
        for n in 0..(MAX_GEMINI_TOOL_FRAMES + 200) {
            reader.read_response_events(
                "",
                &serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                        }
                    }]
                }),
                &mut state,
            );
        }
        assert!(
            state.open_tools.len() <= MAX_GEMINI_TOOL_FRAMES,
            "open_tools must be capped at MAX_GEMINI_TOOL_FRAMES, got {}",
            state.open_tools.len()
        );
    }

    /// The cap must NOT perturb a realistic stream: a small number of tool calls are all recorded
    /// and each gets a matching BlockStart it can close on finishReason.
    #[test]
    fn test_stream_open_tools_under_cap_records_all() {
        let reader = GeminiReader;
        let mut state = StreamDecodeState::default();
        let mut starts = 0usize;
        for n in 0..3 {
            for ev in reader.read_response_events(
                "",
                &serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                        }
                    }]
                }),
                &mut state,
            ) {
                if matches!(ev, IrStreamEvent::BlockStart { .. }) {
                    starts += 1;
                }
            }
        }
        assert_eq!(state.open_tools.len(), 3, "all 3 tool frames recorded");
        assert_eq!(starts, 3, "each tool frame emits exactly one BlockStart");
    }

    /// A well-formed credential yields exactly one `x-goog-api-key` header carrying the verbatim key.
    #[test]
    fn test_auth_headers_valid_key_emits_x_goog_api_key() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("AIzaSyValidKey123");
        assert_eq!(headers.len(), 1, "one auth header for a valid key");
        assert_eq!(headers[0].0.as_str(), "x-goog-api-key");
        assert_eq!(headers[0].1.to_str().ok(), Some("AIzaSyValidKey123"));
    }

    /// MEDIUM/security regression: a credential whose bytes are invalid for an HTTP header value
    /// (here an embedded newline) must NOT be silently swallowed into an empty `x-goog-api-key`
    /// value. The writer omits the header entirely (empty vec) and never panics on the request path.
    /// The accompanying `tracing::warn!` (not asserted here) gives the operator the diagnostic the
    /// empty-header behavior lacked.
    #[test]
    fn test_auth_headers_invalid_key_omits_header_no_empty_value() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("bad\nkey");
        assert!(
            headers.is_empty(),
            "an invalid-byte credential must omit the auth header, not emit an empty value: \
             {headers:?}"
        );
    }

    /// An ASCII control byte other than the newline above (here a NUL) is also rejected, exercising
    /// the control-character class of header-invalid byte the validation guards against.
    #[test]
    fn test_auth_headers_control_byte_key_omits_header() {
        let writer = GeminiWriter;
        let headers = writer.auth_headers("key\u{0000}bad");
        assert!(
            headers.is_empty(),
            "a control-byte credential must omit the auth header: {headers:?}"
        );
    }

    /// HIGH/correctness regression: a Tool-role IR message carries `ToolResult` blocks, which the
    /// writer emits as Gemini `functionResponse` parts. In the native GenerateContentRequest schema
    /// a `functionResponse` turn MUST be sent under `role:"user"` — the `model` role is exclusively
    /// the assistant turn (which produces `functionCall`s). Mapping Tool → "model" emits a
    /// non-native shape the real Gemini API / google-genai SDK rejects (400 INVALID_ARGUMENT). The
    /// turn carrying the `functionResponse` must therefore have `role == "user"`, matching the
    /// Bedrock writer's `toolResult` handling.
    #[test]
    fn test_tool_role_maps_to_user_for_function_response() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "get_weather".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "{\"temp\":21}".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let wire = writer.write_request(&req);
        let content = &wire["contents"][0];

        assert_eq!(
            content["role"], "user",
            "a Tool-role message carrying a functionResponse must be emitted under role:\"user\", \
             never \"model\": {wire}"
        );
        // The functionResponse part must still be present and correctly shaped under that turn.
        let fr = &content["parts"][0]["functionResponse"];
        assert_eq!(
            fr["name"], "get_weather",
            "functionResponse must name the tool: {wire}"
        );
        assert_eq!(
            fr["response"]["temp"], 21,
            "structured JSON tool output must be forwarded verbatim: {wire}"
        );
    }

    /// HIGH/correctness regression: an Assistant-role message carrying a `functionCall` (ToolUse)
    /// must still be emitted under `role:"model"` — the fix to the Tool role must NOT regress the
    /// assistant mapping, since `functionCall`s are exclusively a model-turn shape.
    #[test]
    fn test_assistant_tool_use_stays_model_role() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({ "city": "SF" }),
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let wire = writer.write_request(&req);
        let content = &wire["contents"][0];
        assert_eq!(
            content["role"], "model",
            "an Assistant functionCall turn must stay role:\"model\": {wire}"
        );
        assert_eq!(
            content["parts"][0][FIELD_FUNCTION_CALL]["name"], "get_weather",
            "functionCall must be preserved under the model turn: {wire}"
        );
    }

    /// Regression (MEDIUM/correctness): an inline `{"error":{...}}` google.rpc.Status object
    /// delivered as a 200-status SSE data chunk mid-stream MUST surface as a single
    /// `IrStreamEvent::Error` (mapped from `error.status`) rather than being silently swallowed.
    /// Before the fix the reader emitted a bare MessageStart and then nothing — a hung,
    /// non-terminated stream — because the chunk carried no `candidates`.
    #[test]
    fn test_stream_inline_error_envelope_surfaces_ir_error() {
        let events = collect_stream(&[serde_json::json!({
            "error": {
                "code": 429,
                "message": "Resource has been exhausted (e.g. check quota).",
                "status": GRPC_RESOURCE_EXHAUSTED
            }
        })]);

        // Exactly one event, an Error mapped to RateLimit, carrying the upstream message. NO
        // MessageStart precedes it (an error-only chunk must not emit a stray start frame).
        match events.as_slice() {
            [IrStreamEvent::Error(err)] => {
                assert_eq!(err.class, StatusClass::RateLimit, "events: {events:?}");
                assert_eq!(
                    err.provider_signal.as_deref(),
                    Some("Resource has been exhausted (e.g. check quota)."),
                    "events: {events:?}"
                );
            }
            other => panic!("expected exactly one IrStreamEvent::Error, got {other:?}"),
        }
    }

    /// An inline error whose `status` is absent falls back to the numeric `code` mapping (503 →
    /// Overloaded), and a missing/unknown code defaults to ServerError — never silently dropped.
    #[test]
    fn test_stream_inline_error_code_fallback_and_default() {
        // status absent → 503 maps to Overloaded.
        let by_code = collect_stream(&[serde_json::json!({
            "error": { "code": 503, "message": "backend overloaded" }
        })]);
        match by_code.as_slice() {
            [IrStreamEvent::Error(err)] => {
                assert_eq!(err.class, StatusClass::Overloaded, "events: {by_code:?}")
            }
            other => panic!("expected one Error, got {other:?}"),
        }

        // Neither status nor a recognized code → ServerError default (safe, breaker-tripping).
        let bare = collect_stream(&[serde_json::json!({
            "error": { "message": "something failed" }
        })]);
        match bare.as_slice() {
            [IrStreamEvent::Error(err)] => {
                assert_eq!(err.class, StatusClass::ServerError, "events: {bare:?}");
                assert_eq!(
                    err.provider_signal.as_deref(),
                    Some("something failed"),
                    "events: {bare:?}"
                );
            }
            other => panic!("expected one Error, got {other:?}"),
        }
    }

    /// `gemini_error_status_class` prefers the UPPER_SNAKE `status` over the numeric `code`, and an
    /// unrecognized status string falls through to the code mapping.
    #[test]
    fn test_gemini_error_status_class_mapping() {
        assert_eq!(
            gemini_error_status_class(Some(GRPC_UNAVAILABLE), Some(503)),
            StatusClass::Overloaded
        );
        assert_eq!(
            gemini_error_status_class(Some(GRPC_UNAUTHENTICATED), Some(401)),
            StatusClass::Auth
        );
        assert_eq!(
            gemini_error_status_class(Some(GRPC_PERMISSION_DENIED), Some(403)),
            StatusClass::Billing
        );
        assert_eq!(
            gemini_error_status_class(Some(GRPC_DEADLINE_EXCEEDED), Some(504)),
            StatusClass::Timeout
        );
        assert_eq!(
            gemini_error_status_class(Some(GRPC_INVALID_ARGUMENT), Some(400)),
            StatusClass::ClientError
        );
        // status wins over code: an INTERNAL status with a (nonsensical) 429 code is ServerError.
        assert_eq!(
            gemini_error_status_class(Some(GRPC_INTERNAL), Some(429)),
            StatusClass::ServerError
        );
        // Unknown status string → fall through to the numeric code (429 → RateLimit).
        assert_eq!(
            gemini_error_status_class(Some("SOME_FUTURE_CODE"), Some(429)),
            StatusClass::RateLimit
        );
    }

    /// Regression (MEDIUM/conformance): the Gemini bad-key auth-failure envelope MUST carry the
    /// canonical `error.details[]` array with a google.rpc.ErrorInfo whose `reason` is
    /// `API_KEY_INVALID`. The `google-genai` SDK keys auth handling off `details[].reason`, so the
    /// real Generative Language API always populates it on the bad-key 400. The triple of (status
    /// 400, INVALID_ARGUMENT, the canonical bad-key message) is exactly what
    /// `auth.rs::unauthorized_response` produces for a Gemini-inferred path.
    #[test]
    fn test_write_error_bad_key_carries_api_key_invalid_details() {
        let writer = GeminiWriter;
        let envelope = writer.write_error(
            400,
            "invalid_request_error",
            crate::proto::gemini::GEMINI_BAD_KEY_MESSAGE,
        );

        assert_eq!(
            envelope.pointer("/error/code"),
            Some(&serde_json::json!(400)),
            "envelope: {envelope}"
        );
        assert_eq!(
            envelope.pointer("/error/status").and_then(|s| s.as_str()),
            Some("INVALID_ARGUMENT"), // golden wire-contract literal (kept bare on purpose)
            "envelope: {envelope}"
        );
        let detail = envelope
            .pointer("/error/details/0")
            .expect("bad-key envelope must carry error.details[0]");
        assert_eq!(
            detail.get("@type").and_then(|t| t.as_str()),
            Some("type.googleapis.com/google.rpc.ErrorInfo"), // golden wire-contract literal (kept bare on purpose)
            "detail: {detail}"
        );
        assert_eq!(
            detail.get("reason").and_then(|r| r.as_str()),
            Some("API_KEY_INVALID"), // golden wire-contract literal (kept bare on purpose)
            "detail: {detail}"
        );
        assert_eq!(
            detail.get("domain").and_then(|d| d.as_str()),
            Some("googleapis.com"),
            "detail: {detail}"
        );
        assert_eq!(
            detail.pointer("/metadata/service").and_then(|s| s.as_str()),
            Some("generativelanguage.googleapis.com"),
            "detail: {detail}"
        );
    }

    /// A NON-auth 400/INVALID_ARGUMENT (e.g. a generic malformed-request body) must NOT grow the
    /// API_KEY_INVALID details array — real Google does not carry that reason on a non-key 400, so
    /// over-filling it would itself be a tell. Only the canonical bad-key message triggers details.
    #[test]
    fn test_write_error_generic_invalid_argument_has_no_details() {
        let writer = GeminiWriter;
        let envelope =
            writer.write_error(400, "invalid_request_error", "Invalid value at 'contents'.");
        assert_eq!(
            envelope.pointer("/error/status").and_then(|s| s.as_str()),
            Some("INVALID_ARGUMENT"), // golden wire-contract literal (kept bare on purpose)
            "envelope: {envelope}"
        );
        assert!(
            envelope.pointer("/error/details").is_none(),
            "a non-bad-key 400 must NOT carry API_KEY_INVALID details: {envelope}"
        );
    }

    /// HIGH/correctness regression: on a CROSS-protocol multi-turn tool call (Anthropic/OpenAI
    /// ingress → Gemini egress) the IR's ToolUse carries a SYNTHETIC `call_<hash>` id and the matching
    /// ToolResult's `tool_use_id` carries that SAME synthetic id — NOT the real function name. Gemini
    /// correlates a `functionResponse` to its `functionCall` strictly BY NAME (no ids), so the emitted
    /// `functionResponse.name` MUST equal the `functionCall.name` (`get_weather`), NOT the hash.
    /// Before the fix the writer emitted the hash verbatim, so the backend could not correlate and
    /// every cross-protocol→Gemini multi-turn tool call broke. The writer resolves the real name from
    /// an id→name map built across all request messages.
    #[test]
    fn test_write_request_cross_protocol_function_response_name_matches_call() {
        let writer = GeminiWriter;
        let synthetic_id = "call_00000000deadbeef".to_string();
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![
                // Assistant turn: the tool CALL carries a synthetic id, real name `get_weather`.
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: synthetic_id.clone(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({ "city": "SF" }),
                        cache_control: None,
                    }],
                },
                // Tool turn: the RESULT references the call by the SAME synthetic id (cross-protocol
                // seam keeps the id, not the name).
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: synthetic_id.clone(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "{\"temp\":21}".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let wire = writer.write_request(&req);
        let call_name = wire
            .pointer("/contents/0/parts/0/functionCall/name")
            .and_then(|n| n.as_str());
        let resp_name = wire
            .pointer("/contents/1/parts/0/functionResponse/name")
            .and_then(|n| n.as_str());
        assert_eq!(
            call_name,
            Some("get_weather"),
            "functionCall.name must be the real tool name: {wire}"
        );
        assert_eq!(
            resp_name,
            Some("get_weather"),
            "functionResponse.name must resolve to the real function name (matching \
             functionCall.name), NOT the synthetic call_<hash> id: {wire}"
        );
        assert_eq!(
            call_name, resp_name,
            "Gemini correlates by name: functionResponse.name MUST equal functionCall.name: {wire}"
        );
    }

    /// Same-protocol (Gemini→Gemini) regression guard for the fix above: when the ToolResult's
    /// `tool_use_id` is ALREADY the function name (the reader's same-protocol behavior) and there is no
    /// matching ToolUse id in the request, the writer must FALL BACK to that name verbatim — the
    /// id→name map lookup must not blank it out.
    #[test]
    fn test_write_request_same_protocol_function_response_name_falls_back_to_id() {
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "get_weather".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "{\"temp\":21}".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        assert_eq!(
            wire.pointer("/contents/0/parts/0/functionResponse/name")
                .and_then(|n| n.as_str()),
            Some("get_weather"),
            "same-protocol functionResponse.name must fall back to the tool_use_id (the name): {wire}"
        );
    }

    /// LOW/completeness regression: a STREAMING chunk with an EMPTY `candidates: []` array (rather than
    /// an absent array) alongside a top-level `promptFeedback.blockReason` must still route into the
    /// prompt-block terminal arm — MessageStart, then a `safety` MessageDelta + MessageStop. Before the
    /// fix `candidates_absent` keyed only on array-PRESENCE, so `[]` slipped past the arm and the
    /// stream emitted a bare un-terminated frame.
    #[test]
    fn test_stream_empty_candidates_array_prompt_block_terminates() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [],
            "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
        })]);
        let stop_reason = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
            _ => None,
        });
        assert_eq!(
            stop_reason,
            Some(crate::ir::IrStopReason::Safety),
            "an empty candidates[] + blockReason stream must surface a `safety` stop: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(IrStreamEvent::MessageStop)),
            "the empty-candidates prompt-block stream must terminate with MessageStop: {events:?}"
        );
    }

    /// LOW/completeness regression: a NON-STREAMING body with an EMPTY `candidates: []` array plus a
    /// top-level `promptFeedback.blockReason` must decode to an empty-content `safety` response, NOT
    /// hard-fail `candidates.is_empty()` into a spurious `ir_parse` error (the old behavior, since
    /// `candidates_absent` treated `[]` as present and skipped the prompt-block arm).
    #[test]
    fn test_read_response_empty_candidates_array_prompt_block_is_safety_stop() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [],
            "promptFeedback": {"blockReason": GEMINI_FINISH_PROHIBITED_CONTENT},
            "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 0}
        });
        let ir = reader
            .read_response(&body)
            .expect("empty-candidates prompt-blocked body must decode, not error");
        assert!(
            ir.content.is_empty(),
            "a blocked prompt has no content blocks, got {:?}",
            ir.content
        );
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::Safety),
            "an empty candidates[] + blockReason body must surface a `safety` stop_reason"
        );
    }

    /// Guard: an EMPTY `candidates: []` with NO block reason and NO error is still a malformed
    /// envelope and MUST hard-fail (the broadened `candidates_absent` routes it into the prompt-block
    /// arm, which finds no reason and falls through to the existing empty-array hard-fail below).
    #[test]
    fn test_read_response_empty_candidates_array_without_block_still_errors() {
        let reader = GeminiReader;
        let body = serde_json::json!({"candidates": [], "usageMetadata": {"promptTokenCount": 1}});
        assert!(
            reader.read_response(&body).is_err(),
            "an empty candidates[] body with no block reason must still error"
        );
    }

    /// Regression (MED #2): Gemini has no TOOL_USE finishReason — a tool-call turn ends with STOP.
    /// `read_response` mapped STOP → `end_turn` unconditionally, so the IR carried `end_turn` next to
    /// a `ToolUse` block, which leaked on cross-protocol egress (Anthropic relays `end_turn`; OpenAI
    /// maps it to `"stop"`). When a `ToolUse` block is present, the buffered reader MUST promote
    /// `end_turn` → `tool_use`. Fails against the old unconditional mapping.
    #[test]
    fn test_read_response_stop_with_function_call_is_tool_use() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        });
        let ir = reader
            .read_response(&body)
            .expect("tool-call STOP body must decode");
        assert!(
            ir.content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })),
            "the response must carry a ToolUse block: {:?}",
            ir.content
        );
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::ToolUse),
            "STOP + functionCall must read back as `tool_use`, not `end_turn`"
        );
    }

    /// Companion guard (MED #2): a plain STOP with NO tool block must stay `end_turn`. The promotion
    /// must be gated on a ToolUse block being present, not applied to every STOP.
    #[test]
    fn test_read_response_plain_stop_stays_end_turn() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hello"}]},
                "finishReason": GEMINI_FINISH_STOP
            }]
        });
        let ir = reader.read_response(&body).expect("plain STOP must decode");
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::EndTurn),
            "a plain STOP with no tool block must stay `end_turn`"
        );
    }

    /// Regression (MED #2, streaming sibling): the streaming reader mapped STOP → `end_turn` on the
    /// terminal MessageDelta unconditionally, leaking `end_turn` for a tool-call turn on the streamed
    /// cross-protocol path. When tool blocks were opened this run (`state.open_tools` non-empty at the
    /// finishReason handler), the terminal stop_reason MUST be `tool_use`. Fails against old code.
    #[test]
    fn test_stream_stop_with_function_call_terminal_is_tool_use() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
                },
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);
        let stop = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
            _ => None,
        });
        assert_eq!(
            stop.flatten(),
            Some(crate::ir::IrStopReason::ToolUse),
            "streamed STOP + functionCall must terminate with `tool_use`: {events:?}"
        );
    }

    /// Companion guard (MED #2, streaming): a plain STOP stream with no tool block must terminate
    /// with `end_turn` (no spurious promotion when `state.open_tools` is empty).
    #[test]
    fn test_stream_plain_stop_terminal_stays_end_turn() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hello"}]},
                "finishReason": GEMINI_FINISH_STOP
            }]
        })]);
        let stop = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
            _ => None,
        });
        assert_eq!(
            stop.flatten(),
            Some(crate::ir::IrStopReason::EndTurn),
            "a plain STOP stream must terminate with `end_turn`: {events:?}"
        );
    }

    /// Regression (LOW #10): a `ToolUse.input` that is a JSON ARRAY must be coerced to a valid Gemini
    /// `functionCall.args` OBJECT (Gemini `args` is a protobuf Struct). The old code passed an array
    /// through verbatim (`input.is_array()` branch), producing a backend-rejected request. After the
    /// fix the array is wrapped under `{"args": <value>}`. Asserts BOTH writers (request + response).
    #[test]
    fn test_tool_use_array_input_coerced_to_object_args() {
        let block = crate::ir::IrBlock::ToolUse {
            id: "call_1".to_string(),
            name: "do_thing".to_string(),
            input: serde_json::json!([1, 2, 3]),
            cache_control: None,
        };

        // write_request path
        let writer = GeminiWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![block.clone()],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let wire = writer.write_request(&req);
        let args = wire
            .pointer("/contents/0/parts/0/functionCall/args")
            .expect("functionCall.args must be present");
        assert!(
            args.is_object(),
            "request functionCall.args MUST be an object (Gemini Struct), got: {args}"
        );
        assert_eq!(
            args.pointer("/args"),
            Some(&serde_json::json!([1, 2, 3])),
            "array input must be wrapped under `args`: {args}"
        );

        // write_response path
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![block],
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let rwire = writer.write_response(&resp);
        let rargs = rwire
            .pointer("/candidates/0/content/parts/0/functionCall/args")
            .expect("response functionCall.args must be present");
        assert!(
            rargs.is_object(),
            "response functionCall.args MUST be an object, got: {rargs}"
        );
        assert_eq!(
            rargs.pointer("/args"),
            Some(&serde_json::json!([1, 2, 3])),
            "array input must be wrapped under `args` in the response too: {rargs}"
        );
    }

    /// Companion guard (LOW #10): an OBJECT `ToolUse.input` must pass through byte-identical so the
    /// same-protocol Gemini→Gemini round-trip stays lossless (no `{"args": ...}` wrapping).
    #[test]
    fn test_tool_use_object_input_passes_through_unchanged() {
        let writer = GeminiWriter;
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "do_thing".to_string(),
                input: serde_json::json!({"city": "SF", "unit": "C"}),
                cache_control: None,
            }],
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let rwire = writer.write_response(&resp);
        let rargs = rwire
            .pointer("/candidates/0/content/parts/0/functionCall/args")
            .expect("functionCall.args must be present");
        assert_eq!(
            rargs,
            &serde_json::json!({"city": "SF", "unit": "C"}),
            "object input must pass through unchanged (no `args` wrapper): {rargs}"
        );
    }

    // ---- PF-H1: Gemini tool_choice (functionCallingConfig) round-trips ----

    fn gemini_read(body: serde_json::Value) -> crate::ir::IrRequest {
        GeminiReader
            .read_request(&body)
            .expect("gemini read_request")
    }

    #[test]
    fn tool_choice_any_required_roundtrips() {
        let ir = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY"}}
        }));
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out["toolConfig"]["functionCallingConfig"],
            serde_json::json!({"mode": "ANY"})
        );
    }

    #[test]
    fn tool_choice_specific_tool_roundtrips() {
        let ir = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig":
                {"mode": "ANY", "allowedFunctionNames": ["get_weather"]}}
        }));
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out["toolConfig"]["functionCallingConfig"],
            serde_json::json!({"mode": "ANY", "allowedFunctionNames": ["get_weather"]})
        );
    }

    /// Fix #10 (fidelity): `ANY` + `allowedFunctionNames` with N>1 names cannot be expressed by the
    /// IR's single-tool `Tool` variant. Rather than fabricating `Tool{name: first}` (inventing a
    /// stricter constraint the request never made), it must degrade to `Required` (call SOME tool) —
    /// a true superset of the allow-list. A SINGLE name still maps to `Tool{name}` (unchanged).
    #[test]
    fn tool_choice_multi_name_allowlist_relaxes_to_required() {
        let ir = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig":
                {"mode": "ANY", "allowedFunctionNames": ["get_weather", "get_time"]}}
        }));
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Required),
            "a multi-name allow-list must relax to Required, not Tool{{name: first}}"
        );

        // A single-name allow-list is still representable and must stay a targeted Tool.
        let ir_one = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig":
                {"mode": "ANY", "allowedFunctionNames": ["get_weather"]}}
        }));
        assert_eq!(
            ir_one.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );
    }

    #[test]
    fn tool_choice_none_and_auto_roundtrip() {
        for (mode, variant) in [
            ("AUTO", crate::ir::IrToolChoice::Auto),
            ("NONE", crate::ir::IrToolChoice::None),
        ] {
            let ir = gemini_read(serde_json::json!({
                "contents": [],
                "toolConfig": {"functionCallingConfig": {"mode": mode}}
            }));
            assert_eq!(ir.tool_choice, Some(variant));
            let writer = GeminiWriter;
            let out = writer.write_request(&ir);
            assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], mode);
        }
    }

    #[test]
    fn tool_choice_absent_emits_no_function_calling_config() {
        let ir = gemini_read(serde_json::json!({"contents": []}));
        assert_eq!(ir.tool_choice, None);
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        assert!(
            out.get("toolConfig")
                .and_then(|tc| tc.get("functionCallingConfig"))
                .is_none(),
            "absent tool_choice must NOT synthesize a functionCallingConfig"
        );
    }

    #[test]
    fn tool_choice_no_duplicate_function_calling_config() {
        // Same-protocol passthrough: the raw toolConfig is preserved in `extra` AND the writer
        // overlays a fresh functionCallingConfig — there must be exactly ONE in the output (the
        // overlay replaces, never duplicates).
        let ir = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY"}}
        }));
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        let s = serde_json::to_string(&out).unwrap();
        assert_eq!(
            s.matches("functionCallingConfig").count(),
            1,
            "exactly one functionCallingConfig must appear, got: {s}"
        );
    }

    // ---- PF-M2: Gemini finishReason mapping ----

    #[test]
    fn finish_reason_maps_gemini_only_reasons_to_canonical() {
        use crate::ir::IrStopReason as S;
        // The Gemini-only reasons map to canonical IR stop reasons (NOT a verbatim lowercase token).
        assert_eq!(
            map_gemini_finish_reason(GEMINI_FINISH_RECITATION),
            S::Safety
        );
        assert_eq!(map_gemini_finish_reason("IMAGE_SAFETY"), S::Safety);
        assert_eq!(map_gemini_finish_reason("SPII"), S::Safety);
        // A malformed function call is a FAILED generation with no runnable tool call — it maps to
        // `error`, NOT `tool_use` (which would tell the client to execute a call that doesn't exist).
        assert_eq!(
            map_gemini_finish_reason(GEMINI_FINISH_MALFORMED_FUNCTION_CALL),
            S::Error
        );
        // Unenumerated reasons map to `Other` (the writer projects it to the native OTHER member).
        assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_OTHER), S::Other);
        assert_eq!(map_gemini_finish_reason("LANGUAGE"), S::Other);
        // The direct ones still map.
        assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_STOP), S::EndTurn);
        assert_eq!(
            map_gemini_finish_reason(GEMINI_FINISH_MAX_TOKENS),
            S::MaxTokens
        );
        assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_SAFETY), S::Safety);
    }

    #[test]
    fn finish_reason_recitation_in_response_is_safety() {
        // End-to-end through read_response: a RECITATION finishReason surfaces as the canonical
        // `safety` stop_reason, which the Anthropic/OpenAI writers recognize.
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "x"}], "role": "model"},
                "finishReason": GEMINI_FINISH_RECITATION
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let resp = GeminiReader.read_response(&body).expect("read_response");
        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Safety));
    }

    /// End-to-end through read_response: a MALFORMED_FUNCTION_CALL finishReason surfaces as the
    /// canonical `error` stop_reason (a failed generation with no runnable tool call) — NOT `tool_use`.
    /// Guards that the read_response path actually routes through `map_gemini_finish_reason` (the unit
    /// test alone would not catch a read_response site that bypassed the mapping).
    #[test]
    fn finish_reason_malformed_function_call_in_response_is_error() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "x"}], "role": "model"},
                "finishReason": GEMINI_FINISH_MALFORMED_FUNCTION_CALL
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let resp = GeminiReader.read_response(&body).expect("read_response");
        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Error));
    }

    /// The STREAMING reader (read_response_events) routes finishReason through the SAME
    /// `map_gemini_finish_reason`, so a MALFORMED_FUNCTION_CALL terminal chunk must surface
    /// stop_reason=Error on the MessageDelta — guarding the stream call site, not just the unit fn.
    #[test]
    fn finish_reason_malformed_function_call_stream_is_error() {
        let chunks = vec![serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "x"}]},
                "finishReason": GEMINI_FINISH_MALFORMED_FUNCTION_CALL
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        })];
        let events = collect_stream(&chunks);
        let stop = events.iter().find_map(|e| match e {
            IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
            _ => None,
        });
        assert_eq!(
            stop,
            Some(Some(crate::ir::IrStopReason::Error)),
            "streamed MALFORMED_FUNCTION_CALL must terminate stop_reason=Error; got {events:?}"
        );
    }

    // ---- C4: context-length override is status-gated ----

    #[test]
    fn context_length_override_only_fires_on_400_or_413() {
        let token_body =
            br#"{"error":{"code":429,"message":"input is longer than the maximum number of tokens"}}"#;
        // A 429 with token-phrased body must NOT be reclassified to context_length_exceeded — the
        // breaker must still record the rate-limit fault.
        let err = GeminiReader.extract_error(StatusCode::TOO_MANY_REQUESTS, token_body);
        assert_ne!(
            err.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 429 with token-phrased body must NOT be mis-dispositioned as ContextLength (C4)"
        );
        // The same body on a real 400 IS the canonical context-length signal.
        let body_400 =
            br#"{"error":{"code":400,"message":"input is longer than the maximum number of tokens"}}"#;
        let err = GeminiReader.extract_error(StatusCode::BAD_REQUEST, body_400);
        assert_eq!(
            err.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 400 with the token-overflow message must classify as context_length_exceeded"
        );
        // ...and on a 413 as well.
        let err = GeminiReader.extract_error(StatusCode::PAYLOAD_TOO_LARGE, token_body);
        assert_eq!(
            err.provider_code.as_deref(),
            Some("context_length_exceeded")
        );
    }

    // ===================================================================================
    // Integration gaps — sampling / response_format / reasoning / cache / image / schema
    // (cross-protocol survival). Each test proves a read+write site round-trips a control
    // that previously degraded to the target default on the cross-protocol seam.
    // ===================================================================================

    /// Minimal IR request with a single user "hi" turn and all controls defaulted. Tests mutate the
    /// field(s) under test so the assertion targets exactly one gap.
    fn base_ir_request() -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        }
    }

    // --- Gap 1: sampling controls via generationConfig ---

    /// OpenAI→Gemini: an IR carrying frequency/presence penalties, seed, and n MUST emit them in
    /// Gemini's native generationConfig shape (frequencyPenalty/presencePenalty/seed/candidateCount).
    #[test]
    fn test_write_request_sampling_controls_emit_generation_config() {
        let mut req = base_ir_request();
        req.frequency_penalty = Some(0.5);
        req.presence_penalty = Some(-0.25);
        req.seed = Some(42);
        req.n = Some(3);
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&req)
        };
        let gc = wire
            .get("generationConfig")
            .expect("generationConfig must be emitted");
        assert_eq!(gc.get("frequencyPenalty"), Some(&serde_json::json!(0.5)));
        assert_eq!(gc.get("presencePenalty"), Some(&serde_json::json!(-0.25)));
        assert_eq!(gc.get("seed"), Some(&serde_json::json!(42)));
        assert_eq!(
            gc.get("candidateCount"),
            Some(&serde_json::json!(3)),
            "n maps to Gemini candidateCount: {wire}"
        );
    }

    /// None sampling controls emit NOTHING (no spurious zero penalties / seed on a plain request).
    #[test]
    fn test_write_request_sampling_controls_omitted_when_none() {
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&base_ir_request())
        };
        if let Some(gc) = wire.get("generationConfig") {
            assert!(gc.get("frequencyPenalty").is_none());
            assert!(gc.get("presencePenalty").is_none());
            assert!(gc.get("seed").is_none());
            assert!(gc.get("candidateCount").is_none());
        }
    }

    /// Gemini→IR: native generationConfig sampling controls promote into the typed IR fields, and a
    /// read→write round-trips them (same-protocol fidelity).
    #[test]
    fn test_read_request_sampling_controls_promote_and_round_trip() {
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {
                "frequencyPenalty": 0.7,
                "presencePenalty": 0.1,
                "seed": 99,
                "candidateCount": 2
            }
        });
        let ir = GeminiReader.read_request(&body).expect("read_request");
        assert_eq!(ir.frequency_penalty, Some(0.7));
        assert_eq!(ir.presence_penalty, Some(0.1));
        assert_eq!(ir.seed, Some(99));
        assert_eq!(ir.n, Some(2), "candidateCount promotes to IR n");

        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&ir)
        };
        let gc = wire.get("generationConfig").expect("generationConfig");
        assert_eq!(gc.get("frequencyPenalty"), Some(&serde_json::json!(0.7)));
        assert_eq!(gc.get("presencePenalty"), Some(&serde_json::json!(0.1)));
        assert_eq!(gc.get("seed"), Some(&serde_json::json!(99)));
        assert_eq!(gc.get("candidateCount"), Some(&serde_json::json!(2)));
    }

    // --- Gap 2 (M1): response_format ↔ responseSchema/responseMimeType ---

    /// Gemini→IR→Gemini: native responseMimeType + responseSchema read into the normalized IR
    /// response_format object and round-trip back into generationConfig.
    #[test]
    fn test_response_format_round_trips_native_gemini() {
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {
                "responseMimeType": MIME_APPLICATION_JSON,
                "responseSchema": {"type": "object", "properties": {"x": {"type": "string"}}}
            }
        });
        let ir = GeminiReader.read_request(&body).expect("read_request");
        let rf = ir
            .response_format
            .as_ref()
            .expect("response_format must be populated");
        assert!(
            rf.json,
            "application/json mime must read as a JSON directive"
        );
        assert!(rf.schema.is_some(), "responseSchema must be carried");

        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&ir)
        };
        let gc = wire.get("generationConfig").expect("generationConfig");
        assert_eq!(
            gc.get(FIELD_RESPONSE_MIME_TYPE),
            Some(&serde_json::json!("application/json")) // golden wire-contract literal (kept bare on purpose)
        );
        assert_eq!(
            gc.pointer("/responseSchema/properties/x/type"),
            Some(&serde_json::json!("string")),
            "responseSchema must round-trip: {wire}"
        );
    }

    /// A JSON structured-output directive (from any source protocol — here a typed IR carrying a
    /// schema) maps onto Gemini responseMimeType + responseSchema, with JSON-Schema keywords Gemini
    /// rejects (e.g. `$schema`) stripped by `sanitize_gemini_schema`.
    #[test]
    fn test_response_format_maps_to_gemini_and_sanitizes_schema() {
        let mut req = base_ir_request();
        req.response_format = Some(crate::ir::IrResponseFormat {
            json: true,
            schema: Some(serde_json::json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-07/schema#"
            })),
            name: None,
            strict: None,
            description: None,
        });
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&req)
        };
        let gc = wire.get("generationConfig").expect("generationConfig");
        assert_eq!(
            gc.get(FIELD_RESPONSE_MIME_TYPE),
            Some(&serde_json::json!("application/json")), // golden wire-contract literal (kept bare on purpose)
            "json_schema type maps to application/json: {wire}"
        );
        assert_eq!(
            gc.pointer("/responseSchema/type"),
            Some(&serde_json::json!("object"))
        );
        assert!(
            gc.pointer("/responseSchema/$schema").is_none(),
            "rejected JSON-Schema keyword $schema must be stripped from responseSchema: {wire}"
        );
    }

    // --- Gap 3 (H2): reasoning thought parts ↔ IrBlock::Thinking ---

    /// A Gemini response `thought:true` part with a `thoughtSignature` reads into IrBlock::Thinking
    /// (text + signature), and write_response re-emits it as a `{text, thought:true,
    /// thoughtSignature}` part — full round-trip with the signature preserved.
    #[test]
    fn test_thought_part_round_trips_through_ir_thinking() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [
                    {"text": "let me reason", "thought": true, "thoughtSignature": "sig-abc"},
                    {"text": "the answer"}
                ]},
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let resp = GeminiReader.read_response(&body).expect("read_response");
        // First block is Thinking with text + signature; second is plain Text.
        match &resp.content[0] {
            crate::ir::IrBlock::Thinking {
                text, signature, ..
            } => {
                assert_eq!(text, "let me reason");
                assert_eq!(signature.as_deref(), Some("sig-abc"));
            }
            other => panic!("expected Thinking block, got {other:?}"),
        }
        assert!(matches!(
            &resp.content[1],
            crate::ir::IrBlock::Text { text, .. } if text == "the answer"
        ));

        let wire = {
            let __w = GeminiWriter;
            __w.write_response(&resp)
        };
        let part0 = wire
            .pointer("/candidates/0/content/parts/0")
            .expect("first part");
        assert_eq!(part0.get("text"), Some(&serde_json::json!("let me reason")));
        assert_eq!(part0.get("thought"), Some(&serde_json::json!(true)));
        assert_eq!(
            part0.get("thoughtSignature"),
            Some(&serde_json::json!("sig-abc")),
            "thoughtSignature must round-trip: {wire}"
        );
    }

    /// A Thinking block in a REQUEST assistant turn round-trips through write_request as a thought
    /// part with its signature (cross-protocol reasoning survives into a Gemini request).
    #[test]
    fn test_thinking_block_round_trips_in_write_request() {
        let mut req = base_ir_request();
        req.messages.push(crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Thinking {
                text: "thinking...".to_string(),
                signature: Some("sig-1".to_string()),
                redacted: false,
                cache_control: None,
            }],
        });
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&req)
        };
        // Assistant turn is the 2nd contents entry (role "model").
        let parts = wire
            .pointer("/contents/1/parts")
            .and_then(|p| p.as_array())
            .expect("model parts");
        let thought = &parts[0];
        assert_eq!(thought.get("text"), Some(&serde_json::json!("thinking...")));
        assert_eq!(thought.get("thought"), Some(&serde_json::json!(true)));
        assert_eq!(
            thought.get("thoughtSignature"),
            Some(&serde_json::json!("sig-1")),
            "request-side thought signature must round-trip: {wire}"
        );
    }

    // --- Gap 4 (H6): cachedContentTokenCount → cache_read_input_tokens ---

    /// Gemini usageMetadata.cachedContentTokenCount maps into the IR cache_read_input_tokens field
    /// (the same field Bedrock/Anthropic cache-read map to), surviving the cross-protocol seam.
    #[test]
    fn test_cached_content_token_count_reads_into_cache_read() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 5,
                "cachedContentTokenCount": 80
            }
        });
        let resp = GeminiReader.read_response(&body).expect("read_response");
        assert_eq!(
            resp.usage.cache_read_input_tokens,
            Some(80),
            "cachedContentTokenCount must map to cache_read_input_tokens"
        );
        // Absent cache count stays None.
        let body_no_cache = serde_json::json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": GEMINI_FINISH_STOP}],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let resp2 = GeminiReader
            .read_response(&body_no_cache)
            .expect("read_response");
        assert_eq!(resp2.usage.cache_read_input_tokens, None);
    }

    // --- Gap 5 (L1): fileData reads into the typed Url source ---

    /// A Gemini `fileData` part (with or without a mimeType) is a remote URL reference → reads into
    /// the typed `Url` source and re-emits as `fileData{fileUri}`. The optional `mimeType` hint is not
    /// carried on this path; that is operationally lossless — Gemini's `fileData.mimeType` is optional
    /// (inferred from the URI), so the backend accepts the part and a native client is unaffected.
    #[test]
    fn test_file_data_reads_into_url_source_and_round_trips() {
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [
                {"fileData": {"fileUri": "gs://bucket/img.png", "mimeType": "image/png"}}
            ]}]
        });
        let ir = GeminiReader.read_request(&body).expect("read_request");
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(url),
                ..
            } => assert_eq!(url, "gs://bucket/img.png"),
            other => panic!("expected Image(Url), got {other:?}"),
        }
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&ir)
        };
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri"),
            Some(&serde_json::json!("gs://bucket/img.png")),
            "fileUri must round-trip as a fileData reference: {wire}"
        );
    }

    /// Regression guard: a fileData WITHOUT a mimeType (bare remote URI) still falls back to the
    /// image_url sentinel and re-emits as fileData{fileUri} (no spurious mimeType).
    #[test]
    fn test_file_data_without_mime_type_uses_sentinel() {
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"fileData": {"fileUri": "https://x/i.jpg"}}]}]
        });
        let ir = GeminiReader.read_request(&body).expect("read_request");
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(url),
                ..
            } => {
                assert_eq!(url, "https://x/i.jpg");
            }
            other => panic!("expected Image, got {other:?}"),
        }
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&ir)
        };
        assert_eq!(
            wire.pointer("/contents/0/parts/0/fileData/fileUri"),
            Some(&serde_json::json!("https://x/i.jpg"))
        );
        assert!(
            wire.pointer("/contents/0/parts/0/fileData/mimeType")
                .is_none(),
            "sentinel image must not gain a bogus mimeType: {wire}"
        );
    }

    // --- Gap 6 (L3): tool input_schema strips Gemini-rejected JSON-Schema keywords ---

    /// A cross-protocol tool def carrying JSON-Schema keywords Gemini 400-rejects ($schema,
    /// additionalProperties, $ref, …) must be stripped on write so the tool def survives instead of
    /// hard-failing — recursively, including nested object/array schemas.
    #[test]
    fn test_write_request_strips_rejected_schema_keywords() {
        let mut req = base_ir_request();
        req.tools.push(crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: Some("w".to_string()),
            input_schema: serde_json::json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "loc": {"type": "string"},
                    "nested": {
                        "type": "object",
                        "additionalProperties": true,
                        "properties": {"$ref": {"type": "string"}}
                    }
                },
                "required": ["loc"]
            }),
            cache_control: None,
        });
        let wire = {
            let __w = GeminiWriter;
            __w.write_request(&req)
        };
        let params = wire
            .pointer("/tools/0/functionDeclarations/0/parameters")
            .expect("parameters");
        assert!(
            params.get("$schema").is_none(),
            "$schema must be stripped: {wire}"
        );
        assert!(
            params.get("additionalProperties").is_none(),
            "top-level additionalProperties must be stripped: {wire}"
        );
        // Survivors preserved.
        assert_eq!(params.get("type"), Some(&serde_json::json!("object")));
        assert_eq!(params.get("required"), Some(&serde_json::json!(["loc"])));
        assert_eq!(
            params.pointer("/properties/loc/type"),
            Some(&serde_json::json!("string"))
        );
        // Recursion: nested additionalProperties stripped, nested properties kept.
        assert!(
            params
                .pointer("/properties/nested/additionalProperties")
                .is_none(),
            "nested additionalProperties must be stripped recursively: {wire}"
        );
        assert_eq!(
            params.pointer("/properties/nested/type"),
            Some(&serde_json::json!("object"))
        );
    }

    /// `sanitize_gemini_schema` leaves a clean Gemini-native schema untouched and walks arrays.
    #[test]
    fn test_sanitize_gemini_schema_preserves_clean_and_walks_arrays() {
        let clean = serde_json::json!({
            "type": "object",
            "anyOf": [{"type": "string"}, {"type": "number", "$comment": "drop me"}]
        });
        let out = sanitize_gemini_schema(&clean);
        assert_eq!(out.get("type"), Some(&serde_json::json!("object")));
        assert_eq!(
            out.pointer("/anyOf/0/type"),
            Some(&serde_json::json!("string"))
        );
        assert!(
            out.pointer("/anyOf/1/$comment").is_none(),
            "rejected keyword in an array element must be stripped: {out}"
        );
        assert_eq!(
            out.pointer("/anyOf/1/type"),
            Some(&serde_json::json!("number"))
        );
    }

    /// D4: the Gemini stream WRITE path must emit a streamed reasoning part for a `ThinkingDelta`
    /// (`{text, thought:true}`) and carry the signature for a `SignatureDelta`
    /// (`{thought:true, thoughtSignature}`), mirroring the non-stream `write_response` thinking shape.
    /// Previously both returned None, silently dropping a cross-protocol reasoning stream.
    #[test]
    fn test_stream_thinking_and_signature_deltas_emit_thought_parts() {
        let writer = GeminiWriter;

        // ThinkingDelta → a `thought:true` text part on a candidates chunk.
        let think = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::ThinkingDelta("let me reason".to_string()),
            })
            .expect("a ThinkingDelta must emit a streamed thought chunk, not None");
        let think_part = think
            .1
            .pointer("/candidates/0/content/parts/0")
            .expect("thought chunk must carry a part");
        assert_eq!(
            think_part.pointer("/text").and_then(|t| t.as_str()),
            Some("let me reason"),
            "streamed thought part must carry the reasoning text: {think_part}"
        );
        assert_eq!(
            think_part.pointer("/thought"),
            Some(&serde_json::json!(true)),
            "streamed thought part must be flagged thought:true: {think_part}"
        );

        // SignatureDelta → a `thought:true` part bearing the opaque `thoughtSignature`.
        let sig = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::SignatureDelta("sig-xyz".to_string()),
            })
            .expect("a SignatureDelta must emit a streamed thought chunk, not None");
        let sig_part = sig
            .1
            .pointer("/candidates/0/content/parts/0")
            .expect("signature chunk must carry a part");
        assert_eq!(
            sig_part
                .pointer("/thoughtSignature")
                .and_then(|s| s.as_str()),
            Some("sig-xyz"),
            "streamed signature part must carry the thoughtSignature: {sig_part}"
        );
        assert_eq!(
            sig_part.pointer("/thought"),
            Some(&serde_json::json!(true)),
            "streamed signature part must be flagged thought:true: {sig_part}"
        );
    }

    /// L2: a Gemini response carrying `candidates[].citationMetadata.citationSources[]` must read
    /// into IrCitation(s) on the answer's Text block (url/title/indices preserved), and a CROSS-
    /// protocol Anthropic egress must re-emit them as `web_search_result_location` citations carrying
    /// the url/title — closing the grounding-citation gap that previously dropped them entirely.
    #[test]
    fn gemini_citation_metadata_reads_and_projects_to_anthropic() {
        let reader = GeminiReader;
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "The sky is blue."}]
                },
                "citationMetadata": {
                    "citationSources": [
                        {
                            "startIndex": 0,
                            "endIndex": 15,
                            "uri": "https://example.com/sky",
                            "title": "Why the sky is blue",
                            "license": ""
                        }
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 4,
                "totalTokenCount": 9
            }
        });
        let ir = reader.read_response(&body).expect("read_response");
        // Citations land on the Text block with neutral fields populated.
        let citations = ir
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::Text { citations, .. } if !citations.is_empty() => {
                    Some(citations)
                }
                _ => None,
            })
            .expect("citations must be attached to the Text block");
        assert_eq!(citations.len(), 1);
        assert_eq!(citations[0].url.as_deref(), Some("https://example.com/sky"));
        assert_eq!(citations[0].title.as_deref(), Some("Why the sky is blue"));
        assert_eq!(citations[0].start_index, Some(0));
        assert_eq!(citations[0].end_index, Some(15));

        // Cross-protocol Anthropic egress carries url + title.
        let aw = crate::proto::anthropic::AnthropicWriter;
        let wire = aw.write_response(&ir);
        let c = wire
            .pointer("/content")
            .and_then(|c| c.as_array())
            .and_then(|blocks| blocks.iter().find_map(|b| b.pointer("/citations/0")))
            .expect("Anthropic egress must carry the citation");
        assert_eq!(
            c.get("type").and_then(|v| v.as_str()),
            Some("web_search_result_location")
        );
        assert_eq!(
            c.get("url").and_then(|v| v.as_str()),
            Some("https://example.com/sky")
        );
        assert_eq!(
            c.get("title").and_then(|v| v.as_str()),
            Some("Why the sky is blue")
        );
    }

    /// L2: same-protocol Gemini→IR→Gemini citation round-trip re-emits candidate-level
    /// citationMetadata (verbatim source via `raw`), and a response WITHOUT citations stays free of a
    /// `citationMetadata` key.
    #[test]
    fn gemini_citations_roundtrip_and_absent_unaffected() {
        let reader = GeminiReader;
        let writer = GeminiWriter;
        let body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Answer."}]},
                "citationMetadata": {
                    "citationSources": [
                        {"startIndex": 1, "endIndex": 7, "uri": "https://src/x", "title": "X"}
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
        });
        let mut ir = reader.read_response(&body).expect("read_response");
        // Force the cross-protocol boundary signal so the Gemini writer runs the full egress path.
        ir.created = Some(1);
        let wire = writer.write_response(&ir);
        let src = wire
            .pointer("/candidates/0/citationMetadata/citationSources/0")
            .expect("citationMetadata re-emitted at candidate level");
        assert_eq!(
            src.get("uri").and_then(|v| v.as_str()),
            Some("https://src/x")
        );
        assert_eq!(src.get("startIndex").and_then(|v| v.as_i64()), Some(1));

        // No citations → no citationMetadata key.
        let plain_body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Plain."}]},
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
        });
        let mut plain_ir = reader.read_response(&plain_body).expect("read_response");
        plain_ir.created = Some(1);
        let plain_wire = writer.write_response(&plain_ir);
        assert!(
            plain_wire
                .pointer("/candidates/0/citationMetadata")
                .is_none(),
            "no citationMetadata for a citation-free response; got {plain_wire}"
        );
    }

    /// L2-5 STREAMING citations, cross-protocol: a Gemini stream chunk carrying candidate-level
    /// `citationMetadata.citationSources[]` must read into an `IrDelta::CitationsDelta` on the answer
    /// text block, and a cross-protocol Anthropic egress must re-emit it as a native
    /// `content_block_delta`/`citations_delta` event carrying the url/title — closing the streaming
    /// grounding-citation gap that previously dropped the citation entirely.
    #[test]
    fn stream_gemini_citation_metadata_projects_to_anthropic_citations_delta() {
        // Gemini delivers citations on a (late) chunk, here alongside the finishReason.
        let events = collect_stream(&[
            serde_json::json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "The sky is blue."}]}
                }]
            }),
            serde_json::json!({
                "candidates": [{
                    "citationMetadata": {
                        "citationSources": [
                            {
                                "startIndex": 0,
                                "endIndex": 15,
                                "uri": "https://example.com/sky",
                                "title": "Why the sky is blue"
                            }
                        ]
                    },
                    "finishReason": GEMINI_FINISH_STOP
                }],
                "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 4}
            }),
        ]);

        // A CitationsDelta lands on the answer text block, neutral fields populated.
        let (cite_idx, citations) = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    index,
                    delta: crate::ir::IrDelta::CitationsDelta(cs),
                } if !cs.is_empty() => Some((*index, cs.clone())),
                _ => None,
            })
            .expect("a CitationsDelta must be emitted for a streamed Gemini citation");
        assert_eq!(citations.len(), 1);
        assert_eq!(citations[0].url.as_deref(), Some("https://example.com/sky"));
        assert_eq!(citations[0].title.as_deref(), Some("Why the sky is blue"));
        assert_eq!(citations[0].start_index, Some(0));
        assert_eq!(citations[0].end_index, Some(15));

        // The citation block index must be opened by a BlockStart and closed by a BlockStop —
        // the stream stays balanced.
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart { index, .. } if *index == cite_idx
            )),
            "citation block must be opened: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStop { index } if *index == cite_idx
            )),
            "citation block must be closed: {events:?}"
        );

        // Cross-protocol Anthropic egress: the CitationsDelta becomes a native
        // content_block_delta/citations_delta carrying the synthesized Anthropic citation.
        let aw = crate::proto::anthropic::AnthropicWriter;
        let delta_ev = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::CitationsDelta(_),
                    ..
                } => aw.write_response_event(e),
                _ => None,
            })
            .expect("Anthropic writer must emit a frame for the CitationsDelta");
        assert_eq!(delta_ev.0, "content_block_delta");
        // One citation → a single citations_delta body (not an array).
        let citation = delta_ev
            .1
            .pointer("/delta/citation")
            .expect("body must carry delta.citation");
        assert_eq!(
            delta_ev.1.pointer("/delta/type").and_then(|t| t.as_str()),
            Some("citations_delta")
        );
        assert_eq!(
            citation.get("type").and_then(|v| v.as_str()),
            Some("web_search_result_location")
        );
        assert_eq!(
            citation.get("url").and_then(|v| v.as_str()),
            Some("https://example.com/sky")
        );
        assert_eq!(
            citation.get("title").and_then(|v| v.as_str()),
            Some("Why the sky is blue")
        );
    }

    /// L2-5 STREAMING citations, reverse direction: an `IrDelta::CitationsDelta` (as an Anthropic
    /// stream reader would produce) must project onto a native Gemini `citationMetadata.citationSources`
    /// chunk when written by the Gemini writer — and the shape-gate must REBUILD the Gemini source from
    /// the neutral fields rather than leak the foreign Anthropic `raw` through.
    #[test]
    fn stream_anthropic_citation_projects_to_gemini_citation_metadata() {
        let writer = GeminiWriter;
        // A CitationsDelta whose `raw` is an ANTHROPIC-shaped object (a Gemini→Anthropic would never
        // produce this; here we model the Anthropic→Gemini direction). The Gemini writer must NOT
        // emit the Anthropic `raw` verbatim — it has no Gemini uri/index keys — and must synthesize
        // a Gemini source from the neutral fields instead.
        let cit = crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title: Some("Doc Title".to_string()),
            url: Some("https://anthropic.example/doc".to_string()),
            document_index: None,
            start_index: Some(3),
            end_index: Some(9),
            encrypted_index: Some("enc-xyz".to_string()),
            raw: Some(serde_json::json!({
                "type": "web_search_result_location",
                "url": "https://anthropic.example/doc",
                "title": "Doc Title",
                "encrypted_index": "enc-xyz"
            })),
        };
        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::CitationsDelta(vec![cit]),
        };
        let (_, body) = writer
            .write_response_event(&ev)
            .expect("Gemini writer must emit a citationMetadata chunk for a CitationsDelta");
        let src = body
            .pointer("/candidates/0/citationMetadata/citationSources/0")
            .expect("chunk must carry candidate-level citationSources");
        // Synthesized from neutral fields — NOT the Anthropic raw (which has no `uri`).
        assert_eq!(
            src.get("uri").and_then(|v| v.as_str()),
            Some("https://anthropic.example/doc")
        );
        assert_eq!(src.get("title").and_then(|v| v.as_str()), Some("Doc Title"));
        assert_eq!(src.get("startIndex").and_then(|v| v.as_i64()), Some(3));
        assert_eq!(src.get("endIndex").and_then(|v| v.as_i64()), Some(9));
        // The foreign Anthropic `type` tag must NOT leak into the Gemini source.
        assert!(
            src.get("type").is_none(),
            "Anthropic `raw` must not leak through the Gemini writer: {src}"
        );
    }

    /// L2-5: a Gemini stream with NO citations must be unaffected — no `CitationsDelta` is produced,
    /// and the block balance is unchanged.
    #[test]
    fn stream_gemini_no_citations_unaffected() {
        let events = collect_stream(&[serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Plain answer."}]},
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
        })]);
        assert!(
            !events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::CitationsDelta(_),
                    ..
                }
            )),
            "a citation-free stream must not produce a CitationsDelta: {events:?}"
        );
        let starts = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
        let stops = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count();
        assert_eq!(starts, stops, "unbalanced block events: {events:?}");
    }

    /// Each `IrToolChoice` variant must round-trip through Gemini's native
    /// `toolConfig.functionCallingConfig` shape (the tool-selection directive is a headline
    /// cross-protocol control — ir.rs:82): AUTO↔Auto, NONE↔None, ANY↔Required, and
    /// ANY+allowedFunctionNames:[n]↔Tool{n}. A dropped/degraded directive silently reverts forced tool
    /// use to the target's default on the seam.
    #[test]
    fn tool_choice_variants_round_trip_via_function_calling_config() {
        let cases = [
            (crate::ir::IrToolChoice::Auto, "AUTO", None),
            (crate::ir::IrToolChoice::None, "NONE", None),
            (crate::ir::IrToolChoice::Required, "ANY", None),
            (
                crate::ir::IrToolChoice::Tool {
                    name: "get_weather".to_string(),
                },
                "ANY",
                Some("get_weather"),
            ),
        ];
        for (variant, expect_mode, expect_name) in cases {
            // WRITE: the union projects to the native functionCallingConfig object.
            let wire = write_gemini_tool_choice(&variant);
            assert_eq!(
                wire.pointer("/mode").and_then(|m| m.as_str()),
                Some(expect_mode),
                "mode mismatch for {variant:?}"
            );
            if let Some(name) = expect_name {
                assert_eq!(
                    wire.pointer("/allowedFunctionNames/0")
                        .and_then(|n| n.as_str()),
                    Some(name)
                );
            } else {
                assert!(
                    wire.get("allowedFunctionNames").is_none(),
                    "no allowedFunctionNames expected for {variant:?}"
                );
            }
            // READ back through the native toolConfig shape reproduces the same union.
            let tool_config = serde_json::json!({"functionCallingConfig": wire});
            assert_eq!(
                read_gemini_tool_choice(Some(&tool_config)),
                Some(variant.clone()),
                "round-trip failed for {variant:?}"
            );
        }
    }

    /// A multi-name `allowedFunctionNames` (a SUBSET restriction the IR cannot express) must relax to
    /// `Required` (call SOME tool — a true superset), NOT fabricate a stricter single-tool constraint
    /// the request never made.
    #[test]
    fn tool_choice_multi_allowed_names_relaxes_to_required() {
        let tool_config = serde_json::json!({
            "functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["a", "b"]}
        });
        assert_eq!(
            read_gemini_tool_choice(Some(&tool_config)),
            Some(crate::ir::IrToolChoice::Required),
            "a 2-name allow-list has no IR analog; must degrade to Required, not Tool{{first}}"
        );
    }

    /// An UNKNOWN native `finishReason` (a future/novel Gemini token) maps to `IrStopReason::Other`
    /// (ir.rs:186 — no String payload), and on egress `Other` degrades to the honest native `OTHER`
    /// enum member, never an off-spec upper-cased token a strict client rejects.
    #[test]
    fn unknown_finish_reason_maps_to_other_and_writes_native_other() {
        assert_eq!(
            map_gemini_finish_reason("SOME_FUTURE_REASON"),
            crate::ir::IrStopReason::Other
        );
        // Egress: Other -> the valid native OTHER member.
        assert_eq!(
            write_gemini_stop_reason(crate::ir::IrStopReason::Other),
            GEMINI_FINISH_OTHER
        );
        // MALFORMED_FUNCTION_CALL is a modeled abnormal stop -> Error (not Other).
        assert_eq!(
            map_gemini_finish_reason(GEMINI_FINISH_MALFORMED_FUNCTION_CALL),
            crate::ir::IrStopReason::Error
        );
    }

    /// cachedContentTokenCount NORMALIZATION, WRITE side (the read side is covered by
    /// `test_cached_content_token_count_reads_into_cache_read`): the IR stores UNCACHED input, so the
    /// writer must ADD the cached prefix BACK to re-derive Gemini's TOTAL `promptTokenCount` and
    /// re-emit `cachedContentTokenCount`. Pins the inverse of the read normalization (ir.rs:457).
    #[test]
    fn write_response_reconstructs_prompt_token_count_with_cached() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: crate::ir::IrUsage {
                input_tokens: 20,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: Some(80),
            },
            model: Some("gemini-2.0-flash".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = {
            let w = GeminiWriter;
            w.write_response(&resp)
        };
        let um = out.get("usageMetadata").expect("usageMetadata present");
        assert_eq!(
            um.get(FIELD_PROMPT_TOKEN_COUNT),
            Some(&serde_json::json!(100)),
            "promptTokenCount must re-add cached: uncached(20) + cached(80) = 100"
        );
        assert_eq!(
            um.get(FIELD_CACHED_CONTENT_TOKEN_COUNT),
            Some(&serde_json::json!(80))
        );
        assert_eq!(
            um.get(FIELD_CANDIDATES_TOKEN_COUNT),
            Some(&serde_json::json!(5))
        );
        // totalTokenCount is emitted (model present -> cross-protocol boundary signal): 100 + 5.
        assert_eq!(
            um.get(FIELD_TOTAL_TOKEN_COUNT),
            Some(&serde_json::json!(105))
        );
    }

    /// A system prompt must survive read→IR→write: Gemini's `systemInstruction.parts[]` reads into
    /// `IrRequest.system` and writes back to the same native container (the system prompt is a headline
    /// cross-protocol feature).
    #[test]
    fn system_instruction_round_trips_through_ir_system() {
        let body = serde_json::json!({
            "systemInstruction": {"parts": [{"text": "You are terse."}]},
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let ir = GeminiReader.read_request(&body).expect("read_request");
        assert_eq!(
            ir.system.len(),
            1,
            "systemInstruction must feed IrRequest.system"
        );
        match &ir.system[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "You are terse."),
            other => panic!("expected a Text system block, got {other:?}"),
        }
        // WRITE re-emits the native systemInstruction.parts[] container.
        let out = {
            let w = GeminiWriter;
            w.write_request(&ir)
        };
        assert_eq!(
            out.pointer("/systemInstruction/parts/0/text")
                .and_then(|t| t.as_str()),
            Some("You are terse."),
            "IrRequest.system must write back to systemInstruction.parts[]"
        );
    }
}

#[cfg(test)]
mod logprobs_carry_tests {
    //! Cross-protocol logprobs (OpenAI<->Gemini): the ask (request) and the data (response,
    //! buffered AND streaming) must cross the seam in both directions via the neutral IR.
    use crate::proto::Protocol;

    fn gemini_body_with_logprobs() -> serde_json::Value {
        serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hi"}]},
                "finishReason": "STOP",
                "logprobsResult": {
                    "chosenCandidates": [
                        {"token": "Hi", "logProbability": -0.031},
                        {"token": "!", "logProbability": -0.87}
                    ],
                    "topCandidates": [
                        {"candidates": [
                            {"token": "Hi", "logProbability": -0.031},
                            {"token": "Hello", "logProbability": -3.5}
                        ]},
                        {"candidates": [
                            {"token": "!", "logProbability": -0.87},
                            {"token": ".", "logProbability": -1.2}
                        ]}
                    ]
                }
            }],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2}
        })
    }

    /// Gemini backend -> OpenAI caller (buffered): `logprobsResult` becomes
    /// `choices[0].logprobs.content[]`, chosen+top zipped, bytes synthesized from UTF-8.
    #[test]
    fn gemini_logprobs_reach_openai_caller() {
        let ir = Protocol::gemini()
            .reader()
            .read_response(&gemini_body_with_logprobs())
            .expect("parses");
        assert_eq!(ir.logprobs.len(), 2);
        assert_eq!(ir.logprobs[0].token, "Hi");
        assert_eq!(ir.logprobs[0].top.len(), 2);

        let out = Protocol::openai().writer().write_response(&ir);
        let content = &out["choices"][0]["logprobs"]["content"];
        assert_eq!(content[0]["token"], "Hi");
        assert_eq!(content[0]["logprob"], -0.031);
        assert_eq!(content[0]["bytes"], serde_json::json!([72, 105])); // "Hi" UTF-8
        assert_eq!(content[0]["top_logprobs"][1]["token"], "Hello");
        assert_eq!(content[1]["token"], "!");
    }

    /// OpenAI backend -> Gemini caller (buffered): `choices[0].logprobs.content[]` becomes
    /// `candidates[0].logprobsResult` with parallel chosen/top arrays.
    #[test]
    fn openai_logprobs_reach_gemini_caller() {
        let body = serde_json::json!({
            "id": "chatcmpl-x", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hi"},
                "logprobs": {"content": [
                    {"token": "Hi", "logprob": -0.05, "bytes": [72, 105],
                     "top_logprobs": [{"token": "Hi", "logprob": -0.05, "bytes": [72, 105]}]}
                ]},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1}
        });
        let ir = Protocol::openai()
            .reader()
            .read_response(&body)
            .expect("parses");
        assert_eq!(ir.logprobs.len(), 1);
        assert_eq!(ir.logprobs[0].bytes.as_deref(), Some(&[72u8, 105][..]));

        let out = Protocol::gemini().writer().write_response(&ir);
        let lr = &out["candidates"][0]["logprobsResult"];
        assert_eq!(lr["chosenCandidates"][0]["token"], "Hi");
        assert_eq!(lr["chosenCandidates"][0]["logProbability"], -0.05);
        assert_eq!(lr["topCandidates"][0]["candidates"][0]["token"], "Hi");
    }

    /// A response WITHOUT logprobs gains nothing on translation in either direction.
    #[test]
    fn absence_gains_nothing() {
        let mut body = gemini_body_with_logprobs();
        body["candidates"][0]
            .as_object_mut()
            .unwrap()
            .remove("logprobsResult");
        let ir = Protocol::gemini().reader().read_response(&body).unwrap();
        assert!(ir.logprobs.is_empty());
        let out = Protocol::openai().writer().write_response(&ir);
        assert!(
            out["choices"][0].get("logprobs").is_none(),
            "no logprobs from the backend -> no logprobs key emitted: {out}"
        );
    }

    /// STREAMING, Gemini backend -> OpenAI caller: a chunk's `logprobsResult` becomes an OpenAI
    /// chunk carrying `choices[0].logprobs.content[]` (alongside the text delta's own chunk).
    #[test]
    fn gemini_stream_logprobs_reach_openai_caller() {
        let chunk = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hi"}]},
                "logprobsResult": {
                    "chosenCandidates": [{"token": "Hi", "logProbability": -0.031}]
                }
            }]
        });
        let mut state = crate::ir::StreamDecodeState::default();
        let events = Protocol::gemini()
            .reader()
            .read_response_events("", &chunk, &mut state);
        let lp_event = events
            .iter()
            .find(|e| {
                matches!(
                    e,
                    crate::ir::IrStreamEvent::BlockDelta {
                        delta: crate::ir::IrDelta::LogprobsDelta(_),
                        ..
                    }
                )
            })
            .expect("a LogprobsDelta must be decoded from the chunk");

        let openai = Protocol::openai();
        let (_, frame) = openai
            .writer()
            .write_response_event(lp_event)
            .expect("openai writer must emit a logprobs chunk");
        assert_eq!(frame["choices"][0]["logprobs"]["content"][0]["token"], "Hi");
        assert_eq!(frame["choices"][0]["delta"], serde_json::json!({}));
    }

    /// STREAMING, OpenAI backend -> Gemini caller: a chunk's `choices[0].logprobs` becomes a
    /// Gemini chunk candidate carrying `logprobsResult`.
    #[test]
    fn openai_stream_logprobs_reach_gemini_caller() {
        let chunk = serde_json::json!({
            "id": "chatcmpl-x", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "choices": [{
                "index": 0,
                "delta": {"content": "Hi"},
                "logprobs": {"content": [{"token": "Hi", "logprob": -0.05}]},
                "finish_reason": null
            }]
        });
        let mut state = crate::ir::StreamDecodeState::default();
        let events = Protocol::openai()
            .reader()
            .read_response_events("", &chunk, &mut state);
        let lp_event = events
            .iter()
            .find(|e| {
                matches!(
                    e,
                    crate::ir::IrStreamEvent::BlockDelta {
                        delta: crate::ir::IrDelta::LogprobsDelta(_),
                        ..
                    }
                )
            })
            .expect("a LogprobsDelta must be decoded from the chunk");

        let gemini = Protocol::gemini();
        let (_, frame) = gemini
            .writer()
            .write_response_event(lp_event)
            .expect("gemini writer must emit a logprobsResult chunk");
        assert_eq!(
            frame["candidates"][0]["logprobsResult"]["chosenCandidates"][0]["token"],
            "Hi"
        );
    }
}
