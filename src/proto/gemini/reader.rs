use super::*;

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
                    Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
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
        // client (proxy engine `auth_failure_status_and_kind`), never this raw value — it is consumed
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
                provider_signal: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
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
        // because `proxy::strip_router_shim_keys` now runs UNCONDITIONALLY (same- AND cross-protocol)
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
        // hung/non-terminated stream while the breaker/observability never see it. proxy engine only
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
                                        if let Some(sig) =
                                            part.get("thoughtSignature").and_then(|v| v.as_str())
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
                                    let ti =
                                        state.text_index.unwrap_or(offset + state.open_tools.len());
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
                // Offset by the thinking slot (index 0) when a reasoning block is open, exactly
                // like the text-part arm — otherwise a citation/logprobs delta arriving before the
                // first answer-text part opens a text block at index 0, colliding with the
                // thinking block and corrupting cross-protocol block-index mapping.
                let offset = usize::from(state.reasoning_seen);
                let ti = state.text_index.unwrap_or(offset + state.open_tools.len());
                if !state.text_block_open {
                    // Close a still-open thinking block first (the text-part arm does this too);
                    // otherwise two blocks are open at once and the downstream translator sees an
                    // invariant violation.
                    if state.thinking_block_open {
                        state.thinking_block_open = false;
                        out.push(IrStreamEvent::BlockStop { index: 0 });
                    }
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
                // Offset by the thinking slot (index 0) when a reasoning block is open, exactly
                // like the text-part arm — otherwise a citation/logprobs delta arriving before the
                // first answer-text part opens a text block at index 0, colliding with the
                // thinking block and corrupting cross-protocol block-index mapping.
                let offset = usize::from(state.reasoning_seen);
                let ti = state.text_index.unwrap_or(offset + state.open_tools.len());
                if !state.text_block_open {
                    // Close a still-open thinking block first (the text-part arm does this too);
                    // otherwise two blocks are open at once and the downstream translator sees an
                    // invariant violation.
                    if state.thinking_block_open {
                        state.thinking_block_open = false;
                        out.push(IrStreamEvent::BlockStop { index: 0 });
                    }
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
