use super::*;

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
                        hosted: None,
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
                        // Populate the model when the frame carries one (forward-compat / compatible
                        // backends) rather than hardcoding None so a cross-protocol ingress can surface
                        // it; native Cohere omits it here, in which case this stays None.
                        model: data
                            .get("model")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from),
                    });
                }
            }
            // Guard on `!text_block_closed`: once the text block has been closed (content-end or a
            // leading tool-plan's tool-call-start), a later text frame must NOT reopen it. A failed
            // guard falls through to the `other` no-op arm and is dropped, keeping the egress balanced
            // (no second content_block_start / delta into a stopped index). (1.4.0 audit, translation.)
            ET_CONTENT_START if !state.text_block_closed => {
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
            ET_CONTENT_DELTA if !state.text_block_closed => {
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
            // Cohere v2 streams the assistant's pre-tool-call reasoning as `tool-plan-delta`
            // frames (one token each at `delta.message.tool_plan`) that PRECEDE the
            // `tool-call-start` frames — the streamed counterpart of the non-stream reader's
            // `message.tool_plan` fold (audit H4). Without reading it here, a STREAMING Cohere→X hop
            // still lost that reasoning while the non-stream hop preserved it (audit finding #7).
            // Map the plan onto the SAME leading Text block a `content-delta` would open (via the
            // dynamic `cohere_text_ir_index` seam): it claims IR index 0 by first appearance, and the
            // following `tool-call-start` offsets to 1+, mirroring the non-stream case where the plan
            // is a leading Text ahead of the tool calls. Like a normal streamed Text this Text carries
            // no marker distinguishing it FROM a plain content Text — the IR has no tool_plan flag — so
            // a downstream Cohere writer re-emits it as `content`, not `tool_plan` (documented in the
            // writer; the reasoning survives, its native `tool_plan` slot does not).
            ET_TOOL_PLAN_DELTA if !state.text_block_closed => {
                let text_idx = cohere_text_ir_index(state);
                if !state.text_block_open {
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: text_idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
                if let Some(text) = data
                    .get("delta")
                    .and_then(|d| d.get("message"))
                    .and_then(|m| m.get("tool_plan"))
                    .and_then(|p| p.as_str())
                    .filter(|s| !s.is_empty())
                {
                    out.push(IrStreamEvent::BlockDelta {
                        index: text_idx,
                        delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                    });
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
                // stream's lifetime): keeping the claimed index immutable means a tool opened after
                // content-end still derives its base off the persistent TEXT_BLOCK_SEEN_SENTINEL, so it
                // cannot collide with the text index. `text_block_closed` latches here so a stray text
                // frame after the close is dropped rather than reopening the (now stopped) index.
                if state.text_block_open {
                    state.text_block_open = false;
                    state.text_block_closed = true;
                    let ti = state.text_index.unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
            }
            ET_MESSAGE_END => {
                // A stream that ends with the leading tool-plan / content text block still OPEN (no
                // content-end and no tool-call-start closed it first — a truncated or adversarial
                // upstream) would leave a dangling `content_block_start` with no matching stop on an
                // Anthropic egress (an unbalanced stream / proxy-signature tell). Force-close it here,
                // before the terminal frames, at the index it CLAIMED — so the egress stream is always
                // balanced regardless of upstream truncation. (1.4.0 audit, translation.)
                if state.text_block_open {
                    state.text_block_open = false;
                    state.text_block_closed = true;
                    let ti = state.text_index.unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
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
                // Close a still-open text block before opening the tool. Real Cohere v2 emits a
                // `content-end` for a content text block BEFORE the first `tool-call-start`, so on the
                // normal text-then-tool turn `text_block_open` is already false here and this is a
                // no-op. But the `tool-plan-delta` path (above) opens a LEADING text block that Cohere
                // NEVER closes with `content-end` — it goes straight from the plan tokens to
                // `tool-call-start`, and `message-end` does not close a dangling text block. Left open,
                // that block emits a `content_block_start` with NO matching `content_block_stop` on an
                // Anthropic egress (an unbalanced stream / proxy-signature tell). Close it here — at the
                // index it CLAIMED on first appearance (`state.text_index`, never a hardcoded 0, so a
                // tool that took 0 ahead of the text is not mis-closed) — and clear the live flag.
                // `state.text_index` stays recorded (mirroring `content-end`), so the persistent
                // TEXT_BLOCK_SEEN_SENTINEL still offsets this and later tools past the text index; the
                // tool BlockStart below therefore lands at the SAME index it did before.
                if state.text_block_open {
                    state.text_block_open = false;
                    state.text_block_closed = true;
                    let ti = state.text_index.unwrap_or(0);
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
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
        // Cohere v2 carries the assistant's textual plan that PRECEDES its tool calls in
        // `message.tool_plan` (a string, distinct from `content[]`). Without reading it, that reasoning
        // vanishes on any Cohere→X cross-protocol hop. Emit it as a LEADING Text block so it keeps its
        // native position ahead of the tool calls. (audit H4)
        if let Some(plan) = message_val.get("tool_plan").and_then(|p| p.as_str()) {
            if !plan.is_empty() {
                content.push(crate::ir::IrBlock::Text {
                    text: plan.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            }
        }
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
