use super::*;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body once and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (error paths are already degraded; avoid the extra
        // parse+alloc on every non-2xx response).
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
            Ok(json) => {
                let error = json.get("error");
                let provider_code = error
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(String::from);
                let structured_type = error
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str())
                    .map(String::from);
                (provider_code, structured_type)
            }
            Err(_) => (None, None),
        };

        // Anthropic signals context-length via the error MESSAGE (no distinct code).
        // Surface the canonical code so the breaker pipeline (normalize_raw_error) → ContextLength.
        //
        // GATE the message-scan override on a request-SIZE status (400 Bad Request / 413 Payload Too
        // Large) — the only statuses under which an oversized-prompt body is the authoritative signal.
        // Cross-protocol sibling of the Cohere `body_signals_context_length` gate. Without
        // the gate, ANY non-2xx whose body merely mentions a token/length phrase was reclassified to
        // context_length: a 401/403 ("...invalid token...") or a 429 ("...rate limit on tokens...")
        // would be turned into a non-penalizing ContextLength fail-over, so the breaker never recorded
        // the auth/rate-limit fault and the lane stayed "healthy" while hard-down or throttled. By
        // confining the override to 400/413, a 401/403/429 that happens to mention tokens keeps its
        // auth/rate-limit disposition and is penalized by the breaker as it should be.
        let status_code = status.as_u16();
        let is_request_size_status = status_code == 400 || status_code == 413;
        let provider_code = provider_code.or_else(|| {
            if !is_request_size_status {
                return None;
            }
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("prompt is too long")
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
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
        let text = String::from_utf8_lossy(body);

        // context-length-exceeded (Anthropic returns 400 invalid_request_error). The lane
        // is healthy; this must fail over (to a larger-context model), not penalize the breaker.
        // Check before the generic 400/client-error path so it wins.
        let lower = text.to_lowercase();
        if lower.contains("prompt is too long")
            || (lower.contains("exceeds the maximum")
                && (lower.contains("token") || lower.contains("context")))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length".to_string()),
                retry_after: None,
            };
        }

        // Prefer the HTTP status, then structured error codes, then substrings as a fallback.
        // Parse the JSON once and examine `error.code` and `error.message` INDEPENDENTLY: the
        // message-substring billing/auth checks must fire even when the structured `code` field is
        // absent (some Anthropic error shapes carry a 200/non-401-403 body with only a message), so
        // they live OUTSIDE the `if let Some(code_val)` guard rather than nested inside it.
        if let Ok(json) = crate::json::parse::<serde_json::Value>(body) {
            let error = json.get("error");

            if let Some(code_val) = error.and_then(|e| e.get("code")) {
                if code_val.as_str() == Some("400") || code_val.as_str() == Some("422") {
                    return CanonicalSignal {
                        class: StatusClass::ClientError,
                        provider_signal: Some("client_error".to_string()),
                        retry_after: None,
                    };
                }
            }

            // Message-substring billing/auth detection — independent of `error.code` presence.
            if let Some(msg_str) = error
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
            {
                if msg_str.contains("nsufficient balance") {
                    return CanonicalSignal {
                        class: StatusClass::Billing,
                        provider_signal: Some("billing".to_string()),
                        retry_after: None,
                    };
                }
                if msg_str.contains("unauthorized") || msg_str.contains("invalid token") {
                    return CanonicalSignal {
                        class: StatusClass::Auth,
                        provider_signal: Some("auth".to_string()),
                        retry_after: None,
                    };
                }
            }
        }

        if status.as_u16() == 401 || status.as_u16() == 403 {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: None,
                retry_after: None,
            };
        }

        if status.as_u16() == 429 {
            // Reuse the single lower-cased copy computed at the top of `classify` rather than
            // allocating a second one — on a verbose 429 body this avoids a redundant heap copy.
            if lower.contains("quota") && lower.contains("exhausted") {
                return CanonicalSignal {
                    class: StatusClass::Billing,
                    provider_signal: Some("429-quota-exhausted".to_string()),
                    retry_after: None,
                };
            }
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429-slowdown".to_string()),
                retry_after: None,
            };
        }

        if status.as_u16() >= 500 {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: None,
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        }
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        // Handle system field (string or array)
        if let Some(system_val) = obj.get("system") {
            if system_val.is_string() {
                let text = system_val.as_str().unwrap_or("").to_string();
                system_blocks.push(crate::ir::IrBlock::Text {
                    text,
                    cache_control: None,
                    citations: Vec::new(),
                });
            } else if let Some(arr) = system_val.as_array() {
                for block_val in arr {
                    system_blocks.push(read_block(block_val)?);
                }
            }
        }

        // Handle messages array. Anthropic's Messages API has NO `system` role inside `messages` —
        // system instructions live in the top-level `system` field. A cross-protocol IR, however, can
        // carry an `IrRole::System` message (e.g. translated from an OpenAI `system` message), and a
        // wire body could nominally present a `role:"system"` message too. PROMOTE any such message
        // into `system_blocks` here at the root rather than pushing it into `req.messages`, so the
        // writer never sees an `IrRole::System` message and can never emit the INVALID Anthropic
        // `role:"system"` (which upstream rejects with a 400). System blocks are appended in order,
        // preserving their position relative to any top-level `system` field already read above.
        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(messages_val) = obj.get("messages") {
            for msg_val in messages_val.as_array().unwrap_or(&Vec::new()) {
                let msg = read_message(msg_val)?;
                if msg.role == crate::ir::IrRole::System {
                    system_blocks.extend(msg.content);
                } else {
                    messages.push(msg);
                }
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                tools.push(read_tool(tool_val)?);
            }
        }

        // Extract scalar fields and extra
        // Checked `u32::try_from` rather than a raw `as u32`: a `max_tokens`/`top_k` larger than
        // `u32::MAX` would silently TRUNCATE under `as` (e.g. 4294967297 → 1), forwarding a wildly
        // wrong cap upstream. An out-of-range value drops to `None` here, matching the sibling
        // readers; the upstream then applies its own default rather than receiving a corrupted limit.
        let max_tokens = obj
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            // Treat `max_tokens: 0` as absent (matches the OpenAI/Gemini/Bedrock/Cohere/Responses
            // readers). A zero cap is meaningless (no output budget) and would force an invalid body
            // on egress; dropping it to None lets the target apply its own default.
            .filter(|&v| v > 0);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        let top_k = obj
            .get("top_k")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Anthropic's native `stop_sequences` is an array of strings.
        let stop = crate::ir::read_stop_sequences(obj.get("stop_sequences"));
        // Anthropic `tool_choice` is an object: {type:"auto"|"any"|"tool"|"none", name?}. Normalize
        // into the IR union so forced/targeted tool use survives the cross-protocol seam.
        let tool_choice = read_anthropic_tool_choice(obj.get("tool_choice"));
        // `disable_parallel_tool_use` rides INSIDE Anthropic's tool_choice object; normalize it
        // inverted ("parallel allowed?") so it carries to OpenAI's top-level `parallel_tool_calls`.
        let parallel_tool_calls = obj
            .get("tool_choice")
            .and_then(|tc| tc.get("disable_parallel_tool_use"))
            .and_then(|v| v.as_bool())
            .map(|disabled| !disabled);
        // `metadata.user_id` is Anthropic's spelling of OpenAI's `user`; promote it so it carries
        // across the seam. The `metadata` object itself still rides `extra` (unmodeled), keeping
        // same-protocol fidelity byte-exact.
        let user = obj
            .get("metadata")
            .and_then(|m| m.get("user_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // The request-level `thinking` param (the ASK, not the response content blocks):
        // {type:"enabled", budget_tokens:N} promotes into the IR reasoning ask so it can carry to
        // Gemini's thinkingBudget or OpenAI's reasoning_effort. Any other form ({type:"disabled"},
        // malformed) stays in `extra` untouched: same-protocol fidelity, and foreign targets treat
        // an absent ask as off anyway.
        let reasoning = obj
            .get("thinking")
            .filter(|t| t.get("type").and_then(|v| v.as_str()) == Some("enabled"))
            .and_then(|t| t.get("budget_tokens"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .map(crate::ir::IrReasoningAsk::Budget);
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect unmodeled top-level keys into `extra`. The set of modeled keys is a static,
        // never-changing list of `&'static str` literals, so it lives as a compile-time SORTED slice
        // and membership is an O(log n) `binary_search` — zero allocation, zero hashing, on every
        // inbound request (the previous per-call `HashSet` allocated + hashed up to 10 entries and
        // dropped the set immediately, pure churn on the hot ingress path). Kept sorted by hand;
        // `debug_assert` below pins that invariant so a future edit that breaks ordering fails tests.
        const MODELED_KEYS: &[&str] = &[
            "max_tokens",
            "messages",
            "model",
            "stop_sequences",
            "stream",
            "system",
            "temperature",
            "tool_choice",
            "tools",
            "top_k",
            "top_p",
        ];
        debug_assert!(
            MODELED_KEYS.windows(2).all(|w| w[0] < w[1]),
            "MODELED_KEYS must stay sorted for binary_search"
        );

        for (key, value) in obj.iter() {
            if MODELED_KEYS.binary_search(&key.as_str()).is_err() {
                extra.insert(key.clone(), value.clone());
            }
        }
        // A PROMOTED thinking ask must not also ride extra (the writer re-emits it from the typed
        // field; a duplicate from extra would double-emit on a translated same-protocol hop).
        if reasoning.is_some() {
            extra.remove("thinking");
        }

        // (No ingress sentinel scrub needed anymore: a client cannot forge a redacted-reasoning block.
        // `redacted` is a TYPED flag only the Anthropic/Bedrock readers set on a genuine
        // `redacted_thinking`/`redactedContent` block — a client-supplied `signature` string can never
        // mark a block redacted, so the old `__busbar` sentinel forgery vector is structurally closed.)

        Ok(crate::ir::IrRequest {
            reasoning,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user,
            parallel_tool_calls,
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
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra,
        })
    }

    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        match event_type {
            EVT_MESSAGE_START => {
                let msg = data.get("message")?;
                let role_str = msg.get("role").and_then(|r| r.as_str())?;
                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => return None,
                };
                let usage = data
                    .get("message")
                    .and_then(|m| m.get("usage"))
                    .map(|u| IrUsage {
                        input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                        cache_creation_input_tokens: u
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64()),
                        cache_read_input_tokens: u
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64()),
                    });
                // Capture the stream's native identity so an anthropic→anthropic passthrough
                // re-emits the exact `message_start.message` an SDK expects (it reads
                // `message.id`/`message.model` to populate the assembled `Message`). Anthropic's
                // `message_start` has no `created` field, so `created` stays None on this path; the
                // writer synthesizes one only when translating from a protocol that omitted it.
                let id = msg.get("id").and_then(|i| i.as_str()).map(String::from);
                // Empty `model` maps to `None`: the writer emits `model: ""` as the mandatory-field
                // fallback when no source model exists, so reading it back as `None` keeps the
                // stream-event round-trip idempotent (a real model id is never empty).
                let model = msg
                    .get("model")
                    .and_then(|m| m.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                Some(IrStreamEvent::MessageStart {
                    role,
                    usage,
                    id,
                    created: None,
                    model,
                })
            }
            EVT_CONTENT_BLOCK_START => {
                let index = read_clamped_block_index(data)?;
                let block = data.get("content_block")?;
                let block_type = block.get("type").and_then(|t| t.as_str())?;
                let meta = match block_type {
                    "text" => IrBlockMeta::Text,
                    "thinking" => IrBlockMeta::Thinking,
                    STOP_TOOL_USE => {
                        let id = block.get("id").and_then(|i| i.as_str()).map(String::from)?;
                        let name = block
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(String::from)?;
                        IrBlockMeta::ToolUse { id, name }
                    }
                    "image" => IrBlockMeta::Image,
                    _ => return None,
                };
                Some(IrStreamEvent::BlockStart { index, block: meta })
            }
            EVT_CONTENT_BLOCK_DELTA => {
                let index = read_clamped_block_index(data)?;
                let delta_val = data.get("delta")?;
                let delta_type = delta_val.get("type").and_then(|t| t.as_str())?;
                let delta = match delta_type {
                    DELTA_TYPE_TEXT => {
                        let text = delta_val
                            .get("text")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::TextDelta(text)
                    }
                    DELTA_TYPE_THINKING => {
                        let thinking = delta_val
                            .get("thinking")
                            .and_then(|t| t.as_str())
                            .map(String::from)?;
                        IrDelta::ThinkingDelta(thinking)
                    }
                    DELTA_TYPE_INPUT_JSON => {
                        let json = delta_val
                            .get("partial_json")
                            .or_else(|| delta_val.get("input_json"))
                            .and_then(|j| j.as_str())
                            .map(String::from)?;
                        IrDelta::InputJsonDelta(json)
                    }
                    DELTA_TYPE_SIGNATURE => {
                        let signature = delta_val
                            .get("signature")
                            .and_then(|s| s.as_str())
                            .map(String::from)?;
                        IrDelta::SignatureDelta(signature)
                    }
                    // L2-5 STREAMING citation: a native Anthropic `content_block_delta` whose
                    // `delta.type == "citations_delta"` carries a single `citation` object (one of
                    // the four citation variants). Reuse `read_citation` so the neutral fields AND
                    // the byte-exact `raw` escape hatch are filled (same as the non-stream path),
                    // then carry it as `IrDelta::CitationsDelta` (one citation per delta). Without
                    // this arm a streamed grounding/web-search citation was silently dropped.
                    DELTA_TYPE_CITATIONS => {
                        let citation_val = delta_val.get("citation")?;
                        IrDelta::CitationsDelta(vec![read_citation(citation_val)])
                    }
                    _ => return None,
                };
                Some(IrStreamEvent::BlockDelta { index, delta })
            }
            EVT_CONTENT_BLOCK_STOP => {
                let index = read_clamped_block_index(data)?;
                Some(IrStreamEvent::BlockStop { index })
            }
            EVT_MESSAGE_DELTA => {
                let delta = data.get("delta")?;
                let stop_reason = delta
                    .get("stop_reason")
                    .and_then(|r| r.as_str())
                    .map(read_anthropic_stop_reason);
                // `message_delta.delta.stop_sequence` — the matched stop string, present (as a
                // string) only when a stop sequence actually triggered the stop, `null`/absent
                // otherwise. Carry it through so the same-protocol writer can re-emit it.
                let stop_sequence = delta
                    .get("stop_sequence")
                    .and_then(|s| s.as_str())
                    .map(String::from);
                // `usage` is OPTIONAL on read here: do NOT `?` it. `message_delta` is the terminal
                // event that carries `stop_reason`/`stop_sequence`, so propagating `None` out of this
                // closure when `usage` is absent would silently DROP the whole event — the client then
                // never sees the stop reason and cannot tell whether generation completed. A native
                // Anthropic stream always includes `usage`, but an Anthropic-compatible backend that
                // doesn't implement usage counting (or makes it conditional) may omit it; preserve the
                // event regardless by zero-defaulting the counters when `usage` is missing. This mirrors
                // the `message_start` reader above, which already maps a missing `usage` to defaults
                // rather than bailing.
                let usage_val = data.get("usage");
                let usage = IrUsage {
                    input_tokens: usage_val
                        .and_then(|u| u.get("input_tokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    output_tokens: usage_val
                        .and_then(|u| u.get("output_tokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens: usage_val
                        .and_then(|u| u.get("cache_creation_input_tokens"))
                        .and_then(|v| v.as_u64()),
                    cache_read_input_tokens: usage_val
                        .and_then(|u| u.get("cache_read_input_tokens"))
                        .and_then(|v| v.as_u64()),
                };
                Some(IrStreamEvent::MessageDelta {
                    stop_reason,
                    stop_sequence,
                    usage,
                })
            }
            EVT_MESSAGE_STOP => Some(IrStreamEvent::MessageStop),
            "error" => {
                let err_val = data.get("error")?;
                // Carry the upstream error `type` through as-is: `Some("rate_limit_error")` when
                // present, `None` when the event omits it. Do NOT `unwrap_or_default()` into
                // `Some("")` — an empty-string type would make the writer emit `"type": ""` where a
                // native Anthropic error event carries either a real type or `null`. The writer
                // (write_response_event) already renders `None` as JSON `null`, so the absence
                // round-trips faithfully.
                let type_token = err_val.get("type").and_then(|t| t.as_str());
                let provider_signal = type_token.map(String::from);
                // Derive the breaker class from the upstream error `type`, mirroring the HTTP
                // classifier intent (see `classify`/`write_error`'s Anthropic error vocabulary)
                // instead of hardcoding ClientError. A mid-stream `overloaded_error`/
                // `rate_limit_error`/`api_error` is a TRANSIENT upstream fault, not a client fault —
                // hardcoding ClientError mapped every one of them to Disposition::ClientFault, so the
                // breaker never recorded the transient/hard-down signal and took the wrong transition.
                let class = stream_error_class(type_token);
                Some(IrStreamEvent::Error(IrError {
                    class,
                    provider_signal,
                    retry_after: None,
                }))
            }
            _ => None,
        }
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        _state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        // A streamed `redacted_thinking` block carries its full opaque encrypted `data` INLINE on the
        // `content_block_start` event (Anthropic sends NO deltas for redacted blocks), so the 1:1
        // single-event reader dropped it entirely (`_ => return None`). Emit the pair the IR models
        // for redacted reasoning — a `Thinking` BlockStart plus a `RedactedReasoningDelta` carrying
        // the opaque bytes — from this one start event (the natural `content_block_stop` that follows
        // produces the BlockStop). Mirrors the Bedrock streaming reader + the non-stream `read_block`.
        // (found: audit c2r2.)
        if event_type == EVT_CONTENT_BLOCK_START {
            if let Some(block) = data.get("content_block") {
                if block.get("type").and_then(|t| t.as_str()) == Some(BLOCK_TYPE_REDACTED_THINKING)
                {
                    if let Some(index) = read_clamped_block_index(data) {
                        let bytes = block
                            .get("data")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string();
                        return vec![
                            IrStreamEvent::BlockStart {
                                index,
                                block: IrBlockMeta::Thinking,
                            },
                            IrStreamEvent::BlockDelta {
                                index,
                                delta: IrDelta::RedactedReasoningDelta(bytes),
                            },
                        ];
                    }
                }
            }
        }
        // Anthropic events are otherwise already block-structured (1:1): wrap the singular.
        match self.read_response_event(event_type, data) {
            Some(ev) => vec![ev],
            None => vec![],
        }
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;

        // Parse role (should be "assistant" for responses)
        let role_str = obj.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let role = match role_str {
            "assistant" => crate::ir::IrRole::Assistant,
            _ => {
                return Err(IrError {
                    class: StatusClass::ClientError,
                    provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
                    retry_after: None,
                })
            }
        };

        // Parse content blocks
        let content_val = obj.get("content").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.into()),
            retry_after: None,
        })?;
        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(arr) = content_val.as_array() {
            for block_val in arr {
                content.push(read_block(block_val)?);
            }
        }

        // Parse stop_reason (optional)
        let stop_reason = obj
            .get("stop_reason")
            .and_then(|r| r.as_str())
            .map(read_anthropic_stop_reason);

        // Parse usage. `usage` is OPTIONAL on read here: do NOT `ok_or?` it. A native Anthropic
        // non-streaming `Message` always carries `usage`, but an Anthropic-compatible backend that
        // doesn't implement usage counting (or makes it conditional) may omit it — hard-requiring the
        // field turned an otherwise-valid 200 body into a 400, inconsistent with this protocol's own
        // streaming readers (`message_start`/`message_delta` above already zero-default a missing
        // `usage` rather than bailing) and with the gemini/cohere reader tolerance. When `usage` is
        // absent each counter defaults to zero (`Some` → parse, `None` → 0).
        let usage_val = obj.get("usage");
        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: usage_val
                .and_then(|u| u.get("cache_creation_input_tokens"))
                .and_then(|v| v.as_u64()),
            cache_read_input_tokens: usage_val
                .and_then(|u| u.get("cache_read_input_tokens"))
                .and_then(|v| v.as_u64()),
        };

        // Treat an empty `model` string as absent (`None`). The writer emits `model: ""` as the
        // mandatory-field fallback when the source carried no model (see `write_response`); mapping
        // that empty string back to `None` keeps a write→read round-trip IR-idempotent and never
        // mistakes the placeholder for a real model identifier (a genuine model id is never empty).
        let model = obj
            .get("model")
            .and_then(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        // Capture the native response identity so a same-protocol (anthropic→anthropic) passthrough
        // preserves it byte-for-byte. An official SDK's `Message` carries `id` ("msg_<rand>"),
        // `type` ("message"), `role`, `model`, `stop_reason`, `stop_sequence`, and `usage`; the
        // first four plus `stop_sequence` round-trip through these IR fields (role/model/stop_reason
        // are already parsed above; `type` is a constant the writer re-emits).
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        // Anthropic's non-streaming `Message` has no `created` field, so there is nothing to carry
        // through; the writer synthesizes one only on the cross-protocol path (where the IR field is
        // None) for SDKs that read it. `system_fingerprint` is an OpenAI concept Anthropic never
        // emits — left None so a same-protocol round-trip does not invent one.
        let stop_sequence = obj
            .get("stop_sequence")
            .and_then(|s| s.as_str())
            .map(String::from);

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
            role,
            content,
            stop_reason,
            usage,
            model,
            id,
            created: None,
            system_fingerprint: None,
            stop_sequence,
        })
    }
}
