use super::*;

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
        // translate seam (`proxy engine`).
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
        // makes proxy engine discard a valid 200 body and emit a spurious 500. The sibling Gemini and
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
