use super::*;

impl ProtocolReader for ResponsesReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body ONCE and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (matches the anthropic.rs pattern; error paths are
        // already degraded — avoid the extra parse+alloc on every non-2xx response).
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
            Ok(json) => {
                let error = json.get("error").and_then(|e| e.as_object());
                let provider_code = error
                    .and_then(|e_obj| e_obj.get("code"))
                    .and_then(|c| c.as_str())
                    .map(String::from);
                let structured_type = error
                    .and_then(|e_obj| e_obj.get("type"))
                    .and_then(|t| t.as_str())
                    .map(String::from);
                (provider_code, structured_type)
            }
            Err(_) => (None, None),
        };

        // Native /v1/responses already carries `code: "context_length_exceeded"` on the oversized
        // path, so the common case flows straight through. But some upstreams (and the OpenAI
        // Chat-Completions-shaped surface this proxy also fronts) signal the same condition only via
        // the error MESSAGE — e.g. `This model's maximum context length is 8192 tokens...` — with a
        // null or generic `code`. Mirror openai_chat.rs / anthropic.rs: when no canonical code was parsed,
        // scan the body for the protocol's context-length phrasing and synthesize the canonical code
        // so the breaker pipeline (normalize_raw_error, breaker.rs) → StatusClass::ContextLength
        // and oversized-request failover triggers WITHOUT penalizing the lane. This is the production
        // counterpart of the `#[cfg(test)] classify()` helper's message scan below.
        //
        // GATE the message scan to the HTTP statuses an oversized request actually uses (400
        // invalid_request_error; 413 payload-too-large), mirroring `OpenAiReader::extract_error`.
        // Without the gate a 401/429/5xx whose prose happens to contain "maximum context length"
        // would synthesize `context_length_exceeded` → the breaker maps it to ContextLength → the
        // genuine auth/rate-limit/server failure escapes fault attribution (no fault recorded).
        let provider_code = provider_code.or_else(|| {
            let oversized_status =
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
            if !oversized_status {
                return None;
            }
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if super::openai_family::openai_context_length_prose_scan(&lower) {
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
        // Identical to OpenAiReader::classify — both emit the same OpenAI error envelope, so the
        // mapping is single-sourced in `super::openai_family::openai_classify`.
        super::openai_family::openai_classify(status, body)
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        if obj.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(instructions) = obj.get("instructions").and_then(|v| v.as_str()) {
            if !instructions.is_empty() {
                system_blocks.push(crate::ir::IrBlock::Text {
                    text: instructions.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();

        if let Some(input_val) = obj.get("input") {
            if input_val.is_string() {
                let text = input_val.as_str().unwrap_or("").to_string();
                messages.push(crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text,
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                });
            } else if let Some(arr) = input_val.as_array() {
                for item in arr {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some(CONTENT_TYPE_INPUT_TEXT) => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("input_image") => {
                            // L5: a Responses `input_image` can reference an uploaded file by
                            // `file_id` INSTEAD of carrying an inline `image_url`. The prior code only
                            // read `image_url`, so a file_id-only image produced an EMPTY Image block
                            // (media_type/data both ""), a lossy degradation. Carry the file_id
                            // faithfully under a distinct `file_id` sentinel (mirroring the `image_url`
                            // sentinel) so the writer reconstructs `{type:input_image,file_id}` and the
                            // round-trip is lossless. Prefer `image_url` when present (the inline form).
                            if let Some(block) = responses_input_image_block(item) {
                                messages.push(crate::ir::IrMessage {
                                    role: crate::ir::IrRole::User,
                                    content: vec![block],
                                });
                            }
                        }
                        Some(CONTENT_TYPE_OUTPUT_TEXT) => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some(ITEM_TYPE_FUNCTION_CALL) => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let arguments = item
                                .get("arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");
                            // On malformed argument JSON, preserve the raw string rather than
                            // discarding the caller's tool arguments to Null (mirrors the OpenAI
                            // reader). Losing arguments entirely is a lossy cross-protocol bug.
                            let input = crate::json::parse_str(arguments).unwrap_or_else(|_| {
                                serde_json::Value::String(arguments.to_string())
                            });

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::ToolUse {
                                    id: call_id,
                                    name,
                                    input,
                                    cache_control: None,
                                }],
                            });
                        }
                        Some("function_call_output") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let output_val = item.get("output");
                            let content_blocks: Vec<crate::ir::IrBlock> = match output_val {
                                Some(serde_json::Value::String(out_str)) => {
                                    vec![crate::ir::IrBlock::Text {
                                        text: out_str.clone(),
                                        cache_control: None,
                                        citations: Vec::new(),
                                    }]
                                }
                                _ => output_val
                                    .and_then(|o| o.as_array())
                                    .map(|arr| {
                                        arr.iter().filter_map(|b| responses_block(b).ok()).collect()
                                    })
                                    .unwrap_or_default(),
                            };

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Tool,
                                content: vec![crate::ir::IrBlock::ToolResult {
                                    tool_use_id: call_id,
                                    content: content_blocks,
                                    is_error: false,
                                    cache_control: None,
                                }],
                            });
                        }
                        Some(ITEM_TYPE_MESSAGE) => {
                            // The official OpenAI Responses SDK emits conversation turns as typed
                            // `{"type":"message","role":...,"content":[...]}` items. The role-keyed
                            // fallback below only fires for UNTYPED items, so without this arm a
                            // typed message turn would be silently dropped. Read role+content and
                            // map the content blocks via `responses_block`, mirroring the untyped
                            // branch.
                            let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                            // `system`/`developer` turns carry the system prompt. They have no
                            // IrRole and must NOT become conversation messages — accumulate their
                            // text into `system_blocks` (which feeds `IrRequest.system` ->
                            // top-level instructions), or the system prompt is silently lost on a
                            // cross-protocol hop. Content can be an array of `input_text` blocks or
                            // a bare string; handle both.
                            if role_str == "system" || role_str == "developer" {
                                push_system_content(&mut system_blocks, item.get("content"));
                                continue;
                            }
                            let role = match role_str {
                                "user" => Some(crate::ir::IrRole::User),
                                "assistant" => Some(crate::ir::IrRole::Assistant),
                                _ => None,
                            };
                            if let Some(role) = role {
                                // `content` may be an array of typed blocks OR a bare string
                                // shorthand; `message_content_blocks` handles both so a
                                // string-content turn is not silently dropped.
                                if let Some(msg_content) =
                                    message_content_blocks(item.get("content"))
                                {
                                    messages.push(crate::ir::IrMessage {
                                        role,
                                        content: msg_content,
                                    });
                                }
                            }
                        }
                        Some(ITEM_TYPE_REASONING) => {
                            // Fix #6: a prior-turn `reasoning` INPUT item carries assistant
                            // reasoning (text under `content`/`summary`, opaque blob under
                            // `encrypted_content`). Dropping it lost that reasoning entirely on egress
                            // to a protocol that models reasoning (Anthropic/Bedrock Thinking). Decode
                            // it into an `IrBlock::Thinking` on its own assistant turn (a Responses
                            // `reasoning` item is a top-level sibling of the assistant message it
                            // precedes, so a standalone assistant turn is the faithful mapping). The
                            // paired writer (`write_request`) re-emits this as a `reasoning` input
                            // item, so a same-protocol Responses->Responses round-trip is preserved.
                            let text = read_reasoning_text(item);
                            let signature = item
                                .get("encrypted_content")
                                .and_then(|s| s.as_str())
                                .filter(|s| !s.is_empty())
                                .map(String::from);
                            if !text.is_empty() || signature.is_some() {
                                messages.push(crate::ir::IrMessage {
                                    role: crate::ir::IrRole::Assistant,
                                    content: vec![crate::ir::IrBlock::Thinking {
                                        text,
                                        signature,
                                        redacted: false,
                                        cache_control: None,
                                    }],
                                });
                            }
                        }
                        Some(_) | None => {}
                    }

                    // Handle role/content structured items (user/assistant messages) ONLY when the
                    // item carries no `type` field. A typed item (e.g. "output_text") that also
                    // happens to include a `role` must NOT be re-processed here, or the turn would
                    // be duplicated in the resulting conversation.
                    if item.get("type").is_none() && item.get("role").is_some() {
                        let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                        let content_val = item.get("content");

                        // As in the typed `message` arm, untyped `system`/`developer` turns carry
                        // the system prompt and must be accumulated into `system_blocks` rather than
                        // dropped (the prior `_ => continue` lost them on cross-protocol hops).
                        if role_str == "system" || role_str == "developer" {
                            push_system_content(&mut system_blocks, content_val);
                            continue;
                        }

                        let role = match role_str {
                            "user" => crate::ir::IrRole::User,
                            "assistant" => crate::ir::IrRole::Assistant,
                            _ => continue,
                        };

                        // As in the typed `message` arm, `content` may be an array of typed
                        // blocks OR a bare string shorthand; handle both via
                        // `message_content_blocks` so a string-content untyped turn survives.
                        if let Some(msg_content) = message_content_blocks(content_val) {
                            messages.push(crate::ir::IrMessage {
                                role,
                                content: msg_content,
                            });
                        }
                    }
                }
            }
        } else if !obj.contains_key("instructions") {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                let name = tool_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool_val
                    .get("description")
                    .and_then(|v| v.as_str().map(String::from));
                let input_schema = tool_val
                    .get("parameters")
                    .or_else(|| tool_val.get("input_schema"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                tools.push(crate::ir::IrTool {
                    name,
                    description,
                    input_schema,
                    cache_control: None,
                });
            }
        }

        // Read `max_output_tokens` as u64 and fall back to None on out-of-range values rather than
        // silently truncating a value larger than u32::MAX via `as u32` (matches the anthropic and
        // bedrock readers). `try_from` also rejects negatives, so an explicit `> 0` filter is moot;
        // a value of 0 is preserved as Some(0) just as the prior code dropped it — keep dropping it.
        let max_tokens = obj
            .get("max_output_tokens")
            .and_then(|v| v.as_u64())
            .filter(|&v| v > 0)
            .and_then(|v| u32::try_from(v).ok());
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        // The Responses API supports `top_p` but has NO `top_k` and no top-level stop-sequence param,
        // so only top_p is promoted here; `top_k`/`stop` stay None/empty (any unmodeled knob remains
        // in `extra`).
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        // The Responses API carries `stream` in the request body — read it (don't drop the intent).
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        // `tool_choice` (PF-H1): promote to the IR union so a forced/targeted directive survives the
        // cross-protocol seam instead of degrading to `auto`. "tool_choice" is added to the modeled
        // keys below so it does not also linger in `extra`.
        let tool_choice = read_responses_tool_choice(obj.get("tool_choice"));

        // M1 response_format: the Responses API carries structured-output config under `text.format`
        // (NOT a top-level `response_format` as Chat Completions does). Read `text.format` and
        // normalize it into the IR's canonical `response_format` shape (the Chat-Completions shape the
        // OpenAI reader stores), so a Responses structured-output request reaches an OpenAI/Anthropic
        // backend faithfully and a same-protocol round-trip is lossless. `text` is added to the modeled
        // keys below so it does not also linger in `extra` (which would double-emit it on write).
        // SAMPLING (Phase 0): the Responses create API does NOT model `frequency_penalty`,
        // `presence_penalty`, `seed`, or `n` (verified against the official openai-python
        // `ResponseCreateParamsBase` — only `temperature`/`top_p`/`top_logprobs`/`text` are present),
        // so none are promoted here (they stay None) and none are added to the modeled-keys exclusion.
        // STOP (M5): the Responses create API has NO `stop`/`stop_sequences` param either, so `stop`
        // stays empty and is not read.
        let response_format = read_text_format(obj.get("text"));

        // NOTE: `text` is NOT in the modeled-keys set — it is intercepted by its own branch in the
        // loop below (its `format` sub-key → IR `response_format` per M1, the remainder preserved
        // in `extra`). `metadata` is also deliberately excluded from the set; see `responses_modeled_keys`.
        let modeled_keys = responses_modeled_keys();

        for (key, value) in obj.iter() {
            // `text` is partially modeled: its `format` sub-key is promoted to the IR
            // `response_format` (M1) and MUST NOT also linger in `extra` (the writer rebuilds `text`
            // from `response_format`, so a leftover `extra["text"]["format"]` would double-emit /
            // conflict). But `text` may carry OTHER sub-keys (e.g. `verbosity`) that busbar does not
            // model — those must survive via `extra`. So when `text` carries non-`format` keys, route a
            // `format`-stripped copy into `extra`; when `text` is format-only, drop it from `extra`
            // entirely (the writer re-synthesizes it from `response_format`). Checked BEFORE the
            // modeled-keys short-circuit so the format-stripped remainder is preserved even though
            // `text` is listed as modeled.
            if key == "text" {
                if let Some(text_obj) = value.as_object() {
                    let remainder: serde_json::Map<String, serde_json::Value> = text_obj
                        .iter()
                        .filter(|(k, _)| k.as_str() != "format")
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if !remainder.is_empty() {
                        extra.insert("text".to_string(), serde_json::Value::Object(remainder));
                    }
                }
                continue;
            }
            if modeled_keys.contains(key.as_str()) {
                continue;
            }
            extra.insert(key.clone(), value.clone());
        }

        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
        }

        // The reasoning ASK: Responses spells it `reasoning: {effort}`. Promote the effort word so
        // it carries to Anthropic/Gemini thinking budgets; the raw `reasoning` object (which can
        // also carry `summary`) STAYS in extra for same-protocol fidelity — the writer emits from
        // the typed field only when extra does not already carry the verbatim original.
        let reasoning = obj
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(|v| v.as_str())
            .and_then(crate::ir::IrReasoningEffort::parse)
            .map(crate::ir::IrReasoningAsk::Effort);

        Ok(crate::ir::IrRequest {
            reasoning,
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
            top_k: None,
            stop: vec![],
            tool_choice,
            stream,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format,
            extra,
        })
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match event_type {
            EVT_RESPONSE_CREATED | "response.in_progress" => {
                if !state.started {
                    state.started = true;
                    // Capture stream identity from the nested `response` object so a same-protocol
                    // passthrough preserves it. `created_at` is the Responses field name (mapped to
                    // the IR's `created`).
                    let resp = data.get("response");
                    let id = resp
                        .and_then(|r| r.get("id"))
                        .and_then(|i| i.as_str())
                        .map(String::from);
                    let created = resp
                        .and_then(|r| r.get("created_at"))
                        .and_then(|c| c.as_u64());
                    let model = resp
                        .and_then(|r| r.get("model"))
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created,
                        model,
                    });
                }
            }

            EVT_OUTPUT_ITEM_ADDED => {
                if let Some(item_obj) = data.get("item") {
                    if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_FUNCTION_CALL)
                    {
                        let call_id = item_obj
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item_obj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            // Clamp the wire index before the cast: a crafted `u64::MAX` would
                            // otherwise feed the per-stream set and downstream index arithmetic
                            // unbounded. Saturate at MAX_OUTPUT_INDEX (mirrors openai_chat.rs).
                            let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                            // Record the open tool index so the terminal `output_item.done` for
                            // this index closes the block EXACTLY once. Native Responses emits a
                            // single `output_item.done` per function-call item, so unlike text
                            // (which also gets a `content_part.done`) a tool index is closed by one
                            // event — tracking it here keeps the open/close pair balanced and lets
                            // the done arm distinguish a real open block from a duplicate close.
                            //
                            // Cap the distinct-index cardinality: a backend emitting a unique
                            // `output_index` per event must not grow `open_tools` without bound
                            // (a per-connection amplification DoS). Open a new block ONLY when the
                            // index is not already tracked AND there is room under the cap. An
                            // already-open index must NOT re-emit BlockStart — a second
                            // `output_item.added` for an open index would produce an invalid
                            // BlockStart→BlockStart→BlockStop sequence (a duplicate
                            // `content_block_start`), a deterministic proxy tell that corrupts a
                            // downstream writer's tool-call state. Beyond the cap a NEW index is
                            // silently skipped (no BlockStart), matching openai_chat.rs.
                            // An index must not open as BOTH a tool and a text block: a text delta
                            // at this same `output_index` stores its open marker under
                            // `idx + TEXT_INDEX_KEY_OFFSET`, and if such a text block is already open
                            // here, opening a tool block at the raw `idx` too would leave two open
                            // markers (`idx` and `idx + offset`) for one wire index — both BlockStarts
                            // collapse onto IR index `idx`, yielding a duplicate
                            // `content_block_start` and (at the terminal frame) a duplicate
                            // BlockStop. Require the symmetric text key to be CLEAR before opening a
                            // tool block, so a single output_index is exactly one block kind.
                            let already_open = state.open_tools.contains(&idx)
                                || state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET));
                            if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                                state.open_tools.insert(idx);
                                out.push(IrStreamEvent::BlockStart {
                                    index: idx,
                                    block: crate::ir::IrBlockMeta::ToolUse { id: call_id, name },
                                });
                            }
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_REASONING)
                    {
                        // H1 REASONING (stream): a native Responses stream opens a chain-of-thought
                        // item with `output_item.added` typed `reasoning`. The prior `_`/`message`
                        // no-op DROPPED it, so a reasoning stream lost its thinking on any
                        // cross-protocol hop. Open a Thinking block at this `output_index`, tracked in
                        // `open_tools` at the RAW idx (like a tool item — closed once by the single
                        // `output_item.done` this index receives). Same cardinality cap and
                        // already-open guard as the tool arm so a malformed stream cannot double-open
                        // or grow the set without bound.
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                            let already_open = state.open_tools.contains(&idx)
                                || state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET));
                            if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                                state.open_tools.insert(idx);
                                out.push(IrStreamEvent::BlockStart {
                                    index: idx,
                                    block: crate::ir::IrBlockMeta::Thinking,
                                });
                            }
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_MESSAGE)
                    {
                    }
                }
            }

            // H1 REASONING (stream): native reasoning text arrives as `response.reasoning_text.delta`
            // (the full reasoning) and `response.reasoning_summary_text.delta` (a summarized form),
            // both carrying an `output_index` and a `delta` string. The prior `_ => {}` DROPPED these,
            // so a streamed reasoning response lost its chain-of-thought. Route each as an
            // `IrDelta::ThinkingDelta` against the reasoning block at this `output_index`, lazily
            // opening the Thinking BlockStart if the `output_item.added` was absent (some backends emit
            // reasoning deltas with no preceding `added`). The block is tracked at the RAW idx in
            // `open_tools`, closed once by the terminal `output_item.done`/stream end.
            EVT_REASONING_TEXT_DELTA | "response.reasoning_summary_text.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| (v as usize).min(MAX_OUTPUT_INDEX));
                    // Lazily open the Thinking block if `output_item.added` did not already. Guard the
                    // open against a TEXT key collision at the same index (a reasoning index and a text
                    // index should never share a wire index, but stay defensive) and the cardinality
                    // cap; beyond the cap suppress the delta rather than emit an orphan.
                    if !state.open_tools.contains(&idx)
                        && !state.open_tools.contains(&(idx + TEXT_INDEX_KEY_OFFSET))
                    {
                        if state.open_tools.len() >= MAX_OPEN_TOOLS {
                            return out;
                        }
                        state.open_tools.insert(idx);
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Thinking,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::ThinkingDelta(delta),
                    });
                }
            }

            EVT_OUTPUT_TEXT_DELTA => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                // Drop empty keepalive deltas entirely: they neither open a block nor carry
                // content, so emitting a zero-length TextDelta would be spurious noise.
                if !delta.is_empty() {
                    // Use the wire `output_index` for BOTH the lazy BlockStart and the BlockDelta so
                    // the open/close pair stays index-matched even when the text part is not at
                    // index 0 (e.g. it follows a tool call at index 0).
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| (v as usize).min(MAX_OUTPUT_INDEX));
                    // Track open TEXT indices PER INDEX in `open_tools` under a disjoint key offset
                    // (see `TEXT_INDEX_KEY_OFFSET`) instead of the single index-blind
                    // `text_block_open` bool. A native stream can carry multiple message items, each
                    // at its own `output_index`; the per-index set opens a BlockStart lazily ONLY for
                    // an index not already open (so a second text item gets its own BlockStart rather
                    // than an orphan delta), and bounds cardinality under the same cap as tool items
                    // so a backend emitting a unique index per delta cannot grow the set without
                    // bound. Beyond the cap a new index streams no BlockStart/BlockDelta (matching
                    // the tool arm's suppression), never an orphan delta.
                    // Symmetric to the tool arm: an index already open as a TOOL block (raw `idx` in
                    // `open_tools`) must not also open a TEXT block under `idx +
                    // TEXT_INDEX_KEY_OFFSET`. If a function-call item already holds this
                    // `output_index`, a stray text delta at the same index must NOT open a second
                    // block (two BlockStarts collapsing onto one IR index — a duplicate
                    // `content_block_start` and an eventual duplicate BlockStop). Treat the index as
                    // already open and route no text BlockStart/BlockDelta to it.
                    let text_key = idx + TEXT_INDEX_KEY_OFFSET;
                    if state.open_tools.contains(&idx) {
                        // This `output_index` is already held by an OPEN TOOL block. A text delta
                        // here must NOT open a second block (a duplicate `content_block_start`/
                        // `_stop` once both keys collapse onto IR index `idx`) AND must NOT push a
                        // TextDelta into a tool block (a malformed text fragment inside an open
                        // tool-use block a strict SDK rejects). Drop the stray text delta entirely.
                        return out;
                    }
                    let already_open = state.open_tools.contains(&text_key);
                    if !already_open {
                        if state.open_tools.len() >= MAX_OPEN_TOOLS {
                            // Cap reached: suppress this index entirely (no BlockStart, no orphan
                            // BlockDelta) rather than emitting a delta for an unopened block.
                            return out;
                        }
                        state.open_tools.insert(text_key);
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::TextDelta(delta),
                    });
                }
            }

            EVT_FUNCTION_CALL_ARGS_DELTA => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                        let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                        // Route the argument delta ONLY to an index that actually emitted a
                        // BlockStart (tracked in `open_tools` by the `output_item.added` arm).
                        // An index suppressed by the cardinality cap — or an arguments-delta that
                        // arrives with no preceding `output_item.added` at all — has no open block,
                        // so a BlockDelta against it would be a tool-argument fragment for a block
                        // with no `content_block_start`: an invalid event sequence that breaks a
                        // strict SDK reassembling tool-call arguments and a distinguishability tell.
                        // Drop it (mirrors openai_chat.rs's `state.open_tools.contains` guard).
                        if state.open_tools.contains(&idx) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(delta),
                            });
                        }
                    }
                }
            }

            EVT_OUTPUT_ITEM_DONE | "response.content_part.done" => {
                if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                    let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                    // Native Responses closes a single text item with TWO terminal frames at the
                    // SAME `output_index`: `content_part.done` (the text content part) immediately
                    // followed by `output_item.done` (the enclosing message item). Emitting a
                    // BlockStop for BOTH produces a duplicate `content_block_stop` at one index for
                    // a block that opened once — an invalid event sequence and a distinguishability
                    // tell. So close a block EXACTLY once: only emit BlockStop for an index that is
                    // currently open, and clear the open marker so the second terminal frame at the
                    // same index is a no-op. A tool index (raw `idx`) and a text index (stored under
                    // `TEXT_INDEX_KEY_OFFSET`) are tracked PER INDEX in `open_tools`, so the close
                    // routes to the correct block kind AND the correct index — a native stream's two
                    // terminal frames for one text item (`content_part.done` then `output_item.done`,
                    // same index) close it exactly once because the second frame finds the key gone.
                    if state.open_tools.remove(&idx) {
                        // This index was a (now-closed) function-call item.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    } else if state.open_tools.remove(&(idx + TEXT_INDEX_KEY_OFFSET)) {
                        // This index was an open text block; close THIS index once. Removing the
                        // per-index key (rather than clearing a global bool) lets a different text
                        // index stay open and close on its own terminal frame, and makes the paired
                        // `content_part.done`/`output_item.done` for the same item a no-op the
                        // second time.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    }
                    // Otherwise nothing is open at this index (e.g. the second terminal frame of a
                    // text item, or a `done` for an item we never opened): emit nothing.
                }
            }

            EVT_RESPONSE_COMPLETED | EVT_RESPONSE_FAILED | EVT_RESPONSE_INCOMPLETE => {
                // A terminal event ends the message. Any content block still open at this point
                // (a tool index tracked as a raw `idx`, or a text index tracked under
                // `TEXT_INDEX_KEY_OFFSET`) was opened with a BlockStart but never received its
                // matching `output_item.done`/`content_part.done` — e.g. the upstream cut the
                // stream off mid-block, or a `failed`/`incomplete` arrives while content is still
                // streaming. Pushing MessageStop without closing them emits an unbalanced
                // BlockStart-without-BlockStop, which a strict SDK reassembling the stream rejects.
                // Drain `open_tools` and emit a BlockStop for every still-open index BEFORE the
                // MessageStop, converting text keys (>= TEXT_INDEX_KEY_OFFSET) back to their IR
                // index. This closure is invoked in EVERY terminal sub-path (incl. the failed
                // early-return) right before the MessageStop is pushed.
                let close_open_blocks =
                    |out: &mut Vec<IrStreamEvent>, state: &mut crate::ir::StreamDecodeState| {
                        // Drain into a sorted Vec first: closing in ascending IR-index order keeps
                        // the emitted BlockStop sequence deterministic regardless of insertion order
                        // (text and tool keys interleave under the offset scheme).
                        let mut indices: Vec<usize> = state
                            .open_tools
                            .iter()
                            .map(|&key| {
                                if key >= TEXT_INDEX_KEY_OFFSET {
                                    key - TEXT_INDEX_KEY_OFFSET
                                } else {
                                    key
                                }
                            })
                            .collect();
                        state.open_tools.clear();
                        // Dedup AFTER sorting: a tool key (`N`) and a text key (`N +
                        // TEXT_INDEX_KEY_OFFSET`) both map back to the SAME IR index `N`, so without
                        // dedup a single output_index that was (erroneously, pre-fix) opened as both
                        // kinds would emit TWO BlockStop{N} — a duplicate `content_block_stop` the
                        // downstream Anthropic writer relays for an already-closed index. One
                        // BlockStop per distinct IR index, regardless of how many keys collapsed onto
                        // it. (The output_item.added / output_text.delta guards below also prevent the
                        // double-open in the first place; this dedup is the second, defensive layer.)
                        indices.sort_unstable();
                        indices.dedup();
                        for index in indices {
                            out.push(IrStreamEvent::BlockStop { index });
                        }
                    };

                if let Some(response_obj) = data.get("response") {
                    let status = response_obj
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    // A genuinely failed terminal stream must NOT be decoded as a successful
                    // end_turn — that would mask the upstream failure from a downstream client
                    // (e.g. an Anthropic client would see stop_reason=end_turn). Surface it as an
                    // explicit IrStreamEvent::Error so the failure propagates, then still terminate
                    // the stream so consumers do not hang.
                    if status == STATUS_FAILED {
                        let provider_signal = response_obj
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_str())
                            .or_else(|| {
                                response_obj
                                    .get("error")
                                    .and_then(|e| e.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .map(String::from)
                            .or_else(|| Some(SIGNAL_RESPONSE_FAILED.to_string()));
                        // Derive the breaker class from the captured provider signal rather than
                        // hardcoding ServerError: an auth/rate-limit/context-length failure that
                        // arrives mid-stream must classify the same way it would on the non-stream
                        // HTTP path, or the breaker takes the wrong disposition/failover. The
                        // fallback "response_failed" (no error code/type present) maps to the
                        // default ServerError bucket.
                        let class = class_for_response_failed(
                            provider_signal.as_deref().unwrap_or(SIGNAL_RESPONSE_FAILED),
                        );
                        out.push(IrStreamEvent::Error(IrError {
                            class,
                            provider_signal,
                            retry_after: None,
                        }));
                        close_open_blocks(&mut out, state);
                        out.push(IrStreamEvent::MessageStop);
                        return out;
                    }

                    // Enumerate the recognized statuses rather than defaulting unknown ones to a
                    // successful end_turn. An unrecognized status is treated as a terminal stop
                    // with no specific reason (None) rather than silently claiming success.
                    let stop_reason = match status {
                        STATUS_COMPLETED | "" => Some(crate::ir::IrStopReason::EndTurn),
                        // An `incomplete` is NOT a successful end_turn; map its machine-readable
                        // reason, or surface None (don't mask the truncation) when there is none.
                        STATUS_INCOMPLETE => response_obj
                            .get("incomplete_details")
                            .and_then(|d| d.get("reason"))
                            .and_then(|r| r.as_str())
                            .map(read_responses_incomplete_reason),
                        _ => None,
                    };

                    // Tool-use override, mirroring the non-streaming `read_response` (which flips a
                    // `completed` end_turn to `tool_use` when the output carries a function_call).
                    // Without this, a STREAMED Responses tool call terminated stop_reason=end_turn
                    // while the non-stream path said tool_use — so a cross-protocol client (OpenAI/
                    // Anthropic ingress) never saw the tool-call finish signal on the streaming path.
                    // The `response.completed` event carries the fully-assembled `output`, so detect a
                    // function_call item there and override only the successful end_turn cases.
                    let stop_reason = if stop_reason == Some(crate::ir::IrStopReason::EndTurn)
                        && response_obj
                            .get("output")
                            .and_then(|o| o.as_array())
                            .is_some_and(|items| {
                                items.iter().any(|it| {
                                    it.get("type").and_then(|t| t.as_str())
                                        == Some(ITEM_TYPE_FUNCTION_CALL)
                                })
                            }) {
                        Some(crate::ir::IrStopReason::ToolUse)
                    } else {
                        stop_reason
                    };

                    // Refusal override, mirroring the non-streaming `read_response`. A STREAMED
                    // Responses refusal does NOT arrive via `output_text.delta` — the refusal text
                    // appears ONLY in this terminal `response.completed` frame as an
                    // `output[].content[]` `{type:"refusal", refusal:"..."}` part (status stays
                    // `completed`). Without this scan the streaming path SILENTLY DROPPED the refusal
                    // text and left stop_reason=end_turn — the client saw an empty response with no
                    // refusal signal. Emit the refusal text as a Text block (opened here, closed by
                    // `close_open_blocks` below) and promote stop_reason end_turn -> Refusal so a
                    // non-Responses client still sees the refusal. Anthropic/Bedrock have no distinct
                    // refusal part, so a refusal is plain assistant text + a `refusal` stop there.
                    let mut saw_refusal = false;
                    if let Some(items) = response_obj.get("output").and_then(|o| o.as_array()) {
                        for (item_pos, item) in items.iter().enumerate() {
                            let Some(content) = item.get("content").and_then(|c| c.as_array())
                            else {
                                continue;
                            };
                            for block in content {
                                if block.get("type").and_then(|t| t.as_str()) != Some("refusal") {
                                    continue;
                                }
                                let Some(text) = block
                                    .get("refusal")
                                    .and_then(|r| r.as_str())
                                    .filter(|s| !s.is_empty())
                                else {
                                    continue;
                                };
                                saw_refusal = true;
                                // Open a Text block for the refusal text at this item's index, unless
                                // that index is already open (defensive — a refusal is normally the
                                // sole output) or the per-stream block cap is reached.
                                let idx = item_pos.min(MAX_OUTPUT_INDEX);
                                let text_key = idx + TEXT_INDEX_KEY_OFFSET;
                                if !state.open_tools.contains(&idx)
                                    && !state.open_tools.contains(&text_key)
                                    && state.open_tools.len() < MAX_OPEN_TOOLS
                                {
                                    state.open_tools.insert(text_key);
                                    out.push(IrStreamEvent::BlockStart {
                                        index: idx,
                                        block: crate::ir::IrBlockMeta::Text,
                                    });
                                    out.push(IrStreamEvent::BlockDelta {
                                        index: idx,
                                        delta: crate::ir::IrDelta::TextDelta(text.to_string()),
                                    });
                                }
                            }
                        }
                    }
                    let stop_reason =
                        if saw_refusal && stop_reason == Some(crate::ir::IrStopReason::EndTurn) {
                            Some(crate::ir::IrStopReason::Refusal)
                        } else {
                            stop_reason
                        };

                    let usage = response_obj
                        .get("usage")
                        .map(|u| {
                            let cached = read_cached_tokens(u);
                            crate::ir::IrUsage {
                                // NORMALIZE to the additive-cache convention: the Responses API's
                                // `input_tokens` is a TOTAL that already INCLUDES the cached prefix,
                                // so subtract the cached tokens to leave only the uncached input.
                                // `saturating_sub` guards an odd upstream where cached > input.
                                input_tokens: u
                                    .get("input_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0)
                                    .saturating_sub(cached.unwrap_or(0)),
                                output_tokens: u
                                    .get("output_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                cache_creation_input_tokens: None,
                                // H6: carry the streamed prompt-cache hit count
                                // (`usage.input_tokens_details.cached_tokens`) into the IR's
                                // read-side cache field so a streaming Responses terminal preserves
                                // the cache saving.
                                cache_read_input_tokens: cached,
                            }
                        })
                        .unwrap_or(crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        });

                    // Close any still-open content blocks BEFORE the MessageDelta so the emitted
                    // order is BlockStop* → MessageDelta → MessageStop, mirroring Anthropic's
                    // content_block_stop-before-message_delta sequencing.
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        // Responses API has no stop_sequence analog in its stream.
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                } else if event_type == EVT_RESPONSE_FAILED {
                    // Terminal failure event with no nested `response` object (e.g. a truncated SSE
                    // frame or a proxy that stripped the body). The wire `event_type` is the only
                    // failure signal available — honour it. Surfacing this as a successful end_turn
                    // would mask the upstream failure from downstream clients AND deny the breaker
                    // the failure signal, so we mirror the body-present failure arm above: emit an
                    // explicit Error followed by MessageStop.
                    // No nested response object → no error code/type to inspect. The only signal is
                    // the wire event_type; classify via the shared helper (which defaults the
                    // unrecognized "response_failed" sentinel to ServerError) so both response.failed
                    // arms derive their class through the same mapping.
                    let provider_signal = SIGNAL_RESPONSE_FAILED;
                    out.push(IrStreamEvent::Error(IrError {
                        class: class_for_response_failed(provider_signal),
                        provider_signal: Some(provider_signal.to_string()),
                        retry_after: None,
                    }));
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageStop);
                } else {
                    // Terminal completed/incomplete event with no nested `response` object. We must
                    // still terminate the translated stream with a MessageDelta + MessageStop so
                    // downstream consumers do not hang waiting for the end of the message.
                    //
                    // The wire `event_type` is the only status signal available — select the stop
                    // reason from it rather than hardcoding end_turn. A bodyless `incomplete` is NOT
                    // a successful end_turn: with no nested `incomplete_details.reason` to inspect
                    // there is no specific truncation reason to surface, so emit None (mirrors the
                    // body-present `incomplete`/no-details precedent above and the non-streaming
                    // `read_response`). Only a `completed` event maps to end_turn. (`failed` is
                    // handled by the branch above; this else covers `completed`/`incomplete`.)
                    let stop_reason = match event_type {
                        EVT_RESPONSE_COMPLETED => Some(crate::ir::IrStopReason::EndTurn),
                        EVT_RESPONSE_INCOMPLETE => None,
                        // No other event_type reaches this arm (the outer match guards the set and
                        // `response.failed` is handled above), so anything else is an unrecognized
                        // terminal with no specific reason.
                        _ => None,
                    };
                    let usage = crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };
                    close_open_blocks(&mut out, state);
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                }
            }

            _ => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("");

        // A non-streaming Responses body with `status:"failed"` is an upstream provider failure
        // (rate_limit, content_filter, server_error, etc.), NOT a parse failure. The writer emits
        // `{"status":"failed","output":[],"error":{...}}` — note `output` is a PRESENT EMPTY array,
        // not null/absent — so this MUST be handled before the `output`-array branch below, or an
        // empty `output:[]` would iterate zero items, fail the usage check, and mask the real error
        // as an internal `ir_parse` (ClientFault, no-retry) — the wrong breaker transition. Handle
        // failed bodies uniformly here whether `output` is `[]`, null, or absent. Surface the
        // upstream signal so the real error reaches the client and the breaker sees the correct
        // class via `class_for_response_failed`. Mirror the streaming `response.failed` arm: prefer
        // the `error.code` enum, fall back to `error.type`, then a generic `response_failed`.
        if status == STATUS_FAILED {
            let provider_signal = obj
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .or_else(|| {
                    obj.get("error")
                        .and_then(|e| e.get("type"))
                        .and_then(|t| t.as_str())
                })
                .map(String::from)
                .or_else(|| Some(SIGNAL_RESPONSE_FAILED.to_string()));
            // Same class as the streaming `response.failed` arms: derive the breaker class from the
            // captured provider signal rather than hardcoding ServerError, so an auth/rate-limit/
            // context-length failed body classifies correctly (right breaker disposition/failover).
            let class = class_for_response_failed(
                provider_signal.as_deref().unwrap_or(SIGNAL_RESPONSE_FAILED),
            );
            return Err(IrError {
                class,
                provider_signal,
                retry_after: None,
            });
        }

        let mut stop_reason: Option<crate::ir::IrStopReason> = match status {
            STATUS_COMPLETED => Some(crate::ir::IrStopReason::EndTurn),
            STATUS_INCOMPLETE => obj
                .get("incomplete_details")
                .and_then(|d| d.get("reason"))
                .and_then(|r| r.as_str())
                .map(read_responses_incomplete_reason),
            _ => None,
        };

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        // A refusal rides on a `refusal` content part with `status:"completed"`, so the refusal
        // SIGNAL is not in `status`. Track it here to promote `stop_reason` to `Refusal` below.
        let mut saw_refusal = false;
        if let Some(output_arr) = obj.get("output").and_then(|o| o.as_array()) {
            for item in output_arr {
                let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

                match item_type {
                    ITEM_TYPE_MESSAGE => {
                        if let Some(content_arr) = item.get("content").and_then(|c| c.as_array()) {
                            for block_item in content_arr {
                                let block_type = block_item
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or("");

                                if block_type == CONTENT_TYPE_OUTPUT_TEXT {
                                    if let Some(text) =
                                        block_item.get("text").and_then(|t| t.as_str())
                                    {
                                        content.push(crate::ir::IrBlock::Text {
                                            text: text.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                } else if block_type == "refusal" {
                                    // A model refusal rides on a `{type:"refusal", refusal:"..."}`
                                    // content part (the status stays `completed`). The prior reader
                                    // only matched `output_text`, SILENTLY DROPPING the refusal text.
                                    // Carry it as assistant Text so the explanation survives the
                                    // translation (Anthropic/Bedrock have no distinct refusal part —
                                    // a refusal is plain assistant text there). The refusal SIGNAL is
                                    // separately promoted onto `stop_reason` below.
                                    if let Some(text) =
                                        block_item.get("refusal").and_then(|t| t.as_str())
                                    {
                                        saw_refusal = true;
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

                    ITEM_TYPE_FUNCTION_CALL => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = item
                            .get("arguments")
                            .and_then(|a| a.as_str())
                            .unwrap_or("{}");
                        // Preserve the raw string on malformed JSON rather than dropping the tool
                        // arguments to Null (mirrors the OpenAI reader; avoids lossy translation).
                        let input = crate::json::parse_str(arguments)
                            .unwrap_or_else(|_| serde_json::Value::String(arguments.to_string()));

                        content.push(crate::ir::IrBlock::ToolUse {
                            id: call_id,
                            name,
                            input,
                            cache_control: None,
                        });
                    }

                    // H1 REASONING: a native Responses `reasoning` output item carries the model's
                    // chain-of-thought. The prior `_ => {}` DROPPED it, so a reasoning response lost
                    // its thinking entirely on any cross-protocol hop (Responses → Anthropic/Bedrock,
                    // which DO carry thinking). Read it into an `IrBlock::Thinking` so it survives the
                    // seam. The reasoning text lives in `content[].text` (`reasoning_text` parts) and/or
                    // `summary[].text` (`summary_text` parts); concatenate whichever is present (a real
                    // reasoning item carries one or the other). Responses has no `signature`, but it
                    // carries an opaque `encrypted_content` blob for multi-turn reasoning reuse — map it
                    // into the IR `signature` slot so a same-protocol round-trip preserves it (and a
                    // cross-protocol hop to a signature-carrying protocol keeps the opaque token).
                    //
                    // LOW (accepted, non-portable by nature): the IR `signature` slot is a single
                    // opaque token shared across protocols (Anthropic `thinking.signature`, Responses
                    // `encrypted_content`, Gemini `thoughtSignature`). These are each PROTOCOL-OPAQUE
                    // and vendor-scoped: an Anthropic signature carried into a Responses
                    // `encrypted_content` (or vice-versa) preserves the BYTES, but the blob is NOT
                    // re-feedable to the OTHER vendor's API — each vendor only accepts its own. So the
                    // token round-trips faithfully same-protocol and survives the seam as an opaque
                    // value, but cross-vendor reasoning-reuse (replaying a foreign vendor's signature)
                    // is inherently unsupported. No behavior change; documented so the limitation is
                    // explicit rather than an implied promise of cross-vendor reasoning continuation.
                    ITEM_TYPE_REASONING => {
                        let text = read_reasoning_text(item);
                        let signature = item
                            .get("encrypted_content")
                            .and_then(|s| s.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from);
                        // Skip a wholly-empty reasoning item (no text and no encrypted_content)
                        // rather than emitting a blank Thinking block.
                        if !text.is_empty() || signature.is_some() {
                            content.push(crate::ir::IrBlock::Thinking {
                                text,
                                signature,
                                redacted: false,
                                cache_control: None,
                            });
                        }
                    }

                    _ => {}
                }
            }
        } else {
            // `status:"failed"` is handled by the early return above, so a missing/non-array
            // `output` here is a genuine parse failure (malformed body).
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                retry_after: None,
            });
        }

        // Promote a successful end_turn to tool_use when the assembled content carries a tool call,
        // mirroring the streaming `response.completed` arm. Guard the override on `end_turn` ONLY: an
        // `incomplete` status (max_tokens/safety/other truncation reason) means the model was cut off
        // mid-output — even if a partial function_call survived, the turn did NOT cleanly finish on a
        // tool call, and clobbering `max_tokens`/`safety` with `tool_use` would tell the client the
        // call is complete and deny the truncation signal to the breaker. Only the clean-finish case
        // (`end_turn`) is promoted; any other reason is left untouched.
        if stop_reason == Some(crate::ir::IrStopReason::EndTurn)
            && content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. }))
        {
            stop_reason = Some(crate::ir::IrStopReason::ToolUse);
        }

        // A `completed` response that carried a `refusal` part is a refusal, not a clean end_turn.
        // Promote the typed `Refusal` stop_reason (which the Anthropic/OpenAI writers translate) so
        // the refusal signal survives even though the Responses `status` was `completed`.
        if saw_refusal && stop_reason == Some(crate::ir::IrStopReason::EndTurn) {
            stop_reason = Some(crate::ir::IrStopReason::Refusal);
        }

        // Tolerate an absent `usage` object leniently — zero-default rather than hard-erroring,
        // mirroring all five sibling readers (openai_chat.rs, gemini, cohere, etc.). A missing
        // `usage` on an otherwise valid 200 is an upstream response-format quirk (a mock/staging/
        // proxy backend that omits it), NOT a client mistake: a `ClientError` here would make
        // forward.rs discard a valid body and emit a spurious 500.
        let usage_val = obj.get("usage");

        let cached = usage_val.and_then(read_cached_tokens);
        let usage = crate::ir::IrUsage {
            // NORMALIZE to the additive-cache convention: the Responses API's `input_tokens` is a
            // TOTAL that already INCLUDES the cached prefix, so subtract the cached tokens to leave
            // only the uncached input. `saturating_sub` guards an odd upstream where cached > input.
            input_tokens: usage_val
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .saturating_sub(cached.unwrap_or(0)),
            output_tokens: usage_val
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            // H6: the Responses API reports prompt-cache hits under
            // `usage.input_tokens_details.cached_tokens`. Map it into the IR's
            // `cache_read_input_tokens` (the read-side cache field Bedrock already uses) so the cache
            // saving survives a cross-protocol hop instead of being dropped. No new IR field is added.
            cache_read_input_tokens: cached,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response's identity so a same-protocol (responses → responses)
        // passthrough preserves `id`/`created_at` exactly. The Responses API names its creation
        // timestamp `created_at` (NOT `created`, which is the Chat Completions field); we map it
        // into the shared IR `created` slot. `system_fingerprint`/`stop_sequence` have no analog in
        // the Responses shape, so they stay `None`.
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        let created = obj.get("created_at").and_then(|c| c.as_u64());

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}
