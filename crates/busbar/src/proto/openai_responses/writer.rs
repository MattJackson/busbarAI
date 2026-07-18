use super::*;

impl ProtocolWriter for ResponsesWriter {
    fn upstream_path(&self) -> &str {
        "/v1/responses"
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        if !req.system.is_empty() {
            let instructions: String = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !instructions.is_empty() {
                out.insert("instructions".to_string(), serde_json::json!(instructions));
            }
        }

        let mut input_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            match msg.role {
                crate::ir::IrRole::User | crate::ir::IrRole::Assistant => {
                    let role_str = if msg.role == crate::ir::IrRole::User {
                        "user"
                    } else {
                        "assistant"
                    };

                    let mut content_arr: Vec<serde_json::Value> = Vec::new();
                    // function_call / function_call_output items are flat top-level `input`
                    // entries in the Responses API, NOT nested inside a message's `content`.
                    // Collect them separately so the enclosing assistant `message` is emitted
                    // FIRST (and only when it actually has content), with the tool items appended
                    // after it in order — matching the conversation order the assistant produced.
                    let mut tool_items: Vec<serde_json::Value> = Vec::new();
                    // Fix #6: prior-turn reasoning re-emitted as top-level `reasoning` input items,
                    // placed BEFORE the message they precede (matching how the model produced them).
                    let mut reasoning_items: Vec<serde_json::Value> = Vec::new();
                    for block in &msg.content {
                        match block {
                            crate::ir::IrBlock::Text { text, .. } => {
                                let type_str = if msg.role == crate::ir::IrRole::User {
                                    CONTENT_TYPE_INPUT_TEXT
                                } else {
                                    CONTENT_TYPE_OUTPUT_TEXT
                                };
                                content_arr.push(serde_json::json!({
                                    "type": type_str,
                                    "text": text
                                }));
                            }
                            crate::ir::IrBlock::Image { source, .. } => match source {
                                // L5: a Responses-produced vendor reference is a `file_id` — re-emit
                                // the native `input_image.file_id` form (a data URI would corrupt it).
                                crate::ir::IrImageSource::Vendor { vendor, value }
                                    if *vendor == VENDOR_NAME =>
                                {
                                    if let Some(id) = value.get("file_id").and_then(|i| i.as_str())
                                    {
                                        content_arr.push(serde_json::json!({
                                            "type": "input_image",
                                            "file_id": id
                                        }));
                                    }
                                }
                                // A foreign vendor reference (a Bedrock s3Location) has no Responses
                                // analog — drop with a warn rather than corrupt the block.
                                crate::ir::IrImageSource::Vendor { .. } => {
                                    tracing::warn!(
                                        "dropping unresolvable foreign vendor image reference on \
                                         Responses egress: no cross-vendor analog"
                                    );
                                }
                                // A URL/base64 image reconstructs the original `image_url`.
                                url_or_b64 => {
                                    if let Some(image_url) = super::image_url_from_ir(url_or_b64) {
                                        content_arr.push(serde_json::json!({
                                            "type": "input_image",
                                            "image_url": image_url
                                        }));
                                    }
                                }
                            },
                            crate::ir::IrBlock::Json(_) => {
                                // Structured-json (Bedrock tool-result content) has no Responses
                                // input-content shape; dropped here.
                            }
                            crate::ir::IrBlock::ToolUse {
                                id, name, input, ..
                            } => {
                                // Emit a raw `Value::String` (unparseable/streaming-partial args) verbatim
                                // rather than JSON-encoding it a second time — same as the Chat writer.
                                let args_str =
                                    crate::proto::openai_chat::tool_arguments_to_string(input);
                                tool_items.push(serde_json::json!({
                                    "type": ITEM_TYPE_FUNCTION_CALL,
                                    "call_id": id,
                                    "name": name,
                                    "arguments": args_str
                                }));
                            }
                            crate::ir::IrBlock::ToolResult {
                                tool_use_id,
                                content,
                                ..
                            } => {
                                // Concatenate adjacent text blocks WITHOUT a separator: a space
                                // between fragments corrupts base64 / split JSON payloads.
                                // Mirrors `openai_chat.rs::write_request`'s tool_result concat fix.
                                let output_text = content
                                    .iter()
                                    .filter_map(|b| match b {
                                        crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                        // A non-Text ToolResult block is a Bedrock json-tool-result
                                        // sentinel with no Responses analog. Drop WITH a warn
                                        // (drop-with-warn convention) instead of vanishing silently.
                                        other => {
                                            if super::is_json_tool_result_block(other) {
                                                tracing::warn!(
                                                    "dropping structured json tool-result block on \
                                                     Responses egress: a Bedrock `{{\"json\":...}}` \
                                                     tool-result has no cross-protocol analog and is \
                                                     NOT emitted"
                                                );
                                            }
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .concat();

                                tool_items.push(serde_json::json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": output_text
                                }));
                            }
                            // Fix #6: a prior-turn Thinking block re-emits as a top-level Responses
                            // `reasoning` INPUT item (a sibling of the message, NOT a content block),
                            // so a Responses->Responses round-trip preserves reasoning and a
                            // reasoning block decoded from another protocol survives onto Responses
                            // egress. Mirrors the `write_response` reasoning item shape: a REDACTED
                            // reasoning block holds opaque encrypted bytes with no plaintext analog
                            // on the Responses surface, so it is dropped rather than leaked.
                            crate::ir::IrBlock::Thinking {
                                text,
                                signature,
                                redacted,
                                ..
                            } if !*redacted => {
                                let emit_sig = signature.as_deref();
                                // A wholly-empty reasoning block (no text, no signature) emits no item.
                                if !text.is_empty() || emit_sig.is_some() {
                                    let mut item = serde_json::Map::new();
                                    item.insert(
                                        "type".to_string(),
                                        serde_json::json!(ITEM_TYPE_REASONING),
                                    );
                                    item.insert(
                                        "id".to_string(),
                                        serde_json::json!(synthesize_item_id(ITEM_ID_PREFIX_RS)),
                                    );
                                    item.insert(
                                        "summary".to_string(),
                                        serde_json::Value::Array(Vec::new()),
                                    );
                                    item.insert(
                                        "content".to_string(),
                                        serde_json::json!([
                                            { "type": CONTENT_TYPE_REASONING_TEXT, "text": text }
                                        ]),
                                    );
                                    if let Some(sig) = emit_sig {
                                        item.insert(
                                            "encrypted_content".to_string(),
                                            serde_json::json!(sig),
                                        );
                                    }
                                    reasoning_items.push(serde_json::Value::Object(item));
                                }
                            }
                            // A REDACTED reasoning block (opaque encrypted bytes, no plaintext
                            // analog on Responses) is dropped rather than leaked as `reasoning_text`.
                            crate::ir::IrBlock::Thinking { .. } => {}
                        }
                    }

                    // Reasoning items come BEFORE the message they precede.
                    input_arr.extend(reasoning_items);

                    // Emit the assistant/user `message` wrapper only when it carries content. A
                    // turn that is purely a tool call must NOT produce a spurious
                    // `{role, content: []}` item — the Responses API rejects empty-content
                    // message items.
                    if !content_arr.is_empty() {
                        let mut msg_obj = serde_json::Map::new();
                        msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                        msg_obj
                            .insert("content".to_string(), serde_json::Value::Array(content_arr));
                        input_arr.push(serde_json::Value::Object(msg_obj));
                    }
                    // Then the flat tool items, in order, AFTER the message they belong to.
                    input_arr.extend(tool_items);
                }

                crate::ir::IrRole::Tool => {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } = block
                        {
                            // Concatenate adjacent text blocks WITHOUT a separator: a space
                            // between fragments corrupts base64 / split JSON payloads.
                            // Mirrors `openai_chat.rs::write_request`'s tool_result concat fix.
                            let output_text = content
                                .iter()
                                .filter_map(|b| match b {
                                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                    // A non-Text ToolResult block is a Bedrock json-tool-result
                                    // sentinel with no Responses analog. Drop WITH a warn
                                    // (drop-with-warn convention) instead of vanishing silently.
                                    other => {
                                        if super::is_json_tool_result_block(other) {
                                            tracing::warn!(
                                                "dropping structured json tool-result block on \
                                                 Responses egress: a Bedrock `{{\"json\":...}}` \
                                                 tool-result has no cross-protocol analog and is NOT \
                                                 emitted"
                                            );
                                        }
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .concat();

                            input_arr.push(serde_json::json!({
                                "type": "function_call_output",
                                "call_id": tool_use_id,
                                "output": output_text
                            }));
                        }
                    }
                }

                crate::ir::IrRole::System => {}
            }
        }

        if !input_arr.is_empty() {
            out.insert("input".to_string(), serde_json::Value::Array(input_arr));
        }

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                tool_obj.insert("parameters".to_string(), params);

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Emit `tool_choice` (PF-H1) in the Responses native shape when present so a forced/targeted
        // directive translated from another protocol does not silently degrade to `auto`.
        if let Some(tc) = &req.tool_choice {
            out.insert("tool_choice".to_string(), write_responses_tool_choice(tc));
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert(
                "max_output_tokens".to_string(),
                serde_json::json!(max_tokens),
            );
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling control: the Responses API supports `top_p` (but no top_k / stop), so
        // only top_p is emitted. A cross-protocol source's top_k/stop have no Responses target and
        // are dropped (documented in the reader).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        // LOW: the Responses create API models no `top_k` (only `top_p`). A cross-protocol source's
        // `top_k` has no Responses target. Rather than silently dropping it, emit a `warn!` so the
        // lossy-by-target omission is observable in logs (mirrors the `stop`-drop warn below and the
        // anthropic/bedrock writers' drop-with-warn contract). Nothing is written to `out`.
        if req.top_k.is_some() {
            tracing::warn!(
                "responses writer: the /v1/responses API models no `top_k` parameter; \
                 dropping top_k (lossy-by-target)"
            );
        }

        // SAMPLING (Phase 0): the Responses create API does NOT model `frequency_penalty`,
        // `presence_penalty`, `seed`, or `n` (verified against the official openai-python
        // `ResponseCreateParamsBase`: only `temperature`/`top_p`/`top_logprobs`/`text` are present).
        // They are lossy-by-target on this surface, so they are intentionally NOT emitted — emitting an
        // unsupported param would 400 a real `/v1/responses` call. A cross-protocol source that carried
        // them simply loses them here (a target-capability omission, not a leak).

        // M5 STOP: the Responses create API has NO `stop`/`stop_sequences` param (same verification as
        // sampling above — no stop field exists on `ResponseCreateParamsBase`). So stop sequences
        // cannot be expressed on this surface. Rather than silently dropping them, emit a `warn!` so
        // the lossy-by-target omission is observable in logs (mirrors the anthropic/bedrock writers'
        // drop-with-warn contract). Nothing is written to `out`.
        if !req.stop.is_empty() {
            tracing::warn!(
                stop_count = req.stop.len(),
                "responses writer: the /v1/responses API models no `stop` parameter; \
                 dropping {} stop sequence(s) (lossy-by-target)",
                req.stop.len()
            );
        }

        // M1 response_format → Responses `text.format`. The Responses surface carries structured-output
        // config under `text.format` (flat json_schema shape), NOT a top-level `response_format`. Build
        // the `format` value from the canonical IR shape and MERGE it into any `text` object already
        // forwarded via `extra` (e.g. one carrying `verbosity`), so a request that pairs a structured
        // output with another `text` knob keeps both. `extra` is applied FIRST (below) so this merge
        // sees the forwarded remainder; then this overwrites `text` with the merged object.
        if let Some(rf) = &req.response_format {
            let format = write_text_format(rf);
            // Start from any `text` object forwarded through extra (the format-stripped remainder the
            // reader preserved), so non-`format` sub-keys like `verbosity` survive alongside `format`.
            let mut text_obj = req
                .extra
                .get("text")
                .and_then(|t| t.as_object())
                .cloned()
                .unwrap_or_default();
            text_obj.insert("format".to_string(), format);
            out.insert("text".to_string(), serde_json::Value::Object(text_obj));
            // The extra-forwarding loop below SKIPS `text` when `response_format` is Some (see its
            // guard), so the bare extra `text` cannot clobber this merged object back to format-less.
        }

        // `stream` is a modeled key (excluded from `extra`), so it must be emitted explicitly or it
        // is silently dropped — a `stream: true` request would otherwise be answered non-streaming,
        // stalling the SSE translation loop. Mirrors the OpenAI writer.
        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // The reasoning carry in the Responses spelling: `reasoning: {effort}`. A numeric budget
        // (Anthropic/Gemini source) is bucketized through the effort table. Emitted from the typed
        // field only when `extra` does not carry a verbatim native `reasoning` object (the extra
        // overlay below would forward the original, and must win: it can carry `summary` too).
        if let Some(ask) = req.reasoning {
            if !req.extra.contains_key("reasoning") {
                let table = req
                    .reasoning_budgets
                    .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
                out.insert(
                    "reasoning".to_string(),
                    serde_json::json!({"effort": ask.to_effort(table).as_openai_reasoning_effort()}),
                );
            }
        }

        for (key, value) in &req.extra {
            // `text` from extra carries only the non-`format` remainder (verbosity, etc.). When the IR
            // carried a `response_format`, the merged `text` (remainder + format) was already inserted
            // above; do NOT let the bare extra `text` clobber it back to format-less. When the IR
            // carried NO response_format, fall through and forward the extra `text` verbatim.
            if key == "text" && req.response_format.is_some() {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        // The stream's opening event resets the per-stream `sequence_number` counter so each stream's
        // sequence starts at 0. Every event this writer emits then carries a top-level
        // `sequence_number` injected just before return (see the closing `map` below). The reader
        // gates `MessageStart` on `state.started`, so exactly one reset happens per stream.
        if matches!(ev, IrStreamEvent::MessageStart { .. }) {
            self.reset_sequence_number();
        }

        let emitted: Option<(String, serde_json::Value)> = match ev {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                // The official OpenAI Responses SDK reads `response.id`/`created_at`/`model` from the
                // opening `response.created` event to construct its Response object; a stub omitting
                // them yields null identity fields and breaks event correlation. Forward the captured
                // identity when present (same-protocol passthrough), otherwise synthesize a
                // protocol-correct `resp_` id and the current unix time (cross-protocol, where
                // `translate_event` strips these to None) so the event stays SDK-valid.
                let mut resp_obj = serde_json::Map::new();
                let id = id.clone().unwrap_or_else(synthesize_response_id);
                // Carry this stream's id forward so the terminal events (and any failure) replay
                // the SAME `response.id` — a native stream never changes its id mid-flight.
                self.set_response_id(&id);
                let created_at = created.unwrap_or_else(now_unix_secs);
                // Carry this stream's `created_at` forward so the terminal events (and any failure)
                // replay the SAME timestamp — a native stream's `created_at` is constant across
                // every event.
                self.set_created_at(created_at);
                resp_obj.insert("id".to_string(), serde_json::json!(id));
                resp_obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
                resp_obj.insert("created_at".to_string(), serde_json::json!(created_at));
                resp_obj.insert("status".to_string(), serde_json::json!(STATUS_IN_PROGRESS));
                // `Response.model` is a REQUIRED non-nullable string in the official SDK; emit it
                // unconditionally with the DEFAULT_MODEL fallback when the IR carries none (a
                // cross-protocol stream where `translate_event` strips the model to None) rather
                // than omitting the key — omission breaks strict decoders and is a proxy tell.
                let model_name = model.as_deref().unwrap_or(DEFAULT_MODEL);
                // Carry this stream's model forward so the terminal events (and any failure) replay
                // the SAME `model` — a native stream's `model` is constant across every event.
                self.set_model(model_name);
                resp_obj.insert("model".to_string(), serde_json::json!(model_name));
                // The native `response.created` carries the FULL Response skeleton, not just its
                // identity: an official SDK constructs a `Response` object from this event and reads
                // `usage`/`output`/`error` unconditionally. At stream start there are no tokens yet
                // and no failure, so emit `usage: null`, an empty `output` array, and `error: null`
                // — present-but-empty, NOT omitted. Omitting `usage` left the SDK's `Response.usage`
                // unpopulated (or crashed strict decoders) on the opening chunk.
                resp_obj.insert("output".to_string(), serde_json::json!([]));
                resp_obj.insert("error".to_string(), serde_json::Value::Null);
                resp_obj.insert("usage".to_string(), serde_json::Value::Null);
                Some((
                    EVT_RESPONSE_CREATED.to_string(),
                    serde_json::json!({ "type": EVT_RESPONSE_CREATED, "response": resp_obj }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // A native /v1/responses stream brackets a text part inside a `message` output
                    // item: `output_item.added(message)` opens it, the `output_text.delta`s carry
                    // the body, and `output_item.done(message)` closes it. The official SDK builds
                    // `response.output[]` from the added/done pair, so without an enclosing item the
                    // assembled Response has an empty output array even though deltas streamed.
                    // Previously the Text BlockStart returned None, leaving the deltas orphaned.
                    //
                    // The `ProtocolWriter` trait emits at most ONE wire frame per IR event, so the
                    // intermediate `content_part.added` sub-frame (which would need a second frame
                    // for this single BlockStart) cannot be produced here; the message item's
                    // `output_item.added`/`.done` pair is the load-bearing lifecycle the SDK reads
                    // to materialize the assistant message, and the deltas already carry
                    // `content_index: 0`. Track the open text index (capped) so the matching
                    // BlockStop emits `output_item.done` for THIS index only.
                    if !self.open_text_item(*index) {
                        return None;
                    }
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_MSG, *index);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_MESSAGE,
                                "id": item_id,
                                "role": "assistant",
                                "status": STATUS_IN_PROGRESS,
                                "content": []
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // `item_id` (a stable per-output-item id, `fc_…` for a function-call item) is
                    // carried on the native `output_item.added`/`.done` pair so a client correlates the
                    // item's lifecycle. Synthesize it deterministically from the output index so the
                    // matching `.done` (which sees only the index) reconstructs the same id.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_FC, *index);
                    // Record the open function-call index so the matching `BlockStop` emits
                    // `output_item.done` for THIS index only — a text block's BlockStop (whose
                    // BlockStart produced no `output_item.added`) must emit no `done`.
                    self.mark_tool_open(*index);
                    // Capture call_id/name now so the matching `output_item.done` can emit the
                    // fully finalized item (native `done` carries call_id/name/arguments; the IR
                    // BlockStop carries only the index).
                    self.record_tool_meta(*index, id, name);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_FUNCTION_CALL,
                                "id": item_id,
                                "call_id": id,
                                "name": name
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::Thinking => {
                    // H1 REASONING (stream): open a native Responses `reasoning` output item. The IR
                    // Thinking BlockStart carries only the index; emit `output_item.added` typed
                    // "reasoning" with a stable `rs_…` item_id (so the matching `.done` reconstructs
                    // it), tracking the open index so BlockStop closes it as a reasoning item. The
                    // prior `None` DROPPED the reasoning lifecycle entirely.
                    if !self.open_reasoning_item(*index) {
                        return None;
                    }
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_RS, *index);
                    Some((
                        EVT_OUTPUT_ITEM_ADDED.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_ADDED,
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": ITEM_TYPE_REASONING,
                                "id": item_id,
                                "summary": [],
                                "content": []
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) if !text.is_empty() => {
                    // Native `output_text.delta` carries `item_id` (the enclosing message item) and
                    // `content_index` (the index of the text part within that item). The IR delta
                    // carries only the output index; synthesize the message `item_id` deterministically
                    // from it (matching the `msg_…` part), and emit `content_index: 0` — the single
                    // text content part of the item.
                    //
                    // Accumulate the fragment so the matching `BlockStop` can assemble the message
                    // item with its COMPLETE `output_text` for the terminal `response.output` array.
                    self.append_text(*index, text);
                    Some((
                        EVT_OUTPUT_TEXT_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_TEXT_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_MSG, *index),
                            "content_index": 0,
                            "delta": text
                        }),
                    ))
                }
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    // Accumulate the arguments fragment so the matching `output_item.done` emits the
                    // COMPLETE arguments string the native event (and the SDK's `event.item.arguments`)
                    // carries.
                    self.append_tool_arguments(*index, json_str);
                    Some((
                        EVT_FUNCTION_CALL_ARGS_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_FUNCTION_CALL_ARGS_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_FC, *index),
                            "delta": json_str
                        }),
                    ))
                }
                &crate::ir::IrDelta::TextDelta(_) => None,
                crate::ir::IrDelta::ThinkingDelta(text) if !text.is_empty() => {
                    // H1 REASONING (stream): emit the native `response.reasoning_text.delta` for the
                    // reasoning item at this index, accumulating the fragment so the matching
                    // BlockStop assembles the complete reasoning item. The prior `None` DROPPED the
                    // streamed chain-of-thought. `content_index: 0` — the single reasoning content
                    // part of the item.
                    self.append_reasoning(*index, text);
                    Some((
                        EVT_REASONING_TEXT_DELTA.to_string(),
                        serde_json::json!({
                            "type": EVT_REASONING_TEXT_DELTA,
                            "output_index": index,
                            "item_id": self.item_id_for(ITEM_ID_PREFIX_RS, *index),
                            "content_index": 0,
                            "delta": text
                        }),
                    ))
                }
                // An empty ThinkingDelta carries no content (drop it), and Responses has no streaming
                // analog for a thinking `SignatureDelta` (the signature rides on the item's
                // `encrypted_content`, not a stream delta) — so both emit no frame.
                &crate::ir::IrDelta::ThinkingDelta(_)
                | crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_) => None,
                // L2-5: the Responses streaming surface has no confirmable citation/annotation
                // delta shape to map this onto, so suppress rather than synthesize one (the
                // citation stays in the IR and is re-emitted by protocols that model streaming
                // citations). No panic on this otherwise-unhandled variant.
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Responses streaming logprobs (inside `output_text` events) are out of the 1.2
                // OpenAI<->Gemini scope; dropped rather than emitted in a non-native shape.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer output index, not the block kind. A
                // native Responses stream emits `response.output_item.done` ONLY for an item it
                // previously `output_item.added`, and the `.done` type must match the `.added` type.
                // This writer opens an `output_item.added` for both message (text) and function-call
                // items, so each must close with a correctly-typed `output_item.done`. Emitting
                // `output_item.done` with a hardcoded type — as a prior revision did, always typing
                // it `type:"function_call"` — mis-typed every text item's close: an unmatched lifecycle
                // event (a `done` with no prior `added`) AND a text response mis-typed as a
                // function call, both of which break a typed Responses SDK and are deterministic
                // distinguishability tells.
                //
                // So consult the per-stream open sets: a function-call index closes with an
                // `output_item.done` typed "function_call"; a text index (opened by the Text
                // BlockStart with `output_item.added` typed "message") closes with an
                // `output_item.done` typed "message"; any other (never-opened) index emits NOTHING.
                //
                // NOTE: this arm must YIELD its `Option` as the match value (never `return` it), so
                // the closing `emitted.map(...)` tail injects the top-level `sequence_number` every
                // native Responses event carries — an early `return Some(..)` would skip it.
                if self.take_reasoning_open(*index) {
                    // H1 REASONING (stream): close the reasoning item opened by the Thinking
                    // BlockStart. Emit `output_item.done` typed "reasoning" with the SAME `rs_…`
                    // item_id and the assembled reasoning text under a `content[]` `reasoning_text`
                    // part. Record the finalized item so the terminal `response.completed` emits it in
                    // `output[]`. The prior writer dropped reasoning entirely, so a reasoning stream
                    // reassembled to an OpenAI/Anthropic client lost the chain-of-thought.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_RS, *index);
                    let text = self.take_reasoning_accum(*index);
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_REASONING,
                        "id": item_id,
                        "summary": [],
                        "content": [
                            { "type": CONTENT_TYPE_REASONING_TEXT, "text": text }
                        ]
                    });
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else if self.take_tool_open(*index) {
                    // Native `response.output_item.done` carries the SAME stable `item_id` as the
                    // matching `output_item.added` (so a client correlates the `added → done`
                    // lifecycle) plus the FULLY finalized `item` object: a typed SDK reads
                    // `event.item.call_id`/`.name`/`.arguments` off the done event to reconstruct the
                    // tool invocation. Emit all three from the per-stream accumulator (call_id/name
                    // captured on `output_item.added`, arguments concatenated from the delta frames).
                    // The function-call `output_item.added` used `item_id_for("fc", index)`, so the
                    // cached id reconstructs the matching pair here. A poisoned-lock-empty accumulator
                    // degrades to empty-string fields rather than panicking.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_FC, *index);
                    let accum = self.take_tool_accum(*index).unwrap_or_default();
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_FUNCTION_CALL,
                        "id": item_id,
                        "call_id": accum.call_id,
                        "name": accum.name,
                        "arguments": accum.arguments,
                    });
                    // Record the finalized function-call item so the terminal `response.completed`/
                    // `response.incomplete` event emits the fully assembled `output[]` array (the
                    // SDK reads `event.response.output` to materialize `Response.output`).
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else if self.take_text_open(*index) {
                    // Close the message item opened by the Text BlockStart. The same cached `msg_…`
                    // id (also carried on every `output_text.delta`) reconstructs the matching
                    // `added → done` pair the SDK uses to finalize `response.output[]`. The native
                    // `output_item.done` for a message item carries the assembled `output_text`
                    // content part with the COMPLETE text the deltas delivered (the SDK accumulates
                    // `Response.output_text` from it), so emit the accumulated text rather than an
                    // empty content array.
                    let item_id = self.item_id_for(ITEM_ID_PREFIX_MSG, *index);
                    let text = self.take_text_accum(*index);
                    let item = serde_json::json!({
                        "type": ITEM_TYPE_MESSAGE,
                        "id": item_id,
                        "role": "assistant",
                        "status": STATUS_COMPLETED,
                        "content": [
                            { "type": CONTENT_TYPE_OUTPUT_TEXT, "text": text, "annotations": [] }
                        ]
                    });
                    // Record the finalized message item so the terminal event emits the fully
                    // assembled `output[]` array.
                    self.record_output_item(*index, item.clone());
                    Some((
                        EVT_OUTPUT_ITEM_DONE.to_string(),
                        serde_json::json!({
                            "type": EVT_OUTPUT_ITEM_DONE,
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else {
                    // Nothing open at this index (e.g. a repeated BlockStop, or an index whose
                    // BlockStart was suppressed by the cardinality cap): emit no frame.
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                // Map IR stop reasons to Responses statuses. An unknown/None reason defaults to
                // `completed` (the safe choice) rather than `failed`: a future IR reason (e.g. a
                // new `refusal`) that did NOT explicitly signal an error must not be misclassified
                // as a failed response, which would trigger client-side error handling for a
                // successful turn. Genuine failures arrive via IrStreamEvent::Error, not here.
                let status = stop_reason
                    .map(write_responses_status)
                    .unwrap_or(STATUS_COMPLETED);

                let mut resp_obj = serde_json::Map::new();
                // The native `response.completed`/`response.incomplete` terminal event ALWAYS
                // carries `id` (a `resp_…` string) and `created_at` (unix seconds) in its inner
                // `response` object; the official Python/Node SDK reads `event.response.id` on the
                // terminal event to finalize the `Response`, and strict typed decoders raise on a
                // missing `id`/`created_at`. A real OpenAI stream never sends a terminal event
                // without an `id`, so omitting it is also a distinguishability tell. The IR
                // `MessageDelta` carries no identity, so REPLAY the id captured on this stream's
                // opening `MessageStart` (stored in `response_id`) so `response.completed`/
                // `response.incomplete` carries the SAME `id` as `response.created` — a native
                // stream never changes its id mid-flight, and the SDK reads `event.response.id` on
                // the terminal event to finalize the `Response`. Only if the cell is unexpectedly
                // empty (a malformed stream whose terminal event preceded `MessageStart`, or a
                // poisoned lock) do we fall back to synthesizing a fresh id so the event stays
                // structurally valid.
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                resp_obj.insert("id".to_string(), serde_json::json!(response_id));
                resp_obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
                // Replay the `created_at` captured on this stream's opening `MessageStart` so the
                // terminal event carries the SAME timestamp as `response.created`. The IR
                // `MessageDelta` carries no identity, so a direct `now_unix_secs()` here would emit
                // a later wall-clock value than the opening event — a detectable proxy tell. Fall
                // back to the current time only if the cell was never populated.
                resp_obj.insert(
                    "created_at".to_string(),
                    serde_json::json!(self.carried_created_at()),
                );
                resp_obj.insert("status".to_string(), serde_json::json!(status));
                // Replay the `model` captured on this stream's opening `MessageStart` so the
                // terminal event's inner `response` carries the SAME required non-nullable `model`
                // as `response.created`. The IR `MessageDelta` carries no model, and omitting it
                // fails a strict SDK decoder and is a distinguishability tell; `carried_model`
                // falls back to DEFAULT_MODEL only if the cell was never populated.
                resp_obj.insert("model".to_string(), serde_json::json!(self.carried_model()));

                if status == STATUS_INCOMPLETE {
                    let reason = stop_reason
                        .map(write_responses_incomplete_reason)
                        .unwrap_or(INCOMPLETE_REASON_OTHER);
                    let mut incomplete_details = serde_json::Map::new();
                    incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
                    resp_obj.insert(
                        "incomplete_details".to_string(),
                        serde_json::Value::Object(incomplete_details),
                    );
                }

                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but the Responses API's `input_tokens` is a TOTAL that includes the cached
                // prefix, so add `cache_read` back.
                let input_total = usage
                    .input_tokens
                    .saturating_add(usage.cache_read_input_tokens.unwrap_or(0))
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let mut usage_map = serde_json::Map::new();
                usage_map.insert("input_tokens".to_string(), serde_json::json!(input_total));
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                // H6: surface the IR read-side cache count on the streaming terminal as the
                // Responses-native `usage.input_tokens_details.cached_tokens` (only when present), so a
                // cross-protocol stream carrying a cache hit reports it to a Responses client just as
                // the non-stream body does. Omitted when absent (no `cached_tokens: 0`).
                if let Some(cached) = usage.cache_read_input_tokens {
                    usage_map.insert(
                        "input_tokens_details".to_string(),
                        serde_json::json!({ "cached_tokens": cached }),
                    );
                }
                resp_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                // The native terminal `response.completed`/`response.incomplete` event carries the
                // FULLY assembled inner `response` object: the official Python/Node SDK reads
                // `event.response.output` to finalize the assembled `Response`, and `output` is a
                // REQUIRED field a strict typed decoder raises on when absent. The writer recorded
                // each finalized item (message text parts and function-call items) into
                // `output_items` as the matching `BlockStop` fired, so drain that index-ordered
                // buffer here — a `completed` response with nonzero `usage.output_tokens` but an
                // EMPTY `output` is a shape real OpenAI never emits and breaks SDK consumers that
                // read the assembled output off the completed event. The buffer is empty (yielding
                // `[]`) only for a genuinely output-less turn or a poisoned lock. `error` is
                // likewise REQUIRED and `null` on a non-failed terminal event (a genuine failure
                // arrives via IrStreamEvent::Error → `response.failed`, never this arm).
                resp_obj.insert(
                    "output".to_string(),
                    serde_json::Value::Array(self.drain_output_items()),
                );
                resp_obj.insert("error".to_string(), serde_json::Value::Null);

                // The terminal event's NAME and inner `type` MUST agree with the inner
                // `response.status`: a native /v1/responses stream emits `response.completed` for a
                // completed response and a DISTINCT `response.incomplete` for a truncated/safety-
                // stopped one, and the official Python/Node SDKs dispatch on the event `type`
                // (`ResponseCompletedEvent` vs `ResponseIncompleteEvent`). Emitting a
                // `response.completed` envelope around an inner `status:"incomplete"` (plus
                // `incomplete_details`) is a shape impossible from real OpenAI and mislabels a
                // max_tokens-truncated or safety-stopped generation to the client. So select the
                // envelope from `status`. `status` is only ever `completed`/`incomplete` here
                // (genuine failures arrive via IrStreamEvent::Error → `response.failed`, never this
                // arm); the match is over those two with a defensive fallback to `completed` for any
                // future status string, never a `response.failed` (which would invent a failure).
                let (event_name, event_type) = match status {
                    STATUS_INCOMPLETE => (EVT_RESPONSE_INCOMPLETE, EVT_RESPONSE_INCOMPLETE),
                    STATUS_COMPLETED => (EVT_RESPONSE_COMPLETED, EVT_RESPONSE_COMPLETED),
                    _ => (EVT_RESPONSE_COMPLETED, EVT_RESPONSE_COMPLETED),
                };
                Some((
                    event_name.to_string(),
                    serde_json::json!({ "type": event_type, "response": resp_obj }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => {
                // The native OpenAI Responses `response.failed` event wraps the error inside a
                // `response` object (`{"response":{"id":...,"status":"failed","error":{...}}}`); the
                // official Python/Node streaming decoder reads `event.response` to build the failed
                // Response, NOT a top-level `error` key. Emitting `{"error":{...}}` would leave a
                // native SDK unable to locate `event.response` and it would crash or silently
                // swallow the failure. Synthesize a `resp_` id so the SDK can correlate the failed
                // response.
                //
                // The in-band `response.error` object is the Responses-native `ResponseError` shape
                // — `{"code": <non-null string enum>, "message": <str>}` — NOT the Chat-Completions
                // `{message, type, code, param}` envelope. The official Python/Node SDK decodes
                // `event.response.error` into a typed `ResponseError` whose `code` is a required
                // non-null enum (default `"server_error"`); emitting a null `code` plus an extra
                // `type`/`param` pair is an impossible-from-real-OpenAI shape and a deterministic
                // indistinguishability tell. This protocol's OWN reader confirms the field choice:
                // it reads `response.error.code` FIRST (canonical) and only falls back to `type`.
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                // `code` MUST be a valid Responses enum, never the free-form human `provider_signal`
                // (a cross-protocol / transport-abort path carries a sentence like "The response
                // stream was interrupted." there). A recognized code round-trips; otherwise it is
                // derived from the error class. `message` keeps the human text. (found: audit c2r2.)
                let code = responses_error_code(err);
                // Replay the stream's captured `response.id` so `response.failed` correlates with
                // the opening `response.created` (the SDK reads `event.response.id` on the failure
                // event); fall back to a fresh id only if the cell is empty (failure before any
                // `MessageStart`, or a poisoned lock).
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                Some((
                    EVT_RESPONSE_FAILED.to_string(),
                    serde_json::json!({
                        "type": EVT_RESPONSE_FAILED,
                        "response": {
                            "id": response_id,
                            "object": OBJ_RESPONSE,
                            // Replay the captured `created_at` so `response.failed` carries the
                            // SAME timestamp as `response.created` (a native stream never changes
                            // it mid-flight); falls back to the current time only if the failure
                            // preceded any `MessageStart`.
                            "created_at": self.carried_created_at(),
                            // Replay the captured `model` so `response.failed`'s inner `response`
                            // carries the SAME required non-nullable `model` as `response.created`;
                            // falls back to DEFAULT_MODEL only if the failure preceded any
                            // `MessageStart`.
                            "model": self.carried_model(),
                            "status": STATUS_FAILED,
                            // A native terminal event's inner `response` always carries `output`
                            // (REQUIRED by the SDK's typed `Response`); a failed response produced
                            // no assistant items, so emit a present-but-empty array — never omit it.
                            "output": [],
                            "error": {
                                "code": code,
                                "message": message,
                            }
                        }
                    }),
                ))
            }
        };

        // EVERY native `/v1/responses` SSE event carries a top-level `sequence_number` (monotonic
        // from 0 per stream). Inject it uniformly here so no writer arm can forget it and so the
        // counter advances exactly once per emitted event. Events that produce no body
        // (`MessageStop`, empty text deltas, Image `BlockStart`) do NOT consume a
        // sequence number — only events that actually go on the wire are numbered, matching the
        // native stream where the integer counts emitted events.
        emitted.map(|(event_name, mut data)| {
            if let Some(obj) = data.as_object_mut() {
                obj.insert(
                    "sequence_number".to_string(),
                    serde_json::json!(self.next_sequence_number()),
                );
            }
            (event_name, data)
        })
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Unknown/None stop reasons default to `completed` (not `failed`): a future IR reason that
        // did not explicitly signal an error must not surface as a failed response to a Responses
        // client. Only the explicitly-mapped incomplete reasons downgrade the status.
        let status = resp
            .stop_reason
            .map(write_responses_status)
            .unwrap_or(STATUS_COMPLETED);

        // Build the `output` array in IR ENCOUNTER order, emitting one native output item per block
        // exactly as the streaming writer's `drain_output_items` does. The streaming path assigns each
        // Text/ToolUse BlockStart its own `output_index` (in arrival order) and drains them in that
        // order, so a response that interleaves text and tool blocks (e.g. text → tool → text) streams
        // those items in that sequence. A prior revision collected text separately and `insert(0)`'d a
        // single coalesced message item at the FRONT of the array — that forced text ahead of any tool
        // item and broke the order for any non-text-first or interleaved content, so the non-stream
        // body disagreed with the stream a client reassembling `response.output[]` would observe.
        // Process in order with no hardcoded index: each block appends to `output_arr` where it occurs.
        let mut output_arr: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if text.is_empty() {
                        continue;
                    }
                    // Match the native message-item shape the STREAMING `output_item.done` emits: an
                    // item-level `id` (`msg_…`), a `status`, and `annotations: []` on the `output_text`
                    // content part. Omitting them is a proxy tell — a typed SDK reading `item.id` /
                    // `item.status` / `content[0].annotations` sees missing fields on the non-stream
                    // path. Each non-empty text block becomes its OWN message item at its encounter
                    // position (mirroring the per-index message items the stream emits).
                    output_arr.push(serde_json::json!({
                        "type": ITEM_TYPE_MESSAGE,
                        "id": synthesize_item_id(ITEM_ID_PREFIX_MSG),
                        "role": "assistant",
                        "status": STATUS_COMPLETED,
                        "content": [{
                            "type": CONTENT_TYPE_OUTPUT_TEXT,
                            "text": text,
                            "annotations": []
                        }]
                    }));
                }
                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    // Verbatim for a raw `Value::String` (avoid double-encoding), same as the Chat writer.
                    let args_str = crate::proto::openai_chat::tool_arguments_to_string(input);
                    output_arr.push(serde_json::json!({
                        "type": ITEM_TYPE_FUNCTION_CALL,
                        // Native function_call items carry an item-level opaque `id` (`fc_…`) DISTINCT
                        // from `call_id` — the streaming `output_item.done` emits it, so the non-stream
                        // body must too or a typed SDK reading `item.id` sees a missing field (a proxy
                        // tell). The IR has no per-item id, so synthesize one of the native shape.
                        "id": synthesize_item_id(ITEM_ID_PREFIX_FC),
                        "call_id": id,
                        "name": name,
                        "arguments": args_str
                    }));
                }
                // H1 REASONING: write an IR Thinking block back as a native Responses `reasoning`
                // output item. The prior `_ => {}`-equivalent DROPPED it, so a thinking-carrying
                // response translated from Anthropic/Bedrock lost its reasoning on the Responses
                // surface. Emit the text under a `content[]` `reasoning_text` part (the full-reasoning
                // location); when the IR carries a signature, round-trip it into Responses'
                // `encrypted_content` slot (the opaque reasoning-reuse blob) so a same-protocol hop is
                // lossless. A purely-empty Thinking block emits no item.
                crate::ir::IrBlock::Thinking {
                    text,
                    signature,
                    redacted,
                    ..
                } => {
                    // A REDACTED reasoning block (Bedrock `redactedContent`) holds opaque encrypted
                    // bytes with no plaintext analog on the Responses surface — drop it entirely
                    // rather than leak the bytes as visible `reasoning_text`.
                    if *redacted {
                        continue;
                    }
                    let emit_sig = signature.as_deref();
                    // A purely-empty Thinking block (no text and no signature) emits no item.
                    if text.is_empty() && emit_sig.is_none() {
                        continue;
                    }
                    let mut item = serde_json::Map::new();
                    item.insert("type".to_string(), serde_json::json!(ITEM_TYPE_REASONING));
                    item.insert(
                        "id".to_string(),
                        serde_json::json!(synthesize_item_id(ITEM_ID_PREFIX_RS)),
                    );
                    item.insert("summary".to_string(), serde_json::Value::Array(Vec::new()));
                    item.insert(
                        "content".to_string(),
                        serde_json::json!([{ "type": CONTENT_TYPE_REASONING_TEXT, "text": text }]),
                    );
                    if let Some(sig) = emit_sig {
                        item.insert("encrypted_content".to_string(), serde_json::json!(sig));
                    }
                    output_arr.push(serde_json::Value::Object(item));
                }
                // ToolResult and Image have no representation in a Responses API `output` array
                // (output carries assistant `message`/`function_call` items only), so they are
                // intentionally dropped here. Enumerated explicitly rather than swallowed by a
                // catch-all so a future IrBlock variant forces a compile error instead of silently
                // vanishing from Responses output.
                crate::ir::IrBlock::ToolResult { .. } => {}
                crate::ir::IrBlock::Image { .. } | crate::ir::IrBlock::Json(_) => {}
            }
        }

        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but the Responses API's `input_tokens` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back.
        let input_total = resp
            .usage
            .input_tokens
            .saturating_add(resp.usage.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("input_tokens".to_string(), serde_json::json!(input_total));
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        // H6: write the IR read-side cache count back as the Responses-native
        // `usage.input_tokens_details.cached_tokens` (ONLY when present), so a cross-protocol response
        // that carried a cache hit (e.g. from a Bedrock backend) surfaces it to a Responses client.
        // Omitted entirely when the IR carries no cache-read value — a real Responses body without
        // cache hits omits the details object rather than emitting `cached_tokens: 0`.
        if let Some(cached) = resp.usage.cache_read_input_tokens {
            usage_map.insert(
                "input_tokens_details".to_string(),
                serde_json::json!({ "cached_tokens": cached }),
            );
        }

        let mut obj = serde_json::Map::new();
        // Emit the SDK-required top-level identity. Same-protocol passthrough carries the captured
        // upstream values verbatim; cross-protocol (backend supplied none) synthesizes a
        // protocol-correct `resp_` id and the current unix time so the body stays SDK-valid.
        // `created_at` is the Responses field name (the official SDK's `Response.created_at`).
        let id = resp.id.clone().unwrap_or_else(synthesize_response_id);
        let created_at = resp.created.unwrap_or_else(now_unix_secs);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!(OBJ_RESPONSE));
        obj.insert("created_at".to_string(), serde_json::json!(created_at));
        obj.insert("status".to_string(), serde_json::json!(status));
        // model that served the response (preserved across cross-protocol translation). The
        // official SDK types `Response.model` as a REQUIRED non-nullable string, so emit it
        // unconditionally with the DEFAULT_MODEL fallback when the IR carries none rather than
        // omitting the key — omission breaks strict decoders and is a distinguishability tell.
        obj.insert(
            "model".to_string(),
            serde_json::json!(resp.model.as_deref().unwrap_or(DEFAULT_MODEL)),
        );
        obj.insert("output".to_string(), serde_json::Value::Array(output_arr));
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
        // The official SDK types `Response.error` as a REQUIRED nullable field present on EVERY
        // Response object: `null` on success/incomplete, a populated object on failure. The
        // streaming `response.created` skeleton already emits `error: null`; the non-streaming body
        // must match. Omitting the key breaks strict SDK/Pydantic/Zod decoders that read
        // `response.error` unconditionally and is a distinguishability tell (a real non-streaming
        // `/v1/responses` body always carries `error`). A genuine upstream failure is surfaced as
        // an error envelope via `write_error`, never through this success/incomplete body, so `null`
        // is correct here.
        obj.insert("error".to_string(), serde_json::Value::Null);

        if status == STATUS_INCOMPLETE {
            let reason = resp
                .stop_reason
                .map(write_responses_incomplete_reason)
                .unwrap_or(INCOMPLETE_REASON_OTHER);
            let mut incomplete_details = serde_json::Map::new();
            incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
            obj.insert(
                "incomplete_details".to_string(),
                serde_json::Value::Object(incomplete_details),
            );
        }

        serde_json::Value::Object(obj)
    }

    /// Native OpenAI Responses error envelope. The Responses API shares the OpenAI error shape an
    /// official SDK (`openai` Python / `openai-node`) decodes into a typed `APIError`:
    /// `{"error":{"message":<msg>,"type":<type>,"code":<code|null>,"param":<param|null>}}`, served
    /// as `application/json`. `code` and `param` are always present (null here — busbar's
    /// router/auth/forward errors are not field-level validation errors). The generic `kind` is
    /// mapped to the Responses `type` vocabulary where one exists.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map busbar's generic error `kind` to the OpenAI/Responses `error.type` vocabulary. The
        // canonical Responses/OpenAI types are `invalid_request_error`, `authentication_error`,
        // `permission_error`, `not_found_error`, `rate_limit_error`, `server_error`, and
        // `insufficient_quota`. Anything already in that vocabulary (or any unrecognized caller
        // string) is passed through verbatim rather than swallowed by a catch-all, so a precise
        // upstream type is never lost.
        let error_type = match kind {
            "invalid_request" | ERR_TYPE_INVALID_REQUEST => ERR_TYPE_INVALID_REQUEST,
            "authentication" | ERR_TYPE_AUTHENTICATION | "auth" => ERR_TYPE_AUTHENTICATION,
            "permission" | ERR_TYPE_PERMISSION | "forbidden" => ERR_TYPE_PERMISSION,
            "not_found" | ERR_TYPE_NOT_FOUND => ERR_TYPE_NOT_FOUND,
            "rate_limit" | ERR_TYPE_RATE_LIMIT => ERR_TYPE_RATE_LIMIT,
            ERR_TYPE_SERVER_ERROR | "internal" | "internal_error" => ERR_TYPE_SERVER_ERROR,
            // A 503 exhaustion/timeout is reported by proxy engine as kind `"overloaded"` (an
            // Anthropic-vocabulary token). The OpenAI/Responses error vocabulary has no
            // `overloaded` type — a 5xx is `server_error` — so without this arm `other => other`
            // would leak `{"error":{"type":"overloaded",...}}` to an OpenAI-family client on every
            // exhaustion/timeout, a non-native type and a deterministic cross-protocol tell. Map the
            // overloaded/unavailable family onto the native `server_error`. Same class as the OpenAI
            // writer's 5xx bucket.
            crate::proxy::KIND_OVERLOADED
            | ERR_TYPE_OVERLOADED
            | "service_unavailable"
            | "unavailable" => ERR_TYPE_SERVER_ERROR,
            // proxy engine emits these transient/upstream-failure kinds directly to every ingress
            // writer (`timeout`/`network`/`connect` from the request-error path, `5xx`/`transient`
            // from the canonical-signal mapping, `api_error` from the generic upstream-error path).
            // None is an OpenAI/Responses error type — real OpenAI reports a transient upstream
            // failure as `server_error` — so without these arms `other => other` would leak a
            // non-native `type` such as `{"error":{"type":"timeout"}}` or `{"error":{"type":"5xx"}}`
            // to a Responses-API client: a deterministic cross-protocol tell that breaks SDK
            // consumers switching on `error.type`. Mirrors openai_chat.rs's `server_error` bucket.
            crate::proxy::KIND_TIMEOUT
            | "network"
            | "connect"
            | "5xx"
            | "transient"
            | crate::proxy::KIND_API_ERROR => ERR_TYPE_SERVER_ERROR,
            // A context-length overflow is surfaced by proxy engine as `context_length_exceeded`; the
            // Responses vocabulary has no dedicated type for it (as openai_chat.rs also maps it), so it
            // folds into `invalid_request_error`. `bad_request` is the same client-error class.
            crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH | "bad_request" => ERR_TYPE_INVALID_REQUEST,
            "billing" | ERR_TYPE_INSUFFICIENT_QUOTA => ERR_TYPE_INSUFFICIENT_QUOTA,
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "code": bearer_error_code(error_type),
                "param": serde_json::Value::Null,
            }
        })
    }

    fn egress_user_agent(&self) -> &'static str {
        // Responses API is served by the same OpenAI SDK/UA as the Chat Completions surface.
        // Pinned — see `EGRESS_UA_OPENAI` in proxy engine.
        crate::proxy::EGRESS_UA_OPENAI
    }

    fn auth_failure_message(&self) -> &'static str {
        AUTH_FAILURE_MSG
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}
