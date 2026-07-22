use super::*;

impl ProtocolWriter for CohereWriter {
    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        // The reasoning carry has no Cohere shape in this pass; dropped observably (matching
        // the penalties/top_k convention) rather than silently.
        if req.reasoning.is_some() {
            tracing::warn!(
                "dropping cross-protocol reasoning/thinking ask: no Cohere mapping in this release"
            );
        }
        let mut out = serde_json::Map::new();
        let mut messages_arr: Vec<serde_json::Value> = Vec::new();

        // Cohere v2 carries the system prompt as a leading system-role message.
        let system_text: String = req
            .system
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::Text { text, .. } = b {
                    Some(text.as_str())
                } else {
                    // A non-text system block (image/thinking/tool/…) has no Cohere v2 analog — the
                    // system prompt carries text only. WARN on the drop so the loss is operator-
                    // visible in observability, mirroring the Gemini writer's warn for the same case
                    // (the Gemini writer's comment even claims cohere already warns). (audit c2r3.)
                    tracing::warn!(
                        "dropping non-text system block on Cohere egress: Cohere v2 system prompt carries text only"
                    );
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !system_text.is_empty() {
            messages_arr.push(serde_json::json!({ "role": "system", "content": system_text }));
        }

        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::System => "system",
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
            };

            // Build content from the text blocks actually present. A single text block is sent as
            // a bare string (Cohere's preferred shape); multiple text blocks become a text-part
            // array. A message whose only block(s) are non-Text (e.g. a sole ToolUse, surfaced
            // separately via `tool_calls`) must NOT emit `content: []` — Cohere may reject that —
            // so we omit the `content` key entirely in that case.
            let text_blocks: Vec<&String> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Text { text, .. } = b {
                        Some(text)
                    } else {
                        None
                    }
                })
                .collect();

            // Cohere v2 multimodal output: an image block is written as an
            // `{"type":"image_url","image_url":{"url":"<data-uri|https>"}}` content part — the SAME
            // shape OpenAI v1 chat uses and this file's reader consumes. `image_url_from_ir` re-wraps
            // the IR (media_type, data) pair into the original URL (a base64 image becomes a
            // `data:<mime>;base64,<payload>` URI; an "image_url"-sentinel image emits its raw URL
            // verbatim). When ANY image is present the message MUST use the array content shape (a
            // bare string cannot carry an image part). ASSUMPTION (see report): the wire shape is
            // OpenAI-style `image_url`; no Cohere v2 image fixture exists in-repo to confirm it.
            let image_parts: Vec<serde_json::Value> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Image { source, .. } = b {
                        // A URL/base64 image projects to an `image_url`; a Responses `file_id` or
                        // Bedrock `s3Location` reference has no Cohere projection (returns None) and
                        // is skipped with a warn rather than corrupting the block.
                        match super::image_url_from_ir(source) {
                            Some(url) => Some(serde_json::json!({
                                "type": "image_url", "image_url": { "url": url }
                            })),
                            None => {
                                tracing::warn!(
                                    "dropping unresolvable vendor-scoped image reference on Cohere \
                                     egress: a file_id / s3Location has no cross-vendor analog"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
                .collect();

            let content_val: Option<serde_json::Value> = if image_parts.is_empty() {
                match text_blocks.as_slice() {
                    [] => None,
                    [single] => Some(serde_json::Value::String((*single).clone())),
                    many => Some(serde_json::Value::Array(
                        many.iter()
                            .map(|text| serde_json::json!({ "type": "text", "text": text }))
                            .collect(),
                    )),
                }
            } else {
                // Mixed/image content: emit a parts array with text parts first (preserving the
                // existing ordering of text before media), then the image parts.
                let mut parts: Vec<serde_json::Value> = text_blocks
                    .iter()
                    .map(|text| serde_json::json!({ "type": "text", "text": text }))
                    .collect();
                parts.extend(image_parts);
                Some(serde_json::Value::Array(parts))
            };

            // A `ToolResult` block can land on a `Tool`-role message (OpenAI/Cohere source) OR on a
            // `User`-role message (Anthropic/Gemini carry tool_results on the user turn in the IR).
            // Cohere v2 `/chat` represents EVERY tool result as its own `role:"tool"` message with a
            // `tool_call_id`; a Cohere user message cannot carry tool results. So the emission must
            // gate on the PRESENCE of a ToolResult block, not on the carrying role; otherwise
            // Anthropic/Gemini -> Cohere silently drops tool results and breaks multi-turn tool use.
            let has_tool_result = msg
                .content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolResult { .. }));
            if msg.role == crate::ir::IrRole::Tool || has_tool_result {
                // Emit one Cohere tool message per ToolResult block. Any plain text carried
                // alongside the tool results (and the degenerate case of a Tool turn with NO
                // ToolResult block at all) must NOT be silently dropped: fold that text in, onto
                // the first tool message if there is one, otherwise as a standalone tool message,
                // so the turn is never lossy.
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let mut tool_result_obj = serde_json::Map::new();
                        tool_result_obj.insert("role".to_string(), serde_json::json!("tool"));
                        tool_result_obj.insert(
                            "tool_call_id".to_string(),
                            serde_json::Value::String(tool_use_id.clone()),
                        );
                        let mut text_parts: Vec<String> = content
                            .iter()
                            .filter_map(|b| {
                                if let crate::ir::IrBlock::Text { text, .. } = b {
                                    Some(text.clone())
                                } else {
                                    // A non-Text ToolResult block is a Bedrock json-tool-result
                                    // sentinel with no Cohere analog. Drop WITH a warn (drop-with-warn
                                    // convention) instead of vanishing silently.
                                    if super::is_json_tool_result_block(b) {
                                        tracing::warn!(
                                            "dropping structured json tool-result block on Cohere \
                                             egress: a Bedrock `{{\"json\":...}}` tool-result has no \
                                             cross-protocol analog and is NOT emitted"
                                        );
                                    }
                                    None
                                }
                            })
                            .collect();
                        // Prepend any message-level text onto the first tool result so it survives.
                        if !emitted_tool_result {
                            for t in text_blocks.iter().rev() {
                                text_parts.insert(0, (*t).clone());
                            }
                        }
                        tool_result_obj.insert(
                            "content".to_string(),
                            // Concatenate with NO separator, matching `read_request`'s `.join("")`:
                            // a block boundary is not a semantic space, and a " " here inserts a
                            // phantom space at each former boundary on a Cohere->X->Cohere round-trip
                            // (corrupting base64 / split-JSON tool-result payloads).
                            serde_json::Value::String(text_parts.join("")),
                        );
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                        emitted_tool_result = true;
                    }
                }
                // Degenerate Tool turn with text but no ToolResult: emit the text as a tool message
                // rather than dropping it entirely. Cohere tool message `content` must be a string,
                // so we stringify the text blocks (join with "") exactly like the ToolResult path —
                // forwarding `content_val` here would emit a JSON array for multi-block turns,
                // producing an invalid Cohere request.
                if !emitted_tool_result && !text_blocks.is_empty() {
                    let mut tool_obj = serde_json::Map::new();
                    tool_obj.insert("role".to_string(), serde_json::json!("tool"));
                    tool_obj.insert(
                        "content".to_string(),
                        serde_json::Value::String(
                            text_blocks
                                .iter()
                                .map(|t| t.as_str())
                                .collect::<Vec<&str>>()
                                .join(""),
                        ),
                    );
                    messages_arr.push(serde_json::Value::Object(tool_obj));
                }
                continue;
            }

            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            if let Some(content_val) = content_val {
                msg_obj.insert("content".to_string(), content_val);
            }

            if msg.role == crate::ir::IrRole::Assistant {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        // Emit a raw Value::String (unparseable/streaming-partial args) verbatim rather
                        // than JSON-encoding it a second time (double-encoding) — same as the OpenAI/
                        // Responses writers. (find-1-solve-6: same bug, Cohere sibling.)
                        let args_str = crate::proto::openai_chat::tool_arguments_to_string(input);
                        tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                    }
                }
                if !tool_calls_arr.is_empty() {
                    msg_obj.insert(
                        "tool_calls".to_string(),
                        serde_json::Value::Array(tool_calls_arr),
                    );
                }
            }

            messages_arr.push(serde_json::Value::Object(msg_obj));
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_arr),
        );

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut func_obj = serde_json::Map::new();
                func_obj.insert("name".to_string(), serde_json::json!(tool.name));
                if let Some(desc) = &tool.description {
                    func_obj.insert("description".to_string(), serde_json::json!(desc));
                }
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                func_obj.insert("parameters".to_string(), params);
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("function".to_string(), serde_json::Value::Object(func_obj));
                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Cohere v2 `tool_choice` is a top-level enum string with only REQUIRED/NONE — there is NO
        // single-tool targeting in the Cohere v2 API. `Auto` is Cohere's default (omit the field).
        //
        // A targeted single tool (`IrToolChoice::Tool { name }`) therefore has NO faithful Cohere
        // representation, so we degrade it to REQUIRED — force *some* tool — rather than silently
        // dropping to `auto`: this preserves the caller's "must call a tool" intent, which is the
        // load-bearing half of the request. What is lost is the *target* (the specific tool name):
        // Cohere may pick any tool, not the one the caller named. This is the ONE documented
        // tool_choice degradation in the codebase — lossy-by-target, intentional, and unavoidable
        // until/unless the Cohere v2 API gains a named-tool choice (PF-H1).
        if let Some(tc) = &req.tool_choice {
            let v = match tc {
                crate::ir::IrToolChoice::Required | crate::ir::IrToolChoice::Tool { .. } => {
                    Some(COHERE_TOOL_CHOICE_REQUIRED)
                }
                crate::ir::IrToolChoice::None => Some(COHERE_TOOL_CHOICE_NONE),
                crate::ir::IrToolChoice::Auto => None,
            };
            if let Some(s) = v {
                out.insert("tool_choice".to_string(), serde_json::json!(s));
            }
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            // Clamp to Cohere's native [0.0, 1.0] (PF-M1) — see `clamp_temperature_for_cohere`.
            // NON-SILENT clamp (the M2 fidelity fix): the writer previously clamped SILENTLY, exactly
            // the lossy mutation busbar exists to avoid. We keep the clamp (Cohere 400s on >1.0) but
            // emit a `warn!` whenever it ACTUALLY changes the value so an operator can detect the
            // divergence in logs. Mirrors the anthropic/bedrock writers' non-silent clamp.
            let (clamped, was_clamped) = clamp_temperature_for_cohere(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "clamping temperature to Cohere's [0.0, 1.0] range; the requested value was \
                     outside it (e.g. an OpenAI/Responses value up to 2.0) and would 400 — the \
                     forwarded value diverges from the caller's request"
                );
            }
            out.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Promoted sampling controls in Cohere v2's native names: `p` (top_p), `k` (top_k),
        // `stop_sequences`. Emitted before the `extra` overlay (the reader pulled these keys out of
        // extra, so there is no double-emit on a same-protocol passthrough).
        if let Some(top_p) = req.top_p {
            out.insert("p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            out.insert("k".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            out.insert("stop_sequences".to_string(), serde_json::json!(req.stop));
        }
        // Phase 0 sampling/output controls in Cohere v2's native (OpenAI-shaped) names. Emitted
        // before the `extra` overlay (the reader pulled these keys out of extra, so there is no
        // double-emit on a same-protocol passthrough).
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
        // Cohere v2 chat supports a top-level integer `seed`. Emit it when present so deterministic
        // sampling survives the seam (the reader models it as a modeled key, so no double-emit).
        if let Some(seed) = req.seed {
            out.insert("seed".to_string(), serde_json::json!(seed));
        }
        // `response_format` (structured output): a Cohere-native object passes through verbatim; a
        // foreign shape (OpenAI `type:"json_schema"` with a nested `json_schema.schema`, or Gemini
        // `responseMimeType`/`responseSchema`) is mapped into Cohere's native `{type:"json_object",
        // json_schema:<schema>}` so a Cohere backend accepts it instead of 400-ing on the off-shape.
        if let Some(response_format) = &req.response_format {
            out.insert(
                "response_format".to_string(),
                write_cohere_response_format(response_format),
            );
        }
        // M4: Cohere-native `documents` (RAG grounding) has no cross-protocol analog and is not
        // modeled in the IR; on a same-protocol hop it flows through `extra` byte-exact below. The
        // non-silent loss warn for the cross-protocol case lives in `read_request` (the only Cohere
        // site that still sees an inbound `documents` before `extra` is cleared at the seam).
        // Only emit `stream` when streaming is requested. A native Cohere client omitting `stream`
        // (relying on the `false` default) produces a body WITHOUT the field; always injecting
        // `"stream": false` is a proxy tell and a same-protocol passthrough fidelity break (the
        // reader treats `stream` as a modeled key, so it is never echoed via `extra`). The Gemini
        // writer likewise never emits `stream` in the body.
        if req.stream {
            out.insert("stream".to_string(), serde_json::json!(true));
        }
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, id, .. } => {
                let cohere_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::System
                    | crate::ir::IrRole::User
                    | crate::ir::IrRole::Tool => return None,
                };
                // Cohere v2 streams carry the response `id` on the message-start frame. Preserve a
                // captured id; synthesize a shape-valid one for the cross-protocol case so the
                // emitted stream is indistinguishable from a native Cohere stream.
                let id = id.clone().unwrap_or_else(synthesize_cohere_id);
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "id": id,
                        "type": ET_MESSAGE_START,
                        "delta": { "message": { "role": cohere_role } }
                    }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // Record the open text index so its matching `BlockStop` emits `content-end`. A
                    // cross-protocol block that carries NO opening frame (Thinking / Image, below)
                    // is never recorded, so its `BlockStop` stays silent rather than emitting an
                    // orphan `content-end` — see `open_text_indices`.
                    self.mark_text_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_CONTENT_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "content": { "type": "text", "text": "" }
                                }
                            }
                        }),
                    ))
                }
                // Cross-protocol streaming tool use (e.g. Anthropic/Gemini → Cohere-ingress) must
                // surface a native `tool-call-start` frame mirroring the shape this file's own
                // reader consumes (delta.message.tool_calls.{id,type,function.{name,arguments}}).
                // Omitting it made streamed tool calls invisible to a Cohere client. The reader
                // expects `function.arguments` to be a (possibly empty) string and accumulates
                // tool-call-delta argument fragments onto it, so we open with an empty string.
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Record the open tool index so the matching `BlockStop` closes it with
                    // `tool-call-end` (the native Cohere v2 close event for a tool block) rather
                    // than `content-end` (the text-block close event) — see `open_tool_indices`.
                    self.mark_tool_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_TOOL_CALL_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "tool_calls": {
                                        "id": id,
                                        "type": "function",
                                        "function": { "name": name, "arguments": "" }
                                    }
                                }
                            }
                        }),
                    ))
                }
                // Cohere v2 has no streamed thinking/image block shape. Emitting a fabricated frame
                // would be a non-native proxy tell, so these IR block kinds carry no opening frame.
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    // Native Cohere v2 content-delta frames carry the text at
                    // delta.message.content.text (an object), matching the content-start shape and
                    // this reader's object path. A bare string here is non-native and a client that
                    // reads content.text would accumulate nothing.
                    serde_json::json!({
                        "type": ET_CONTENT_DELTA,
                        "index": index,
                        "delta": { "message": { "content": { "type": "text", "text": text } } }
                    }),
                )),
                // Streamed tool-call argument fragments map to a native `tool-call-delta` frame
                // carrying the argument chunk at delta.message.tool_calls.function.arguments — the
                // exact path this file's reader reads. Without this arm, cross-protocol tool-call
                // arguments never reached a Cohere-ingress client.
                crate::ir::IrDelta::InputJsonDelta(args) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_TOOL_CALL_DELTA,
                        "index": index,
                        "delta": {
                            "message": {
                                "tool_calls": { "function": { "arguments": args } }
                            }
                        }
                    }),
                )),
                // Cohere v2 streams carry no thinking/signature delta shape; suppress rather than
                // emit a non-native frame.
                crate::ir::IrDelta::ThinkingDelta(_) => None,
                crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_) => None,
                // L2-5: Cohere v2 streams carry no citation delta shape; suppress rather than emit
                // a non-native frame. The citation is preserved in the IR for protocols that model
                // streaming citations.
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Cohere v2 has no cross-protocol logprobs shape (token IDs only); dropped.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer index, not the block kind. A native
                // Cohere v2 stream closes a tool-call block with `tool-call-end` and a text-content
                // block with `content-end`. Emitting `content-end` for BOTH — as a prior revision
                // did — closed a tool-call block with the text close event, so a native Cohere SDK
                // (which keys on event type to track tool-call state) mis-decoded the stream and the
                // tool block was never properly terminated. So consult the
                // per-stream open-tool set: a tool-call index (recorded by its `tool-call-start`)
                // closes with `tool-call-end`, consuming the marker; any other index (a text block)
                // closes with `content-end`.
                // A tool-call index (recorded by its `tool-call-start`) closes with `tool-call-end`,
                // consuming its marker. A text index (recorded by its `content-start`) closes with
                // `content-end`, consuming its marker. An UNTRACKED index — a cross-protocol block
                // that emitted no opening frame (Thinking / Image, whose `BlockStart` maps to `None`)
                // — emits NOTHING: previously it fell through to an unconditional `content-end`,
                // producing an orphan close with no matching `content-start`. This
                // mirrors the Gemini writer's no-frame-for-untracked-index behavior.
                if self.take_tool_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_TOOL_CALL_END, "index": index }),
                    ))
                } else if self.take_text_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_CONTENT_END, "index": index }),
                    ))
                } else {
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let cohere_finish_reason = stop_reason
                    .map(write_cohere_stop_reason)
                    .unwrap_or(COHERE_FINISH_COMPLETE);
                // Native Cohere v2 message-end frames carry token usage inside
                // delta.usage.tokens.{input_tokens,output_tokens}. Surface it so a Cohere SDK
                // client tracking billing/rate-limit data from the stream is not silently zeroed.
                // IrUsage is always present (not Option); when upstream supplied nothing it is
                // zero-valued, which serializes here as a safe `{input_tokens:0,output_tokens:0}`.
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": cohere_finish_reason,
                            "usage": {
                                "tokens": {
                                    "input_tokens": usage.input_tokens,
                                    "output_tokens": usage.output_tokens
                                }
                            }
                        }
                    }),
                ))
            }

            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                // Cohere v2 has NO `type: "error"` out-of-band stream event. A native v2 stream
                // signals a mid-stream error by terminating with a `message-end` frame whose
                // `finish_reason` is `ERROR` (infrastructure failure) or `ERROR_TOXIC` (content
                // moderation). Emitting a `type: "error"` frame was both non-native (a strict Cohere
                // SDK ignores or rejects an unknown event type, silently dropping the error) and a
                // protocol-indistinguishability tell. We therefore emit the native `message-end`
                // termination instead. The reader maps `ERROR_TOXIC` back to IR `safety` and the
                // generic `ERROR` to IR `error` (the lowercase passthrough), so this round-trips: a
                // content-moderation signal in the provider_signal maps to `ERROR_TOXIC`, everything
                // else to the generic `ERROR`.
                let toxic = err
                    .provider_signal
                    .as_deref()
                    .is_some_and(cohere_error_is_content_moderation);
                let finish_reason = if toxic {
                    COHERE_FINISH_ERROR_TOXIC
                } else {
                    COHERE_FINISH_ERROR
                };
                // Emit the native `message-end` shape EXACTLY — `type` + `delta.{finish_reason,
                // usage}` — and nothing else. A native Cohere v2 `message-end` frame (the one the
                // normal MessageDelta arm above produces) carries ONLY `type` and `delta`; it never
                // carries a top-level `message`, and it ALWAYS includes `delta.usage`. A prior
                // revision added a top-level `"message": <detail>` field and omitted `delta.usage`,
                // both of which diverge from the native wire shape and let a client (or passive
                // observer) fingerprint the proxy — and a strict v2 SDK may reject the unexpected
                // field. The load-bearing discriminant is
                // `finish_reason` (`ERROR`/`ERROR_TOXIC`), which the reader maps back to IR
                // (`error`/`safety` respectively), so the detail string carries no protocol value on
                // the wire; surface it server-side instead so operators are not left with an opaque
                // error.
                if let Some(detail) = err.provider_signal.as_deref() {
                    tracing::warn!(
                        finish_reason,
                        detail,
                        "cohere: mid-stream error terminating with native message-end frame"
                    );
                }
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": finish_reason,
                            "usage": {
                                "tokens": { "input_tokens": 0, "output_tokens": 0 }
                            }
                        }
                    }),
                ))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let mut content_arr: Vec<serde_json::Value> = Vec::new();
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    // KNOWN LIMITATION (audit finding #7): Cohere's `message.tool_plan` (the
                    // assistant's pre-tool-call reasoning) is READ into a plain leading `IrBlock::Text`
                    // by both cohere readers (non-stream `read_response`, streaming
                    // `tool-plan-delta`). The IR has NO flag distinguishing that Text FROM an ordinary
                    // content Text, so on an X→Cohere hop we cannot reliably tell which leading Text
                    // was a `tool_plan` and reshape it back into the native `tool_plan` slot — a
                    // heuristic ("the leading Text when tool_calls follow") would misclassify a genuine
                    // leading assistant message as reasoning. The reasoning is therefore re-emitted as
                    // `content` (lossless in text, but reshaped from `tool_plan` to `content`).
                    // Faithful `tool_plan` round-tripping would require a first-class IR marker; until
                    // one exists, preserving the text as content is the correct, non-lossy choice.
                    content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                }
                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    // Verbatim for a raw Value::String (avoid double-encoding), same as OpenAI/Responses.
                    // (find-1-solve-6: same bug, Cohere sibling.)
                    let args_str = crate::proto::openai_chat::tool_arguments_to_string(input);
                    // Accumulate every tool call. Inserting per-iteration would overwrite the
                    // key and silently drop all but the last call on parallel tool use.
                    tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                crate::ir::IrBlock::Image { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Json(_) => {}
            }
        }

        let cohere_finish_reason = resp
            .stop_reason
            .map(write_cohere_stop_reason)
            .unwrap_or(COHERE_FINISH_COMPLETE);

        // Cohere format: usage.tokens.input_tokens, usage.tokens.output_tokens
        let mut tokens_map = serde_json::Map::new();
        tokens_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        tokens_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        // Emit the response identity. Same-protocol passthrough preserves the captured upstream
        // `id` exactly; the cross-protocol case (a non-Cohere backend that never supplied one)
        // hits `None` and we synthesize a shape-valid Cohere id so a native SDK always reads a
        // non-empty `.id` string.
        let id = resp.id.clone().unwrap_or_else(synthesize_cohere_id);
        out.insert("id".to_string(), serde_json::Value::String(id));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out.insert("model".to_string(), serde_json::json!(model));
        }
        out.insert(
            "finish_reason".to_string(),
            serde_json::json!(cohere_finish_reason),
        );
        // Native Cohere v2 carries tool calls INSIDE the message object (response.message
        // .tool_calls) — exactly where this file's own read_response reads them from. Nesting them
        // here (rather than at the top level) keeps the body native for a real Cohere SDK and lets
        // a Cohere -> Cohere passthrough round-trip every parallel tool call.
        let mut message_obj = serde_json::Map::new();
        message_obj.insert("role".to_string(), serde_json::json!("assistant"));
        message_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
        if !tool_calls_arr.is_empty() {
            message_obj.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls_arr),
            );
        }
        out.insert(
            "message".to_string(),
            serde_json::Value::Object(message_obj),
        );
        // Wrap tokens under "tokens" key per Cohere API spec
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("tokens".to_string(), serde_json::Value::Object(tokens_map));
        out.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(out)
    }

    /// NATIVE Cohere v2 error envelope. The Cohere v2 chat API conveys the error *category* via the
    /// HTTP status (400/401/404/429/5xx) and carries only a human-readable `{"message": <detail>}`
    /// body — it has no typed `error.type`/`code` field the way OpenAI/Anthropic do. So the generic
    /// `kind` is intentionally NOT surfaced in the body (it would be a field a native SDK never
    /// sees); it is dropped here and conveyed solely by the caller's HTTP status. Real Cohere v2
    /// error bodies are a bare `{"message": "..."}` and do NOT carry a synthesized id; this reader's
    /// own `extract_error` reads only `message`/`error_type` and never `id`, so emitting an `id`
    /// here was both a proxy tell and internally inconsistent with the reader. Served as
    /// `application/json` per the trait contract.
    ///
    /// This is a LIVE production code path, not test-only scaffolding: it is reached at runtime via
    /// the `ProtocolWriter` trait object on every Cohere-ingress error response (e.g. ingress,
    /// proxy engine, and auth.rs all dispatch `p.writer().write_error(...)`). It carries no
    /// `allow(dead_code)` suppression — matching every other protocol writer — because the
    /// dead-code lint never fires on vtable-dispatched trait method implementations.
    fn write_error(&self, _status: u16, _kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "message": message,
        })
    }

    fn egress_user_agent(&self) -> &'static str {
        // Cohere Python SDK UA shape — pinned, see `EGRESS_UA_COHERE` in proxy engine.
        crate::proxy::EGRESS_UA_COHERE
    }

    fn auth_failure_message(&self) -> &'static str {
        "invalid api token"
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}
