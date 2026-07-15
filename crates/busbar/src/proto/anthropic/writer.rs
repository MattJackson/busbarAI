use super::*;

impl ProtocolWriter for AnthropicWriter {
    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    /// Anthropic's streamed `citations_delta` SSE event carries EXACTLY ONE `citation` object (a
    /// native SDK `JSON.parse`s one object per `data:` line and crashes on an array), so a multi-
    /// citation `CitationsDelta` must be fanned out into one event each. See `StreamTranslate`.
    fn max_citations_per_delta(&self) -> Option<usize> {
        Some(1)
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Mode-blind primitive (no signing context). An Ambiguous credential emits BOTH headers so
        // neither the static-key nor the passthrough path silently drops. The live wire path uses
        // `sign_request` below, which carries the auth mode and resolves Ambiguous to one header —
        // so a real request never sends the dual-header upstream tell.
        anthropic_auth_headers(key, None)
    }

    fn sign_request(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // Wire path: the upstream-credential mode (set by proxy engine into the SigningContext) resolves
        // an Ambiguous Anthropic credential to the SINGLE native header it implies — Passthrough
        // forwards the caller's token as `authorization: Bearer`; Own presents the configured key as
        // `x-api-key`. Clear ApiKey/OAuth credentials are unaffected (still single-header).
        anthropic_auth_headers(key, Some(ctx.upstream_creds))
    }

    fn requires_max_tokens(&self) -> bool {
        // Anthropic Messages 400s with `max_tokens: Field required` when absent.
        true
    }

    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Native Anthropic error envelope: `{"type":"error","error":{"type":<kind>,"message":<msg>}}`
        // (see the Anthropic SDK / API error shape — the `anthropic.APIStatusError` family decodes
        // `error.type` into the typed exception, e.g. `RateLimitError`, and surfaces `error.message`).
        // Served as `application/json` by the caller, per the `ProtocolWriter::write_error` contract.
        // The generic `kind` strings the router emits are mapped to Anthropic's own error-type
        // vocabulary so a native SDK gets the exception it expects; an unrecognized `kind` is passed
        // through verbatim (it is already an Anthropic-style type, or a value we don't want to
        // silently rewrite — no `_ =>` swallow).
        //
        // Status-driven override first: native Anthropic represents upstream overload as the 529
        // `overloaded_error`, never a generic `api_error`. When a cross-protocol upstream relays a
        // 503 (or 529) to an Anthropic-ingress client, the router hands us the generic `api_error`
        // kind — but the native type for that status family is `overloaded_error`. Map by status so
        // a native SDK raises the right exception (and the body matches what real Anthropic returns
        // under load) rather than a generic server error. Status takes precedence over `kind` here
        // because the wire status is the authoritative signal of the overload condition.
        if status == STATUS_OVERLOADED || status == STATUS_ANTHROPIC_OVERLOADED {
            return Self::error_envelope(ERR_TYPE_OVERLOADED, message);
        }
        let anthropic_type = match kind {
            // Generic router/auth/forward `kind`s → Anthropic's typed error vocabulary.
            "invalid_request" | "bad_request" => ERR_TYPE_INVALID_REQUEST,
            "authentication" | "unauthorized" => ERR_TYPE_AUTHENTICATION,
            "permission" | "forbidden" => ERR_TYPE_PERMISSION,
            "not_found" => ERR_TYPE_NOT_FOUND,
            ERR_TYPE_REQUEST_TOO_LARGE | "payload_too_large" => ERR_TYPE_REQUEST_TOO_LARGE,
            "rate_limit" | "too_many_requests" => ERR_TYPE_RATE_LIMIT,
            crate::proxy::KIND_OVERLOADED => ERR_TYPE_OVERLOADED,
            crate::proxy::KIND_TIMEOUT => ERR_TYPE_TIMEOUT,
            ERR_TYPE_API_ERROR | crate::proxy::KIND_SERVER_ERROR | "internal" => ERR_TYPE_API_ERROR,
            // Already an Anthropic-native type (e.g. "invalid_request_error") or an unmapped value:
            // emit it unchanged rather than collapsing every unknown into one bucket.
            ERR_TYPE_INVALID_REQUEST
            | ERR_TYPE_AUTHENTICATION
            | ERR_TYPE_PERMISSION
            | ERR_TYPE_NOT_FOUND
            | ERR_TYPE_RATE_LIMIT
            | ERR_TYPE_OVERLOADED
            | ERR_TYPE_TIMEOUT => kind,
            other => other,
        };
        Self::error_envelope(anthropic_type, message)
    }

    fn attach_error_response_headers(
        &self,
        headers: &mut axum::http::HeaderMap,
        _kind: &str,
        envelope: &serde_json::Value,
    ) {
        // A real Anthropic response ALWAYS carries the request id in the `request-id` RESPONSE HEADER
        // (the official SDK reads `request-id` into `APIError.request_id` / `Message._request_id`, NOT
        // the body). The writer already mints a top-level body `request_id`; mirror it into the header
        // so body and header AGREE and the SDK populates `request_id` — omitting it was a deterministic
        // proxy tell on every error response.
        if let Some(rid) = envelope.get("request_id").and_then(|v| v.as_str()) {
            if let Ok(hv) = axum::http::HeaderValue::from_str(rid) {
                headers.insert(HDR_REQUEST_ID, hv);
            }
        }
    }

    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        // Forward the captured UPSTREAM `request-id` verbatim on a same-protocol passthrough;
        // synthesize a shape-correct `req_…` id otherwise. Synthesis failure OMITS the header.
        upstream_request_id
            .map(String::from)
            .or_else(synth_anthropic_request_id)
            .map(|id| (HDR_REQUEST_ID, id))
    }

    fn ingress_relayed_response_header_names(&self) -> &'static [&'static str] {
        // Forwarded VERBATIM on a same-protocol anthropic passthrough: `request-id`.
        &[HDR_REQUEST_ID]
    }

    fn auth_failure_message(&self) -> &'static str {
        "invalid x-api-key"
    }

    fn egress_user_agent(&self) -> &'static str {
        // Anthropic Python SDK UA shape — pinned, see `EGRESS_UA_ANTHROPIC` in proxy engine.
        crate::proxy::EGRESS_UA_ANTHROPIC
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        // Anthropic's Messages API has NO `system` role inside `messages` — system content lives in
        // the top-level `system` field. Anthropic's OWN reader canonicalizes a wire `role:"system"`
        // message into `req.system` (see `read_request`), but a CROSS-PROTOCOL IR (e.g. read by the
        // OpenAI reader) can still carry an `IrRole::System` message in `req.messages` that never
        // passed through that promotion. Fold any such message's blocks into the top-level system
        // array here so `write_message` never receives a System role and can never emit the INVALID
        // `role:"system"` (which upstream rejects with a 400) — mirroring the gemini/bedrock writers,
        // which `continue` past an `IrRole::System` message in their request message loop.
        let mut system_blocks: Vec<&crate::ir::IrBlock> = req.system.iter().collect();
        for msg in &req.messages {
            if msg.role == crate::ir::IrRole::System {
                system_blocks.extend(msg.content.iter());
            }
        }
        if !system_blocks.is_empty() {
            let system_array: Vec<_> = system_blocks.into_iter().map(write_block).collect();
            out.insert("system".to_string(), serde_json::Value::Array(system_array));
        }
        let messages_array: Vec<_> = req
            .messages
            .iter()
            .filter(|msg| msg.role != crate::ir::IrRole::System)
            .map(write_message)
            .collect();
        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );
        if !req.tools.is_empty() {
            let tools_array: Vec<_> = req.tools.iter().map(write_tool).collect();
            out.insert("tools".to_string(), serde_json::Value::Array(tools_array));
        }
        // Emit `tool_choice` in Anthropic's native object shape when present so a forced /
        // targeted directive translated from another protocol does not silently degrade to `auto`.
        // The parallelism carry (OpenAI `parallel_tool_calls`) rides the same object as Anthropic's
        // inverted `disable_parallel_tool_use` — valid on auto/any/tool, not on `none`.
        if let Some(tc) = &req.tool_choice {
            let mut tc_val = write_anthropic_tool_choice(tc);
            if let (Some(parallel), Some(map)) = (req.parallel_tool_calls, tc_val.as_object_mut()) {
                if map.get("type").and_then(|t| t.as_str()) != Some("none") {
                    map.insert(
                        "disable_parallel_tool_use".to_string(),
                        serde_json::json!(!parallel),
                    );
                }
            }
            out.insert("tool_choice".to_string(), tc_val);
        } else if let Some(parallel) = req.parallel_tool_calls {
            // No directive but the caller did set parallelism: Anthropic can only express it inside
            // a tool_choice object, so synthesize the neutral `auto` carrier — only when tools are
            // actually present (the flag is meaningless without them, and Anthropic rejects a
            // tool_choice on a tool-less request).
            if !req.tools.is_empty() {
                out.insert(
                    "tool_choice".to_string(),
                    serde_json::json!({"type": "auto", "disable_parallel_tool_use": !parallel}),
                );
            }
        }
        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        // The reasoning carry: project the IR ask into Anthropic's `thinking` param. The budget is
        // clamped to leave >=1024 tokens of answer under max_tokens (Anthropic requires
        // budget_tokens < max_tokens and spends thinking FROM it) and floored at the API's 1024
        // minimum; when max_tokens is too small to fit any thinking, the ask is dropped with a
        // warn rather than shipped to a certain 400. Anthropic also rejects temperature/top_k
        // modifications alongside thinking, so when the ask IS emitted those knobs are omitted
        // (warned) below instead of shipped to a 400.
        let mut thinking_emitted = false;
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
            if matches!(ask, crate::ir::IrReasoningAsk::Dynamic) {
                tracing::warn!(
                    "gemini dynamic thinking (-1) has no Anthropic analog; projecting as the \
                     'medium' effort budget"
                );
            }
            let want = ask.to_budget(table);
            let cap = req.max_tokens.map(|mt| mt.saturating_sub(1024));
            let budget = cap.map_or(want, |c| want.min(c));
            if budget >= 1024 {
                if budget != want {
                    tracing::warn!(
                        requested_budget = want,
                        clamped_budget = budget,
                        max_tokens = ?req.max_tokens,
                        "thinking budget clamped to fit under max_tokens"
                    );
                }
                out.insert(
                    "thinking".to_string(),
                    serde_json::json!({"type": "enabled", "budget_tokens": budget}),
                );
                thinking_emitted = true;
            } else {
                tracing::warn!(
                    max_tokens = ?req.max_tokens,
                    "dropping reasoning ask on Anthropic egress: max_tokens leaves no room for \
                     the 1024-token thinking minimum"
                );
            }
        }
        if thinking_emitted {
            // Anthropic rejects a FORCED/TARGETED tool_choice (`{type:"any"}` / `{type:"tool"}`)
            // alongside extended thinking with a 400 — only `auto`/`none` are allowed. tool_choice
            // was already written above (before the thinking decision), so downgrade a now-illegal
            // `any`/`tool` to `auto` here, preserving any `disable_parallel_tool_use`, with a warn —
            // same "think-ask wins, observably" rule applied to temperature/top_p/top_k below.
            if let Some(tc) = out.get_mut("tool_choice").and_then(|v| v.as_object_mut()) {
                let ty = tc.get("type").and_then(|t| t.as_str());
                if ty == Some("any") || ty == Some("tool") {
                    tracing::warn!(
                        tool_choice = ?ty,
                        "downgrading forced/targeted tool_choice to 'auto' on Anthropic egress: \
                         not compatible with thinking"
                    );
                    tc.insert("type".to_string(), serde_json::json!("auto"));
                    tc.remove("name"); // `name` is only valid on `{type:"tool"}`
                }
            }
        }
        if thinking_emitted && req.temperature.is_some_and(|t| t != 1.0) {
            // Anthropic 400s on temperature != 1 with thinking enabled; the think-ask wins and the
            // sampling knob is omitted, observably.
            tracing::warn!(
                temperature = ?req.temperature,
                "omitting temperature on Anthropic egress: not compatible with thinking"
            );
        }
        if let Some(temperature) = req.temperature.filter(|_| !thinking_emitted) {
            // Clamp to Anthropic's valid [0.0, 1.0] — see `clamp_temperature_for_anthropic`.
            // NON-SILENT clamp: silently rewriting a caller's sampling temperature
            // is exactly the lossy mutation busbar exists to avoid; we keep the clamp (Anthropic 422s on
            // >1.0) but emit a `warn!` whenever it ACTUALLY changes the value so an operator can detect
            // the divergence in logs. A request-time RESPONSE header (`x-busbar-parameter-clamped`)
            // cannot be attached from here: `write_request` returns only the egress request JSON and
            // has no handle on the (much-later-built) client response; surfacing it as a header would
            // require threading a clamp signal back out through the whole `forward` path / trait
            // signature, deferred as out-of-scope for this minimal-safe fix. The warn! is the contract.
            let (clamped, was_clamped) = clamp_temperature_for_anthropic(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "clamping temperature to Anthropic's [0.0, 1.0] range; the requested value was \
                     outside it (e.g. an OpenAI/Responses value up to 2.0) and would 422 — the \
                     forwarded value diverges from the caller's request"
                );
            }
            out.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Sampling controls promoted to first-class IR fields (see `IrRequest`): emit each in
        // Anthropic's native shape when present. `top_p`/`top_k` map 1:1; the IR's normalized `stop`
        // vec is Anthropic's native `stop_sequences` array. Emitted before the `extra` overlay (these
        // keys were pulled OUT of extra by the reader, so there is no double-emit on passthrough).
        if let Some(top_p) = req.top_p {
            if thinking_emitted {
                // Anthropic rejects top_p modifications alongside thinking (same rule as
                // temperature/top_k); omit it, observably, rather than ship a certain 400.
                tracing::warn!(
                    top_p,
                    "omitting top_p on Anthropic egress: not compatible with thinking"
                );
            } else {
                out.insert("top_p".to_string(), serde_json::json!(top_p));
            }
        }
        if let Some(top_k) = req.top_k {
            if thinking_emitted {
                // Anthropic rejects top_k modifications alongside thinking; omit, observably.
                tracing::warn!(
                    top_k,
                    "omitting top_k on Anthropic egress: not compatible with thinking"
                );
            } else {
                out.insert("top_k".to_string(), serde_json::json!(top_k));
            }
        }
        if !req.stop.is_empty() {
            out.insert("stop_sequences".to_string(), serde_json::json!(req.stop));
        }
        out.insert("stream".to_string(), serde_json::json!(req.stream));
        // response_format (M1): Anthropic's Messages API has NO native `response_format` field. The
        // idiomatic Anthropic mapping is tool-forcing (a synthetic tool + `tool_choice:{type:"tool"}`),
        // which is non-trivial and deliberately NOT implemented in this pass. The reader never sets
        // `response_format` on the same-protocol (Anthropic→Anthropic) path — same-protocol relays the
        // raw upstream body and never reaches this writer — so this only fires for a CROSS-PROTOCOL IR
        // (e.g. an OpenAI/Responses request carrying `response_format`) reaching the Anthropic egress.
        // Dropping it silently would be exactly the lossy mutation busbar exists to avoid; emit a
        // `warn!` so the divergence is observable in logs rather than invisible. (The block is dropped,
        // not forwarded: emitting an unknown `response_format` key would 400 the upstream.)
        if req.response_format.is_some() {
            tracing::warn!(
                parameter = "response_format",
                "dropping response_format on Anthropic egress: the Messages API has no native \
                 response_format field and tool-forcing is not implemented in this pass; the \
                 structured-output directive from a cross-protocol request is NOT forwarded"
            );
        }
        // Carry the end-user identifier into Anthropic's spelling (`metadata.user_id`). Emitted
        // before the `extra` overlay: if the request natively carried an Anthropic `metadata`
        // object it rides `extra` and overwrites this, so the verbatim original always wins.
        if let Some(user) = &req.user {
            out.insert("metadata".to_string(), serde_json::json!({"user_id": user}));
        }
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }
        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                usage,
                id,
                model,
                ..
            } => {
                let role_str = match role {
                    crate::ir::IrRole::User => "user",
                    crate::ir::IrRole::Assistant => "assistant",
                    _ => return None,
                };
                let mut msg_obj = serde_json::Map::new();
                // The native `message_start.message` is a skeleton Message EVERY native Anthropic
                // stream carries and an SDK reads `id`/`type`/`role`/`model`/`content`/`usage` from
                // (plus `stop_reason`/`stop_sequence`, null at stream start). Emit that full skeleton
                // UNCONDITIONALLY — synthesizing a `msg_`-prefixed id when the source carried none —
                // exactly as every other ingress writer does (openai/cohere/responses/gemini all
                // `unwrap_or_else` an id). `write_response_event` runs ONLY on the cross-protocol
                // `StreamTranslate` path (same-protocol streams pass raw bytes through and never
                // reconstruct events), where `StreamTranslate` strips the foreign `id` to `None`;
                // gating the skeleton on `has_identity` therefore emitted a DEGENERATE
                // `{role,usage}` message_start on every cross-protocol Anthropic-ingress stream —
                // missing the mandatory `id`/`type`/`content`/`stop_reason`/`stop_sequence` an SDK
                // requires to construct its streaming Message (a decode failure and a proxy tell).
                let msg_id = id.clone().unwrap_or_else(synth_message_id);
                msg_obj.insert("id".to_string(), serde_json::json!(msg_id));
                msg_obj.insert("type".to_string(), serde_json::json!("message"));
                msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                // model: same conformance class as the non-stream `write_response` writer — the SDK
                // types `message_start.message.model` as a REQUIRED non-optional string and reads it to
                // populate the assembled streaming Message. Emit it UNCONDITIONALLY (empty-string
                // fallback when the cross-protocol source didn't carry a model), so the skeleton is
                // structurally valid rather than dropping a mandatory field.
                let model_str = model.as_deref().unwrap_or("");
                msg_obj.insert("model".to_string(), serde_json::json!(model_str));
                msg_obj.insert("content".to_string(), serde_json::Value::Array(Vec::new()));
                msg_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                msg_obj.insert("stop_sequence".to_string(), serde_json::Value::Null);
                // `usage` is a REQUIRED field of `message_start.message`: a native Anthropic stream
                // always carries `usage:{"input_tokens":N,"output_tokens":0}` at stream open, and the
                // official TypeScript SDK types `message.usage` as `Usage` (not `Usage | undefined`) —
                // a client that reads `event.message.usage.input_tokens` on the first event throws if
                // it is absent. On the cross-protocol path (e.g. OpenAI→Anthropic) the first chunk
                // carries no usage, so `usage` is `None`; emit a zero-valued skeleton in that case
                // (which also matches native behavior: output_tokens is 0 at stream open) rather than
                // omitting the key.
                let mut usage_map = serde_json::Map::new();
                let (input_tokens, output_tokens) = usage
                    .as_ref()
                    .map(|u| (u.input_tokens, u.output_tokens))
                    .unwrap_or((0, 0));
                usage_map.insert("input_tokens".to_string(), serde_json::json!(input_tokens));
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(output_tokens),
                );
                if let Some(usage_val) = usage {
                    if let Some(ccit) = usage_val.cache_creation_input_tokens {
                        usage_map.insert(
                            "cache_creation_input_tokens".to_string(),
                            serde_json::json!(ccit),
                        );
                    }
                    if let Some(crit) = usage_val.cache_read_input_tokens {
                        usage_map.insert(
                            "cache_read_input_tokens".to_string(),
                            serde_json::json!(crit),
                        );
                    }
                }
                msg_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                let mut data_obj = serde_json::Map::new();
                // Native Anthropic SSE data bodies carry a top-level `type` matching the SSE `event:`
                // header (e.g. `{"type":"message_start",...}`). The SDK streaming decoder accepts the
                // event off the header, but native parity (and any consumer that dispatches on
                // `data.type`) requires the field — emit it on every event body.
                data_obj.insert("type".to_string(), serde_json::json!(EVT_MESSAGE_START));
                data_obj.insert("message".to_string(), serde_json::Value::Object(msg_obj));
                Some((
                    EVT_MESSAGE_START.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStart { index, block } => {
                let content_block = match block {
                    IrBlockMeta::Text => {
                        serde_json::json!({ "type": "text" })
                    }
                    IrBlockMeta::Thinking => {
                        serde_json::json!({ "type": "thinking" })
                    }
                    IrBlockMeta::ToolUse { id, name } => {
                        serde_json::json!({ "type": STOP_TOOL_USE, "id": id, "name": name })
                    }
                    IrBlockMeta::Image => {
                        serde_json::json!({ "type": "image" })
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_START),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("content_block".to_string(), content_block);
                Some((
                    EVT_CONTENT_BLOCK_START.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockDelta { index, delta } => {
                let delta_val = match delta {
                    IrDelta::TextDelta(text) => {
                        serde_json::json!({ "type": DELTA_TYPE_TEXT, "text": text })
                    }
                    IrDelta::ThinkingDelta(thinking) => {
                        serde_json::json!({ "type": DELTA_TYPE_THINKING, "thinking": thinking })
                    }
                    IrDelta::InputJsonDelta(json) => {
                        serde_json::json!({ "type": DELTA_TYPE_INPUT_JSON, "partial_json": json })
                    }
                    IrDelta::SignatureDelta(sig) => {
                        serde_json::json!({ "type": DELTA_TYPE_SIGNATURE, "signature": sig })
                    }
                    // A streamed redacted-reasoning delta (opaque encrypted bytes) has no Anthropic
                    // streaming-delta analog — emit nothing for this frame.
                    IrDelta::RedactedReasoningDelta(_) => return None,
                    // Anthropic has no logprobs concept at all — lossy-by-target, emit nothing.
                    IrDelta::LogprobsDelta(_) => return None,
                    // L2-5 STREAMING citation: re-emit each carried citation as its own native
                    // `content_block_delta`/`citations_delta` event (the native wire carries ONE
                    // `citation` per delta). `write_citation` re-emits a byte-exact Anthropic `raw`
                    // verbatim (same-protocol path) and synthesizes the Anthropic object from neutral
                    // fields otherwise (e.g. a Gemini-sourced citation on a Gemini→Anthropic hop) —
                    // the shape-gate (`is_anthropic_citation_shape`) inside `write_citation` keeps a
                    // foreign `raw` from leaking through. An EMPTY citation vec carries nothing, so we
                    // emit no event (return None) rather than a stray empty `content_block_delta`.
                    IrDelta::CitationsDelta(citations) => {
                        // EVERY Anthropic `citations_delta` event on the wire is EXACTLY ONE citation
                        // object — never a JSON array (a native SDK `JSON.parse`s one object per
                        // `data:` line and crashes on an array). The `ProtocolWriter` trait returns at
                        // most one `(event_type, body)` per event, so a delta MUST carry at most one
                        // citation by the time it reaches this writer. A multi-citation `CitationsDelta`
                        // (e.g. a Gemini chunk batching N `citationSources[]`) is split into N
                        // single-citation deltas UPSTREAM at the `StreamTranslate` framing seam (the
                        // Anthropic-ingress multi-citation fan-out), so each call here sees exactly one.
                        // An EMPTY vec carries nothing → emit no event (None) rather than a stray empty
                        // `content_block_delta`. A vec of >1 cannot occur via the framer, but defend the
                        // invariant anyway: take the FIRST and drop the rest rather than ever emitting
                        // an array.
                        let c = citations.first()?;
                        let mut data_obj = serde_json::Map::new();
                        data_obj.insert(
                            "type".to_string(),
                            serde_json::json!(EVT_CONTENT_BLOCK_DELTA),
                        );
                        data_obj.insert("index".to_string(), serde_json::json!(index));
                        data_obj.insert(
                            "delta".to_string(),
                            serde_json::json!({
                                "type": DELTA_TYPE_CITATIONS,
                                "citation": write_citation(c),
                            }),
                        );
                        return Some((
                            EVT_CONTENT_BLOCK_DELTA.to_string(),
                            serde_json::Value::Object(data_obj),
                        ));
                    }
                };
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_DELTA),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                data_obj.insert("delta".to_string(), delta_val);
                Some((
                    EVT_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::BlockStop { index } => {
                let mut data_obj = serde_json::Map::new();
                data_obj.insert(
                    "type".to_string(),
                    serde_json::json!(EVT_CONTENT_BLOCK_STOP),
                );
                data_obj.insert("index".to_string(), serde_json::json!(index));
                Some((
                    EVT_CONTENT_BLOCK_STOP.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                let mut delta_obj = serde_json::Map::new();
                if let Some(reason) = stop_reason {
                    delta_obj.insert(
                        "stop_reason".to_string(),
                        serde_json::json!(write_anthropic_stop_reason(*reason)),
                    );
                } else {
                    delta_obj.insert("stop_reason".to_string(), serde_json::Value::Null);
                }
                // `stop_sequence`: native Anthropic `message_delta` ALWAYS carries this key —
                // the matched stop string when a stop sequence fired, else explicit `null`. Emit
                // `null` rather than omitting the key so a strict property-presence validator sees
                // the native shape (the TS SDK already treats `undefined`/`null` alike).
                delta_obj.insert(
                    "stop_sequence".to_string(),
                    stop_sequence
                        .as_deref()
                        .map(serde_json::Value::from)
                        .unwrap_or(serde_json::Value::Null),
                );
                let mut usage_map = serde_json::Map::new();
                usage_map.insert(
                    "input_tokens".to_string(),
                    serde_json::json!(usage.input_tokens),
                );
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                if let Some(ccit) = usage.cache_creation_input_tokens {
                    usage_map.insert(
                        "cache_creation_input_tokens".to_string(),
                        serde_json::json!(ccit),
                    );
                }
                if let Some(crit) = usage.cache_read_input_tokens {
                    usage_map.insert(
                        "cache_read_input_tokens".to_string(),
                        serde_json::json!(crit),
                    );
                }
                let mut data_obj = serde_json::Map::new();
                data_obj.insert("type".to_string(), serde_json::json!(EVT_MESSAGE_DELTA));
                data_obj.insert("delta".to_string(), serde_json::Value::Object(delta_obj));
                data_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                Some((
                    EVT_MESSAGE_DELTA.to_string(),
                    serde_json::Value::Object(data_obj),
                ))
            }
            IrStreamEvent::MessageStop => Some((
                EVT_MESSAGE_STOP.to_string(),
                serde_json::json!({ "type": EVT_MESSAGE_STOP }),
            )),
            IrStreamEvent::Error(err) => {
                // Native Anthropic in-stream error event:
                // `{"type":"error","error":{"type":<type>,"message":<msg>}}`. The SDK's streaming
                // decoder reads BOTH `error.type` (→ typed exception) AND `error.message` (the
                // human-readable description, a required field in the documented shape). Omitting
                // `message` leaves the SDK's `APIError` with an undefined description and is a
                // distinguishability tell vs a native event.
                let mut error_obj = serde_json::Map::new();
                match err.provider_signal {
                    Some(ref ps) => {
                        error_obj.insert("type".to_string(), serde_json::json!(ps));
                    }
                    None => {
                        error_obj.insert("type".to_string(), serde_json::Value::Null);
                    }
                }
                // The IR carries no separate message string (IrError == CanonicalSignal, which has
                // no `message` field), so derive a human-readable one from the signal: prefer the
                // provider type when present, otherwise a generic fallback. Always non-empty so the
                // SDK's `error.message` is never undefined/null.
                //
                // The message text MUST stay native-plausible: a real Anthropic streaming `error`
                // event never carries reverse-proxy vocabulary ("upstream", "gateway", "backend",
                // …). The provider type token (`provider_signal`, e.g. `overloaded_error`) is the
                // provider's OWN type string, so emit it VERBATIM — never prefixed with router/proxy
                // words. When no signal is present, fall back to the generic native phrasing.
                let message = match err.provider_signal.as_deref() {
                    Some(ps) if !ps.is_empty() => ps.to_string(),
                    Some(_) | None => "an error occurred while streaming the response".to_string(),
                };
                error_obj.insert("message".to_string(), serde_json::json!(message));
                let mut data_obj = serde_json::Map::new();
                // Native Anthropic in-stream error data body carries the top-level `type:"error"`
                // discriminator matching the SSE `event: error` header — exactly like every other
                // event arm inserts its own `type`. An SDK that dispatches on `data.type` (the
                // documented shape) won't recognize the event as an error without it, and its
                // absence is a proxy-signature tell vs a native stream.
                data_obj.insert("type".to_string(), serde_json::json!("error"));
                data_obj.insert("error".to_string(), serde_json::Value::Object(error_obj));
                Some(("error".to_string(), serde_json::Value::Object(data_obj)))
            }
        }
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // id: an official SDK's `Message.id` is a REQUIRED `"msg_<rand>"` string — the Python/TS SDK
        // types `Message.id` as a non-optional `str`, so a body that omits it fails to decode. Emit
        // it UNCONDITIONALLY, mirroring the streaming `message_start` writer and every
        // other protocol writer (openai/cohere/responses), all of which `unwrap_or_else` a synthesized
        // id rather than gating on a second field:
        //   * same-protocol passthrough / any source that carried an id — `resp.id` is `Some`; re-emit
        //     it verbatim so a native SDK sees the exact id its backend assigned.
        //   * id absent (`resp.id == None`) — synthesize a protocol-correct `msg_<rand>` via
        //     `synth_message_id`. This covers BOTH the cross-protocol path where the source recorded a
        //     `created` (e.g. OpenAI) AND the path where the source recorded neither id nor created
        //     (e.g. a Bedrock Converse body, whose reader returns `created: None`) — the latter
        //     previously hit a `(None, None)` arm that emitted NO `id`, producing an invalid Message
        //     for a Bedrock→Anthropic non-stream client. Synthesis is safe for idempotence because
        //     `write_response` runs ONLY on the cross-protocol translate path (see the `stop_sequence`
        //     note below: same-protocol non-stream relays the raw upstream body and never reaches this
        //     writer), so there is no same-protocol read→write→read round-trip to keep id-less.
        let id = resp.id.clone().unwrap_or_else(synth_message_id);
        obj.insert("id".to_string(), serde_json::json!(id));

        // type/role are constant for a Messages API response ("message"/"assistant").
        obj.insert("type".to_string(), serde_json::json!("message"));
        obj.insert("role".to_string(), serde_json::json!("assistant"));

        // model: the official SDKs type `Message.model` as a REQUIRED non-optional string, so a body
        // that omits it fails to decode (Pydantic/Zod validation error). Emit it UNCONDITIONALLY,
        // mirroring the `id` handling above. On a cross-protocol path where the egress reader didn't
        // populate `resp.model` (notably Bedrock→Anthropic, whose `read_response` may not surface a
        // model), fall back to an empty string so the key is always present and structurally valid
        // rather than dropping it. Same-protocol passthrough preserves the upstream value verbatim.
        let model = resp.model.as_deref().unwrap_or("");
        obj.insert("model".to_string(), serde_json::json!(model));

        // content blocks
        let content_array: Vec<serde_json::Value> = resp.content.iter().map(write_block).collect();
        obj.insert(
            "content".to_string(),
            serde_json::Value::Array(content_array),
        );

        // stop_reason (omit if None — a native body omits it until the turn ends, and omitting
        // keeps same-protocol round-trips lossless)
        if let Some(ref reason) = resp.stop_reason {
            obj.insert(
                "stop_reason".to_string(),
                serde_json::json!(write_anthropic_stop_reason(*reason)),
            );
        }

        // stop_sequence: a native non-streaming Anthropic `Message` ALWAYS carries this key — the
        // matched stop string when a stop sequence fired, JSON `null` otherwise (the SDK types
        // `Message.stop_sequence` as `Optional[str]` and always populates it). `write_response` runs
        // ONLY on the cross-protocol translate path (proxy engine: same-protocol non-stream relays the
        // raw upstream body and never reaches here), where the egress is Anthropic and must byte-match
        // the native shape — so emit an explicit `null` when absent rather than omitting the key. A
        // read→write→read round-trip stays IR-idempotent (`read_response` maps a `null`
        // `stop_sequence` back to `None`). Same conformance class as the streaming `message_delta`
        // `stop_sequence`.
        match &resp.stop_sequence {
            Some(seq) => {
                obj.insert("stop_sequence".to_string(), serde_json::json!(seq));
            }
            None => {
                obj.insert("stop_sequence".to_string(), serde_json::Value::Null);
            }
        }

        // usage
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        if let Some(ccit) = resp.usage.cache_creation_input_tokens {
            usage_map.insert(
                "cache_creation_input_tokens".to_string(),
                serde_json::json!(ccit),
            );
        }
        if let Some(crit) = resp.usage.cache_read_input_tokens {
            usage_map.insert(
                "cache_read_input_tokens".to_string(),
                serde_json::json!(crit),
            );
        }
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}
