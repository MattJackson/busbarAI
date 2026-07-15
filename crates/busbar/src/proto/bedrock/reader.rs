use super::*;

impl ProtocolReader for BedrockReader {
    fn uses_sigv4_ingress_auth(&self) -> bool {
        // A Bedrock-SDK client signs inbound requests with AWS SigV4 (access-key-id + secret tied to
        // a busbar virtual key), not a bearer token — so the auth middleware runs the SigV4 verify
        // path for bedrock ingress. Every other protocol uses the default (bearer / api-key).
        true
    }

    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body once. Bedrock error responses carry the human-readable
        // text in `message` and the machine-readable error type in `__type`
        // (e.g. `ValidationException`, `ThrottlingException`). The structured
        // type is what the breaker's error_map keys on for fine-grained routing,
        // so it must come from `__type`, not from `message`.
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
            Ok(json) => {
                let provider_code = json
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(String::from);
                // AWS may also serialise the type as `__type` containing a
                // shape ARN suffix (e.g. `com.amazon...#ThrottlingException`);
                // keep only the trailing type token in that case.
                let structured_type = json
                    .get("__type")
                    .and_then(|t| t.as_str())
                    .map(|t| t.rsplit(['#', '/']).next().unwrap_or(t).to_string());
                (provider_code, structured_type)
            }
            Err(_) => (None, None),
        };

        // Bedrock has no distinct context-length error CODE: an oversized request comes back as a
        // generic `ValidationException` whose human-readable `message` carries the signal (e.g.
        // "Input is longer than the maximum number of tokens allowed" or a "maximum-tokens …
        // requested" phrasing). Without surfacing the canonical `context_length_exceeded` code here,
        // the breaker pipeline (normalize_raw_error → StatusClass) would route an oversized request
        // as a plain ClientError and PENALIZE the lane instead of failing over without penalty. Mirror
        // `AnthropicReader::extract_error`: scan the raw body for the context-length phrasing and
        // override `provider_code` so the breaker (breaker.rs `code == "context_length_exceeded"`)
        // maps it to `StatusClass::ContextLength`. Keep this in sync with the `classify` helper below.
        //
        // GATE THE SCAN ON A 400. Bedrock ONLY emits an oversized-context error as a `400
        // ValidationException` — never as a 5xx. The raw body-text scan, left ungated, would also
        // fire on a 5xx whose body merely happened to echo the phrasing (e.g. an upstream
        // server-error envelope quoting the request, or a proxied error message), misclassifying a
        // genuine ServerError as ContextLength and triggering a no-penalty failover that masks an
        // unhealthy lane. Confining the override to `status == 400` means a 5xx can never trip it
        // (the structured ServerError path is preserved), while every real Bedrock context-length
        // error — which is always a 400 — is still caught.
        let provider_code = if status == StatusCode::BAD_REQUEST {
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("input is longer than the maximum number of tokens")
                || (lower.contains("maximum-tokens") && lower.contains("requested"))
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
                Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
            } else {
                provider_code
            }
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

        // Keep this set of context-length phrasings in LOCKSTEP with the production
        // `extract_error` above (R21 #17 added the third `exceeds the maximum` pattern there but
        // not here, drifting the two). All three must match identically so the test-only classifier
        // mirrors what the breaker actually sees. The `status == 400` gate is ALSO part of that
        // lockstep (R23 LOW #14): `extract_error` only runs the body-scan override on a 400
        // ValidationException, so a 5xx body that happens to echo context-length phrasing must NOT
        // be reclassified as ContextLength here either — it falls through to the ServerError arm
        // below.
        if status == StatusCode::BAD_REQUEST
            && (lower.contains("input is longer than the maximum number of tokens")
                || (lower.contains("maximum-tokens") && lower.contains("requested"))
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context"))))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
                retry_after: None,
            };
        }

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

        // Collect every unmodeled top-level request field into `extra` so a same-protocol
        // Bedrock->Bedrock passthrough re-emits them faithfully (see `write_request`, which merges
        // `req.extra`). Without this, native Converse fields this reader does not explicitly model —
        // `topP`, `topK`, `stopSequences`, `additionalModelRequestFields`, `guardrailConfig`,
        // `additionalModelResponseFieldPaths`, `performanceConfig`, `promptVariables`, etc. — are
        // silently dropped, changing model behaviour (guardrails disabled, sampling reset) and making
        // the proxy behaviourally divergent from a direct AWS call. Mirrors the Gemini/Cohere readers.
        // `stream` is the route-injected streaming discriminant captured into `IrRequest.stream`
        // below; it is intentionally NOT echoed via `extra` (a native Bedrock body never carries it,
        // and re-emitting it would be a tell). All other modeled keys are re-serialised by
        // `write_request` from the structured IR, so excluding them here avoids a double-emit.
        // NOTE: `inferenceConfig` is DELIBERATELY NOT modeled-out here. This reader only typed two of
        // its sub-fields (`maxTokens`, `temperature`); the rest — `stopSequences`, `topP`, `topK`,
        // `stopCriteria`, and any future AWS-defined sub-field — were silently dropped on both
        // same-protocol passthrough AND cross-protocol egress, changing model behaviour (no stop at
        // the requested sequences, different sampling) and making the proxy behaviourally divergent
        // from a direct AWS call. So we capture the WHOLE raw `inferenceConfig` object into `extra`
        // (preserving every sub-field verbatim) and let `write_request` overlay the two typed fields
        // (`maxTokens`/`temperature`) onto that raw object. The two typed fields are still parsed into
        // the structured IR below for cross-protocol egress; the raw capture is what makes a
        // Bedrock->Bedrock passthrough re-emit `stopSequences`/`topP`/`topK` faithfully.
        // The modeled top-level keys this reader handles structurally (so they must NOT be swept into
        // `extra`). Held as a sorted `&'static` slice and probed with `binary_search`: a fixed,
        // four-element membership set that was previously a `HashSet` rebuilt (and heap-allocated) on
        // every `read_request` call on the Bedrock ingress hot path. A sorted-slice binary search is
        // allocation-free and faster than hashing for a set this small. MUST stay sorted for
        // `binary_search` — keep alphabetical when editing.
        // NOTE: `toolConfig` is DELIBERATELY NOT modeled-out here (mirroring `inferenceConfig`). This
        // reader only typed ONE of its sub-fields — `tools` (extracted into `ir.tools` below) — while
        // the rest, notably `toolChoice` (`{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`, the
        // force-tool-use control) and any future AWS-defined sub-field, were silently dropped on a
        // same-protocol passthrough whenever the writer rebuilt the body. A native AWS client that sets
        // `toolChoice: {any: {}}` to force mandatory tool use would have that constraint stripped,
        // changing model behaviour (the model may skip the tool) and diverging from a direct AWS call.
        // So we capture the WHOLE raw `toolConfig` object into `extra` (preserving `toolChoice`
        // verbatim) and let `write_request` overlay the typed `tools` array onto that raw object. The
        // `tools` array is still parsed into the structured IR below for cross-protocol egress; the raw
        // capture is what makes a Bedrock->Bedrock passthrough re-emit `toolChoice` faithfully.
        const MODELED_KEYS: &[&str] = &["messages", "model", "stream", "system"];
        debug_assert!(
            MODELED_KEYS.windows(2).all(|w| w[0] < w[1]),
            "MODELED_KEYS must stay sorted for binary_search"
        );

        let mut extra = serde_json::Map::new();
        for (key, value) in obj.iter() {
            if MODELED_KEYS.binary_search(&key.as_str()).is_err() {
                extra.insert(key.clone(), value.clone());
            }
        }

        // Captures native `cachePoint` markers (with their ORIGINAL absolute array index) so the
        // writer can re-emit them at the same position on a same-protocol passthrough. See
        // `CACHE_POINTS_SENTINEL`. Kept as `Value`s ready to nest under the sentinel object.
        let mut system_cache_points: Vec<serde_json::Value> = Vec::new();
        let mut message_cache_points: Vec<serde_json::Value> = Vec::new();
        // Captured native `guardContent` (inline Guardrails) markers, same stash shape as the
        // cachePoint capture; see `GUARD_CONTENT_SENTINEL`.
        let mut system_guard_content: Vec<serde_json::Value> = Vec::new();
        let mut message_guard_content: Vec<serde_json::Value> = Vec::new();

        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(system_arr) = obj.get("system").and_then(|s| s.as_array()) {
            for (idx, sys_val) in system_arr.iter().enumerate() {
                if let Some(text_val) = sys_val.get("text").and_then(|t| t.as_str()) {
                    system_blocks.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                } else if let Some(cache_point) = sys_val.get("cachePoint") {
                    // No IR counterpart for a prompt-cache marker; stash it with its original index
                    // so the writer re-emits it verbatim at the same position (a same-protocol
                    // passthrough keeps prompt caching enabled instead of silently dropping it).
                    system_cache_points.push(serde_json::json!({
                        "i": idx,
                        "block": { "cachePoint": cache_point.clone() },
                    }));
                    // ALSO map the marker onto the preceding block's first-class IR `cache_control`
                    // (H3 cross-protocol): the positional stash above is dropped on the cross-protocol
                    // seam, so without this a Bedrock->Anthropic hop would lose the prompt-cache
                    // boundary. Additive — the stash still drives the byte-identical same-protocol
                    // round-trip; the writer suppresses the inline `cache_control` emission whenever
                    // the stash is present, so the two never double-emit.
                    set_preceding_block_cache_control(&mut system_blocks);
                } else if let Some(guard_content) = sys_val.get("guardContent") {
                    // No IR counterpart for an inline Guardrails marker; stash it with its original
                    // index so the writer re-emits it verbatim at the same position (a same-protocol
                    // passthrough keeps the guardrail span the caller marked instead of silently
                    // dropping it). See `GUARD_CONTENT_SENTINEL`.
                    system_guard_content.push(serde_json::json!({
                        "i": idx,
                        "block": { "guardContent": guard_content.clone() },
                    }));
                }
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(msgs_arr) = obj.get("messages").and_then(|m| m.as_array()) {
            for (msg_idx, msg_val) in msgs_arr.iter().enumerate() {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");

                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                            retry_after: None,
                        })
                    }
                };

                let mut msg_content: Vec<crate::ir::IrBlock> = Vec::new();
                if let Some(content_arr) = msg_val.get("content").and_then(|c| c.as_array()) {
                    for (block_idx, content_val) in content_arr.iter().enumerate() {
                        if let Some(text_val) = content_val.get("text").and_then(|t| t.as_str()) {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text_val.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(tool_use) = content_val.get("toolUse") {
                            let tu_id = tool_use
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = tool_use
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let input = tool_use
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);

                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id: tu_id,
                                name,
                                input,
                                cache_control: None,
                            });
                        } else if let Some(tool_result) = content_val.get("toolResult") {
                            let tu_id = tool_result
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();

                            let mut inner_content: Vec<crate::ir::IrBlock> = Vec::new();
                            if let Some(inner_arr) =
                                tool_result.get("content").and_then(|c| c.as_array())
                            {
                                for inner_val in inner_arr {
                                    if let Some(text_val) =
                                        inner_val.get("text").and_then(|t| t.as_str())
                                    {
                                        inner_content.push(crate::ir::IrBlock::Text {
                                            text: text_val.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    } else if let Some(json_val) = inner_val.get("json") {
                                        // A native Converse `{"json": <value>}` tool-result block is
                                        // structured data with no text/image analog — carry it as the
                                        // typed `IrBlock::Json` so `write_request` re-emits a faithful
                                        // `{"json": ...}` block on same-protocol egress (the old reader
                                        // serialized it into a `{"text": "..."}` string, losing the
                                        // json/text distinction).
                                        inner_content
                                            .push(crate::ir::IrBlock::Json(json_val.clone()));
                                    } else if let Some(image) = inner_val.get("image") {
                                        // The Converse `ToolResultContentBlock` union also includes
                                        // `image` (and `document`/`video`). Decode `image`
                                        // symmetric with the WRITER, which emits an `image` inside a
                                        // toolResult (see `write_request`) — the old reader skipped
                                        // any non-text/json block, silently dropping image tool
                                        // results and making read/write asymmetric. `document` and
                                        // `video` have no IR block counterpart (the IR models only
                                        // Text/Thinking/ToolUse/ToolResult/Image), so they remain
                                        // unrepresentable and are left undecoded — a documented
                                        // limitation, not a silent class-wide loss of all binary
                                        // tool-result content.
                                        if let Some(block) = read_bedrock_image_block(image) {
                                            inner_content.push(block);
                                        }
                                    } else if let Some(document) = inner_val.get("document") {
                                        // `document`/`video` members of the ToolResultContentBlock
                                        // union have no IR block counterpart and were silently lost.
                                        // Best-effort: an AWS DocumentBlock carries text only nested
                                        // under `source.content[].text` (there is NO flat `.text`);
                                        // flatten any such text into an IR Text block so a textual
                                        // document survives. Always warn so the (partial) loss is
                                        // observable rather than silent.
                                        tracing::warn!(
                                            "bedrock tool-result `document` block has no IR \
                                             counterpart; flattening any nested source text, \
                                             dropping the rest"
                                        );
                                        if let Some(content_arr) = document
                                            .get("source")
                                            .and_then(|s| s.get("content"))
                                            .and_then(|c| c.as_array())
                                        {
                                            for piece in content_arr {
                                                if let Some(t) =
                                                    piece.get("text").and_then(|t| t.as_str())
                                                {
                                                    inner_content.push(crate::ir::IrBlock::Text {
                                                        text: t.to_string(),
                                                        cache_control: None,
                                                        citations: Vec::new(),
                                                    });
                                                }
                                            }
                                        }
                                    } else if inner_val.get("video").is_some() {
                                        // `video` likewise has no IR counterpart and no flat text to
                                        // salvage — warn instead of dropping silently.
                                        tracing::warn!(
                                            "bedrock tool-result `video` block has no IR \
                                             counterpart; dropping it"
                                        );
                                    }
                                }
                            }

                            let is_error = tool_result
                                .get("status")
                                .and_then(|s| s.as_str())
                                .map(|s| s == "error")
                                .unwrap_or(false);

                            msg_content.push(crate::ir::IrBlock::ToolResult {
                                tool_use_id: tu_id,
                                content: inner_content,
                                is_error,
                                cache_control: None,
                            });
                        } else if let Some(image) = content_val.get("image") {
                            // Decode both `source.bytes` (base64) AND `source.s3Location` (an S3
                            // URI) — the two members of the Converse `ImageSource` union. An
                            // S3-referenced image is stashed under the `image_s3` sentinel so the
                            // writer re-emits `source.s3Location` on same-protocol egress instead of
                            // dropping it (the old reader only read `bytes`, silently losing it).
                            if let Some(block) = read_bedrock_image_block(image) {
                                msg_content.push(block);
                            }
                        } else if let Some(reasoning) = content_val.get("reasoningContent") {
                            // A native Converse `reasoningContent` (extended-thinking) block maps onto
                            // IR `Thinking { text, signature }` (mirroring anthropic.rs `thinking`).
                            // The old reader skipped every non-text/toolUse/toolResult/image/cachePoint
                            // block, so an assistant turn carrying its prior reasoning had that
                            // reasoning silently DROPPED on a same-protocol passthrough — and Bedrock
                            // REQUIRES the signed reasoning echoed back on the follow-up turn, so the
                            // loss made the proxy diverge from a direct AWS call. `redactedContent` is
                            // carried via the redacted-signature sentinel so it re-emits faithfully.
                            // A future union member yields `None` (left undecoded, not mis-mapped).
                            // `redacted` is a typed flag the reader sets only on a genuine native
                            // `redactedContent` member, so a client cannot forge a redacted block via a
                            // `reasoningText.signature` — no ingress scrub needed.
                            if let Some(block) = read_bedrock_reasoning_block(reasoning) {
                                msg_content.push(block);
                            }
                        } else if let Some(cache_point) = content_val.get("cachePoint") {
                            // No IR counterpart for a prompt-cache marker; stash it with its
                            // (message, block) index so the writer re-emits it verbatim at the same
                            // position on a same-protocol passthrough (prompt caching stays enabled
                            // instead of being silently dropped — a real cost regression otherwise).
                            message_cache_points.push(serde_json::json!({
                                "m": msg_idx,
                                "i": block_idx,
                                "block": { "cachePoint": cache_point.clone() },
                            }));
                            // ALSO map the marker onto the preceding block's first-class IR
                            // `cache_control` (H3 cross-protocol) so the prompt-cache boundary
                            // survives a Bedrock->Anthropic hop where the positional stash is dropped.
                            // Additive — see `set_preceding_block_cache_control`; the writer suppresses
                            // the inline emission while the stash is present, so no double-emit.
                            set_preceding_block_cache_control(&mut msg_content);
                        } else if let Some(guard_content) = content_val.get("guardContent") {
                            // No IR counterpart for an inline Guardrails marker; stash it with its
                            // (message, block) index so the writer re-emits it verbatim at the same
                            // position on a same-protocol passthrough (the guardrail span the caller
                            // marked stays present instead of being silently dropped). See
                            // `GUARD_CONTENT_SENTINEL`.
                            message_guard_content.push(serde_json::json!({
                                "m": msg_idx,
                                "i": block_idx,
                                "block": { "guardContent": guard_content.clone() },
                            }));
                        }
                    }
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tool_config) = obj.get("toolConfig").and_then(|t| t.as_object()) {
            if let Some(tools_arr) = tool_config.get("tools").and_then(|t| t.as_array()) {
                for tool_val in tools_arr {
                    if let Some(tool_spec) = tool_val.get("toolSpec").and_then(|t| t.as_object()) {
                        let name = tool_spec
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = tool_spec
                            .get("description")
                            .and_then(|d| d.as_str().map(String::from));

                        let input_schema = if let Some(input_schema) = tool_spec.get("inputSchema")
                        {
                            input_schema
                                .get("json")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        } else {
                            serde_json::Value::Null
                        };

                        tools.push(crate::ir::IrTool {
                            name,
                            description,
                            input_schema,
                            cache_control: None,
                        });
                    } else if tool_val.get("cachePoint").is_some() {
                        // A `cachePoint` entry in the `toolConfig.tools` array marks the prompt-cache
                        // boundary for the tool DEFINITIONS preceding it (Anthropic places the same
                        // breakpoint on a tool). Map it onto the preceding tool's first-class IR
                        // `cache_control` (H3) so the boundary survives the cross-protocol seam. There
                        // is no positional tool-cachePoint stash, so this is the sole carrier; on
                        // same-protocol egress the writer re-emits the marker from this field. A
                        // leading cachePoint with no preceding tool has nothing to attach to and is
                        // dropped (a tool-list prefix boundary with an empty prefix is a no-op).
                        //
                        // LOW (accepted): degenerate tools-array cachePoint shapes — a LEADING
                        // cachePoint (no preceding tool) or DOUBLED adjacent cachePoints — do not
                        // byte-round-trip (the leading one is dropped; doubled ones collapse onto the
                        // one preceding tool's single boolean field). This is a no-op only on inputs
                        // AWS itself REJECTS (a tool-cache breakpoint with an empty/duplicate prefix is
                        // not a valid Converse `toolConfig`), so there is no valid request whose
                        // fidelity it harms; not worth a positional stash to preserve invalid shapes.
                        if let Some(last) = tools.last_mut() {
                            last.cache_control = Some(crate::ir::CacheControl {
                                kind: crate::ir::CacheKind::Ephemeral,
                            });
                        }
                    }
                }
            }
        }

        // Promote Bedrock's native `toolConfig.toolChoice` into the IR union (PF-H1) so a forced /
        // targeted directive survives the cross-protocol seam instead of degrading to `auto`.
        let tool_choice = read_bedrock_tool_choice(obj.get("toolConfig"));

        let max_tokens = if let Some(inference_config) =
            obj.get("inferenceConfig").and_then(|i| i.as_object())
        {
            inference_config
                .get("maxTokens")
                .and_then(|v| v.as_u64())
                .filter(|&v| v > 0)
                // Bounds-checked: a bare `as u32` would silently TRUNCATE (wrap) a value above
                // u32::MAX (e.g. 5_000_000_000 → 705_032_704) and forward it as a real cap the
                // caller never asked for, diverging from a direct AWS call. Drop out-of-range
                // values to None so the backend applies its own default. Mirrors the Gemini reader.
                .and_then(|v| u32::try_from(v).ok())
        } else {
            None
        };

        let inference_config = obj.get("inferenceConfig").and_then(|i| i.as_object());
        let temperature =
            inference_config.and_then(|ic| ic.get("temperature").and_then(|v| v.as_f64()));
        // Promoted sampling controls in Bedrock's `inferenceConfig`: topP and stopSequences. `topK`
        // is NOT an inferenceConfig field (it lives in model-specific `additionalModelRequestFields`),
        // so it is promoted from THERE (see `top_k` below). These two are ALSO preserved verbatim in
        // the raw `inferenceConfig` captured into `extra` for the same-protocol passthrough; the IR
        // fields are what carry them across the cross-protocol seam (where `extra` is cleared). The
        // writer's overlay re-emits the typed fields onto the raw object, so a Bedrock->Bedrock
        // round-trip is unaffected (the overlaid value equals the captured one).
        let top_p = inference_config.and_then(|ic| ic.get("topP").and_then(|v| v.as_f64()));
        // Promote `top_k` (PF-H1 fidelity fix). Bedrock's Converse API carries `top_k` only via the
        // model-specific `additionalModelRequestFields` escape hatch (it has no `inferenceConfig`
        // home). Anthropic-on-Bedrock and several model families spell it `top_k`; some use `topK`.
        // Accept either so a native Bedrock request that pins top_k populates the first-class IR field
        // and survives the cross-protocol seam (where `extra` is cleared) instead of vanishing. The
        // raw `additionalModelRequestFields` is still captured verbatim into `extra` for the
        // same-protocol passthrough; the writer overlays the typed `top_k` back onto it.
        // Track which spelling the source used so the writer can re-emit it (losslessness): prefer
        // snake_case `top_k`, fall back to camelCase `topK`. `top_k_was_camel` is true only when the
        // value came from the `topK` key, so a same-protocol passthrough that spelled it `topK`
        // round-trips byte-identically instead of being renamed to `top_k`.
        let amrf = obj
            .get("additionalModelRequestFields")
            .and_then(|v| v.as_object());
        let mut top_k_was_camel = false;
        let top_k = amrf
            .and_then(|amrf| {
                amrf.get("top_k").or_else(|| {
                    top_k_was_camel = true;
                    amrf.get("topK")
                })
            })
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Only meaningful when a usable top_k actually came from the camel key; reset otherwise so a
        // present-but-`top_k`-spelled (or absent/out-of-range) value never stamps the sentinel.
        top_k_was_camel &= top_k.is_some();
        let stop =
            crate::ir::read_stop_sequences(inference_config.and_then(|ic| ic.get("stopSequences")));

        // Stash any captured `cachePoint` markers (with their original positions) under the sentinel
        // so `write_request` re-emits them at the same spots on a same-protocol passthrough. Only
        // inserted when at least one was present, so a request that never used prompt caching does
        // not gain a stray key (and the byte-exact round-trip of a cache-free body is preserved).
        if !system_cache_points.is_empty() || !message_cache_points.is_empty() {
            let mut cache_points = serde_json::Map::new();
            if !system_cache_points.is_empty() {
                cache_points.insert(
                    "system".to_string(),
                    serde_json::Value::Array(system_cache_points),
                );
            }
            if !message_cache_points.is_empty() {
                cache_points.insert(
                    "messages".to_string(),
                    serde_json::Value::Array(message_cache_points),
                );
            }
            extra.insert(
                CACHE_POINTS_SENTINEL.to_string(),
                serde_json::Value::Object(cache_points),
            );
        }

        // Stash any captured `guardContent` markers (with their original positions) under the
        // sentinel so `write_request` re-emits them at the same spots on a same-protocol passthrough.
        // Only inserted when at least one was present, so a request that used no inline guardrails
        // does not gain a stray key (preserving the byte-exact round-trip of a guard-free body).
        if !system_guard_content.is_empty() || !message_guard_content.is_empty() {
            let mut guard_content = serde_json::Map::new();
            if !system_guard_content.is_empty() {
                guard_content.insert(
                    "system".to_string(),
                    serde_json::Value::Array(system_guard_content),
                );
            }
            if !message_guard_content.is_empty() {
                guard_content.insert(
                    "messages".to_string(),
                    serde_json::Value::Array(message_guard_content),
                );
            }
            extra.insert(
                GUARD_CONTENT_SENTINEL.to_string(),
                serde_json::Value::Object(guard_content),
            );
        }

        // Stamp the source-spelling hint when top_k arrived as camelCase `topK`, so the writer
        // re-emits `topK` on a same-protocol passthrough (else the canonical `top_k`). `extra` is
        // cleared on the cross-protocol seam, so the sentinel naturally vanishes there and a
        // cross-protocol egress emits the canonical `top_k`. Only inserted when it produced a usable
        // value, so a body that never carried a camel top_k does not gain a stray key.
        if top_k_was_camel {
            extra.insert(
                TOP_K_CAMEL_SENTINEL.to_string(),
                serde_json::Value::Bool(true),
            );
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
            // Bedrock's native Converse request body has no `stream` field — streaming is selected
            // by the endpoint (converse vs converse-stream). The Bedrock ingress route therefore
            // INJECTS `"stream": true` into the body for converse-stream requests before this reader
            // runs (see `ingress_path_model`), so on a Bedrock-INGRESS cross-protocol request the
            // re-parsed IR must carry that flag through — otherwise the target egress writer is never
            // told to produce a streaming body and a client that called /converse-stream silently
            // gets a buffered (non-streaming) response. Defaults to false when the field is absent
            // (a native Bedrock egress reads the flag from the endpoint, not the body, so this is
            // a no-op for the same-protocol path).
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
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

        if !data.is_object() {
            return out;
        }

        match data.get("type").and_then(|t| t.as_str()) {
            Some(ET_MESSAGE_START) => {
                if !state.started {
                    state.started = true;
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id: None,
                        created: None,
                        model: None,
                    });
                }
            }

            Some(ET_CONTENT_BLOCK_START) => {
                let idx = clamp_content_block_index(data);

                if let Some(start_obj) = data.get("start").and_then(|s| s.as_object()) {
                    if let Some(tool_use) = start_obj.get("toolUse").and_then(|t| t.as_object()) {
                        // Mirror the `state.started` guard the text branch (below) enforces: a
                        // BlockStart must NEVER precede the MessageStart it belongs to. Without this
                        // guard, a `contentBlockStart` arriving before `messageStart` (malformed or
                        // reordered stream) would emit a tool BlockStart ahead of MessageStart,
                        // breaking the IR ordering invariant downstream consumers rely on. Skip it.
                        if state.started {
                            let tu_id = tool_use
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = tool_use
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();

                            out.push(IrStreamEvent::BlockStart {
                                index: idx,
                                block: crate::ir::IrBlockMeta::ToolUse { id: tu_id, name },
                            });
                        }
                    } else if start_obj.contains_key("reasoningContent")
                        && state.started
                        && !state.thinking_block_open
                    {
                        // Some Bedrock-compatible backends prefix a streamed reasoning block with an
                        // explicit `contentBlockStart` carrying an (empty) `reasoningContent` start
                        // object, rather than implying the block on the first delta. Open the Thinking
                        // block here so the following `reasoningContent` deltas attach to it; the
                        // delta arm's lazy-open then sees the flag already set and does not re-open it.
                        // (The native AWS `ContentBlockStart` union only models `toolUse`, so a real
                        // AWS stream never takes this branch — it lazily opens on the first delta.)
                        state.thinking_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Thinking,
                        });
                    } else if start_obj.is_empty() && state.started && !state.text_block_open {
                        // The native Bedrock ConverseStream wire sends `contentBlockStart` with an
                        // empty `start: {}` for a text block. Only that empty-object shape opens a
                        // Text block. A `start` object carrying an unrecognized key (e.g. a future
                        // `image`/`reasoningContent` block type) is NOT a text block: skip it rather
                        // than mis-opening a spurious Text block (forward-compatibility). Mirrors the
                        // defensive Gemini/Cohere readers.
                        state.text_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                } else if state.started && !state.text_block_open {
                    // No `start` object at all → a text block (the absent-`start` text shape).
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
            }

            Some(ET_CONTENT_BLOCK_DELTA) => {
                let idx = clamp_content_block_index(data);

                if let Some(delta_obj) = data.get("delta").and_then(|d| d.as_object()) {
                    if delta_obj.contains_key("text") {
                        let text_val = delta_obj
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();

                        out.push(IrStreamEvent::BlockDelta {
                            index: idx,
                            delta: crate::ir::IrDelta::TextDelta(text_val),
                        });
                    } else if let Some(tool_use) =
                        delta_obj.get("toolUse").and_then(|t| t.as_object())
                    {
                        if let Some(input_str) = tool_use.get("input").and_then(|i| i.as_str()) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(input_str.to_string()),
                            });
                        }
                    } else if let Some(reasoning) = delta_obj
                        .get("reasoningContent")
                        .and_then(|r| r.as_object())
                    {
                        // Native Bedrock ConverseStream streams the model's extended-thinking as a
                        // `reasoningContent` member on `contentBlockDelta`. The buffered reader
                        // (`read_bedrock_reasoning_block`) already preserves this in the non-streaming
                        // path; the streaming path used to silently DROP it — no Thinking BlockStart
                        // and no ThinkingDelta/SignatureDelta were ever emitted. Mirror the buffered
                        // logic here: lazily open the Thinking block on the FIRST reasoningContent
                        // delta (the wire sends NO dedicated `contentBlockStart` for a reasoning
                        // block — it is implied by the first delta), then emit the matching delta.
                        //
                        // The `ReasoningContentBlockDelta` union has three members:
                        //   - `text`            → ThinkingDelta(text)            (plaintext reasoning)
                        //   - `signature`       → SignatureDelta(signature)      (the opaque token)
                        //   - `redactedContent` → RedactedReasoningDelta(bytes)    (opaque encrypted
                        //                         reasoning). A typed delta distinct from the plaintext
                        //                         ThinkingDelta keeps the redacted block to ONE IR
                        //                         delta → ONE Bedrock frame, so the writer re-emits
                        //                         `redactedContent: <bytes>` faithfully without a
                        //                         plaintext `text` leak; non-Bedrock writers drop it.
                        if state.started && !state.thinking_block_open {
                            state.thinking_block_open = true;
                            out.push(IrStreamEvent::BlockStart {
                                index: idx,
                                block: crate::ir::IrBlockMeta::Thinking,
                            });
                        }
                        if state.thinking_block_open {
                            if let Some(text) = reasoning.get("text").and_then(|t| t.as_str()) {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::ThinkingDelta(text.to_string()),
                                });
                            } else if let Some(sig) =
                                reasoning.get("signature").and_then(|s| s.as_str())
                            {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
                                });
                            } else if let Some(redacted) =
                                reasoning.get("redactedContent").and_then(|r| r.as_str())
                            {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::RedactedReasoningDelta(
                                        redacted.to_string(),
                                    ),
                                });
                            }
                            // A future `reasoningContent` delta member with none of the three known
                            // keys carries no representable IR delta; the block stays open and the
                            // unknown member is skipped (forward-compat), mirroring the buffered
                            // reader's `None` arm.
                        }
                    }
                }
            }

            Some(ET_CONTENT_BLOCK_STOP) => {
                let idx = clamp_content_block_index(data);

                // Clear `text_block_open` on ANY contentBlockStop while a text block is open, not
                // only at index 0. Bedrock indexes text blocks that follow a tool-use block at
                // index > 0 (reachable via cross-protocol ingress where a tool-use precedes text).
                // The old `idx == 0` guard left the flag set for a text block opened at index N>0,
                // so the `!state.text_block_open` guard in contentBlockStart stayed true-blocked and
                // every subsequent text block was suppressed — silently dropping the rest of the
                // text content. At most one text block is open at a time on this wire (a new text
                // block only opens once the prior is closed), so the open flag unambiguously belongs
                // to the block whose stop we are processing; tool-use stops never set the flag.
                if state.text_block_open {
                    state.text_block_open = false;
                }

                // Clear the reasoning-block open flag on its stop too, so a subsequent reasoning
                // block (or a reasoning-then-text sequence) opens cleanly. At most one block of a
                // given kind is open at a time on this wire, so the stop unambiguously closes the
                // open thinking block; a text/tool stop with no thinking block open is a no-op here.
                if state.thinking_block_open {
                    state.thinking_block_open = false;
                }

                out.push(IrStreamEvent::BlockStop { index: idx });
            }

            Some(ET_MESSAGE_STOP) => {
                // Bedrock splits the stop reason (`messageStop` frame) from the token usage (a
                // following `metadata` frame). To emit ONE combined `MessageDelta{stop_reason, usage}`
                // — so a cross-protocol ingress (e.g. Anthropic) sees the SINGLE `message_delta` a
                // native non-Bedrock stream carries, instead of two (the previous behavior was a
                // detectable tell) — we BUFFER the stop_reason here and pair it with the usage when
                // `metadata` arrives (see below). The combined delta is emitted from the `metadata`
                // branch.
                //
                // The terminal `MessageStop` is also DEFERRED to the `metadata` branch and emitted
                // AFTER the combined `MessageDelta`. The combined delta carries stop_reason + usage and
                // must precede the terminal stop in IR order, so that a non-eventstream ingress writer
                // (e.g. Anthropic) emits `message_delta` BEFORE `message_stop` — the native order. If
                // the `MessageStop` were emitted here (on `messageStop`, which arrives BEFORE
                // `metadata`), the IR order would be MessageStop-then-MessageDelta and the Anthropic
                // ingress would write `message_stop` before `message_delta` — a wrong, detectable
                // ordering. A bedrock->bedrock round-trip is unaffected: the `MessageStop` IR event
                // maps to no wire frame (`BedrockWriter` returns `None`), and the combined delta is
                // re-split into the native `messageStop` + `metadata` frame pair by `StreamTranslate`.
                state.pending_stop_reason = data
                    .get("stopReason")
                    .and_then(|s| s.as_str())
                    .map(stop_reason_map);
            }

            Some(ET_METADATA) => {
                // Usage trails the stop reason (Bedrock sends `metadata` after `messageStop`). Pair it
                // with the stop_reason buffered from the preceding `messageStop` frame into ONE
                // combined MessageDelta, so a cross-protocol ingress emits a single `message_delta`/
                // usage event (native fidelity) rather than two. A bedrock->bedrock round-trip re-splits
                // this combined delta back into the native `messageStop` + `metadata` frame pair in the
                // writer (`BedrockWriter::write_response_event` fan-out, driven by `StreamTranslate`).
                //
                // The terminal `MessageStop` is emitted HERE, AFTER the combined delta, so the IR order
                // is delta-then-stop and the ingress writer emits its native `message_delta` then
                // `message_stop` (Finding: delta-before-stop ordering). It is pushed unconditionally
                // (even when `metadata` carries no `usage`) so the downstream stream always receives its
                // terminal frame once `metadata` arrives.
                // Emit the combined MessageDelta UNCONDITIONALLY — even when `metadata` carries no
                // `usage` object. Native AWS Bedrock always sends `usage` here, but a mock /
                // Bedrock-compatible backend (common in staging & integration tests) may omit it. The
                // old code took `pending_stop_reason` only INSIDE the `usage` guard, so a usage-less
                // `metadata` dropped the buffered stop_reason entirely and terminated the stream with a
                // bare MessageStop — no preceding MessageDelta. For a Bedrock→Anthropic translation that
                // is a protocol-ordering violation (the Anthropic SDK expects `message_delta` before
                // `message_stop`) AND a silent loss of the stop_reason. We therefore build a usage from
                // whatever the frame carries (zero when absent — harmless) and always emit the delta,
                // consuming the buffered stop_reason, BEFORE the terminal MessageStop. A bare
                // `metadata` with neither usage nor a buffered stop_reason yields a zero-usage,
                // stop_reason-less delta, which is benign.
                let usage_obj = data.get("usage").and_then(|u| u.as_object());
                let (cache_creation_input_tokens, cache_read_input_tokens) =
                    read_cache_usage(usage_obj);
                let usage = crate::ir::IrUsage {
                    input_tokens: usage_obj
                        .and_then(|u| u.get("inputTokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    output_tokens: usage_obj
                        .and_then(|u| u.get("outputTokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens,
                    cache_read_input_tokens,
                };

                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: state.pending_stop_reason.take(),
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
            }

            // Bedrock mid-stream exception event shapes. The `ConverseStream.responseStream` output
            // union has EXACTLY five modeled error-event members — `internalServerException`,
            // `modelStreamErrorException`, `validationException`, `throttlingException`, and
            // `serviceUnavailableException` — any of which can arrive in place of (or before)
            // `messageStop`. (`modelTimeoutException` is a REQUEST-level Converse exception, NOT a
            // member of this stream union, so a real AWS endpoint never emits it mid-stream; it is
            // therefore not accepted here — see `bedrock_stream_exception_for`'s docstring.) Surface
            // a recognized event as an `IrStreamEvent::Error` so the downstream ingress writer
            // terminates the client stream with a protocol-shaped error rather than silently dropping
            // the event and leaving the client on a hanging / EOF-without-terminator stream.
            Some(
                exc @ ("internalServerException"
                | "modelStreamErrorException"
                | "throttlingException"
                | "validationException"
                | "serviceUnavailableException"),
            ) => {
                let message = data
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(String::from);
                // Map each of the five outer-bound exception strings to its StatusClass. Every one
                // the outer `Some(exc @ (...))` arm can bind is listed explicitly (the two
                // server-error strings inclusive) so the class mapping is co-located with the string
                // set rather than hiding behind a `_ => ServerError` default — a new exception added
                // to the outer union without a class here would surface as the documented
                // `other =>` arm, which we keep (not a `_` wildcard) only because `&str` matches are
                // never type-exhaustive; the outer pattern is the real guard.
                let class = match exc {
                    "throttlingException" => StatusClass::RateLimit,
                    "validationException" => StatusClass::ClientError,
                    "serviceUnavailableException" => StatusClass::Overloaded,
                    "internalServerException" | "modelStreamErrorException" => {
                        StatusClass::ServerError
                    }
                    // Unreachable given the outer `Some(exc @ (...))` guard restricts `exc` to the
                    // five strings above. A NAMED binding (not a `_` wildcard, per the no-catch-all
                    // rule — mirrors the `other =>` pattern in proto::openai_family::bearer_error_code)
                    // keeps the arm explicit; ServerError is the safe class for any exception event
                    // whose class is otherwise unknown.
                    other => {
                        let _ = other;
                        StatusClass::ServerError
                    }
                };
                out.push(IrStreamEvent::Error(crate::proto::IrError {
                    class,
                    provider_signal: message.or_else(|| Some(exc.to_string())),
                    retry_after: None,
                }));
            }

            // Any other (or absent) event type is a no-op. This is NOT a disposition/breaker match:
            // it is the wire event-type demux for an open-ended, vendor-extensible event stream, so
            // an unrecognized future event must be skipped (not error) to avoid breaking forward
            // compatibility. The error-bearing event types are handled explicitly above.
            Some(_) | None => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let output_val = obj.get("output").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let message_val = output_val.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(content_arr) = message_val.get("content").and_then(|c| c.as_array()) {
            for block_val in content_arr {
                if let Some(text_val) = block_val.get("text").and_then(|t| t.as_str()) {
                    content.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                } else if let Some(tool_use) = block_val.get("toolUse").and_then(|t| t.as_object())
                {
                    let tu_id = tool_use
                        .get("toolUseId")
                        .and_then(|id| id.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = tool_use
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let input = tool_use
                        .get("input")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    content.push(crate::ir::IrBlock::ToolUse {
                        id: tu_id,
                        name,
                        input,
                        cache_control: None,
                    });
                } else if let Some(reasoning) = block_val.get("reasoningContent") {
                    // A Converse response message can carry a `reasoningContent` (extended-thinking)
                    // block — the model's reasoning output. Mirror the request-side reader: map it
                    // onto IR `Thinking { text, signature }` via `read_bedrock_reasoning_block` (and
                    // the redacted-signature sentinel for `redactedContent`). The old response loop
                    // skipped it entirely, silently DROPPING the model's reasoning so a
                    // bedrock->bedrock passthrough lost the thinking block (and a cross-protocol
                    // egress could not surface it). A future union member yields `None` (undecoded).
                    if let Some(block) = read_bedrock_reasoning_block(reasoning) {
                        content.push(block);
                    } else {
                        tracing::warn!(
                            "dropping Converse response reasoningContent block with no decodable \
                             member (neither reasoningText nor redactedContent)"
                        );
                    }
                } else if let Some(image) = block_val.get("image") {
                    // An assistant Converse response can carry an `image` content block (model
                    // image output / tool-rendered image). Mirror the request-side readers
                    // (`read_request` content loop + the `toolResult` inner loop), which both decode
                    // `image` via `read_bedrock_image_block` — handling both `source.bytes` (base64)
                    // and `source.s3Location` (stashed under the `image_s3` sentinel for faithful
                    // re-emit). Without this arm the response loop silently DROPPED the image,
                    // diverging from a direct AWS call. A block with neither source yields `None`
                    // (no empty-bytes block injected).
                    if let Some(block) = read_bedrock_image_block(image) {
                        content.push(block);
                    } else {
                        tracing::warn!(
                            "dropping Converse response image block with no decodable source \
                             (neither source.bytes nor source.s3Location)"
                        );
                    }
                }
            }
        }

        let stop_reason_val = obj
            .get("stopReason")
            .and_then(|s| s.as_str())
            .map(stop_reason_map);

        // Treat an absent `usage` object leniently, mirroring the streaming path
        // (`read_response_events` defaults each token field to 0 when `metadata` carries no usage):
        // fall back to zero counts rather than hard-erroring. A missing `usage` is an upstream
        // response-format quirk (mock/staging backend, or a future model variant), not a client
        // error, so a spurious `ClientError` here would mislabel the cause and confuse retry logic.
        let usage_obj = obj.get("usage");
        let (cache_creation_input_tokens, cache_read_input_tokens) =
            read_cache_usage(usage_obj.and_then(|u| u.as_object()));
        let usage = crate::ir::IrUsage {
            input_tokens: usage_obj
                .and_then(|u| u.get("inputTokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_obj
                .and_then(|u| u.get("outputTokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens,
            cache_read_input_tokens,
        };

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason: stop_reason_val,
            usage,
            // Identity capture for same-protocol passthrough fidelity. The AWS Converse response
            // body is deliberately minimal: it has NO `id`, NO `created`, NO `system_fingerprint`,
            // and NO stop-sequence echo (`stopReason` is the discriminant, captured above; `usage`
            // is captured above). The only identity AWS returns is the `x-amzn-RequestId` HTTP
            // header, which is not part of the body this reader sees. So every body-level identity
            // field is `None` here — that is the faithful capture of what Bedrock actually sends,
            // and a bedrock→bedrock passthrough reproduces the native (id-less) body exactly.
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}
