use super::*;

/// The cached streaming-CT set aggregated from the writer vtable must be exactly the SSE +
/// AWS-event-stream pair the per-request sweep produced — the `OnceLock` only memoizes it.
#[test]
fn test_streaming_content_types_cached_set() {
    let got = streaming_content_types();
    let mut want = ["text/event-stream", "application/vnd.amazon.eventstream"]; // golden wire-contract literal (kept bare on purpose)
    want.sort_unstable();
    assert_eq!(
        got, want,
        "cached streaming CT set must be exactly the SSE + amazon-eventstream pair"
    );
}

/// The cached array-stream shim-key set must be exactly Gemini's `GEMINI_JSON_ARRAY_SHIM_KEY`
/// (the only writer that overrides `array_stream_shim_key`).
#[test]
fn test_array_stream_shim_keys_cached_set() {
    assert_eq!(
        array_stream_shim_keys(),
        [crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY],
        "cached shim-key set must be exactly the gemini json-array key"
    );
}

/// Regression for the conformance bug where `find_frame_terminator` reported `term_len = 3`
/// for the spec-legal CRLF blank-line terminator (`\r\n\r\n`, 4 bytes), contradicting its own
/// documented contract (`offset` = index of the FIRST terminator byte, `len` = terminator
/// length). The slice `end = offset + len` happened to land correctly only because the old
/// off-by-one offset compensated the short length; this pins the documented `(offset, len)`
/// directly so the contract is honored, not just the derived `end`.
#[test]
fn test_find_frame_terminator_crlf_reports_four_bytes() {
    // A frame ending in CRLF followed by a CRLF blank line: `data: x\r\n\r\n`.
    let buf = b"data: x\r\n\r\n";
    let (offset, len) = find_frame_terminator(buf).expect("CRLF terminator must be found");
    // First terminator byte is the trailing `\r` of the data line's CRLF (index 7), and the
    // full `\r\n\r\n` terminator is 4 bytes long.
    assert_eq!(
        offset, 7,
        "offset must index the first terminator byte (\\r)"
    );
    assert_eq!(
        len, 4,
        "CRLF terminator length must be 4 (\\r\\n\\r\\n), not 3"
    );
    assert_eq!(&buf[offset..], b"\r\n\r\n");
    // The derived frame boundary must still cover the whole input.
    assert_eq!(offset + len, buf.len());
}

/// The LF-only blank-line terminator (`\n\n`) must stay 2 bytes, anchored at the first `\n`.
#[test]
fn test_find_frame_terminator_lf_reports_two_bytes() {
    let buf = b"data: x\n\n";
    let (offset, len) = find_frame_terminator(buf).expect("LF terminator must be found");
    assert_eq!(offset, 7, "offset must index the first `\\n`");
    assert_eq!(len, 2, "LF terminator length must be 2 (\\n\\n)");
    assert_eq!(&buf[offset..], b"\n\n");
    assert_eq!(offset + len, buf.len());
}

/// Two adjacent CRLF frames must split at exactly the documented boundary, so the second
/// frame begins cleanly (no stray leading `\r` and no missing byte).
#[test]
fn test_find_frame_terminator_crlf_frame_split_is_clean() {
    let buf = b"data: x\r\n\r\ndata: y\r\n\r\n";
    let (offset, len) = find_frame_terminator(buf).expect("first CRLF terminator");
    let end = offset + len;
    assert_eq!(
        &buf[..end],
        b"data: x\r\n\r\n",
        "first frame incl. terminator"
    );
    assert_eq!(
        &buf[end..],
        b"data: y\r\n\r\n",
        "remainder is the next frame verbatim"
    );
}

/// The default `ProtocolWriter::write_error` (the only impl in this wave — no per-protocol
/// overrides yet) must produce valid JSON carrying the message and the `kind` as `error.type`,
/// so the §8.1 / Unit I plumbing exists before per-protocol envelopes land. (Content-type is a
/// caller concern; the doc contract says `application/json` for all protocols.)
#[test]
fn test_write_error_default_envelope_is_valid_json() {
    // Any writer exercises the default impl since none override it yet.
    let writer: Box<dyn ProtocolWriter> = Box::new(OpenAiWriter);
    let v = writer.write_error(404, "not_found", "model 'x' not found");
    // Round-trips as JSON (no panic) and has the generic envelope shape.
    let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
    let reparsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("write_error output must be valid JSON");
    assert_eq!(
        reparsed["error"]["message"],
        serde_json::json!("model 'x' not found")
    );
    assert_eq!(reparsed["error"]["type"], serde_json::json!("not_found"));
}

/// MEDIUM/conformance (proto_for_path:75-86): a `GET /v1/models/<id>` whose id legitimately
/// CONTAINS a colon (OpenAI fine-tuned `ft:...`, deployment-style `gpt-4o:deployment`) must
/// classify as OpenAI — NOT Gemini — so `model.retrieve` gets an OpenAI-decodable error envelope.
/// Only the known Gemini ACTION suffixes (`:generateContent`, …) are Gemini.
#[test]
fn test_proto_for_path_colon_model_id_is_openai_not_gemini() {
    // OpenAI fine-tuned model id (multiple colons) on the model.retrieve path → OpenAI.
    assert_eq!(
        proto_for_path("/v1/models/ft:gpt-3.5-turbo:my-org::abc123"),
        "openai",
        "a colon-bearing OpenAI fine-tuned model id must stay OpenAI"
    );
    // Azure-style deployment id with a colon → OpenAI.
    assert_eq!(proto_for_path("/v1/models/gpt-4o:deployment"), "openai");
    // Plain model id (no colon) → OpenAI.
    assert_eq!(proto_for_path("/v1/models/gpt-4o"), "openai");
    // A genuine Gemini action suffix → Gemini.
    assert_eq!(
        proto_for_path("/v1/models/gemini-pro:generateContent"),
        "gemini",
        "the Gemini :generateContent action suffix still classifies as Gemini"
    );
    assert_eq!(
        proto_for_path("/v1/models/gemini-pro:streamGenerateContent"),
        "gemini"
    );
    assert_eq!(
        proto_for_path("/v1/models/text-embedding-004:embedContent"),
        "gemini"
    );
    assert_eq!(
        proto_for_path("/v1/models/gemini-pro:countTokens"),
        "gemini"
    );
}

/// MEDIUM/conformance (synth_anthropic_request_id): the synthesized `request-id` header value must
/// carry the native Anthropic shape (`req_01` prefix + non-empty token) so the official SDK reads
/// a well-formed `Message._request_id` / `APIError.request_id`.
#[test]
fn test_synth_anthropic_request_id_is_well_formed() {
    let id = synth_anthropic_request_id().expect("entropy available in test");
    assert!(
        id.starts_with("req_01"),
        "anthropic request-id must carry the native req_01 prefix; got {id}"
    );
    // Native Anthropic `request-id` is EXACTLY 30 chars (`req_01` + 24-char token). A short value
    // (the old 22-char form) is a length-based fingerprint tell and must not regress. Match the
    // body `request_id` produced by `synth_id_with_prefix("req_")`.
    assert_eq!(
        id.len(),
        30,
        "anthropic request-id must be exactly 30 chars to match native; got {} ({id})",
        id.len()
    );
    // ASCII base62 token (no padding/special chars that a native id never carries).
    let token = &id["req_01".len()..];
    assert_eq!(
        token.len(),
        24,
        "token must be 24 base62 chars; got {token}"
    );
    assert!(
        token.bytes().all(|b| b.is_ascii_alphanumeric()),
        "the token must be base62 (alphanumeric); got {token}"
    );
    // Distinct across calls (CSPRNG-backed) — no fixed/predictable id.
    let id2 = synth_anthropic_request_id().expect("entropy available in test");
    assert_ne!(id, id2, "successive ids must differ");
}

/// MEDIUM/conformance (GeminiJsonArrayFramer::finish_with_error): the truncation error element must
/// carry NO busbar-internal vocabulary ("upstream"). A real Gemini API never emits that word, so it
/// is a fingerprintable tell. The message must read like Gemini's own canonical 500 body.
#[test]
fn test_gemini_truncation_error_carries_no_internal_vocabulary() {
    let mut f = GeminiJsonArrayFramer::new();
    // Force the truncation/abort path: a frame with NO terminator that overruns MAX_BUF, mirroring
    // `test_gemini_json_array_framer_finish_signals_abort`.
    let huge = vec![b'x'; GeminiJsonArrayFramer::MAX_BUF + 16];
    let mut pre = Vec::from(&b"data: {\"k\":\""[..]);
    pre.extend_from_slice(&huge);
    let _ = f.feed(&pre);
    let tail = f.finish();
    let body = String::from_utf8_lossy(&tail);
    assert!(
        !body.to_lowercase().contains("upstream"),
        "the truncation error must NOT contain the busbar-internal word 'upstream': {body}"
    );
    assert!(
        body.contains("Internal error encountered."),
        "the truncation error must mirror Gemini's own 500 body text: {body}"
    );
}

/// Every protocol's writer must produce a non-empty, valid-JSON probe body that carries the
/// requested model (or, for path-model protocols like Gemini/Bedrock, at least valid JSON) —
/// this is what the active health prober sends.
#[test]
fn test_probe_body_valid_for_all_protocols() {
    for name in [
        "anthropic",
        "openai",
        "gemini",
        "bedrock",
        "responses",
        "cohere",
    ] {
        let proto = protocol_for(name).unwrap();
        let body = proto.writer().probe_body("my-model");
        assert!(!body.is_empty(), "{name}: probe body must be non-empty");
        let v: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{name}: invalid JSON: {e}"));
        assert!(v.is_object(), "{name}: probe body must be a JSON object");
    }
}

/// `requires_max_tokens()` must be true exactly for the protocols whose APIs hard-reject a
/// request lacking `max_tokens` (Anthropic Messages) and false for the rest — including Bedrock,
/// which defaults maxTokens when omitted. This flag gates the translation-seam injection in
/// `forward`; a false positive would silently cap a backend's output.
#[test]
fn test_requires_max_tokens_per_protocol() {
    for (name, want) in [
        ("anthropic", true),
        ("bedrock", false),
        ("openai", false),
        ("gemini", false),
        ("responses", false),
        ("cohere", false),
    ] {
        let proto = protocol_for(name).unwrap();
        assert_eq!(
            proto.writer().requires_max_tokens(),
            want,
            "{name}: requires_max_tokens() mismatch"
        );
    }
}

/// OpenAI-compatible reasoning models put the chain-of-thought in `reasoning_content`; it must
/// map to a Thinking block (ahead of the answer) so it survives translation to Anthropic.
#[test]
fn test_openai_reasoning_content_maps_to_thinking() {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "reasoning_content": "step 1: think; step 2: answer",
                "content": "the answer"
            },
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7}
    });
    let ir = OpenAiReader.read_response(&body).expect("read_response");
    assert!(
        matches!(ir.content.first(), Some(crate::ir::IrBlock::Thinking { text, .. }) if text == "step 1: think; step 2: answer"),
        "first block should be the reasoning as a Thinking block"
    );
    assert!(
        ir.content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::Text { text, .. } if text == "the answer")),
        "the answer text should follow"
    );
    // And it should render as an Anthropic thinking block on write.
    let wire = AnthropicWriter.write_response(&ir);
    let blocks = wire.get("content").and_then(|c| c.as_array()).unwrap();
    assert!(
        blocks
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking")),
        "Anthropic output should contain a thinking block"
    );
}

/// Streaming reasoning: `delta.reasoning_content` must open a Thinking block at index 0 and
/// close it before the text block (which shifts to index 1).
#[test]
fn test_openai_streaming_reasoning_blocks() {
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let mut ev = Vec::new();
    ev.extend(reader.read_response_events(
        "",
        &serde_json::json!({"choices":[{"delta":{"reasoning_content":"mulling"}}]}),
        &mut st,
    ));
    ev.extend(reader.read_response_events(
        "",
        &serde_json::json!({"choices":[{"delta":{"content":"answer"}}]}),
        &mut st,
    ));
    ev.extend(reader.read_response_events(
            "",
            &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}),
            &mut st,
        ));

    let think_start = ev.iter().position(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Thinking
            }
        )
    });
    let think_delta = ev.iter().any(|e| matches!(e, IrStreamEvent::BlockDelta { index: 0, delta: IrDelta::ThinkingDelta(t) } if t == "mulling"));
    let think_stop = ev
        .iter()
        .position(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 }));
    let text_start = ev.iter().position(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::Text
            }
        )
    });
    let text_delta = ev.iter().any(|e| matches!(e, IrStreamEvent::BlockDelta { index: 1, delta: IrDelta::TextDelta(t) } if t == "answer"));

    assert!(
        think_start.is_some() && think_delta,
        "reasoning opens a Thinking block at index 0"
    );
    assert!(
        text_start.is_some() && text_delta,
        "text opens at index 1 after reasoning"
    );
    assert!(
        think_stop < text_start,
        "the thinking block must close before the text block opens"
    );
}

/// Regression: a normal (no-reasoning) OpenAI stream keeps text at index 0 (offset unchanged).
#[test]
fn test_openai_streaming_no_reasoning_text_index_zero() {
    use crate::ir::{IrBlockMeta, IrStreamEvent};
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({"choices":[{"delta":{"content":"hi"}}]}),
        &mut st,
    );
    assert!(
        ev.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            }
        )),
        "without reasoning, text stays at index 0"
    );
}

fn rich_fixture() -> serde_json::Value {
    // temperature is a natural 0.7 — IrRequest.temperature is f64 so it round-trips exactly.
    serde_json::json!({
        "system": [{"type": "text", "text": "You are a helpful assistant.", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "What is the weather?"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}}]},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": "I need to analyze the weather...", "signature": "sig_abc123xyz"}, {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"location": "San Francisco"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tool_1", "content": [{"type": "text", "text": "Sunny, 72°F"}]}]}
        ],
        "tools": [{"name": "get_weather", "description": "Get weather for a location", "input_schema": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
        "max_tokens": 4096,
        "temperature": 0.7,
        "stream": true,
        "top_p": 0.95
    })
}

#[test]
fn test_openai_tool_schema_translates_to_anthropic() {
    // Regression: OpenAI nests name/description/parameters under `function`. The reader must
    // descend into it so the JSON schema reaches Anthropic's `input_schema` — otherwise the
    // translated tool has `input_schema: null` and the Anthropic backend 422s.
    let openai_body = serde_json::json!({
        "model": "x",
        "max_tokens": 200,
        "messages": [{"role": "user", "content": "weather in Paris?"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }
            }
        }]
    });
    let ir = OpenAiReader
        .read_request(&openai_body)
        .expect("openai read_request");
    assert_eq!(ir.tools.len(), 1);
    assert_eq!(
        ir.tools[0].name, "get_weather",
        "tool name (nested under function)"
    );
    assert_eq!(
        ir.tools[0].input_schema["properties"]["city"]["type"], "string",
        "parameters schema must be read into IrTool.input_schema"
    );

    let anthropic = AnthropicWriter.write_request(&ir);
    let tools = anthropic.get("tools").unwrap().as_array().unwrap();
    assert_eq!(tools[0]["name"], "get_weather");
    assert!(
        !tools[0]["input_schema"].is_null(),
        "Anthropic tool input_schema must not be null (caused the 422)"
    );
    assert_eq!(
        tools[0]["input_schema"]["properties"]["city"]["type"], "string",
        "the full JSON schema must survive OpenAI → Anthropic translation"
    );
}

#[test]
fn test_roundtrip_identity() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();
    let j = rich_fixture();
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    let roundtrip = writer.write_request(&ir);
    assert_eq!(
        roundtrip, j,
        "round-trip must be byte-identical on representable subset"
    );
}

#[test]
fn test_signature_verbatim() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();
    let j = rich_fixture();
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    let mut found_thinking = false;
    for msg in &ir.messages {
        if msg.role == crate::ir::IrRole::Assistant {
            for block in &msg.content {
                if let crate::ir::IrBlock::Thinking {
                    text: _, signature, ..
                } = block
                {
                    found_thinking = true;
                    assert_eq!(signature.as_deref(), Some("sig_abc123xyz"));
                }
            }
        }
    }
    assert!(found_thinking);
    let roundtrip = writer.write_request(&ir);
    if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
        for msg_val in msgs {
            if let Some(content_arr) = msg_val.get("content").and_then(|v| v.as_array()) {
                for block_val in content_arr {
                    if let Some(block_obj) = block_val.as_object() {
                        if block_obj.get("type").and_then(|t| t.as_str()) == Some("thinking") {
                            assert_eq!(
                                block_obj.get("signature").and_then(|s| s.as_str()),
                                Some("sig_abc123xyz")
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_cache_control_preserved() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();
    let j = rich_fixture();
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    assert!(!ir.system.is_empty());
    if let crate::ir::IrBlock::Text {
        text: _,
        cache_control,
        citations: _,
    } = &ir.system[0]
    {
        assert!(cache_control.is_some());
        match cache_control.as_ref().unwrap().kind {
            crate::ir::CacheKind::Ephemeral => {}
        };
    }
    let roundtrip = writer.write_request(&ir);
    if let Some(system_arr) = roundtrip.get("system").and_then(|v| v.as_array()) {
        if let Some(first_block) = system_arr.first() {
            assert!(first_block
                .as_object()
                .unwrap()
                .contains_key("cache_control"));
        }
    }
}

/// REGRESSION (found live, Claude Code → Nova on Bedrock): an Anthropic `cache_control`
/// breakpoint translated to a Bedrock `cachePoint` marker, which Amazon Nova hard-rejects
/// (400 "extraneous key [cachePoint] is not permitted"). Bedrock's marker is MODEL-gated, so
/// the seam must clear the cache ask unless the lane asserts `prompt_caching` — mirroring the
/// `reasoning` gate. With the flag, the marker flows (Claude-on-Bedrock keeps its caching).
#[test]
fn cache_breakpoints_gated_by_lane_capability_on_bedrock() {
    let registry = ProtocolRegistry::with_builtins();
    let anthropic = registry.get("anthropic").unwrap();
    let bedrock = registry.get("bedrock").unwrap();
    assert!(bedrock.writer().cache_markers_model_gated());
    assert!(!anthropic.writer().cache_markers_model_gated());

    let body = serde_json::json!({
        "model": "claude", "max_tokens": 64,
        "system": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}
        ]}],
        "tools": [{"name": "t", "input_schema": {"type": "object"},
                   "cache_control": {"type": "ephemeral"}}]
    });

    let prep = |allowed: bool| crate::ir::variant::EgressPrep {
        ingress_protocol: "anthropic",
        egress_requires_max_tokens: false,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: false,
        reasoning_budgets: [1024, 4096, 8192, 16384],
        prompt_caching_allowed: allowed,
    };
    let contains_cache_point =
        |wire: &serde_json::Value| serde_json::to_string(wire).unwrap().contains("cachePoint");

    // Lane WITHOUT the capability: every breakpoint cleared, no cachePoint on the wire.
    let ir = anthropic.reader().read_request(&body).unwrap();
    let mut req = crate::ir::variant::IrReq::Chat(ir);
    req.prepare_for_egress(&prep(false));
    let crate::ir::variant::IrReq::Chat(ir) = req else {
        unreachable!()
    };
    let wire = bedrock.writer().write_request(&ir);
    assert!(
        !contains_cache_point(&wire),
        "an unasserted lane must never receive a cachePoint (Nova 400s on it): {wire}"
    );

    // Lane WITH `prompt_caching: true`: the breakpoints project (Claude on Bedrock).
    let ir = anthropic.reader().read_request(&body).unwrap();
    let mut req = crate::ir::variant::IrReq::Chat(ir);
    req.prepare_for_egress(&prep(true));
    let crate::ir::variant::IrReq::Chat(ir) = req else {
        unreachable!()
    };
    let wire = bedrock.writer().write_request(&ir);
    assert!(
        contains_cache_point(&wire),
        "an asserted lane keeps its cache markers: {wire}"
    );
}

#[test]
fn test_extra_passthrough() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();
    let j = rich_fixture();
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    // top_p is now a first-class IR sampling control (promoted out of `extra` so it survives the
    // cross-protocol seam); it must NOT linger in `extra` but MUST still round-trip via the typed
    // field into the written body.
    assert!(!ir.extra.contains_key("top_p"));
    assert!(ir.top_p.is_some());
    let roundtrip = writer.write_request(&ir);
    assert!(roundtrip.as_object().unwrap().contains_key("top_p"));
}

// Finding 2 (native control fields dropped on cross-protocol hops). The universally-modeled
// sampling controls (top_p, top_k, stop) are now first-class IR fields, so they survive the
// cross-protocol seam (which CLEARS `ir.extra` to stop source-only key leakage). Each test reads
// a native request, CLEARS `extra` to simulate the seam (proxy engine `ir.extra.clear()`), then
// writes through a DIFFERENT protocol and asserts the control reappears in that protocol's native
// shape. Were these still extra-only, the clear would drop them.

#[test]
fn test_cross_protocol_openai_top_p_to_anthropic() {
    let body = serde_json::json!({
        "model":"gpt-x",
        "messages":[{"role":"user","content":"hi"}],
        "top_p":0.81
    });
    let mut ir = OpenAiReader.read_request(&body).expect("openai parses");
    assert_eq!(ir.top_p, Some(0.81));
    ir.extra.clear(); // simulate the cross-protocol seam
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out.get("top_p").and_then(|v| v.as_f64()),
        Some(0.81),
        "openai top_p must translate to anthropic top_p across the seam; got {out}"
    );
}

#[test]
fn test_cross_protocol_gemini_stop_sequences_to_openai_stop() {
    let body = serde_json::json!({
        "model":"gemini-x",
        "contents":[{"role":"user","parts":[{"text":"hi"}]}],
        "generationConfig":{"stopSequences":["STOP","END"]}
    });
    let mut ir = GeminiReader.read_request(&body).expect("gemini parses");
    assert_eq!(ir.stop, vec!["STOP".to_string(), "END".to_string()]);
    ir.extra.clear(); // simulate the cross-protocol seam
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out.get("stop"),
        Some(&serde_json::json!(["STOP", "END"])),
        "gemini stopSequences must translate to openai stop across the seam; got {out}"
    );
}

#[test]
fn test_cross_protocol_anthropic_top_k_to_gemini() {
    let body = serde_json::json!({
        "model":"claude-x",
        "messages":[{"role":"user","content":"hi"}],
        "max_tokens":16,
        "top_k":40
    });
    let mut ir = AnthropicReader
        .read_request(&body)
        .expect("anthropic parses");
    assert_eq!(ir.top_k, Some(40));
    ir.extra.clear(); // simulate the cross-protocol seam
    let writer = GeminiWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/generationConfig/topK")
            .and_then(|v| v.as_u64()),
        Some(40),
        "anthropic top_k must translate to gemini generationConfig.topK; got {out}"
    );
}

// top_k has NO OpenAI target: the OpenAI writer must NOT invent one (lossy-by-target, not a leak).
#[test]
fn test_cross_protocol_top_k_dropped_for_openai_target() {
    let body = serde_json::json!({
        "model":"claude-x",
        "messages":[{"role":"user","content":"hi"}],
        "max_tokens":16,
        "top_k":40
    });
    let mut ir = AnthropicReader
        .read_request(&body)
        .expect("anthropic parses");
    ir.extra.clear();
    let out = OpenAiWriter.write_request(&ir);
    assert!(
        out.get("top_k").is_none() && out.get("k").is_none(),
        "OpenAI has no top_k knob; the writer must not synthesize one; got {out}"
    );
}

#[test]
fn test_registry_resolves_anthropic() {
    let registry = ProtocolRegistry::with_builtins();

    // Anthropic should be present
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    assert_eq!(protocol.name(), "anthropic");
    assert_eq!(protocol.writer().upstream_path(), "/v1/messages");

    // Non-existent should return None
    assert!(registry.get("nonexistent").is_none());
}

#[test]
fn test_reader_classify_behavior() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("anthropic").expect("anthropic should exist");
    let reader = protocol.reader();

    // Test 429 → RateLimit
    let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
    assert_eq!(signal.class, StatusClass::RateLimit);

    // Test 401 → Auth
    let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
    assert_eq!(signal.class, StatusClass::Auth);

    // Test 503 → ServerError
    let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
    assert_eq!(signal.class, StatusClass::ServerError);
}

#[test]
fn test_writer_auth_headers() {
    let headers = crate::proto::anthropic::anthropic_auth_headers("k", None);
    let header_names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();

    assert!(header_names.contains(&"x-api-key"));
    assert!(header_names.contains(&"anthropic-version"));
}

#[test]
fn test_irerror_bridge() {
    // `IrError` is a type alias for the breaker's `CanonicalSignal`; verify the bridge by routing
    // it through the classifier rather than re-asserting the field we just set.
    let ir_error: IrError = IrError {
        class: StatusClass::Billing,
        provider_signal: Some("test".to_string()),
        retry_after: None,
    };

    // Billing is a hard, non-retryable failure for the breaker.
    assert_eq!(
        crate::breaker::classify(&ir_error),
        crate::breaker::Disposition::HardDown
    );
}

#[test]
fn test_stream_roundtrip_identity() {
    let reader = AnthropicReader;
    let writer = AnthropicWriter;

    // message_start with usage. `write_response_event` runs ONLY on the cross-protocol
    // StreamTranslate path (same-protocol streams pass raw bytes through), so the writer ALWAYS
    // emits the full native skeleton — `id` (synthesized when absent), `type`, `content[]`,
    // `stop_reason`, `stop_sequence` — that every native Anthropic message_start carries. Assert
    // those structural fields (the synthesized `id` is non-deterministic) plus the round-tripped
    // usage, rather than byte-identity to the bare input.
    let data = serde_json::json!({
        "message": {
            "role": "assistant",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15
            }
        }
    });
    let ev = reader.read_response_event("message_start", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        let (et, out) = writer
            .write_response_event(&e)
            .expect("writes message_start");
        assert_eq!(et, "message_start");
        let msg = out.get("message").expect("message object");
        assert!(
            msg.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .starts_with("msg_"),
            "synthesized id must be msg_-prefixed: {out}"
        );
        assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
        assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
        assert!(msg.get("content").and_then(|c| c.as_array()).is_some());
        assert!(msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false));
        assert!(msg
            .get("stop_sequence")
            .map(|v| v.is_null())
            .unwrap_or(false));
        assert_eq!(
            msg.get("usage").and_then(|u| u.get("input_tokens")),
            Some(&serde_json::json!(10))
        );
    }

    // content_block_start for tool_use. Fixtures carry the top-level `type` field that native
    // Anthropic SSE data bodies include and that `AnthropicWriter::write_response_event` now emits
    // (the reader dispatches on the SSE `event:` header, not `data.type`, so the field is dropped
    // on read and re-synthesized by the writer — exact-equality holds with `type` present in the
    // fixture).
    let data = serde_json::json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": {
            "type": "tool_use",
            "id": "tool_123",
            "name": "get_weather"
        }
    });
    let ev = reader.read_response_event("content_block_start", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_start".to_string(), data))
        );
    }

    // content_block_delta - text_delta
    let data = serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
            "type": "text_delta",
            "text": "hello"
        }
    });
    let ev = reader.read_response_event("content_block_delta", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_delta".to_string(), data))
        );
    }

    // content_block_delta - thinking_delta
    let data = serde_json::json!({
        "type": "content_block_delta",
        "index": 1,
        "delta": {
            "type": "thinking_delta",
            "thinking": "I need to think"
        }
    });
    let ev = reader.read_response_event("content_block_delta", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_delta".to_string(), data))
        );
    }

    // content_block_delta - input_json_delta
    let data = serde_json::json!({
        "type": "content_block_delta",
        "index": 2,
        "delta": {
            "type": "input_json_delta",
            "partial_json": "{\"loc"
        }
    });
    let ev = reader.read_response_event("content_block_delta", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_delta".to_string(), data))
        );
    }

    // content_block_delta - signature_delta
    let data = serde_json::json!({
        "type": "content_block_delta",
        "index": 1,
        "delta": {
            "type": "signature_delta",
            "signature": "sig_abc123xyz"
        }
    });
    let ev = reader.read_response_event("content_block_delta", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_delta".to_string(), data))
        );
    }

    // content_block_stop
    let data = serde_json::json!({ "type": "content_block_stop", "index": 0 });
    let ev = reader.read_response_event("content_block_stop", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("content_block_stop".to_string(), data))
        );
    }

    // message_delta with usage. Native Anthropic ALWAYS carries `delta.stop_sequence` (explicit
    // `null` when no stop sequence fired), so the round-tripped frame includes it.
    let data = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": "end_turn", "stop_sequence": null },
        "usage": {
            "input_tokens": 10,
            "output_tokens": 20,
            "cache_creation_input_tokens": 5,
            "cache_read_input_tokens": 15
        }
    });
    let ev = reader.read_response_event("message_delta", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("message_delta".to_string(), data))
        );
    }

    // message_stop
    let data = serde_json::json!({ "type": "message_stop" });
    let ev = reader.read_response_event("message_stop", &data);
    assert!(ev.is_some());
    if let Some(e) = ev {
        assert_eq!(
            writer.write_response_event(&e),
            Some(("message_stop".to_string(), data))
        );
    }
}

#[test]
fn test_split_usage_never_collapses() {
    let reader = AnthropicReader;
    let writer = AnthropicWriter;

    // message_delta with all four usage fields distinct
    let data = serde_json::json!({
        "delta": { "stop_reason": "end_turn" },
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_creation_input_tokens": 30,
            "cache_read_input_tokens": 200
        }
    });

    let ev = reader
        .read_response_event("message_delta", &data)
        .expect("should parse");
    if let crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: _,
        usage,
        ..
    } = ev
    {
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.cache_creation_input_tokens, Some(30));
        assert_eq!(usage.cache_read_input_tokens, Some(200));
        // input_tokens (100) is carried verbatim, NOT collapsed into the cache totals (30+200=230) —
        // the `input_tokens == 100` assertion above already proves it (230 would fail there).
    } else {
        panic!("expected MessageDelta");
    }

    let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: Some(30),
            cache_read_input_tokens: Some(200),
        },
    });
    assert!(roundtrip.is_some());
    let (_, rt_data) = roundtrip.unwrap();
    assert_eq!(
        rt_data
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(|v| v.as_u64()),
        Some(100)
    );
    assert_eq!(
        rt_data
            .get("usage")
            .and_then(|u| u.get("output_tokens"))
            .and_then(|v| v.as_u64()),
        Some(50)
    );
    assert_eq!(
        rt_data
            .get("usage")
            .and_then(|u| u.get("cache_creation_input_tokens"))
            .and_then(|v| v.as_u64()),
        Some(30)
    );
    assert_eq!(
        rt_data
            .get("usage")
            .and_then(|u| u.get("cache_read_input_tokens"))
            .and_then(|v| v.as_u64()),
        Some(200)
    );
}

#[test]
fn test_signature_delta_verbatim() {
    let reader = AnthropicReader;
    let writer = AnthropicWriter;

    // Signature delta with byte-identical string
    let sig = "sig_abc123xyz_signature_for_thinking";
    let data = serde_json::json!({
        "index": 0,
        "delta": {
            "type": "signature_delta",
            "signature": sig
        }
    });

    let ev = reader
        .read_response_event("content_block_delta", &data)
        .expect("should parse");
    if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
        if let crate::ir::IrDelta::SignatureDelta(s) = delta {
            assert_eq!(s, sig);
        } else {
            panic!("expected SignatureDelta");
        }
    } else {
        panic!("expected BlockDelta");
    }

    let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
    });
    assert!(roundtrip.is_some());
    let (_, rt_data) = roundtrip.unwrap();
    let rt_sig = rt_data
        .get("delta")
        .and_then(|d| d.get("signature"))
        .and_then(|s| s.as_str())
        .unwrap();
    assert_eq!(rt_sig, sig);
}

#[test]
fn test_ping_returns_none() {
    let reader = AnthropicReader;
    let data = serde_json::json!({});
    let result = reader.read_response_event("ping", &data);
    assert!(result.is_none());

    // Unknown event type also returns None
    let result = reader.read_response_event("unknown_event_type", &data);
    assert!(result.is_none());
}

#[test]
fn test_openai_request_roundtrip_identity() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("openai").expect("openai should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();

    // Canonical OpenAI request with system message, user+image, assistant tool_call, tool_result, tools array, max_tokens, temperature:0.7, stream:true, top_p→extra
    let j = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}]},
            {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]},
            {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
        ],
        "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
        "max_tokens": 100,
        "temperature": 0.7,
        "stream": true,
        "top_p": 0.95
    });

    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    let roundtrip = writer.write_request(&ir);

    // Compare structurally rather than byte-identical since IR doesn't preserve model field and tool_call ids are regenerated
    assert_eq!(
        roundtrip
            .as_object()
            .unwrap()
            .get("messages")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        j.get("messages")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
    );
    assert_eq!(
        roundtrip.as_object().unwrap().get("max_tokens"),
        j.as_object().unwrap().get("max_tokens")
    );
    assert_eq!(
        roundtrip.as_object().unwrap().get("temperature"),
        j.as_object().unwrap().get("temperature")
    );
    assert_eq!(
        roundtrip.as_object().unwrap().get("stream"),
        j.as_object().unwrap().get("stream")
    );
    assert_eq!(
        roundtrip.as_object().unwrap().get("top_p"),
        j.as_object().unwrap().get("top_p")
    );

    // Correctness-critical: the tool_call id must round-trip VERBATIM (not be regenerated),
    // so the assistant tool_call still correlates with the tool-result `tool_call_id`.
    let msgs = roundtrip
        .get("messages")
        .and_then(|v| v.as_array())
        .unwrap();
    let written_id = msgs
        .iter()
        .find_map(|m| m.get("tool_calls").and_then(|tc| tc.as_array()))
        .and_then(|tc| tc.first())
        .and_then(|c| c.get("id"))
        .and_then(|i| i.as_str());
    assert_eq!(
        written_id,
        Some("call_123"),
        "tool_call id must round-trip verbatim, not be regenerated"
    );
    // And the tool-result must still reference that same id (correlation preserved).
    let result_ref = msgs
        .iter()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
        .and_then(|m| m.get("tool_call_id"))
        .and_then(|i| i.as_str());
    assert_eq!(
        result_ref,
        Some("call_123"),
        "tool-result correlation must survive round-trip"
    );
}

#[test]
fn test_openai_tool_call_arguments_string_to_value() {
    let registry = ProtocolRegistry::with_builtins();
    let protocol = registry.get("openai").expect("openai should exist");
    let reader = protocol.reader();
    let writer = protocol.writer();

    // Test with arguments that parse to a JSON object
    let j = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]}
        ]
    });

    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");

    // Find the ToolUse block and verify arguments parsed to Value
    let mut found_tool_use = false;
    for msg in &ir.messages {
        if msg.role == crate::ir::IrRole::Assistant {
            for block in &msg.content {
                if let crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } = block
                {
                    found_tool_use = true;
                    assert_eq!(id, "call_123");
                    assert_eq!(name, "get_weather");
                    // Verify arguments parsed to an object Value
                    match input {
                        serde_json::Value::Object(_) => {}
                        _ => panic!("arguments should parse to Object"),
                    }
                }
            }
        }
    }
    assert!(found_tool_use);

    let roundtrip = writer.write_request(&ir);

    // Re-parse the arguments from roundtrip and compare parsed values
    if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
        for msg_val in msgs {
            if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                for tc_val in tc_arr {
                    if let Some(func) = tc_val.get("function") {
                        let args_str = func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");
                        let roundtrip_args: serde_json::Value =
                            serde_json::from_str(args_str).expect("args should parse");

                        // Original parsed value
                        let orig_input = &ir.messages[0].content[0];
                        if let crate::ir::IrBlock::ToolUse { input, .. } = orig_input {
                            assert_eq!(roundtrip_args, *input, "parsed arguments must match");
                        } else {
                            panic!("expected ToolUse block");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_registry_has_both_protocols() {
    let registry = ProtocolRegistry::with_builtins();

    // Both should exist
    assert!(
        registry.get("anthropic").is_some(),
        "anthropic should exist"
    );
    assert!(registry.get("openai").is_some(), "openai should exist");

    // Verify openai writer path
    let openai = registry.get("openai").expect("openai should exist");
    assert_eq!(openai.writer().upstream_path(), "/v1/chat/completions");

    // Verify anthropic writer path
    let anthropic = registry.get("anthropic").expect("anthropic should exist");
    assert_eq!(anthropic.writer().upstream_path(), "/v1/messages");
}

#[test]
fn test_protocol_clone_works() {
    // Test OpenAI protocol clone doesn't panic
    let openai_proto = Protocol::openai();
    let cloned_openai = openai_proto.clone();

    // Clone must PRESERVE the protocol identity (golden values), not merely equal itself.
    assert_eq!(cloned_openai.name(), "openai");
    assert_eq!(
        cloned_openai.writer().upstream_path(),
        "/v1/chat/completions"
    );

    // Test Anthropic protocol clone doesn't panic
    let anthropic_proto = Protocol::anthropic();
    let cloned_anthropic = anthropic_proto.clone();

    assert_eq!(cloned_anthropic.name(), "anthropic");
    assert_eq!(cloned_anthropic.writer().upstream_path(), "/v1/messages");

    // Verify clone_box works for trait objects (just check it doesn't panic and returns same type)
    let openai_reader: Box<dyn ProtocolReader> = Box::new(OpenAiReader);
    let _cloned_reader = openai_reader.clone();

    let openai_writer: Box<dyn ProtocolWriter> = Box::new(OpenAiWriter);
    let _cloned_writer = openai_writer.clone();
}

/// audit H4: Cohere v2 carries the assistant's pre-tool reasoning in `message.tool_plan`. It must be
/// read as a LEADING Text block (ahead of the tool call) or it vanishes on any Cohere→X hop.
#[test]
fn cohere_read_response_surfaces_tool_plan_as_leading_text() {
    let body = serde_json::json!({
        "message": {
            "tool_plan": "First I will check the weather.",
            "tool_calls": [{"id": "t1", "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]
        },
        "finish_reason": "COMPLETE"
    });
    let ir = CohereReader
        .read_response(&body)
        .expect("cohere read_response");
    assert!(
        matches!(ir.content.first(), Some(crate::ir::IrBlock::Text { text, .. }) if text == "First I will check the weather."),
        "tool_plan must be the leading Text block, got: {:?}",
        ir.content
    );
    assert!(
        ir.content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })),
        "the tool call must still follow the plan"
    );
}

/// audit LOW (find-1-solve-6): an unparseable/streaming-partial tool arg is stored as
/// `Value::String(raw)`; EVERY string-args writer (OpenAI Chat, Responses, Cohere) must emit it
/// VERBATIM, not JSON-encode it a second time. Covers Responses AND Cohere (the found sibling);
/// OpenAI Chat already routed through the helper.
#[test]
fn string_args_writers_emit_raw_tool_args_verbatim() {
    let raw = "not valid json {";
    let ir = crate::ir::IrResponse {
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::ToolUse {
            id: "call_1".into(),
            name: "do_it".into(),
            input: serde_json::Value::String(raw.into()),
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
        logprobs: Vec::new(),
    };

    // Responses: output[].arguments
    let resp = ResponsesWriter.write_response(&ir);
    let resp_args = resp
        .get("output")
        .and_then(|o| o.as_array())
        .expect("output array")
        .iter()
        .find(|it| it.get("type").and_then(|t| t.as_str()) == Some("function_call"))
        .and_then(|it| it.get("arguments"))
        .and_then(|a| a.as_str())
        .expect("responses function_call arguments");
    assert_eq!(
        resp_args, raw,
        "Responses must emit raw string args verbatim"
    );

    // Cohere: message.tool_calls[].function.arguments
    let coh = CohereWriter.write_response(&ir);
    let coh_args = coh
        .get("message")
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
        .expect("cohere tool_calls array")
        .first()
        .and_then(|tc| tc.get("function"))
        .and_then(|f| f.get("arguments"))
        .and_then(|a| a.as_str())
        .expect("cohere function arguments");
    assert_eq!(coh_args, raw, "Cohere must emit raw string args verbatim");
}

/// Regression: Cohere is a free-form-tool-id
/// ingress with NO canonical prefix, so `native_tool_id_prefix("cohere")` must be `None` (like
/// Gemini). An empty prefix would make the bare `bb1` marker the only distinguishing signal and
/// silently hex-decode a legitimate client-authored id of shape `bb1<even-len-hex-UTF8>`,
/// corrupting tool_use/tool_result correlation on a Cohere-ingress cross-protocol hop.
#[test]
fn cohere_tool_ids_pass_through_verbatim_no_decode() {
    // No prefix for Cohere — the encode never reshapes a Cohere-ingress tool id.
    assert_eq!(native_tool_id_prefix("cohere"), None);

    // A client-authored Cohere id that matches the colliding `bb1<even-hex-UTF8>` shape
    // (`bb161626364` → `bb1` + hex("abcd")) must NOT be decoded — it passes through unchanged.
    assert_eq!(decode_native_tool_id("cohere", "bb161626364"), None);
    // Any other free-form Cohere id is likewise a no-op on decode.
    assert_eq!(decode_native_tool_id("cohere", "my-tool-call-7"), None);

    // The forward (encode) path is also a verbatim no-op for a Cohere ingress: the egress id is
    // emitted as-is, so there is nothing to mis-decode on the client's echo.
    let mut remap = ToolIdRemap::default();
    assert_eq!(remap.native_for("cohere", "call_xyz"), "call_xyz");
    assert_eq!(remap.native_for("cohere", "bb161626364"), "bb161626364");
}

#[cfg(test)]
mod ir_property_tests {
    use super::*;

    // ============================================================================
    // A. Anthropic REQUEST property tests (decode assertions + round-trip)
    // ============================================================================

    /// Rich canonical Anthropic fixture with natural values only (0.7, "hello", 10, "call_123").
    fn anthropic_rich_fixture() -> serde_json::Value {
        serde_json::json!({
            "system": [
                {
                    "type": "text",
                    "text": "You are a helpful assistant.",
                    "cache_control": {"type": "ephemeral"}
                }
            ],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "hello"},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                            }
                        }
                    ]
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "thinking",
                            "thinking": "I need to analyze this request carefully...",
                            "signature": "sig_thinking_abc123"
                        },
                        {
                            "type": "tool_use",
                            "id": "call_123",
                            "name": "get_weather",
                            "input": {"location": "San Francisco"}
                        }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "call_123",
                            "content": [{"type": "text", "text": "Sunny, 72°F"}],
                            "is_error": false
                        }
                    ]
                }
            ],
            "tools": [
                {
                    "name": "get_weather",
                    "description": "Get weather for a location",
                    "input_schema": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            ],
            "max_tokens": 10,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        })
    }

    #[test]
    fn test_anthropic_request_decode_assertions() {
        // DECODE assertions on rich canonical fixture - exact field values that a doctored
        // fixture cannot fake
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let j = anthropic_rich_fixture();

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Assert system[0] has cache_control Some(Ephemeral) & text
        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text {
            ref text,
            ref cache_control,
            ref citations,
        } = ir.system[0]
        {
            assert_eq!(text, "You are a helpful assistant.");
            assert!(cache_control.is_some());
            match cache_control.as_ref().unwrap().kind {
                crate::ir::CacheKind::Ephemeral => {}
            }
            assert!(citations.is_empty());
        } else {
            panic!("system[0] should be Text block");
        }

        // Assert the Thinking signature String == "sig_thinking_abc123"
        let mut found_assistant = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                found_assistant = true;
                let mut found_thinking = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::Thinking {
                        text: _,
                        ref signature,
                        ..
                    } = block
                    {
                        found_thinking = true;
                        assert_eq!(signature.as_deref(), Some("sig_thinking_abc123"));
                    }
                }
                assert!(found_thinking);
            }
        }
        assert!(found_assistant);

        // Assert ToolUse id/name/input
        let mut found_tool_use = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        found_tool_use = true;
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        match input {
                            serde_json::Value::Object(obj) => {
                                assert_eq!(
                                    obj.get("location"),
                                    Some(&serde_json::json!("San Francisco"))
                                );
                            }
                            _ => panic!("input should be Object"),
                        }
                    }
                }
            }
        }
        assert!(found_tool_use);

        // Assert Image media_type+data in user message
        let mut found_image = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::User {
                for block in &msg.content {
                    if let crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Base64 { media_type, data },
                        ..
                    } = block
                    {
                        found_image = true;
                        assert_eq!(media_type, "image/png");
                        assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
                    }
                }
            }
        }
        assert!(found_image);

        // Assert tool_result tool_use_id == "call_123" (correlation)
        let mut found_tool_result = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::User {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        ref tool_use_id,
                        ref content,
                        ref is_error,
                        ..
                    } = block
                    {
                        found_tool_result = true;
                        assert_eq!(tool_use_id, "call_123");
                        assert!(!content.is_empty());
                        assert!(!*is_error);
                    }
                }
            }
        }
        assert!(found_tool_result);

        // Assert temperature == Some(0.7) (f64, exact - natural value not 0.699999988)
        assert_eq!(ir.temperature, Some(0.7_f64));

        // top_p is now promoted to a first-class IR field (so it survives the cross-protocol
        // seam): it must be carried in `ir.top_p`, NOT left in `extra`.
        assert!(!ir.extra.contains_key("top_p"));
        assert_eq!(ir.top_p, Some(0.95_f64));
    }

    #[test]
    fn test_anthropic_request_roundtrip_identity() {
        // Round-trip identity: semantic equivalence via decoded IR (NOT byte-identical) because
        // serializer adds is_error:false for tool_result blocks that had no is_error field in input.
        // This is documented semantic equivalence per anti-fab spec - assert on DECODED IR directly
        // which is the ground truth that a doctored fixture cannot fake.
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = anthropic_rich_fixture();

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Round-trip the JSON through write + read and verify DECODED IR is identical
        let roundtrip_json = writer.write_request(&ir);
        let rt_ir = reader
            .read_request(&roundtrip_json)
            .expect("read round-trip should succeed");

        // Assert decoded IR is byte-identical (ground truth for anti-fab)
        assert_eq!(ir, rt_ir, "decoded IR must be identical after round-trip");
    }

    #[test]
    fn test_anthropic_request_empty_minimal() {
        // Empty/minimal: a bare {"messages":[{"role":"user","content":"hi"}]} round-trips and decodes
        let j = serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}]
        });

        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Assert empty/minimal properties
        assert!(ir.system.is_empty());
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        if let crate::ir::IrBlock::Text { ref text, .. } = ir.messages[0].content[0] {
            assert_eq!(text, "hi");
        } else {
            panic!("expected Text block");
        }
        assert!(ir.tools.is_empty());
        assert_eq!(ir.max_tokens, None);
        assert_eq!(ir.temperature, None);
        assert!(!ir.stream);

        // Round-trip: semantic equivalence (NOT byte-identical) because serializer always outputs
        // content as array even for single text block - this is a known serialization difference
        let roundtrip = writer.write_request(&ir);

        // Verify semantic equivalence via decoded IR
        let rt_ir = reader
            .read_request(&roundtrip)
            .expect("read round-trip should succeed");
        assert_eq!(ir, rt_ir);
    }

    // ============================================================================
    // B. OpenAI REQUEST property tests (decode assertions + correlation)
    // ============================================================================

    /// Canonical OpenAI fixture with natural values only.
    fn openai_rich_fixture() -> serde_json::Value {
        serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "hello"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}
                    ]
                },
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"location\":\"San Francisco\"}"
                            }
                        }
                    ]
                },
                {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
            ],
            "tools": [
                {
                    "type": "function",
                    "name": "get_weather",
                    "description": "Get weather for a location",
                    "parameters": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            ],
            "max_tokens": 100,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        })
    }

    #[test]
    fn test_openai_request_decode_assertions() {
        // DECODE assertions on canonical OpenAI fixture - exact field values that a doctored
        // fixture cannot fake
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let j = openai_rich_fixture();

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Assert system decoded from messages[0] (OpenAI convention)
        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text { ref text, .. } = ir.system[0] {
            assert_eq!(text, "You are a helpful assistant.");
        } else {
            panic!("system[0] should be Text block");
        }

        // Assert ToolUse id == "call_123" (NOT regenerated)
        let mut found_tool_use = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse { id, name, .. } = block {
                        found_tool_use = true;
                        assert_eq!(id, "call_123", "ToolUse id must be verbatim from input");
                        assert_eq!(name, "get_weather");
                    }
                }
            }
        }
        assert!(found_tool_use);

        // Assert the tool_result tool_use_id == "call_123" (correlation)
        let mut found_tool_result = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Tool {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        ref tool_use_id, ..
                    } = block
                    {
                        found_tool_result = true;
                        assert_eq!(
                            tool_use_id, "call_123",
                            "tool_result correlation must survive"
                        );
                    }
                }
            }
        }
        assert!(found_tool_result);

        // Assert image url preserved in Image.data
        let mut found_image = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::User {
                for block in &msg.content {
                    if let crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Url(data),
                        ..
                    } = block
                    {
                        found_image = true;
                        assert_eq!(data, "https://example.com/image.png");
                    }
                }
            }
        }
        assert!(found_image);

        // Assert temperature Some(0.7) (f64, exact natural value)
        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_openai_tool_call_id_correlation_survives_write() {
        // tool_call id correlation survives write: after write_request, the assistant
        // tool_calls[0].id == "call_123" AND the tool message tool_call_id == "call_123" (same id)
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = openai_rich_fixture();

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);

        // Verify assistant tool_calls[0].id == "call_123"
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc_val in tc_arr {
                        if let Some(id) = tc_val.get("id").and_then(|i| i.as_str()) {
                            assert_eq!(id, "call_123", "assistant tool_call id must survive write");
                        }
                    }
                }
            }
        }

        // Verify tool message tool_call_id == "call_123" (same id)
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if msg_val.get("role").and_then(|r| r.as_str()) == Some("tool") {
                    if let Some(tool_call_id) = msg_val.get("tool_call_id").and_then(|i| i.as_str())
                    {
                        assert_eq!(
                            tool_call_id, "call_123",
                            "tool message correlation must survive"
                        );
                    } else {
                        panic!("tool message should have tool_call_id");
                    }
                }
            }
        }
    }

    #[test]
    fn test_openai_arguments_string_to_value_roundtrip() {
        // arguments string↔Value: OpenAI function `arguments` (JSON string) → ToolUse.input
        // (Value/Object) on read, re-serialized to a string on write that re-parses equal
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        let j = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"location\":\"San Francisco\",\"unit\":\"celsius\"}"
                            }
                        }
                    ]
                }
            ]
        });

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Find ToolUse and verify arguments parsed to Value/Object on read
        let mut found_tool_use = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        found_tool_use = true;
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        match input {
                            serde_json::Value::Object(obj) => {
                                assert_eq!(
                                    obj.get("location"),
                                    Some(&serde_json::json!("San Francisco"))
                                );
                                assert_eq!(obj.get("unit"), Some(&serde_json::json!("celsius")));
                            }
                            _ => panic!("arguments should parse to Object Value"),
                        }
                    }
                }
            }
        }
        assert!(found_tool_use);

        // Write and re-parse arguments from roundtrip
        let roundtrip = writer.write_request(&ir);
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc_val in tc_arr {
                        if let Some(func) = tc_val.get("function") {
                            let args_str =
                                func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");

                            // Re-parse the serialized string and compare parsed values
                            let roundtrip_args: serde_json::Value =
                                serde_json::from_str(args_str).expect("args should parse");

                            // Compare with original parsed value
                            if let crate::ir::IrBlock::ToolUse { input, .. } =
                                &ir.messages[0].content[0]
                            {
                                assert_eq!(
                                    roundtrip_args, *input,
                                    "re-serialized arguments must equal original parsed Value"
                                );
                            } else {
                                panic!("expected ToolUse block");
                            }
                        }
                    }
                }
            }
        }
    }

    // ============================================================================
    // C. Anthropic RESPONSE/STREAM per-event property tests (read_response_event/write_response_event)
    // ============================================================================

    #[test]
    fn test_anthropic_stream_per_event_roundtrip() {
        // Per-event round-trip for each event type with natural values
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // 1. message_start w/ usage incl. cache tokens. The writer (cross-protocol-only path)
        // always emits the full native skeleton with a synthesized `id`, so assert the structural
        // fields + round-tripped usage rather than byte-identity to the bare input.
        let data = serde_json::json!({
            "message": {
                "role": "assistant",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            }
        });
        let ev = reader.read_response_event("message_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            let (et, out) = writer
                .write_response_event(&e)
                .expect("writes message_start");
            assert_eq!(et, "message_start");
            let msg = out.get("message").expect("message object");
            assert!(
                msg.get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .starts_with("msg_"),
                "synthesized id must be msg_-prefixed: {out}"
            );
            assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
            assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
            assert!(msg.get("content").and_then(|c| c.as_array()).is_some());
            assert!(msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false));
            assert!(msg
                .get("stop_sequence")
                .map(|v| v.is_null())
                .unwrap_or(false));
            assert_eq!(
                msg.get("usage")
                    .and_then(|u| u.get("cache_read_input_tokens")),
                Some(&serde_json::json!(15))
            );
        }

        // 2. content_block_start tool_use. Fixtures carry the native top-level `type` field
        // (matching the SSE `event:` header) that `AnthropicWriter` now emits; the reader drops it
        // (it dispatches on the header, not `data.type`) and the writer re-synthesizes it, so the
        // same-protocol round-trip stays byte-identical with `type` present in the fixture.
        let data = serde_json::json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "call_123",
                "name": "get_weather"
            }
        });
        let ev = reader.read_response_event("content_block_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_start".to_string(), data))
            );
        }

        // 3. content_block_delta ×4 delta kinds (text, thinking, input_json, signature)
        let text_data = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "hello"}
        });
        let ev = reader.read_response_event("content_block_delta", &text_data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), text_data))
            );
        }

        let thinking_data = serde_json::json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "thinking_delta", "thinking": "I need to think"}
        });
        let ev = reader.read_response_event("content_block_delta", &thinking_data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), thinking_data))
            );
        }

        let json_data = serde_json::json!({
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": "{\"loc"}
        });
        let ev = reader.read_response_event("content_block_delta", &json_data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), json_data))
            );
        }

        let sig_data = serde_json::json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "signature_delta", "signature": "sig_thinking_xyz"}
        });
        let ev = reader.read_response_event("content_block_delta", &sig_data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), sig_data))
            );
        }

        // 4. content_block_stop
        let data = serde_json::json!({"type": "content_block_stop", "index": 0});
        let ev = reader.read_response_event("content_block_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_stop".to_string(), data))
            );
        }

        // 5. message_delta w/ usage, no matched stop_sequence (the common case). The source
        // carried no matched `stop_sequence`, so the IR's `stop_sequence` is `None`. Native
        // Anthropic ALWAYS carries `delta.stop_sequence` (explicit `null` when none fired), so
        // the writer emits it as `null` and the round-trip preserves that native shape.
        let data = serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15
            }
        });
        let ev = reader.read_response_event("message_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            // The IR must carry stop_sequence = None for a delta whose wire had none.
            if let crate::ir::IrStreamEvent::MessageDelta { stop_sequence, .. } = &e {
                assert_eq!(*stop_sequence, None);
            } else {
                panic!("expected MessageDelta");
            }
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_delta".to_string(), data))
            );
        }

        // 5b. message_delta WHERE a stop_sequence matched (`stop_reason: "stop_sequence"` carries
        // the matched string). The reader now captures `stop_sequence` and the writer re-emits it,
        // so this same-protocol round-trip is byte-faithful — previously the field was dropped.
        let data = serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "stop_sequence", "stop_sequence": "\n\nHuman:"},
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15
            }
        });
        let ev = reader.read_response_event("message_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            if let crate::ir::IrStreamEvent::MessageDelta { stop_sequence, .. } = &e {
                assert_eq!(stop_sequence.as_deref(), Some("\n\nHuman:"));
            } else {
                panic!("expected MessageDelta");
            }
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_delta".to_string(), data))
            );
        }

        // 6. message_stop
        let data = serde_json::json!({"type": "message_stop"});
        let ev = reader.read_response_event("message_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_stop".to_string(), data))
            );
        }

        // 7. error event
        let data = serde_json::json!({
            "error": {"type": "invalid_request_error"}
        });
        let ev = reader.read_response_event("error", &data);
        assert!(ev.is_some());
    }

    #[test]
    fn test_split_usage_decode_all_fields_distinct() {
        // Split usage decode: a message_delta usage {input 100, output 50, cache_creation 30,
        // cache_read 200} decodes to IrUsage with all four DISTINCT (assert each ==, and input != sum)
        let reader = AnthropicReader;

        let data = serde_json::json!({
            "delta": {"stop_reason": "end_turn"},
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 30,
                "cache_read_input_tokens": 200
            }
        });

        let ev = reader
            .read_response_event("message_delta", &data)
            .expect("should parse message_delta");

        if let crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: _,
            usage,
            ..
        } = ev
        {
            // Assert each field == exact value (natural values only)
            assert_eq!(usage.input_tokens, 100);
            assert_eq!(usage.output_tokens, 50);
            assert_eq!(usage.cache_creation_input_tokens, Some(30));
            assert_eq!(usage.cache_read_input_tokens, Some(200));

            // Verify they weren't collapsed: input != sum of cache tokens (anti-fab)
            let cache_sum = 30 + 200;
            assert_ne!(
                100, cache_sum,
                "input_tokens must not be collapsed into cache token sum"
            );
        } else {
            panic!("expected MessageDelta event");
        }
    }

    #[test]
    fn test_signature_delta_verbatim_roundtrip() {
        // signature_delta decodes to IrDelta::SignatureDelta(s) with s == input, round-trips
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        let sig = "sig_thinking_abc123xyz";
        let data = serde_json::json!({
            "index": 0,
            "delta": {
                "type": "signature_delta",
                "signature": sig
            }
        });

        // Decode assertion: signature decodes to SignatureDelta(s) with s == input
        let ev = reader
            .read_response_event("content_block_delta", &data)
            .expect("should parse");

        if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
            if let crate::ir::IrDelta::SignatureDelta(s) = delta {
                assert_eq!(s, sig);
            } else {
                panic!("expected SignatureDelta variant");
            }
        } else {
            panic!("expected BlockDelta event");
        }

        // Round-trip: write back and verify signature preserved verbatim
        let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
        });
        assert!(roundtrip.is_some());
        let (_, rt_data) = roundtrip.unwrap();

        let rt_sig = rt_data
            .get("delta")
            .and_then(|d| d.get("signature"))
            .and_then(|s| s.as_str())
            .unwrap();
        assert_eq!(rt_sig, sig);
    }

    #[test]
    fn test_openai_write_response_event_text_delta() {
        let writer = OpenAiWriter;
        let ev = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
        };
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, chunk) = result.unwrap();
        assert_eq!(
            chunk.get("object").and_then(|v| v.as_str()),
            Some("chat.completion.chunk")
        );
        let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(choices.len(), 1);
        let choice = &choices[0];
        assert_eq!(choice.get("index").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            choice
                .get("delta")
                .and_then(|d| d.get("content").and_then(|c| c.as_str())),
            Some("hello")
        );
    }

    #[test]
    fn test_openai_write_response_event_message_start() {
        let writer = OpenAiWriter;
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, chunk) = result.unwrap();
        assert_eq!(
            chunk.get("object").and_then(|v| v.as_str()),
            Some("chat.completion.chunk")
        );
        let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(choices.len(), 1);
        let choice = &choices[0];
        assert_eq!(
            choice
                .get("delta")
                .and_then(|d| d.get("role").and_then(|r| r.as_str())),
            Some("assistant")
        );
    }

    #[test]
    fn test_openai_write_response_event_finish_reason_mapping() {
        let writer = OpenAiWriter;

        // end_turn -> stop
        let ev1 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let result1 = writer.write_response_event(&ev1);
        assert!(result1.is_some());
        let (_, chunk1) = result1.unwrap();
        let choices1 = chunk1.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(
            choices1[0].get("finish_reason").and_then(|v| v.as_str()),
            Some("stop")
        );

        // max_tokens -> length
        let ev2 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let result2 = writer.write_response_event(&ev2);
        assert!(result2.is_some());
        let (_, chunk2) = result2.unwrap();
        let choices2 = chunk2.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(
            choices2[0].get("finish_reason").and_then(|v| v.as_str()),
            Some("length")
        );

        // tool_use -> tool_calls
        let ev3 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let result3 = writer.write_response_event(&ev3);
        assert!(result3.is_some());
        let (_, chunk3) = result3.unwrap();
        let choices3 = chunk3.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(
            choices3[0].get("finish_reason").and_then(|v| v.as_str()),
            Some("tool_calls")
        );
    }

    #[test]
    fn test_openai_write_response_event_tool_call_args() {
        let writer = OpenAiWriter;
        let ev = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta(r#"{"x":1}"#.to_string()),
        };
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, chunk) = result.unwrap();
        let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
        assert_eq!(choices.len(), 1);
        let choice = &choices[0];
        let tool_calls = choice
            .get("delta")
            .and_then(|d| d.get("tool_calls"))
            .and_then(|tc| tc.as_array())
            .unwrap();
        assert_eq!(tool_calls.len(), 1);
        let func_args = tool_calls[0]
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(|a| a.as_str())
            .unwrap();
        assert_eq!(func_args, r#"{"x":1}"#);
    }

    #[test]
    fn test_openai_write_response_event_lossy_drops() {
        let writer = OpenAiWriter;

        // ThinkingDelta -> None
        let ev1 = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::ThinkingDelta("thinking...".to_string()),
        };
        assert!(writer.write_response_event(&ev1).is_none());

        // SignatureDelta -> None
        let ev2 = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::SignatureDelta("sig...".to_string()),
        };
        assert!(writer.write_response_event(&ev2).is_none());

        // BlockStop -> None
        let ev3 = crate::ir::IrStreamEvent::BlockStop { index: 0 };
        assert!(writer.write_response_event(&ev3).is_none());

        // MessageStop -> None
        let ev4 = crate::ir::IrStreamEvent::MessageStop;
        assert!(writer.write_response_event(&ev4).is_none());
    }

    #[test]
    fn test_openai_write_response_event_error() {
        let writer = OpenAiWriter;
        let err = crate::proto::IrError {
            class: crate::breaker::StatusClass::ClientError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        };
        let ev = crate::ir::IrStreamEvent::Error(err);
        let result = writer.write_response_event(&ev);
        assert!(result.is_some());
        let (_, chunk) = result.unwrap();
        assert_eq!(
            chunk
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str()),
            Some("boom")
        );
    }
}
