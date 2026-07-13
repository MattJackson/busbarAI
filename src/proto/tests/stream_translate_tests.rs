use super::*;

/// STRUCTURAL ROUND-TRIP MATRIX (the test class that would have caught the cohere object-shape
/// and openai usage bugs): for EVERY protocol, writing a canonical IR stream through that
/// protocol's WRITER and reading the frames back through its OWN READER must preserve the streamed
/// text and a terminal signal. A writer that emits a shape its own reader can't decode (the exact
/// cohere content-delta defect: text round-tripped to ZERO events) fails here.
#[test]
fn test_all_protocols_stream_write_read_roundtrip_preserves_text_and_terminal() {
    let text = "Hello, world";
    // Canonical IR stream: start → open text block → text delta → close → terminal delta → stop.
    let events = [
        crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: Some("test-model".to_string()),
        },
        crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        },
        crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(text.to_string()),
        },
        crate::ir::IrStreamEvent::BlockStop { index: 0 },
        crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 7,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        },
        crate::ir::IrStreamEvent::MessageStop,
    ];

    for proto in [
        Protocol::anthropic(),
        Protocol::openai(),
        Protocol::gemini(),
        Protocol::bedrock(),
        Protocol::responses(),
        Protocol::cohere(),
    ] {
        let name = proto.name().to_string();
        // WRITE: each IR event → its native (event_type, json) frame (skip events a protocol
        // intentionally has no frame for).
        let frames: Vec<(String, serde_json::Value)> = events
            .iter()
            .filter_map(|ev| proto.writer().write_response_event(ev))
            .collect();
        assert!(
            !frames.is_empty(),
            "{name}: writer produced no frames for a normal text stream"
        );
        // READ BACK through the SAME protocol's reader over one decode state. Bedrock's reader
        // keys on `data["type"]`, which on the real wire the binary eventstream DECODER injects
        // from each frame's `:event-type` header (the writer emits the type in the tuple position,
        // not the JSON). Simulate that injection so the round-trip crosses the same boundary the
        // production pipeline does. No-op for the SSE protocols (their frames already carry `type`
        // or their readers ignore it); only fires when a non-empty event-type isn't already in the
        // payload.
        let mut state = crate::ir::StreamDecodeState::default();
        let mut decoded: Vec<crate::ir::IrStreamEvent> = Vec::new();
        for (et, data) in &frames {
            let mut data = data.clone();
            if !et.is_empty() {
                if let Some(obj) = data.as_object_mut() {
                    obj.entry("type")
                        .or_insert_with(|| serde_json::Value::String(et.clone()));
                }
            }
            decoded.extend(proto.reader().read_response_events(et, &data, &mut state));
        }
        // Streamed text must survive (concatenation of all decoded TextDeltas).
        let got: String = decoded
            .iter()
            .filter_map(|e| match e {
                crate::ir::IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::TextDelta(t),
                    ..
                } => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            got, text,
            "{name}: streamed text must round-trip writer→reader; got {got:?} from {decoded:?}"
        );
        // A terminal signal must survive — for the 5 SSE protocols. Bedrock is EXCLUDED here:
        // its native terminal is a TWO-frame `messageStop` (stop reason) + `metadata` (usage)
        // split that the reader pairs into one combined MessageDelta, and the writer side of that
        // split is driven by `StreamTranslate`'s eventstream fan-out (the `ingress_eventstream`
        // branch), not a raw per-event `write_response_event`. That two-frame terminal round-trip
        // is covered by the dedicated `*_egress_to_bedrock_ingress_*metadata*` tests; asserting it
        // here would test a path the production pipeline doesn't use for bedrock.
        if name != "bedrock" {
            let has_terminal = decoded.iter().any(|e| {
                matches!(e, crate::ir::IrStreamEvent::MessageStop)
                    || matches!(
                        e,
                        crate::ir::IrStreamEvent::MessageDelta {
                            stop_reason: Some(_),
                            ..
                        }
                    )
            });
            assert!(
                    has_terminal,
                    "{name}: a terminal (MessageStop / stop_reason MessageDelta) must round-trip; got {decoded:?}"
                );
        }
    }
}

/// NON-STREAMING round-trip matrix (the class the responses `write_response` bug fell in): for
/// every protocol, an assistant text response written by `write_response` and read back by
/// `read_response` must preserve the text. A writer that emits a non-conformant body its own
/// reader can't decode is caught here.
#[test]
fn test_all_protocols_nonstream_write_read_roundtrip_preserves_text() {
    let text = "Hello, world";
    for proto in [
        Protocol::anthropic(),
        Protocol::openai(),
        Protocol::gemini(),
        Protocol::bedrock(),
        Protocol::responses(),
        Protocol::cohere(),
    ] {
        let name = proto.name().to_string();
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: text.to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 7,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("test-model".to_string()),
            id: Some("resp_x".to_string()),
            created: Some(1_700_000_000),
            system_fingerprint: None,
        };
        let body = proto.writer().write_response(&resp);
        let back = proto.reader().read_response(&body).unwrap_or_else(|e| {
            panic!("{name}: write_response output must read back: {e:?}\nbody: {body}")
        });
        let got: String = back
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            got, text,
            "{name}: non-streaming text must round-trip write_response→read_response; got {got:?}"
        );
    }
}

// ===================================================================================
// A2: cache-token billing-correctness — normalize IrUsage to ONE additive convention.
//
// Readers normalize `input_tokens` to UNCACHED input and keep the cache fields ADDITIVE;
// writers reconstruct the faithful native WIRE shape; billing sums `billable_tokens()`.
// Two safety nets below: (A) ROUND-TRIP FIDELITY — native usage read→IR→write re-emits the
// exact native usage shape (same field names/nesting/presence), proving reader/writer
// normalization is symmetric; (B) BILLING PARITY — OpenAI-family billable UNCHANGED vs pre-A2,
// Anthropic/Bedrock INCREASED by exactly the additive cache tokens (the fix).
// ===================================================================================

/// Build a minimal native assistant response body for `proto` carrying `usage` verbatim. Used to
/// drive read→IR→write and assert usage re-emission fidelity. Bodies mirror each provider's
/// native non-stream shape (the minimum the reader accepts + a text block).
fn native_response_with_usage(name: &str, usage: serde_json::Value) -> serde_json::Value {
    use serde_json::json;
    match name {
        "anthropic" => json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn", "model": "claude", "usage": usage
        }),
        "openai" => json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": usage
        }),
        "gemini" => json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
            "modelVersion": "gemini-pro",
            "usageMetadata": usage
        }),
        "responses" => json!({
            "id": "resp_1", "object": "response", "status": "completed", "model": "gpt-4o",
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": usage
        }),
        "bedrock" => json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn", "usage": usage
        }),
        "cohere" => json!({
            "id": "co_1", "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": usage
        }),
        other => panic!("unknown protocol {other}"),
    }
}

/// (A) ROUND-TRIP FIDELITY with cache tokens: each protocol that carries cache fields, read a
/// native usage block WITH cache tokens → IR → write, and assert the re-emitted usage is
/// semantically identical to the native wire (same field names, numbers, nesting, presence).
/// Especially: OpenAI/Gemini/Responses reconstruct prompt_total = uncached + cached.
#[test]
fn a2_roundtrip_usage_fidelity_with_cache() {
    use serde_json::json;
    // OpenAI: prompt_tokens is a TOTAL (95 uncached + 5 cached); details.cached_tokens = 5.
    {
        let p = protocol_for("openai").unwrap();
        let native = native_response_with_usage(
            "openai",
            json!({"prompt_tokens": 100, "completion_tokens": 10, "prompt_tokens_details": {"cached_tokens": 5}}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.input_tokens, 95, "openai: uncached input");
        assert_eq!(ir.usage.cache_read_input_tokens, Some(5));
        let out = p.writer().write_response(&ir);
        assert_eq!(
            out["usage"]["prompt_tokens"],
            json!(100),
            "openai: prompt_total reconstructed"
        );
        assert_eq!(out["usage"]["completion_tokens"], json!(10));
        assert_eq!(
            out["usage"]["prompt_tokens_details"]["cached_tokens"],
            json!(5)
        );
    }
    // Gemini: promptTokenCount is a TOTAL (120 uncached + 30 cached); cachedContentTokenCount = 30.
    {
        let p = protocol_for("gemini").unwrap();
        let native = native_response_with_usage(
            "gemini",
            json!({"promptTokenCount": 150, "candidatesTokenCount": 20, "cachedContentTokenCount": 30, "totalTokenCount": 170}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.input_tokens, 120, "gemini: uncached input");
        assert_eq!(ir.usage.cache_read_input_tokens, Some(30));
        let out = p.writer().write_response(&ir);
        assert_eq!(
            out["usageMetadata"]["promptTokenCount"],
            json!(150),
            "gemini: prompt_total reconstructed"
        );
        assert_eq!(out["usageMetadata"]["candidatesTokenCount"], json!(20));
        assert_eq!(out["usageMetadata"]["cachedContentTokenCount"], json!(30));
        assert_eq!(out["usageMetadata"]["totalTokenCount"], json!(170));
    }
    // Responses: input_tokens is a TOTAL (36 uncached + 64 cached); details.cached_tokens = 64.
    {
        let p = protocol_for("responses").unwrap();
        let native = native_response_with_usage(
            "responses",
            json!({"input_tokens": 100, "output_tokens": 10, "input_tokens_details": {"cached_tokens": 64}}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.input_tokens, 36, "responses: uncached input");
        assert_eq!(ir.usage.cache_read_input_tokens, Some(64));
        let out = p.writer().write_response(&ir);
        assert_eq!(
            out["usage"]["input_tokens"],
            json!(100),
            "responses: input_total reconstructed"
        );
        assert_eq!(out["usage"]["output_tokens"], json!(10));
        assert_eq!(
            out["usage"]["input_tokens_details"]["cached_tokens"],
            json!(64)
        );
    }
    // Anthropic: cache fields ADDITIVE — input_tokens unchanged, re-emitted verbatim.
    {
        let p = protocol_for("anthropic").unwrap();
        let native = native_response_with_usage(
            "anthropic",
            json!({"input_tokens": 100, "output_tokens": 50, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 2000}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.input_tokens, 100,
            "anthropic: input stays uncached (additive)"
        );
        assert_eq!(ir.usage.cache_read_input_tokens, Some(5000));
        assert_eq!(ir.usage.cache_creation_input_tokens, Some(2000));
        let out = p.writer().write_response(&ir);
        assert_eq!(
            out["usage"]["input_tokens"],
            json!(100),
            "anthropic: input re-emitted verbatim"
        );
        assert_eq!(out["usage"]["cache_read_input_tokens"], json!(5000));
        assert_eq!(out["usage"]["cache_creation_input_tokens"], json!(2000));
    }
    // Bedrock: cache fields ADDITIVE — inputTokens unchanged, re-emitted verbatim.
    {
        let p = protocol_for("bedrock").unwrap();
        let native = native_response_with_usage(
            "bedrock",
            json!({"inputTokens": 100, "outputTokens": 50, "cacheReadInputTokens": 5000, "cacheWriteInputTokens": 2000}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.input_tokens, 100,
            "bedrock: input stays uncached (additive)"
        );
        assert_eq!(ir.usage.cache_read_input_tokens, Some(5000));
        assert_eq!(ir.usage.cache_creation_input_tokens, Some(2000));
        let out = p.writer().write_response(&ir);
        assert_eq!(
            out["usage"]["inputTokens"],
            json!(100),
            "bedrock: input re-emitted verbatim"
        );
        assert_eq!(out["usage"]["cacheReadInputTokens"], json!(5000));
        assert_eq!(out["usage"]["cacheWriteInputTokens"], json!(2000));
    }
}

/// (A) NO-CACHE fidelity: a response with NO cache fields must emit NO cache sub-object/field for
/// EVERY protocol (no spurious `prompt_tokens_details` / `cachedContentTokenCount` /
/// `input_tokens_details` / `cache_read_input_tokens`).
#[test]
fn a2_roundtrip_usage_fidelity_no_cache_emits_no_cache_object() {
    use serde_json::json;
    // OpenAI
    {
        let p = protocol_for("openai").unwrap();
        let native = native_response_with_usage(
            "openai",
            json!({"prompt_tokens": 12, "completion_tokens": 4}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.input_tokens, 12);
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        let out = p.writer().write_response(&ir);
        assert_eq!(out["usage"]["prompt_tokens"], json!(12));
        assert!(
            out["usage"].get("prompt_tokens_details").is_none(),
            "no spurious details: {out}"
        );
    }
    // Gemini (model present so totalTokenCount is emitted, but no cachedContentTokenCount)
    {
        let p = protocol_for("gemini").unwrap();
        let native = native_response_with_usage(
            "gemini",
            json!({"promptTokenCount": 12, "candidatesTokenCount": 4, "totalTokenCount": 16}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        let out = p.writer().write_response(&ir);
        assert_eq!(out["usageMetadata"]["promptTokenCount"], json!(12));
        assert!(
            out["usageMetadata"]
                .get("cachedContentTokenCount")
                .is_none(),
            "no spurious cache field: {out}"
        );
    }
    // Responses
    {
        let p = protocol_for("responses").unwrap();
        let native = native_response_with_usage(
            "responses",
            json!({"input_tokens": 12, "output_tokens": 4}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        let out = p.writer().write_response(&ir);
        assert_eq!(out["usage"]["input_tokens"], json!(12));
        assert!(
            out["usage"].get("input_tokens_details").is_none(),
            "no spurious details: {out}"
        );
    }
    // Anthropic
    {
        let p = protocol_for("anthropic").unwrap();
        let native = native_response_with_usage(
            "anthropic",
            json!({"input_tokens": 12, "output_tokens": 4}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        let out = p.writer().write_response(&ir);
        assert_eq!(out["usage"]["input_tokens"], json!(12));
        assert!(
            out["usage"].get("cache_read_input_tokens").is_none(),
            "no spurious cache field: {out}"
        );
        assert!(out["usage"].get("cache_creation_input_tokens").is_none());
    }
    // Bedrock
    {
        let p = protocol_for("bedrock").unwrap();
        let native =
            native_response_with_usage("bedrock", json!({"inputTokens": 12, "outputTokens": 4}));
        let ir = p.reader().read_response(&native).unwrap();
        let out = p.writer().write_response(&ir);
        assert_eq!(out["usage"]["inputTokens"], json!(12));
        assert!(
            out["usage"].get("cacheReadInputTokens").is_none(),
            "no spurious cache field: {out}"
        );
        assert!(out["usage"].get("cacheWriteInputTokens").is_none());
    }
    // Cohere (no cache fields ever)
    {
        let p = protocol_for("cohere").unwrap();
        let native = native_response_with_usage(
            "cohere",
            json!({"tokens": {"input_tokens": 12, "output_tokens": 4}}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(ir.usage.input_tokens, 12);
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        assert_eq!(ir.usage.billable_tokens(), 16);
    }
}

/// (B) BILLING PARITY + FIX. OpenAI/Gemini/Responses/Cohere: billable UNCHANGED vs pre-A2
/// (prompt_total + output). Anthropic/Bedrock: INCREASED by exactly cache_read + cache_creation.
#[test]
fn a2_billing_parity_and_fix() {
    use serde_json::json;
    // OpenAI-family: a cached response still bills prompt_total + output (NOT uncached+output).
    {
        let p = protocol_for("openai").unwrap();
        let native = native_response_with_usage(
            "openai",
            json!({"prompt_tokens": 100, "completion_tokens": 10, "prompt_tokens_details": {"cached_tokens": 5}}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        // pre-A2: prompt_tokens(100) + completion(10) = 110. Must stay 110.
        assert_eq!(
            ir.usage.billable_tokens(),
            110,
            "openai cached: billable unchanged"
        );
    }
    {
        let p = protocol_for("gemini").unwrap();
        let native = native_response_with_usage(
            "gemini",
            json!({"promptTokenCount": 150, "candidatesTokenCount": 20, "cachedContentTokenCount": 30}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.billable_tokens(),
            170,
            "gemini cached: billable unchanged (150+20)"
        );
    }
    {
        let p = protocol_for("responses").unwrap();
        let native = native_response_with_usage(
            "responses",
            json!({"input_tokens": 100, "output_tokens": 10, "input_tokens_details": {"cached_tokens": 64}}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.billable_tokens(),
            110,
            "responses cached: billable unchanged (100+10)"
        );
    }
    // Anthropic: the explicit fix example. input=100, cache_read=5000, cache_creation=2000,
    // output=50 → billable 7150 (pre-A2 was 150).
    {
        let p = protocol_for("anthropic").unwrap();
        let native = native_response_with_usage(
            "anthropic",
            json!({"input_tokens": 100, "output_tokens": 50, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 2000}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.billable_tokens(),
            7150,
            "anthropic: billable INCREASED by cache (was 150)"
        );
    }
    // Bedrock: additive cache likewise increases billable by cache_read + cache_creation.
    {
        let p = protocol_for("bedrock").unwrap();
        let native = native_response_with_usage(
            "bedrock",
            json!({"inputTokens": 100, "outputTokens": 50, "cacheReadInputTokens": 5000, "cacheWriteInputTokens": 2000}),
        );
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.billable_tokens(),
            7150,
            "bedrock: billable INCREASED by cache (was 150)"
        );
    }
    // No-cache: billable unchanged for all 6 = input + output.
    for (name, usage) in [
        (
            "anthropic",
            json!({"input_tokens": 100, "output_tokens": 50}),
        ),
        (
            "openai",
            json!({"prompt_tokens": 100, "completion_tokens": 50}),
        ),
        (
            "gemini",
            json!({"promptTokenCount": 100, "candidatesTokenCount": 50}),
        ),
        (
            "responses",
            json!({"input_tokens": 100, "output_tokens": 50}),
        ),
        ("bedrock", json!({"inputTokens": 100, "outputTokens": 50})),
        (
            "cohere",
            json!({"tokens": {"input_tokens": 100, "output_tokens": 50}}),
        ),
    ] {
        let p = protocol_for(name).unwrap();
        let native = native_response_with_usage(name, usage);
        let ir = p.reader().read_response(&native).unwrap();
        assert_eq!(
            ir.usage.billable_tokens(),
            150,
            "{name}: no-cache billable = input + output"
        );
    }
}

/// CROSS-PROTOCOL cache_creation reconstruction: an Anthropic/Bedrock-ingress response carries
/// `cache_creation_input_tokens`, which is part of the OpenAI-family TOTAL prompt count. The
/// reconstructed prompt total must include it (input + cache_read + cache_creation), else a
/// cross-protocol client sees a low prompt/total. (None — hence unaffected — same-protocol.)
#[test]
fn a2_cross_protocol_cache_creation_included_in_prompt_total() {
    use serde_json::json;
    let anth = protocol_for("anthropic").unwrap();
    let native = native_response_with_usage(
        "anthropic",
        json!({"input_tokens": 11, "output_tokens": 5, "cache_read_input_tokens": 20, "cache_creation_input_tokens": 40}),
    );
    let ir = anth.reader().read_response(&native).unwrap();
    assert_eq!(ir.usage.input_tokens, 11);
    assert_eq!(ir.usage.cache_read_input_tokens, Some(20));
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(40));
    // OpenAI egress: prompt_tokens = 11 + 20 + 40 = 71; total_tokens = 76.
    let o = protocol_for("openai").unwrap().writer().write_response(&ir);
    assert_eq!(
        o["usage"]["prompt_tokens"],
        json!(71),
        "openai prompt_total includes cache_creation"
    );
    assert_eq!(o["usage"]["total_tokens"], json!(76));
    // Gemini egress: promptTokenCount = 71.
    let g = protocol_for("gemini").unwrap().writer().write_response(&ir);
    assert_eq!(
        g["usageMetadata"]["promptTokenCount"],
        json!(71),
        "gemini prompt_total includes cache_creation"
    );
    // Responses egress: input_tokens = 71.
    let r = protocol_for("responses")
        .unwrap()
        .writer()
        .write_response(&ir);
    assert_eq!(
        r["usage"]["input_tokens"],
        json!(71),
        "responses input_total includes cache_creation"
    );
    // billable is summed straight from the IR and is unaffected by the writer fix: 11+20+40+5.
    assert_eq!(ir.usage.billable_tokens(), 76);
}

/// (f) UNDERFLOW edge case: a hostile/odd upstream where cached > prompt must NOT underflow.
/// `saturating_sub` clamps uncached input to 0 (never panics, never wraps to u64::MAX).
#[test]
fn a2_cached_exceeds_prompt_saturates_to_zero() {
    use serde_json::json;
    // OpenAI: cached(50) > prompt(10) → uncached input clamps to 0; cache_read keeps 50.
    let p = protocol_for("openai").unwrap();
    let native = native_response_with_usage(
        "openai",
        json!({"prompt_tokens": 10, "completion_tokens": 4, "prompt_tokens_details": {"cached_tokens": 50}}),
    );
    let ir = p.reader().read_response(&native).unwrap();
    assert_eq!(
        ir.usage.input_tokens, 0,
        "saturating_sub clamps to 0, no underflow"
    );
    assert_eq!(ir.usage.cache_read_input_tokens, Some(50));
    // Gemini likewise.
    let pg = protocol_for("gemini").unwrap();
    let gnative = native_response_with_usage(
        "gemini",
        json!({"promptTokenCount": 10, "candidatesTokenCount": 4, "cachedContentTokenCount": 50}),
    );
    let irg = pg.reader().read_response(&gnative).unwrap();
    assert_eq!(
        irg.usage.input_tokens, 0,
        "gemini saturating_sub clamps to 0"
    );
    // Responses likewise.
    let pr = protocol_for("responses").unwrap();
    let rnative = native_response_with_usage(
        "responses",
        json!({"input_tokens": 10, "output_tokens": 4, "input_tokens_details": {"cached_tokens": 50}}),
    );
    let irr = pr.reader().read_response(&rnative).unwrap();
    assert_eq!(
        irr.usage.input_tokens, 0,
        "responses saturating_sub clamps to 0"
    );
}

/// The gemini JSON-array framer turns gemini SSE `data:` frames into one streaming JSON array
/// (`[obj,obj,...]`). The concatenated output must be a syntactically valid JSON array whose
/// elements are the per-chunk payloads, in order.
#[test]
fn test_gemini_json_array_framer_basic() {
    let mut f = GeminiJsonArrayFramer::new();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&f.feed(b"data: {\"candidates\":[{\"index\":0}]}\n\n"));
    // A split frame yields nothing until the terminator arrives.
    out.extend_from_slice(&f.feed(b"data: {\"candi"));
    out.extend_from_slice(&f.feed(b"dates\":[{\"index\":1}]}\n\n"));
    out.extend_from_slice(&f.finish());
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("framer output must be a valid JSON array");
    let arr = parsed.as_array().expect("must be an array");
    assert_eq!(arr.len(), 2, "two chunks → two array elements");
    assert_eq!(arr[0]["candidates"][0]["index"], 0);
    assert_eq!(arr[1]["candidates"][0]["index"], 1);
}

/// An empty stream (no data frame) still finishes as a valid empty JSON array `[]`, and the
/// `[DONE]`/keepalive SSE sentinels are dropped (the array close is `finish`'s job).
#[test]
fn test_gemini_json_array_framer_empty_and_done() {
    let mut f = GeminiJsonArrayFramer::new();
    let mid = f.feed(b"data: [DONE]\n\n");
    let end = f.finish();
    let mut out = mid;
    out.extend_from_slice(&end);
    assert_eq!(out, b"[]", "empty stream → empty JSON array");
}

/// The agnostic `finish_with_server_error` seam (proxy engine:`poll_next`) reaches the framer through
/// a `Box<dyn JsonArrayFramer>` — exercise THAT dispatch path: the trait method must produce the
/// native Gemini server-error element (HTTP 500 / gRPC `INTERNAL`) carrying the supplied message,
/// closed into a valid JSON array. The core passes only the message; the impl owns 500/`INTERNAL`.
#[test]
fn test_finish_with_server_error_through_trait_object_is_gemini_500_internal() {
    let mut framer: Box<dyn JsonArrayFramer> = Box::new(gemini::GeminiJsonArrayFramer::new());
    let out = framer.finish_with_server_error("boom");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("server-error body must parse as a JSON array");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1, "empty stream → single trailing error element");
    assert_eq!(arr[0]["error"]["code"], 500);
    assert_eq!(arr[0]["error"]["status"], "INTERNAL");
    assert_eq!(arr[0]["error"]["message"], "boom");
}

/// `finish_with_error` after real chunks appends a gemini-shaped error element + `]`, so
/// the body stays a valid JSON array (used on a mid-stream transport failure).
#[test]
fn test_gemini_json_array_framer_finish_with_error_closes_array() {
    let mut f = GeminiJsonArrayFramer::new();
    let mut out = f.feed(b"data: {\"candidates\":[{\"index\":0}]}\n\n");
    out.extend_from_slice(&f.finish_with_error(500, "INTERNAL", "boom"));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("error-terminated body must parse as JSON array");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 2, "one chunk + one trailing error element");
    assert_eq!(arr[1]["error"]["code"], 500);
    assert_eq!(arr[1]["error"]["status"], "INTERNAL");
    // A finish_with_error on an EMPTY stream still yields a valid single-element array.
    let mut g = GeminiJsonArrayFramer::new();
    let only = g.finish_with_error(503, "UNAVAILABLE", "x");
    let pv: serde_json::Value = serde_json::from_slice(&only).expect("parses");
    assert_eq!(pv.as_array().expect("array").len(), 1);
}

/// When the framer ABORTS (reassembly buffer overran `MAX_BUF` without a terminator),
/// `finish` must emit a gemini error element instead of a bare `]` that would make the silently
/// truncated stream look complete.
#[test]
fn test_gemini_json_array_framer_finish_signals_abort() {
    let mut f = GeminiJsonArrayFramer::new();
    // Feed a frame with no terminator that overruns MAX_BUF → aborts.
    let huge = vec![b'x'; GeminiJsonArrayFramer::MAX_BUF + 16];
    let mut pre = Vec::from(&b"data: {\"k\":\""[..]);
    pre.extend_from_slice(&huge);
    let _ = f.feed(&pre);
    let out = f.finish();
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("aborted finish must still parse as JSON array");
    let arr = parsed.as_array().expect("array");
    assert!(
        arr.iter().any(|el| el.get("error").is_some()),
        "aborted stream must surface an error element, not a silent bare close; got {parsed}"
    );
}

/// Regression: on the GEMINI JSON-ARRAY ingress path the buffer-overflow abort of the
/// UPSTREAM `StreamTranslate` must surface as a trailing error element, NOT a silently truncated
/// bare `]`. The framer's OWN `aborted` flag stays clear (the translate simply stops feeding it),
/// and the caller discards the translate's SSE `finish()` bytes (an SSE error can't ride inside a
/// JSON-array body), so `finish_for_translate(translate.aborted())` must observe the translate-side
/// abort and emit the gemini error-close — mirroring the SSE-ingress terminal-error path. Against
/// the old code (no `aborted()` accessor, plain `framer.finish()`) the array closed with a bare
/// `]` and the truncation was swallowed.
#[test]
fn test_gemini_json_array_surfaces_upstream_translate_abort() {
    // openai egress → gemini ingress: the cross-protocol pairing that engages BOTH a
    // StreamTranslate (openai→gemini SSE) and the JSON-array framer downstream of it.
    let mut st = StreamTranslate::new("gemini", "openai").expect("translator");
    // Drive a real chunk through translate→framer so the array opens with one element.
    let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"index\":0}]}\n\n";
    let mut framer = GeminiJsonArrayFramer::new();
    let translated = st.feed(chunk);
    let mut out = framer.feed(&translated);
    // Now overflow the TRANSLATE reassembly buffer with a never-terminated frame → it aborts.
    let huge = vec![b'x'; StreamTranslate::MAX_BUF + 16];
    let mut never_terminated = Vec::from(&b"data: {\"choices\":[{\"delta\":{\"content\":\""[..]);
    never_terminated.extend_from_slice(&huge);
    let _ = st.feed(&never_terminated);
    assert!(
        st.aborted(),
        "the translate must have aborted on the MAX_BUF overflow"
    );
    // The framer itself did NOT abort — only the upstream translate did.
    // Close the array via the translate-aware path, surfacing the upstream abort.
    out.extend_from_slice(&framer.finish_for_translate(st.aborted()));
    let parsed: serde_json::Value = serde_json::from_slice(&out)
        .expect("aborted-translate finish must still parse as a JSON array");
    let arr = parsed.as_array().expect("array");
    assert!(
            arr.iter().any(|el| el.get("error").is_some()),
            "an aborted upstream translate must surface an error element, not a silent bare close; got {parsed}"
        );

    // Control: with NO upstream abort, `finish_for_translate(false)` closes cleanly (no error
    // element) — the accessor must not spuriously inject an error on a healthy stream.
    let mut clean_st = StreamTranslate::new("gemini", "openai").expect("translator");
    let mut clean_framer = GeminiJsonArrayFramer::new();
    let mut clean_out = clean_framer.feed(&clean_st.feed(chunk));
    let _ = clean_st.finish();
    clean_out.extend_from_slice(&clean_framer.finish_for_translate(clean_st.aborted()));
    let clean: serde_json::Value = serde_json::from_slice(&clean_out).expect("clean finish parses");
    assert!(
        clean
            .as_array()
            .expect("array")
            .iter()
            .all(|el| el.get("error").is_none()),
        "a non-aborted stream must close cleanly with no error element; got {clean}"
    );
}

/// Regression (`StreamTranslate::feed` egress eventstream path): a MALFORMED Bedrock EGRESS
/// prelude (an out-of-range `total_len`) must ABORT the stream — surfacing the ingress protocol's
/// native terminal error from `finish()` — not be silently swallowed. Before the wiring `feed`
/// used the discarding `drain_frames` wrapper, which cleared the buffer on a malformed prelude with
/// no distinct signal, so the stream continued as if healthy and closed with NO terminal exception
/// (a silent truncation a native SDK reads as a clean short completion). The fix uses
/// `drain_frames_checked` and aborts on `DrainStatus::MalformedPrelude`.
#[test]
fn test_egress_eventstream_malformed_prelude_aborts_and_surfaces_error() {
    // anthropic ingress, bedrock egress → `egress_eventstream` is engaged on the feed path.
    let mut st = StreamTranslate::new("anthropic", "bedrock").expect("translator");
    // A malformed prelude: 12 bytes is enough to read `total_len`/`headers_len`. Declare a
    // `total_len` far above MAX_FRAME_BYTES (out of the 16..=MAX_FRAME_BYTES range) → the decoder
    // treats it as an unrecoverable malformed prelude and clears the buffer.
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&u32::MAX.to_be_bytes()); // total_len = ~4 GiB (out of range)
    malformed.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
    malformed.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC (unchecked by the decoder)
    let out = st.feed(&malformed);
    assert!(
        out.is_empty(),
        "a malformed prelude yields no translated frames; got {} bytes",
        out.len()
    );
    assert!(
        st.aborted(),
        "a malformed egress prelude must abort the stream, not silently continue"
    );
    // Every subsequent feed is a no-op (the stream is abandoned).
    assert!(
        st.feed(b"anything").is_empty(),
        "an aborted translator must ignore all further input"
    );
    // `finish()` must surface the ingress-native (anthropic SSE) terminal error frame — the
    // truncation is signaled in-band, not swallowed.
    let term = st.finish();
    let text = String::from_utf8_lossy(&term);
    assert!(
        text.contains("error"),
        "an aborted stream's finish must emit a native error event, not a bare close; got: {text}"
    );
}

/// Regression (same-proto verbatim emit): on a SAME-PROTOCOL
/// bedrock→bedrock stream, a malformed prelude must NOT splice the cleared garbage tail into the
/// client stream ahead of the synthesized exception frame. The verbatim emit uses
/// `drain_frames_checked`'s `consumed_sink` (which collects exactly the complete valid frame
/// bytes), so only the complete valid frame(s) BEFORE the malformed prelude are re-emitted; the
/// cleared malformed remainder is discarded.
#[test]
fn same_proto_bedrock_malformed_prelude_emits_only_valid_frames_not_garbage() {
    let mut st = StreamTranslate::new_same_proto("bedrock").expect("same-proto translator");
    // One VALID bedrock eventstream frame, then a MALFORMED prelude (out-of-range total_len) with
    // a distinctive garbage tail that must NEVER reach the client.
    let valid =
        crate::eventstream::encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
    let mut bytes = valid.clone();
    bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // total_len ~4 GiB — malformed prelude
    bytes.extend_from_slice(&0u32.to_be_bytes()); // headers_len
    bytes.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC (unchecked by the decoder)
    bytes.extend_from_slice(b"GARBAGE-MUST-NOT-REACH-CLIENT");
    let out = st.feed(&bytes);
    assert_eq!(
        out, valid,
        "same-proto verbatim emit must forward ONLY the valid frame bytes, never the cleared \
             malformed remainder"
    );
    assert!(
        !out.windows(7).any(|w| w == b"GARBAGE"),
        "the malformed garbage tail must NOT appear in the client stream"
    );
    assert!(st.aborted(), "a malformed prelude aborts the stream");
    // finish() surfaces the native bedrock terminal exception frame (not a silent truncation).
    assert!(
        !st.finish().is_empty(),
        "an aborted same-proto bedrock stream must emit a terminal exception frame"
    );
}

/// HIGH-1 (wire-correctness): a single Gemini stream chunk batching N `citationSources[]` becomes
/// ONE `IrDelta::CitationsDelta(vec of N)`. On Gemini EGRESS → Anthropic INGRESS, that MUST NOT be
/// flushed as ONE Anthropic `content_block_delta` whose body is a JSON ARRAY of N citation frames
/// (a native Anthropic SDK `JSON.parse`s ONE object per `data:` line and crashes on an array).
/// Every `citations_delta` event on the wire must be EXACTLY ONE citation object; a 3-source
/// Gemini chunk must yield THREE separate single-object `citations_delta` events.
#[test]
fn stream_gemini_multi_citation_yields_separate_single_object_anthropic_events() {
    // ingress = anthropic (the client), egress = gemini (the backend): `feed` consumes Gemini SSE
    // and emits Anthropic SSE.
    let mut st = StreamTranslate::new("anthropic", "gemini").expect("translator");
    // One Gemini chunk: a text part + candidate-level citationMetadata with 3 sources.
    let chunk = br#"data: {"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"answer text"}]},"citationMetadata":{"citationSources":[{"startIndex":0,"endIndex":3,"uri":"https://example.com/a","title":"A"},{"startIndex":3,"endIndex":6,"uri":"https://example.com/b","title":"B"},{"startIndex":6,"endIndex":9,"uri":"https://example.com/c","title":"C"}]}}]}

"#;
    let mut out = st.feed(chunk);
    out.extend_from_slice(&st.finish());
    let text = String::from_utf8(out).expect("anthropic SSE is utf-8");

    // Collect every `data:` line whose parsed body is a `citations_delta` content_block_delta.
    let mut citation_bodies: Vec<serde_json::Value> = Vec::new();
    for line in text.lines() {
        let Some(json) = line.strip_prefix("data:") else {
            continue;
        };
        let Ok(body) = serde_json::from_str::<serde_json::Value>(json.trim()) else {
            continue;
        };
        // INVARIANT: a `citations_delta` event body is NEVER a JSON array — always one object.
        assert!(
            !body.is_array(),
            "no SSE event body may be a JSON array (a native Anthropic SDK crashes on it): {body}"
        );
        if body.pointer("/delta/type").and_then(|t| t.as_str()) == Some("citations_delta") {
            // Each citation event carries exactly ONE `citation` object, never an array.
            let citation = body
                .pointer("/delta/citation")
                .expect("a citations_delta carries a single `citation`");
            assert!(
                citation.is_object(),
                "the `citation` field must be a single object, not an array: {citation}"
            );
            citation_bodies.push(body);
        }
    }

    assert_eq!(
        citation_bodies.len(),
        3,
        "3 Gemini citationSources → 3 separate single-object Anthropic citations_delta events"
    );
    // The three carry the three distinct sources, in order.
    let urls: Vec<&str> = citation_bodies
        .iter()
        .filter_map(|b| b.pointer("/delta/citation/url").and_then(|u| u.as_str()))
        .collect();
    assert_eq!(
        urls,
        vec![
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c"
        ]
    );
}

/// HIGH-1 reverse direction: 3 Anthropic single-citation `citations_delta` events (as a native
/// Anthropic stream emits — one citation per delta) → Gemini EGRESS-shaped `citationMetadata`
/// chunks that are VALID Gemini (candidate-level `citationSources`), never an array-bodied frame.
#[test]
fn stream_anthropic_single_citations_project_to_valid_gemini_citation_metadata() {
    let writer = GeminiWriter;
    let mk = |url: &str| crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::CitationsDelta(vec![crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title: Some("T".to_string()),
            url: Some(url.to_string()),
            document_index: None,
            start_index: Some(0),
            end_index: Some(3),
            encrypted_index: None,
            raw: None,
        }]),
    };
    for url in ["https://x/1", "https://x/2", "https://x/3"] {
        let (_, body) = writer
            .write_response_event(&mk(url))
            .expect("each single-citation delta emits a Gemini citationMetadata chunk");
        let sources = body
            .pointer("/candidates/0/citationMetadata/citationSources")
            .and_then(|s| s.as_array())
            .expect("a valid Gemini chunk carries candidate-level citationSources[]");
        assert_eq!(sources.len(), 1, "one citation per delta → one source");
        assert_eq!(
            sources[0].get("uri").and_then(|v| v.as_str()),
            Some(url),
            "the Gemini source carries the citation uri"
        );
    }
}

/// A REDACTED reasoning block (`Thinking { redacted: true }`) holds opaque encrypted bytes. On a
/// NON-Bedrock egress (Anthropic re-emits its own `redacted_thinking`; the others have no analog),
/// Gemini/Responses/OpenAI/Cohere MUST DROP it — the opaque bytes must never reach the wire as
/// visible text, and no busbar marker exists to leak. Streamed redacted deltas drop likewise.
#[test]
fn redacted_reasoning_drops_on_writers_without_a_native_form() {
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Thinking {
            text: "OPAQUEENCRYPTEDBYTES".to_string(),
            signature: None,
            redacted: true,
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
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
    };

    // Bind each writer to a local (interior-mutable per-stream state).
    let (gw, rw, cw) = (GeminiWriter, ResponsesWriter, CohereWriter);
    let gemini = gw.write_response(&ir).to_string();
    let responses = rw.write_response(&ir).to_string();
    let openai = OpenAiWriter.write_response(&ir).to_string();
    let cohere = cw.write_response(&ir).to_string();
    for (name, wire) in [
        ("gemini", &gemini),
        ("responses", &responses),
        ("openai", &openai),
        ("cohere", &cohere),
    ] {
        assert!(
                !wire.contains("OPAQUEENCRYPTEDBYTES"),
                "{name} must DROP a redacted block — the opaque bytes must never reach the wire: {wire}"
            );
    }

    // A streamed redacted-reasoning delta emits NOTHING on Gemini.
    let redacted_delta = crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::RedactedReasoningDelta("OPAQUEENCRYPTEDBYTES".to_string()),
    };
    assert!(
        gw.write_response_event(&redacted_delta).is_none(),
        "gemini stream must drop a redacted-reasoning delta"
    );
}

/// Encode one AWS event-stream frame (`:event-type` string header + JSON payload) for tests.
fn es_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let name = b":event-type";
    let mut headers = vec![name.len() as u8];
    headers.extend_from_slice(name);
    headers.push(7);
    headers.extend_from_slice(&(event_type.len() as u16).to_be_bytes());
    headers.extend_from_slice(event_type.as_bytes());
    let total = 12 + headers.len() + payload.len() + 4;
    let mut f = Vec::new();
    f.extend_from_slice(&(total as u32).to_be_bytes());
    f.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(&headers);
    f.extend_from_slice(payload);
    f.extend_from_slice(&[0, 0, 0, 0]);
    f
}

/// HIGH/conformance regression (eventstream.rs): a Bedrock EGRESS that sends a mid-stream
/// MODELED-EXCEPTION frame (`:message-type: exception` + `:exception-type`, NO `:event-type`)
/// must surface as a translated ERROR event on the ingress stream, not be silently dropped. Before
/// the fix, `drain_frames` returned `("", payload)` for the exception frame, the folded `type:""`
/// fell into the reader's no-op arm, and the ingress client saw an abrupt EOF with no error.
#[test]
fn test_translate_bedrock_egress_exception_frame_surfaces_error_to_ingress() {
    let mut st = StreamTranslate::new("anthropic", "bedrock").expect("bedrock egress translator");
    let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
    // A real AWS modeled-exception frame built by the production encoder: ThrottlingException
    // carries `:message-type: exception` + `:exception-type: ThrottlingException` and no
    // `:event-type`. `drain_frames` must normalize it to `throttlingException` so the reader's
    // exception arm fires and emits an IR Error → the Anthropic ingress writes an error event.
    bytes.extend(crate::eventstream::encode_exception_frame(
        "ThrottlingException",
        "rate exceeded mid-stream",
    ));

    let out = String::from_utf8(st.feed(&bytes)).unwrap();
    // The mid-stream exception must reach the client as an Anthropic-native error event, NOT be
    // dropped (which would leave the client on a hanging / EOF-without-terminator stream).
    assert!(
        out.contains("event: error") || out.contains("\"type\":\"error\""),
        "bedrock-egress mid-stream exception must translate to an ingress error event; got:\n{out}"
    );
    // The human message rides through.
    assert!(
        out.contains("rate exceeded mid-stream"),
        "the exception message must reach the ingress error body; got:\n{out}"
    );
}

/// a Bedrock ConverseStream (binary event-stream egress) translates to Anthropic SSE for
/// the caller — proving the eventstream decoder → IR → ingress-writer path end to end.
#[test]
fn test_translate_bedrock_eventstream_egress_to_anthropic_ingress() {
    let mut st = StreamTranslate::new("anthropic", "bedrock").expect("bedrock egress translator");
    let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
    bytes.extend(es_frame(
        "contentBlockDelta",
        br#"{"contentBlockIndex":0,"delta":{"text":"Hi"}}"#,
    ));
    bytes.extend(es_frame("contentBlockStop", br#"{"contentBlockIndex":0}"#));
    bytes.extend(es_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
    bytes.extend(es_frame(
        "metadata",
        br#"{"usage":{"inputTokens":5,"outputTokens":2}}"#,
    ));

    let out = String::from_utf8(st.feed(&bytes)).unwrap();
    // Anthropic SSE framing with the translated content.
    assert!(out.contains("event: message_start"), "got:\n{out}");
    assert!(
        out.contains("\"text\":\"Hi\"") || out.contains("Hi"),
        "text delta; got:\n{out}"
    );
    assert!(out.contains("message_stop"), "terminator; got:\n{out}");

    // Finding 1 (delta-before-stop): Bedrock splits stop_reason (`messageStop`) from usage
    // (`metadata`); the egress reader collapses them into ONE combined IR `MessageDelta` emitted
    // BEFORE the terminal `MessageStop`. The Anthropic ingress writer must therefore emit
    // `message_delta` BEFORE `message_stop` — the native non-eventstream order. (Before the fix
    // the IR order was MessageStop-then-MessageDelta, so the writer emitted them reversed.)
    let delta_pos = out.find("event: message_delta");
    let stop_pos = out.find("event: message_stop");
    assert!(
        delta_pos.is_some() && stop_pos.is_some() && delta_pos < stop_pos,
        "message_delta must precede message_stop (native order); got:\n{out}"
    );

    // Finding 2: each translated Anthropic SSE data body carries the native top-level `type`
    // field matching its `event:` header. Assert it for the delta and the terminal stop produced
    // on this cross-protocol path.
    assert!(
        out.contains("\"type\":\"message_delta\""),
        "message_delta data body must carry top-level type; got:\n{out}"
    );
    assert!(
        out.contains("\"type\":\"message_stop\""),
        "message_stop data body must carry top-level type; got:\n{out}"
    );
    // The combined delta carries the usage that arrived in the Bedrock `metadata` frame.
    assert!(
        out.contains("\"input_tokens\":5") && out.contains("\"output_tokens\":2"),
        "combined message_delta must carry the Bedrock metadata usage; got:\n{out}"
    );
}

/// Finding 1 regression at the reader→writer level (independent of eventstream framing): the
/// Bedrock reader must emit the combined `MessageDelta` BEFORE the terminal `MessageStop`, so the
/// Anthropic writer maps them to `message_delta` then `message_stop` — the native order. Guards
/// against a reorder regressing back to MessageStop-then-MessageDelta (which made the Anthropic
/// ingress write `message_stop` first).
#[test]
fn test_bedrock_reader_emits_delta_before_stop_for_anthropic_ingress() {
    use crate::ir::IrStreamEvent;
    let reader = BedrockReader;
    let writer = AnthropicWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    // The terminal pair of the Bedrock wire: `messageStop` (stop_reason) then `metadata` (usage).
    let mut events: Vec<IrStreamEvent> = Vec::new();
    events.extend(reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    ));
    events.extend(reader.read_response_events(
        "",
        &serde_json::json!({"type": "metadata", "usage": {"inputTokens": 5, "outputTokens": 2}}),
        &mut state,
    ));

    // IR order: combined MessageDelta first, terminal MessageStop second.
    assert!(
        matches!(events.first(), Some(IrStreamEvent::MessageDelta { .. })),
        "combined MessageDelta must come first; got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(IrStreamEvent::MessageStop)),
        "terminal MessageStop must come last; got {events:?}"
    );

    // The Anthropic writer maps that order to `message_delta` then `message_stop`.
    let wire: Vec<String> = events
        .iter()
        .filter_map(|e| writer.write_response_event(e).map(|(et, _)| et))
        .collect();
    let delta_pos = wire.iter().position(|t| t == "message_delta");
    let stop_pos = wire.iter().position(|t| t == "message_stop");
    assert!(
        delta_pos.is_some() && stop_pos.is_some() && delta_pos < stop_pos,
        "Anthropic writer must emit message_delta before message_stop; got {wire:?}"
    );
}

/// Regression: the post-`MessageStop` ordering guard must drop a DUPLICATE terminal
/// `MessageDelta` (one carrying a `stop_reason`), not only the usage-only
/// `MessageDelta{stop_reason: None}` flavour. A misbehaving / re-emitting egress backend can
/// repeat its finish event after the stop; writing the second `message_delta` AFTER
/// `message_stop` is invalid stream framing and a proxy tell. Drive an Anthropic SSE egress
/// (so we control the exact `message_delta`/`message_stop` ordering) into an OpenAI ingress
/// (a terminal `MessageDelta` surfaces as a `finish_reason` chunk), inject a second terminal
/// `message_delta` after the stop, and assert exactly ONE `finish_reason` chunk reaches the
/// wire. Before the broadened guard the duplicate slipped through as a second finish chunk.
#[test]
fn test_duplicate_terminal_message_delta_after_stop_is_dropped() {
    let mut st = StreamTranslate::new("openai", "anthropic").expect("translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            // DUPLICATE terminal delta AFTER the stop — must be dropped by the guard.
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
        ] {
            raw.extend(st.feed(frame.as_bytes()));
        }

    let out = String::from_utf8(raw).expect("utf8 SSE");
    // Exactly one OpenAI terminal chunk: the terminal `MessageDelta` maps to a
    // `finish_reason:"stop"` chunk (intermediate chunks carry `finish_reason:null`), and the
    // duplicate that arrived after the stop must NOT add a second terminal chunk.
    let finishes = out.matches("\"finish_reason\":\"stop\"").count();
    assert_eq!(
            finishes, 1,
            "exactly one terminal finish_reason chunk; the duplicate terminal delta must be dropped; got:\n{out}"
        );
}

/// BYTE-IDENTITY GUARD: locks the wire shape of the OpenAI chunk-identity replay +
/// include_usage trailing-usage split. This logic now lives behind the writer vtable in
/// `proto::openai_chat`'s `StreamFraming` impl (the protocol-named `openai_chunk_identity` field is gone
/// from `StreamTranslate`); this guard proves the vtable relocation stayed byte-identical and
/// catches any future regression. ingress=openai (client), egress=anthropic (backend): the translator
/// writes OpenAI chunks, replaying ONE latched id/created across every chunk and un-folding the
/// usage off the finish chunk into a separate trailing chunk.
#[test]
fn openai_egress_chunk_identity_and_trailing_usage_byte_shape() {
    let mut st = StreamTranslate::new("openai", "anthropic").expect("translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(st.feed(frame.as_bytes()));
        }
    raw.extend(st.finish());
    let out = String::from_utf8(raw).expect("utf8 SSE");

    // (a) Every chat.completion.chunk shares ONE latched stream id — never a per-chunk id, never
    // the backend's `msg_x`.
    let ids: std::collections::BTreeSet<String> = out
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter(|d| d.contains("chat.completion.chunk"))
        .filter_map(|d| {
            let start = d.find("\"id\":\"")? + 6;
            let rest = &d[start..];
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "all openai chunks must share ONE stream id; got {ids:?} in\n{out}"
    );
    assert!(
        !out.contains("msg_x"),
        "the anthropic backend id must not leak; got\n{out}"
    );

    // (b) include_usage un-fold: a terminal finish chunk AND a separate trailing usage chunk —
    // never one chunk carrying both a non-null finish_reason and usage.
    assert!(
        out.contains("\"finish_reason\":\"stop\""),
        "a terminal finish chunk; got\n{out}"
    );
    assert!(
        out.contains("\"usage\""),
        "a trailing usage chunk; got\n{out}"
    );
    for line in out.lines().filter_map(|l| l.strip_prefix("data: ")) {
        let has_finish = line.contains("\"finish_reason\":\"stop\"");
        let has_usage = line.contains("\"usage\":{");
        assert!(
            !(has_finish && has_usage),
            "no single chunk may carry BOTH finish_reason=stop AND usage (un-fold); got:\n{line}"
        );
    }
}

/// BYTE-IDENTITY GUARD: locks the wire shape of the Bedrock messageStop/metadata two-frame
/// deferral. This logic now lives behind the writer vtable in `proto::bedrock`'s `StreamFraming`
/// impl (the protocol-named `bedrock_metadata_emitted`/`bedrock_metadata_pending` fields are gone
/// from `StreamTranslate`). A native ConverseStream ends with EXACTLY ONE `metadata` frame, however
/// the egress backend splits stop vs usage; this guard proves the vtable relocation stayed
/// byte-identical. Two cases: usage-bundled-with-stop, and the deferred (no-usage-on-stop)
/// case that `finish()` must flush.
#[test]
fn bedrock_egress_emits_exactly_one_metadata_frame() {
    // Case A — usage rides WITH the stop (Anthropic backend bundles usage on message_delta):
    // exactly one metadata frame, after messageStop.
    let mut a = StreamTranslate::new("bedrock", "anthropic").expect("translator");
    let mut raw_a: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw_a.extend(a.feed(frame.as_bytes()));
        }
    raw_a.extend(a.finish());
    let mut buf_a = raw_a;
    let frames_a = crate::eventstream::drain_frames(&mut buf_a);
    assert!(
        buf_a.is_empty(),
        "case A frames must decode cleanly; {} left",
        buf_a.len()
    );
    let meta_a = frames_a.iter().filter(|(et, _)| et == "metadata").count();
    assert_eq!(
        meta_a, 1,
        "case A must emit exactly ONE metadata frame; got {meta_a}"
    );

    // Case B — deferred: an OpenAI backend's finish chunk carries NO usage, no trailing usage chunk
    // follows (no include_usage). finish() must flush ONE zero-usage metadata so the native
    // always-one-metadata invariant holds.
    let mut b = StreamTranslate::new("bedrock", "openai").expect("translator");
    let mut raw_b: Vec<u8> = Vec::new();
    for frame in [
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ] {
            raw_b.extend(b.feed(frame.as_bytes()));
        }
    raw_b.extend(b.finish());
    let mut buf_b = raw_b;
    let frames_b = crate::eventstream::drain_frames(&mut buf_b);
    assert!(
        buf_b.is_empty(),
        "case B frames must decode cleanly; {} left",
        buf_b.len()
    );
    let meta_b = frames_b.iter().filter(|(et, _)| et == "metadata").count();
    assert_eq!(
        meta_b, 1,
        "case B (deferred) must flush exactly ONE metadata frame via finish(); got {meta_b}"
    );
}

/// Bedrock *ingress* streaming: an Anthropic SSE backend stream → a native AWS SDK Bedrock
/// client. `StreamTranslate("bedrock", "anthropic")` must emit BINARY
/// `application/vnd.amazon.eventstream` frames (not SSE) that `drain_frames` decodes back into
/// the expected Converse event sequence. This is the encoder's cross-protocol acceptance test:
/// it exercises encode_frame on the live streaming path and round-trips through the production
/// decoder, proving CRC + framing validity end to end. No `data: [DONE]` terminator.
#[test]
fn test_translate_anthropic_egress_to_bedrock_ingress_binary_frames() {
    let mut t = StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_backend\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
    // Bedrock has no `[DONE]`: the messageStop frame is the terminator, so finish() is empty.
    assert!(
        t.finish().is_empty(),
        "bedrock ingress emits no terminator frame in finish()"
    );

    // The output must NOT be SSE text — it must be binary frames the decoder can parse.
    assert!(
        !raw.starts_with(b"event:") && !raw.starts_with(b"data:"),
        "bedrock ingress output must be binary frames, not SSE"
    );

    let mut buf = raw.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "all emitted frames must decode cleanly (valid CRC + lengths); {} bytes left",
        buf.len()
    );
    let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
    assert_eq!(
        types.first().copied(),
        Some("messageStart"),
        "stream opens with messageStart; got {types:?}"
    );
    assert!(
        types.contains(&"contentBlockDelta"),
        "must carry a contentBlockDelta; got {types:?}"
    );
    assert!(
        types.contains(&"messageStop"),
        "must carry messageStop terminator; got {types:?}"
    );
    // The combined IR MessageDelta (stop_reason + usage) must FAN OUT into BOTH a `messageStop`
    // frame AND a following `metadata` frame carrying the real usage — the native two-frame
    // ConverseStream sequence (finding: messageStop+metadata fan-out). A single Anthropic
    // `message_delta` thus reproduces the genuine Bedrock pair.
    assert!(
        types.contains(&"metadata"),
        "combined delta must fan out a `metadata` usage frame; got {types:?}"
    );
    // messageStop must precede metadata (native order).
    let stop_pos = types.iter().position(|t| *t == "messageStop");
    let meta_pos = types.iter().position(|t| *t == "metadata");
    assert!(
        stop_pos < meta_pos,
        "messageStop must precede metadata (native order); got {types:?}"
    );
    // The metadata frame carries the real token usage from the Anthropic message_delta.
    let meta = frames
        .iter()
        .find(|(et, _)| et == "metadata")
        .expect("a metadata frame");
    let mv: serde_json::Value =
        serde_json::from_slice(&meta.1).expect("valid metadata JSON payload");
    assert_eq!(
        mv.pointer("/usage/inputTokens").and_then(|x| x.as_u64()),
        Some(5),
        "metadata usage inputTokens round-trips; got {mv}"
    );
    assert_eq!(
        mv.pointer("/usage/outputTokens").and_then(|x| x.as_u64()),
        Some(2),
        "metadata usage outputTokens round-trips; got {mv}"
    );
    // The metadata frame carries a real `metrics.latencyMs` (a u64), never the tell-tale absent /
    // fabricated-0 of the old writer; it is injected by StreamTranslate from the stream wall-clock.
    assert!(
        mv.pointer("/metrics/latencyMs")
            .and_then(|x| x.as_u64())
            .is_some(),
        "metadata must carry a real metrics.latencyMs; got {mv}"
    );

    // The contentBlockDelta payload must round-trip the translated text.
    let delta = frames
        .iter()
        .find(|(et, _)| et == "contentBlockDelta")
        .expect("a contentBlockDelta frame");
    let v: serde_json::Value = serde_json::from_slice(&delta.1).expect("valid JSON payload");
    assert_eq!(
        v.pointer("/delta/text").and_then(|x| x.as_str()),
        Some("Hi"),
        "delta text round-trips; got {v}"
    );

    // The foreign Anthropic `msg_backend` id must NOT appear anywhere in the binary stream
    // (cross-protocol MessageStart identity strip). Bedrock's messageStart carries no id anyway,
    // so this also guards against a regression that would leak it.
    assert!(
        !raw.windows(b"msg_backend".len())
            .any(|w| w == b"msg_backend"),
        "foreign backend stream id must be stripped on cross-protocol ingress"
    );
}

/// Bedrock *ingress* streaming, TOOL-CALL path: an Anthropic SSE `content_block_start` with a
/// `tool_use` block + `input_json_delta` + `content_block_stop` must translate through the binary
/// Bedrock encoder into a `contentBlockStart` frame carrying a `toolUse` start, a
/// `contentBlockDelta` carrying the tool input, and a `contentBlockStop`. Exercises
/// `BedrockWriter::write_response_event`'s `BlockStart(ToolUse)`/`InputJsonDelta` arms on the live
/// `StreamTranslate` path (previously only covered by the unit `test_write_response_event`).
#[test]
fn test_translate_anthropic_egress_to_bedrock_ingress_tool_call() {
    let mut t = StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_abc\",\"name\":\"get_weather\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\\\"SF\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }

    let mut buf = raw.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "all emitted frames decode cleanly; {} bytes left",
        buf.len()
    );
    let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
    assert!(
        types.contains(&"contentBlockStart"),
        "tool_use must emit a contentBlockStart frame; got {types:?}"
    );
    assert!(
        types.contains(&"contentBlockStop"),
        "must emit a contentBlockStop frame; got {types:?}"
    );

    // The contentBlockStart frame must carry the toolUse start payload.
    let start = frames
        .iter()
        .find(|(et, _)| et == "contentBlockStart")
        .expect("a contentBlockStart frame");
    let v: serde_json::Value = serde_json::from_slice(&start.1).expect("valid JSON payload");
    assert_eq!(
        v.pointer("/start/toolUse/name").and_then(|x| x.as_str()),
        Some("get_weather"),
        "toolUse name round-trips; got {v}"
    );
    // §Finding-2 (cross-protocol tool-id native remap): the egress Anthropic `toolu_abc` id is NO
    // LONGER emitted verbatim to the Bedrock client — that would leak a foreign id shape. It is
    // reshaped to the Bedrock-native `tooluse_` form at the seam, and the reshaped id must decode
    // back to the original `toolu_abc` so the round-trip (client → request path → backend) stays
    // consistent. (Updated from the prior verbatim-`toolu_abc` assertion — the new, more-correct
    // contract.)
    let emitted_tool_id = v
        .pointer("/start/toolUse/toolUseId")
        .and_then(|x| x.as_str())
        .expect("toolUseId present");
    assert!(
            emitted_tool_id.starts_with("tooluse_") && emitted_tool_id != "toolu_abc",
            "Bedrock client must see a native `tooluse_` id, not the foreign `toolu_abc`; got {emitted_tool_id}"
        );
    assert_eq!(
        decode_native_tool_id("bedrock", emitted_tool_id).as_deref(),
        Some("toolu_abc"),
        "the reshaped id must decode back to the original egress tool id; got {emitted_tool_id}"
    );

    // The contentBlockDelta frame must carry the tool input JSON.
    let delta = frames
        .iter()
        .find(|(et, _)| et == "contentBlockDelta")
        .expect("a contentBlockDelta frame");
    let dv: serde_json::Value = serde_json::from_slice(&delta.1).expect("valid JSON payload");
    assert!(
        dv.pointer("/delta/toolUse/input").is_some(),
        "tool input delta round-trips through the binary encoder; got {dv}"
    );
}

/// HIGH/conformance regression: a mid-stream upstream ERROR on a Bedrock-INGRESS cross-protocol
/// stream must be framed as a MODELED EXCEPTION (`:message-type: exception` + `:exception-type`),
/// NOT a normal `:message-type: event` frame. An AWS SDK dispatches errors off `:message-type`;
/// an `event`-typed frame naming a Converse exception is silently dropped, so the client never
/// surfaces the error and the stream appears to truncate. This drives an Anthropic egress
/// `event: error` frame (decoded to `IrStreamEvent::Error`) through the bedrock-ingress translator
/// and asserts the emitted frame is a real exception frame.
#[test]
fn test_translate_error_to_bedrock_ingress_is_exception_frame() {
    let mut t = StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
    // Anthropic native mid-stream error envelope → IrStreamEvent::Error. The Anthropic reader now
    // derives the breaker class from the error `type`: `overloaded_error` → Overloaded,
    // which the bedrock-ingress writer frames as `ServiceUnavailableException` (the transient
    // overload exception), NOT the generic `ValidationException` a client fault would yield.
    let err_frame = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"upstream is overloaded\"}}\n\n";
    let raw = t.feed(err_frame.as_bytes());
    assert!(!raw.is_empty(), "an error event must emit a frame");
    // Must be binary framing, not SSE text.
    assert!(
        !raw.starts_with(b"event:") && !raw.starts_with(b"data:"),
        "bedrock ingress error must be a binary frame, not SSE text"
    );
    // The frame must be a valid event-stream message carrying the exception headers.
    let headers_len = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let headers = String::from_utf8_lossy(&raw[12..12 + headers_len]);
    assert!(
        headers.contains(":message-type"),
        "frame carries a :message-type header; headers: {headers}"
    );
    assert!(
        headers.contains("exception"),
        ":message-type must be `exception`, not `event`; headers: {headers}"
    );
    assert!(
        headers.contains(":exception-type"),
        "frame carries an :exception-type header; headers: {headers}"
    );
    // The exception-type is a real Converse exception name (Overloaded → ServiceUnavailableException).
    assert!(
        headers.contains("ServiceUnavailableException"),
        ":exception-type names the transient overload Converse exception; headers: {headers}"
    );
    // The whole frame must decode without trailing bytes (valid CRC + lengths).
    let total_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    assert_eq!(total_len, raw.len(), "total_len matches the bytes emitted");
    // Payload is the JSON `{"message": ...}` the SDK surfaces. The Anthropic stream-error reader
    // carries the upstream error `type` as the IR `provider_signal`, which becomes the message.
    let payload = &raw[12 + headers_len..total_len - 4];
    let v: serde_json::Value = serde_json::from_slice(payload).expect("valid JSON payload");
    assert!(
        v.get("message").and_then(|m| m.as_str()).is_some(),
        "exception frame carries a JSON message body; got {v}"
    );
}

/// MEDIUM/conformance regression: on a cross-protocol Gemini-INGRESS stream, the MessageStart
/// frame must still carry a `responseId` even though `StreamTranslate` strips the foreign id/model
/// to `None` — a native google-genai SDK reads `chunk.response_id` off the first chunk. Previously
/// the Gemini writer emitted NO frame when both id and model were `None`, leaving the client with
/// no responseId on any cross-protocol Gemini stream.
#[test]
fn test_translate_to_gemini_ingress_synthesizes_response_id() {
    let mut t = StreamTranslate::new("gemini", "openai").expect("gemini ingress translator");
    // OpenAI chunk with a top-level id/model that the cross-protocol strip will clear.
    let chunk = "data: {\"id\":\"chatcmpl-abc\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n";
    let out = String::from_utf8(t.feed(chunk.as_bytes())).unwrap();
    assert!(
        out.contains("responseId"),
        "gemini cross-protocol stream must carry a synthesized responseId; got:\n{out}"
    );
    // The foreign OpenAI id must NOT leak through.
    assert!(
        !out.contains("chatcmpl-abc"),
        "foreign backend id must be stripped, not leaked; got:\n{out}"
    );
}

/// Regression: a CROSS-PROTOCOL tool call streamed to a Gemini client
/// must surface as a SINGLE native `functionCall` part `{name, args}` — not a `{name, args:{}}`
/// opening frame followed by a separate nameless `{args}` part. An OpenAI backend emits the tool
/// NAME on the first tool-call chunk and the arguments as later `arguments` fragments; the IR
/// preserves that split (BlockStart{ToolUse{name}} then InputJsonDelta). Before the GeminiWriter
/// per-stream buffer, the writer emitted two parts: an empty-args part carrying the name and an
/// args part carrying NO name — a shape a native google-genai client never produces (and where a
/// strict client reading `function_call.name` off the args part sees an empty string). The
/// per-stream buffer re-attaches the name to the args part so exactly one `{name, args}` part is
/// written.
#[test]
fn test_translate_to_gemini_tool_call_single_functioncall_part() {
    let mut t = StreamTranslate::new("gemini", "openai").expect("gemini ingress translator");
    let mut out = String::new();
    for frame in [
            // role chunk
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            // first tool-call chunk: id + name, no args yet
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\"}}]}}]}\n\n",
            // argument fragments
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"SF\\\"}\"}}]}}]}\n\n",
            // finish
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    out.push_str(&String::from_utf8(t.finish()).unwrap());

    // Collect every `functionCall` part across all emitted Gemini chunks.
    let payloads = data_payloads(&out);
    let func_parts: Vec<&serde_json::Value> = payloads
        .iter()
        .filter_map(|p| {
            p.pointer("/candidates/0/content/parts")
                .and_then(|parts| parts.as_array())
        })
        .flatten()
        .filter_map(|part| part.get("functionCall"))
        .collect();

    assert_eq!(
            func_parts.len(),
            1,
            "exactly one native functionCall part expected (no empty-args-then-args split); got:\n{out}"
        );
    let func = func_parts[0];
    assert_eq!(
        func.pointer("/name").and_then(|n| n.as_str()),
        Some("get_weather"),
        "the single functionCall part must carry the name; got:\n{out}"
    );
    assert_eq!(
        func.pointer("/args/city").and_then(|c| c.as_str()),
        Some("SF"),
        "the single functionCall part must carry the args; got:\n{out}"
    );
    // No nameless functionCall part anywhere (the old split's second part).
    assert!(
        !func_parts.iter().any(|f| f
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .is_empty()),
        "no nameless functionCall part may be emitted; got:\n{out}"
    );
}

/// A CRLF-delimited SSE upstream (`\r\n\r\n` frame terminators — spec-legal, emitted by some
/// gateways/CDNs) must reassemble and translate correctly. An LF-only scanner would never detect
/// a terminator and buffer the whole stream until MAX_BUF, then abort — stalling the client.
#[test]
fn test_translate_crlf_sse_frames() {
    let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
    // OpenAI-style bare `data:` frames with CRLF line endings and `\r\n\r\n` terminators.
    let chunk = "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\r\n\r\n";
    let out = String::from_utf8(t.feed(chunk.as_bytes())).unwrap();
    assert!(
        !out.is_empty(),
        "CRLF SSE must produce translated output, not stall"
    );
    assert!(
        out.contains("He") && out.contains("llo"),
        "both CRLF-delimited deltas must translate; got:\n{out}"
    );
    assert!(!t.aborted, "CRLF stream must not be abandoned");
}

/// Decoder also works when the binary frames arrive split across feed() calls (partial frame
/// buffered, then completed) — the realistic chunked-transport case.
#[test]
fn test_translate_bedrock_eventstream_split_chunks() {
    let mut st = StreamTranslate::new("anthropic", "bedrock").expect("translator");
    let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
    bytes.extend(es_frame(
        "contentBlockDelta",
        br#"{"contentBlockIndex":0,"delta":{"text":"Yo"}}"#,
    ));
    let split = bytes.len() - 6; // mid-second-frame
    let mut out = st.feed(&bytes[..split]);
    out.extend(st.feed(&bytes[split..]));
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains("Yo"),
        "text survives a frame split across chunks; got:\n{s}"
    );
}

/// Collect the JSON payloads of all `data:` lines (excluding `[DONE]`).
fn data_payloads(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(|s| s.trim())
        .filter(|s| *s != "[DONE]")
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect()
}

// anthropic egress stream → openai ingress: client receives OpenAI chat.completion.chunks.
#[test]
fn test_translate_anthropic_egress_to_openai_ingress() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let mut out = String::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    out.push_str(&String::from_utf8(t.finish()).unwrap());

    assert!(
        !out.contains("event:"),
        "OpenAI output must have no event: lines; got {out}"
    );
    let payloads = data_payloads(&out);
    assert!(
        payloads.iter().any(|p| p
            .pointer("/choices/0/delta/content")
            .and_then(|v| v.as_str())
            == Some("hi")),
        "translated content 'hi' missing; got {out}"
    );
    assert!(
        payloads.iter().any(|p| p
            .pointer("/choices/0/finish_reason")
            .and_then(|v| v.as_str())
            == Some("stop")),
        "finish_reason 'stop' missing; got {out}"
    );
    assert!(
        out.trim_end().ends_with("data: [DONE]"),
        "OpenAI stream must end with data: [DONE]; got {out}"
    );
}

// openai egress stream → anthropic ingress: client receives Anthropic event: frames.
#[test]
fn test_translate_openai_egress_to_anthropic_ingress() {
    let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
    let mut out = String::new();
    for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    assert!(
        t.finish().is_empty(),
        "Anthropic ingress has no [DONE] terminator"
    );
    assert!(
        out.contains("event: message_start"),
        "missing message_start; got {out}"
    );
    assert!(
        out.contains("event: content_block_delta"),
        "missing content_block_delta; got {out}"
    );
    assert!(
        out.contains("text_delta") && out.contains("hi"),
        "missing text_delta 'hi'; got {out}"
    );
    assert!(
        out.contains("event: message_stop"),
        "missing message_stop; got {out}"
    );
}

// Finding 1 (input-token loss across the IR on streaming). Anthropic's SSE carries
// `usage.input_tokens` ONLY on `message_start`; its `message_delta` carries `output_tokens`
// alone. On a cross-protocol hop OUT of an Anthropic backend the terminal `MessageDelta.usage`
// therefore had `input_tokens == 0` and the prompt-token count vanished. `StreamTranslate` now
// latches the start-usage input/cache tokens and backfills the terminal delta. Gemini ingress is
// the cleanest observer: its writer renders the terminal usage as `usageMetadata.promptTokenCount`
// (Anthropic→Gemini), so a non-zero promptTokenCount proves the input count survived the seam.
#[test]
fn test_translate_anthropic_egress_to_gemini_ingress_preserves_input_tokens() {
    let mut t = StreamTranslate::new("gemini", "anthropic").expect("gemini ingress translator");
    let mut out = String::new();
    for frame in [
            // input_tokens live ONLY here (message_start), per the native Anthropic shape.
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input_tokens\":42,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            // message_delta carries output_tokens but NO input_tokens (native Anthropic).
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    out.push_str(&String::from_utf8(t.finish()).unwrap());
    let payloads = data_payloads(&out);
    // The terminal Gemini chunk's usageMetadata must report BOTH the input (prompt) tokens
    // latched at stream start AND the output (candidates) tokens from the delta.
    let usage = payloads
        .iter()
        .find_map(|p| p.pointer("/usageMetadata"))
        .unwrap_or_else(|| panic!("no usageMetadata in translated stream; got {out}"));
    assert_eq!(
        usage.get("promptTokenCount").and_then(|v| v.as_u64()),
        Some(42),
        "input tokens captured at message_start must survive to the terminal usage; got {out}"
    );
    assert_eq!(
        usage.get("candidatesTokenCount").and_then(|v| v.as_u64()),
        Some(7),
        "output tokens from message_delta must be reported; got {out}"
    );
}

// Finding 1, same-protocol round-trip: an Anthropic stream read into IR events and written back
// out by the Anthropic writer must carry input tokens (message_start) AND output tokens
// (message_delta) — neither half lost. (Same-protocol forwarding is byte-passthrough in prod and
// never hits StreamTranslate; this asserts the reader+writer IR contract underneath that.)
#[test]
fn test_anthropic_stream_usage_roundtrips_input_and_output_tokens() {
    let reader = AnthropicReader;
    let writer = AnthropicWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    // message_start → MessageStart carrying input_tokens.
    let start_in = serde_json::json!({
        "type":"message_start",
        "message":{"role":"assistant","usage":{"input_tokens":42,"output_tokens":0}}
    });
    let start_evs = reader.read_response_events("message_start", &start_in, &mut state);
    let (_et, start_out) = writer
        .write_response_event(&start_evs[0])
        .expect("message_start writes");
    assert_eq!(
        start_out
            .pointer("/message/usage/input_tokens")
            .and_then(|v| v.as_u64()),
        Some(42),
        "message_start must round-trip input_tokens"
    );

    // message_delta → MessageDelta carrying output_tokens.
    let delta_in = serde_json::json!({
        "type":"message_delta",
        "delta":{"stop_reason":"end_turn"},
        "usage":{"output_tokens":7}
    });
    let delta_evs = reader.read_response_events("message_delta", &delta_in, &mut state);
    let (_et, delta_out) = writer
        .write_response_event(&delta_evs[0])
        .expect("message_delta writes");
    assert_eq!(
        delta_out
            .pointer("/usage/output_tokens")
            .and_then(|v| v.as_u64()),
        Some(7),
        "message_delta must round-trip output_tokens"
    );
}

// HIGH/test-coverage (proto/mod.rs): StreamTranslate with COHERE as the ingress side. Cohere
// uses a bare `data:` envelope keyed on `type` and must NEVER emit a `[DONE]` sentinel
// (`emit_done` is false for cohere). Exercises CohereWriter::write_delta/write_stop through the
// translator end-to-end.
#[test]
fn test_translate_anthropic_egress_to_cohere_ingress() {
    let mut t = StreamTranslate::new("cohere", "anthropic").expect("cohere ingress translator");
    let mut out = String::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    out.push_str(&String::from_utf8(t.finish()).unwrap());

    // Cohere v2 native stream: bare `data:` frames, no `event:` lines.
    assert!(
        !out.contains("event:"),
        "Cohere output must have no event: lines; got {out}"
    );
    // Cohere must NEVER emit a `[DONE]` sentinel (emit_done is false for cohere ingress).
    assert!(
        !out.contains("[DONE]"),
        "Cohere stream must NOT emit a [DONE] sentinel; got {out}"
    );
    let payloads = data_payloads(&out);
    // The translated text rides at delta.message.content.text in a `content-delta` frame.
    assert!(
        payloads.iter().any(|p| p["type"] == "content-delta"
            && p.pointer("/delta/message/content/text")
                .and_then(|v| v.as_str())
                == Some("hi")),
        "missing cohere content-delta carrying 'hi'; got {out}"
    );
    // The terminal `message-end` carries the finish reason and usage.
    assert!(
        payloads.iter().any(|p| p["type"] == "message-end"
            && p.pointer("/delta/finish_reason").and_then(|v| v.as_str()) == Some("COMPLETE")),
        "missing cohere message-end COMPLETE; got {out}"
    );
}

// HIGH/test-coverage (proto/mod.rs): StreamTranslate with RESPONSES as the ingress side.
// The Responses API uses NAMED SSE events (`event: response.created` ... `response.completed`),
// not bare `data:` frames, and never a `[DONE]`. Exercises ResponsesWriter::write_delta/write_stop
// through the translator end-to-end.
#[test]
fn test_translate_anthropic_egress_to_responses_ingress() {
    let mut t =
        StreamTranslate::new("responses", "anthropic").expect("responses ingress translator");
    let mut out = String::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    out.push_str(&String::from_utf8(t.finish()).unwrap());

    // Responses uses named events for the stream boundaries.
    assert!(
        out.contains("event: response.created"),
        "missing Responses event: response.created; got {out}"
    );
    assert!(
        out.contains("event: response.completed"),
        "missing Responses event: response.completed; got {out}"
    );
    // Never a `[DONE]` (emit_done is only true for openai ingress).
    assert!(
        !out.contains("[DONE]"),
        "Responses stream must NOT emit a [DONE] sentinel; got {out}"
    );
}

// MEDIUM/conformance (proto/mod.rs fan-out): OpenAI egress with `stream_options.include_usage`
// splits its terminal info across TWO chunks — a finish_reason chunk with NO usage, then a
// usage-only chunk. A native ConverseStream emits EXACTLY ONE `metadata` frame; the pre-fix
// fan-out emitted a zero-usage metadata for the first AND a real metadata for the second. Assert
// exactly one `metadata` frame, carrying the REAL tokens.
#[test]
fn test_translate_openai_include_usage_egress_to_bedrock_ingress_single_metadata() {
    let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        // include_usage: terminal finish chunk carries NO usage...
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        // ...usage rides a SEPARATE trailing chunk (empty choices).
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":11}}\n\n",
        "data: [DONE]\n\n",
    ] {
        raw.extend_from_slice(&t.feed(frame.as_bytes()));
    }
    raw.extend_from_slice(&t.finish());

    // Decode the binary eventstream frames.
    let mut buf = raw.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(buf.is_empty(), "all frames must decode cleanly");

    // Exactly ONE `metadata` frame (a native ConverseStream emits exactly one), carrying the
    // REAL tokens — NOT the pre-fix pair (a zero-usage frame + a real frame).
    let metadata: Vec<&(String, Vec<u8>)> =
        frames.iter().filter(|(et, _)| et == "metadata").collect();
    assert_eq!(
        metadata.len(),
        1,
        "a native ConverseStream emits exactly ONE metadata frame; got {}",
        metadata.len()
    );
    let md: serde_json::Value =
        serde_json::from_slice(&metadata[0].1).expect("metadata payload is JSON");
    assert_eq!(
        md["usage"]["inputTokens"], 7,
        "metadata must carry the REAL input tokens, not a zero frame; got {md}"
    );
    assert_eq!(
        md["usage"]["outputTokens"], 11,
        "metadata must carry the REAL output tokens; got {md}"
    );
    // And exactly one messageStop frame (the stop discriminant).
    let stops = frames.iter().filter(|(et, _)| et == "messageStop").count();
    assert_eq!(stops, 1, "exactly one messageStop frame");
}

// Regression: for NON-eventstream (SSE) ingress, the
// trailing OpenAI `include_usage` usage-only chunk arrives AFTER the finish chunk that already
// produced the terminal frame. Translating it would put a `message_delta` AFTER `message_stop` on
// an Anthropic-ingress wire — invalid stream framing and a proxy tell. `StreamTranslate` must
// drop the post-stop usage-only delta for SSE ingress (the bedrock path folds it into metadata
// instead, covered by the test above).
#[test]
fn test_translate_openai_include_usage_to_anthropic_ingress_no_post_stop_message_delta() {
    let mut t = StreamTranslate::new("anthropic", "openai").expect("anthropic ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        // include_usage trailing chunk (empty choices, real usage) — arrives after the finish.
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":11}}\n\n",
        "data: [DONE]\n\n",
    ] {
        raw.extend_from_slice(&t.feed(frame.as_bytes()));
    }
    raw.extend_from_slice(&t.finish());
    let wire = String::from_utf8_lossy(&raw);

    // The SSE event sequence must end the message with `message_stop`; NO `message_delta` may
    // appear after it. Find the byte offsets of the last message_stop and any later message_delta.
    let stop_at = wire
        .rfind("event: message_stop")
        .or_else(|| wire.rfind("\"type\":\"message_stop\""))
        .or_else(|| wire.rfind("message_stop"))
        .expect("anthropic stream must emit a message_stop");
    let after = &wire[stop_at..];
    assert!(
        !after.contains("message_delta"),
        "no message_delta may follow message_stop on the wire; tail after stop:\n{after}"
    );
}

// MEDIUM/conformance (proto/mod.rs fan-out): DEFAULT OpenAI streaming — NO
// `stream_options.include_usage` — the finish chunk carries no usage AND there is NO trailing
// usage-only chunk. The pre-fix fan-out DEFERRED the `metadata` frame to a trailing delta that
// never arrived, so the ConverseStream ended with messageStop but NO `metadata` frame at all (a
// deterministic proxy tell + lost token accounting). `finish()` must now flush exactly one
// (zero-usage) `metadata` frame so the stream is never missing its terminal metadata.
#[test]
fn test_translate_openai_no_include_usage_egress_to_bedrock_ingress_emits_metadata() {
    let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        // Default streaming: terminal finish chunk carries NO usage, and NO trailing usage chunk.
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n",
    ] {
        raw.extend_from_slice(&t.feed(frame.as_bytes()));
    }
    // finish() must flush the deferred metadata frame.
    raw.extend_from_slice(&t.finish());

    let mut buf = raw.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(buf.is_empty(), "all frames must decode cleanly");

    // EXACTLY ONE metadata frame — present (the fix), never the pre-fix total absence.
    let metadata: Vec<&(String, Vec<u8>)> =
        frames.iter().filter(|(et, _)| et == "metadata").collect();
    assert_eq!(
        metadata.len(),
        1,
        "default OpenAI stream (no include_usage) must STILL terminate with exactly one \
             metadata frame; got {} frames: {:?}",
        metadata.len(),
        frames.iter().map(|(et, _)| et.as_str()).collect::<Vec<_>>()
    );
    // It carries zero tokens (no usage was reported) — far closer to native than no frame.
    let md: serde_json::Value =
        serde_json::from_slice(&metadata[0].1).expect("metadata payload is JSON");
    assert_eq!(md["usage"]["inputTokens"], 0);
    assert_eq!(md["usage"]["outputTokens"], 0);

    // messageStop must precede the flushed metadata (native order).
    let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
    let stop_pos = types.iter().position(|t| *t == "messageStop");
    let meta_pos = types.iter().position(|t| *t == "metadata");
    assert!(
        stop_pos.is_some() && meta_pos.is_some() && stop_pos < meta_pos,
        "messageStop must precede metadata (native order); got {types:?}"
    );
    // Exactly one messageStop.
    assert_eq!(
        frames.iter().filter(|(et, _)| et == "messageStop").count(),
        1,
        "exactly one messageStop frame"
    );
}

// A frame split across two feeds yields no output until complete, then translates.
#[test]
fn test_translate_split_frame_reassembly() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
    let (a, b) = frame.as_bytes().split_at(20);
    assert!(t.feed(a).is_empty(), "partial frame must yield no output");
    let s = String::from_utf8(t.feed(b)).unwrap();
    assert!(
        s.contains("\"content\":\"hi\""),
        "completed frame must translate to openai content; got {s}"
    );
}

// Cross-protocol tool-calling fidelity: openai tool_calls → anthropic tool_use survives, and the
// foreign `call_1` id is RESHAPED to the Anthropic-native `toolu_` form at the seam (§Finding-2),
// never leaked verbatim. (Updated from the prior verbatim-`call_1` assertion — the new contract.)
#[test]
fn test_translate_tool_call_fidelity() {
    let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
    let mut out = String::new();
    for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"loc\\\":\\\"SF\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
    assert!(
        out.contains("content_block_start"),
        "missing content_block_start; got {out}"
    );
    assert!(
        out.contains("tool_use"),
        "tool_use block type missing; got {out}"
    );
    // The tool NAME survives; the foreign `call_1` id must NOT — it is reshaped to a native
    // `toolu_…` id that decodes back to `call_1`.
    assert!(
        out.contains("get_weather"),
        "tool name must survive; got {out}"
    );
    assert!(
        !out.contains("call_1"),
        "foreign `call_1` id must NOT leak to the Anthropic client; got {out}"
    );
    // Pull the emitted tool_use id out of the content_block_start frame and confirm it is native
    // and reversible.
    let emitted = data_payloads(&out)
        .into_iter()
        .find_map(|p| {
            p.pointer("/content_block/id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .expect("a content_block_start carrying a tool_use id");
    assert!(
        emitted.starts_with("toolu_"),
        "emitted tool id must be Anthropic-native; got {emitted}"
    );
    assert_eq!(
        decode_native_tool_id("anthropic", &emitted).as_deref(),
        Some("call_1"),
        "the reshaped id must decode back to the original egress `call_1`; got {emitted}"
    );
    assert!(
        out.contains("input_json_delta"),
        "missing input_json_delta; got {out}"
    );
}

#[test]
fn test_translate_same_protocol_is_none() {
    assert!(StreamTranslate::new("openai", "openai").is_none());
    assert!(StreamTranslate::new("anthropic", "anthropic").is_none());
}

// §Finding-3 (linear SSE drain): a single `feed` carrying MANY complete SSE frames at once must
// translate ALL of them (the cursor advances frame-by-frame and reclaims the prefix in one shift —
// no per-frame `drain` re-scan, no dropped/duplicated frames, no infinite loop). Large N here would
// be quadratic under the old `drain(..end)`-per-frame reassembly; it must complete near-instantly.
#[test]
fn test_translate_many_frames_in_one_feed_is_linear_and_complete() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    const N: usize = 20_000;
    let mut blob = String::with_capacity(N * 96);
    for _ in 0..N {
        blob.push_str(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n",
            );
    }
    let start = std::time::Instant::now();
    let out = String::from_utf8(t.feed(blob.as_bytes())).expect("utf8");
    let elapsed = start.elapsed();
    // Every frame translated exactly once: N openai content deltas out.
    assert_eq!(
        out.matches("\"content\":\"x\"").count(),
        N,
        "all {N} frames must translate exactly once"
    );
    // Generous ceiling — quadratic reassembly of 20k frames would blow well past this; linear
    // completes in milliseconds. Guards against a regression to per-frame front-draining.
    assert!(
        elapsed.as_secs() < 5,
        "draining {N} frames must be linear; took {elapsed:?}"
    );
}

// §Finding-3: the same buffer split arbitrarily across many `feed` calls (frames straddling chunk
// boundaries) must reassemble identically — the `scanned`/`consumed` cursors carry across feeds.
#[test]
fn test_translate_frames_split_across_chunks_reassemble() {
    // ingress=anthropic, egress=openai → feed OpenAI SSE, expect Anthropic `text_delta` output.
    let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
    let mut blob = String::new();
    for i in 0..50 {
        blob.push_str(&format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"t{i}\"}}}}]}}\n\n"
        ));
    }
    // Feed 7 bytes at a time so terminators land mid-chunk.
    let mut out = String::new();
    let bytes = blob.as_bytes();
    let mut p = 0;
    while p < bytes.len() {
        let end = (p + 7).min(bytes.len());
        out.push_str(&String::from_utf8(t.feed(&bytes[p..end])).unwrap());
        p = end;
    }
    for i in 0..50 {
        assert!(
            out.contains(&format!("\"text\":\"t{i}\"")),
            "frame t{i} must survive chunk-boundary reassembly; got {out}"
        );
    }
}

/// Multiple `data:` lines in one SSE frame must be concatenated with `\n` (SSE spec §9.2.6),
/// not collapsed to the last line. A leading space after the colon is stripped exactly once.
#[test]
fn test_parse_sse_frame_concatenates_multiple_data_lines() {
    let frame = b"event: e\ndata: {\"a\":1,\ndata: \"b\":2}\n\n";
    let (et, data) = parse_sse_frame(frame).expect("frame has data");
    assert_eq!(et, "e");
    assert_eq!(data, "{\"a\":1,\n\"b\":2}");
    // and the joined payload is valid JSON
    let v: serde_json::Value = serde_json::from_str(&data).expect("joined data parses");
    assert_eq!(v.get("a"), Some(&serde_json::json!(1)));
    assert_eq!(v.get("b"), Some(&serde_json::json!(2)));
}

/// A frame carrying only an `event:` line (no `data:`) must return None.
#[test]
fn test_parse_sse_frame_event_only_is_none() {
    assert!(parse_sse_frame(b"event: ping\n\n").is_none());
    assert!(parse_sse_frame(b"\n\n").is_none());
}

/// A `data:` line with empty value still yields Some (caller treats empty payload as a
/// terminator/keepalive); the OpenAI `[DONE]` sentinel survives leading-space stripping.
#[test]
fn test_parse_sse_frame_done_sentinel() {
    let (et, data) = parse_sse_frame(b"data: [DONE]\n\n").expect("data line present");
    assert_eq!(et, "");
    assert_eq!(data, "[DONE]");
}

/// An upstream that splits a single JSON event across two `data:` lines must still translate
/// correctly end-to-end (the payload is rejoined before JSON parsing).
#[test]
fn test_translate_multiline_data_payload() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\ndata: \"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
    let s = String::from_utf8(t.feed(frame.as_bytes())).unwrap();
    assert!(
        s.contains("\"content\":\"hi\""),
        "multi-line data payload must reassemble and translate; got {s}"
    );
}

/// An upstream that streams bytes without ever emitting a frame terminator must not grow the
/// reassembly buffer without bound: once past the cap the stream is abandoned and the buffer
/// is released.
#[test]
fn test_feed_aborts_on_unbounded_buffer() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let chunk = vec![b'x'; 1024 * 1024]; // 1 MiB of garbage, no `\n\n`
    let mut total = 0usize;
    // Feed past MAX_BUF (16 MiB) — the +1 iteration crosses the cap and triggers the abort.
    for _ in 0..18 {
        let out = t.feed(&chunk);
        assert!(out.is_empty(), "garbage stream must produce no output");
        total += chunk.len();
        if t.aborted {
            break;
        }
        assert!(
            t.buf.len() <= StreamTranslate::MAX_BUF,
            "buffer must stay within MAX_BUF while accumulating"
        );
    }
    assert!(
        t.aborted,
        "stream must abort after exceeding MAX_BUF (fed {total} bytes)"
    );
    assert!(t.buf.is_empty(), "aborted stream must release its buffer");
    // Further feeds are no-ops, including a now-complete frame.
    assert!(
        t.feed(b"data: {\"choices\":[]}\n\n").is_empty(),
        "feeds after abort must be ignored"
    );
}

/// MEDIUM/conformance (StreamTranslate::abort / finish for bedrock ingress): when the SSE
/// reassembly buffer overflows MAX_BUF without a frame terminator on a BEDROCK-INGRESS stream, the
/// stream must NOT end with a bare TCP close. A real ConverseStream ALWAYS terminates with
/// messageStop+metadata or a modeled exception frame; a bare close with neither is structurally
/// impossible and a protocol-indistinguishability tell that leaves an AWS SDK's
/// exception/metadata callbacks in an ambiguous state. `finish()` must emit a modeled
/// `InternalServerException` frame (drain_frames surfaces it lowercased as `internalServerException`).
#[test]
fn test_bedrock_ingress_overflow_abort_emits_exception_frame() {
    // openai egress → bedrock ingress: ingress_eventstream == true.
    let mut t = StreamTranslate::new("bedrock", "openai").expect("translator");
    assert!(t.ingress_eventstream, "bedrock ingress must be eventstream");
    let chunk = vec![b'x'; 1024 * 1024]; // garbage, no `\n\n`
    for _ in 0..18 {
        let _ = t.feed(&chunk);
        if t.aborted {
            break;
        }
    }
    assert!(t.aborted, "stream must abort after exceeding MAX_BUF");
    // finish() on the aborted bedrock-ingress stream must emit a well-formed terminal exception
    // frame, not an empty/bare close.
    let mut tail = t.finish();
    assert!(
        !tail.is_empty(),
        "aborted bedrock-ingress finish must emit a terminal exception frame, not a bare close"
    );
    let frames = crate::eventstream::drain_frames(&mut tail);
    let names: Vec<&str> = frames.iter().map(|(ty, _)| ty.as_str()).collect();
    assert_eq!(
            names.as_slice(),
            ["internalServerException"],
            "aborted bedrock-ingress stream must terminate with a single modeled exception frame; got {names:?}"
        );

    // A NON-bedrock ingress (SSE client) aborted the same way must NOT get a binary exception
    // frame (its wire is SSE) — but it must STILL signal the truncation with the ingress
    // protocol's NATIVE streaming error frame, not a silent bare close (see below).
}

/// Regression: an SSE-INGRESS stream aborted by reassembly-buffer overflow must NOT
/// end with a silently-truncated body. Before this fix `finish()` returned an empty tail for SSE
/// ingress (only bedrock ingress emitted a terminal frame), so an SSE/native SDK client saw a
/// short stream indistinguishable from a successful completion. `finish()` must now emit the
/// ingress protocol's NATIVE streaming error frame (mirroring `proxy::mid_stream_error_bytes`),
/// and OpenAI ingress must still append `data: [DONE]`.
#[test]
fn test_sse_ingress_overflow_abort_emits_native_error_frame() {
    let chunk = vec![b'x'; 1024 * 1024]; // garbage, no `\n\n`

    // Anthropic ingress: the native streaming error is `event: error` with a
    // `{"type":"error","error":{...}}` payload — NOT a binary frame, NOT an empty tail.
    let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
    assert!(
        !t.ingress_eventstream,
        "anthropic ingress must be SSE, not eventstream"
    );
    for _ in 0..18 {
        let _ = t.feed(&chunk);
        if t.aborted {
            break;
        }
    }
    assert!(
        t.aborted,
        "anthropic-ingress stream must abort after MAX_BUF"
    );
    let tail = String::from_utf8(t.finish()).expect("SSE error tail is UTF-8");
    assert!(
        !tail.is_empty(),
        "aborted SSE-ingress finish must emit a native error frame, not a silent bare close"
    );
    assert!(
        tail.starts_with("event: error\n"),
        "anthropic-ingress abort must emit a native `event: error` frame; got {tail:?}"
    );
    // The `data:` payload must be the Anthropic stream error shape `{"type":"error",...}`.
    let data_line = tail
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .map(|s| s.trim())
        .expect("error frame carries a data: line");
    let v: serde_json::Value = serde_json::from_str(data_line).expect("error frame data: is JSON");
    assert_eq!(
        v.get("type").and_then(|x| x.as_str()),
        Some("error"),
        "anthropic stream error payload is `type:error`; got {v}"
    );
    assert!(
        v.get("error").and_then(|e| e.get("message")).is_some(),
        "anthropic stream error carries an error.message; got {v}"
    );

    // OpenAI ingress: the native streaming error is a BARE `data:` error envelope, and the stream
    // must still terminate with `data: [DONE]\n\n` after it (a genuine OpenAI stream's terminator).
    let mut t2 = StreamTranslate::new("openai", "anthropic").expect("translator");
    for _ in 0..18 {
        let _ = t2.feed(&chunk);
        if t2.aborted {
            break;
        }
    }
    assert!(t2.aborted);
    let tail2 = String::from_utf8(t2.finish()).expect("SSE error tail is UTF-8");
    assert!(
        tail2.contains("\"error\""),
        "openai-ingress abort must emit a native bare `data:` error envelope; got {tail2:?}"
    );
    assert!(
        tail2.trim_end().ends_with("data: [DONE]"),
        "openai-ingress aborted stream must still terminate with `data: [DONE]`; got {tail2:?}"
    );
    // The error frame must precede the [DONE] terminator (in-band error, then terminator).
    let err_pos = tail2.find("\"error\"").expect("error envelope present");
    let done_pos = tail2.find("data: [DONE]").expect("[DONE] present");
    assert!(
        err_pos < done_pos,
        "the error frame must precede [DONE]; got {tail2:?}"
    );
}

/// The scanned-offset optimization must not break terminator detection when `\n\n` straddles a
/// chunk boundary (one `\n` at the end of chunk A, the next at the start of chunk B).
#[test]
fn test_feed_terminator_straddles_chunk_boundary() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n";
    // First chunk ends right after the first '\n'; the second '\n' opens the next chunk.
    assert!(t.feed(frame.as_bytes()).is_empty(), "no terminator yet");
    let s = String::from_utf8(t.feed(b"\n")).unwrap();
    assert!(
        s.contains("\"content\":\"hi\""),
        "terminator split across chunks must still complete the frame; got {s}"
    );
}

/// Many tiny chunks comprising a single large frame must reassemble and translate exactly once.
#[test]
fn test_feed_large_frame_many_chunks() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
    let big = "x".repeat(200_000);
    let frame = format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{big}\"}}}}\n\n"
        );
    let bytes = frame.as_bytes();
    let mut out = Vec::new();
    for chunk in bytes.chunks(64) {
        out.extend(t.feed(chunk));
    }
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains(&big),
        "large frame split across many chunks must reassemble"
    );
}

// ============================================================
// Whole-response (non-streaming) R/W tests
// ============================================================

#[test]
fn test_anthropic_read_response_decode() {
    // Anthropic message → IrResponse with exact fields
    let data = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 3,
            "cache_creation_input_tokens": null,
            "cache_read_input_tokens": null
        }
    });

    let reader = AnthropicReader;
    let resp = reader.read_response(&data).expect("should parse");

    assert_eq!(resp.role, crate::ir::IrRole::Assistant);
    assert_eq!(resp.content.len(), 1);
    if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
        assert_eq!(text, "hi");
    } else {
        panic!("expected Text block");
    }
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::EndTurn));
    assert_eq!(resp.usage.input_tokens, 5);
}

#[test]
fn test_openai_read_response_decode() {
    // OpenAI chat.completion → IrResponse with exact fields and stop_reason mapping
    let data = serde_json::json!({
        "choices": [{
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3
        }
    });

    let reader = OpenAiReader;
    let resp = reader.read_response(&data).expect("should parse");

    assert_eq!(resp.role, crate::ir::IrRole::Assistant);
    assert_eq!(resp.content.len(), 1);
    if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
        assert_eq!(text, "hi");
    } else {
        panic!("expected Text block");
    }
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::EndTurn)); // mapped from "stop"
    assert_eq!(resp.usage.input_tokens, 5);
}

#[test]
fn test_cross_protocol_openai_to_anthropic() {
    // OpenAI → IR → Anthropic: verify output is Anthropic-shaped
    let openai_data = serde_json::json!({
        "choices": [{
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3
        }
    });

    let ir_resp = OpenAiReader
        .read_response(&openai_data)
        .expect("OpenAI read");
    let anthropic_json = AnthropicWriter.write_response(&ir_resp);

    // Assert Anthropic-shaped output
    assert_eq!(
        anthropic_json.get("type").and_then(|v| v.as_str()),
        Some("message")
    );
    if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
        assert!(!content_arr.is_empty());
        let first_block = &content_arr[0];
        assert_eq!(
            first_block.get("type").and_then(|v| v.as_str()),
            Some("text")
        );
        assert_eq!(first_block.get("text").and_then(|v| v.as_str()), Some("hi"));
    } else {
        panic!("missing content array");
    }
    assert_eq!(
        anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
        Some("end_turn")
    );
}

#[test]
fn test_cross_protocol_anthropic_to_openai() {
    // Anthropic → IR → OpenAI: verify output is OpenAI-shaped
    let anthropic_data = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 3,
            "cache_creation_input_tokens": null,
            "cache_read_input_tokens": null
        }
    });

    let ir_resp = AnthropicReader
        .read_response(&anthropic_data)
        .expect("Anthropic read");
    let openai_json = OpenAiWriter.write_response(&ir_resp);

    // Assert OpenAI-shaped output
    assert_eq!(
        openai_json.get("object").and_then(|v| v.as_str()),
        Some("chat.completion")
    );
    if let Some(choices_arr) = openai_json.get("choices").and_then(|c| c.as_array()) {
        assert!(!choices_arr.is_empty());
        let choice = &choices_arr[0];
        if let Some(msg) = choice.get("message") {
            assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
            assert_eq!(msg.get("content").and_then(|v| v.as_str()), Some("hi"));
        } else {
            panic!("missing message");
        }
        assert_eq!(
            choice.get("finish_reason").and_then(|v| v.as_str()),
            Some("stop")
        );
    } else {
        panic!("missing choices array");
    }
}

#[test]
fn test_cross_protocol_tool_use_response() {
    // OpenAI tool_calls response → IR → Anthropic: verify tool_use block round-trips
    let openai_data = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "f", "arguments": "{\"x\":1}"}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3
        }
    });

    let ir_resp = OpenAiReader
        .read_response(&openai_data)
        .expect("OpenAI read");

    // Verify IR has ToolUse block
    assert_eq!(ir_resp.content.len(), 1);
    if let crate::ir::IrBlock::ToolUse {
        id, name, input, ..
    } = &ir_resp.content[0]
    {
        assert_eq!(id, "call_1");
        assert_eq!(name, "f");
        match input {
            serde_json::Value::Object(obj) => {
                assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
            }
            _ => panic!("input should be Object"),
        }
    } else {
        panic!("expected ToolUse block");
    }

    let anthropic_json = AnthropicWriter.write_response(&ir_resp);

    // Assert Anthropic output has tool_use block with correct fields
    if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
        assert!(!content_arr.is_empty());
        let first_block = &content_arr[0];
        assert_eq!(
            first_block.get("type").and_then(|v| v.as_str()),
            Some("tool_use")
        );
        assert_eq!(
            first_block.get("id").and_then(|v| v.as_str()),
            Some("call_1")
        );
        assert_eq!(first_block.get("name").and_then(|v| v.as_str()), Some("f"));
        // input should be an object with x: 1
        if let Some(input_val) = first_block.get("input") {
            match input_val {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("missing input");
        }
    } else {
        panic!("missing content array");
    }

    // stop_reason should be "tool_use" (passthrough from Anthropic canonical form)
    assert_eq!(
        anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
        Some("tool_use")
    );
}

// ── §Finding-2: cross-protocol tool-id native remap at the seam ──────────────────────────────

#[test]
fn test_tool_id_remap_reshapes_to_ingress_native_prefix() {
    // An OpenAI backend's `call_…` reshaped for an Anthropic client must carry the native
    // `toolu_` prefix and the busbar marker — never the foreign `call_` shape.
    let mut remap = ToolIdRemap::default();
    let native = remap.native_for("anthropic", "call_abc123");
    assert!(
        native.starts_with("toolu_"),
        "anthropic-ingress id must carry the native `toolu_` prefix, got {native}"
    );
    assert!(
        !native.contains("call_"),
        "the foreign `call_` shape must NOT survive into the client id, got {native}"
    );
    // Bedrock `tooluse_` and OpenAI `call_` prefixes for the other ingress shapes.
    assert!(ToolIdRemap::default()
        .native_for("bedrock", "call_x")
        .starts_with("tooluse_"));
    assert!(ToolIdRemap::default()
        .native_for("openai", "toolu_y")
        .starts_with("call_"));
    // Gemini carries no tool id on the wire → remap is a no-op (id returned unchanged).
    assert_eq!(
        ToolIdRemap::default().native_for("gemini", "call_z"),
        "call_z"
    );
}

#[test]
fn test_tool_id_remap_is_a_stable_reversible_bijection() {
    // Forward: the SAME egress id maps to the SAME native id within a request (stable map), and
    // decoding the native id recovers the ORIGINAL egress id (so a later `tool_result` reference
    // stays consistent across rounds).
    let mut remap = ToolIdRemap::default();
    let a1 = remap.native_for("anthropic", "call_one");
    let a2 = remap.native_for("anthropic", "call_one");
    let b = remap.native_for("anthropic", "call_two");
    assert_eq!(a1, a2, "a repeated egress id must map stably");
    assert_ne!(a1, b, "distinct egress ids must map to distinct native ids");
    assert_eq!(
        decode_native_tool_id("anthropic", &a1).as_deref(),
        Some("call_one")
    );
    assert_eq!(
        decode_native_tool_id("anthropic", &b).as_deref(),
        Some("call_two")
    );

    // A client-authored id (no busbar marker) is NOT a busbar id → decode returns None so the
    // request path passes it through verbatim (must not mangle a genuine native tool id).
    assert_eq!(
        decode_native_tool_id("anthropic", "toolu_01RealClientId"),
        None
    );
    // The colliding-shape guard: a CLIENT-authored id matching `<foreign-prefix>bb1<hex>` or the
    // bare empty-prefix `bb1<hex>` must NOT be decoded when the ingress is not that foreign
    // protocol. `call_bb1<hex>` looks busbar-shaped under the OpenAI prefix, but for an Anthropic
    // ingress the only valid prefix is `toolu_`, so it stays verbatim (no silent corruption).
    let foreign_shaped = format!("call_{TOOL_ID_REMAP_MARKER}{}", hex::encode("x"));
    assert_eq!(
        decode_native_tool_id("anthropic", &foreign_shaped),
        None,
        "a foreign-prefix busbar-shaped id must not be decoded on a non-matching ingress"
    );
    let bare_shaped = format!("{TOOL_ID_REMAP_MARKER}{}", hex::encode("y"));
    assert_eq!(
        decode_native_tool_id("anthropic", &bare_shaped),
        None,
        "a bare `bb1<hex>` (empty-prefix) id must not be decoded on a non-Cohere ingress"
    );
    // A marker-only id (`<prefix>bb1` with an EMPTY hex tail) is client-authored, not busbar:
    // `native_for` always hex-encodes the egress id, so it can never emit an empty tail. Decoding
    // it would yield `Some("")` and break the exact-inverse round-trip, so it must pass through
    // verbatim (None). Covers both the ingress's own prefix and the bare empty-prefix form.
    let marker_only = format!("toolu_{TOOL_ID_REMAP_MARKER}");
    assert_eq!(
        decode_native_tool_id("anthropic", &marker_only),
        None,
        "a marker-only id (empty hex tail) must not decode to an empty string"
    );
    assert_eq!(
        decode_native_tool_id("anthropic", TOOL_ID_REMAP_MARKER),
        None,
        "a bare marker with no prefix and empty hex tail must pass through verbatim"
    );
    // Sanity: the matching ingress DOES decode its own prefix.
    assert_eq!(
        decode_native_tool_id("openai", &foreign_shaped).as_deref(),
        Some("x")
    );
}

#[test]
fn test_tool_id_remap_response_round_trip_through_seam() {
    // Response seam (egress → ingress): an OpenAI `tool_use` reshaped to the Anthropic-native shape.
    let mut ir = OpenAiReader
        .read_response(&serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_seam",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{\"x\":1}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3}
        }))
        .expect("OpenAI read");
    ToolIdRemap::default().remap_response("anthropic", &mut ir);
    let client_id = match &ir.content[0] {
        crate::ir::IrBlock::ToolUse { id, .. } => id.clone(),
        other => panic!("expected ToolUse, got {other:?}"),
    };
    assert!(
        client_id.starts_with("toolu_") && !client_id.contains("call_seam"),
        "client must see a native id, not the foreign `call_seam`, got {client_id}"
    );

    // Request seam (ingress → egress): the Anthropic client echoes that native id back inside a
    // `tool_result`; the request path must decode it to the ORIGINAL `call_seam` for the backend.
    let mut messages = vec![crate::ir::IrMessage {
        role: crate::ir::IrRole::Tool,
        content: vec![crate::ir::IrBlock::ToolResult {
            tool_use_id: client_id,
            content: vec![],
            is_error: false,
            cache_control: None,
        }],
    }];
    decode_request_tool_ids("anthropic", &mut messages);
    match &messages[0].content[0] {
        crate::ir::IrBlock::ToolResult { tool_use_id, .. } => {
            assert_eq!(
                tool_use_id, "call_seam",
                "the egress backend must see the id it originally issued"
            );
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
}

#[test]
fn test_tool_id_remap_event_reshapes_block_start() {
    // Streaming seam: a `BlockStart{ToolUse}` id is reshaped to the ingress-native form in place.
    let mut ev = IrStreamEvent::BlockStart {
        index: 0,
        block: IrBlockMeta::ToolUse {
            id: "call_stream".to_string(),
            name: "f".to_string(),
        },
    };
    ToolIdRemap::default().remap_event("anthropic", &mut ev);
    match ev {
        IrStreamEvent::BlockStart {
            block: IrBlockMeta::ToolUse { id, .. },
            ..
        } => {
            assert!(id.starts_with("toolu_") && id != "call_stream");
            assert_eq!(
                decode_native_tool_id("anthropic", &id).as_deref(),
                Some("call_stream")
            );
        }
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    }
}

#[test]
fn test_same_protocol_roundtrip_idempotence() {
    // Anthropic read → write → read yields equal IrResponse.
    // `id` is seeded because a native Anthropic Message always carries one and the writer
    // (correctly) synthesizes an `id` when absent — so idempotence is only meaningful with a
    // real id present (an id-less fixture is not a shape a native client ever sends).
    let original_data = serde_json::json!({
        "id": "msg_01TestRoundtripIdempotence",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "hello"},
            {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"loc": "SF"}}
        ],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 10,
            "output_tokens": 20,
            "cache_creation_input_tokens": null,
            "cache_read_input_tokens": null
        }
    });

    let reader = AnthropicReader;
    let writer = AnthropicWriter;

    // First read
    let ir1 = reader.read_response(&original_data).expect("first read");

    // Write to JSON
    let written_json = writer.write_response(&ir1);

    // Read again
    let ir2 = reader.read_response(&written_json).expect("second read");

    // Decode IR must be identical (ground truth for anti-fab)
    assert_eq!(ir1, ir2, "decoded IR must be identical after round-trip");
}

// Gemini decode test - systemInstruction + contents with mixed blocks + tools
#[test]
fn test_gemini_decode() {
    let j = serde_json::json!({
        "systemInstruction": {
            "parts": [{"text": "You are a helpful assistant."}]
        },
        "contents": [
            {"role": "user", "parts": [
                {"text": "What is the weather?"},
                {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"}}
            ]},
            {"role": "model", "parts": [
                {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
            ]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "get_weather", "response": {"temperature": 72, "units": "F"}}}
            ]}
        ],
        "tools": [{
            "functionDeclarations": [
                {
                    "name": "get_weather",
                    "description": "Get weather for a location",
                    "parameters": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            ]
        }],
        "generationConfig": {
            "maxOutputTokens": 4096,
            "temperature": 0.7
        },
        "stream": true
    });

    let reader = GeminiReader;
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");

    // Assert system Text block
    assert_eq!(ir.system.len(), 1);
    if let crate::ir::IrBlock::Text {
        text,
        cache_control: _,
        citations: _,
    } = &ir.system[0]
    {
        assert_eq!(text, "You are a helpful assistant.");
    } else {
        panic!("expected Text block in system");
    }

    // Assert messages roles and content
    assert_eq!(ir.messages.len(), 3);

    // First message: User with text + image
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    assert_eq!(ir.messages[0].content.len(), 2);
    if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
        assert_eq!(text, "What is the weather?");
    } else {
        panic!("expected Text block in first message");
    }
    if let crate::ir::IrBlock::Image {
        source: crate::ir::IrImageSource::Base64 { media_type, data },
        ..
    } = &ir.messages[0].content[1]
    {
        assert_eq!(media_type, "image/png");
        assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
    } else {
        panic!("expected Image block in first message");
    }

    // Second message: Assistant with functionCall (ToolUse)
    assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
    assert_eq!(ir.messages[1].content.len(), 1);
    if let crate::ir::IrBlock::ToolUse {
        id: _, name, input, ..
    } = &ir.messages[1].content[0]
    {
        assert_eq!(name, "get_weather");
        assert_eq!(
            input.get("location").and_then(|v| v.as_str()),
            Some("San Francisco")
        );
    } else {
        panic!("expected ToolUse block in second message");
    }

    // Third message: User with functionResponse (ToolResult)
    assert_eq!(ir.messages[2].role, crate::ir::IrRole::User);
    assert_eq!(ir.messages[2].content.len(), 1);
    if let crate::ir::IrBlock::ToolResult {
        tool_use_id,
        content,
        is_error,
        ..
    } = &ir.messages[2].content[0]
    {
        assert_eq!(tool_use_id, "get_weather");
        assert!(!is_error);
        assert_eq!(content.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
            // Response serialized as JSON string
            assert!(text.contains("72") || text.contains("temperature"));
        } else {
            panic!("expected Text block in tool result");
        }
    } else {
        panic!("expected ToolResult block in third message");
    }

    // Assert tools
    assert_eq!(ir.tools.len(), 1);
    let crate::ir::IrTool {
        name,
        description,
        input_schema,
        ..
    } = &ir.tools[0];
    {
        assert_eq!(name, "get_weather");
        assert_eq!(description.as_deref(), Some("Get weather for a location"));
        assert!(!input_schema.is_null());
    }

    // Assert generationConfig fields
    assert_eq!(ir.max_tokens, Some(4096));
    assert_eq!(ir.temperature, Some(0.7));
    assert!(ir.stream);
}

// Gemini round-trip test - write_request(read_request(j)) == j for canonical fixture
#[test]
fn test_gemini_roundtrip_identity() {
    let j = serde_json::json!({
        "model": "gemini-pro",
        "systemInstruction": {"parts": [{"text": "You are a helpful assistant."}]},
        "contents": [
            {"role": "user", "parts": [{"text": "Hello"}]},
            {"role": "model", "parts": [{"text": "Hi there!"}]}
        ],
        "generationConfig": {"maxOutputTokens": 100, "temperature": 0.5},
        "stream": false
    });

    let reader = GeminiReader;
    let writer = GeminiWriter;

    // Canonical form: minimal fixture that round-trips exactly
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    let roundtrip = writer.write_request(&ir);

    // Compare as Value - exact identity on representable subset
    assert_eq!(roundtrip, j, "round-trip must be byte-identical");
}

// Protocol::gemini resolves correctly with working reader/writer
#[test]
fn test_gemini_protocol_resolves() {
    let proto = Protocol::gemini();
    assert_eq!(proto.name(), "gemini");

    let reader = proto.reader();
    let writer = proto.writer();

    // Verify reader methods work
    let j = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "test"}]}]
    });
    let ir = reader.read_request(&j).expect("reader should parse");
    assert_eq!(ir.messages.len(), 1);

    // Verify writer methods work
    let output = writer.write_request(&ir);
    assert!(output.as_object().unwrap().contains_key("contents"));

    // Verify other protocol methods.: the real per-request path embeds the model via
    // upstream_path_for(); upstream_path() is just the model-independent base.
    assert_eq!(writer.upstream_path(), "/v1beta/models");
    assert_eq!(
        writer.upstream_path_for("gemini-pro"),
        "/v1beta/models/gemini-pro:generateContent"
    );
    let headers = writer.auth_headers("test-key");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "x-goog-api-key");

    // Verify error handling methods
    let status_code = StatusCode::TOO_MANY_REQUESTS;
    let signal = reader.classify(status_code, b"{}");
    assert_eq!(signal.class, StatusClass::RateLimit);

    let raw_error = reader.extract_error(status_code, b"{}");
    assert_eq!(raw_error.http_status, 429);
}

#[test]
fn test_bedrock_and_responses_register() {
    // Both 0.10 protocols resolve via the registry and the ingress resolver.
    let registry = ProtocolRegistry::with_builtins();
    assert!(registry.get("bedrock").is_some(), "bedrock in registry");
    assert!(registry.get("responses").is_some(), "responses in registry");
    assert!(
        protocol_for("bedrock").is_some(),
        "bedrock resolves for ingress"
    );
    assert!(
        protocol_for("responses").is_some(),
        "responses resolves for ingress"
    );

    // Responses: bearer auth + the /v1/responses egress path (fully usable).
    let responses = Protocol::responses();
    assert_eq!(responses.name(), "responses");
    assert_eq!(responses.writer().upstream_path(), "/v1/responses");
    let headers = responses.writer().auth_headers("sk-test");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "authorization");
    assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");

    // Gemini selects the streaming vs non-streaming endpoint by request intent.
    let gemini = Protocol::gemini();
    assert_eq!(
        gemini
            .writer()
            .upstream_path_for_stream("gemini-pro", false),
        "/v1beta/models/gemini-pro:generateContent"
    );
    assert_eq!(
        gemini.writer().upstream_path_for_stream("gemini-pro", true),
        "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse"
    );
    // Non-Gemini protocols ignore the stream flag (single path).
    assert_eq!(
        Protocol::openai()
            .writer()
            .upstream_path_for_stream("x", true),
        Protocol::openai().writer().upstream_path_for("x")
    );

    // Bedrock: model-in-path Converse URL + native SigV4 auth + ConverseStream
    // event-stream decoding. Fully first-class.
    let bedrock = Protocol::bedrock();
    assert_eq!(bedrock.name(), "bedrock");
    assert_eq!(
        bedrock.writer().upstream_path_for("anthropic.claude-3"),
        "/model/anthropic.claude-3/converse"
    );
}
