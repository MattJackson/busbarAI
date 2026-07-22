use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn stop_reason_reverse_never_leaks_foreign_tokens() {
    use crate::ir::IrStopReason as S;
    assert_eq!(stop_reason_reverse(S::EndTurn), "end_turn");
    assert_eq!(stop_reason_reverse(S::ToolUse), "tool_use");
    assert_eq!(stop_reason_reverse(S::Safety), "content_filtered");
    // Foreign / off-enum reasons degrade to end_turn rather than emit an off-spec Converse
    // `stopReason` a strict client rejects. (A Bedrock `guardrail_intervened` read folds to
    // `Safety`, which writes back as `content_filtered`.)
    assert_eq!(read_bedrock_stop_reason_guardrail(), S::Safety);
    assert_eq!(stop_reason_reverse(S::Refusal), "end_turn");
    assert_eq!(stop_reason_reverse(S::Error), "end_turn");
    assert_eq!(stop_reason_reverse(S::Other), "end_turn");
}

fn read_bedrock_stop_reason_guardrail() -> crate::ir::IrStopReason {
    stop_reason_map("guardrail_intervened")
}

// Cross-protocol response-id synthesis is NOT wired into any production path (Bedrock's own
// body has no id field, and the inverse direction is the consuming ingress writer's job — see
// `write_response`). The helper trio below was previously shipped in the production binary under
// `#[cfg_attr(not(test), allow(dead_code))]`; it is now confined to the test module so 1.0 does
// not carry dead production scaffolding. If/when the cross-protocol id-population seam lands, the
// trio moves back into production scope (and loses this test-only home).

/// Monotonic per-process counter so two ids minted in the same wall-clock second still differ.
static SYNTH_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Current unix time in whole seconds; a pre-epoch clock degrades to 0 rather than panicking.
fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a syntactically-plausible, collision-resistant `<hex16>-<hex16>` token from
/// (unix seconds + a monotonic counter) — no UUID crate, no panic.
fn synth_response_id() -> String {
    let n = SYNTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}-{:016x}", unix_now_secs(), n)
}

#[test]
fn test_bedrock_sigv4_sign_request_structure() {
    // SigV4 header assembly + scope/region derivation. (The signing crypto itself is
    // verified against AWS's published vector in sigv4::tests.)
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        canonical_uri: crate::sigv4::uri_encode_path("/model/anthropic.claude:0/converse"),
        body: br#"{"messages":[]}"#,
        timestamp_epoch: 1_440_938_160, // 20150830T123600Z
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKIDEXAMPLE:SECRETKEY", &ctx);

    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap().to_string())
    };
    let auth = get("authorization").expect("authorization header");
    assert!(
        auth.starts_with(
            // golden wire-contract literal (kept bare on purpose)
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, "
        ),
        "scope/region derived from host; got: {auth}"
    );
    // golden wire-contract literal (kept bare on purpose)
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
    assert!(auth.contains("Signature="));
    assert_eq!(get("x-amz-date").as_deref(), Some("20150830T123600Z")); // golden wire-contract literal (kept bare on purpose)
    assert!(get("x-amz-content-sha256").is_some()); // golden wire-contract literal (kept bare on purpose)
                                                    // No session token configured → no security-token header.
    assert!(get("x-amz-security-token").is_none()); // golden wire-contract literal (kept bare on purpose)
}

#[test]
fn test_bedrock_sigv4_session_token() {
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime.eu-west-1.amazonaws.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET:SESSIONTOKEN", &ctx);
    let tok = headers
        .iter()
        .find(|(k, _)| k.as_str() == "x-amz-security-token") // golden wire-contract literal (kept bare on purpose)
        .map(|(_, v)| v.to_str().unwrap().to_string());
    assert_eq!(tok.as_deref(), Some("SESSIONTOKEN"));
    // region parsed from the eu-west-1 host + token in the signed set.
    let auth = headers
        .iter()
        .find(|(k, _)| k.as_str() == "authorization")
        .map(|(_, v)| v.to_str().unwrap().to_string())
        .unwrap();
    assert!(auth.contains("/eu-west-1/bedrock/aws4_request")); // golden wire-contract literal (kept bare on purpose)
    assert!(auth.contains("x-amz-security-token")); // golden wire-contract literal (kept bare on purpose)
}

#[test]
fn test_bedrock_sigv4_misconfigured_key_no_signature() {
    // A key without ACCESS:SECRET shape yields no headers (AWS will 403 → surfaced as auth).
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    assert!(crate::proto::bedrock::sigv4_sign_headers("not-a-valid-key", &ctx).is_empty());
}

fn bedrock_rich_fixture() -> serde_json::Value {
    serde_json::json!({
        "system": [{"text": "You are a helpful assistant."}],
        "messages": [
            {"role": "user", "content": [{"text": "What is the weather in San Francisco?"}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tool_123", "name": "get_weather", "input": {"city": "San Francisco"}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "tool_123", "content": [{"text": "Sunny, 72°F"}], "status": "success"}}]}
        ],
        "inferenceConfig": {"maxTokens": 1024, "temperature": 0.7},
        "toolConfig": {
            "tools": [{
                "toolSpec": {
                    "name": "get_weather",
                    "description": "Get weather for a city",
                    "inputSchema": {"json": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}
                }
            }]
        },
        "top_p": 0.95
    })
}

#[test]
fn test_write_request() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![crate::ir::IrBlock::Text {
            text: "You are a helpful assistant.".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "What is the weather in San Francisco?".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "tool_123".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "San Francisco"}),
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "tool_123".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Sunny, 72°F".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
        ],
        tools: vec![crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: Some("Get weather for a city".to_string()),
            input_schema: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}),
            cache_control: None,
        }],
        max_tokens: Some(1024),
        temperature: Some(0.7_f64),
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };

    let writer = BedrockWriter;
    let json = writer.write_request(&ir);

    assert_eq!(
        json.get("system")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str()),
        Some("You are a helpful assistant.")
    );
    assert_eq!(
        json.get("messages")
            .and_then(|m| m.as_array())
            .and_then(|a| a.first())
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str()),
        Some("What is the weather in San Francisco?")
    );
    assert_eq!(
        json.get("messages")
            .and_then(|m| m.as_array())
            .and_then(|a| a.get(1))
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("toolUse"))
            .and_then(|tu| tu.get("toolUseId"))
            .and_then(|id| id.as_str()),
        Some("tool_123")
    );
    assert_eq!(
        json.get("messages")
            .and_then(|m| m.as_array())
            .and_then(|a| a.get(1))
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("toolUse"))
            .and_then(|tu| tu.get("name"))
            .and_then(|n| n.as_str()),
        Some("get_weather")
    );
    assert_eq!(
        json.get("messages")
            .and_then(|m| m.as_array())
            .and_then(|a| a.get(1))
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("toolUse"))
            .and_then(|tu| tu.get("input"))
            .and_then(|i| i.get("city"))
            .and_then(|c| c.as_str()),
        Some("San Francisco")
    );
    assert_eq!(
        json.get("messages")
            .and_then(|m| m.as_array())
            .and_then(|a| a.get(2))
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("toolResult"))
            .and_then(|tr| tr.get("status"))
            .and_then(|s| s.as_str()),
        Some("success")
    );
    assert_eq!(
        json.get("inferenceConfig")
            .and_then(|ic| ic.get("maxTokens"))
            .and_then(|m| m.as_u64()),
        Some(1024)
    );
    assert_eq!(
        json.get("inferenceConfig")
            .and_then(|ic| ic.get("temperature"))
            .and_then(|t| t.as_f64()),
        Some(0.7)
    );
    assert_eq!(
        json.get("toolConfig")
            .and_then(|tc| tc.get("tools"))
            .and_then(|ts| ts.as_array())
            .and_then(|arr| arr.first())
            .and_then(|t| t.get("toolSpec"))
            .and_then(|spec| spec.get("name"))
            .and_then(|n| n.as_str()),
        Some("get_weather")
    );
}

#[test]
fn test_read_request() {
    let reader = BedrockReader;
    let j = bedrock_rich_fixture();
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");

    assert!(!ir.system.is_empty());
    if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
        assert_eq!(text, "You are a helpful assistant.");
    } else {
        panic!("system[0] should be Text block");
    }

    assert_eq!(ir.messages.len(), 3);

    if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
        assert_eq!(text, "What is the weather in San Francisco?");
    } else {
        panic!("messages[0].content[0] should be Text block");
    }

    if let crate::ir::IrBlock::ToolUse {
        id, name, input, ..
    } = &ir.messages[1].content[0]
    {
        assert_eq!(id, "tool_123");
        assert_eq!(name, "get_weather");
        match input {
            serde_json::Value::Object(obj) => {
                assert_eq!(obj.get("city"), Some(&serde_json::json!("San Francisco")));
            }
            _ => panic!("input should be Object"),
        }
    } else {
        panic!("messages[1].content[0] should be ToolUse block");
    }

    if let crate::ir::IrBlock::ToolResult {
        tool_use_id,
        content,
        is_error,
        ..
    } = &ir.messages[2].content[0]
    {
        assert_eq!(tool_use_id, "tool_123");
        assert!(!is_error);
        if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
            assert_eq!(text, "Sunny, 72°F");
        } else {
            panic!("toolResult content[0] should be Text block");
        }
    } else {
        panic!("messages[2].content[0] should be ToolResult block");
    }

    assert_eq!(ir.max_tokens, Some(1024));
    assert_eq!(ir.temperature, Some(0.7_f64));
    assert_eq!(ir.tools.len(), 1);
    let crate::ir::IrTool {
        ref name,
        ref description,
        ..
    } = ir.tools[0];
    assert_eq!(name, "get_weather");
    assert_eq!(description.as_deref(), Some("Get weather for a city"));
}

#[test]
fn test_roundtrip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;

    // Same-protocol passthrough fidelity is a WIRE->IR->WIRE byte-identity guarantee: a native
    // Converse body read into the IR and written back must reproduce the original body exactly.
    // (Note: an IR->WIRE->IR round-trip is intentionally NOT idempotent for the typed
    // `inferenceConfig` sub-fields — the reader now captures the whole raw `inferenceConfig` into
    // `extra` so unmodeled sub-fields survive passthrough (finding-2 fix), so reading a written
    // body re-populates `extra.inferenceConfig`. The contract that matters is the wire round-trip
    // below.)
    let wire = serde_json::json!({
        "system": [{"text": "You are helpful."}],
        "messages": [{"role": "user", "content": [{"text": "Hello!"}]}],
        "inferenceConfig": {"maxTokens": 512, "temperature": 0.7}
    });

    let ir = reader
        .read_request(&wire)
        .expect("read round-trip should succeed");
    let wire_after = writer.write_request(&ir);

    assert_eq!(
        wire, wire_after,
        "same-protocol wire round-trip must be byte-identical"
    );
}

#[test]
fn test_temperature_fidelity() {
    let j = serde_json::json!({"inferenceConfig": {"temperature": 0.7}, "messages": [{"role": "user", "content": [{"text": "hi"}]}]});
    let reader = BedrockReader;
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    assert_eq!(ir.temperature, Some(0.7_f64));
}

#[test]
fn test_read_response_decode() {
    let j = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "Let me check the weather for you."},
                    {"toolUse": {"toolUseId": "tu_1", "name": "get_weather", "input": {"city": "SF"}}}
                ]
            }
        },
        "stopReason": "tool_use",
        "usage": {
            "inputTokens": 42,
            "outputTokens": 15,
            "totalTokens": 57
        }
    });

    let reader = BedrockReader;
    let resp = reader
        .read_response(&j)
        .expect("read_response should succeed");

    assert_eq!(resp.role, crate::ir::IrRole::Assistant);
    assert_eq!(resp.content.len(), 2);

    if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
        assert_eq!(text, "Let me check the weather for you.");
    } else {
        panic!("content[0] should be Text block");
    }

    if let crate::ir::IrBlock::ToolUse {
        id, name, input, ..
    } = &resp.content[1]
    {
        assert_eq!(id, "tu_1");
        assert_eq!(name, "get_weather");
        match input {
            serde_json::Value::Object(obj) => {
                assert_eq!(obj.get("city"), Some(&serde_json::json!("SF")));
            }
            _ => panic!("input should be Object"),
        }
    } else {
        panic!("content[1] should be ToolUse block");
    }

    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
    assert_eq!(resp.usage.input_tokens, 42);
    assert_eq!(resp.usage.output_tokens, 15);
}

#[test]
fn test_read_write_response_roundtrip() {
    let j = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Hello, world!"}]
            }
        },
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10,
            "outputTokens": 5,
            "totalTokens": 15
        }
    });

    let reader = BedrockReader;
    let writer = BedrockWriter;

    let resp = reader
        .read_response(&j)
        .expect("read_response should succeed");
    let written = writer.write_response(&resp);

    assert_eq!(
        written, j,
        "round-trip must be byte-identical for text-only response"
    );
}

#[test]
fn test_stream_decode_sequence() {
    use crate::ir::IrStreamEvent;

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events: Vec<_> = vec![
        (serde_json::json!({"type": "messageStart", "role": "assistant"})),
        (serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {}
        })),
        (serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": "Hello"}
        })),
        (serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": ", world!"}
        })),
        (serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0})),
        (serde_json::json!({
            "type": "messageStop",
            "stopReason": "end_turn"
        })),
        (serde_json::json!({
            "type": "metadata",
            "usage": {"inputTokens": 10, "outputTokens": 5}
        })),
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    // Seven events: MessageStart, text BlockStart, 2×BlockDelta, BlockStop, ONE combined
    // MessageDelta{stop_reason, usage} (from `metadata`, which BUFFERS the stop_reason from the
    // preceding `messageStop` frame), and the terminal MessageStop (also from `metadata`, emitted
    // AFTER the delta). The combined delta precedes the terminal stop so a non-eventstream ingress
    // (e.g. Anthropic) writes `message_delta` then `message_stop` — the native order (finding:
    // delta-before-stop). Previously the order was stop-then-delta (MessageStop on `messageStop`,
    // MessageDelta on `metadata`), which made the Anthropic ingress emit `message_stop` first.
    assert_eq!(events.len(), 7);

    match &events[0] {
        IrStreamEvent::MessageStart { role, usage, .. } => {
            assert_eq!(*role, crate::ir::IrRole::Assistant);
            assert!(usage.is_none());
        }
        _ => panic!("event[0] should be MessageStart"),
    }

    match &events[1] {
        IrStreamEvent::BlockStart { index, block } => {
            assert_eq!(*index, 0);
            assert!(matches!(block, crate::ir::IrBlockMeta::Text));
        }
        _ => panic!("event[1] should be BlockStart"),
    }

    match &events[2] {
        IrStreamEvent::BlockDelta { index, delta } => {
            assert_eq!(*index, 0);
            if let crate::ir::IrDelta::TextDelta(text) = delta {
                assert_eq!(text, "Hello");
            } else {
                panic!("event[2] should be TextDelta");
            }
        }
        _ => panic!("event[2] should be BlockDelta"),
    }

    match &events[3] {
        IrStreamEvent::BlockDelta { index, delta } => {
            assert_eq!(*index, 0);
            if let crate::ir::IrDelta::TextDelta(text) = delta {
                assert_eq!(text, ", world!");
            } else {
                panic!("event[3] should be TextDelta");
            }
        }
        _ => panic!("event[3] should be BlockDelta"),
    }

    match &events[4] {
        IrStreamEvent::BlockStop { index } => assert_eq!(*index, 0),
        _ => panic!("event[4] should be BlockStop"),
    }

    // The `metadata` event emits ONE combined MessageDelta carrying BOTH the buffered stop_reason
    // (from the preceding `messageStop` frame) AND the real usage — a single
    // `message_delta`-equivalent event, matching what a native non-Bedrock stream emits (finding:
    // combined MessageDelta). It precedes the terminal MessageStop so the ingress writer emits the
    // delta before the stop.
    match &events[5] {
        IrStreamEvent::MessageDelta {
            stop_reason, usage, ..
        } => {
            assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::EndTurn));
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.output_tokens, 5);
        }
        _ => {
            panic!("event[5] should be the combined MessageDelta carrying stop_reason + usage")
        }
    }

    // The terminal MessageStop is emitted from the `metadata` branch AFTER the combined delta, so
    // the IR order is delta-then-stop. The ingress writer therefore emits `message_delta` then the
    // terminal `message_stop` — the native order a non-Bedrock stream carries.
    match &events[6] {
        IrStreamEvent::MessageStop => {}
        _ => panic!("event[6] should be the terminal MessageStop"),
    }
}

#[test]
fn test_write_response_event() {
    let writer = BedrockWriter;

    let delta_ev = IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    };

    if let Some((event_type, payload)) = writer.write_response_event(&delta_ev) {
        assert_eq!(event_type, "contentBlockDelta");
        assert_eq!(
            payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
            Some(0)
        );
        assert_eq!(
            payload
                .get("delta")
                .and_then(|d| d.as_object())
                .and_then(|o| o.get("text"))
                .and_then(|t| t.as_str()),
            Some("hi")
        );
    } else {
        panic!("write_response_event should return Some for BlockDelta");
    }

    let delta_ev2 = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };

    if let Some((event_type, payload)) = writer.write_response_event(&delta_ev2) {
        assert_eq!(event_type, "messageStop");
        assert_eq!(
            payload.get("stopReason").and_then(|s| s.as_str()),
            Some("tool_use")
        );
    } else {
        panic!("write_response_event should return Some for MessageDelta with tool_use");
    }
}

// --- Regression tests for the 1.0 hardening pass -------------------------------------------

/// Regression: a malformed lane credential (access key id containing a control char that
/// `HeaderValue::from_str` rejects) must NOT panic the request-handling task. It takes the
/// same graceful path as a structurally-misconfigured key: an empty header set, so the
/// request goes out unsigned and AWS surfaces a 403 auth error instead of aborting the task.
#[test]
fn test_bedrock_sigv4_control_char_in_access_key_no_panic() {
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    // CR/LF embedded in the access key id → invalid Authorization header value
    // (HeaderValue::from_str rejects ASCII control chars, including CR/LF). This is the
    // header-injection / misconfiguration vector the finding describes.
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKID\r\nINJECT:SECRET", &ctx);
    assert!(
        headers.is_empty(),
        "control-char access key must yield no headers (graceful), not panic; got: {headers:?}"
    );

    // A bare NUL / control byte is likewise rejected gracefully rather than panicking.
    let headers2 = crate::proto::bedrock::sigv4_sign_headers("AKID\u{0001}X:SECRET", &ctx);
    assert!(
        headers2.is_empty(),
        "control-char access key must yield no headers; got: {headers2:?}"
    );

    // Sanity: a well-formed key still produces the full signed header set.
    let ok = crate::proto::bedrock::sigv4_sign_headers("AKIDEXAMPLE:SECRETKEY", &ctx);
    assert!(
        ok.iter().any(|(k, _)| k.as_str() == "authorization"),
        "valid key still signs"
    );
}

/// Regression: `extract_error` must read the machine-readable error type from the AWS `__type`
/// field (used by the breaker's error_map for fine-grained routing), keeping the
/// human-readable text in `provider_code` from `message`. Previously both were set from
/// `message`, so error_map rules keyed on `structured_type` never matched.
#[test]
fn test_extract_error_structured_type_from_type_field() {
    let reader = BedrockReader;
    let body = br#"{"__type":"ThrottlingException","message":"Rate exceeded"}"#;
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
    assert_eq!(raw.http_status, 429);
    assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("ThrottlingException"),
        "structured_type must come from __type, not the message"
    );
}

/// `__type` is sometimes serialised as a shape ARN suffix
/// (`com.amazon.coral.service#ValidationException`); only the trailing type token is kept.
#[test]
fn test_extract_error_strips_type_arn_prefix() {
    let reader = BedrockReader;
    let body =
        br#"{"__type":"com.amazon.coral.service#ValidationException","message":"bad input"}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(raw.provider_code.as_deref(), Some("bad input"));
    assert_eq!(raw.structured_type.as_deref(), Some("ValidationException"));
}

/// When `__type` is absent, `structured_type` is None (no longer duplicated from `message`).
#[test]
fn test_extract_error_no_type_field_yields_none_structured_type() {
    let reader = BedrockReader;
    let body = br#"{"message":"something went wrong"}"#;
    let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, body);
    assert_eq!(raw.provider_code.as_deref(), Some("something went wrong"));
    assert!(
        raw.structured_type.is_none(),
        "structured_type must NOT be duplicated from message"
    );
}

/// A non-JSON body parses gracefully to (None, None) — single parse, no panic.
#[test]
fn test_extract_error_non_json_body() {
    let reader = BedrockReader;
    let raw = reader.extract_error(StatusCode::BAD_GATEWAY, b"<html>502</html>");
    assert_eq!(raw.http_status, 502);
    assert!(raw.provider_code.is_none());
    assert!(raw.structured_type.is_none());
}

/// A ConverseStream that ends after `messageStop` WITHOUT a trailing `metadata` event
/// (malformed/truncated upstream) emits NO terminal MessageStop and NO combined MessageDelta:
/// both are deferred to the `metadata` frame so the combined `MessageDelta{stop_reason, usage}`
/// can precede the terminal `MessageStop` in IR order (Finding: delta-before-stop, so a
/// non-eventstream ingress writes `message_delta` then `message_stop` — the native order). The
/// stop_reason from `messageStop` is buffered but, absent the `metadata` it pairs with, is
/// dropped on truncation — exactly as token usage was already dropped on a metadata-less stream.
/// Native ConverseStream always sends `metadata` after `messageStop`; a genuine mid-stream
/// truncation also drops the downstream HTTP connection, so the client already sees a broken
/// stream rather than a clean terminator. Modeled mid-stream errors take the separate
/// `*Exception` → `IrStreamEvent::Error` path, which is unaffected.
#[test]
fn test_stream_metadata_less_defers_terminator() {
    use crate::ir::IrStreamEvent;

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events: Vec<_> = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": "Hi"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        // NOTE: no `metadata` event — the upstream truncated here.
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    // `messageStop` only BUFFERS the stop_reason now; without the trailing `metadata` neither the
    // combined MessageDelta nor the terminal MessageStop is emitted.
    assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageStop)),
            "no terminal MessageStop is emitted on a metadata-less stream (deferred to metadata); got: {events:?}"
        );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "no combined MessageDelta is emitted without metadata; got: {events:?}"
    );
    // The buffered stop_reason is retained in decode state (it would pair with `metadata`).
    assert_eq!(
        state.pending_stop_reason,
        Some(crate::ir::IrStopReason::EndTurn)
    );
}

/// Exactly one terminal MessageStop is emitted across the full happy-path sequence
/// (messageStop + metadata) — no duplicate terminator.
#[test]
fn test_stream_emits_single_message_stop_with_metadata() {
    use crate::ir::IrStreamEvent;

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events: Vec<_> = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        serde_json::json!({"type": "metadata", "usage": {"inputTokens": 3, "outputTokens": 1}}),
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    let stop_count = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::MessageStop))
        .count();
    assert_eq!(
        stop_count, 1,
        "exactly one terminal MessageStop expected; got: {events:?}"
    );
}

// --- 1.0 ingress: native error envelope + response-identity fidelity ----------------------

/// The native Bedrock Converse error envelope is a flat `{"__type", "message"}` body (the exact
/// shape `extract_error` reads back) — NOT the generic `{"error":{...}}` default. A generic kind
/// maps to a real AWS exception name in `__type`, and the human text lands in lowercase
/// `message`. There must be no top-level `error` object (that would be a non-native tell).
#[test]
fn test_write_error_native_bedrock_shape() {
    let writer = BedrockWriter;
    let v = writer.write_error(400, "invalid_request_error", "bad input");
    assert_eq!(
        v.get("message").and_then(|m| m.as_str()),
        Some("bad input"),
        "human text must be in lowercase `message`"
    );
    assert_eq!(
        v.get("__type").and_then(|t| t.as_str()),
        Some("ValidationException"),
        "generic kind must map to a native Converse exception name in `__type`"
    );
    assert!(
        v.get("error").is_none(),
        "must NOT carry the generic `{{\"error\":...}}` envelope (non-native tell)"
    );
    // Serializes cleanly (served as application/json).
    let s = serde_json::to_string(&v).expect("error envelope must serialize");
    assert!(s.contains("\"__type\""));
}

/// Kind → Bedrock exception-name mapping covers the common categories and falls back to a real
/// exception name (never an invented one) for anything unmapped.
#[test]
fn test_error_kind_to_bedrock_type_mapping() {
    assert_eq!(
        error_kind_to_bedrock_type("rate_limit_error"),
        "ThrottlingException"
    );
    assert_eq!(error_kind_to_bedrock_type("auth"), "AccessDeniedException");
    assert_eq!(
        error_kind_to_bedrock_type("not_found"),
        "ResourceNotFoundException"
    );
    assert_eq!(
        error_kind_to_bedrock_type(ERR_TYPE_OVERLOADED),
        "ServiceUnavailableException"
    );
    // Regression (R9 HIGH): the forward layer emits the BARE kind `"overloaded"` for every
    // operational 503 path (lane exhaustion, deadline exceeded, no usable lane). It must map to
    // ServiceUnavailableException — NOT fall through to the ValidationException catch-all, which
    // would pair an HTTP 503 with a 400-class `__type` AWS never produces, making an AWS SDK
    // raise a non-retryable client fault instead of a retryable ServiceUnavailableException.
    assert_eq!(
        error_kind_to_bedrock_type(crate::proxy::KIND_OVERLOADED),
        "ServiceUnavailableException"
    );
    assert_eq!(
        error_kind_to_bedrock_type("api_error"),
        "InternalServerException"
    );
    // Unmapped → still a real AWS exception name, not a catch-all literal.
    assert_eq!(
        error_kind_to_bedrock_type("some_future_kind"),
        "ValidationException"
    );
}

/// The native error envelope round-trips back through `extract_error`: a Bedrock SDK (and the
/// breaker's own reader) recovers both the structured type from `__type` and the text from
/// `message`. This is the indistinguishability check that ties the writer to the reader.
#[test]
fn test_write_error_roundtrips_through_extract_error() {
    let writer = BedrockWriter;
    let reader = BedrockReader;
    let v = writer.write_error(429, "rate_limit_error", "Rate exceeded");
    let body = serde_json::to_vec(&v).expect("serialize");
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, &body);
    assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
    assert_eq!(raw.structured_type.as_deref(), Some("ThrottlingException"));
}

/// Same-protocol passthrough fidelity: reading a native Converse response and writing it back
/// preserves stopReason + usage exactly, and the written body carries NO synthesized identity
/// (`id`/`created`) — the native Converse body has none, so injecting one would be a tell.
#[test]
fn test_response_identity_same_protocol_roundtrip_no_synth() {
    let reader = BedrockReader;
    let writer = BedrockWriter;

    let j = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Hello, world!"}]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
    });

    let resp = reader.read_response(&j).expect("read_response");
    // Capture: Bedrock's minimal body yields no body-level identity.
    assert_eq!(resp.id, None, "Converse body has no id to capture");
    assert_eq!(
        resp.created, None,
        "Converse body has no created to capture"
    );
    assert_eq!(resp.system_fingerprint, None);
    assert_eq!(resp.stop_sequence, None);
    // stopReason + usage are present (the identity-bearing fields Bedrock does emit).
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::EndTurn));
    assert_eq!(resp.usage.input_tokens, 10);
    assert_eq!(resp.usage.output_tokens, 5);

    let written = writer.write_response(&resp);
    assert_eq!(
        written, j,
        "same-protocol round-trip must be byte-identical"
    );
    // No proxy-tell identity fields injected into the native body.
    assert!(written.get("id").is_none(), "native body must carry no id");
    assert!(
        written.get("created").is_none(),
        "native body must carry no created"
    );
}

/// Cross-protocol synthesis: minting a Bedrock-flavored response id never panics and yields a
/// unique, non-empty token (so an OpenAI/Anthropic ingress fed by a Bedrock egress can always
/// get a valid body id). Uniqueness comes from the monotonic counter even within one second.
#[test]
fn test_synth_response_id_unique_and_nonempty() {
    let a = synth_response_id();
    let b = synth_response_id();
    assert!(!a.is_empty(), "synthesized id must be non-empty");
    assert!(!b.is_empty(), "synthesized id must be non-empty");
    assert_ne!(a, b, "two synthesized ids minted back-to-back must differ");
    // Shape sanity: `<hex16>-<hex16>` (no panic on parse of either half).
    let (lhs, rhs) = a.split_once('-').expect("synth id has a `-` separator");
    assert_eq!(lhs.len(), 16, "left half is 16 hex chars");
    assert_eq!(rhs.len(), 16, "right half is 16 hex chars");
    assert!(u64::from_str_radix(lhs, 16).is_ok());
    assert!(u64::from_str_radix(rhs, 16).is_ok());
}

// --- Round 2 regression tests --------------------------------------------------------------

/// Regression (writer): a stream MessageDelta with `stop_reason = None` (the usage-only trailing
/// delta the reader emits from the Bedrock `metadata` event, or a cross-protocol egress's usage
/// frame) must be reframed as a native `metadata` frame carrying the real token usage — NOT a
/// second `messageStop` (the old behavior, which both discarded usage and produced two
/// `messageStop` frames, a distinguishable tell). A delta WITH a stop_reason still maps to
/// `messageStop`.
#[test]
fn test_write_response_event_usage_delta_is_metadata_frame() {
    let writer = BedrockWriter;

    // Usage-only delta → `metadata` frame with the real usage (and a derived totalTokens).
    let usage_only = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (et, payload) = writer
        .write_response_event(&usage_only)
        .expect("usage-only delta must emit a frame");
    assert_eq!(
        et, "metadata",
        "usage-only delta must be a `metadata` frame, not messageStop"
    );
    assert_eq!(
        payload
            .pointer("/usage/inputTokens")
            .and_then(|v| v.as_u64()),
        Some(11)
    );
    assert_eq!(
        payload
            .pointer("/usage/outputTokens")
            .and_then(|v| v.as_u64()),
        Some(7)
    );
    assert_eq!(
        payload
            .pointer("/usage/totalTokens")
            .and_then(|v| v.as_u64()),
        Some(18),
        "totalTokens must be inputTokens + outputTokens"
    );

    // Stop-reason delta still maps to `messageStop` (the stop discriminant).
    let stop = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (et2, payload2) = writer
        .write_response_event(&stop)
        .expect("stop delta must emit a frame");
    assert_eq!(et2, "messageStop");
    assert_eq!(
        payload2.get("stopReason").and_then(|s| s.as_str()),
        Some("tool_use")
    );
}

/// Regression (writer): a text BlockStart must emit a native `contentBlockStart` frame with an
/// empty `start` struct (AWS emits one for every block, text included) so a native SDK can
/// initialize its block decoder and the following deltas are not orphaned.
#[test]
fn test_write_response_event_text_block_start_emits_frame() {
    let writer = BedrockWriter;
    let ev = IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::Text,
    };
    let (et, payload) = writer
        .write_response_event(&ev)
        .expect("text BlockStart must emit a contentBlockStart frame");
    assert_eq!(et, "contentBlockStart");
    assert_eq!(
        payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
        Some(0)
    );
    assert!(
        payload
            .get("start")
            .and_then(|s| s.as_object())
            .map(|o| o.is_empty())
            .unwrap_or(false),
        "text block start must carry an empty `start` struct; got {payload}"
    );
}

/// Regression (reader): a mid-stream Bedrock exception event (`internalServerException` etc.)
/// must surface as an `IrStreamEvent::Error` rather than being silently swallowed by a catch-all,
/// so a client whose stream hits an upstream model error receives a protocol-shaped error frame
/// instead of a hanging / EOF-without-terminator stream.
#[test]
fn test_stream_decode_surfaces_midstream_exception() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "internalServerException",
            "message": "the model is on fire"
        }),
        &mut state,
    );
    assert_eq!(
        events.len(),
        1,
        "exactly one Error event expected; got {events:?}"
    );
    match &events[0] {
        IrStreamEvent::Error(err) => {
            assert_eq!(err.class, StatusClass::ServerError);
            assert_eq!(err.provider_signal.as_deref(), Some("the model is on fire"));
        }
        other => panic!("expected IrStreamEvent::Error, got {other:?}"),
    }

    // A throttling exception maps to the RateLimit class and falls back to the exception name
    // when no `message` is present.
    let throttle = reader.read_response_events(
        "",
        &serde_json::json!({"type": "throttlingException"}),
        &mut state,
    );
    match throttle.as_slice() {
        [IrStreamEvent::Error(err)] => {
            assert_eq!(err.class, StatusClass::RateLimit);
            assert_eq!(err.provider_signal.as_deref(), Some("throttlingException"));
        }
        other => panic!("expected a single RateLimit Error; got {other:?}"),
    }

    // An unrecognized (future / non-error) event type is still a silent no-op.
    let unknown = reader.read_response_events(
        "",
        &serde_json::json!({"type": "someFutureEvent"}),
        &mut state,
    );
    assert!(
        unknown.is_empty(),
        "unknown event types must be skipped; got {unknown:?}"
    );

    // Regression (R9 MEDIUM): `modelTimeoutException` is a REQUEST-level Converse exception, NOT
    // a member of the `ConverseStream.responseStream` output union (which has exactly five
    // members), so a real AWS endpoint never emits it mid-stream. It must be treated as an
    // unrecognized event (silent no-op) — NOT accepted as a stream exception and re-emitted as
    // `ModelStreamErrorException`, which would mutate the exception type across a same-protocol
    // boundary.
    let model_timeout = reader.read_response_events(
        "",
        &serde_json::json!({"type": "modelTimeoutException", "message": "slow"}),
        &mut state,
    );
    assert!(
        model_timeout.is_empty(),
        "modelTimeoutException is not a ConverseStream output-union member; must be skipped, \
             got {model_timeout:?}"
    );
}

/// Regression (R9 HIGH): `bedrock_image_block` must never emit `format: ""`. An exact `"image/"`
/// media_type (empty subtype) once slipped past the `strip_prefix(...).unwrap_or("png")` fallback
/// — `strip_prefix` returns `Some("")`, not `None` — producing a `format: ""` block outside
/// Bedrock's `ImageFormat` union that the SDK rejects with a ValidationException. It must fall
/// back to `png`, like a missing/unprefixed media_type.
#[test]
fn test_bedrock_image_block_empty_subtype_falls_back_to_png() {
    // Exact `"image/"` prefix with an empty subtype.
    let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "image/".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("base64 image must emit a block");
    assert_eq!(
        block.pointer("/format").and_then(|f| f.as_str()),
        Some("png"),
        "empty subtype must fall back to png, never an empty `format`; got {block}"
    );
    assert_eq!(
        block.pointer("/source/bytes").and_then(|b| b.as_str()),
        Some("QQ==")
    );

    // A real subtype is preserved verbatim.
    let jpeg = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "image/jpeg".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("jpeg must emit a block");
    assert_eq!(
        jpeg.pointer("/format").and_then(|f| f.as_str()),
        Some("jpeg")
    );

    // A media_type with no `image/` prefix also falls back to png (unchanged behavior).
    let bare = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "png".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("bare png must emit a block");
    assert_eq!(
        bare.pointer("/format").and_then(|f| f.as_str()),
        Some("png")
    );

    // The URL sentinel is still dropped (no corrupt block).
    assert!(
        bedrock_image_block(&crate::ir::IrImageSource::Url(
            ("https://example.com/x.png").to_string()
        ))
        .is_none(),
        "URL-source image must be dropped, not emitted as a base64 block"
    );
}

/// Regression (reader): the injected `stream` flag on a Bedrock-INGRESS converse-stream request
/// must be read into the IR so a cross-protocol egress writer produces a streaming body. A body
/// without the flag (native Bedrock egress, where streaming is endpoint-selected) defaults false.
#[test]
fn test_read_request_honors_injected_stream_flag() {
    let reader = BedrockReader;

    let streaming = serde_json::json!({
        "stream": true,
        "messages": [{"role": "user", "content": [{"text": "hi"}]}]
    });
    let ir = reader.read_request(&streaming).expect("read_request");
    assert!(
        ir.stream,
        "injected `stream: true` must be read into the IR"
    );

    let buffered = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}]
    });
    let ir2 = reader.read_request(&buffered).expect("read_request");
    assert!(
        !ir2.stream,
        "absent `stream` defaults to false (native egress)"
    );
}

/// Regression (writer): a System-role message that escapes the caller's system extraction is
/// SKIPPED, not silently emitted as a `user` turn (which would inject system text as a user
/// message). A Tool-role message is still emitted as a `user` turn (the native shape for a
/// `toolResult` block).
#[test]
fn test_write_request_skips_system_role_message() {
    let writer = BedrockWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::System,
                content: vec![crate::ir::IrBlock::Text {
                    text: "leaked system text".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "ok".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
        ],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };

    let json = writer.write_request(&req);
    let msgs = json
        .get("messages")
        .and_then(|m| m.as_array())
        .expect("messages array");
    assert_eq!(
        msgs.len(),
        1,
        "the System-role message must be dropped; got {msgs:?}"
    );
    assert_eq!(
        msgs[0].get("role").and_then(|r| r.as_str()),
        Some("user"),
        "the surviving Tool-role message maps to a user turn"
    );
    // The leaked system text must not appear anywhere on the wire.
    let wire = serde_json::to_string(&json).unwrap();
    assert!(
        !wire.contains("leaked system text"),
        "system text must not leak onto the wire; got {wire}"
    );
}

/// Regression (writer): a non-Text block inside a ToolResult must be re-encoded faithfully
/// (Image → Bedrock `{"image":...}`, ToolUse/ToolResult → `{"json":...}`), never collapsed to
/// the constant string `"{}"` placeholder the old catch-all produced.
#[test]
fn test_write_request_tool_result_preserves_non_text_content() {
    let writer = BedrockWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "t1".to_string(),
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: "image/png".to_string(),
                        data: "BASE64DATA".to_string(),
                    },
                    cache_control: None,
                }],
                is_error: false,
                cache_control: None,
            }],
        }],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };

    let json = writer.write_request(&req);
    let inner = json
        .pointer("/messages/0/content/0/toolResult/content/0")
        .expect("tool result inner content block");
    assert_eq!(
        inner.pointer("/image/format").and_then(|v| v.as_str()),
        Some("png"),
        "image inner block must be a native Bedrock image block; got {inner}"
    );
    assert_eq!(
        inner
            .pointer("/image/source/bytes")
            .and_then(|v| v.as_str()),
        Some("BASE64DATA")
    );
    // The old `"{}"` placeholder must be gone.
    let wire = serde_json::to_string(&json).unwrap();
    assert!(
        !wire.contains(r#"{"text":"{}"}"#),
        "must not emit the `{{}}` placeholder; got {wire}"
    );
}

/// Regression (writer): a stream Error event names a REAL Converse exception (mapped from the IR
/// error class) as its event-type token instead of the non-native literal `"error"`. (The
/// `:message-type: exception` framing itself is the encoder's job — see the production
/// mid-stream-error path in proxy engine — and is out of this unit's scope.)
#[test]
fn test_write_response_event_error_names_real_exception() {
    let writer = BedrockWriter;

    let throttle = IrStreamEvent::Error(crate::proto::IrError {
        class: StatusClass::RateLimit,
        provider_signal: Some("slow down".to_string()),
        retry_after: None,
    });
    let (et, payload) = writer
        .write_response_event(&throttle)
        .expect("error event must emit a frame");
    assert_eq!(
        et, "ThrottlingException",
        "event-type token must be a real Converse exception name, not `error`"
    );
    assert_eq!(
        payload.get("message").and_then(|m| m.as_str()),
        Some("slow down")
    );

    // A server-class error maps to InternalServerException and falls back to the exception name
    // when no provider_signal is present.
    let server = IrStreamEvent::Error(crate::proto::IrError {
        class: StatusClass::ServerError,
        provider_signal: None,
        retry_after: None,
    });
    let (et2, payload2) = writer
        .write_response_event(&server)
        .expect("error event must emit a frame");
    assert_eq!(et2, "InternalServerException");
    assert_eq!(
        payload2.get("message").and_then(|m| m.as_str()),
        Some("InternalServerException")
    );
}

// --- Round 3 regression tests --------------------------------------------------------------

/// Regression (reader): unmodeled top-level request fields must be collected into `extra` so a
/// same-protocol Bedrock->Bedrock passthrough re-emits them faithfully (via `write_request`'s
/// extra-merge). Previously `extra` was built empty and every native Converse field this reader
/// does not explicitly model — `topP`, `topK`, `stopSequences`, `guardrailConfig`,
/// `additionalModelRequestFields`, etc. — was silently dropped, disabling guardrails / resetting
/// sampling on passthrough. The fully-modeled keys (system/messages/toolConfig/stream) must NOT
/// leak into `extra` (they are re-serialised from the structured IR; a double-emit / echoed
/// `stream` would be a tell). `inferenceConfig` is the exception: it is only PARTIALLY modeled
/// (just `maxTokens`/`temperature`), so the WHOLE raw object is now captured into `extra` to
/// preserve its unmodeled sub-fields (`stopSequences`/`topP`/`topK`/...) — see the finding-2 fix.
#[test]
fn test_read_request_collects_unmodeled_fields_into_extra() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 10},
        "system": [{"text": "sys"}],
        "toolConfig": {"tools": []},
        "stream": true,
        "topP": 0.95,
        "topK": 40,
        "stopSequences": ["STOP"],
        "guardrailConfig": {"guardrailIdentifier": "gr-1", "guardrailVersion": "1"},
        "additionalModelRequestFields": {"foo": "bar"}
    });
    let ir = reader.read_request(&j).expect("read_request");

    // Unmodeled fields are preserved verbatim.
    assert_eq!(ir.extra.get("topP"), Some(&serde_json::json!(0.95)));
    assert_eq!(ir.extra.get("topK"), Some(&serde_json::json!(40)));
    assert_eq!(
        ir.extra.get("stopSequences"),
        Some(&serde_json::json!(["STOP"]))
    );
    assert_eq!(
        ir.extra.get("guardrailConfig"),
        Some(&serde_json::json!({"guardrailIdentifier": "gr-1", "guardrailVersion": "1"}))
    );
    assert_eq!(
        ir.extra.get("additionalModelRequestFields"),
        Some(&serde_json::json!({"foo": "bar"}))
    );

    // `inferenceConfig` IS now captured verbatim into `extra` (it is only partially modeled, so
    // its raw object preserves unmodeled sub-fields for passthrough; finding-2 fix).
    assert_eq!(
        ir.extra.get("inferenceConfig"),
        Some(&serde_json::json!({"maxTokens": 10})),
        "inferenceConfig must be captured into extra verbatim"
    );

    // `toolConfig` IS now captured verbatim into `extra` (it is only partially modeled — only
    // `tools` is typed into `ir.tools`; `toolChoice` and future sub-fields are unmodeled — so the
    // raw object preserves them for passthrough; R15 toolChoice fix).
    assert_eq!(
        ir.extra.get("toolConfig"),
        Some(&serde_json::json!({"tools": []})),
        "toolConfig must be captured into extra verbatim"
    );

    // Fully-modeled keys must NOT be duplicated into `extra` (avoids double-emit / echoed
    // `stream`). `inferenceConfig` and `toolConfig` are intentionally absent from this list now
    // (they are only partially modeled; see above).
    for k in ["system", "messages", "stream"] {
        assert!(
            ir.extra.get(k).is_none(),
            "modeled key `{k}` must not leak into extra; got {:?}",
            ir.extra
        );
    }
    // `stream` is still captured in the structured field.
    assert!(
        ir.stream,
        "injected stream flag still captured structurally"
    );
}

/// Regression (reader + writer): a full passthrough — read a native Converse request carrying
/// unmodeled fields, then write it back — must re-emit `topP`/`stopSequences`/`guardrailConfig`
/// onto the wire, never strip them. Uses the existing rich fixture (which carries `top_p`).
#[test]
fn test_request_passthrough_preserves_unmodeled_fields() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let j = bedrock_rich_fixture(); // carries a top-level `top_p`
    let ir = reader.read_request(&j).expect("read_request");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("top_p").and_then(|v| v.as_f64()),
        Some(0.95),
        "unmodeled `top_p` must survive a Bedrock->Bedrock passthrough; got {out}"
    );
}

/// Regression (R15 toolChoice): `toolConfig.toolChoice` (the force-tool-use control:
/// `{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`) is an UNMODELED sub-field of `toolConfig` —
/// only `toolConfig.tools` is typed into `ir.tools`. The old code listed `toolConfig` in
/// `MODELED_KEYS`, so the raw object never reached `extra` and the writer rebuilt `toolConfig`
/// from `ir.tools` ALONE, silently dropping `toolChoice` on a Bedrock->Bedrock passthrough
/// whenever the body was rebuilt. A native AWS client that sent `toolChoice: {any: {}}` to force a
/// tool call would have that constraint stripped, changing model behaviour. The reader now
/// captures the whole raw `toolConfig` into `extra` and the writer overlays the typed `tools`
/// array onto it, preserving `toolChoice`.
#[test]
fn test_request_passthrough_preserves_tool_choice() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let j = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "weather?"}]}],
        "toolConfig": {
            "tools": [{
                "toolSpec": {
                    "name": "get_weather",
                    "inputSchema": {"json": {"type": "object"}}
                }
            }],
            "toolChoice": {"any": {}}
        }
    });
    let ir = reader.read_request(&j).expect("read_request");

    // The tools array is parsed into the structured IR (for cross-protocol egress)...
    assert_eq!(ir.tools.len(), 1);
    assert_eq!(ir.tools[0].name, "get_weather");
    // ...and the whole raw toolConfig (incl. toolChoice) is preserved in `extra` for passthrough.
    assert_eq!(
        ir.extra
            .get("toolConfig")
            .and_then(|tc| tc.get("toolChoice")),
        Some(&serde_json::json!({"any": {}})),
        "raw toolChoice must be captured into extra; got {:?}",
        ir.extra
    );

    let out = writer.write_request(&ir);
    let tc = out
        .get("toolConfig")
        .and_then(|v| v.as_object())
        .expect("toolConfig must be re-emitted");
    // toolChoice survives the round-trip...
    assert_eq!(
        tc.get("toolChoice"),
        Some(&serde_json::json!({"any": {}})),
        "toolChoice must survive a Bedrock->Bedrock passthrough; got {out}"
    );
    // ...and the typed tools array is re-emitted (one toolSpec).
    assert_eq!(
        tc.get("tools").and_then(|t| t.as_array()).map(|a| a.len()),
        Some(1),
        "rebuilt tools array must be present; got {out}"
    );
}

/// Regression (R15 toolChoice): on the CROSS-protocol seam `extra` is cleared, so a writer driven
/// by an IR with `ir.tools` but no `extra.toolConfig` must still emit a valid `toolConfig` built
/// purely from the typed tools (no `toolChoice`, since the IR has no field for it). And a degenerate
/// IR with neither typed tools nor a raw `toolConfig` must NOT emit a bare/empty `toolConfig` (AWS
/// rejects a `toolConfig` with no `tools`).
#[test]
fn test_write_request_tool_config_cross_protocol_and_empty() {
    let writer = BedrockWriter;

    // Cross-protocol shape: typed tools, empty extra (seam cleared it).
    let ir_tools = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![],
        tools: vec![crate::ir::IrTool {
            name: "f".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            cache_control: None,
        }],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&ir_tools);
    let tc = out
        .get("toolConfig")
        .and_then(|v| v.as_object())
        .expect("toolConfig must be emitted from typed tools alone");
    assert_eq!(
        tc.get("tools").and_then(|t| t.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert!(
        tc.get("toolChoice").is_none(),
        "no toolChoice should appear cross-protocol (IR has no field for it); got {out}"
    );

    // No tools, no raw toolConfig → no toolConfig key at all.
    let ir_empty = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out_empty = writer.write_request(&ir_empty);
    assert!(
        out_empty.get("toolConfig").is_none(),
        "no toolConfig must be emitted when there are no tools; got {out_empty}"
    );
}

/// Regression (reader): a text block that opens at index > 0 (after a preceding tool-use block,
/// reachable via cross-protocol ingress) must have its `text_block_open` flag cleared on its
/// contentBlockStop, so a LATER text block still emits a fresh BlockStart. The old `idx == 0`
/// guard left the flag set for a text block at index N>0, suppressing all subsequent text
/// BlockStarts and silently dropping the rest of the text content.
#[test]
fn test_stream_text_block_after_tool_not_dropped() {
    use crate::ir::IrStreamEvent;
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events: Vec<_> = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        // tool-use block at index 0
        serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        // text block at index 1 (start has no `start` object → text)
        serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 1}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 1,
            "delta": {"text": "first"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 1}),
        // a SECOND text block at index 2 — must still open (flag was cleared at idx 1 stop)
        serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 2}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 2,
            "delta": {"text": "second"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 2}),
    ]
    .into_iter()
    .flat_map(|d| reader.read_response_events("", &d, &mut state))
    .collect();

    // Two text BlockStarts must appear (at index 1 and index 2).
    let text_starts: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::Text,
            } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(
        text_starts,
        vec![1, 2],
        "both text blocks (idx 1 and idx 2) must emit a BlockStart; got {events:?}"
    );
    // Both text deltas survive.
    let deltas: Vec<String> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::TextDelta(t),
                ..
            } => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(deltas, vec!["first".to_string(), "second".to_string()]);
}

/// Regression (reader): a `contentBlockStart` whose `start` object carries an UNRECOGNIZED key
/// (not `toolUse`, and not the empty `{}` text shape — e.g. a future `image`/`reasoningContent`
/// block) must NOT be mis-opened as a Text block. Only an empty `start: {}` (or an absent
/// `start`) opens text. Forward-compatibility / defensive parsing.
#[test]
fn test_stream_unrecognized_start_does_not_open_text() {
    use crate::ir::IrStreamEvent;
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let _ = reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStart", "role": "assistant"}),
        &mut state,
    );
    // A `start` with an unrecognized key — must emit nothing (no spurious Text BlockStart).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {"reasoningContent": {"foo": "bar"}}
        }),
        &mut state,
    );
    assert!(
        !evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Text,
                ..
            }
        )),
        "an unrecognized `start` key must not open a Text block; got {evs:?}"
    );
    assert!(
        !state.text_block_open,
        "text_block_open must remain false for an unrecognized start shape"
    );

    // The empty `start: {}` text shape still opens a Text block (sanity).
    let evs2 = reader.read_response_events(
        "",
        &serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 0, "start": {}}),
        &mut state,
    );
    assert!(
        evs2.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Text,
                ..
            }
        )),
        "an empty `start: {{}}` must still open a Text block; got {evs2:?}"
    );
}

/// Regression (writer): a session (STS) token containing a byte `HeaderValue` rejects (control
/// char / >= 0x80) must NOT produce a request signed over `x-amz-security-token` with the header
/// absent (which AWS rejects with SignatureDoesNotMatch). The signed set and the wire set are
/// gated by the same up-front validation, so an un-encodable token bails to the graceful
/// empty-header path (unsigned request → AWS 403 as auth) — no panic, no divergence.
#[test]
fn test_bedrock_sigv4_unencodable_session_token_bails_gracefully() {
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    // Session token with an embedded control char → un-encodable HeaderValue.
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET:TOK\r\nEN", &ctx);
    assert!(
        headers.is_empty(),
        "un-encodable session token must yield no headers (graceful), not a signed-but-absent \
             token header; got {headers:?}"
    );
    // A bare control byte (e.g. NUL / U+0001) likewise bails — `HeaderValue::from_str` rejects
    // ASCII control characters, the same vector as the misconfigured access-key path.
    let headers2 = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET:TOK\u{0001}EN", &ctx);
    assert!(
        headers2.is_empty(),
        "control-byte token must bail; got {headers2:?}"
    );

    // Sanity: a clean token still signs AND emits the token header, and the signed set commits
    // to it (so the two never diverge in the success case either).
    let ok = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET:CLEANTOKEN", &ctx);
    let auth = ok
        .iter()
        .find(|(k, _)| k.as_str() == "authorization")
        .map(|(_, v)| v.to_str().unwrap().to_string())
        .expect("authorization header");
    assert!(
        auth.contains("x-amz-security-token"), // golden wire-contract literal (kept bare on purpose)
        "clean token must be in the signed header set"
    );
    assert!(
        ok.iter().any(
            |(k, v)| k.as_str() == "x-amz-security-token" // golden wire-contract literal (kept bare on purpose)
                && v.to_str().unwrap() == "CLEANTOKEN"
        ),
        "clean token must be emitted on the wire; got {ok:?}"
    );
}

/// Regression (writer): a usage-only delta's `metadata` frame carries the real `usage` but does
/// NOT fabricate a `metrics` object at the writer layer. The native ConverseStream `metrics`
/// object reports the stream's REAL `latencyMs`, which the writer cannot know — so it is injected
/// (with the elapsed wall-clock) by `StreamTranslate::emit_ir_event` on the Bedrock-ingress path,
/// or OMITTED when timing is unavailable. Emitting a hard-coded `latencyMs: 0` here (the old
/// behavior) was itself a detectable tell (a real stream never reports exactly 0). The live
/// latency injection is covered by the StreamTranslate test in proto/mod.rs.
#[test]
fn test_write_response_event_metadata_no_fabricated_metrics() {
    let writer = BedrockWriter;
    let usage_only = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 3,
            output_tokens: 2,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (et, payload) = writer
        .write_response_event(&usage_only)
        .expect("usage-only delta emits a metadata frame");
    assert_eq!(et, "metadata");
    assert!(
        payload.pointer("/metrics").is_none(),
        "writer must NOT fabricate a `metrics` object (latency is injected by StreamTranslate \
             or omitted); got {payload}"
    );
    // usage is still present and correct.
    assert_eq!(
        payload
            .pointer("/usage/totalTokens")
            .and_then(|v| v.as_u64()),
        Some(5)
    );
}

/// Regression (writer, streaming `metadata` frame): `totalTokens` is computed with a saturating
/// add, so a pathological/hostile upstream sending token counts near `u64::MAX` clamps to
/// `u64::MAX` instead of panicking under overflow-checks (debug / opt-in release) or silently
/// wrapping to a near-zero nonsense total in plain release. Mirrors the Gemini writer's
/// `test_stream_message_delta_total_token_count_saturates`.
#[test]
fn test_write_response_event_total_tokens_saturates() {
    let writer = BedrockWriter;
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: u64::MAX,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (et, payload) = writer
        .write_response_event(&ev)
        .expect("usage-only delta emits a metadata frame");
    assert_eq!(et, "metadata");
    // No panic on the request path, and the total clamps at u64::MAX rather than wrapping to 0.
    assert_eq!(
        payload
            .pointer("/usage/totalTokens")
            .and_then(|v| v.as_u64()),
        Some(u64::MAX),
        "totalTokens must saturate, not wrap; got {payload}"
    );
    // Component counts are passed through untouched.
    assert_eq!(
        payload
            .pointer("/usage/inputTokens")
            .and_then(|v| v.as_u64()),
        Some(u64::MAX)
    );
    assert_eq!(
        payload
            .pointer("/usage/outputTokens")
            .and_then(|v| v.as_u64()),
        Some(1)
    );
}

/// REGRESSION (audit c2r2): `bedrock_response_to_eventstream` (buffered 2xx → synthesized
/// ConverseStream, used when a Bedrock-streaming client gets a non-streaming cross-protocol 2xx)
/// must NOT drop a `Thinking` (reasoningContent) block. The old arm skipped it, silently losing
/// upstream reasoning; it now synthesizes the `reasoningContent` start/delta/stop frames.
#[test]
fn eventstream_emits_reasoning_content_for_thinking_block() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Thinking {
                text: "let me think".to_string(),
                signature: Some("sigblob".to_string()),
                redacted: false,
                cache_control: None,
            },
            crate::ir::IrBlock::Text {
                text: "answer".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
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
    let bytes = bedrock_response_to_eventstream(&resp, Some(5));
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("reasoningContent"),
        "a Thinking block must synthesize a reasoningContent frame, not be dropped"
    );
    assert!(
        text.contains("let me think"),
        "the thinking text must ride a reasoningContent delta"
    );
    assert!(
        text.contains("sigblob"),
        "the reasoning signature must ride a signature delta"
    );
}

/// Regression (writer, non-stream `write_response` body): the buffered Converse `totalTokens`
/// uses the same saturating add as the streaming frame, so an upstream response carrying token
/// counts near `u64::MAX` does not panic (overflow-checks) or wrap (release).
#[test]
fn test_write_response_total_tokens_saturates() {
    let writer = BedrockWriter;
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: u64::MAX - 1,
            output_tokens: 100,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let body = writer.write_response(&resp);
    assert_eq!(
        body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
        Some(u64::MAX),
        "totalTokens must saturate, not wrap; got {body}"
    );
    // A normal (non-overflowing) pair still sums exactly.
    let normal = crate::ir::IrResponse {
        usage: IrUsage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        ..resp
    };
    let body = writer.write_response(&normal);
    assert_eq!(
        body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
        Some(15)
    );
}

/// Regression (R24 LOW#7 — writer, non-stream `write_response`): an assistant response carrying
/// an `IrBlock::Image` must be PROJECTED as a native Bedrock `{"image": ...}` content block, not
/// silently dropped by the old combined `ToolResult | Image => {}` no-op arm. A base64 image
/// uses the `bytes` source and the subtype-derived `format`.
#[test]
fn test_write_response_projects_image_block() {
    let writer = BedrockWriter;
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Text {
                text: "see image".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: "image/png".to_string(),
                    data: "aGVsbG8=".to_string(),
                },
                cache_control: None,
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
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
    let body = writer.write_response(&resp);
    let content = body
        .pointer("/output/message/content")
        .and_then(|v| v.as_array())
        .expect("content array present");
    // Both the text block and the projected image block survive (2 entries, none dropped).
    assert_eq!(content.len(), 2, "image block must not be dropped: {body}");
    let image = content
        .iter()
        .find(|b| b.get("image").is_some())
        .expect("a native image block must be present");
    assert_eq!(
        image.pointer("/image/format").and_then(|v| v.as_str()),
        Some("png"),
        "image format derived from MIME subtype: {body}"
    );
    assert_eq!(
        image
            .pointer("/image/source/bytes")
            .and_then(|v| v.as_str()),
        Some("aGVsbG8="),
        "base64 image data carried as `bytes` source: {body}"
    );
}

/// Regression (R24 LOW#8 — writer, non-stream `write_response`): a response whose blocks are ALL
/// non-representable in an assistant Converse message (here a lone `ToolResult`, which belongs to
/// a user turn) must NOT emit an empty `content: []` array — Bedrock rejects that with a
/// ValidationException. `write_request` already guards every turn; this mirrors that guard with a
/// minimal placeholder text block.
///
/// NOTE: a `Thinking` block is NO LONGER non-representable in a response (R25 MED #3 re-emits it
/// as a native `reasoningContent` block), so it cannot be part of an "all non-representable" case;
/// the lone `ToolResult` (genuinely a user-turn block) is the only remaining no-op here.
#[test]
fn test_write_response_empty_content_emits_placeholder() {
    let writer = BedrockWriter;
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::ToolResult {
            tool_use_id: "tu_1".to_string(),
            content: Vec::new(),
            is_error: false,
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
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
    let body = writer.write_response(&resp);
    let content = body
        .pointer("/output/message/content")
        .and_then(|v| v.as_array())
        .expect("content array present");
    assert!(
        !content.is_empty(),
        "content array must never be empty (Bedrock rejects it): {body}"
    );
    assert_eq!(
        content.len(),
        1,
        "exactly one placeholder block when all blocks are non-representable: {body}"
    );
    assert_eq!(
        content[0].get("text").and_then(|v| v.as_str()),
        Some(""),
        "placeholder is a minimal empty-text block (mirrors write_request): {body}"
    );
}

// --- Round 5 regression tests --------------------------------------------------------------

/// Regression (finding 2 — reader+writer): an `inferenceConfig` carrying sub-fields this reader
/// does NOT type (`stopSequences`, `topP`, `topK`, future AWS additions) must survive a
/// same-protocol Bedrock->Bedrock passthrough, NOT be silently dropped. Previously
/// `inferenceConfig` was modeled-out wholesale and only `maxTokens`/`temperature` were
/// re-emitted, so `stopSequences` (a commonly-used generation-boundary control) and the
/// `topP`/`topK` sampling knobs vanished — changing model behaviour vs a direct AWS call.
#[test]
fn test_inference_config_passthrough_preserves_unmodeled_subfields() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let wire = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {
            "maxTokens": 256,
            "temperature": 0.3,
            "topP": 0.9,
            "topK": 50,
            "stopSequences": ["\n\nHuman:", "END"]
        }
    });

    let ir = reader.read_request(&wire).expect("read_request");
    // The typed fields still flow into the structured IR (for cross-protocol egress).
    assert_eq!(ir.max_tokens, Some(256));
    assert_eq!(ir.temperature, Some(0.3));
    // The whole raw inferenceConfig is captured for passthrough fidelity.
    assert!(ir.extra.contains_key("inferenceConfig"));

    let out = writer.write_request(&ir);
    // Every sub-field — modeled AND unmodeled — must round-trip onto the wire.
    assert_eq!(
        out.pointer("/inferenceConfig/maxTokens")
            .and_then(|v| v.as_u64()),
        Some(256)
    );
    assert_eq!(
        out.pointer("/inferenceConfig/temperature")
            .and_then(|v| v.as_f64()),
        Some(0.3)
    );
    assert_eq!(
        out.pointer("/inferenceConfig/topP")
            .and_then(|v| v.as_f64()),
        Some(0.9),
        "topP must survive passthrough; got {out}"
    );
    assert_eq!(
        out.pointer("/inferenceConfig/topK")
            .and_then(|v| v.as_u64()),
        Some(50),
        "topK must survive passthrough; got {out}"
    );
    assert_eq!(
        out.pointer("/inferenceConfig/stopSequences"),
        Some(&serde_json::json!(["\n\nHuman:", "END"])),
        "stopSequences must survive passthrough; got {out}"
    );
    // The whole body round-trips byte-identically (no `inferenceConfig` double-emit).
    assert_eq!(out, wire, "full body must round-trip byte-identically");
}

/// PF-H1: `top_k` (a first-class IR field) must reach a Bedrock egress via
/// `additionalModelRequestFields.top_k`. A cross-protocol request (e.g. Anthropic) carries `top_k`
/// in the IR with an empty `extra`; the Bedrock writer must emit it instead of dropping it. And a
/// native Bedrock request that pins `top_k` in `additionalModelRequestFields` must round-trip
/// through the reader/writer.
#[test]
fn test_top_k_reaches_bedrock_via_additional_model_request_fields() {
    let writer = BedrockWriter;

    // Cross-protocol shape: top_k set in the IR, extra cleared (as the translate seam leaves it).
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        top_k: Some(40),
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/additionalModelRequestFields/top_k")
            .and_then(|v| v.as_u64()),
        Some(40),
        "top_k must be emitted under additionalModelRequestFields.top_k; got {out}"
    );

    // Native Bedrock round-trip: a request that pins top_k in additionalModelRequestFields must
    // read into the IR and re-emit faithfully (no double-emit of additionalModelRequestFields).
    let reader = BedrockReader;
    let wire = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 64},
        "additionalModelRequestFields": {"top_k": 40}
    });
    let ir2 = reader.read_request(&wire).expect("read_request");
    assert_eq!(ir2.top_k, Some(40), "reader must promote top_k into the IR");
    let out2 = writer.write_request(&ir2);
    assert_eq!(
        out2.pointer("/additionalModelRequestFields/top_k")
            .and_then(|v| v.as_u64()),
        Some(40),
        "top_k must survive the Bedrock round-trip; got {out2}"
    );
    assert_eq!(
        out2, wire,
        "native Bedrock body must round-trip byte-identically"
    );
}

/// Losslessness (top_k spelling preservation): a native Bedrock->Bedrock passthrough whose body
/// spelled top_k as camelCase `topK` must round-trip byte-identically (NOT be renamed to
/// `top_k`), while a cross-protocol egress (empty `extra`, no sentinel) still emits the canonical
/// snake_case `top_k`.
#[test]
fn test_top_k_camel_spelling_round_trips_and_cross_protocol_stays_snake() {
    let reader = BedrockReader;
    let writer = BedrockWriter;

    // Same-protocol: source used camelCase `topK`. The reader lifts it into the IR AND stamps the
    // source-spelling sentinel; the writer re-emits `topK` and consumes the sentinel.
    let wire = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 64},
        "additionalModelRequestFields": {"topK": 40}
    });
    let ir = reader.read_request(&wire).expect("read_request");
    assert_eq!(ir.top_k, Some(40), "reader must promote topK into the IR");
    assert!(
        ir.extra.contains_key(TOP_K_CAMEL_SENTINEL),
        "reader must stamp the camel-spelling sentinel when source used topK"
    );
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/additionalModelRequestFields/topK")
            .and_then(|v| v.as_u64()),
        Some(40),
        "topK source spelling must be preserved; got {out}"
    );
    assert!(
        out.pointer("/additionalModelRequestFields/top_k").is_none(),
        "must NOT also emit snake_case top_k; got {out}"
    );
    // The sentinel must be CONSUMED — never serialized to the wire.
    assert!(
        out.get(TOP_K_CAMEL_SENTINEL).is_none(),
        "the source-spelling sentinel must never reach the wire; got {out}"
    );
    assert_eq!(
        out, wire,
        "Bedrock->Bedrock topK body must round-trip byte-identically"
    );

    // Cross-protocol: top_k in the IR, `extra` cleared (as the translate seam leaves it) — no
    // sentinel, so the writer emits the canonical snake_case `top_k`.
    let ir_cross = crate::ir::IrRequest {
        top_k: Some(40),
        extra: serde_json::Map::new(),
        ..ir.clone()
    };
    let out_cross = writer.write_request(&ir_cross);
    assert_eq!(
        out_cross
            .pointer("/additionalModelRequestFields/top_k")
            .and_then(|v| v.as_u64()),
        Some(40),
        "cross-protocol egress (no sentinel) must emit canonical top_k; got {out_cross}"
    );
    assert!(
        out_cross
            .pointer("/additionalModelRequestFields/topK")
            .is_none(),
        "cross-protocol egress must NOT emit camelCase topK; got {out_cross}"
    );
}

/// PF (non-silent clamp): the Bedrock temperature clamp helper signals when it changes the value
/// (so the writer can warn) and is a no-op (was_clamped=false) for in-range values.
#[test]
fn test_clamp_temperature_for_bedrock_signals_on_change() {
    // Out-of-range values are clamped AND flagged as changed.
    assert_eq!(clamp_temperature_for_bedrock(1.8), (1.0, true));
    assert_eq!(clamp_temperature_for_bedrock(2.0), (1.0, true));
    assert_eq!(clamp_temperature_for_bedrock(-0.5), (0.0, true));
    // In-range values pass through unchanged and are NOT flagged.
    assert_eq!(clamp_temperature_for_bedrock(0.7), (0.7, false));
    assert_eq!(clamp_temperature_for_bedrock(0.0), (0.0, false));
    assert_eq!(clamp_temperature_for_bedrock(1.0), (1.0, false));
}

/// Regression (finding 2): the typed IR fields WIN over a same-named raw `inferenceConfig` entry
/// (the structured IR is the source of truth for the values it models), and a cross-protocol
/// egress (no `inferenceConfig` in `extra`) still emits a config built purely from the typed IR.
#[test]
fn test_inference_config_typed_fields_override_raw_and_cross_protocol() {
    let writer = BedrockWriter;

    // Typed maxTokens overrides a stale raw value carried in extra.
    let mut extra = serde_json::Map::new();
    extra.insert(
        "inferenceConfig".to_string(),
        serde_json::json!({"maxTokens": 1, "topP": 0.5}),
    );
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        max_tokens: Some(999),
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra,
    };
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/inferenceConfig/maxTokens")
            .and_then(|v| v.as_u64()),
        Some(999),
        "typed maxTokens must override the raw extra value; got {out}"
    );
    assert_eq!(
        out.pointer("/inferenceConfig/topP")
            .and_then(|v| v.as_f64()),
        Some(0.5),
        "unmodeled topP from raw config still survives"
    );

    // Cross-protocol egress: no inferenceConfig in extra → config built purely from typed IR.
    let ir2 = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        max_tokens: Some(42),
        temperature: Some(0.1),
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out2 = writer.write_request(&ir2);
    assert_eq!(
        out2.pointer("/inferenceConfig/maxTokens")
            .and_then(|v| v.as_u64()),
        Some(42)
    );
    assert_eq!(
        out2.pointer("/inferenceConfig/temperature")
            .and_then(|v| v.as_f64()),
        Some(0.1)
    );
    // No stray topP/stopSequences appear from nowhere.
    assert!(out2.pointer("/inferenceConfig/topP").is_none());
}

/// Regression (finding 3): a mid-stream `IrError` mapped for the ConverseStream output union must
/// only ever name one of the FIVE legal stream-event exceptions. Request-level shapes
/// (`ModelTimeoutException`, `AccessDeniedException`, `ServiceQuotaExceededException`) are NOT
/// members of the stream union and would be treated as unknown/unmodeled by a native AWS SDK
/// stream decoder — an indistinguishability tell. Both the exception-frame path
/// (`write_response_exception`) and the fallback `write_response_event` Error arm use this map.
#[test]
fn test_stream_exception_only_emits_converse_stream_union_members() {
    let writer = BedrockWriter;
    const STREAM_UNION: [&str; 5] = [
        "InternalServerException",
        "ModelStreamErrorException",
        "ValidationException",
        "ThrottlingException",
        "ServiceUnavailableException",
    ];

    let cases = [
        (StatusClass::RateLimit, "ThrottlingException"),
        (StatusClass::Overloaded, "ServiceUnavailableException"),
        (StatusClass::ClientError, "ValidationException"),
        (StatusClass::ContextLength, "ValidationException"),
        // Timeout folds onto the stream-internal failure shape, NOT request-level
        // ModelTimeoutException (not a stream-union member).
        (StatusClass::Timeout, "ModelStreamErrorException"),
        // Auth / Billing have no stream-union counterpart → generic InternalServerException
        // (NOT AccessDeniedException / ServiceQuotaExceededException, which are request-level).
        (StatusClass::Auth, "InternalServerException"),
        (StatusClass::Billing, "InternalServerException"),
        (StatusClass::ServerError, "InternalServerException"),
        (StatusClass::Network, "InternalServerException"),
    ];

    for (class, expected) in cases {
        let err = crate::proto::IrError {
            class,
            provider_signal: Some("upstream detail".to_string()),
            retry_after: None,
        };
        // Exception-frame path.
        let (exc, msg) = writer
            .write_response_exception(&err)
            .expect("write_response_exception must map every class");
        assert_eq!(
            exc, expected,
            "class {class:?} must map to {expected} on the exception frame"
        );
        assert!(
            STREAM_UNION.contains(&exc.as_str()),
            "{exc} is not a ConverseStream output-union member"
        );
        assert_eq!(msg, "upstream detail", "message prefers provider_signal");

        // Fallback event-arm path uses the SAME stream union.
        let ev = IrStreamEvent::Error(crate::proto::IrError {
            class,
            provider_signal: None,
            retry_after: None,
        });
        let (et, payload) = writer
            .write_response_event(&ev)
            .expect("error event must emit a frame");
        assert_eq!(
            et, expected,
            "event-arm class {class:?} must also map to {expected}"
        );
        assert!(
            STREAM_UNION.contains(&et.as_str()),
            "{et} is not a ConverseStream output-union member"
        );
        // Falls back to the exception name when no provider_signal is present.
        assert_eq!(
            payload.get("message").and_then(|m| m.as_str()),
            Some(expected)
        );
    }

    // Explicitly assert the request-level-only shapes never appear on the stream path.
    for class in [
        StatusClass::Timeout,
        StatusClass::Auth,
        StatusClass::Billing,
    ] {
        let err = crate::proto::IrError {
            class,
            provider_signal: None,
            retry_after: None,
        };
        let (exc, _) = writer.write_response_exception(&err).unwrap();
        assert_ne!(exc, "ModelTimeoutException");
        assert_ne!(exc, "AccessDeniedException");
        assert_ne!(exc, "ServiceQuotaExceededException");
    }
}

/// Regression (class sweep — image `"image_url"` sentinel): a cross-protocol ingress
/// (OpenAI/Responses) parses an `https://…` image into the IR as
/// `Image{media_type: "image_url", data: <url>}`. The Bedrock Converse `image` block has no
/// arbitrary-URL source (only base64 `bytes` / `s3Location`), so the URL must NOT be stuffed into
/// `source.bytes` and labeled `format: "png"` (the old behavior — a corrupt block a native SDK
/// rejects). Such a block is DROPPED (with a trace), never mangled. A genuine base64 image is
/// still emitted natively.
#[test]
fn test_write_request_url_sentinel_image_not_emitted_as_base64() {
    let writer = BedrockWriter;

    // Top-level URL-sentinel image → dropped (no image block, no garbage bytes).
    let url = "https://example.com/cat.png";
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "look".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Url(url.to_string()),
                    cache_control: None,
                },
            ],
        }],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains(url),
        "URL must NOT be emitted as base64 image bytes; got {wire}"
    );
    assert!(
        !wire.contains("\"image\""),
        "no image block must be emitted for a URL sentinel; got {wire}"
    );
    // The accompanying text block still survives.
    assert_eq!(
        out.pointer("/messages/0/content/0/text")
            .and_then(|v| v.as_str()),
        Some("look")
    );

    // A genuine base64 image is still emitted natively.
    let req2 = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: "image/png".to_string(),
                    data: "QkFTRTY0".to_string(),
                },
                cache_control: None,
            }],
        }],
        ..req.clone()
    };
    let out2 = writer.write_request(&req2);
    assert_eq!(
        out2.pointer("/messages/0/content/0/image/format")
            .and_then(|v| v.as_str()),
        Some("png")
    );
    assert_eq!(
        out2.pointer("/messages/0/content/0/image/source/bytes")
            .and_then(|v| v.as_str()),
        Some("QkFTRTY0")
    );
}

/// Regression (R19 #16): a user/assistant turn whose blocks are ALL non-representable on the
/// Bedrock wire (here a user message holding only a URL-sentinel image) must NOT be silently
/// dropped. Dropping it loses turn structure and can break the strict user/assistant alternation
/// Bedrock Converse enforces. The writer mirrors the Anthropic writer by emitting a minimal
/// placeholder `{"text":""}` block so the turn (and its role) survives.
///
/// NOTE: a Thinking block is NO LONGER non-representable on Bedrock (R25 MED #3 re-emits it as a
/// native `reasoningContent` block), so the thinking-only assistant turn here now carries that
/// reasoningContent block — NOT a placeholder. The remaining turn (a URL-sentinel image) is still
/// non-representable and exercises the placeholder path.
#[test]
fn test_write_request_all_nonrepresentable_turn_kept_with_placeholder() {
    let writer = BedrockWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hello".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            // Assistant turn carrying ONLY a thinking block (now re-emitted as reasoningContent).
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Thinking {
                    text: "internal reasoning".to_string(),
                    signature: None,
                    redacted: false,
                    cache_control: None,
                }],
            },
            // User turn carrying ONLY a URL-sentinel image (also non-representable here).
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Url(
                        "https://example.com/cat.png".to_string(),
                    ),
                    cache_control: None,
                }],
            },
        ],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);

    // All three turns survive (old code dropped turns 1 and 2, yielding length 1).
    let msgs = out
        .get("messages")
        .and_then(|v| v.as_array())
        .expect("messages array present");
    assert_eq!(msgs.len(), 3, "no turn may be dropped; got {out:?}");

    // Roles preserved in order — alternation intact.
    assert_eq!(
        msgs[0].pointer("/role").and_then(|v| v.as_str()),
        Some("user")
    );
    assert_eq!(
        msgs[1].pointer("/role").and_then(|v| v.as_str()),
        Some("assistant")
    );
    assert_eq!(
        msgs[2].pointer("/role").and_then(|v| v.as_str()),
        Some("user")
    );

    // The assistant thinking-only turn now re-emits a native `reasoningContent` block (R25 MED
    // #3) — NOT a placeholder — so the turn survives carrying its reasoning rather than an empty
    // text stub.
    assert_eq!(
        msgs[1]
            .pointer("/content/0/reasoningContent/reasoningText/text")
            .and_then(|v| v.as_str()),
        Some("internal reasoning"),
        "thinking-only assistant turn must carry its reasoningContent block"
    );
    assert_eq!(
        msgs[1]
            .pointer("/content")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(1)
    );
    // The image-only (URL-sentinel) user turn IS still non-representable, so it keeps the
    // placeholder text block.
    assert_eq!(
        msgs[2].pointer("/content/0/text").and_then(|v| v.as_str()),
        Some(""),
        "image-only (URL-sentinel) user turn must carry a placeholder text block"
    );
}

// --- Round 6 regression tests --------------------------------------------------------------

/// Regression (findings 1+2 — SigV4 region derivation): the region is parsed robustly from the
/// endpoint host across every real Bedrock shape (vanilla, FIPS, VPC-interface front,
/// control-plane label), not just `bedrock-runtime.<region>.`. A host that yields no derivable
/// region returns `None` (the caller warns and falls back to us-east-1) rather than silently
/// guessing — so a mis-derived region is diagnosable instead of producing a confusing 403.
#[test]
fn test_derive_sigv4_region_shapes() {
    // Vanilla runtime endpoint.
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-east-1.amazonaws.com"),
        Some("us-east-1")
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.ap-southeast-2.amazonaws.com"),
        Some("ap-southeast-2")
    );
    // FIPS endpoint (previously fell back to us-east-1 → cross-region mis-sign).
    assert_eq!(
        derive_sigv4_region("bedrock-runtime-fips.eu-west-1.amazonaws.com"),
        Some("eu-west-1")
    );
    // VPC-interface endpoint front (does NOT start with the bare prefix).
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.eu-central-1.vpce.amazonaws.com"),
        Some("eu-central-1")
    );
    assert_eq!(
        derive_sigv4_region(
            "vpce-0a1b2c3d4e5f-9zyxw.bedrock-runtime.ca-central-1.vpce.amazonaws.com"
        ),
        Some("ca-central-1")
    );
    // Control-plane label, defensively handled.
    assert_eq!(
        derive_sigv4_region("bedrock.us-west-2.amazonaws.com"),
        Some("us-west-2")
    );

    // 4-part AWS partition regions: GovCloud and ISO. The old EXACTLY-3-parts parser rejected
    // every one of these and silently signed for us-east-1 (403 SignatureDoesNotMatch).
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-gov-west-1.amazonaws.com"),
        Some("us-gov-west-1")
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-gov-east-1.amazonaws.com"),
        Some("us-gov-east-1")
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime-fips.us-gov-west-1.amazonaws.com"),
        Some("us-gov-west-1")
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-iso-east-1.c2s.ic.gov"),
        Some("us-iso-east-1")
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-isob-east-1.sc2s.sgov.gov"),
        Some("us-isob-east-1")
    );

    // Non-derivable hosts → None (caller warns + falls back to us-east-1).
    assert_eq!(derive_sigv4_region("my-cname-front.example.com"), None);
    assert_eq!(derive_sigv4_region("10.0.0.5"), None);
    assert_eq!(derive_sigv4_region("localhost"), None);
    // A Bedrock label whose following token is not a region (custom front) → None, not a wrong
    // guess from a non-region label.
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.internal.corp.example.com"),
        None
    );
    // Still reject obvious non-regions even though the part-count rule relaxed: a 2-part token,
    // a non-numeric final part, and a numeric leading part all fail the alpha+...+digit shape.
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-east.amazonaws.com"),
        None
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.us-gov-west-foo.amazonaws.com"),
        None
    );
    assert_eq!(
        derive_sigv4_region("bedrock-runtime.1-gov-west-1.amazonaws.com"),
        None
    );
}

/// Regression (findings 1+2): a FIPS host in a non-us-east-1 region signs for THAT region's
/// scope, not the silent `us-east-1` default the old prefix-only parser produced (which AWS
/// rejects with SignatureDoesNotMatch). The signing crypto itself is covered by sigv4::tests;
/// here we assert the derived scope region in the Authorization header.
#[test]
fn test_bedrock_sigv4_fips_host_derives_correct_region() {
    let ctx = crate::proto::SigningContext {
        host: "bedrock-runtime-fips.eu-west-1.amazonaws.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET", &ctx);
    let auth = headers
        .iter()
        .find(|(k, _)| k.as_str() == "authorization")
        .map(|(_, v)| v.to_str().unwrap().to_string())
        .expect("authorization header");
    assert!(
        auth.contains("/eu-west-1/bedrock/aws4_request"), // golden wire-contract literal (kept bare on purpose)
        "FIPS host must derive eu-west-1 scope, not the us-east-1 default; got: {auth}"
    );
    assert!(
        !auth.contains("/us-east-1/"),
        "must NOT silently fall back to us-east-1 for a derivable FIPS host; got: {auth}"
    );
}

/// Regression (findings 1+2): a non-derivable host falls back to us-east-1 (signing still
/// proceeds, so a genuinely region-less endpoint is not failed closed) — the WARN is the
/// operator-visible signal, asserted indirectly via the resulting scope.
#[test]
fn test_bedrock_sigv4_undecodable_host_falls_back_to_us_east_1() {
    let ctx = crate::proto::SigningContext {
        host: "my-cname-front.example.com",
        canonical_uri: "/model/m/converse".to_string(),
        body: b"{}",
        timestamp_epoch: 1_440_938_160,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    let headers = crate::proto::bedrock::sigv4_sign_headers("AKID:SECRET", &ctx);
    let auth = headers
        .iter()
        .find(|(k, _)| k.as_str() == "authorization")
        .map(|(_, v)| v.to_str().unwrap().to_string())
        .expect("authorization header");
    assert!(
        auth.contains("/us-east-1/bedrock/aws4_request"), // golden wire-contract literal (kept bare on purpose)
        "non-derivable host falls back to the us-east-1 default scope; got: {auth}"
    );
}

/// Regression (finding 3 — metadata WITHOUT usage): a `metadata` frame that lacks a `usage` key
/// (a mock / Bedrock-compatible backend) must STILL emit the combined `MessageDelta` (consuming
/// the stop_reason buffered from the preceding `messageStop`) BEFORE the terminal `MessageStop`,
/// so a Bedrock→Anthropic translation keeps the native `message_delta`-before-`message_stop`
/// ordering and never loses the stop_reason. Previously the delta lived inside the `usage` guard,
/// so a usage-less metadata dropped the stop_reason and emitted a bare MessageStop.
#[test]
fn test_stream_metadata_without_usage_still_emits_delta_with_stop_reason() {
    use crate::ir::IrStreamEvent;

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    let events: Vec<_> = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": "Hi"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        // `metadata` arrives but carries NO `usage` key (mock backend).
        serde_json::json!({"type": "metadata", "metrics": {"latencyMs": 12}}),
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    // The combined MessageDelta must be present, carry the buffered stop_reason, and have
    // zero (harmless) usage since none was sent.
    let delta_idx = events
        .iter()
        .position(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
        .expect("a combined MessageDelta must be emitted even without usage");
    match &events[delta_idx] {
        IrStreamEvent::MessageDelta {
            stop_reason, usage, ..
        } => {
            assert_eq!(
                stop_reason,
                &Some(crate::ir::IrStopReason::EndTurn),
                "stop_reason buffered from messageStop must survive a usage-less metadata"
            );
            assert_eq!(usage.input_tokens, 0);
            assert_eq!(usage.output_tokens, 0);
        }
        other => panic!("expected MessageDelta, got {other:?}"),
    }

    // The terminal MessageStop must follow the delta (delta-before-stop ordering).
    let stop_idx = events
        .iter()
        .position(|e| matches!(e, IrStreamEvent::MessageStop))
        .expect("a terminal MessageStop must be emitted");
    assert!(
        delta_idx < stop_idx,
        "MessageDelta must precede MessageStop; got {events:?}"
    );
    // Exactly one terminal stop, and the buffered stop_reason was consumed.
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStop))
            .count(),
        1
    );
    assert!(
        state.pending_stop_reason.is_none(),
        "buffered stop_reason must be consumed by the delta"
    );
}

/// Regression (class sweep — image sentinel inside a toolResult): the same URL-sentinel guard
/// applies to an `Image` nested in a `ToolResult`'s content — it must be dropped, not mangled
/// into a base64 `image` block, while a base64 image inside a toolResult is still emitted.
#[test]
fn test_write_request_tool_result_url_sentinel_image_dropped() {
    let writer = BedrockWriter;
    let url = "https://example.com/in-tool.png";
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Tool,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "t1".to_string(),
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "result".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Url(url.to_string()),
                        cache_control: None,
                    },
                ],
                is_error: false,
                cache_control: None,
            }],
        }],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains(url),
        "URL sentinel inside toolResult must not be emitted as base64; got {wire}"
    );
    // The text content of the toolResult still survives.
    assert_eq!(
        out.pointer("/messages/0/content/0/toolResult/content/0/text")
            .and_then(|v| v.as_str()),
        Some("result")
    );
    // Only the text inner block survives (the URL image was dropped).
    assert_eq!(
        out.pointer("/messages/0/content/0/toolResult/content")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(1),
        "URL-sentinel image inner block must be dropped; got {out}"
    );
}

/// Regression (class sweep — maxTokens overflow): a `maxTokens` value above u32::MAX must be
/// dropped to None (backend applies its default) rather than silently TRUNCATED (wrapped) into
/// an arbitrary smaller cap by a bare `as u32`. Mirrors the hardened Gemini reader; an in-range
/// value and the `> 0` filter are still honored.
#[test]
fn test_read_request_max_tokens_overflow_dropped_not_truncated() {
    let reader = BedrockReader;

    // Above u32::MAX → dropped to None (no truncation to 705_032_704).
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 5_000_000_000u64}
    });
    let ir = reader.read_request(&body).unwrap();
    assert_eq!(
        ir.max_tokens, None,
        "maxTokens above u32::MAX must drop to None, not wrap; got {:?}",
        ir.max_tokens
    );

    // Exactly u32::MAX is in range and preserved.
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": u32::MAX as u64}
    });
    let ir = reader.read_request(&body).unwrap();
    assert_eq!(ir.max_tokens, Some(u32::MAX));

    // Zero is still filtered out (> 0 guard).
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 0}
    });
    let ir = reader.read_request(&body).unwrap();
    assert_eq!(ir.max_tokens, None);
}

/// Regression (reader, S3 image source): a message-level `image` block whose source is
/// `s3Location` (not `bytes`) must be captured under the `image_s3` sentinel — not dropped with
/// `data = ""` — so a same-protocol passthrough re-emits `source.s3Location` faithfully.
#[test]
fn test_read_request_image_s3_location_captured() {
    let reader = BedrockReader;
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [{
                "image": {
                    "format": "jpeg",
                    "source": {
                        "s3Location": {
                            "uri": "s3://my-bucket/img.jpg",
                            "bucketOwner": "123456789012"
                        }
                    }
                }
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let block = &ir.messages[0].content[0];
    match block {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Vendor { vendor, value },
            ..
        } => {
            assert_eq!(
                *vendor, "bedrock",
                "S3-source image is a bedrock vendor reference"
            );
            assert_eq!(
                value.pointer("/s3Location/uri").and_then(|v| v.as_str()),
                Some("s3://my-bucket/img.jpg")
            );
            assert_eq!(
                value
                    .pointer("/s3Location/bucketOwner")
                    .and_then(|v| v.as_str()),
                Some("123456789012")
            );
            assert_eq!(
                value.pointer("/format").and_then(|v| v.as_str()),
                Some("jpeg")
            );
        }
        other => panic!("expected Image(Vendor) block, got {other:?}"),
    }
}

/// Regression (round-trip, S3 image source): a Bedrock body carrying an S3-sourced image must
/// survive a reader→writer round-trip with its `source.s3Location` (uri + bucketOwner) and
/// `format` intact — the old reader dropped the source, so the writer emitted nothing.
#[test]
fn test_image_s3_location_round_trip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [{
                "image": {
                    "format": "png",
                    "source": {
                        "s3Location": {
                            "uri": "s3://b/k.png",
                            "bucketOwner": "999988887777"
                        }
                    }
                }
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let out = writer.write_request(&ir);
    let img = out
        .pointer("/messages/0/content/0/image")
        .expect("image block must be re-emitted, not dropped");
    assert_eq!(
        img.pointer("/format").and_then(|v| v.as_str()),
        Some("png"),
        "format must round-trip; got {img}"
    );
    assert_eq!(
        img.pointer("/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://b/k.png"),
        "s3Location.uri must round-trip; got {img}"
    );
    assert_eq!(
        img.pointer("/source/s3Location/bucketOwner")
            .and_then(|v| v.as_str()),
        Some("999988887777"),
        "s3Location.bucketOwner must round-trip; got {img}"
    );
    // The sentinel media_type must never leak onto the wire.
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("image_s3"),
        "the image_s3 sentinel must not appear on the wire; got {wire}"
    );
    // No empty/base64 `bytes` source for an S3 image.
    assert!(
        img.pointer("/source/bytes").is_none(),
        "an S3 image must not be emitted with a bytes source; got {img}"
    );
}

/// Regression (reader, toolResult image): an `image` block inside a `toolResult.content` array
/// must be decoded into an IR Image — symmetric with the writer's toolResult-image emission.
/// The old reader skipped any non-text/json inner block, silently dropping image tool results.
#[test]
fn test_read_request_tool_result_decodes_image() {
    let reader = BedrockReader;
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [{
                "toolResult": {
                    "toolUseId": "t1",
                    "status": "success",
                    "content": [
                        {"text": "see image"},
                        {"image": {"format": "png", "source": {"bytes": "QQ=="}}}
                    ]
                }
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::ToolResult { content, .. } => {
            assert_eq!(
                content.len(),
                2,
                "both inner blocks must decode; got {content:?}"
            );
            match &content[1] {
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 { media_type, data },
                    ..
                } => {
                    assert_eq!(media_type, "image/png");
                    assert_eq!(data, "QQ==");
                }
                other => panic!("expected inner Image block, got {other:?}"),
            }
        }
        other => panic!("expected ToolResult block, got {other:?}"),
    }
}

/// Regression (round-trip, toolResult image): an S3-sourced image inside a toolResult survives
/// reader→writer with its `source.s3Location` intact (the writer already emits `image` inside a
/// toolResult; the reader must now decode it symmetrically).
#[test]
fn test_tool_result_image_s3_round_trip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [{
                "toolResult": {
                    "toolUseId": "t9",
                    "status": "success",
                    "content": [
                        {"image": {"format": "gif", "source": {"s3Location": {"uri": "s3://x/y.gif"}}}}
                    ]
                }
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let out = writer.write_request(&ir);
    let inner = out
        .pointer("/messages/0/content/0/toolResult/content/0/image")
        .expect("toolResult image must round-trip, not be dropped");
    assert_eq!(
        inner.pointer("/format").and_then(|v| v.as_str()),
        Some("gif")
    );
    assert_eq!(
        inner
            .pointer("/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://x/y.gif"),
        "toolResult s3Location.uri must round-trip; got {inner}"
    );
}

/// Regression (writer): `bedrock_image_block` re-emits `source.s3Location` for a Bedrock-produced
/// vendor reference (`{format, s3Location}`), and DROPS a vendor reference from another protocol
/// (no Bedrock projection) rather than corrupting the source.
#[test]
fn test_bedrock_image_block_s3_vendor() {
    let source = crate::ir::IrImageSource::Vendor {
        vendor: "bedrock",
        value: serde_json::json!({
            "format": "png",
            "s3Location": { "uri": "s3://bk/i.png", "bucketOwner": "111122223333" }
        }),
    };
    let block = bedrock_image_block(&source).expect("bedrock vendor ref must emit a block");
    assert_eq!(
        block.pointer("/format").and_then(|f| f.as_str()),
        Some("png")
    );
    assert_eq!(
        block
            .pointer("/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://bk/i.png")
    );
    assert_eq!(
        block
            .pointer("/source/s3Location/bucketOwner")
            .and_then(|v| v.as_str()),
        Some("111122223333")
    );
    // A vendor reference produced by ANOTHER protocol has no Bedrock projection → dropped.
    let foreign = crate::ir::IrImageSource::Vendor {
        vendor: "responses",
        value: serde_json::json!({ "file_id": "x" }),
    };
    assert!(
        bedrock_image_block(&foreign).is_none(),
        "a foreign vendor ref must be dropped"
    );
}

// --- Round 18 regression tests: prompt-cache token plumbing -------------------------------

/// Regression (reader, non-streaming): a Converse response `usage` carrying
/// `cacheReadInputTokens` / `cacheWriteInputTokens` must surface them on the IR usage as
/// `cache_read_input_tokens` / `cache_creation_input_tokens`. The old reader hardcoded both
/// to `None`, silently dropping real prompt-cache accounting — this asserts the real values
/// round-trip out of the read path.
#[test]
fn test_read_response_plumbs_cache_tokens() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10,
            "outputTokens": 5,
            "totalTokens": 15,
            "cacheReadInputTokens": 64,
            "cacheWriteInputTokens": 128
        }
    });
    let resp = reader.read_response(&j).expect("read_response");
    assert_eq!(
        resp.usage.cache_read_input_tokens,
        Some(64),
        "cacheReadInputTokens must map to cache_read_input_tokens (was hardcoded None)"
    );
    assert_eq!(
        resp.usage.cache_creation_input_tokens,
        Some(128),
        "cacheWriteInputTokens must map to cache_creation_input_tokens (was hardcoded None)"
    );
}

/// Regression (reader): an absent cache field stays `None` (not `Some(0)`), so a no-cache
/// response is distinguishable from a zero-token cache hit.
#[test]
fn test_read_response_absent_cache_tokens_are_none() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
    });
    let resp = reader.read_response(&j).expect("read_response");
    assert_eq!(resp.usage.cache_read_input_tokens, None);
    assert_eq!(resp.usage.cache_creation_input_tokens, None);
}

/// Regression (reader, streaming): the `metadata` event's `usage` cache fields must surface on
/// the combined MessageDelta's IR usage (old code hardcoded both to `None`).
#[test]
fn test_read_stream_metadata_plumbs_cache_tokens() {
    use crate::ir::IrStreamEvent;
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;
    let events: Vec<IrStreamEvent> = [
        serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        serde_json::json!({
            "type": "metadata",
            "usage": {
                "inputTokens": 3,
                "outputTokens": 1,
                "cacheReadInputTokens": 9,
                "cacheWriteInputTokens": 17
            }
        }),
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    let usage = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("a combined MessageDelta must be emitted");
    assert_eq!(usage.cache_read_input_tokens, Some(9));
    assert_eq!(usage.cache_creation_input_tokens, Some(17));
}

/// Regression (writer, non-streaming): IR usage cache fields must be emitted as
/// `cacheReadInputTokens` / `cacheWriteInputTokens` on the native body (old writer omitted
/// them entirely), and a full read→write round-trip of a cache-bearing usage is byte-identical.
#[test]
fn test_write_response_emits_cache_tokens_roundtrip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let j = serde_json::json!({
        "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10,
            "outputTokens": 5,
            "totalTokens": 15,
            "cacheReadInputTokens": 64,
            "cacheWriteInputTokens": 128
        }
    });
    let resp = reader.read_response(&j).expect("read_response");
    let written = writer.write_response(&resp);
    assert_eq!(
        written
            .pointer("/usage/cacheReadInputTokens")
            .and_then(|v| v.as_u64()),
        Some(64),
        "writer must emit cacheReadInputTokens (was omitted)"
    );
    assert_eq!(
        written
            .pointer("/usage/cacheWriteInputTokens")
            .and_then(|v| v.as_u64()),
        Some(128),
        "writer must emit cacheWriteInputTokens (was omitted)"
    );
    assert_eq!(
        written, j,
        "cache-bearing round-trip must be byte-identical"
    );
}

/// Regression (writer): a `None` cache field is OMITTED, not serialized as `0` — so a no-cache
/// response stays byte-identical to native AWS (which omits the fields when caching was idle).
#[test]
fn test_write_response_omits_absent_cache_tokens() {
    let writer = BedrockWriter;
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
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
    let written = writer.write_response(&resp);
    assert!(
        written.pointer("/usage/cacheReadInputTokens").is_none(),
        "absent cache_read must not be emitted as 0"
    );
    assert!(
        written.pointer("/usage/cacheWriteInputTokens").is_none(),
        "absent cache_creation must not be emitted as 0"
    );
}

/// Regression (writer, streaming): a usage-only MessageDelta carrying cache fields must emit
/// them on the `metadata` frame's `usage` (old writer dropped them).
#[test]
fn test_write_stream_metadata_emits_cache_tokens() {
    let writer = BedrockWriter;
    let usage_only = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_creation_input_tokens: Some(40),
            cache_read_input_tokens: Some(20),
        },
    };
    let (et, payload) = writer
        .write_response_event(&usage_only)
        .expect("usage-only delta must emit a frame");
    assert_eq!(et, "metadata");
    assert_eq!(
        payload
            .pointer("/usage/cacheReadInputTokens")
            .and_then(|v| v.as_u64()),
        Some(20)
    );
    assert_eq!(
        payload
            .pointer("/usage/cacheWriteInputTokens")
            .and_then(|v| v.as_u64()),
        Some(40)
    );
    // The pre-existing token fields are unaffected.
    assert_eq!(
        payload
            .pointer("/usage/inputTokens")
            .and_then(|v| v.as_u64()),
        Some(11)
    );
    assert_eq!(
        payload
            .pointer("/usage/totalTokens")
            .and_then(|v| v.as_u64()),
        Some(18)
    );
}

/// Regression (R20 MED #7): native Converse `cachePoint` blocks (the prompt-cache markers) that
/// appear inside the `system` array and inside a message's `content` array were SILENTLY DROPPED
/// by `read_request` (no IR `IrBlock` counterpart), so a same-protocol Bedrock->Bedrock
/// passthrough re-emitted a body with prompt caching disabled — a real cost regression (a cache
/// HIT becomes a full re-bill of the cached prefix every turn). They must now survive the
/// read->write round-trip at their ORIGINAL positions. This test FAILS against the old code
/// (the cachePoint blocks vanish) and passes after.
#[test]
fn test_cache_point_round_trip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let wire = serde_json::json!({
        "system": [
            {"text": "you are a helpful assistant with a long static preamble"},
            {"cachePoint": {"type": "default"}}
        ],
        "messages": [
            {"role": "user", "content": [
                {"text": "first big doc"},
                {"cachePoint": {"type": "default"}},
                {"text": "now the question"}
            ]},
            {"role": "assistant", "content": [
                {"text": "an answer"}
            ]}
        ]
    });

    let ir = reader.read_request(&wire).expect("read_request");
    // The markers are stashed under the busbar-internal sentinel (Bedrock-native, no
    // cross-protocol meaning — so it lives in `extra`, not a first-class IR field).
    assert!(
        ir.extra.contains_key(CACHE_POINTS_SENTINEL),
        "cachePoint markers must be captured into extra; got {:?}",
        ir.extra
    );

    let out = writer.write_request(&ir);
    // The sentinel must NEVER leak onto the wire.
    assert!(
        out.get(CACHE_POINTS_SENTINEL).is_none(),
        "the cachePoint sentinel must not appear on the wire; got {out}"
    );
    // The whole body round-trips byte-identically: every cachePoint re-emitted at its position.
    assert_eq!(
        out, wire,
        "cachePoint markers must survive the round-trip at their original positions; got {out}"
    );
}

/// Regression (R20 MED #7): a message whose ONLY content block is a `cachePoint` (no
/// representable text/tool block) must re-emit the marker rather than the empty-content `""`
/// placeholder — the splice runs BEFORE the placeholder substitution, so the cachePoint keeps
/// the turn non-empty and the prompt-cache boundary intact.
#[test]
fn test_cache_point_only_message_round_trip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let wire = serde_json::json!({
        "messages": [
            {"role": "user", "content": [
                {"text": "context block"}
            ]},
            {"role": "user", "content": [
                {"cachePoint": {"type": "default"}}
            ]}
        ]
    });

    let ir = reader.read_request(&wire).expect("read_request");
    let out = writer.write_request(&ir);
    // The input carries two CONSECUTIVE `user` messages — a shape Bedrock Converse itself rejects
    // (roles must alternate). The F4 alternation fix coalesces them into ONE user turn, appending
    // the cachePoint AFTER the text block: the canonical, Bedrock-valid placement with identical
    // cache semantics (cache the prefix up to this point). The marker MUST survive the merge — the
    // original concern was that a cachePoint-only turn would degrade to a bare `text:""` placeholder
    // and LOSE the marker. (A pristine same-protocol Bedrock request never reaches this writer in
    // production: it takes the verbatim serialize short-circuit, so its exact bytes are preserved.)
    assert_eq!(
            out,
            serde_json::json!({
                "messages": [
                    {"role": "user", "content": [
                        {"text": "context block"},
                        {"cachePoint": {"type": "default"}}
                    ]}
                ]
            }),
            "consecutive user turns must coalesce (alternation) while preserving the cachePoint; got {out}"
        );
    // The cachePoint marker must still be present (not dropped to a bare text "").
    assert_eq!(
        out.pointer("/messages/0/content/1/cachePoint"),
        Some(&serde_json::json!({"type": "default"})),
        "the merged turn must carry the cachePoint marker; got {out}"
    );
}

/// A request that NEVER used prompt caching must not gain a stray sentinel key, and its body must
/// round-trip byte-identically (the cachePoint capture is opt-in: zero markers → no `extra`
/// entry, no behavioural change).
#[test]
fn test_no_cache_point_no_sentinel() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let wire = serde_json::json!({
        "system": [{"text": "plain system"}],
        "messages": [{"role": "user", "content": [{"text": "hi"}]}]
    });

    let ir = reader.read_request(&wire).expect("read_request");
    assert!(
        !ir.extra.contains_key(CACHE_POINTS_SENTINEL),
        "no cachePoint marker → no sentinel key; got {:?}",
        ir.extra
    );
    let out = writer.write_request(&ir);
    assert_eq!(
        out, wire,
        "cache-free body must round-trip byte-identically"
    );
}

/// `splice_cache_points` must NOT panic on a stale/foreign index (e.g. an `extra` that survived
/// an unexpected hop): an out-of-range `i` is bounds-clamped to the array end, never indexing
/// past it. Guards the no-panic-on-the-request-path rule.
#[test]
fn test_splice_cache_points_out_of_range_does_not_panic() {
    let mut arr = vec![serde_json::json!({"text": "only block"})];
    let entries = vec![
        serde_json::json!({"i": 999, "block": {"cachePoint": {"type": "default"}}}),
        // Missing fields are skipped, not panicked on.
        serde_json::json!({"block": {"cachePoint": {"type": "default"}}}),
        serde_json::json!({"i": 0}),
    ];
    splice_cache_points(&mut arr, &entries);
    // The valid (clamped) entry landed at the end; the malformed ones were skipped.
    assert_eq!(arr.len(), 2);
    assert_eq!(
        arr[1].pointer("/cachePoint"),
        Some(&serde_json::json!({"type": "default"}))
    );
}

// --- Round 21 regression tests: audit findings --------------------------------------------

/// Regression (R21 #1, ContextLength reachability): `extract_error` must synthesize the canonical
/// `context_length_exceeded` provider_code for a real Bedrock oversized-context error body.
/// Bedrock returns a generic `ValidationException` whose `message` carries the signal; the
/// PRODUCTION `extract_error` (not just the `#[cfg(test)]` classify helper) must detect it so the
/// breaker maps it to `StatusClass::ContextLength` and fails over without penalizing the lane.
#[test]
fn test_extract_error_synthesizes_context_length_exceeded() {
    let reader = BedrockReader;
    // The real AWS Bedrock validation message for an oversized request.
    let body = br#"{"__type":"ValidationException","message":"Input is longer than the maximum number of tokens allowed (200000) for this model."}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "an oversized-context ValidationException must surface the canonical \
             context_length_exceeded code; got {raw:?}"
    );

    // The alternate "maximum-tokens … requested" phrasing is also recognized.
    let body2 = br#"{"__type":"ValidationException","message":"The maximum-tokens limit was exceeded: 250000 requested."}"#;
    let raw2 = reader.extract_error(StatusCode::BAD_REQUEST, body2);
    assert_eq!(
            raw2.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "the maximum-tokens/requested phrasing must also map to context_length_exceeded; got {raw2:?}"
        );

    // A plain validation error (not context-length) keeps its human-readable message code —
    // the context-length scan must not over-trigger.
    let body3 =
        br#"{"__type":"ValidationException","message":"malformed request: unknown field foo"}"#;
    let raw3 = reader.extract_error(StatusCode::BAD_REQUEST, body3);
    assert_eq!(
        raw3.provider_code.as_deref(),
        Some("malformed request: unknown field foo"),
        "a non-context-length validation error must keep its message; got {raw3:?}"
    );
}

/// Regression (R21 #2, ordering invariant): the `contentBlockStart` toolUse arm must honor the
/// same `state.started` guard the text branch enforces — a tool BlockStart must NEVER precede the
/// MessageStart it belongs to. A `contentBlockStart` carrying a `toolUse` that arrives BEFORE
/// `messageStart` (reordered/malformed stream) must emit NO BlockStart.
#[test]
fn test_stream_tool_block_start_before_message_start_is_dropped() {
    use crate::ir::IrStreamEvent;
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    // toolUse contentBlockStart BEFORE any messageStart: state.started is false → drop it.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
        }),
        &mut state,
    );
    assert!(
        !evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { .. },
                ..
            }
        )),
        "a tool BlockStart must not precede MessageStart; got {evs:?}"
    );

    // After a proper messageStart, the same toolUse start DOES emit a BlockStart (sanity).
    let _ = reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStart", "role": "assistant"}),
        &mut state,
    );
    let evs2 = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
        }),
        &mut state,
    );
    assert!(
        evs2.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { .. },
                ..
            }
        )),
        "after messageStart, a toolUse start must emit a ToolUse BlockStart; got {evs2:?}"
    );
}

/// Regression (R21 #3, json tool-result fidelity): a native Converse `{"json": <value>}` block
/// inside a `toolResult.content` array must survive a same-protocol reader→writer round-trip as a
/// `json` block — NOT be collapsed to a `text` block (the old behaviour, which lost the json/text
/// distinction). Mirrors the image-sentinel round-trip.
#[test]
fn test_tool_result_json_block_round_trip() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [{
                "toolResult": {
                    "toolUseId": "t1",
                    "status": "success",
                    "content": [
                        {"json": {"temperature": 72, "unit": "F", "nested": {"ok": true}}}
                    ]
                }
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let out = writer.write_request(&ir);
    let inner = out
        .pointer("/messages/0/content/0/toolResult/content/0/json")
        .expect("toolResult json block must round-trip as `json`, not be collapsed to text");
    assert_eq!(
        inner,
        &serde_json::json!({"temperature": 72, "unit": "F", "nested": {"ok": true}}),
        "the json tool-result value must round-trip verbatim; got {inner}"
    );
    // It must NOT have been re-emitted as a `text` block.
    assert!(
        out.pointer("/messages/0/content/0/toolResult/content/0/text")
            .is_none(),
        "a json tool-result block must not degrade to a text block; got {out}"
    );
}

/// Regression (R22 LOW #24, index clamp): the upstream-controlled `contentBlockIndex` is
/// attacker-controllable and was forwarded UNCLAMPED into IR block indices at all three stream
/// read sites (`contentBlockStart` / `contentBlockDelta` / `contentBlockStop`). A malicious huge
/// index must now be clamped to `MAX_CONTENT_BLOCK_INDEX` before it reaches the IR, so a
/// downstream ingress writer can never be driven to track/allocate against a pathological index.
#[test]
fn test_stream_huge_content_block_index_is_clamped() {
    use crate::ir::IrStreamEvent;
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    // Open the stream so the BlockStart `state.started` guard passes.
    let _ = reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStart", "role": "assistant"}),
        &mut state,
    );

    let huge = u64::MAX;
    let expected = MAX_CONTENT_BLOCK_INDEX as usize;

    // contentBlockStart (text shape: empty `start` object).
    let start = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": huge,
            "start": {}
        }),
        &mut state,
    );
    let start_idx = start.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart { index, .. } => Some(*index),
        _ => None,
    });
    assert_eq!(
        start_idx,
        Some(expected),
        "a huge contentBlockIndex on contentBlockStart must be clamped to \
             MAX_CONTENT_BLOCK_INDEX; got {start:?}"
    );

    // contentBlockDelta.
    let delta = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": huge,
            "delta": {"text": "hi"}
        }),
        &mut state,
    );
    let delta_idx = delta.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta { index, .. } => Some(*index),
        _ => None,
    });
    assert_eq!(
        delta_idx,
        Some(expected),
        "a huge contentBlockIndex on contentBlockDelta must be clamped; got {delta:?}"
    );

    // contentBlockStop.
    let stop = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStop",
            "contentBlockIndex": huge
        }),
        &mut state,
    );
    let stop_idx = stop.iter().find_map(|e| match e {
        IrStreamEvent::BlockStop { index } => Some(*index),
        _ => None,
    });
    assert_eq!(
        stop_idx,
        Some(expected),
        "a huge contentBlockIndex on contentBlockStop must be clamped; got {stop:?}"
    );
}

/// Regression (R22 LOW #12, classify/extract_error lockstep): the `#[cfg(test)]` `classify`
/// helper must recognize EVERY context-length phrasing the production `extract_error` does. R21
/// #17 added a third pattern (`exceeds the maximum` + token/context) to `extract_error` but not
/// to `classify`, so the two drifted. The classifier must now map that third phrasing to
/// `StatusClass::ContextLength`, identically to `extract_error`.
#[test]
fn test_classify_third_context_length_pattern_matches_extract_error() {
    let reader = BedrockReader;
    // The third phrasing (R21 #17): "exceeds the maximum" + token/context.
    let body = br#"{"__type":"ValidationException","message":"The request exceeds the maximum context length for this model."}"#;

    // Production extract_error surfaces the canonical code...
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "extract_error must recognize the `exceeds the maximum` phrasing; got {raw:?}"
    );

    // ...and the test-only classify must agree (lockstep).
    let signal = reader.classify(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        signal.class,
        StatusClass::ContextLength,
        "classify must map the `exceeds the maximum` phrasing to ContextLength, in lockstep \
             with extract_error; got {signal:?}"
    );
    assert_eq!(
        signal.provider_signal.as_deref(),
        Some("context_length_exceeded"),
        "classify must surface the canonical context_length_exceeded signal; got {signal:?}"
    );

    // The "token" branch variant also matches.
    let body_tok = br#"{"__type":"ValidationException","message":"Prompt exceeds the maximum number of input tokens."}"#;
    let signal_tok = reader.classify(StatusCode::BAD_REQUEST, body_tok);
    assert_eq!(
        signal_tok.class,
        StatusClass::ContextLength,
        "classify must match the token variant of the third pattern; got {signal_tok:?}"
    );
}

// --- Round 23 regression tests: audit findings --------------------------------------------

/// Regression (R23 LOW #14, context-length body-scan gate): the `extract_error` context-length
/// override must be GATED on a `400` — Bedrock only emits an oversized-context error as a `400
/// ValidationException`. A 5xx whose body merely echoes context-length phrasing (an upstream
/// server-error envelope quoting the request) must NOT be reclassified as
/// `context_length_exceeded`: that would trigger a no-penalty failover masking an unhealthy
/// lane. The 5xx must keep its structured signal so the breaker maps it to ServerError.
#[test]
fn test_extract_error_5xx_context_phrasing_not_reclassified() {
    let reader = BedrockReader;
    // A 5xx whose body happens to contain the canonical context-length phrasing.
    let body = br#"{"__type":"InternalServerException","message":"Input is longer than the maximum number of tokens allowed (200000) for this model."}"#;

    let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, body);
    assert_ne!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 5xx body must NEVER be reclassified as context_length_exceeded; got {raw:?}"
    );
    assert_eq!(
        raw.http_status, 500,
        "the 5xx status must be preserved; got {raw:?}"
    );

    // Sanity: the SAME phrasing on a real 400 ValidationException IS still recognized (the gate
    // does not break the legitimate path).
    let raw_400 = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw_400.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 400 with context-length phrasing must still surface the canonical code; got {raw_400:?}"
    );

    // The test-only `classify` helper must agree (lockstep): a 5xx with the phrasing classifies
    // as ServerError, not ContextLength.
    let signal = reader.classify(StatusCode::INTERNAL_SERVER_ERROR, body);
    assert_eq!(
        signal.class,
        StatusClass::ServerError,
        "classify must map a 5xx context-phrasing body to ServerError, in lockstep with \
             extract_error; got {signal:?}"
    );
}

/// Regression (R23 LOW #15, response image completeness): the `read_response` content loop must
/// carry an `image` block from a Converse response into the IR — the request-side readers
/// already decode `image` via `read_bedrock_image_block`, but the response loop silently DROPPED
/// it. A base64 `source.bytes` image in the assistant message must surface as an
/// `IrBlock::Image`, and an `source.s3Location` image must surface under the `image_s3` sentinel.
#[test]
fn test_read_response_carries_image_block() {
    let reader = BedrockReader;

    // base64 source.bytes image in the response message content.
    let body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "here is the chart"},
                    {"image": {"format": "png", "source": {"bytes": "AAAA"}}}
                ]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 2}
    });
    let ir = reader.read_response(&body).expect("read_response");
    let img = ir.content.iter().find_map(|b| match b {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => Some((media_type, data)),
        _ => None,
    });
    assert_eq!(
        img,
        Some((&"image/png".to_string(), &"AAAA".to_string())),
        "a base64 response image must be carried into IR as an Image block; got {:?}",
        ir.content
    );

    // s3Location source: surfaces under the image_s3 sentinel (stashed for faithful re-emit).
    let body_s3 = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"image": {"format": "jpeg", "source": {"s3Location": {"uri": "s3://b/k"}}}}
                ]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 2}
    });
    let ir_s3 = reader.read_response(&body_s3).expect("read_response s3");
    let has_s3 = ir_s3.content.iter().any(|b| {
        matches!(
            b,
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Vendor {
                    vendor: "bedrock",
                    ..
                },
                ..
            }
        )
    });
    assert!(
        has_s3,
        "an s3Location response image must be carried into IR under the image_s3 sentinel; \
             got {:?}",
        ir_s3.content
    );
}

/// Regression (R25 MED #3): a native Converse `reasoningContent` (extended-thinking) block in a
/// REQUEST message's `content[]` was SILENTLY DROPPED by `read_request` (no arm matched it), so a
/// same-protocol Bedrock->Bedrock passthrough lost the signed reasoning Bedrock requires echoed
/// back on a follow-up turn. It must now round-trip: reader carries it into IR `Thinking`, writer
/// re-emits `reasoningContent`. FAILS against the old code (the block vanishes) and passes after.
#[test]
fn test_request_reasoning_content_round_trips() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"reasoningContent": {"reasoningText": {"text": "let me think", "signature": "sig-abc"}}},
                    {"text": "the answer is 42"}
                ]
            }
        ]
    });
    let ir = reader.read_request(&body).expect("read_request");
    // Reader carried reasoningContent into an IR Thinking block with the signature preserved.
    let thinking = ir.messages[0].content.iter().find_map(|b| match b {
        crate::ir::IrBlock::Thinking {
            text, signature, ..
        } => Some((text, signature)),
        _ => None,
    });
    assert_eq!(
        thinking,
        Some((&"let me think".to_string(), &Some("sig-abc".to_string()))),
        "reasoningContent must be carried into IR as a Thinking block; got {:?}",
        ir.messages[0].content
    );
    let out = writer.write_request(&ir);
    // Writer re-emits the reasoningContent block at the head of the content array.
    assert_eq!(
        out.pointer("/messages/0/content/0/reasoningContent/reasoningText/text")
            .and_then(|v| v.as_str()),
        Some("let me think"),
        "reasoningContent text must survive the round-trip; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/reasoningContent/reasoningText/signature")
            .and_then(|v| v.as_str()),
        Some("sig-abc"),
        "reasoningContent signature must survive the round-trip; got {out}"
    );
    assert_eq!(
        out, body,
        "a reasoningContent-bearing request must round-trip byte-identically; got {out}"
    );
}

/// Regression (R25 MED #3): a `reasoningContent` block in a RESPONSE message's `content[]` was
/// silently dropped by `read_response`. It must now round-trip through read->write. Also covers
/// the `redactedContent` member (carried via the redacted-signature sentinel) so a redacted
/// reasoning block re-emits as `redactedContent`, not a plaintext `reasoningText`.
#[test]
fn test_response_reasoning_content_round_trips() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"reasoningContent": {"reasoningText": {"text": "reasoning", "signature": "rs-1"}}},
                    {"text": "final"}
                ]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 3, "outputTokens": 4, "totalTokens": 7}
    });
    let ir = reader.read_response(&body).expect("read_response");
    assert!(
        ir.content.iter().any(|b| matches!(
            b,
            crate::ir::IrBlock::Thinking { text, signature , .. }
                if text == "reasoning" && signature.as_deref() == Some("rs-1")
        )),
        "response reasoningContent must be carried into IR as a Thinking block; got {:?}",
        ir.content
    );
    let out = writer.write_response(&ir);
    assert_eq!(
        out, body,
        "a reasoningContent-bearing response must round-trip byte-identically; got {out}"
    );

    // redactedContent: carried via the sentinel signature, re-emitted as redactedContent.
    let redacted_body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"reasoningContent": {"redactedContent": "RVhBTVBMRQ=="}},
                    {"text": "ok"}
                ]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}
    });
    let ir_r = reader.read_response(&redacted_body).expect("read redacted");
    assert!(
        ir_r.content.iter().any(|b| matches!(
            b,
            crate::ir::IrBlock::Thinking { text, redacted: true, .. }
                if text == "RVhBTVBMRQ=="
        )),
        "redactedContent must be carried under the redacted-signature sentinel; got {:?}",
        ir_r.content
    );
    let out_r = writer.write_response(&ir_r);
    assert_eq!(
            out_r.pointer("/output/message/content/0/reasoningContent/redactedContent")
                .and_then(|v| v.as_str()),
            Some("RVhBTVBMRQ=="),
            "a redacted reasoning block must re-emit as redactedContent, not reasoningText; got {out_r}"
        );
    assert!(
        out_r
            .pointer("/output/message/content/0/reasoningContent/reasoningText")
            .is_none(),
        "a redacted reasoning block must NOT leak as a plaintext reasoningText; got {out_r}"
    );
}

/// Regression (R26 MED #3/#4): STREAMING extended-thinking (`reasoningContent` deltas on the
/// ConverseStream wire) was SILENTLY DROPPED — `read_response_events` had no reasoning arm and
/// `write_response_event` returned `None` for ThinkingDelta/SignatureDelta — even though the
/// BUFFERED path (R25) preserved it. The streaming path must now mirror the buffered logic: the
/// reader lazily opens a Thinking block on the first `reasoningContent` delta and emits
/// ThinkingDelta/SignatureDelta; the writer re-emits them as `reasoningContent` frames. This test
/// drives a full plaintext-reasoning ConverseStream through read->IR->write and asserts each IR
/// reasoning event round-trips to its native frame. FAILS against the old code (no BlockStart for
/// the reasoning block; ThinkingDelta/SignatureDelta produce no frame) and passes after.
#[test]
fn test_stream_reasoning_content_round_trips() {
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};

    let reader = BedrockReader;
    let writer = BedrockWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    // A native ConverseStream that streams a reasoning block (text deltas then a signature) and
    // then a normal text answer. The reasoning block is implied by its first `reasoningContent`
    // delta (no dedicated `contentBlockStart` on the wire), exactly as AWS streams it.
    let frames = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"reasoningContent": {"text": "let me "}}
        }),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"reasoningContent": {"text": "think"}}
        }),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"reasoningContent": {"signature": "sig-xyz"}}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 1, "start": {}}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 1,
            "delta": {"text": "the answer"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 1}),
    ];

    let events: Vec<IrStreamEvent> = frames
        .into_iter()
        .flat_map(|f| reader.read_response_events("", &f, &mut state))
        .collect();

    // The reader opened a Thinking block lazily on the first reasoningContent delta and emitted
    // the two ThinkingDeltas + the SignatureDelta.
    assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart { index: 0, block: IrBlockMeta::Thinking }
            )),
            "a Thinking BlockStart must be lazily opened on the first reasoningContent delta; got {events:?}"
        );
    let thinking_text: String = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::ThinkingDelta(t),
                ..
            } => Some(t.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        thinking_text, "let me think",
        "the streamed reasoning text must be carried as ThinkingDeltas; got {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockDelta { delta: IrDelta::SignatureDelta(s), .. } if s == "sig-xyz"
        )),
        "the reasoning signature must be carried as a SignatureDelta; got {events:?}"
    );

    // Round-trip every reasoning IR event back through the writer and confirm the native frames.
    let block_start = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Thinking,
        })
        .expect("Thinking BlockStart must produce a frame");
    assert_eq!(block_start.0, "contentBlockStart");
    assert!(
        block_start.1.pointer("/start/reasoningContent").is_some(),
        "a Thinking BlockStart must emit a reasoningContent start; got {}",
        block_start.1
    );

    let text_delta = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::ThinkingDelta("hello".to_string()),
        })
        .expect("ThinkingDelta must produce a frame");
    assert_eq!(text_delta.0, "contentBlockDelta");
    assert_eq!(
        text_delta
            .1
            .pointer("/delta/reasoningContent/text")
            .and_then(|v| v.as_str()),
        Some("hello"),
        "a ThinkingDelta must re-emit as reasoningContent.text; got {}",
        text_delta.1
    );

    let sig_delta = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::SignatureDelta("sig-xyz".to_string()),
        })
        .expect("SignatureDelta must produce a frame");
    assert_eq!(sig_delta.0, "contentBlockDelta");
    assert_eq!(
        sig_delta
            .1
            .pointer("/delta/reasoningContent/signature")
            .and_then(|v| v.as_str()),
        Some("sig-xyz"),
        "a SignatureDelta must re-emit as reasoningContent.signature; got {}",
        sig_delta.1
    );
    // A genuine signature must NOT leak as redactedContent.
    assert!(
        sig_delta
            .1
            .pointer("/delta/reasoningContent/redactedContent")
            .is_none(),
        "a real signature must not re-emit as redactedContent; got {}",
        sig_delta.1
    );
}

/// Regression (R26 MED #3/#4): the STREAMING redacted-reasoning case. A `reasoningContent`
/// delta carrying `redactedContent` (opaque encrypted bytes) must survive read->IR->write on the
/// streaming path, re-emitting as `redactedContent` — never leaking as a plaintext `text` or a
/// `signature`. The reader maps it to a typed `RedactedReasoningDelta(bytes)` (one IR delta → one
/// frame); the writer re-emits the bytes under `redactedContent`. FAILS against the old code (the
/// redacted delta was dropped entirely) and passes after.
#[test]
fn test_stream_reasoning_redacted_round_trips() {
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};

    let reader = BedrockReader;
    let writer = BedrockWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    let frames = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"reasoningContent": {"redactedContent": "RVhBTVBMRQ=="}}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
    ];

    let events: Vec<IrStreamEvent> = frames
        .into_iter()
        .flat_map(|f| reader.read_response_events("", &f, &mut state))
        .collect();

    // A Thinking block is opened and the redacted bytes ride on a sentinel-prefixed SignatureDelta.
    assert!(
        events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Thinking
            }
        )),
        "a Thinking BlockStart must open for a streamed redactedContent delta; got {events:?}"
    );
    let redacted_delta = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            delta: IrDelta::RedactedReasoningDelta(s),
            ..
        } => Some(s.clone()),
        _ => None,
    });
    assert_eq!(
        redacted_delta.as_deref(),
        Some("RVhBTVBMRQ=="),
        "redacted reasoning bytes must ride on a typed RedactedReasoningDelta; got {events:?}"
    );
    // No plaintext ThinkingDelta must be emitted for a redacted block (no leak of the bytes as text).
    assert!(
        !events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockDelta {
                delta: IrDelta::ThinkingDelta(_),
                ..
            }
        )),
        "a redacted reasoning block must NOT emit a plaintext ThinkingDelta; got {events:?}"
    );

    // Writer re-emits the bytes under redactedContent from a typed RedactedReasoningDelta.
    let frame = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::RedactedReasoningDelta(redacted_delta.expect("redacted delta present")),
        })
        .expect("RedactedReasoningDelta must produce a frame");
    assert_eq!(frame.0, "contentBlockDelta");
    assert_eq!(
        frame
            .1
            .pointer("/delta/reasoningContent/redactedContent")
            .and_then(|v| v.as_str()),
        Some("RVhBTVBMRQ=="),
        "a RedactedReasoningDelta must re-emit the bytes as redactedContent; got {}",
        frame.1
    );
    assert!(
        frame
            .1
            .pointer("/delta/reasoningContent/signature")
            .is_none(),
        "a redacted reasoning delta must NOT leak as a plaintext signature; got {}",
        frame.1
    );
    assert!(
        frame.1.pointer("/delta/reasoningContent/text").is_none(),
        "a redacted reasoning delta must NOT leak as a plaintext text; got {}",
        frame.1
    );
}

/// Regression (R25 MED #4): native Converse `guardContent` (inline Guardrails) blocks that appear
/// inside the `system` array and inside a message's `content` array were SILENTLY DROPPED by
/// `read_request` (no IR `IrBlock` counterpart), so a same-protocol Bedrock->Bedrock passthrough
/// re-emitted a body with the guardrail spans the caller marked stripped — disabling the inline
/// content-classification the operator relies on. They must now survive the read->write round-trip
/// at their ORIGINAL positions via the `GUARD_CONTENT_SENTINEL` stash. FAILS against the old code
/// (the guardContent blocks vanish) and passes after.
#[test]
fn test_guard_content_round_trips() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "system": [
            {"text": "be safe"},
            {"guardContent": {"text": {"text": "ground truth", "qualifiers": ["grounding_source"]}}}
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"guardContent": {"text": {"text": "user query", "qualifiers": ["query"]}}},
                    {"text": "hello"}
                ]
            }
        ]
    });
    let ir = reader.read_request(&body).expect("read_request");
    assert!(
        ir.extra.contains_key(GUARD_CONTENT_SENTINEL),
        "guardContent markers must be captured into extra; got {:?}",
        ir.extra
    );
    let out = writer.write_request(&ir);
    assert!(
        out.get(GUARD_CONTENT_SENTINEL).is_none(),
        "the guardContent sentinel must not appear on the wire; got {out}"
    );
    assert_eq!(
        out, body,
        "guardContent markers must survive the round-trip at their original positions; got {out}"
    );
}

/// Regression (R25 MED #4): when BOTH `cachePoint` and `guardContent` markers occupy DISTINCT
/// positions in the SAME content array, they must be re-spliced together so neither shifts the
/// other off its recorded index. This guards the single-batch merge (`merge_marker_entries`)
/// against the naive two-pass splice that would mis-order them.
#[test]
fn test_guard_content_and_cache_point_interleave_preserved() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [
            {
                "role": "user",
                "content": [
                    {"guardContent": {"text": {"text": "q", "qualifiers": ["query"]}}},
                    {"text": "a"},
                    {"cachePoint": {"type": "default"}},
                    {"text": "b"}
                ]
            }
        ]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let out = writer.write_request(&ir);
    assert_eq!(
        out, body,
        "interleaved guardContent + cachePoint markers must round-trip at their original \
             positions; got {out}"
    );
}

/// A `reasoningContent` block carrying neither known member (a hypothetical future union member)
/// must degrade gracefully — `read_bedrock_reasoning_block` returns `None` and the block is left
/// undecoded rather than panicking or being mis-mapped to a Thinking with empty text.
#[test]
fn test_unknown_reasoning_member_does_not_panic() {
    let reader = BedrockReader;
    let body = serde_json::json!({
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"reasoningContent": {"futureMember": {"foo": "bar"}}},
                    {"text": "ok"}
                ]
            }
        ]
    });
    let ir = reader.read_request(&body).expect("read_request");
    // No Thinking block synthesized from the unknown member.
    assert!(
        !ir.messages[0]
            .content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::Thinking { .. })),
        "an unknown reasoningContent member must not be mis-mapped to a Thinking block; got {:?}",
        ir.messages[0].content
    );
}

/// Helper: a minimal IR request carrying only a tool_choice (and one tool so toolConfig is valid).
/// F4 conformance: consecutive same-role IR turns must coalesce so the Bedrock body alternates.
/// The canonical trigger is the Tool→"user" role mapping: an assistant tool_use turn, then a
/// Tool-result turn, then a follow-up User turn would emit assistant,user,user — which Bedrock
/// Converse rejects (a 400). The two user turns must merge into one.
#[test]
fn consecutive_user_turns_coalesce_for_alternation() {
    let text_msg = |role, t: &str| crate::ir::IrMessage {
        role,
        content: vec![crate::ir::IrBlock::Text {
            text: t.to_string(),
            cache_control: None,
            citations: vec![],
        }],
    };
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![
            text_msg(crate::ir::IrRole::User, "q"),
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "get".to_string(),
                    input: serde_json::json!({}),
                    cache_control: None,
                }],
            },
            // A Tool-result turn (maps to "user") immediately followed by a real User turn:
            // assistant, user, user on the wire without coalescing.
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "42".to_string(),
                        cache_control: None,
                        citations: vec![],
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
            text_msg(crate::ir::IrRole::User, "thanks"),
        ],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = BedrockWriter.write_request(&req);
    let msgs = out
        .get("messages")
        .and_then(|m| m.as_array())
        .expect("messages array");
    // Roles must strictly alternate: user, assistant, user (the Tool turn + trailing User merged).
    let roles: Vec<&str> = msgs
        .iter()
        .filter_map(|m| m.get("role").and_then(|r| r.as_str()))
        .collect();
    assert_eq!(
        roles,
        vec!["user", "assistant", "user"],
        "consecutive user turns must coalesce so roles alternate: {out}"
    );
    // The merged final user turn carries BOTH the toolResult and the trailing text.
    let last = msgs.last().expect("last message");
    let last_content = last
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content array");
    assert!(
        last_content.iter().any(|b| b.get("toolResult").is_some()),
        "merged turn must keep the toolResult block: {out}"
    );
    assert!(
        last_content
            .iter()
            .any(|b| b.get("text").and_then(|t| t.as_str()) == Some("thanks")),
        "merged turn must keep the trailing user text: {out}"
    );
}

fn tool_choice_req(tc: Option<crate::ir::IrToolChoice>) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![],
        tools: vec![crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            cache_control: None,
        }],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: tc,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    }
}

/// F3 conformance: a `tool_choice` with NO accompanying tools must NOT produce a `toolConfig`.
/// Bedrock Converse rejects a `toolConfig` whose `toolChoice` has no tools array (a 400). When a
/// cross-protocol request carries a tool_choice but its tools could not be projected, the writer
/// drops the orphan tool_choice and emits no toolConfig at all.
#[test]
fn tool_choice_without_tools_emits_no_tool_config() {
    for tc in [
        crate::ir::IrToolChoice::Auto,
        crate::ir::IrToolChoice::Required,
        crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string(),
        },
    ] {
        let mut req = tool_choice_req(Some(tc.clone()));
        req.tools = vec![]; // tool_choice set, but no tools survived
        let out = BedrockWriter.write_request(&req);
        assert!(
            out.get("toolConfig").is_none(),
            "toolConfig must be omitted entirely when tool_choice={tc:?} has no tools: {out}"
        );
    }
}

/// F5 conformance: the common `image/jpg` media_type (and casing variants) must normalize to
/// Bedrock's `jpeg` ImageFormat, not pass through as the off-enum `jpg` that 400s.
#[test]
fn image_format_jpg_normalizes_to_jpeg() {
    for mt in ["image/jpg", "image/JPG", "image/Jpeg", "image/jpeg"] {
        let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: mt.to_string(),
            data: "QUJD".to_string(),
        })
        .expect("image block");
        assert_eq!(
            block.get("format").and_then(|f| f.as_str()),
            Some("jpeg"),
            "media_type {mt:?} must emit Bedrock format=jpeg"
        );
    }
    // The other native formats are unaffected.
    for (mt, want) in [
        ("image/png", "png"),
        ("image/gif", "gif"),
        ("image/webp", "webp"),
    ] {
        let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: mt.to_string(),
            data: "QUJD".to_string(),
        })
        .expect("image block");
        assert_eq!(block.get("format").and_then(|f| f.as_str()), Some(want));
    }
}

/// PF-H1: Bedrock `toolChoice:{any:{}}` (must call SOME tool) round-trips through the IR's
/// `Required` variant — read promotes it, write re-emits the native `{any:{}}`.
#[test]
fn test_bedrock_tool_choice_any_required_roundtrips() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "messages": [],
        "toolConfig": {
            "tools": [{"toolSpec": {"name": "get_weather", "inputSchema": {"json": {}}}}],
            "toolChoice": {"any": {}}
        }
    });
    let ir = reader.read_request(&j).expect("read ok");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));

    let out = BedrockWriter.write_request(&ir);
    let tc = out
        .get("toolConfig")
        .and_then(|t| t.get("toolChoice"))
        .expect("toolChoice emitted");
    assert_eq!(tc, &serde_json::json!({"any": {}}));
}

/// PF-H1: Bedrock `toolChoice:{tool:{name}}` (forced specific tool) round-trips through the IR's
/// `Tool{name}` variant.
#[test]
fn test_bedrock_tool_choice_specific_tool() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "messages": [],
        "toolConfig": {
            "tools": [{"toolSpec": {"name": "get_weather", "inputSchema": {"json": {}}}}],
            "toolChoice": {"tool": {"name": "get_weather"}}
        }
    });
    let ir = reader.read_request(&j).expect("read ok");
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );

    let out = BedrockWriter.write_request(&ir);
    let tc = out
        .get("toolConfig")
        .and_then(|t| t.get("toolChoice"))
        .expect("toolChoice emitted");
    assert_eq!(tc, &serde_json::json!({"tool": {"name": "get_weather"}}));
}

/// PF-H1: `IrToolChoice::None` has no native Bedrock representation, so the writer must omit
/// `toolChoice` entirely (rather than emit an invalid shape) while still emitting the tools.
#[test]
fn test_bedrock_tool_choice_none_omitted_on_write() {
    let req = tool_choice_req(Some(crate::ir::IrToolChoice::None));
    let out = BedrockWriter.write_request(&req);
    let tool_config = out
        .get("toolConfig")
        .expect("toolConfig with tools emitted");
    assert!(
        tool_config.get("toolChoice").is_none(),
        "Bedrock has no native 'none' — toolChoice must be omitted; got {tool_config:?}"
    );
    assert!(
        tool_config.get("tools").is_some(),
        "tools must still be emitted"
    );
}

/// PF-H1: a request with no native `toolChoice` reads back as `tool_choice == None` (no spurious
/// directive minted on translation).
#[test]
fn test_bedrock_tool_choice_absent_is_none() {
    let reader = BedrockReader;
    let j = serde_json::json!({
        "messages": [],
        "toolConfig": {"tools": [{"toolSpec": {"name": "f", "inputSchema": {"json": {}}}}]}
    });
    let ir = reader.read_request(&j).expect("read ok");
    assert_eq!(ir.tool_choice, None);
    let out = BedrockWriter.write_request(&ir);
    assert!(
        out.get("toolConfig")
            .and_then(|t| t.get("toolChoice"))
            .is_none(),
        "no toolChoice should be emitted when none was provided"
    );
}

// PF-M1: OpenAI/Responses ingress accepts temperature up to 2.0, but Bedrock's native range is
// [0.0, 1.0] and rejects >1 with a hard 400 ValidationException. The writer must clamp.
#[test]
fn test_bedrock_writer_clamps_temperature_above_one() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        max_tokens: None,
        temperature: Some(1.8),
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = BedrockWriter.write_request(&ir);
    assert_eq!(
        out.pointer("/inferenceConfig/temperature")
            .and_then(|v| v.as_f64()),
        Some(1.0),
        "an OpenAI-ingress temperature of 1.8 must clamp to 1.0 on the Bedrock writer; got {out}"
    );
}

// --- H3: cross-protocol cache_control <-> Bedrock cachePoint -------------------------------

/// Helper: a bare IR request with the given system / messages / tools and an EMPTY `extra`
/// (cross-protocol shape — the positional cachePoint stash is absent, so the writer drives
/// cachePoint emission from the first-class `cache_control` field, not the stash).
fn cache_ctrl_req(
    system: Vec<crate::ir::IrBlock>,
    messages: Vec<crate::ir::IrMessage>,
    tools: Vec<crate::ir::IrTool>,
) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system,
        messages,
        tools,
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    }
}

fn ephemeral() -> Option<crate::ir::CacheControl> {
    Some(crate::ir::CacheControl {
        kind: crate::ir::CacheKind::Ephemeral,
    })
}

/// H3 (write): an IR message Text block carrying `cache_control` must emit a Bedrock `cachePoint`
/// block IMMEDIATELY AFTER it (the position Bedrock expects). With an empty `extra` (cross-protocol
/// shape) the first-class field is the sole driver — the old writer dropped it entirely.
#[test]
fn test_cache_control_on_message_block_emits_cache_point() {
    let req = cache_ctrl_req(
        vec![],
        vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "cache me".to_string(),
                    cache_control: ephemeral(),
                    citations: vec![],
                },
                crate::ir::IrBlock::Text {
                    text: "but not this".to_string(),
                    cache_control: None,
                    citations: vec![],
                },
            ],
        }],
        vec![],
    );
    let out = BedrockWriter.write_request(&req);
    // The cachePoint sits AFTER the first text block (index 1), before the second text (index 2).
    assert_eq!(
        out.pointer("/messages/0/content/0/text")
            .and_then(|v| v.as_str()),
        Some("cache me"),
    );
    assert_eq!(
        out.pointer("/messages/0/content/1/cachePoint"),
        Some(&serde_json::json!({"type": "default"})),
        "a cache_control block must emit a trailing cachePoint; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/2/text")
            .and_then(|v| v.as_str()),
        Some("but not this"),
        "the non-cached block must follow, with no extra cachePoint; got {out}"
    );
    // Exactly one cachePoint (the second, uncached block emits none).
    let count = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().filter(|b| b.get("cachePoint").is_some()).count())
        .unwrap_or(0);
    assert_eq!(count, 1, "exactly one cachePoint expected; got {out}");
}

/// H3 (write): a system Text block carrying `cache_control` emits a trailing cachePoint in the
/// `system` array (the system prefix is the canonical prompt-cache target).
#[test]
fn test_cache_control_on_system_block_emits_cache_point() {
    let req = cache_ctrl_req(
        vec![crate::ir::IrBlock::Text {
            text: "long static preamble".to_string(),
            cache_control: ephemeral(),
            citations: vec![],
        }],
        vec![],
        vec![],
    );
    let out = BedrockWriter.write_request(&req);
    assert_eq!(
        out.pointer("/system/0/text").and_then(|v| v.as_str()),
        Some("long static preamble"),
    );
    assert_eq!(
        out.pointer("/system/1/cachePoint"),
        Some(&serde_json::json!({"type": "default"})),
        "a system cache_control block must emit a trailing cachePoint; got {out}"
    );
}

/// H3 (write): a tool definition carrying `cache_control` emits a `cachePoint` element in the
/// `toolConfig.tools` array right after the tool (caching the tool-schema prefix).
#[test]
fn test_cache_control_on_tool_emits_cache_point() {
    let req = cache_ctrl_req(
        vec![],
        vec![],
        vec![crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            cache_control: ephemeral(),
        }],
    );
    let out = BedrockWriter.write_request(&req);
    assert_eq!(
        out.pointer("/toolConfig/tools/0/toolSpec/name")
            .and_then(|v| v.as_str()),
        Some("get_weather"),
    );
    assert_eq!(
        out.pointer("/toolConfig/tools/1/cachePoint"),
        Some(&serde_json::json!({"type": "default"})),
        "a tool cache_control must emit a trailing cachePoint in toolConfig.tools; got {out}"
    );
}

/// H3 (read): a Bedrock `cachePoint` following a content block must map onto the preceding IR
/// block's first-class `cache_control` (so a Bedrock->Anthropic hop, where the positional stash is
/// dropped, still preserves the boundary). The adjacency targets the immediately-preceding block.
#[test]
fn test_cache_point_maps_onto_preceding_block_cache_control() {
    let reader = BedrockReader;
    let wire = serde_json::json!({
        "system": [
            {"text": "preamble"},
            {"cachePoint": {"type": "default"}}
        ],
        "messages": [
            {"role": "user", "content": [
                {"text": "doc"},
                {"cachePoint": {"type": "default"}},
                {"text": "tail"}
            ]}
        ],
        "toolConfig": {
            "tools": [
                {"toolSpec": {"name": "t", "inputSchema": {"json": {}}}},
                {"cachePoint": {"type": "default"}}
            ]
        }
    });
    let ir = reader.read_request(&wire).expect("read_request");
    // System: the first (and only) text block carries cache_control.
    match &ir.system[0] {
        crate::ir::IrBlock::Text { cache_control, .. } => {
            assert!(
                cache_control.is_some(),
                "system block must carry cache_control"
            );
        }
        other => panic!("expected Text, got {other:?}"),
    }
    // Message: the FIRST text ("doc") carries cache_control; the second ("tail") does not.
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            ..
        } => {
            assert_eq!(text, "doc");
            assert!(
                cache_control.is_some(),
                "preceding block must carry cache_control"
            );
        }
        other => panic!("expected Text, got {other:?}"),
    }
    match &ir.messages[0].content[1] {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            ..
        } => {
            assert_eq!(text, "tail");
            assert!(
                cache_control.is_none(),
                "trailing block must NOT carry cache_control"
            );
        }
        other => panic!("expected Text, got {other:?}"),
    }
    // Tool: the preceding tool carries cache_control.
    assert!(
        ir.tools[0].cache_control.is_some(),
        "the tool preceding a tools-array cachePoint must carry cache_control"
    );
}

/// H3 (round-trip, cross-protocol shape): reading a cachePoint-bearing body into the IR and then
/// writing it back with `extra` CLEARED (the cross-protocol seam) re-derives the cachePoint purely
/// from the first-class `cache_control` field — the boundary survives even when the positional
/// stash is gone.
#[test]
fn test_cache_control_round_trip_via_field_only() {
    let reader = BedrockReader;
    let wire = serde_json::json!({
        "messages": [
            {"role": "user", "content": [
                {"text": "doc"},
                {"cachePoint": {"type": "default"}}
            ]}
        ]
    });
    let mut ir = reader.read_request(&wire).expect("read_request");
    // Simulate the cross-protocol seam: drop the busbar-internal positional stash so only the
    // first-class `cache_control` field remains to drive emission.
    ir.extra.clear();
    let out = BedrockWriter.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/0/text")
            .and_then(|v| v.as_str()),
        Some("doc"),
    );
    assert_eq!(
            out.pointer("/messages/0/content/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "the cachePoint must be re-derived from cache_control after the stash is cleared; got {out}"
        );
}

/// H3 (no double-emit): on the SAME-protocol path the positional stash AND the first-class
/// `cache_control` field are both populated by the reader, but the writer must emit EXACTLY ONE
/// cachePoint (the stash drives placement; the inline field emission is suppressed). Guards against
/// a regression that would double-bill the cache boundary.
#[test]
fn test_same_protocol_cache_point_no_double_emit() {
    let reader = BedrockReader;
    let wire = serde_json::json!({
        "messages": [
            {"role": "user", "content": [
                {"text": "doc"},
                {"cachePoint": {"type": "default"}},
                {"text": "tail"}
            ]}
        ]
    });
    let ir = reader.read_request(&wire).expect("read_request");
    let out = BedrockWriter.write_request(&ir);
    let count = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().filter(|b| b.get("cachePoint").is_some()).count())
        .unwrap_or(0);
    assert_eq!(
        count, 1,
        "same-protocol path must emit exactly one cachePoint; got {out}"
    );
    assert_eq!(
        out, wire,
        "same-protocol body must round-trip byte-identically; got {out}"
    );
}

// --- L4: degradations are now observable (warn paths) --------------------------------------

/// L4 (warn path): `tool_choice = None` has no native Converse directive, so it degrades to an
/// omitted `toolChoice` and a `tracing::warn!`. The observable degradation (no `toolChoice` key,
/// tools still emitted) is asserted here; the warn fires on the same branch.
#[test]
fn test_tool_choice_none_warns_and_omits() {
    let req = tool_choice_req(Some(crate::ir::IrToolChoice::None));
    let out = BedrockWriter.write_request(&req);
    let tool_config = out.get("toolConfig").expect("toolConfig emitted");
    assert!(
        tool_config.get("toolChoice").is_none(),
        "tool_choice=None must omit toolChoice (warn-and-degrade); got {tool_config:?}"
    );
    assert!(
        tool_config.get("tools").is_some(),
        "the tools array must still be emitted; got {tool_config:?}"
    );
}

/// L4 (warn path): a malformed image media_type (an empty subtype) is coerced to `format: "png"`
/// and a `tracing::warn!` fires. The observable coercion is asserted here; the warn rides the same
/// fallback branch.
#[test]
fn test_malformed_media_type_warns_and_falls_back_to_png() {
    // Empty subtype (`image/`) takes the fallback branch that warns.
    let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "image/".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("base64 image must emit a block");
    assert_eq!(
        block.pointer("/format").and_then(|v| v.as_str()),
        Some("png"),
        "an empty subtype must coerce to png (warn-and-degrade); got {block}"
    );
    // A bare, unprefixed media_type also takes the warning fallback.
    let bare = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "garbage".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("bare media_type must emit a block");
    assert_eq!(
        bare.pointer("/format").and_then(|v| v.as_str()),
        Some("png"),
    );
    // A well-formed subtype does NOT take the fallback (no coercion, no warn).
    let jpeg = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
        media_type: "image/jpeg".to_string(),
        data: ("QQ==").to_string(),
    })
    .expect("jpeg must emit a block");
    assert_eq!(
        jpeg.pointer("/format").and_then(|v| v.as_str()),
        Some("jpeg")
    );
}

/// D3: a cross-protocol IR carrying `response_format` reaching the Bedrock egress must be DROPPED
/// (Converse has no native response_format field) — and the wire must contain NO `response_format`
/// key (it would 400 the upstream). Mirrors the Anthropic-egress drop. The `warn!` itself is not
/// asserted here (tracing capture is out of scope); the contract is "emits nothing".
#[test]
fn test_write_request_response_format_dropped() {
    let writer = BedrockWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: Some(crate::ir::IrResponseFormat {
            json: true,
            schema: Some(serde_json::json!({"type": "object"})),
            name: Some("s".to_string()),
            strict: None,
            description: None,
        }),
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("response_format") && !wire.contains("json_schema"),
        "response_format must not be emitted on the Bedrock wire; got {wire}"
    );
    assert!(
        out.get("response_format").is_none(),
        "no top-level response_format key may be present; got {out}"
    );
}

#[test]
fn bedrock_stream_framing_emits_one_metadata_delta_then_guards_duplicate() {
    // GUARD: `BedrockStreamFraming::on_combined_stop_delta` must enforce the exactly-one-`metadata`
    // invariant against a (malformed/adversarial) egress that emits a SECOND combined stop-delta
    // carrying usage. The FIRST call (with non-zero usage) emits the stop-only delta PLUS one
    // usage-only `MessageDelta{stop_reason:None}` (the metadata frame); the SECOND call — `emitted`
    // is now set — emits ONLY the stop-only delta, so NO second metadata frame is produced.
    use super::StreamFraming;
    let usage = crate::ir::IrUsage {
        input_tokens: 5,
        output_tokens: 2,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    let mut framing = BedrockStreamFraming::default();

    // Helper: count the usage-only metadata deltas (`MessageDelta{stop_reason: None, ..}`).
    fn metadata_delta_count(events: &[crate::ir::IrStreamEvent]) -> usize {
        events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    crate::ir::IrStreamEvent::MessageDelta {
                        stop_reason: None,
                        ..
                    }
                )
            })
            .count()
    }

    let first = framing
        .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
        .expect("first stop-delta returns events");
    assert_eq!(
        metadata_delta_count(&first),
        1,
        "first call must emit exactly ONE usage-only metadata delta; got {first:?}"
    );

    let second = framing
        .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
        .expect("second stop-delta returns events");
    assert_eq!(
            metadata_delta_count(&second),
            0,
            "second call must emit ZERO metadata deltas (the !emitted guard suppresses the duplicate); got {second:?}"
        );
}

/// REGRESSION (audit c2r4): a CACHE-ONLY stop-delta (`input_tokens == 0 && output_tokens == 0`
/// but non-zero cache tokens — a full cache hit) must emit its `metadata` frame INLINE with the
/// real cache tokens, not defer it and later flush a zero-usage frame. `has_usage` now includes
/// the cache fields.
#[test]
fn cache_only_usage_emits_metadata_inline() {
    fn metadata_delta_count(events: &[crate::ir::IrStreamEvent]) -> usize {
        events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    crate::ir::IrStreamEvent::MessageDelta {
                        stop_reason: None,
                        ..
                    }
                )
            })
            .count()
    }
    let usage = crate::ir::IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: Some(4096), // full cache hit
    };
    let mut framing = BedrockStreamFraming::default();
    let evs = framing
        .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
        .expect("stop-delta returns events");
    assert_eq!(
            metadata_delta_count(&evs),
            1,
            "a cache-only stop-delta must emit ONE metadata frame inline with the real cache tokens, not defer a zero-usage frame; got {evs:?}"
        );
}

/// F4 coalescing (headline Bedrock behavior): Converse requires STRICTLY ALTERNATING
/// user/assistant turns — two consecutive same-role messages are a 400 ValidationException. An IR
/// with `[Assistant(tool_use), Tool(result1), Tool(result2)]` maps the two Tool turns to "user"
/// role and MUST coalesce them into ONE user message so the wire alternates assistant,user.
#[test]
fn consecutive_tool_result_turns_coalesce_into_single_user_message() {
    let req = crate::ir::IrRequest {
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "run both tools".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "a".to_string(),
                    input: serde_json::json!({}),
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "r1".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t2".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "r2".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
        ],
        ..Default::default()
    };
    let out = BedrockWriter.write_request(&req);
    let msgs = out
        .get("messages")
        .and_then(|m| m.as_array())
        .expect("messages array");
    // user, assistant, user — the two Tool turns coalesced into ONE trailing user message.
    let roles: Vec<&str> = msgs
        .iter()
        .filter_map(|m| m.get("role").and_then(|r| r.as_str()))
        .collect();
    assert_eq!(
        roles,
        vec!["user", "assistant", "user"],
        "consecutive same-role (tool→user) turns must coalesce to keep strict alternation: {out}"
    );
    // The coalesced final user message carries BOTH tool results.
    let last_content = msgs
        .last()
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .expect("last content array");
    assert_eq!(
        last_content.len(),
        2,
        "both tool_result blocks must land in the single coalesced user turn: {out}"
    );
}

/// An UNKNOWN native `stopReason` maps to `IrStopReason::Other` on read (ir.rs:186), and `Other`
/// degrades to the safe `end_turn` on egress — a foreign token is never carried into Converse's
/// closed `stopReason` enum. Pins the full read_response→write_response degradation.
#[test]
fn unknown_stop_reason_maps_to_other_and_degrades_to_end_turn() {
    assert_eq!(
        stop_reason_map("some_future_reason"),
        crate::ir::IrStopReason::Other
    );
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "some_future_reason",
        "usage": {"inputTokens": 3, "outputTokens": 1, "totalTokens": 4}
    });
    let resp = BedrockReader.read_response(&body).expect("read_response");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Other));
    let out = BedrockWriter.write_response(&resp);
    assert_eq!(
        out.get("stopReason").and_then(|v| v.as_str()),
        Some("end_turn"),
        "Other must degrade to end_turn, never leak the foreign token into Converse's enum"
    );
}

/// Bedrock cache tokens are ALREADY ADDITIVE (ir.rs:457): unlike OpenAI/Gemini (which subtract the
/// cached prefix out of the input total), the Bedrock reader stores `cacheReadInputTokens` /
/// `cacheWriteInputTokens` AS-IS and does NOT reduce `inputTokens` by them. This pins that
/// `input_tokens` is the raw wire value and `billable_tokens` sums all four additively.
#[test]
fn cache_usage_is_additive_input_not_reduced() {
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10,
            "outputTokens": 5,
            "totalTokens": 15,
            "cacheReadInputTokens": 1000,
            "cacheWriteInputTokens": 200
        }
    });
    let resp = BedrockReader.read_response(&body).expect("read_response");
    assert_eq!(
        resp.usage.input_tokens, 10,
        "Bedrock inputTokens stored AS-IS (additive convention), NOT reduced by cache reads"
    );
    assert_eq!(resp.usage.cache_read_input_tokens, Some(1000));
    assert_eq!(resp.usage.cache_creation_input_tokens, Some(200));
    // Additive sum: 10 + 5 + 1000 + 200.
    assert_eq!(resp.usage.billable_tokens(), 1215);

    // Round-trip: write re-emits the native additive fields under AWS's spellings.
    let out = BedrockWriter.write_response(&resp);
    assert_eq!(
        out.pointer("/usage/cacheReadInputTokens")
            .and_then(|v| v.as_u64()),
        Some(1000)
    );
    assert_eq!(
        out.pointer("/usage/cacheWriteInputTokens")
            .and_then(|v| v.as_u64()),
        Some(200)
    );
    assert_eq!(
        out.pointer("/usage/inputTokens").and_then(|v| v.as_u64()),
        Some(10)
    );
}

/// `write_response_exception` (the Bedrock-INGRESS stream error path) must fold every error class
/// onto ONE of the FIVE legal ConverseStream exception-union members, never a request-level name a
/// native AWS stream decoder can't match. Pins the class→member mapping so a mid-stream error
/// reaches a Bedrock client as a typed, decodable exception.
#[test]
fn write_response_exception_folds_to_stream_union_members() {
    let mk = |class| crate::proto::IrError {
        class,
        provider_signal: None,
        retry_after: None,
    };
    let cases = [
        (StatusClass::RateLimit, "ThrottlingException"),
        (StatusClass::Overloaded, "ServiceUnavailableException"),
        (StatusClass::ClientError, "ValidationException"),
        (StatusClass::ContextLength, "ValidationException"),
        (StatusClass::Timeout, "ModelStreamErrorException"),
        (StatusClass::Auth, "InternalServerException"),
        (StatusClass::Billing, "InternalServerException"),
        (StatusClass::ServerError, "InternalServerException"),
        (StatusClass::Network, "InternalServerException"),
    ];
    for (class, expect) in cases {
        let (name, _msg) = BedrockWriter
            .write_response_exception(&mk(class))
            .expect("Bedrock always returns Some for a stream exception");
        assert_eq!(name, expect, "class {class:?} must fold to {expect}");
    }
    // The message prefers the upstream provider_signal when present.
    let err = crate::proto::IrError {
        class: StatusClass::RateLimit,
        provider_signal: Some("slow down".to_string()),
        retry_after: None,
    };
    let (name, msg) = BedrockWriter.write_response_exception(&err).unwrap();
    assert_eq!(name, "ThrottlingException");
    assert_eq!(
        msg, "slow down",
        "message prefers the upstream provider_signal"
    );
}

/// FINDING 3 [P1] REGRESSION: The native AWS Bedrock ConverseStream `ContentBlockStart$start`
/// union only models `toolUse`, so a real AWS stream sends NO `contentBlockStart` for a text
/// block — the block is implied by the first `contentBlockDelta` carrying `text`. The reader's
/// text-delta arm previously emitted a `BlockDelta` with NO preceding `BlockStart`, producing an
/// orphaned `content_block_delta` at index 0 (breaking the block-event contract when translating
/// Bedrock ConverseStream -> Anthropic-style block events). The text arm must lazily open a Text
/// BlockStart on the first text delta, exactly like the reasoningContent arm.
#[test]
fn test_stream_text_delta_lazily_opens_block_start() {
    use crate::ir::IrStreamEvent;

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;

    // Native AWS text sequence: messageStart, then text deltas with NO contentBlockStart.
    let events: Vec<_> = vec![
        serde_json::json!({"type": "messageStart", "role": "assistant"}),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": "Hello"}
        }),
        serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"text": ", world!"}
        }),
        serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        serde_json::json!({
            "type": "metadata",
            "usage": {"inputTokens": 10, "outputTokens": 5}
        }),
    ]
    .into_iter()
    .flat_map(|data| reader.read_response_events("", &data, &mut state))
    .collect();

    // A Text BlockStart at index 0 must precede any TextDelta.
    let first_block_start = events.iter().position(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Text,
                ..
            }
        )
    });
    let first_text_delta = events.iter().position(|e| {
        matches!(
            e,
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::TextDelta(_),
                ..
            }
        )
    });
    let bs = first_block_start.expect("a Text BlockStart must be emitted for lazy text open");
    let bd = first_text_delta.expect("a TextDelta must be present");
    assert!(
        bs < bd,
        "the Text BlockStart (idx {bs}) must precede the first TextDelta (idx {bd}); \
         an orphaned content_block_delta with no BlockStart is the defect"
    );
    // The lazily-opened block must be indexed 0 (matching the delta index).
    if let IrStreamEvent::BlockStart { index, .. } = &events[bs] {
        assert_eq!(*index, 0, "lazily-opened Text block must be at index 0");
    }
}
