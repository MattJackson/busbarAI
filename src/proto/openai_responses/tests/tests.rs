use super::*;

/// LOW (lossless-by-target): the Responses create API models no `top_k`. A request carrying
/// `top_k` must NOT emit a `top_k` field (it would 400 a real `/v1/responses` call) — it is
/// dropped with a `warn!` (the drop-with-warn branch is exercised here). `top_p`, which the
/// surface DOES model, still passes through.
#[test]
fn write_request_drops_top_k_with_warn() {
    let mk = |top_k: Option<u32>| crate::ir::IrRequest {
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
        top_p: Some(0.9),
        top_k,
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

    let writer = ResponsesWriter;
    // With top_k set: the warn-drop branch runs and NO `top_k` reaches the body.
    let with = writer.write_request(&mk(Some(40)));
    assert!(
        with.get("top_k").is_none(),
        "the Responses body must NOT carry top_k (lossy-by-target): {with}"
    );
    // top_p (a modeled param) still passes through.
    assert_eq!(with.get("top_p").and_then(|v| v.as_f64()), Some(0.9));

    // Without top_k: body shape is identical w.r.t. top_k absence (sanity baseline).
    let without = writer.write_request(&mk(None));
    assert!(without.get("top_k").is_none());
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
            text: "You are helpful.".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "fc_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "fc_1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "sunny".to_string(),
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
            description: Some("Get weather for a location".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }),
            cache_control: None,
        }],
        max_tokens: Some(1024),
        temperature: Some(0.7),
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

    let writer = ResponsesWriter;
    let json = writer.write_request(&ir);

    assert_eq!(
        json.get("instructions").and_then(|v| v.as_str()),
        Some("You are helpful.")
    );

    let input = json
        .get("input")
        .and_then(|v| v.as_array())
        .expect("input should exist");

    let first_item = &input[0];
    assert_eq!(
        first_item.get("role").and_then(|r| r.as_str()),
        Some("user")
    );
    let content = first_item
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content should exist");
    assert_eq!(content.len(), 1);
    assert_eq!(
        content[0].get("type"),
        Some(&serde_json::json!("input_text")) // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("hi"));

    let func_call_item = input
        .iter()
        .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call")) // golden wire-contract literal (kept bare on purpose)
        .expect("should have function_call item");
    assert_eq!(
        func_call_item.get("name").and_then(|n| n.as_str()),
        Some("get_weather")
    );
    let args = func_call_item
        .get("arguments")
        .and_then(|a| a.as_str())
        .expect("arguments should exist");
    assert!(args.contains("SF") || args.contains("city"));

    let func_output_item = input
        .iter()
        .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call_output"))
        .expect("should have function_call_output item");
    assert_eq!(
        func_output_item.get("call_id").and_then(|c| c.as_str()),
        Some("fc_1")
    );
    let output = func_output_item
        .get("output")
        .and_then(|o| o.as_str())
        .expect("output should exist");
    assert_eq!(output, "sunny");

    let tools = json
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("tools should exist");
    assert_eq!(tools.len(), 1);
    let tool_obj = &tools[0];
    assert_eq!(tool_obj.get("type"), Some(&serde_json::json!("function")));
    assert_eq!(
        tool_obj.get("name").and_then(|n| n.as_str()),
        Some("get_weather")
    );
    assert!(
        tool_obj.get("function").is_none(),
        "tools should be flattened"
    );

    assert_eq!(
        json.get("max_output_tokens"),
        Some(&serde_json::json!(1024))
    );
    assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
}

#[test]
fn test_read_request() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "instructions": "You are helpful.",
        "input": [
            {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "What's the weather?"}]},
            {"role": "assistant", "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "Let me check that for you."}]},
            {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_1", "name": "get_weather", "arguments": "{\"city\":\"SF\"}"},
            {"type": "function_call_output", "call_id": "fc_1", "output": "Sunny, 72F"}
        ],
        "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
        "max_output_tokens": 1024,
        "temperature": 0.7
    });

    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("read_request should succeed");

    assert_eq!(ir.system.len(), 1);
    if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
        assert_eq!(text, "You are helpful.");
    } else {
        panic!("system should be Text block");
    }

    // 2 role/content messages + function_call -> assistant + function_call_output -> tool
    assert_eq!(ir.messages.len(), 4);

    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
        assert_eq!(text, "What's the weather?");
    } else {
        panic!("first message should be Text block");
    }

    assert_eq!(ir.max_tokens, Some(1024));
    assert_eq!(ir.temperature, Some(0.7_f64));

    assert_eq!(ir.tools.len(), 1);
    let tool = &ir.tools[0];
    assert_eq!(tool.name, "get_weather");
}

// Regression (MED #4/#5): a `message`-item `content` that is a BARE JSON STRING (the
// Responses shorthand) must survive. The old array-only path returned `None` from
// `as_array()` and silently dropped the whole turn, losing a user/assistant message on a
// cross-protocol hop. Covers BOTH the typed `"type":"message"` arm and the untyped
// role-keyed fallback.
#[test]
fn test_read_request_bare_string_content_survives() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            // typed message arm, bare-string content
            {"type": ITEM_TYPE_MESSAGE, "role": "user", "content": "hello from typed"},
            // typed message arm, assistant bare-string content
            {"type": ITEM_TYPE_MESSAGE, "role": "assistant", "content": "typed assistant reply"},
            // untyped role-keyed fallback, bare-string content
            {"role": "user", "content": "hello from untyped"},
            {"role": "assistant", "content": "untyped assistant reply"}
        ]
    });

    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("read_request should succeed");

    // All four turns must survive (old code dropped every one).
    assert_eq!(ir.messages.len(), 4, "no turn may be dropped");

    let expect_text = |msg: &crate::ir::IrMessage, role: crate::ir::IrRole, text: &str| {
        assert_eq!(msg.role, role);
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            crate::ir::IrBlock::Text { text: t, .. } => assert_eq!(t, text),
            other => panic!("expected Text block, got {other:?}"),
        }
    };

    expect_text(&ir.messages[0], crate::ir::IrRole::User, "hello from typed");
    expect_text(
        &ir.messages[1],
        crate::ir::IrRole::Assistant,
        "typed assistant reply",
    );
    expect_text(
        &ir.messages[2],
        crate::ir::IrRole::User,
        "hello from untyped",
    );
    expect_text(
        &ir.messages[3],
        crate::ir::IrRole::Assistant,
        "untyped assistant reply",
    );
}

#[test]
fn test_roundtrip_identity() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![crate::ir::IrBlock::Text {
            text: "You are helpful.".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "Hello!".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Text {
                    text: "Hi there!".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
        ],
        tools: Vec::new(),
        max_tokens: Some(500),
        temperature: Some(0.7),
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

    let reader = ResponsesReader;
    let writer = ResponsesWriter;

    let json = writer.write_request(&ir);
    let rt_ir = reader
        .read_request(&json)
        .expect("read round-trip should succeed");

    assert_eq!(ir, rt_ir);
}

#[test]
fn test_temperature_fidelity() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "test"}]}],
        "temperature": 0.7,
        "max_output_tokens": 1024
    });

    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("read_request should succeed");

    assert_eq!(ir.temperature, Some(0.7_f64));
}

#[test]
fn test_auth_headers() {
    let writer = ResponsesWriter;
    let headers = writer.auth_headers("sk-test");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "authorization");
    assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");
}

/// Warn+OMIT policy (`proto::bearer_auth_headers`): a key with bytes invalid for an HTTP header
/// value (embedded newline) must OMIT the header entirely (empty Vec), never emit an empty
/// `authorization` value (a syntactically invalid header AND a fingerprinting tell). No panic.
#[test]
fn auth_headers_invalid_key_omits_header_no_panic() {
    let writer = ResponsesWriter;
    let headers = writer.auth_headers("sk-bad\nkey");
    assert!(
        headers.is_empty(),
        "an invalid key must omit the auth header, not emit an empty value"
    );
}

#[test]
fn test_read_response_decode() {
    let json = serde_json::json!({
        "id": "resp_1",
        "object": OBJ_RESPONSE,
        "status": STATUS_COMPLETED,
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "The weather in SF is sunny."}]
            },
            {
                "type": ITEM_TYPE_FUNCTION_CALL,
                "call_id": "fc_1",
                "name": "get_weather",
                "arguments": "{\"city\":\"SF\"}"
            }
        ],
        "usage": {"input_tokens": 50, "output_tokens": 25}
    });

    let reader = ResponsesReader;
    let resp = reader
        .read_response(&json)
        .expect("read_response should succeed");

    assert_eq!(resp.content.len(), 2);
    match &resp.content[0] {
        crate::ir::IrBlock::Text { text, .. } => {
            assert_eq!(text, "The weather in SF is sunny.")
        }
        _ => panic!("first block should be Text"),
    }
    match &resp.content[1] {
        crate::ir::IrBlock::ToolUse {
            id, name, input, ..
        } => {
            assert_eq!(id, "fc_1");
            assert_eq!(name, "get_weather");
            assert_eq!(input.get("city").and_then(|v| v.as_str()), Some("SF"));
        }
        _ => panic!("second block should be ToolUse"),
    }

    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
    assert_eq!(resp.usage.input_tokens, 50);
    assert_eq!(resp.usage.output_tokens, 25);
}

/// Fix #9 (lenience): a Responses `read_response` body with NO `usage` object must parse to a
/// zero IrUsage rather than hard-erroring with a ClientError — mirroring all five sibling readers
/// (openai_chat.rs, etc.). A missing `usage` on an otherwise valid 200 is an upstream format quirk,
/// not a client mistake; erroring here would make forward.rs discard a valid body and 500.
#[test]
fn read_response_without_usage_zero_defaults_no_error() {
    let json = serde_json::json!({
        "id": "resp_no_usage",
        "object": OBJ_RESPONSE,
        "status": STATUS_COMPLETED,
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
            }
        ]
        // intentionally NO "usage" key
    });

    let resp = ResponsesReader
        .read_response(&json)
        .expect("absent usage must parse to zero, not error");
    assert_eq!(resp.usage.input_tokens, 0);
    assert_eq!(resp.usage.output_tokens, 0);
    assert_eq!(resp.usage.cache_read_input_tokens, None);
}

#[test]
fn test_write_response_roundtrip_text_only() {
    // The writer re-emits the SDK-required top-level identity (`id`/`created_at`/`model`/`status`/
    // `error:null`) AND a CONFORMANT message output item: a native message item carries an
    // item-level opaque `id` (`msg_…`), a `status`, and `annotations: []` on the `output_text`
    // part — exactly what the streaming `output_item.done` emits. The non-stream writer must too,
    // or a typed SDK reading `item.id`/`item.status`/`content[0].annotations` sees missing fields
    // (a proxy tell). Because the synthesized item id is opaque/random (as native ids are), this
    // asserts CONFORMANCE + field preservation rather than byte-equality.
    let json = serde_json::json!({
        "id": "resp_abc123",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "Hello world"}]
            }
        ],
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "error": serde_json::Value::Null
    });

    let reader = ResponsesReader;
    let writer = ResponsesWriter;

    let ir_resp = reader.read_response(&json).expect("read should succeed");
    let out = writer.write_response(&ir_resp);

    // Top-level identity preserved verbatim.
    assert_eq!(out["id"], json["id"]);
    assert_eq!(out["object"], "response"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(out["created_at"], json["created_at"]);
    assert_eq!(out["status"], "completed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(out["model"], "gpt-4o");
    assert_eq!(out["usage"], json["usage"]);
    assert!(out["error"].is_null());

    // The message output item is conformant: native opaque id, status, and annotations.
    let item = &out["output"][0];
    assert_eq!(item["type"], "message"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(item["role"], "assistant");
    assert_eq!(item["status"], "completed"); // golden wire-contract literal (kept bare on purpose)
    let id = item["id"].as_str().expect("message item carries an id");
    assert!(
        id.starts_with("msg_") && id.len() > 4,
        "item id must be a native opaque msg_ token, got {id}"
    ); // golden wire-contract literal (kept bare on purpose)
    let part = &item["content"][0];
    assert_eq!(part["type"], "output_text"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(part["text"], "Hello world");
    assert!(
        part["annotations"].as_array().is_some_and(|a| a.is_empty()),
        "output_text part must carry annotations: [], got {part}"
    );
}

/// Regression (MEDIUM/conformance): the NON-streaming `write_response` function_call
/// item must carry the item-level opaque `id` (`fc_…`, distinct from `call_id`) that the streaming
/// `output_item.done` emits, or a typed SDK reading `item.id` sees a missing field.
#[test]
fn test_write_response_function_call_item_has_native_id() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        id: Some("resp_x".to_string()),
        model: Some("gpt-4o".to_string()),
        created: Some(1_700_000_000),
        content: vec![crate::ir::IrBlock::ToolUse {
            id: "call_abc".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"city": "SF"}),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        system_fingerprint: None,
    };
    let writer = ResponsesWriter;
    let out = writer.write_response(&resp);
    let fc = out["output"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["type"] == "function_call")) // golden wire-contract literal (kept bare on purpose)
        .expect("a function_call output item");
    assert_eq!(fc["call_id"], "call_abc", "call_id preserved");
    let id = fc["id"]
        .as_str()
        .expect("function_call item carries an item-level id");
    assert!(
        id.starts_with("fc_") && id.len() > 3,
        "function_call item id must be a native opaque fc_ token, got {id}"
    ); // golden wire-contract literal (kept bare on purpose)
}

/// Regression (MED #1): the NON-streaming `read_response` tool-use override must NOT clobber a
/// truncation reason. An `incomplete` body with `incomplete_details.reason=max_output_tokens` that
/// also carries a (partial) `function_call` item was cut off mid-output — its stop_reason must stay
/// `max_tokens`, NOT be promoted to `tool_use`. Before the fix the override fired unconditionally on
/// any ToolUse block, clobbering `max_tokens` and telling the client the call was complete (and
/// denying the truncation signal to the breaker). The override is now guarded on `end_turn` only,
/// mirroring the streaming `response.completed` arm.
#[test]
fn test_read_response_incomplete_with_function_call_keeps_max_tokens() {
    let json = serde_json::json!({
        "id": "resp_trunc",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_INCOMPLETE,
        "model": "gpt-4o",
        "incomplete_details": { "reason": INCOMPLETE_REASON_MAX_OUTPUT },
        "output": [
            {
                "type": ITEM_TYPE_FUNCTION_CALL,
                "call_id": "call_1",
                "name": "get_weather",
                "arguments": "{\"city\":\"SF\"}"
            }
        ],
        "usage": {"input_tokens": 10, "output_tokens": 5}
    });

    let reader = ResponsesReader;
    let resp = reader.read_response(&json).expect("read should succeed");

    // The tool call survived as content...
    assert!(
        resp.content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })),
        "the partial function_call must still be present as a ToolUse block"
    );
    // ...but the truncation reason must NOT have been clobbered to tool_use.
    assert_eq!(
        resp.stop_reason,
        Some(crate::ir::IrStopReason::MaxTokens),
        "an incomplete (max_output_tokens) response must keep stop_reason=max_tokens, not be \
             promoted to tool_use just because a partial function_call survived"
    );
}

/// Regression (refusal data-loss): a native Responses refusal rides on a
/// `{type:"refusal", refusal:"..."}` content part with `status:"completed"`. The prior reader
/// matched only `output_text`, so the refusal text was SILENTLY DROPPED and the turn looked like a
/// clean empty end_turn. The refusal text must survive as assistant content AND the stop_reason
/// must be promoted to `Refusal` (so a non-Responses client sees the refusal signal).
#[test]
fn read_response_refusal_part_survives_and_promotes_stop_reason() {
    let json = serde_json::json!({
        "id": "resp_refuse",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [
                    { "type": "refusal", "refusal": "I can't help with that." }
                ]
            }
        ],
        "usage": {"input_tokens": 10, "output_tokens": 5}
    });

    let reader = ResponsesReader;
    let resp = reader.read_response(&json).expect("read should succeed");

    // The refusal text survived as assistant Text (not dropped).
    assert!(
        resp.content.iter().any(|b| matches!(
            b,
            crate::ir::IrBlock::Text { text, .. } if text == "I can't help with that."
        )),
        "the refusal text must survive as assistant content, not be silently dropped: {:?}",
        resp.content
    );
    // The completed status was promoted to the typed Refusal stop_reason.
    assert_eq!(
        resp.stop_reason,
        Some(crate::ir::IrStopReason::Refusal),
        "a completed response carrying a refusal part must surface stop_reason=refusal"
    );
}

/// Regression (LOW #5): `write_response` must build the `output` array in IR ENCOUNTER order so it
/// mirrors the streaming `drain_output_items` order. A prior revision `insert(0)`'d the text message
/// item at the FRONT, so a text-AFTER-tool response emitted [message, function_call] on the
/// non-stream path while the stream emitted [function_call, message] — a client reassembling
/// `response.output[]` saw the two paths disagree. Order must now follow the blocks: tool, then text.
#[test]
fn test_write_response_preserves_text_after_tool_order() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        id: Some("resp_order".to_string()),
        model: Some("gpt-4o".to_string()),
        created: Some(1_700_000_000),
        content: vec![
            crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            },
            crate::ir::IrBlock::Text {
                text: "Here is the weather.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        system_fingerprint: None,
    };
    let writer = ResponsesWriter;
    let out = writer.write_response(&resp);
    let arr = out["output"].as_array().expect("output is an array");
    assert_eq!(arr.len(), 2, "one item per non-empty block, in order");
    // Encounter order: the tool block came first, the text block second.
    assert_eq!(
        arr[0]["type"],
        "function_call", // golden wire-contract literal (kept bare on purpose)
        "the tool block was first in IR content, so it must be output[0]"
    );
    assert_eq!(arr[0]["call_id"], "call_1");
    assert_eq!(
        arr[1]["type"],
        "message", // golden wire-contract literal (kept bare on purpose)
        "the text block came after the tool block, so it must NOT be forced to output[0]"
    );
    assert_eq!(arr[1]["content"][0]["text"], "Here is the weather.");
}

/// The native Responses error envelope an official SDK decodes: a JSON object whose `error`
/// carries `message`, a Responses-vocabulary `type`, and `code`/`param` keys (null here).
#[test]
fn test_write_error_native_responses_envelope() {
    let writer = ResponsesWriter;
    let v = writer.write_error(404, "not_found", "model 'x' not found");

    // Round-trips as JSON without panic.
    let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
    let reparsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

    let err = reparsed.get("error").expect("error object present");
    assert_eq!(
        err.get("message").and_then(|m| m.as_str()),
        Some("model 'x' not found")
    );
    // Generic `not_found` maps to the Responses vocabulary `not_found_error`.
    assert_eq!(
        err.get("type").and_then(|t| t.as_str()),
        Some("not_found_error")
    );
    // `code` and `param` keys are present and null (Responses/OpenAI always include them).
    assert!(err.get("code").is_some(), "code key must be present");
    assert!(err.get("param").is_some(), "param key must be present");
    assert!(err.get("code").unwrap().is_null());
    assert!(err.get("param").unwrap().is_null());
}

/// Each generic `kind` maps to the canonical Responses `error.type`; an unrecognized kind is
/// passed through verbatim (no catch-all swallowing of a precise upstream type).
#[test]
fn test_write_error_kind_mapping() {
    let writer = ResponsesWriter;
    // The `want` values are golden wire-contract literals (kept bare on purpose) — they are the
    // exact `error.type` strings busbar emits for each input kind.
    for (kind, want) in [
        ("invalid_request", "invalid_request_error"),
        ("auth", "authentication_error"),
        ("forbidden", "permission_error"),
        ("not_found", "not_found_error"),
        ("rate_limit", "rate_limit_error"),
        ("server_error", "server_error"),
        ("billing", "insufficient_quota"),
        // Already-canonical and unknown types pass through unchanged.
        ("authentication_error", "authentication_error"),
        ("some_future_type", "some_future_type"),
    ] {
        let v = writer.write_error(400, kind, "m");
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some(want),
            "kind {kind} should map to {want}"
        );
    }
}

/// Same-protocol passthrough: `read_response` captures the upstream `id`/`created_at`, and
/// `write_response` emits them verbatim — identity is preserved exactly, not regenerated.
#[test]
fn test_same_protocol_roundtrip_preserves_identity() {
    let json = serde_json::json!({
        "id": "resp_0123456789abcdef",
        "object": OBJ_RESPONSE,
        "created_at": 1_710_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o-2024-08-06",
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
            }
        ],
        "usage": {"input_tokens": 3, "output_tokens": 1}
    });

    let reader = ResponsesReader;
    let writer = ResponsesWriter;

    let ir = reader.read_response(&json).expect("read should succeed");
    assert_eq!(ir.id.as_deref(), Some("resp_0123456789abcdef"));
    assert_eq!(ir.created, Some(1_710_000_000));

    let out = writer.write_response(&ir);
    assert_eq!(
        out.get("id").and_then(|i| i.as_str()),
        Some("resp_0123456789abcdef"),
        "id must be preserved verbatim"
    );
    assert_eq!(
        out.get("created_at").and_then(|c| c.as_u64()),
        Some(1_710_000_000),
        "created_at must be preserved verbatim"
    );
    assert_eq!(out.get("object").and_then(|o| o.as_str()), Some("response"));
    // golden wire-contract literal (kept bare on purpose)
}

/// The streaming start event captures the nested `response` identity for same-protocol
/// passthrough.
#[test]
fn test_stream_message_start_captures_identity() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_CREATED,
        &serde_json::json!({
            "response": {
                "id": "resp_streamid",
                "object": OBJ_RESPONSE,
                "created_at": 1_720_000_000_u64,
                "model": "gpt-4o",
                "status": STATUS_IN_PROGRESS
            }
        }),
        &mut state,
    );
    assert_eq!(events.len(), 1);
    match &events[0] {
        crate::ir::IrStreamEvent::MessageStart {
            id, created, model, ..
        } => {
            assert_eq!(id.as_deref(), Some("resp_streamid"));
            assert_eq!(*created, Some(1_720_000_000));
            assert_eq!(model.as_deref(), Some("gpt-4o"));
        }
        other => panic!("expected MessageStart, got {other:?}"),
    }
}

/// Cross-protocol: when the IR carries no identity (the backend supplied none), `write_response`
/// synthesizes a valid `resp_`-prefixed id and a current `created_at` without panicking, and two
/// successive synthesized ids are distinct.
#[test]
fn test_cross_protocol_write_synthesizes_valid_id() {
    let writer = ResponsesWriter;
    let make_ir = || crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "answer".to_string(),
            cache_control: None,
            citations: Vec::new(),
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

    let out1 = writer.write_response(&make_ir());
    let id1 = out1
        .get("id")
        .and_then(|i| i.as_str())
        .expect("synthesized id present");
    assert!(
        id1.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
        "synthesized id must use the resp_ prefix, got {id1}"
    );
    assert!(
        out1.get("created_at").and_then(|c| c.as_u64()).is_some(),
        "synthesized created_at must be present"
    );

    let out2 = writer.write_response(&make_ir());
    let id2 = out2.get("id").and_then(|i| i.as_str()).unwrap();
    assert_ne!(id1, id2, "successive synthesized ids must be unique");
}

#[test]
fn test_stream_fanout() {
    let mut state = crate::ir::StreamDecodeState::default();

    // response.created → MessageStart only (first time)
    let events1 = reader_read_response_events(
        EVT_RESPONSE_CREATED,
        &serde_json::json!({"response": {"object": OBJ_RESPONSE, "status": STATUS_IN_PROGRESS}}),
        &mut state,
    );
    assert_eq!(events1.len(), 1);
    assert!(matches!(
        events1[0],
        crate::ir::IrStreamEvent::MessageStart { .. }
    ));
    // response.output_item.added for function_call → BlockStart
    let events2 = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 1,
            "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id":"fc_1","name":"get_weather"}
        }),
        &mut state,
    );
    assert_eq!(events2.len(), 1);
    assert!(matches!(
        events2[0],
        crate::ir::IrStreamEvent::BlockStart { .. }
    ));
    // response.output_text.delta ×3 → BlockStart (lazy) + BlockDelta ×3
    let delta_json = |d: &str| serde_json::json!({"output_index": 0, "delta": d});
    let events3a = reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("H"), &mut state);
    assert_eq!(events3a.len(), 2); // BlockStart + BlockDelta
    assert!(matches!(
        events3a[0],
        crate::ir::IrStreamEvent::BlockStart { .. }
    ));
    assert!(matches!(
        events3a[1],
        crate::ir::IrStreamEvent::BlockDelta { .. }
    ));
    let events3b = reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("i"), &mut state);
    assert_eq!(events3b.len(), 1); // BlockDelta only
    assert!(matches!(
        events3b[0],
        crate::ir::IrStreamEvent::BlockDelta { .. }
    ));
    let events3c = reader_read_response_events(EVT_OUTPUT_TEXT_DELTA, &delta_json("!"), &mut state);
    assert_eq!(events3c.len(), 1); // BlockDelta only

    // response.output_item.done → BlockStop
    let events4 = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert_eq!(events4.len(), 1);
    assert!(matches!(
        events4[0],
        crate::ir::IrStreamEvent::BlockStop { .. }
    ));
    // response.completed with usage. The function_call block opened at index 1 (events2) was
    // never closed by an `output_item.done`, so it is STILL OPEN at the terminal event. The
    // terminal arm must close it (BlockStop{index:1}) BEFORE MessageStop so the stream stays
    // balanced (MED #5), giving: BlockStop + MessageDelta + MessageStop.
    let completed_json = serde_json::json!({
        "response": {
            "status": STATUS_COMPLETED,
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }
    });
    let events5 = reader_read_response_events(EVT_RESPONSE_COMPLETED, &completed_json, &mut state);
    assert_eq!(events5.len(), 3);
    assert!(
        matches!(events5[0], crate::ir::IrStreamEvent::BlockStop { index: 1 }),
        "still-open tool block at index 1 must be closed before MessageStop, got {:?}",
        events5[0]
    );
    assert!(matches!(
        events5[1],
        crate::ir::IrStreamEvent::MessageDelta { .. }
    ));
    assert!(matches!(events5[2], crate::ir::IrStreamEvent::MessageStop));
    // response.in_progress should not emit MessageStart again (state.started=true)
    let events6 = reader_read_response_events(
        "response.in_progress",
        &serde_json::json!({"response": {"object": OBJ_RESPONSE, "status": STATUS_IN_PROGRESS}}),
        &mut state,
    );
    assert_eq!(events6.len(), 0);

    // Unknown event type → empty (no panic)
    let events7 = reader_read_response_events(
        "response.content_part.added",
        &serde_json::json!({}),
        &mut state,
    );
    assert_eq!(events7.len(), 0);
}

/// Regression (refusal stream data-loss): a STREAMED Responses refusal carries its text only in
/// the terminal `response.completed` frame as an `output[].content[]` `{type:"refusal"}` part
/// (status `completed`). The streaming reader previously handled only `output_text.delta`, so it
/// SILENTLY DROPPED the refusal text AND left stop_reason=end_turn. It must now surface the
/// refusal text as a Text block and promote stop_reason to Refusal (mirroring the non-stream path).
#[test]
fn read_response_events_streamed_refusal_surfaces_text_and_refusal_stop_reason() {
    use crate::ir::{IrDelta, IrStopReason, IrStreamEvent};
    let mut state = crate::ir::StreamDecodeState::default();
    // No output_text.delta is emitted for a refusal — only the terminal completed frame.
    let events = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({
            "response": {
                "object": OBJ_RESPONSE,
                "status": STATUS_COMPLETED,
                "output": [{
                    "type": ITEM_TYPE_MESSAGE,
                    "role": "assistant",
                    "content": [{ "type": "refusal", "refusal": "I can't help with that." }]
                }],
                "usage": { "input_tokens": 5, "output_tokens": 3 }
            }
        }),
        &mut state,
    );

    // The refusal text surfaced as a Text BlockDelta (not dropped).
    assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta { delta: IrDelta::TextDelta(t), .. } if t == "I can't help with that."
            )),
            "streamed refusal text must surface as a TextDelta; got {events:?}"
        );
    // The terminal MessageDelta promoted stop_reason to Refusal (not end_turn).
    let stop = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
        _ => None,
    });
    assert_eq!(
        stop,
        Some(Some(IrStopReason::Refusal)),
        "a streamed refusal must terminate with stop_reason=Refusal; got {events:?}"
    );
    // Block open/close balance: exactly one BlockStart and one BlockStop for the refusal block.
    let starts = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
        .count();
    let stops = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
        .count();
    assert_eq!(
        (starts, stops),
        (1, 1),
        "one Start/Stop for the refusal block; got {events:?}"
    );
}

#[test]
fn test_write_response_event_blockdelta() {
    let writer = ResponsesWriter;

    // BlockDelta TextDelta("hi") → ("response.output_text.delta", delta=="hi")
    let ev1 = crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    };
    let (etype1, payload1) = writer.write_response_event(&ev1).expect("should emit");
    assert_eq!(etype1, "response.output_text.delta"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(payload1.get("delta").and_then(|d| d.as_str()), Some("hi"));

    // MessageDelta{end_turn} → ("response.completed", status maps to completed)
    let ev2 = crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (etype2, payload2) = writer.write_response_event(&ev2).expect("should emit");
    assert_eq!(etype2, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    let resp_obj = payload2
        .get("response")
        .expect("payload should have response");
    assert_eq!(
        resp_obj.get("status"),
        Some(&serde_json::json!("completed")) // golden wire-contract literal (kept bare on purpose)
    );
}

fn reader_read_response_events(
    event_type: &str,
    data: &serde_json::Value,
    state: &mut crate::ir::StreamDecodeState,
) -> Vec<crate::ir::IrStreamEvent> {
    let reader = ResponsesReader;
    reader.read_response_events(event_type, data, state)
}

/// Regression: a text part arriving at a non-zero `output_index` must open AND write to the
/// same block index. Previously BlockStart was hard-coded to index 0 while BlockDelta used the
/// wire index, producing an unmatched open/write pair for downstream index-keyed consumers.
#[test]
fn test_text_delta_index_pairing_nonzero() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 2, "delta": "hello"}),
        &mut state,
    );
    assert_eq!(events.len(), 2, "expected lazy BlockStart + BlockDelta");
    let start_idx = match &events[0] {
        crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
        other => panic!("first event should be BlockStart, got {other:?}"),
    };
    let delta_idx = match &events[1] {
        crate::ir::IrStreamEvent::BlockDelta { index, .. } => *index,
        other => panic!("second event should be BlockDelta, got {other:?}"),
    };
    assert_eq!(start_idx, 2, "BlockStart must use the wire output_index");
    assert_eq!(delta_idx, 2, "BlockDelta must use the wire output_index");
    assert_eq!(start_idx, delta_idx, "open/write indices must match");
}

/// Regression: an empty-delta keepalive chunk must produce no events, even when a text block is
/// already open. Previously the guard `|| state.text_block_open` emitted a spurious zero-length
/// TextDelta for every keepalive after the block opened.
#[test]
fn test_empty_delta_keepalive_emits_nothing() {
    let mut state = crate::ir::StreamDecodeState::default();
    // Open a block with a real delta first.
    let opened = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "x"}),
        &mut state,
    );
    assert_eq!(opened.len(), 2);
    assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    // Now an empty keepalive while the block is open -> nothing.
    let keepalive = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": ""}),
        &mut state,
    );
    assert!(
        keepalive.is_empty(),
        "empty keepalive delta must not emit events, got {keepalive:?}"
    );
    // And an empty delta before any block is open also emits nothing.
    let mut fresh = crate::ir::StreamDecodeState::default();
    let pre = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": ""}),
        &mut fresh,
    );
    assert!(pre.is_empty());
    assert!(!fresh.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
}

/// Regression: output_item.done must clear the open TEXT index so a subsequent text part can
/// lazily re-open its own block instead of silently reusing stale open state.
#[test]
fn test_done_clears_text_block_open() {
    let mut state = crate::ir::StreamDecodeState::default();
    let _ = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "a"}),
        &mut state,
    );
    assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    let done = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert_eq!(done.len(), 1);
    assert!(matches!(
        done[0],
        crate::ir::IrStreamEvent::BlockStop { .. }
    ));
    assert!(
        !state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
        "done must clear the open text index"
    );
    // A new text part at index 1 re-opens lazily.
    let reopen = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 1, "delta": "b"}),
        &mut state,
    );
    assert_eq!(reopen.len(), 2);
    assert!(matches!(
        reopen[0],
        crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
    ));
}

/// Regression (MED #4): a bodyless `response.incomplete` terminal event (no nested `response`
/// object) must NOT decode to a successful `end_turn`. With no `incomplete_details.reason`
/// available there is no specific truncation reason, so the stop_reason must be None — masking
/// a truncation as end_turn would lie to a downstream client. Previously the else branch
/// hardcoded `Some("end_turn")` for every bodyless terminal regardless of event_type.
#[test]
fn test_bodyless_incomplete_is_not_end_turn() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_INCOMPLETE,
        // No nested `response` object at all.
        &serde_json::json!({}),
        &mut state,
    );
    // Stream still terminates: MessageDelta + MessageStop.
    let delta_stop = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
            _ => None,
        })
        .expect("bodyless incomplete must still emit a MessageDelta");
    assert_eq!(
        *delta_stop, None,
        "bodyless incomplete must surface stop_reason None, not a fabricated end_turn"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageStop)),
        "stream must still terminate with MessageStop"
    );

    // And a bodyless `completed` still maps to end_turn (the only successful terminal).
    let mut s2 = crate::ir::StreamDecodeState::default();
    let completed =
        reader_read_response_events(EVT_RESPONSE_COMPLETED, &serde_json::json!({}), &mut s2);
    let completed_reason = completed
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
            _ => None,
        })
        .expect("bodyless completed must still emit a MessageDelta");
    assert_eq!(
        *completed_reason,
        Some(crate::ir::IrStopReason::EndTurn),
        "bodyless completed must map to end_turn"
    );
}

#[test]
fn test_stream_completed_with_function_call_is_tool_use_not_end_turn() {
    // A STREAMED Responses tool call must terminate with stop_reason=tool_use, matching the
    // non-streaming read_response (which flips a completed end_turn to tool_use when the output
    // carries a function_call). Before the fix the stream said end_turn, so a cross-protocol
    // client never saw the tool-call finish signal on the streaming path.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({
            "response": {
                "status": STATUS_COMPLETED,
                "output": [
                    { "type": ITEM_TYPE_FUNCTION_CALL, "id": "fc_1", "call_id": "call_1",
                      "name": "get_weather", "arguments": "{}" }
                ]
            }
        }),
        &mut state,
    );
    let stop = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
            _ => None,
        })
        .expect("terminal MessageDelta");
    assert_eq!(
        *stop,
        Some(crate::ir::IrStopReason::ToolUse),
        "a streamed completed response containing a function_call must be tool_use, not end_turn"
    );
}

#[test]
fn test_stream_completed_without_function_call_stays_end_turn() {
    // No function_call in the output → still a plain end_turn (the override must not over-fire).
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({
            "response": {
                "status": STATUS_COMPLETED,
                "output": [
                    { "type": ITEM_TYPE_MESSAGE, "role": "assistant",
                      "content": [{ "type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi", "annotations": [] }] }
                ]
            }
        }),
        &mut state,
    );
    let stop = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => Some(stop_reason),
            _ => None,
        })
        .expect("terminal MessageDelta");
    assert_eq!(
        *stop,
        Some(crate::ir::IrStopReason::EndTurn),
        "text-only completed stays end_turn"
    );
}

/// Regression (MED #5): a terminal event arriving while a content block is STILL OPEN must
/// close that block (BlockStop) before MessageStop. Otherwise the translated stream emits a
/// BlockStart with no matching BlockStop — an unbalanced sequence a strict SDK rejects. This
/// covers every terminal sub-path: bodyless completed/incomplete, body-present
/// completed/incomplete, the body-present `failed` early-return, and the bodyless `failed`
/// arm — each with an open text block AND an open tool block to prove both key kinds drain.
#[test]
fn test_terminal_closes_open_blocks_balanced() {
    // Helper: opens a text block at index 0 and a tool block at index 1, then fires `etype`
    // with `data`, and asserts every BlockStart in the WHOLE stream has a matching BlockStop.
    fn assert_balanced(etype: &str, data: serde_json::Value) {
        let mut state = crate::ir::StreamDecodeState::default();
        let mut all: Vec<crate::ir::IrStreamEvent> = Vec::new();
        // Open a text block at index 0.
        all.extend(reader_read_response_events(
            EVT_OUTPUT_TEXT_DELTA,
            &serde_json::json!({"output_index": 0, "delta": "partial"}),
            &mut state,
        ));
        // Open a tool block at index 1.
        all.extend(reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": 1,
                "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "c1", "name": "f"}
            }),
            &mut state,
        ));
        // Sanity: both blocks are open before the terminal event.
        assert!(
            state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
            "{etype}: text block should be open"
        );
        assert!(
            state.open_tools.contains(&1),
            "{etype}: tool block should be open"
        );
        // Fire the terminal event.
        all.extend(reader_read_response_events(etype, &data, &mut state));

        // Count BlockStart vs BlockStop per index — every open index must be closed exactly
        // once and no stray closes.
        use std::collections::BTreeMap;
        let mut starts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut stops: BTreeMap<usize, usize> = BTreeMap::new();
        for ev in &all {
            match ev {
                crate::ir::IrStreamEvent::BlockStart { index, .. } => {
                    *starts.entry(*index).or_insert(0) += 1;
                }
                crate::ir::IrStreamEvent::BlockStop { index } => {
                    *stops.entry(*index).or_insert(0) += 1;
                }
                _ => {}
            }
        }
        assert_eq!(
                starts, stops,
                "{etype}: BlockStart/BlockStop counts must balance per index (starts={starts:?} stops={stops:?})"
            );
        // Specifically index 0 (text) and index 1 (tool) were each opened once and closed once.
        assert_eq!(
            starts.get(&0).copied(),
            Some(1),
            "{etype}: text opened once"
        );
        assert_eq!(stops.get(&0).copied(), Some(1), "{etype}: text closed once");
        assert_eq!(
            starts.get(&1).copied(),
            Some(1),
            "{etype}: tool opened once"
        );
        assert_eq!(stops.get(&1).copied(), Some(1), "{etype}: tool closed once");
        // The terminal arm must have drained the open set.
        assert!(
            state.open_tools.is_empty(),
            "{etype}: open_tools must be drained after the terminal event"
        );
        // BlockStop for an index must precede MessageStop (a stop after the message-end is
        // out of order). Verify the last BlockStop comes before MessageStop.
        let msg_stop_pos = all
            .iter()
            .position(|e| matches!(e, crate::ir::IrStreamEvent::MessageStop))
            .expect("must emit MessageStop");
        let last_block_stop = all
            .iter()
            .rposition(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { .. }))
            .expect("must emit BlockStop");
        assert!(
            last_block_stop < msg_stop_pos,
            "{etype}: all BlockStop must precede MessageStop"
        );
    }

    // Bodyless terminals (no nested `response`).
    assert_balanced(EVT_RESPONSE_COMPLETED, serde_json::json!({}));
    assert_balanced(EVT_RESPONSE_INCOMPLETE, serde_json::json!({}));
    assert_balanced(EVT_RESPONSE_FAILED, serde_json::json!({}));

    // Body-present completed.
    assert_balanced(
        EVT_RESPONSE_COMPLETED,
        serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
    );
    // Body-present incomplete (truncated mid-block).
    assert_balanced(
        EVT_RESPONSE_INCOMPLETE,
        serde_json::json!({
            "response": {"status": STATUS_INCOMPLETE, "incomplete_details": {"reason": INCOMPLETE_REASON_MAX_OUTPUT}}
        }),
    );
    // Body-present failed (the early-return path).
    assert_balanced(
        EVT_RESPONSE_FAILED,
        serde_json::json!({"response": {"status": STATUS_FAILED, "error": {"code": ERR_TYPE_SERVER_ERROR}}}),
    );
}

/// Regression: content_part.done is also a terminal-of-part signal and must close its block.
#[test]
fn test_content_part_done_closes_block() {
    let mut state = crate::ir::StreamDecodeState::default();
    let _ = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "a"}),
        &mut state,
    );
    let done = reader_read_response_events(
        "response.content_part.done",
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert_eq!(done.len(), 1);
    assert!(matches!(
        done[0],
        crate::ir::IrStreamEvent::BlockStop { .. }
    ));
    assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
}

/// Regression: a minimal `response.completed` lacking a nested `response` object must still
/// terminate the stream with MessageDelta + MessageStop, not leave it hanging.
#[test]
fn test_completed_without_response_object_terminates() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events =
        reader_read_response_events(EVT_RESPONSE_COMPLETED, &serde_json::json!({}), &mut state);
    assert_eq!(events.len(), 2, "must emit MessageDelta + MessageStop");
    assert!(matches!(
        events[0],
        crate::ir::IrStreamEvent::MessageDelta { .. }
    ));
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
}

/// Regression: same for `response.incomplete` with no nested response object.
#[test]
fn test_incomplete_without_response_object_terminates() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events =
        reader_read_response_events(EVT_RESPONSE_INCOMPLETE, &serde_json::json!({}), &mut state);
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0],
        crate::ir::IrStreamEvent::MessageDelta { .. }
    ));
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

    // response.failed without object still works (pre-existing behavior preserved).
    let mut s2 = crate::ir::StreamDecodeState::default();
    let failed = reader_read_response_events(EVT_RESPONSE_FAILED, &serde_json::json!({}), &mut s2);
    assert_eq!(failed.len(), 2);
    assert!(matches!(failed[1], crate::ir::IrStreamEvent::MessageStop));
}

/// Regression: an input item carrying BOTH a `type` and a `role` must be processed exactly once
/// (by the type arm), not duplicated by the role-keyed fallback.
#[test]
fn test_typed_item_with_role_not_duplicated() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {
                "type": CONTENT_TYPE_OUTPUT_TEXT,
                "role": "assistant",
                "text": "hello",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "DUPLICATE"}]
            }
        ]
    });
    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("read_request should succeed");
    // Exactly one message: the type arm produced the assistant text turn; the role fallback
    // must NOT have added a second turn from the `content` array.
    assert_eq!(ir.messages.len(), 1, "typed+role item must not duplicate");
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::Assistant);
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello"),
        other => panic!("expected text turn, got {other:?}"),
    }
}

/// Regression: an assistant turn that is PURELY a tool call must emit a flat `function_call`
/// item and NO companion empty-content assistant `message` wrapper. The Responses API rejects
/// assistant message items with `content: []`.
#[test]
fn test_tool_only_assistant_turn_no_empty_message_wrapper() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "fc_1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            }],
        }],
        tools: Vec::new(),
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
    let writer = ResponsesWriter;
    let json = writer.write_request(&ir);
    let input = json
        .get("input")
        .and_then(|v| v.as_array())
        .expect("input should exist");
    // Exactly one item: the function_call. No empty-content assistant message.
    assert_eq!(
        input.len(),
        1,
        "tool-only turn must not emit an empty message wrapper, got {input:?}"
    );
    assert_eq!(
        input[0].get("type").and_then(|t| t.as_str()),
        Some("function_call") // golden wire-contract literal (kept bare on purpose)
    );
    // No item should be a message with an empty content array.
    for item in input {
        if item.get("role").is_some() {
            let content = item.get("content").and_then(|c| c.as_array());
            assert!(
                content.map(|c| !c.is_empty()).unwrap_or(true),
                "no assistant message item may have empty content"
            );
        }
    }
}

/// Regression: an assistant turn carrying BOTH text and a tool call must emit the assistant
/// `message` (with the text) FIRST, then the flat `function_call` item AFTER it — preserving
/// the conversation order the assistant produced.
#[test]
fn test_assistant_text_then_tool_call_order() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "Let me check.".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::ToolUse {
                    id: "fc_9".to_string(),
                    name: "lookup".to_string(),
                    input: serde_json::json!({}),
                    cache_control: None,
                },
            ],
        }],
        tools: Vec::new(),
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
    let writer = ResponsesWriter;
    let json = writer.write_request(&ir);
    let input = json
        .get("input")
        .and_then(|v| v.as_array())
        .expect("input should exist");
    assert_eq!(
        input.len(),
        2,
        "expected message + function_call, got {input:?}"
    );
    // Message first.
    assert_eq!(
        input[0].get("role").and_then(|r| r.as_str()),
        Some("assistant")
    );
    let content = input[0]
        .get("content")
        .and_then(|c| c.as_array())
        .expect("message content");
    assert_eq!(
        content[0].get("text").and_then(|t| t.as_str()),
        Some("Let me check.")
    );
    // function_call after it.
    assert_eq!(
        input[1].get("type").and_then(|t| t.as_str()),
        Some("function_call") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        input[1].get("call_id").and_then(|c| c.as_str()),
        Some("fc_9")
    );
}

/// Regression: a streaming `response.failed` (status=="failed") must surface an
/// IrStreamEvent::Error followed by MessageStop, NOT a successful end_turn MessageDelta that
/// would mask the failure from a downstream client.
#[test]
fn test_stream_failed_status_emits_error_not_end_turn() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_FAILED,
        &serde_json::json!({
            "response": {
                "status": STATUS_FAILED,
                "error": {"code": ERR_TYPE_SERVER_ERROR, "type": ERR_TYPE_SERVER_ERROR}
            }
        }),
        &mut state,
    );
    assert_eq!(
        events.len(),
        2,
        "expected Error + MessageStop, got {events:?}"
    );
    match &events[0] {
        crate::ir::IrStreamEvent::Error(err) => {
            assert_eq!(err.provider_signal.as_deref(), Some("server_error"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    // Crucially, no MessageDelta with end_turn was emitted.
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageDelta { .. })),
        "failed stream must not emit a MessageDelta"
    );
}

/// Regression (LOW #8): a streamed `response.failed` must classify the IrError by the captured
/// provider signal, not a hardcoded ServerError. An `invalid_api_key` mid-stream failure is an
/// Auth failure (HardDown breaker disposition), NOT a transient ServerError — hardcoding
/// ServerError gave the wrong breaker disposition / failover. The provider_signal is preserved
/// verbatim. Against the old code (class: ServerError) this asserts Auth and fails.
#[test]
fn test_stream_failed_invalid_api_key_classifies_as_auth() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_FAILED,
        &serde_json::json!({
            "response": {
                "status": STATUS_FAILED,
                "error": {"code": "invalid_api_key", "type": ERR_TYPE_AUTHENTICATION}
            }
        }),
        &mut state,
    );
    match &events[0] {
        crate::ir::IrStreamEvent::Error(err) => {
            assert_eq!(
                err.class,
                StatusClass::Auth,
                "invalid_api_key mid-stream must classify as Auth, not ServerError"
            );
            // provider_signal is kept as-is (the captured error.code).
            assert_eq!(err.provider_signal.as_deref(), Some("invalid_api_key"));
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // The full mapping mirrors the non-stream HTTP classifier buckets.
    assert_eq!(
        class_for_response_failed("invalid_api_key"),
        StatusClass::Auth
    );
    assert_eq!(
        class_for_response_failed(ERR_TYPE_AUTHENTICATION),
        StatusClass::Auth
    );
    assert_eq!(
        class_for_response_failed(ERR_CODE_RATE_LIMIT),
        StatusClass::RateLimit
    );
    assert_eq!(
        class_for_response_failed(ERR_TYPE_INSUFFICIENT_QUOTA),
        StatusClass::RateLimit
    );
    assert_eq!(
        class_for_response_failed(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH),
        StatusClass::ContextLength
    );
    assert_eq!(
        class_for_response_failed(ERR_CODE_STRING_ABOVE_MAX),
        StatusClass::ContextLength
    );
    assert_eq!(
        class_for_response_failed(ERR_TYPE_SERVER_ERROR),
        StatusClass::ServerError
    );
    assert_eq!(
        class_for_response_failed(ERR_TYPE_OVERLOADED),
        StatusClass::ServerError
    );
    // Unrecognized signal defaults to the transient ServerError bucket.
    assert_eq!(
        class_for_response_failed("response_failed"),
        StatusClass::ServerError
    );
}

/// Regression (LOW #8 sibling): the NON-streaming `read_response` `status:"failed"` path must
/// also classify by the captured provider signal rather than hardcoding ServerError. A failed
/// body carrying `code:"context_length_exceeded"` is a ContextLength failure (fail over without
/// penalizing the lane), NOT a transient ServerError. Against the old code this asserts
/// ContextLength and fails.
#[test]
fn test_read_response_failed_body_classifies_by_signal() {
    let reader = ResponsesReader;
    let err = reader
            .read_response(&serde_json::json!({
                "status": STATUS_FAILED,
                "output": [],
                "error": {"code": crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH, "type": ERR_TYPE_INVALID_REQUEST}
            }))
            .expect_err("failed body must surface an IrError");
    assert_eq!(
        err.class,
        StatusClass::ContextLength,
        "context_length_exceeded failed body must classify as ContextLength, not ServerError"
    );
    assert_eq!(
        err.provider_signal.as_deref(),
        Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
    );

    // An auth-failed body classifies as Auth.
    let err_auth = reader
        .read_response(&serde_json::json!({
            "status": STATUS_FAILED,
            "output": [],
            "error": {"code": "invalid_api_key", "type": ERR_TYPE_AUTHENTICATION}
        }))
        .expect_err("failed body must surface an IrError");
    assert_eq!(err_auth.class, StatusClass::Auth);
}

/// Regression: an unknown terminal status must not be decoded as a successful end_turn; its
/// stop_reason is None (terminal, but no success claim).
#[test]
fn test_stream_unknown_status_not_end_turn() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({"response": {"status": "some_future_status"}}),
        &mut state,
    );
    assert_eq!(events.len(), 2);
    match &events[0] {
        crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
            assert_eq!(*stop_reason, None, "unknown status must not claim end_turn");
        }
        other => panic!("expected MessageDelta, got {other:?}"),
    }
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
}

/// Regression: a streaming `incomplete` status with NO `incomplete_details` must NOT decode to
/// `stop_reason = Some("end_turn")` — that masks the truncation as a clean completion. It must
/// be `None`, mirroring the non-streaming `read_response` path. Two fallback branches: missing
/// `incomplete_details` entirely, and present-but-without-a-`reason`.
#[test]
fn test_stream_incomplete_without_details_is_none() {
    // Branch 1: no `incomplete_details` at all.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_INCOMPLETE,
        &serde_json::json!({"response": {"status": STATUS_INCOMPLETE}}),
        &mut state,
    );
    assert_eq!(events.len(), 2);
    match &events[0] {
        crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
            assert_eq!(
                *stop_reason, None,
                "incomplete with no details must not claim end_turn"
            );
        }
        other => panic!("expected MessageDelta, got {other:?}"),
    }
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

    // Branch 2: `incomplete_details` present but carries no `reason`.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_INCOMPLETE,
        &serde_json::json!({
            "response": {"status": STATUS_INCOMPLETE, "incomplete_details": {}}
        }),
        &mut state,
    );
    assert_eq!(events.len(), 2);
    match &events[0] {
        crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
            assert_eq!(
                *stop_reason, None,
                "incomplete_details without a reason must not claim end_turn"
            );
        }
        other => panic!("expected MessageDelta, got {other:?}"),
    }
    assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

    // Sanity: a known reason still maps (max_output_tokens -> max_tokens).
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader_read_response_events(
        EVT_RESPONSE_INCOMPLETE,
        &serde_json::json!({
            "response": {
                "status": STATUS_INCOMPLETE,
                "incomplete_details": {"reason": INCOMPLETE_REASON_MAX_OUTPUT}
            }
        }),
        &mut state,
    );
    match &events[0] {
        crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
            assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::MaxTokens));
        }
        other => panic!("expected MessageDelta, got {other:?}"),
    }
}

/// Regression (mirrors `openai_chat.rs::write_request_tool_result_multi_text_concatenates_without_separator`):
/// a multi-block ToolResult must concatenate its text fragments with NO separator. A `.join(" ")`
/// injects a spurious space that corrupts base64 / split-JSON payloads. Covers BOTH the
/// Tool-role flat path AND the Assistant-role inline-tool_result path in `write_request`.
#[test]
fn write_request_tool_result_multi_text_concatenates_without_separator() {
    fn text_block(s: &str) -> crate::ir::IrBlock {
        crate::ir::IrBlock::Text {
            text: s.to_string(),
            cache_control: None,
            citations: Vec::new(),
        }
    }
    let writer = ResponsesWriter;
    let multi = || crate::ir::IrBlock::ToolResult {
        tool_use_id: "call_1".to_string(),
        content: vec![text_block("AAA"), text_block("BBB")],
        is_error: false,
        cache_control: None,
    };

    // Tool-role path.
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Tool,
            content: vec![multi()],
        }],
        tools: Vec::new(),
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
    let item = out["input"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["type"] == "function_call_output"))
        .expect("a function_call_output item (Tool role)");
    assert_eq!(
        item["output"], "AAABBB",
        "Tool-role multi-text ToolResult must concatenate with NO separator, got {}",
        item["output"]
    );

    // Assistant-role inline tool_result path.
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![multi()],
        }],
        tools: Vec::new(),
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
    let item = out["input"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["type"] == "function_call_output"))
        .expect("a function_call_output item (Assistant role)");
    assert_eq!(
        item["output"], "AAABBB",
        "Assistant-role multi-text ToolResult must concatenate with NO separator, got {}",
        item["output"]
    );
}

/// Regression: the streaming error event nests the error inside the `response` object the
/// official SDK streaming decoder reads via `event.response`, and the error object is the
/// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
/// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` (or an
/// extra `type`/`param`) is impossible from real OpenAI and a distinguishability tell.
#[test]
fn test_write_error_stream_event_full_shape() {
    let writer = ResponsesWriter;
    let ev = crate::ir::IrStreamEvent::Error(IrError {
        class: StatusClass::ServerError,
        provider_signal: Some("boom".to_string()),
        retry_after: None,
    });
    let (etype, payload) = writer
        .write_response_event(&ev)
        .expect("error event should emit");
    assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
                                          // The error is nested under `response` (SDK reads `event.response`), not top-level.
    assert!(
        payload.get("error").is_none(),
        "error must not be top-level: {payload}"
    );
    let resp = payload.get("response").expect("response object present");
    assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed")); // golden wire-contract literal (kept bare on purpose)
    let err = resp.get("error").expect("nested error object present");
    assert_eq!(err.get("message").and_then(|m| m.as_str()), Some("boom"));
    // Native ResponseError: code is the non-null enum (here carried from provider_signal).
    assert_eq!(err.get("code").and_then(|c| c.as_str()), Some("boom"));
    assert!(
        !err.as_object().unwrap().contains_key("type"),
        "Responses ResponseError carries no `type` field: {err}"
    );
    assert!(
        !err.as_object().unwrap().contains_key("param"),
        "Responses ResponseError carries no `param` field: {err}"
    );
}

/// Regression: an unknown/unmapped stop_reason must map to a `completed` status (not `failed`),
/// so a future IR reason that did not signal an error is not misclassified as a failure.
#[test]
fn test_unknown_stop_reason_maps_to_completed() {
    let writer = ResponsesWriter;
    // Streaming MessageDelta path.
    let ev = crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::Refusal),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
    assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        payload
            .get("response")
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str()),
        Some("completed"), // golden wire-contract literal (kept bare on purpose)
        "unknown stop_reason must map to completed in stream"
    );

    // Non-streaming write_response path.
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "ok".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::Refusal),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("resp_x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = writer.write_response(&resp);
    assert_eq!(
        out.get("status").and_then(|s| s.as_str()),
        Some("completed"), // golden wire-contract literal (kept bare on purpose)
        "unknown stop_reason must map to completed in write_response"
    );
}

/// Regression: malformed function_call arguments must be preserved as the raw string, not
/// dropped to Null (mirrors the OpenAI reader). Covers both the request and response readers.
#[test]
fn test_malformed_function_call_args_preserved() {
    let reader = ResponsesReader;

    // read_request path.
    let req_json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_1", "name": "f", "arguments": "not-json{"}
        ]
    });
    let ir = reader.read_request(&req_json).expect("read_request ok");
    let tool_use = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .find_map(|b| match b {
            crate::ir::IrBlock::ToolUse { input, .. } => Some(input),
            _ => None,
        })
        .expect("tool use present");
    assert_eq!(
        tool_use.as_str(),
        Some("not-json{"),
        "malformed args must be preserved as raw string, not Null"
    );

    // read_response path.
    let resp_json = serde_json::json!({
        "id": "resp_1",
        "status": STATUS_COMPLETED,
        "output": [
            {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "fc_2", "name": "g", "arguments": "broken]"}
        ],
        "usage": {"input_tokens": 1, "output_tokens": 1}
    });
    let resp = reader.read_response(&resp_json).expect("read_response ok");
    match &resp.content[0] {
        crate::ir::IrBlock::ToolUse { input, .. } => {
            assert_eq!(input.as_str(), Some("broken]"));
        }
        other => panic!("expected ToolUse, got {other:?}"),
    }
}

/// Regression: a base64 `input_image` data URI of the canonical single-`;` shape
/// (`data:image/png;base64,<payload>`) must parse the FULL payload, not drop it to "". The old
/// `splitn(3, ';')` logic yielded only two fields and silently discarded every image. Covers
/// both `read_request` and `responses_block`.
#[test]
fn test_input_image_base64_payload_preserved() {
    let payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    let url = format!("data:image/png;base64,{payload}");

    // read_request path.
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {"type": "input_image", "image_url": url}
        ]
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&json).expect("read_request ok");
    assert_eq!(ir.messages.len(), 1);
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, payload, "full base64 payload must be preserved");
        }
        other => panic!("expected Image, got {other:?}"),
    }

    // responses_block path (e.g. a content block nested in a function_call_output).
    let block = serde_json::json!({"type": "input_image", "image_url": url});
    match responses_block(&block).expect("responses_block ok") {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, payload);
        }
        other => panic!("expected Image, got {other:?}"),
    }
}

/// Regression: a base64 `input_image` must survive a same-protocol read -> write -> read
/// round-trip with its payload intact (the writer emits `data:<mime>;base64,<payload>` which the
/// reader must parse back to the identical pair).
#[test]
fn test_input_image_roundtrip_lossless() {
    let payload = "QUJDMTIzKz0=";
    let media_type = "image/jpeg";
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: media_type.to_string(),
                    data: payload.to_string(),
                },
                cache_control: None,
            }],
        }],
        tools: Vec::new(),
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
    let writer = ResponsesWriter;
    let reader = ResponsesReader;
    let json = writer.write_request(&ir);
    let rt = reader.read_request(&json).expect("read round-trip ok");
    match &rt.messages[0].content[0] {
        crate::ir::IrBlock::Image {
            source:
                crate::ir::IrImageSource::Base64 {
                    media_type: mt,
                    data,
                },
            ..
        } => {
            assert_eq!(mt, media_type);
            assert_eq!(data, payload, "round-trip must not corrupt the payload");
        }
        other => panic!("expected Image, got {other:?}"),
    }
}

/// Regression: a non-data (https) image URL must be stored verbatim under the `image_url`
/// sentinel media_type — NOT mangled into a `// note: non-data URL - ...` comment — and must
/// round-trip back to the exact original URL.
#[test]
fn test_input_image_https_url_sentinel_roundtrip() {
    let url = "https://example.com/cat.png";
    let block = serde_json::json!({"type": "input_image", "image_url": url});
    let stored_url = match responses_block(&block).expect("responses_block ok") {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => url,
        other => panic!("expected Image(Url), got {other:?}"),
    };
    assert_eq!(
        stored_url, url,
        "URL must be stored verbatim as the typed Url source"
    );
    assert!(
        !stored_url.starts_with("// note"),
        "must not embed a human comment in the payload"
    );

    // Round-trip through the writer reconstructs the exact original image_url.
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(stored_url),
                cache_control: None,
            }],
        }],
        tools: Vec::new(),
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
    let writer = ResponsesWriter;
    let json = writer.write_request(&ir);
    let emitted = json["input"][0]["content"][0]["image_url"]
        .as_str()
        .expect("image_url present");
    assert_eq!(emitted, url, "writer must emit the original URL verbatim");
}

/// Regression: `write_request` must emit the `stream` field (a modeled key excluded from
/// `extra`); omitting it answers a `stream: true` request non-streaming and stalls SSE.
#[test]
fn test_write_request_emits_stream() {
    let make = |stream: bool| crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let writer = ResponsesWriter;
    assert_eq!(
        writer.write_request(&make(true)).get("stream"),
        Some(&serde_json::json!(true)),
        "stream: true must be emitted"
    );
    assert_eq!(
        writer.write_request(&make(false)).get("stream"),
        Some(&serde_json::json!(false)),
        "stream: false must be emitted explicitly"
    );
}

/// Regression: a typed `{"type":"message","role":...,"content":[...]}` input item (the official
/// SDK conversation-turn shape) must be read, not silently dropped.
#[test]
fn test_typed_message_item_read() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {"type": ITEM_TYPE_MESSAGE, "role": "user",
             "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hello typed"}]},
            {"type": ITEM_TYPE_MESSAGE, "role": "assistant",
             "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi back"}]}
        ]
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&json).expect("read_request ok");
    assert_eq!(
        ir.messages.len(),
        2,
        "both typed message turns must be read"
    );
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello typed"),
        other => panic!("expected Text, got {other:?}"),
    }
    assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
    match &ir.messages[1].content[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi back"),
        other => panic!("expected Text, got {other:?}"),
    }
}

/// Regression: the streaming `response.created` event must carry `id`/`created_at`/`status`
/// (and `model` when present), not a stub. Forwards captured identity for same-protocol
/// passthrough; synthesizes a valid `resp_` id + current time when the IR carries none.
#[test]
fn test_message_start_emits_identity() {
    let writer = ResponsesWriter;

    // Identity present (same-protocol passthrough): forwarded verbatim.
    let ev = crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: Some("resp_streamid".to_string()),
        created: Some(1_720_000_000),
        model: Some("gpt-4o".to_string()),
    };
    let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
    assert_eq!(etype, "response.created"); // golden wire-contract literal (kept bare on purpose)
    let resp = payload.get("response").expect("response object");
    assert_eq!(
        resp.get("id").and_then(|i| i.as_str()),
        Some("resp_streamid")
    );
    assert_eq!(
        resp.get("created_at").and_then(|c| c.as_u64()),
        Some(1_720_000_000)
    );
    assert_eq!(resp.get("model").and_then(|m| m.as_str()), Some("gpt-4o"));
    assert_eq!(
        resp.get("status").and_then(|s| s.as_str()),
        Some("in_progress") // golden wire-contract literal (kept bare on purpose)
    );

    // Identity absent (cross-protocol, stripped by translate_event): synthesized + valid.
    let ev2 = crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (_, payload2) = writer.write_response_event(&ev2).expect("should emit");
    let resp2 = payload2.get("response").expect("response object");
    let id = resp2
        .get("id")
        .and_then(|i| i.as_str())
        .expect("synthesized id present");
    assert!(
        id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
        "synthesized id must use resp_ prefix, got {id}"
    );
    assert!(
        resp2.get("created_at").and_then(|c| c.as_u64()).is_some(),
        "synthesized created_at must be present"
    );
    // `Response.model` is a REQUIRED non-nullable SDK field, so an absent IR model must emit
    // the DEFAULT_MODEL fallback — NOT omit the key (which fails a strict decoder and is a
    // proxy tell).
    assert_eq!(
        resp2.get("model").and_then(|m| m.as_str()),
        Some(DEFAULT_MODEL),
        "absent model must fall back to DEFAULT_MODEL, not be omitted"
    );
}

/// Regression: synthesized response ids stay distinct even across many calls in the same second
/// (the old `timestamp << 24 ^ counter` folding collided once the counter advanced by 2^24).
#[test]
fn test_synthesize_response_id_unique() {
    let n = 1000;
    let ids: std::collections::HashSet<String> = (0..n).map(|_| synthesize_response_id()).collect();
    assert_eq!(
        ids.len(),
        n,
        "all synthesized ids in a burst must be unique"
    );
    assert!(ids.iter().all(|id| id.starts_with("resp_"))); // golden wire-contract literal (kept bare on purpose)
}

/// Regression (LOW/correctness, Round 18): `synth_token<const N>` documents and now ENFORCES a
/// `N >= 11` floor via a compile-time `const _: () = assert!(N >= 11, ...)` evaluated per
/// monomorphization. The guard cannot be exercised from a passing runtime test (a too-small `N`
/// fails to BUILD, which a `cargo test` body can't observe without a trybuild harness), so this
/// test instead locks the observable contract the guard protects: every synthesized id the live
/// callers mint carries an opaque suffix at least the documented floor wide. Both call sites use
/// 48 (`ITEM_ID_TOKEN_LEN`/`RESPONSE_ID_TOKEN_LEN`); if a future edit narrowed a width below the
/// floor (or someone instantiated `synth_token` with `N < 11`), the build would break before this
/// assertion could even run.
#[test]
fn test_synth_token_meets_minimum_width() {
    const MIN_TOKEN_LEN: usize = 11;

    // The compile-time guard is the real enforcement; this also pins that the live callers stay
    // comfortably above the floor so a regression in the width constants surfaces here too.
    const { assert!(ITEM_ID_TOKEN_LEN >= MIN_TOKEN_LEN) };
    const { assert!(RESPONSE_ID_TOKEN_LEN >= MIN_TOKEN_LEN) };

    let resp_id = synthesize_response_id();
    let resp_suffix = resp_id
        .strip_prefix("resp_") // golden wire-contract literal (kept bare on purpose)
        .expect("synthesized response id uses resp_ prefix");
    assert!(
        resp_suffix.len() >= MIN_TOKEN_LEN,
        "synthesized resp_ suffix must be >= {MIN_TOKEN_LEN} base62 chars, got {} ({resp_id})",
        resp_suffix.len()
    );

    let item_id = synthesize_item_id("msg");
    let item_suffix = item_id
        .strip_prefix("msg_") // golden wire-contract literal (kept bare on purpose)
        .expect("synthesized item id uses the given prefix");
    assert!(
        item_suffix.len() >= MIN_TOKEN_LEN,
        "synthesized item suffix must be >= {MIN_TOKEN_LEN} base62 chars, got {} ({item_id})",
        item_suffix.len()
    );
}

/// Regression (LOW/conformance, Round 18 verify): the streaming `response.failed` terminal event
/// (emitted from an IR `Error`) must carry the native non-error skeleton — specifically a
/// present-but-empty `output` array (REQUIRED by the SDK's typed `Response`), never omitting it.
/// A failed response produced no assistant items, so `output` is `[]`. (The `output: []` emission
/// already lived in the Error arm before Round 18; this test locks it against future regression.)
#[test]
fn test_response_failed_carries_empty_output_skeleton() {
    let writer = ResponsesWriter;
    let (etype, failed) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }))
        .expect("Error emits response.failed");
    assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
    let resp = failed
        .get("response")
        .expect("response.failed wraps an inner response object");
    let output = resp
        .get("output")
        .expect("response.failed inner response must carry output, not omit it");
    assert!(
        output.as_array().is_some_and(|a| a.is_empty()),
        "response.failed output must be a present-but-empty array, got {output}"
    );
    // The native failed skeleton also carries the other non-error required fields.
    assert_eq!(
        resp.get("status").and_then(|s| s.as_str()),
        Some("failed"), // golden wire-contract literal (kept bare on purpose)
        "response.failed inner status must be \"failed\""
    );
    assert_eq!(
        resp.get("object").and_then(|o| o.as_str()),
        Some("response"), // golden wire-contract literal (kept bare on purpose)
        "response.failed inner object must be \"response\""
    );
    assert!(
        resp.get("id").and_then(|i| i.as_str()).is_some(),
        "response.failed inner response must carry an id"
    );
    assert!(
        resp.get("error").and_then(|e| e.as_object()).is_some(),
        "response.failed inner response must carry the error object"
    );
}

/// Regression (MEDIUM/correctness): a top-level `metadata` object must NOT be in the modeled-key
/// exclusion set, so it flows into `IrRequest.extra` on read and is re-emitted verbatim by
/// `write_request`. A prior revision listed `metadata` in `modeled_keys` while never emitting it,
/// silently dropping the caller's response tagging / billing-attribution field.
#[test]
fn test_metadata_round_trips_through_extra() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hi"}]}],
        "metadata": {"trace_id": "abc-123", "team": "billing"}
    });
    let reader = ResponsesReader;
    let writer = ResponsesWriter;

    let ir = reader.read_request(&json).expect("read_request ok");
    // metadata must have landed in extra (it is not a modeled IrRequest field).
    assert_eq!(
        ir.extra.get("metadata"),
        Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
        "metadata must flow into extra, not be dropped"
    );

    // write_request forwards extra verbatim, so metadata survives to the upstream body.
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("metadata"),
        Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
        "metadata must be forwarded to the upstream Responses backend"
    );
}

/// Regression (MEDIUM/conformance, class: stream-start skeleton): the opening `response.created`
/// event must carry the FULL required Response skeleton an SDK reads unconditionally — `usage`,
/// `output`, and `error` must be PRESENT (empty/null), not omitted. Omitting `usage` left strict
/// SDK decoders without a `Response.usage` field on the first chunk.
#[test]
fn test_message_start_skeleton_carries_usage_output_error() {
    let writer = ResponsesWriter;
    let ev = crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
    assert_eq!(etype, "response.created"); // golden wire-contract literal (kept bare on purpose)
    let resp = payload.get("response").expect("response object present");

    // usage key MUST be present (null at stream start), not omitted.
    assert!(
        resp.get("usage").is_some(),
        "usage key must be present on the opening chunk: {resp}"
    );
    assert!(
        resp.get("usage").unwrap().is_null(),
        "usage must be null (no tokens yet) at stream start"
    );
    // output array present-but-empty; error present-but-null.
    assert_eq!(
        resp.get("output"),
        Some(&serde_json::json!([])),
        "output must be present as an empty array"
    );
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(false),
        "error key must be present and null at stream start"
    );
}

/// A role-only item (no `type`) must still be processed via the role fallback.
#[test]
fn test_role_only_item_still_processed() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "hi there"}]}
        ]
    });
    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("read_request should succeed");
    assert_eq!(ir.messages.len(), 1);
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi there"),
        other => panic!("expected text turn, got {other:?}"),
    }
}

/// Regression (HIGH/correctness): an array `input` must be iterated without the prior
/// `is_array()` + `.as_array().unwrap()` pattern. Exercises the `if let Some(arr)` path and
/// confirms array items are still decoded into messages.
#[test]
fn test_read_request_array_input_no_unwrap() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            {"type": CONTENT_TYPE_INPUT_TEXT, "text": "hello"},
            {"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "world"}
        ]
    });
    let reader = ResponsesReader;
    let ir = reader
        .read_request(&json)
        .expect("array input should decode");
    assert_eq!(ir.messages.len(), 2);
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
}

/// Regression (HIGH/correctness): a `response.failed` terminal event with NO nested `response`
/// object (truncated SSE frame / body-stripping proxy) must NOT be decoded as a successful
/// end_turn. It must surface as an explicit Error + MessageStop so downstream clients see the
/// failure and the breaker receives the failure signal.
#[test]
fn test_failed_event_without_body_surfaces_error() {
    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let data = serde_json::json!({});
    let events = reader.read_response_events(EVT_RESPONSE_FAILED, &data, &mut state);

    assert_eq!(
        events.len(),
        2,
        "expected Error + MessageStop, got {events:?}"
    );
    match &events[0] {
        IrStreamEvent::Error(err) => {
            assert_eq!(err.class, StatusClass::ServerError);
            assert_eq!(err.provider_signal.as_deref(), Some("response_failed"));
        }
        other => panic!("expected Error first, got {other:?}"),
    }
    assert!(
        matches!(events[1], IrStreamEvent::MessageStop),
        "expected MessageStop, got {:?}",
        events[1]
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "a bodyless failed event must not emit a success MessageDelta"
    );
}

/// A `response.completed`/`response.incomplete` terminal event with no nested `response` object
/// must still terminate the stream with a success MessageDelta + MessageStop (must NOT become an
/// Error — only `response.failed` does).
#[test]
fn test_completed_event_without_body_emits_end_turn() {
    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let data = serde_json::json!({});
    let events = reader.read_response_events(EVT_RESPONSE_COMPLETED, &data, &mut state);

    assert_eq!(events.len(), 2, "expected MessageDelta + MessageStop");
    match &events[0] {
        IrStreamEvent::MessageDelta { stop_reason, .. } => {
            assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::EndTurn));
        }
        other => panic!("expected MessageDelta first, got {other:?}"),
    }
    assert!(matches!(events[1], IrStreamEvent::MessageStop));
    assert!(
        !events.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "a bodyless completed event must not emit an Error"
    );
}

/// Regression (MEDIUM/conformance): the writer's `IrStreamEvent::Error` arm must emit a
/// `response.failed` event whose error lives inside a `response` object (the shape the official
/// SDK streaming decoder reads via `event.response`), with a synthesized `resp_` id and
/// `status: "failed"` — NOT a top-level `{"error":{...}}`.
#[test]
fn test_error_event_wraps_in_response_object() {
    let writer = ResponsesWriter;
    let ev = IrStreamEvent::Error(IrError {
        class: StatusClass::ServerError,
        provider_signal: Some("overloaded".to_string()),
        retry_after: None,
    });
    let (etype, payload) = writer
        .write_response_event(&ev)
        .expect("error event should emit");
    assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)

    // No top-level `error` key — the SDK reads `event.response`, not `event.error`.
    assert!(
        payload.get("error").is_none(),
        "error must be nested under response, not top-level: {payload}"
    );
    let resp = payload
        .get("response")
        .expect("payload must carry a `response` object");
    let id = resp
        .get("id")
        .and_then(|i| i.as_str())
        .expect("synthesized resp_ id present");
    assert!(
        id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
        "synthesized id must use resp_ prefix, got {id}"
    );
    assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed")); // golden wire-contract literal (kept bare on purpose)
    let error = resp.get("error").expect("nested error object");
    assert_eq!(
        error.get("message").and_then(|m| m.as_str()),
        Some("overloaded")
    );
    // Native ResponseError shape: a non-null `code` enum (carried from the provider signal),
    // and NO Chat-style `type`/`param` fields.
    assert_eq!(
        error.get("code").and_then(|c| c.as_str()),
        Some("overloaded")
    );
    assert!(
        !error.as_object().unwrap().contains_key("type"),
        "Responses ResponseError carries no `type` field: {error}"
    );
    assert!(
        !error.as_object().unwrap().contains_key("param"),
        "Responses ResponseError carries no `param` field: {error}"
    );
}

/// Regression (CRITICAL/conformance, class: stream event `type` discriminator): EVERY emitted
/// Responses SSE data body must carry a top-level `"type"` key equal to its event name. The
/// official OpenAI Python/Node streaming decoders dispatch on `data["type"]`; a body missing it
/// (the prior `{"response":{...}}` shape) yields None/undefined for the event type and the SDK
/// never constructs the Response or fires event handlers. This exercises all writer arms that
/// produce a body — response.created, response.output_item.added, response.output_text.delta,
/// response.function_call_arguments.delta, response.output_item.done, response.completed, and
/// response.failed — and asserts `payload["type"] == event_name` for each.
#[test]
fn test_every_stream_event_carries_top_level_type() {
    let writer = ResponsesWriter;
    let usage = || crate::ir::IrUsage {
        input_tokens: 1,
        output_tokens: 1,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    let events = vec![
        IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        },
        IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "fc_1".to_string(),
                name: "f".to_string(),
            },
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
        },
        IrStreamEvent::BlockStop { index: 0 },
        IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage(),
        },
        IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }),
    ];

    for ev in &events {
        let (event_name, payload) = writer
            .write_response_event(ev)
            .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
        assert_eq!(
            payload.get("type").and_then(|t| t.as_str()),
            Some(event_name.as_str()),
            "event {event_name} body must carry top-level \"type\" == event name, got {payload}"
        );
    }
}

/// A full single-stream sequence of emitted Responses events. The events go through the writer in
/// the order `StreamTranslate::feed` would emit them.
fn usage_fixture() -> crate::ir::IrUsage {
    crate::ir::IrUsage {
        input_tokens: 1,
        output_tokens: 1,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    }
}

/// Regression (HIGH/conformance): EVERY emitted Responses SSE event must carry a top-level
/// `sequence_number` that is monotonic from 0 within a single stream. The opening
/// `response.created` (MessageStart) resets the per-stream counter, so a fresh stream starts at 0
/// and increases by one per emitted event. Events that produce no body do not consume a number.
#[test]
fn test_sequence_number_monotonic_from_zero() {
    let writer = ResponsesWriter;
    // A representative stream: created → text deltas → completed.
    let stream = vec![
        IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("Hel".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("lo".to_string()),
        },
        IrStreamEvent::BlockStop { index: 0 },
        IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        },
    ];

    let mut seqs = Vec::new();
    for ev in &stream {
        if let Some((_, payload)) = writer.write_response_event(ev) {
            let n = payload
                .get("sequence_number")
                .and_then(|s| s.as_u64())
                .unwrap_or_else(|| {
                    panic!("every emitted event must carry sequence_number: {payload}")
                });
            seqs.push(n);
        }
    }

    // A TEXT block's `BlockStop` emits no body (a text part has no `output_item.added`/`.done`
    // pair — its content-part lifecycle is closed upstream), so it consumes no sequence number.
    // The numbered events are therefore: created, two text deltas, completed = four events.
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3],
        "sequence_number must be 0..N monotonic within the stream, got {seqs:?}"
    );
}

/// Regression: a SECOND stream (its own `response.created`) must restart its `sequence_number`
/// from 0 — the counter is per-stream, not per-process. Exercises the reset-on-MessageStart
/// contract so one stream's numbering never bleeds into the next on the same worker.
#[test]
fn test_sequence_number_resets_per_stream() {
    let writer = ResponsesWriter;
    let start = || IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let delta = || IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("x".to_string()),
    };

    // Stream A: created(0), delta(1).
    let (_, a0) = writer.write_response_event(&start()).expect("emit");
    let (_, a1) = writer.write_response_event(&delta()).expect("emit");
    assert_eq!(a0.get("sequence_number").and_then(|s| s.as_u64()), Some(0));
    assert_eq!(a1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));

    // Stream B begins with its own created → counter resets to 0.
    let (_, b0) = writer.write_response_event(&start()).expect("emit");
    let (_, b1) = writer.write_response_event(&delta()).expect("emit");
    assert_eq!(
        b0.get("sequence_number").and_then(|s| s.as_u64()),
        Some(0),
        "a new stream's response.created must reset sequence_number to 0"
    );
    assert_eq!(b1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));
}

/// Regression: every writer arm that produces a body carries `sequence_number`, not just the
/// deltas. Mirrors `test_every_stream_event_carries_top_level_type` but asserts the integer
/// `sequence_number` is present (and a u64) on each emitted body.
#[test]
fn test_every_stream_event_carries_sequence_number() {
    let writer = ResponsesWriter;
    let events = vec![
        IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        },
        IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_1".to_string(),
                name: "f".to_string(),
            },
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
        },
        IrStreamEvent::BlockStop { index: 0 },
        IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        },
        IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }),
    ];

    for ev in &events {
        let (event_name, payload) = writer
            .write_response_event(ev)
            .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
        assert!(
            payload
                .get("sequence_number")
                .map(|s| s.is_u64())
                .unwrap_or(false),
            "event {event_name} body must carry a u64 sequence_number, got {payload}"
        );
    }
}

/// Regression: `response.output_text.delta` must carry `item_id` and `content_index` (native
/// shape), and the `output_item.added` for a function call must carry `item_id`. The
/// `function_call_arguments.delta` carries the matching `item_id`.
#[test]
fn test_delta_and_item_added_carry_item_id_and_content_index() {
    let writer = ResponsesWriter;

    // Text delta.
    let (_, text) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 2,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        })
        .expect("emit");
    let text_item = text
        .get("item_id")
        .and_then(|i| i.as_str())
        .expect("output_text.delta must carry item_id");
    assert!(
        text_item.starts_with("msg_"), // golden wire-contract literal (kept bare on purpose)
        "text delta item_id must be a msg_ id, got {text_item}"
    );
    assert_eq!(
        text.get("content_index").and_then(|c| c.as_u64()),
        Some(0),
        "output_text.delta must carry content_index"
    );

    // output_item.added for a function call.
    let (_, added) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_9".to_string(),
                name: "lookup".to_string(),
            },
        })
        .expect("emit");
    let added_item = added
        .get("item_id")
        .and_then(|i| i.as_str())
        .expect("output_item.added must carry item_id");
    assert!(
        added_item.starts_with("fc_"), // golden wire-contract literal (kept bare on purpose)
        "function_call item_id must be an fc_ id, got {added_item}"
    );
    // The nested item id matches the top-level item_id (one logical item).
    assert_eq!(
        added
            .get("item")
            .and_then(|i| i.get("id"))
            .and_then(|i| i.as_str()),
        Some(added_item),
        "nested item.id must equal the top-level item_id"
    );

    // The function_call_arguments.delta at the same index reuses the same fc_ item_id.
    let (_, args) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
        })
        .expect("emit");
    assert_eq!(
        args.get("item_id").and_then(|i| i.as_str()),
        Some(added_item),
        "arguments delta item_id must match the item's added item_id (stable per index)"
    );
}

/// Regression (HIGH/correctness): the `sequence_number` counter is PER-STREAM INSTANCE state,
/// not thread-local. Two distinct writer instances model two concurrent streams sharing one
/// worker thread. Interleave their events (A.start, B.start, A.delta, B.delta, ...) — the way a
/// Tokio work-stealing runtime can schedule two parked stream tasks on the same thread. Each
/// writer's sequence must stay monotonic-from-0 with NO bleed from the other stream's resets or
/// increments. With the old thread-local cell, B's `MessageStart` reset clobbered A's in-flight
/// counter and A's next event would restart non-monotonically; here the counters are independent.
#[test]
fn test_sequence_number_is_per_instance_not_thread_local() {
    let stream_a = ResponsesWriter;
    let stream_b = ResponsesWriter;
    let start = || IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let delta = || IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("x".to_string()),
    };
    let seq = |opt: Option<(String, serde_json::Value)>| {
        opt.expect("emit")
            .1
            .get("sequence_number")
            .and_then(|s| s.as_u64())
            .expect("sequence_number present")
    };

    // Interleave the two streams on the same "thread".
    let a0 = seq(stream_a.write_response_event(&start())); // A: 0
    let b0 = seq(stream_b.write_response_event(&start())); // B: 0 (must NOT touch A)
    let a1 = seq(stream_a.write_response_event(&delta())); // A: 1
    let b1 = seq(stream_b.write_response_event(&delta())); // B: 1
    let a2 = seq(stream_a.write_response_event(&delta())); // A: 2
    let b2 = seq(stream_b.write_response_event(&delta())); // B: 2

    assert_eq!(
        (a0, a1, a2),
        (0, 1, 2),
        "stream A must stay monotonic-from-0 despite stream B interleaving"
    );
    assert_eq!(
        (b0, b1, b2),
        (0, 1, 2),
        "stream B must stay monotonic-from-0 independent of stream A"
    );
}

/// Regression (HIGH/conformance): `response.output_item.done` must carry a stable `item_id`
/// that matches the `response.output_item.added` for the same output index, plus a typed `item`
/// object — an SDK reading `event.item_id`/`event.item` off the `done` event must not see
/// `undefined`. The `added` for a function call and the `done` at the same index share the id.
#[test]
fn test_output_item_done_carries_matching_item_id_and_item() {
    let writer = ResponsesWriter;

    let (_, added) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 3,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_x".to_string(),
                name: "f".to_string(),
            },
        })
        .expect("added emits");
    let added_id = added
        .get("item_id")
        .and_then(|i| i.as_str())
        .expect("added carries item_id")
        .to_string();

    let (etype, done) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 3 })
        .expect("done emits");
    assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        done.get("item_id").and_then(|i| i.as_str()),
        Some(added_id.as_str()),
        "output_item.done item_id must match the output_item.added at the same index"
    );
    // A typed `item` object is present (not undefined / not a bare {}).
    let item = done
        .get("item")
        .and_then(|i| i.as_object())
        .expect("output_item.done must carry an item object");
    assert_eq!(
        item.get("type").and_then(|t| t.as_str()),
        Some("function_call"), // golden wire-contract literal (kept bare on purpose)
        "the done item must be typed"
    );
    assert_eq!(
        item.get("id").and_then(|i| i.as_str()),
        Some(added_id.as_str()),
        "the done item.id must equal the item_id"
    );
}

/// Regression (MEDIUM/conformance): the in-band `response.failed` error object is the
/// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
/// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` is
/// impossible from real OpenAI and a distinguishability tell.
#[test]
fn test_response_failed_uses_native_responseerror_shape() {
    let writer = ResponsesWriter;

    // With a provider signal: it becomes the non-null code enum AND the message.
    let (etype, payload) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("rate_limit_exceeded".to_string()),
            retry_after: None,
        }))
        .expect("emit");
    assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
    let error = payload
        .get("response")
        .and_then(|r| r.get("error"))
        .and_then(|e| e.as_object())
        .expect("response.error object present");
    assert_eq!(
        error.get("code").and_then(|c| c.as_str()),
        Some("rate_limit_exceeded"), // golden wire-contract literal (kept bare on purpose)
        "error.code must be the non-null Responses error enum"
    );
    assert_eq!(
        error.get("message").and_then(|m| m.as_str()),
        Some("rate_limit_exceeded") // golden wire-contract literal (kept bare on purpose)
    );
    assert!(
        !error.contains_key("type"),
        "Responses ResponseError carries no `type` field"
    );
    assert!(
        !error.contains_key("param"),
        "Responses ResponseError carries no `param` field"
    );

    // Without a provider signal: code defaults to the canonical `server_error`, never null.
    let (_, payload) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        }))
        .expect("emit");
    let code = payload
        .get("response")
        .and_then(|r| r.get("error"))
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert_eq!(
        code,
        Some("server_error"), // golden wire-contract literal (kept bare on purpose)
        "error.code must default to server_error, never null"
    );
}

/// REGRESSION (audit c2r2): on a cross-protocol / transport-abort path `provider_signal` carries
/// a HUMAN sentence (e.g. `STREAM_ABORT_DETAIL`), NOT a Responses code enum. `error.code` must be
/// DERIVED from the class (a valid enum an SDK can switch on), while `error.message` keeps the
/// human text — the old code forwarded the sentence as the `code` enum, breaking typed SDKs.
#[test]
fn test_response_failed_code_is_enum_even_for_human_provider_signal() {
    let writer = ResponsesWriter;
    let (_, payload) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some(crate::proto::STREAM_ABORT_DETAIL.to_string()),
            retry_after: None,
        }))
        .expect("emit");
    let error = payload
        .get("response")
        .and_then(|r| r.get("error"))
        .and_then(|e| e.as_object())
        .expect("error object");
    assert_eq!(
        error.get("code").and_then(|c| c.as_str()),
        Some("server_error"),
        "a human provider_signal must NOT leak as the code enum — derive it from the class"
    );
    assert_eq!(
        error.get("message").and_then(|m| m.as_str()),
        Some(crate::proto::STREAM_ABORT_DETAIL),
        "the human text stays in `message`"
    );

    // An auth-class transport error derives the auth code enum, not the human string.
    let (_, payload) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::Auth,
            provider_signal: Some("connection reset by peer".to_string()),
            retry_after: None,
        }))
        .expect("emit");
    assert_eq!(
        payload
            .pointer("/response/error/code")
            .and_then(|c| c.as_str()),
        Some(ERR_TYPE_AUTHENTICATION)
    );
}

/// Regression (HIGH/correctness+conformance): a TEXT block's `BlockStop` must emit NOTHING from
/// the Responses writer. The Text `BlockStart` arm emits no `output_item.added`, so emitting an
/// `output_item.done` (with `type:"function_call"`, as a prior revision did) would be an
/// unmatched lifecycle event AND mis-type a text response as a function call — both break a
/// typed Responses SDK and are distinguishability tells.
/// Regression (HIGH/conformance, Round 10): a TEXT part must be bracketed inside a `message`
/// output item. The Text BlockStart emits `response.output_item.added` (type "message") and the
/// Text BlockStop emits the matching `response.output_item.done` (type "message") carrying the
/// SAME `msg_…` `item_id`. Previously the text BlockStart returned None and the BlockStop
/// returned None, leaving the `output_text.delta`s orphaned with no parent item — so a typed SDK
/// never materialized the assistant message in `response.output[]`.
#[test]
fn test_text_block_emits_message_item_lifecycle() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    // Text BlockStart now opens a message item.
    let (added_et, added) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("text BlockStart opens a message item");
    assert_eq!(added_et, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(added["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(added["item"]["role"], "assistant");
    let added_item_id = added["item_id"]
        .as_str()
        .expect("item_id present")
        .to_string();
    assert!(added_item_id.starts_with("msg_"), "text item id is msg_…"); // golden wire-contract literal (kept bare on purpose)

    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    });

    // Text BlockStop now closes the message item with a matching done.
    let (done_et, done) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("text BlockStop closes the message item");
    assert_eq!(done_et, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(done["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        done["item_id"].as_str(),
        Some(added_item_id.as_str()),
        "done item_id matches the added item_id (added→done correlation)"
    );

    // A SECOND BlockStop at the (already-closed) text index must NOT re-emit a done.
    assert!(
        writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .is_none(),
        "a repeated BlockStop for a closed text index must not re-emit output_item.done"
    );
}

/// Regression (HIGH): an interleaved tool+text stream closes the tool index with a
/// `function_call` done and the text index with a `message` done — each with its own typed
/// item, never cross-typed. Exercises the per-stream open-index tracking so a text index is
/// never mistaken for a function-call item and vice-versa.
#[test]
fn test_tool_and_text_block_stop_emit_correctly_typed_done() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    // Tool at index 0, text at index 1.
    let _ = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_1".to_string(),
                name: "f".to_string(),
            },
        })
        .expect("tool added emits");
    let _ = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("text added emits");
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 1,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    });
    // Tool index closes with a function_call done.
    let (etype, tool_done) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("tool BlockStop emits output_item.done");
    assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(tool_done["item"]["type"], "function_call"); // golden wire-contract literal (kept bare on purpose)
                                                            // Text index closes with a message done.
    let (text_et, text_done) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
        .expect("text BlockStop emits output_item.done (message)");
    assert_eq!(text_et, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(text_done["item"]["type"], "message"); // golden wire-contract literal (kept bare on purpose)
                                                      // A SECOND BlockStop at the (already-closed) tool index 0 must not emit a duplicate done.
    assert!(
        writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .is_none(),
        "a repeated BlockStop for a closed tool index must not re-emit output_item.done"
    );
}

/// Regression (HIGH/conformance): the terminal `response.completed` event's inner `response`
/// object must carry both `id` (a `resp_…` string) and `created_at` (a unix-seconds integer).
/// The official SDKs read `event.response.id` on the terminal event to finalize the Response;
/// omitting it breaks correlation and is a distinguishability tell (a real stream never sends a
/// terminal event without an id).
#[test]
fn test_completed_event_carries_id_and_created_at() {
    let writer = ResponsesWriter;
    let (etype, payload) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("emit");
    assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    let resp = payload
        .get("response")
        .and_then(|r| r.as_object())
        .expect("response object present");
    let id = resp
        .get("id")
        .and_then(|i| i.as_str())
        .expect("response.completed must carry response.id");
    assert!(
        id.starts_with("resp_"), // golden wire-contract literal (kept bare on purpose)
        "synthesized id must be a resp_ id, got {id}"
    );
    assert!(
        resp.get("created_at").and_then(|c| c.as_u64()).is_some(),
        "response.completed must carry an integer created_at"
    );
}

/// Regression (MEDIUM/conformance): `write_error` must emit `code:"invalid_api_key"` for an
/// authentication failure (mirrors `openai_chat.rs` `write_error_emits_invalid_api_key_code_for_auth_failure`).
/// Emitting `code:null` on auth is a deterministic proxy tell vs a real OpenAI Responses 401.
#[test]
fn write_error_emits_invalid_api_key_code_for_auth_failure() {
    let writer = ResponsesWriter;
    for kind in ["authentication", "authentication_error", "auth"] {
        let body = writer.write_error(401, kind, "bad key");
        assert_eq!(
            body["error"]["type"],
            serde_json::json!("authentication_error"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind} must map to authentication_error"
        );
        assert_eq!(
            body["error"]["code"],
            serde_json::json!("invalid_api_key"),
            "auth failure (kind {kind}) must carry code=invalid_api_key, not null"
        );
    }
}

/// Regression (MEDIUM/conformance): non-auth, non-quota error kinds keep `code:null` — the
/// native shape when no machine-readable code applies — so only the auth and quota paths are
/// special-cased.
#[test]
fn write_error_keeps_null_code_for_non_auth_errors() {
    let writer = ResponsesWriter;
    for kind in [
        "invalid_request",
        "permission",
        "not_found",
        "rate_limit",
        "server_error",
    ] {
        let body = writer.write_error(400, kind, "msg");
        assert_eq!(
            body["error"]["code"],
            serde_json::Value::Null,
            "non-auth/non-quota kind {kind} must keep code=null"
        );
    }
}

/// Regression (LOW/conformance): the over-quota path carries a populated machine-readable
/// `code` — native OpenAI/Responses emits `{"type":"insufficient_quota","code":"insufficient_quota"}`
/// — so a `code:null` here (the old behavior) would be a fingerprintable divergence. The
/// `billing` kind (router vocabulary) is normalized to the native `insufficient_quota` type.
#[test]
fn write_error_insufficient_quota_keeps_type_and_sets_code() {
    let writer = ResponsesWriter;
    for kind in ["insufficient_quota", "billing"] {
        let body = writer.write_error(429, kind, "over quota");
        assert_eq!(
            body["error"]["type"],
            serde_json::json!("insufficient_quota"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind} maps to the native insufficient_quota type"
        );
        assert_eq!(
            body["error"]["code"],
            serde_json::json!("insufficient_quota"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind} must carry code=insufficient_quota, not null"
        );
    }
}

/// Regression (MEDIUM/correctness): a native text item is closed by BOTH `content_part.done`
/// and `output_item.done` at the SAME `output_index`. The reader must emit EXACTLY ONE
/// `BlockStop` for that index — the second terminal frame is a no-op — so a downstream writer
/// does not emit a duplicate `content_block_stop`.
#[test]
fn test_paired_content_and_item_done_emits_single_block_stop() {
    let mut state = crate::ir::StreamDecodeState::default();
    // Open a text block lazily.
    let _ = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "a"}),
        &mut state,
    );
    assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    // First terminal frame: content_part.done → one BlockStop, clears the open index.
    let first = reader_read_response_events(
        "response.content_part.done",
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert_eq!(
        first.len(),
        1,
        "content_part.done closes the text block once"
    );
    assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    // Second terminal frame at the same index: output_item.done → NOTHING (already closed).
    let second = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert!(
            second.is_empty(),
            "the second terminal frame for one text item must not emit a duplicate BlockStop, got {second:?}"
        );
}

/// Regression (MEDIUM/correctness): a tool item opened by `output_item.added` is closed by a
/// single `output_item.done`, and a stray second `done` at that index emits nothing.
#[test]
fn test_tool_item_done_emits_single_block_stop() {
    let mut state = crate::ir::StreamDecodeState::default();
    let _ = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 2,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
        }),
        &mut state,
    );
    let first = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 2}),
        &mut state,
    );
    assert_eq!(first.len(), 1);
    assert!(matches!(
        first[0],
        crate::ir::IrStreamEvent::BlockStop { index: 2 }
    ));
    let second = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 2}),
        &mut state,
    );
    assert!(
        second.is_empty(),
        "a closed tool index must not re-emit BlockStop, got {second:?}"
    );
}

/// Regression (CRITICAL/conformance + HIGH/correctness, Round 10): every lifecycle event in ONE
/// stream must carry the SAME `response.id`. On a cross-protocol stream the IR strips identity
/// (id == None), so `response.created` synthesizes a `resp_` id which MUST be replayed verbatim
/// on `response.completed`. Before the per-stream `response_id` cell, `MessageDelta` minted a
/// fresh id, so the terminal event's id differed from `response.created` — SDK-breaking.
#[test]
fn test_terminal_id_matches_created_id_cross_protocol() {
    let writer = ResponsesWriter;
    // Cross-protocol: id is None, so response.created synthesizes one.
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        })
        .expect("MessageStart emits response.created");
    let created_id = created["response"]["id"]
        .as_str()
        .expect("created carries id")
        .to_string();
    assert!(created_id.starts_with("resp_")); // golden wire-contract literal (kept bare on purpose)

    let (etype, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("MessageDelta emits terminal");
    assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        completed["response"]["id"].as_str(),
        Some(created_id.as_str()),
        "response.completed.id must equal response.created.id (same stream, same id)"
    );
}

/// Regression (HIGH/correctness, Round 10): a `response.failed` (from an IR Error) must carry
/// the SAME `response.id` as the opening `response.created`, so an SDK correlates the failure
/// with the in-flight Response. Before the carried-id cell, the Error arm synthesized a fresh
/// id distinct from `response.created`.
#[test]
fn test_failed_id_matches_created_id_cross_protocol() {
    let writer = ResponsesWriter;
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        })
        .expect("MessageStart emits response.created");
    let created_id = created["response"]["id"].as_str().unwrap().to_string();

    let (etype, failed) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }))
        .expect("Error emits response.failed");
    assert_eq!(etype, "response.failed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        failed["response"]["id"].as_str(),
        Some(created_id.as_str()),
        "response.failed.id must equal response.created.id"
    );
}

/// Regression (HIGH/correctness, Round 10): a same-protocol passthrough forwards the upstream
/// `id` on `response.created`, and that SAME id must be replayed on the terminal event.
#[test]
fn test_terminal_id_matches_forwarded_created_id() {
    let writer = ResponsesWriter;
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_upstream123".to_string()),
            created: Some(42),
            model: None,
        })
        .expect("emit");
    assert_eq!(created["response"]["id"].as_str(), Some("resp_upstream123"));
    let (_, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("emit");
    assert_eq!(
        completed["response"]["id"].as_str(),
        Some("resp_upstream123"),
        "terminal event must replay the forwarded upstream id"
    );
}

/// Regression (HIGH/correctness, Round 10): a fresh stream's `response.created` REPLACES the
/// carried id, so a reused/cloned writer never leaks the previous stream's id onto a new
/// stream's terminal event. (`reset_sequence_number` clears the cell; `MessageStart` sets it.)
#[test]
fn test_carried_id_resets_per_stream() {
    let writer = ResponsesWriter;
    // Stream A.
    let (_, a_created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_A".to_string()),
            created: None,
            model: None,
        })
        .expect("emit");
    assert_eq!(a_created["response"]["id"].as_str(), Some("resp_A"));
    // Stream B begins on the same writer instance.
    let (_, b_created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_B".to_string()),
            created: None,
            model: None,
        })
        .expect("emit");
    assert_eq!(b_created["response"]["id"].as_str(), Some("resp_B"));
    let (_, b_completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("emit");
    assert_eq!(
        b_completed["response"]["id"].as_str(),
        Some("resp_B"),
        "stream B's terminal id must be B's, not A's leaked id"
    );
}

/// Regression (HIGH/security, Round 10): a backend that emits a `response.output_item.added`
/// for each of many unique `output_index` values must NOT grow `state.open_tools` without
/// bound. After feeding more than MAX_OPEN_TOOLS distinct indices, the tracked set is capped.
#[test]
fn test_reader_open_tools_is_capped() {
    let mut state = crate::ir::StreamDecodeState::default();
    for i in 0..(MAX_OPEN_TOOLS as u64 + 200) {
        let _ = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": i,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
            }),
            &mut state,
        );
    }
    assert!(
        state.open_tools.len() <= MAX_OPEN_TOOLS,
        "open_tools must be capped at MAX_OPEN_TOOLS, got {}",
        state.open_tools.len()
    );
}

/// Regression (HIGH/security, Round 10): a crafted huge `output_index` must be clamped to
/// MAX_OUTPUT_INDEX before the usize cast/insert, so the tracked index never exceeds the cap and
/// downstream index arithmetic stays bounded.
#[test]
fn test_reader_output_index_clamped() {
    let mut state = crate::ir::StreamDecodeState::default();
    let out = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": u64::MAX,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
        }),
        &mut state,
    );
    match out.first() {
        Some(crate::ir::IrStreamEvent::BlockStart { index, .. }) => {
            assert_eq!(*index, MAX_OUTPUT_INDEX, "u64::MAX index must clamp to cap");
        }
        other => panic!("expected a clamped BlockStart, got {other:?}"),
    }
    assert!(state.open_tools.contains(&MAX_OUTPUT_INDEX));
    assert!(!state.open_tools.iter().any(|&i| i > MAX_OUTPUT_INDEX));
}

/// Regression (HIGH/security, Round 10): the writer's open-text-index set is also capped so a
/// pathological stream of unique text BlockStarts cannot grow per-stream writer memory without
/// bound.
#[test]
fn test_writer_open_text_indices_capped() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let mut opened = 0usize;
    for i in 0..(MAX_OPEN_TOOLS + 200) {
        if writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: i,
                block: crate::ir::IrBlockMeta::Text,
            })
            .is_some()
        {
            opened += 1;
        }
    }
    assert!(
        opened <= MAX_OPEN_TOOLS,
        "writer must open at most MAX_OPEN_TOOLS text items, opened {opened}"
    );
}

/// Regression (LOW/resource, R21 #20): `mark_tool_open` must apply the same cardinality
/// discipline as `open_text_item` — a `contains` guard (idempotent re-mark) plus a
/// `MAX_OPEN_TOOLS` cap — so a pathological backend streaming an unbounded run of distinct
/// function-call indices cannot grow `open_tool_indices` without bound (memory exhaustion).
/// Before the fix this set grew one entry per distinct index with no ceiling.
#[test]
fn test_writer_open_tool_indices_capped() {
    let writer = ResponsesWriter;
    // Feed many distinct indices: re-marking is idempotent and the set is capped.
    for i in 0..(MAX_OPEN_TOOLS + 200) {
        writer.mark_tool_open(i);
    }
    // Re-mark already-tracked indices: must not grow the set further.
    for i in 0..MAX_OPEN_TOOLS {
        writer.mark_tool_open(i);
    }
    let len = writer
        .open_tool_indices
        .lock()
        .map(|s| s.len())
        .expect("lock held only by this test");
    assert!(
        len <= MAX_OPEN_TOOLS,
        "open_tool_indices must be capped at MAX_OPEN_TOOLS, got {len}"
    );
}

/// Regression (MED/completeness, R21 #17): production `extract_error` must synthesize the
/// canonical `context_length_exceeded` code when an oversized-context error carries the
/// condition only in its MESSAGE (null/generic `code`). Without this the breaker pipeline never
/// sees `StatusClass::ContextLength` and oversized-request failover does not trigger for this
/// protocol. Mirrors anthropic.rs's message-scan synthesis. Before the fix `provider_code` was
/// `None` here (only the `#[cfg(test)] classify()` helper recognized the message).
#[test]
fn test_extract_error_synthesizes_context_length_from_message() {
    let reader = ResponsesReader;
    // A real OpenAI-shaped oversized-context body: the canonical code is absent; the signal
    // lives in the human-readable message.
    let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens. Please reduce the length of the messages.","type":"invalid_request_error","param":"messages","code":null}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"), // golden wire-contract literal (kept bare on purpose)
        "message-only context-length error must synthesize the canonical code for failover"
    );
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("invalid_request_error")
    );
}

/// A native body that already carries `code: "context_length_exceeded"` must pass through
/// unchanged (the synthesis is `.or_else`, so a real code always wins).
#[test]
fn test_extract_error_preserves_native_context_length_code() {
    let reader = ResponsesReader;
    let body = br#"{"error":{"message":"too long","type":"invalid_request_error","code":"context_length_exceeded"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
    );
}

/// A non-context-length error must NOT be mislabelled as context-length (no false positives
/// from the message scan).
#[test]
fn test_extract_error_unrelated_error_not_context_length() {
    let reader = ResponsesReader;
    let body = br#"{"error":{"message":"Incorrect API key provided.","type":"authentication_error","code":"invalid_api_key"}}"#;
    let raw = reader.extract_error(StatusCode::UNAUTHORIZED, body);
    assert_eq!(raw.provider_code.as_deref(), Some("invalid_api_key"));
}

/// Regression (MED/breaker-conformance): the message-only context-length synthesis is GATED to
/// the oversized HTTP statuses (400/413), mirroring `OpenAiReader::extract_error`. A 429 (or 401,
/// 5xx) whose prose happens to contain "maximum context length" must NOT synthesize
/// `context_length_exceeded` — otherwise the breaker maps it to ContextLength and the genuine
/// rate-limit/auth/server failure escapes fault attribution (no fault recorded). This test FAILS
/// on the un-gated code (which synthesized the code from the message regardless of status) and
/// passes with the status gate.
#[test]
fn test_extract_error_oversized_phrase_on_non_oversized_status_not_synthesized() {
    let reader = ResponsesReader;
    // A 429 whose body carries no canonical code but whose message contains the context-length
    // phrase. The gate must block synthesis so this stays a rate-limit (not ContextLength).
    let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"rate_limit_error","code":null}}"#;
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        None,
        "a 429 mentioning context length must NOT be reclassified as context_length_exceeded"
    );
    // And the same body on a 401 must likewise not synthesize.
    let raw_401 = reader.extract_error(StatusCode::UNAUTHORIZED, body);
    assert_eq!(
        raw_401.provider_code.as_deref(),
        None,
        "a 401 mentioning context length must NOT be reclassified as context_length_exceeded"
    );
}

/// `ResponsesReader::classify` delegates to `super::openai_family::openai_classify`
/// (single-sourced after dedup). Every other reader has a direct `classify` test, but the Responses delegate was only
/// ever exercised through OpenAi's copy — this guards the delegation directly, mirroring
/// `test_openai_classify`. 429 → RateLimit.
#[test]
fn test_responses_classify_delegates() {
    let reader = ResponsesReader;
    let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
    assert_eq!(signal.class, StatusClass::RateLimit);

    // After the `openai_classify` oversized-status gate fix, a 429 whose body carries the
    // context-length prose (but no canonical code) must classify as RateLimit, NOT ContextLength
    // — the gate blocks the un-gated message scan from hijacking a genuine rate-limit signal.
    let ctx_body =
        br#"{"error":{"message":"This model's maximum context length is 8192 tokens."}}"#;
    let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, ctx_body);
    assert_eq!(
        signal.class,
        StatusClass::RateLimit,
        "a 429 mentioning context length must stay RateLimit, not ContextLength"
    );
}

/// Regression (HIGH/conformance, Round 11): a max_tokens-truncated stream's terminal event must
/// be `response.incomplete` (event name AND inner `type`), NOT `response.completed`. A native
/// stream never wraps a `status:"incomplete"` response in a `response.completed` envelope; the
/// SDKs dispatch on the event `type`, so the previous always-`response.completed` arm mislabelled
/// every truncated generation.
#[test]
fn test_terminal_incomplete_emits_response_incomplete_for_max_tokens() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (etype, body) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("MessageDelta emits a terminal event");
    assert_eq!(
        etype,
        "response.incomplete", // golden wire-contract literal (kept bare on purpose)
        "max_tokens truncation must use the response.incomplete event name"
    );
    assert_eq!(
        body["type"].as_str(),
        Some("response.incomplete"), // golden wire-contract literal (kept bare on purpose)
        "inner dispatch type must agree with the event name"
    );
    assert_eq!(
        body["response"]["status"].as_str(),
        Some("incomplete"), // golden wire-contract literal (kept bare on purpose)
        "inner status stays incomplete"
    );
    assert_eq!(
        body["response"]["incomplete_details"]["reason"].as_str(),
        Some("max_output_tokens"), // golden wire-contract literal (kept bare on purpose)
        "incomplete_details.reason maps max_tokens → max_output_tokens"
    );
}

/// Regression (HIGH/conformance, Round 11): a safety/content-filter stop is also `incomplete`,
/// so its terminal event is `response.incomplete` with reason `content_filter`.
#[test]
fn test_terminal_incomplete_emits_response_incomplete_for_safety() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (etype, body) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::Safety),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("MessageDelta emits a terminal event");
    assert_eq!(etype, "response.incomplete"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(body["type"].as_str(), Some("response.incomplete")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        body["response"]["incomplete_details"]["reason"].as_str(),
        Some("content_filter") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Regression (HIGH/conformance, Round 11): a normally-completed stream still emits
/// `response.completed` with inner type/status `completed` — the fix must not regress the
/// success path. The carried id must still match `response.created`.
#[test]
fn test_terminal_completed_unchanged_for_end_turn() {
    let writer = ResponsesWriter;
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        })
        .expect("created");
    let created_id = created["response"]["id"].as_str().unwrap().to_string();
    let (etype, body) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal");
    assert_eq!(etype, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(body["type"].as_str(), Some("response.completed")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(body["response"]["status"].as_str(), Some("completed")); // golden wire-contract literal (kept bare on purpose)
    assert!(body["response"].get("incomplete_details").is_none());
    assert_eq!(body["response"]["id"].as_str(), Some(created_id.as_str()));
}

/// Regression (HIGH/conformance, Round 11): write_error must NOT leak the Anthropic-vocabulary
/// `overloaded` type to an OpenAI-family client. A 503 exhaustion/timeout (forward.rs passes
/// kind `"overloaded"`) maps onto the native `server_error`.
#[test]
fn test_write_error_maps_overloaded_to_server_error() {
    let writer = ResponsesWriter;
    for kind in [
        "overloaded",
        ERR_TYPE_OVERLOADED,
        "service_unavailable",
        "unavailable",
    ] {
        let v = writer.write_error(503, kind, "upstream busy");
        assert_eq!(
            v["error"]["type"].as_str(),
            Some("server_error"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind:?} must map to server_error, never leak overloaded"
        );
        // `server_error` carries no machine-readable code in the native shape.
        assert!(v["error"]["code"].is_null(), "server_error code is null");
    }
}

/// Regression (MEDIUM/security, Round 11): synthesized `resp_` ids must be opaque base62 of
/// native length with NO embedded timestamp or sequential structure, so an observer cannot
/// fingerprint a proxied response or extract the server clock from the id.
#[test]
fn test_synthesize_response_id_is_opaque_native_length() {
    let id = synthesize_response_id();
    let suffix = id.strip_prefix("resp_").expect("resp_ prefix");
    assert_eq!(
        suffix.len(),
        RESPONSE_ID_TOKEN_LEN,
        "native-length suffix: {id}"
    );
    assert!(
        suffix.len() >= 38,
        "at least the native ~38-char profile: {id}"
    );
    assert!(
        suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
        "opaque base62 suffix only: {id}"
    );
    // Exactly one delimiter (the prefix's underscore) — no internal timestamp/counter fields.
    assert_eq!(
        id.matches('_').count(),
        1,
        "no internal field delimiter: {id}"
    );
}

/// Regression (MEDIUM/security, Round 11): synthesized `msg_`/`fc_` item ids must be opaque
/// base62 of native length, NOT the old sequential `msg_00000000` positional hex.
#[test]
fn test_synthesize_item_id_is_opaque_native_length() {
    for prefix in ["msg", "fc"] {
        let id = synthesize_item_id(prefix);
        let suffix = id
            .strip_prefix(&format!("{prefix}_"))
            .expect("prefix present");
        assert_eq!(
            suffix.len(),
            ITEM_ID_TOKEN_LEN,
            "native-length suffix: {id}"
        );
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "opaque base62 suffix: {id}"
        );
        // The old form was zero-padded hex (all low chars); assert it is no longer a pure
        // zero-prefixed positional counter by requiring it differ from the sequential shape.
        assert_ne!(
            suffix,
            "0".repeat(ITEM_ID_TOKEN_LEN),
            "not all-zero positional: {id}"
        );
    }
}

/// Synthesized ids must be unique across calls even in a tight loop (the monotonic counter folded
/// into the token guarantees this independent of the RNG).
#[test]
fn test_synthesized_ids_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(synthesize_response_id()), "duplicate resp_ id");
        assert!(seen.insert(synthesize_item_id("msg")), "duplicate msg_ id");
    }
}

/// The writer's `item_id_for` cache must return the SAME opaque id for a `(prefix, index)` across
/// the item's lifecycle (so `output_item.added`/delta/`output_item.done` correlate), distinct ids
/// for different indices, and a fresh id for a new stream after `reset_sequence_number`.
#[test]
fn test_item_id_for_is_stream_stable_and_opaque() {
    let writer = ResponsesWriter;
    let a1 = writer.item_id_for("msg", 0);
    let a2 = writer.item_id_for("msg", 0);
    assert_eq!(
        a1, a2,
        "same (prefix,index) yields a stable id within a stream"
    );
    assert!(a1.starts_with("msg_")); // golden wire-contract literal (kept bare on purpose)
    let b = writer.item_id_for("msg", 1);
    assert_ne!(a1, b, "different indices get distinct ids");
    let fc = writer.item_id_for("fc", 0);
    assert_ne!(
        a1, fc,
        "different prefixes at the same index get distinct ids"
    );
    assert!(fc.starts_with("fc_")); // golden wire-contract literal (kept bare on purpose)

    // A new stream (reset) mints a fresh id for the same key.
    writer.reset_sequence_number();
    let a_after = writer.item_id_for("msg", 0);
    assert_ne!(
        a1, a_after,
        "a reused writer must not replay a previous stream's item id"
    );
}

/// Full streamed text item: the `output_item.added`, every `output_text.delta`, and the closing
/// `output_item.done` must all carry the SAME `item_id` so a typed SDK correlates the lifecycle.
#[test]
fn test_streamed_text_item_shares_one_item_id() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (_, added) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("output_item.added");
    let added_id = added["item_id"].as_str().unwrap().to_string();
    assert!(added_id.starts_with("msg_")); // golden wire-contract literal (kept bare on purpose)

    let (_, delta) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
        })
        .expect("output_text.delta");
    assert_eq!(delta["item_id"].as_str(), Some(added_id.as_str()));

    let (_, done) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("output_item.done");
    assert_eq!(
        done["item_id"].as_str(),
        Some(added_id.as_str()),
        "added/delta/done must share one item_id"
    );
    assert_eq!(done["item"]["id"].as_str(), Some(added_id.as_str()));
}

/// Regression (HIGH/correctness, Round 12): the cardinality-cap guard on
/// `response.output_item.added` was inverted (`if already_open || ...`), re-emitting a BlockStart
/// for an index that was already open. A repeated `output_item.added` for the SAME function-call
/// index must NOT produce a second BlockStart (only the first added opens the block); the second
/// is a no-op. Otherwise downstream sees BlockStart→BlockStart for one block — an invalid
/// sequence and a proxy tell.
#[test]
fn test_repeated_output_item_added_does_not_reemit_block_start() {
    let mut state = crate::ir::StreamDecodeState::default();
    let item = serde_json::json!({
        "output_index": 0,
        "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
    });
    let first = reader_read_response_events(EVT_OUTPUT_ITEM_ADDED, &item, &mut state);
    assert_eq!(
        first.len(),
        1,
        "the first output_item.added opens exactly one BlockStart"
    );
    assert!(matches!(
        first.first(),
        Some(crate::ir::IrStreamEvent::BlockStart { index: 0, .. })
    ));
    // A second added for the SAME index must emit nothing (the block is already open).
    let second = reader_read_response_events(EVT_OUTPUT_ITEM_ADDED, &item, &mut state);
    assert!(
            second.is_empty(),
            "a repeated output_item.added for an open index must not re-emit BlockStart, got {second:?}"
        );
    assert_eq!(
        state.open_tools.len(),
        1,
        "the index is tracked exactly once"
    );
}

/// Regression (HIGH/correctness, Round 12): the fixed guard must STILL bound new distinct
/// indices under MAX_OPEN_TOOLS — the inversion fix must not weaken the DoS cap. Beyond the cap
/// a NEW index emits no BlockStart and is not tracked.
#[test]
fn test_cap_still_bounds_new_indices_after_guard_fix() {
    let mut state = crate::ir::StreamDecodeState::default();
    for i in 0..(MAX_OPEN_TOOLS as u64) {
        let out = reader_read_response_events(
            EVT_OUTPUT_ITEM_ADDED,
            &serde_json::json!({
                "output_index": i,
                "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        assert_eq!(out.len(), 1, "each fresh in-cap index opens one BlockStart");
    }
    assert_eq!(state.open_tools.len(), MAX_OPEN_TOOLS);
    // A fresh index beyond the cap (use a distinct, un-clamped value below MAX_OUTPUT_INDEX is
    // impossible here since indices 0..128 already fill it; use a high index that clamps to a
    // value already present is not a "new" index, so instead assert no growth past the cap).
    let over = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": (MAX_OPEN_TOOLS as u64) + 50,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
        }),
        &mut state,
    );
    // The over-cap index clamps to MAX_OUTPUT_INDEX (127), which is already open (it was inserted
    // in the loop), so by the already-open rule it emits nothing and does not grow the set.
    assert!(
        over.is_empty() || state.open_tools.len() <= MAX_OPEN_TOOLS,
        "the cap is never exceeded"
    );
    assert!(
        state.open_tools.len() <= MAX_OPEN_TOOLS,
        "open_tools must never exceed MAX_OPEN_TOOLS, got {}",
        state.open_tools.len()
    );
}

/// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
/// with no open block (suppressed by the cap, or arriving with no preceding
/// `output_item.added`) must be dropped — never an InputJsonDelta against a block that emitted
/// no BlockStart.
#[test]
fn test_args_delta_dropped_for_unopened_index() {
    let mut state = crate::ir::StreamDecodeState::default();
    // No output_item.added for index 3 — the delta must be dropped.
    let out = reader_read_response_events(
        EVT_FUNCTION_CALL_ARGS_DELTA,
        &serde_json::json!({"output_index": 3, "delta": "{\"a\":1}"}),
        &mut state,
    );
    assert!(
        out.is_empty(),
        "args delta for an unopened index must be dropped, got {out:?}"
    );
}

/// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
/// that DID open (via `output_item.added`) is routed as an InputJsonDelta to that index.
#[test]
fn test_args_delta_routed_for_opened_index() {
    let mut state = crate::ir::StreamDecodeState::default();
    let _ = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 1,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc","name":"f"}
        }),
        &mut state,
    );
    let out = reader_read_response_events(
        EVT_FUNCTION_CALL_ARGS_DELTA,
        &serde_json::json!({"output_index": 1, "delta": "{\"a\":1}"}),
        &mut state,
    );
    match out.first() {
        Some(crate::ir::IrStreamEvent::BlockDelta {
            index,
            delta: crate::ir::IrDelta::InputJsonDelta(s),
        }) => {
            assert_eq!(*index, 1);
            assert_eq!(s, "{\"a\":1}");
        }
        other => panic!("expected InputJsonDelta at index 1, got {other:?}"),
    }
}

/// Regression (MEDIUM/conformance, Round 12): every lifecycle event in a stream must carry the
/// SAME `created_at` as the opening `response.created` — the terminal event must replay the
/// captured timestamp, not a fresh `now_unix_secs()` wall-clock read.
#[test]
fn test_created_at_is_constant_across_stream_events() {
    let writer = ResponsesWriter;
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: Some(1_700_000_000),
            model: None,
        })
        .expect("response.created");
    let created_ts = created["response"]["created_at"].as_u64();
    assert_eq!(created_ts, Some(1_700_000_000));

    let (_, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal event");
    assert_eq!(
        completed["response"]["created_at"].as_u64(),
        created_ts,
        "terminal created_at must match the opening event's"
    );
}

/// Regression (MEDIUM/conformance, Round 12): the `response.failed` event must also replay the
/// captured `created_at`, matching `response.created`.
#[test]
fn test_failed_event_replays_created_at() {
    let writer = ResponsesWriter;
    let (_, created) = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: Some(1_700_000_123),
            model: None,
        })
        .expect("response.created");
    let created_ts = created["response"]["created_at"].as_u64();

    let (_, failed) = writer
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }))
        .expect("response.failed");
    assert_eq!(
        failed["response"]["created_at"].as_u64(),
        created_ts,
        "response.failed created_at must match response.created"
    );
}

/// Regression (MEDIUM/conformance, Round 12): the forward.rs transient/upstream error kinds
/// (`timeout`/`network`/`connect`/`5xx`/`transient`/`api_error`) must map to the native
/// `server_error` type, and `context_length_exceeded`/`bad_request` to `invalid_request_error`,
/// never leaking a non-native `error.type` to a Responses client.
#[test]
fn test_write_error_maps_forward_transient_kinds() {
    let writer = ResponsesWriter;
    for kind in [
        "timeout",
        "network",
        "connect",
        "5xx",
        "transient",
        "api_error",
    ] {
        let v = writer.write_error(503, kind, "upstream failure");
        assert_eq!(
            v["error"]["type"].as_str(),
            Some("server_error"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind:?} must map to server_error"
        );
        assert!(v["error"]["code"].is_null(), "server_error code is null");
    }
    for kind in [crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH, "bad_request"] {
        let v = writer.write_error(400, kind, "bad request");
        assert_eq!(
            v["error"]["type"].as_str(),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "kind {kind:?} must map to invalid_request_error"
        );
    }
}

/// Regression (MEDIUM/conformance, finding 2): the function-call `response.output_item.done`
/// must carry the FULLY finalized item — `call_id`, `name`, AND the complete accumulated
/// `arguments` string the SDK reads off `event.item`. Previously it emitted only
/// `{"type":"function_call","id":…}`, an impossible-from-real-OpenAI shape.
#[test]
fn test_function_call_done_carries_finalized_item() {
    let writer = ResponsesWriter;
    // Open the stream so the per-stream state is initialized/reset.
    let _ = writer.write_response_event(&crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    // BlockStart(ToolUse) captures call_id + name.
    let added = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_abc".to_string(),
                name: "get_weather".to_string(),
            },
        })
        .expect("output_item.added should emit");
    assert_eq!(added.0, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)

    // Two argument fragments accumulate into the complete string.
    let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
    });
    let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
    });

    // BlockStop closes it with the fully finalized item.
    let (etype, payload) = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
        .expect("output_item.done should emit");
    assert_eq!(etype, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    let item = &payload["item"];
    assert_eq!(item["type"].as_str(), Some("function_call")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        item["call_id"].as_str(),
        Some("call_abc"),
        "done item must carry call_id"
    );
    assert_eq!(
        item["name"].as_str(),
        Some("get_weather"),
        "done item must carry name"
    );
    assert_eq!(
        item["arguments"].as_str(),
        Some("{\"city\":\"SF\"}"),
        "done item must carry the COMPLETE accumulated arguments"
    );
    // `id` (the opaque fc_ item id) is still present and stable with the added frame.
    assert_eq!(item["id"], added.1["item"]["id"]);
}

/// Regression (MEDIUM/correctness, finding 3): the streaming READER must track open text blocks
/// PER `output_index`, not with a single index-blind bool. Two message items at distinct indices
/// must each get their OWN BlockStart and their OWN BlockStop — no orphan delta, no mismatched
/// close.
#[test]
fn test_reader_multiple_text_items_distinct_indices() {
    let mut state = crate::ir::StreamDecodeState::default();
    // First text item at index 0.
    let a = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "alpha"}),
        &mut state,
    );
    assert_eq!(a.len(), 2, "first delta opens its block then writes");
    assert!(matches!(
        a[0],
        crate::ir::IrStreamEvent::BlockStart { index: 0, .. }
    ));
    // Second text item at index 1 arrives BEFORE index 0 closes — must open its OWN block,
    // never an orphan delta against an unopened block.
    let b = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 1, "delta": "beta"}),
        &mut state,
    );
    assert_eq!(b.len(), 2, "a new index must lazily open its own block");
    assert!(
        matches!(b[0], crate::ir::IrStreamEvent::BlockStart { index: 1, .. }),
        "second text index must emit its OWN BlockStart, got {:?}",
        b[0]
    );
    assert!(matches!(
        b[1],
        crate::ir::IrStreamEvent::BlockDelta { index: 1, .. }
    ));
    // Close index 0: BlockStop must pair with index 0 (not index 1).
    let close0 = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert_eq!(close0.len(), 1);
    assert!(
        matches!(close0[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
        "close must pair with index 0, got {:?}",
        close0[0]
    );
    // Index 1 is still open and closes on its own terminal frame.
    let close1 = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 1}),
        &mut state,
    );
    assert_eq!(close1.len(), 1);
    assert!(matches!(
        close1[0],
        crate::ir::IrStreamEvent::BlockStop { index: 1 }
    ));
}

/// Regression (MEDIUM/correctness, finding 3): a tool item and a text item at DISTINCT indices
/// in the same stream must not interfere — the tool index routes its arguments delta and closes
/// as a tool, while the text index opens/closes independently. Confirms the disjoint key-offset
/// keeps tool routing (`open_tools.contains(&idx)`) intact.
#[test]
fn test_reader_text_and_tool_indices_coexist() {
    let mut state = crate::ir::StreamDecodeState::default();
    // Tool item opens at index 0.
    let _ = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 0,
            "item": {"type":ITEM_TYPE_FUNCTION_CALL,"call_id":"fc_1","name":"f"}
        }),
        &mut state,
    );
    // Text item opens at index 1.
    let t = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 1, "delta": "hi"}),
        &mut state,
    );
    assert!(matches!(
        t[0],
        crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
    ));
    // Tool arguments delta at index 0 must still route (tool index intact under raw key).
    let args = reader_read_response_events(
        EVT_FUNCTION_CALL_ARGS_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "{\"x\":1}"}),
        &mut state,
    );
    assert_eq!(args.len(), 1, "tool args delta must route to the open tool");
    assert!(matches!(
        args[0],
        crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta(_)
        }
    ));
    // Close the tool index → tool BlockStop.
    let close_tool = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 0}),
        &mut state,
    );
    assert!(matches!(
        close_tool[0],
        crate::ir::IrStreamEvent::BlockStop { index: 0 }
    ));
    // Close the text index → text BlockStop.
    let close_text = reader_read_response_events(
        EVT_OUTPUT_ITEM_DONE,
        &serde_json::json!({"output_index": 1}),
        &mut state,
    );
    assert!(matches!(
        close_text[0],
        crate::ir::IrStreamEvent::BlockStop { index: 1 }
    ));
}

/// Regression (MEDIUM/conformance): `write_response` must emit the SDK-required non-nullable
/// `model` even when the IR carries none (cross-protocol path, e.g. Bedrock/Anthropic →
/// Responses). A prior revision emitted `model` only when `resp.model` was `Some`, dropping the
/// key entirely on cross-protocol responses — a strict-decoder failure and a distinguishability
/// tell. Absent IR model must fall back to DEFAULT_MODEL; a present model is preserved verbatim.
#[test]
fn test_write_response_emits_model_fallback() {
    let make_resp = |model: Option<String>| crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model,
        id: Some("resp_x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };

    // Cross-protocol: no model in the IR → DEFAULT_MODEL, never an absent key.
    let writer = ResponsesWriter;
    let out_none = writer.write_response(&make_resp(None));
    assert_eq!(
        out_none.get("model").and_then(|m| m.as_str()),
        Some(DEFAULT_MODEL),
        "absent model must fall back to DEFAULT_MODEL, not be omitted"
    );

    // Same-protocol passthrough: the upstream model is preserved verbatim.
    let writer_some = ResponsesWriter;
    let out_some = writer_some.write_response(&make_resp(Some("gpt-4o-mini".to_string())));
    assert_eq!(
        out_some.get("model").and_then(|m| m.as_str()),
        Some("gpt-4o-mini"),
        "present model must be preserved verbatim"
    );
}

/// Regression (MEDIUM/conformance): on a cross-protocol stream (IR `model` is `None` on
/// `MessageStart`), `response.created` AND every terminal lifecycle event
/// (`response.completed`/`.incomplete`/`.failed`) must carry the same non-nullable `model`
/// (DEFAULT_MODEL here). The terminal arms previously emitted no `model` at all — an inner
/// `response` missing the required field, a strict-decoder failure and a proxy tell.
#[test]
fn test_stream_terminal_events_carry_model_fallback() {
    // --- cross-protocol completed stream: model None throughout the IR ---
    let writer = ResponsesWriter;
    let start = crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (_, created) = writer.write_response_event(&start).expect("created event");
    assert_eq!(
        created
            .get("response")
            .and_then(|r| r.get("model"))
            .and_then(|m| m.as_str()),
        Some(DEFAULT_MODEL),
        "response.created must carry DEFAULT_MODEL when IR model is None"
    );

    let delta = crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (ename, completed) = writer.write_response_event(&delta).expect("terminal event");
    assert_eq!(ename, "response.completed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        completed
            .get("response")
            .and_then(|r| r.get("model"))
            .and_then(|m| m.as_str()),
        Some(DEFAULT_MODEL),
        "response.completed must replay the required model field"
    );

    // --- same-protocol stream: the captured model is replayed onto the terminal event ---
    let writer2 = ResponsesWriter;
    let start2 = crate::ir::IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: Some("resp_keep".to_string()),
        created: Some(1_720_000_000),
        model: Some("gpt-4o-mini".to_string()),
    };
    writer2
        .write_response_event(&start2)
        .expect("created event");
    let err = crate::ir::IrStreamEvent::Error(IrError {
        class: StatusClass::ServerError,
        provider_signal: Some("boom".to_string()),
        retry_after: None,
    });
    let (ename2, failed) = writer2.write_response_event(&err).expect("failed event");
    assert_eq!(ename2, "response.failed"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        failed
            .get("response")
            .and_then(|r| r.get("model"))
            .and_then(|m| m.as_str()),
        Some("gpt-4o-mini"),
        "response.failed must replay the captured stream model"
    );
}

/// Regression (MEDIUM/conformance, Round 15): the non-streaming `write_response` body must carry
/// the REQUIRED nullable `error` field (`null` on a non-failed response), mirroring the
/// streaming `response.created` skeleton. A real `/v1/responses` non-streaming body always
/// includes `error`; omitting it breaks strict SDK/Pydantic/Zod decoders that read
/// `response.error` unconditionally and is a distinguishability tell.
#[test]
fn test_write_response_emits_error_null_for_completed_and_incomplete() {
    let make_resp = |stop: crate::ir::IrStopReason| crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(stop),
        usage: usage_fixture(),
        model: Some("gpt-4o-mini".to_string()),
        id: Some("resp_x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let writer = ResponsesWriter;

    // Completed: error key present and explicitly null.
    let completed = writer.write_response(&make_resp(crate::ir::IrStopReason::EndTurn));
    assert_eq!(completed["status"].as_str(), Some("completed")); // golden wire-contract literal (kept bare on purpose)
    assert!(
        completed.get("error").is_some(),
        "non-streaming body must include the required error key"
    );
    assert!(
        completed["error"].is_null(),
        "error must be null on a completed response"
    );

    // Incomplete (max_tokens): error is still present and null (the failure path is the error
    // envelope, never this success/incomplete body).
    let incomplete = writer.write_response(&make_resp(crate::ir::IrStopReason::MaxTokens));
    assert_eq!(incomplete["status"].as_str(), Some("incomplete")); // golden wire-contract literal (kept bare on purpose)
    assert!(
        incomplete["error"].is_null(),
        "error must be null on an incomplete response"
    );
}

/// Regression (MEDIUM/correctness, Round 15; class-corrected R26/LOW #8): a non-streaming
/// Responses body with `status:"failed"` and `output:null` is an upstream provider failure, NOT
/// a parse error. The reader must surface it as an IrError carrying the upstream `error.code`,
/// never misclassify it as an internal `ir_parse` ClientError. As of R26 the IrError `class` is
/// derived from the captured signal via `class_for_response_failed` (mirroring the streaming
/// `response.failed` arms and the HTTP classifier) rather than hardcoded ServerError: a
/// `rate_limit_exceeded` failed body must classify as RateLimit, not a generic ServerError.
#[test]
fn test_read_response_failed_surfaces_upstream_error() {
    let reader = ResponsesReader;

    // status:"failed" with output:null and a populated error.code. The rate-limit signal must
    // classify as RateLimit (not the old hardcoded ServerError).
    let body = serde_json::json!({
        "id": "resp_fail",
        "object": OBJ_RESPONSE,
        "status": STATUS_FAILED,
        "output": serde_json::Value::Null,
        "error": { "code": ERR_CODE_RATE_LIMIT, "message": "slow down" },
        "usage": { "input_tokens": 1, "output_tokens": 0 },
        "model": "gpt-4o-mini"
    });
    let err = reader
        .read_response(&body)
        .expect_err("failed status must surface as an error");
    assert_eq!(
        err.class,
        StatusClass::RateLimit,
        "a rate_limit_exceeded failed body is a RateLimit, not a generic ServerError"
    );
    assert_eq!(
        err.provider_signal.as_deref(),
        Some("rate_limit_exceeded"),
        "the upstream error.code must be surfaced as the provider signal"
    );

    // error.type fallback when code is absent. `content_filter` is not one of the mapped
    // signals, so it falls to the default transient ServerError bucket.
    let body_type = serde_json::json!({
        "status": STATUS_FAILED,
        "error": { "type": INCOMPLETE_REASON_CONTENT_FILTER, "message": "blocked" },
        "usage": { "input_tokens": 1, "output_tokens": 0 }
    });
    let err_type = reader
        .read_response(&body_type)
        .expect_err("failed status must surface as an error");
    assert_eq!(err_type.class, StatusClass::ServerError);
    assert_eq!(err_type.provider_signal.as_deref(), Some("content_filter")); // golden wire-contract literal (kept bare on purpose)

    // failed with no usable error object → generic response_failed signal, default ServerError.
    let body_bare = serde_json::json!({ "status": STATUS_FAILED });
    let err_bare = reader
        .read_response(&body_bare)
        .expect_err("failed status must surface as an error");
    assert_eq!(err_bare.class, StatusClass::ServerError);
    assert_eq!(err_bare.provider_signal.as_deref(), Some("response_failed"));

    // A genuinely malformed body (no status, no output) is STILL an ir_parse ClientError — the
    // failed-status path must not swallow real parse failures.
    let body_parse = serde_json::json!({ "id": "resp_x" });
    let err_parse = reader
        .read_response(&body_parse)
        .expect_err("missing output must surface as a parse error");
    assert_eq!(err_parse.class, StatusClass::ClientError);
    assert_eq!(err_parse.provider_signal.as_deref(), Some("ir_parse")); // golden wire-contract literal (kept bare on purpose)
}

/// Regression (HIGH, re-audit R20): the writer emits a failed body as
/// `{"status":"failed","output":[],"error":{...}}` — `output` is a PRESENT EMPTY array, not
/// null/absent. Before the fix the empty array took the `if let Some(output_arr)` branch,
/// iterated zero items, then failed the usage check and returned a ClientError `ir_parse`,
/// MASKING the real upstream error and feeding the breaker the wrong (ClientFault, no-retry)
/// transition. The failed-status early return must fire regardless of `output` shape.
#[test]
fn test_read_response_failed_with_empty_output_array_not_masked() {
    let reader = ResponsesReader;
    let body = serde_json::json!({
        "id": "resp_fail",
        "object": OBJ_RESPONSE,
        "status": STATUS_FAILED,
        "output": [],
        "error": { "code": ERR_TYPE_SERVER_ERROR, "message": "boom" },
        // No `usage` on purpose: pre-fix this body fell through to the usage check and that
        // was part of what masked the error. The failed early return must not require usage.
    });
    let err = reader
        .read_response(&body)
        .expect_err("failed status with output:[] must surface as an error, not be masked");
    assert_eq!(
        err.class,
        StatusClass::ServerError,
        "output:[] on a failed body must still be a ServerError, not a ClientError ir_parse"
    );
    assert_eq!(
        err.provider_signal.as_deref(),
        Some("server_error"),
        "the upstream error.code must be carried through even with output:[]"
    );
}

/// Regression (MEDIUM #5, re-audit R20): `system`/`developer` input turns carry the system
/// prompt. The reader previously dropped them (handled by neither the typed `message` arm nor
/// the untyped role arm), losing the system prompt on a cross-protocol hop. They must now be
/// accumulated into `IrRequest.system`. Covers typed + untyped items, and array + bare-string
/// content.
#[test]
fn test_read_request_system_and_developer_turns_feed_system() {
    let reader = ResponsesReader;
    let body = serde_json::json!({
        "model": "gpt-4o",
        "input": [
            // typed message, system role, array content
            { "type": ITEM_TYPE_MESSAGE, "role": "system",
              "content": [{ "type": CONTENT_TYPE_INPUT_TEXT, "text": "you are terse" }] },
            // typed message, developer role, bare-string content
            { "type": ITEM_TYPE_MESSAGE, "role": "developer", "content": "be precise" },
            // untyped item, system role, array content
            { "role": "system",
              "content": [{ "type": CONTENT_TYPE_INPUT_TEXT, "text": "no emojis" }] },
            // a normal user turn must still land in messages
            { "type": CONTENT_TYPE_INPUT_TEXT, "text": "hello" }
        ]
    });
    let req = reader.read_request(&body).expect("request must parse");
    let system_text: Vec<&str> = req
        .system
        .iter()
        .filter_map(|b| match b {
            crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        system_text,
        vec!["you are terse", "be precise", "no emojis"],
        "system/developer turns (typed+untyped, array+string) must feed IrRequest.system in order"
    );
    // The user turn must NOT have been swallowed into system.
    assert_eq!(
        req.messages.len(),
        1,
        "only the user turn becomes a message"
    );
    assert!(
        matches!(req.messages[0].role, crate::ir::IrRole::User),
        "the surviving message is the user turn"
    );
}

/// Regression (MEDIUM #16, re-audit R20): `max_output_tokens` was read via
/// `.as_i64()...map(|v| v as u32)`, silently truncating a value larger than `u32::MAX`. It must
/// now drop an out-of-range value to None (matching the anthropic/bedrock readers) instead of
/// wrapping it to a bogus small cap.
#[test]
fn test_read_request_max_output_tokens_out_of_range_drops_to_none() {
    let reader = ResponsesReader;

    // u32::MAX + 1 — pre-fix `as u32` would truncate this to 0, a wildly wrong cap.
    let big = u64::from(u32::MAX) + 1;
    let body_big = serde_json::json!({
        "model": "gpt-4o",
        "input": "hi",
        "max_output_tokens": big
    });
    let req_big = reader.read_request(&body_big).expect("request must parse");
    assert_eq!(
        req_big.max_tokens, None,
        "an out-of-range max_output_tokens must drop to None, not truncate"
    );

    // An in-range value still round-trips.
    let body_ok = serde_json::json!({
        "model": "gpt-4o",
        "input": "hi",
        "max_output_tokens": 4096
    });
    let req_ok = reader.read_request(&body_ok).expect("request must parse");
    assert_eq!(req_ok.max_tokens, Some(4096));
}

/// Regression (MEDIUM/conformance, Round 15): the terminal `response.completed`/
/// `response.incomplete`/`response.failed` events' inner `response` object must carry the
/// REQUIRED `output` array (present-but-empty) and (on non-failed terminals) `error: null`,
/// mirroring the `response.created` skeleton. The SDK reads `event.response.output` to finalize
/// the assembled Response; omitting it breaks strict decoders and is a distinguishability tell.
#[test]
fn test_stream_terminal_events_carry_output_and_error() {
    // --- completed terminal ---
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (_, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal event");
    assert!(
        completed["response"]["output"].is_array(),
        "response.completed inner response must carry an output array"
    );
    assert!(
        completed["response"]["error"].is_null(),
        "response.completed inner response must carry error: null"
    );

    // --- incomplete terminal ---
    let writer2 = ResponsesWriter;
    let _ = writer2.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (_, incomplete) = writer2
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal event");
    assert!(
        incomplete["response"]["output"].is_array(),
        "response.incomplete inner response must carry an output array"
    );
    assert!(
        incomplete["response"]["error"].is_null(),
        "response.incomplete inner response must carry error: null"
    );

    // --- failed terminal: output present-but-empty alongside the populated error object ---
    let writer3 = ResponsesWriter;
    let _ = writer3.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (ename, failed) = writer3
        .write_response_event(&IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }))
        .expect("failed event");
    assert_eq!(ename, "response.failed"); // golden wire-contract literal (kept bare on purpose)
    assert!(
        failed["response"]["output"].is_array(),
        "response.failed inner response must carry an output array"
    );
    assert_eq!(
        failed["response"]["error"]["code"].as_str(),
        Some("boom"),
        "response.failed must still carry its populated error object"
    );
}

/// Regression (MEDIUM/conformance): the terminal `response.completed` event's inner
/// `response.output` must carry the FULLY assembled output array (the message item with its
/// `output_text` content, and the finalized function-call item) — NOT a hard-coded `[]`. A
/// `completed` response with nonzero `usage.output_tokens` but an empty `output` is a shape real
/// /v1/responses never emits and breaks SDK consumers that read `event.response.output`.
#[test]
fn test_terminal_output_assembles_streamed_text_and_tool_items() {
    let writer = ResponsesWriter;
    // Opening event.
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });

    // Text item at index 0: BlockStart + two deltas + BlockStop.
    let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::Text,
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("Hello ".to_string()),
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("world".to_string()),
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });

    // Function-call item at index 1: BlockStart(ToolUse) + arg deltas + BlockStop.
    let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 1,
        block: crate::ir::IrBlockMeta::ToolUse {
            id: "call_abc".to_string(),
            name: "get_weather".to_string(),
        },
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 1,
        delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 1,
        delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 1 });

    // Terminal.
    let (ename, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal event");
    assert_eq!(ename, "response.completed"); // golden wire-contract literal (kept bare on purpose)

    let output = completed["response"]["output"]
        .as_array()
        .expect("terminal output must be an array");
    assert_eq!(
        output.len(),
        2,
        "assembled output must carry both the message and the function_call item, got {output:?}"
    );

    // Items come out in output_index order: message (0) then function_call (1).
    let msg_item = &output[0];
    assert_eq!(msg_item["type"], serde_json::json!("message")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(msg_item["role"], serde_json::json!("assistant"));
    let text = msg_item["content"][0]["text"]
        .as_str()
        .expect("message item carries assembled output_text");
    assert_eq!(
        text, "Hello world",
        "the streamed text must be fully assembled"
    );

    let fc_item = &output[1];
    assert_eq!(fc_item["type"], serde_json::json!("function_call")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(fc_item["call_id"], serde_json::json!("call_abc"));
    assert_eq!(fc_item["name"], serde_json::json!("get_weather"));
    assert_eq!(
        fc_item["arguments"],
        serde_json::json!("{\"city\":\"SF\"}"),
        "the finalized function-call item must carry the complete accumulated arguments"
    );
}

/// A genuinely output-less turn (no blocks streamed) still emits a present-but-empty `output`
/// array on the terminal event — never an omitted key.
#[test]
fn test_terminal_output_empty_when_no_blocks_streamed() {
    let writer = ResponsesWriter;
    let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let (_, completed) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage_fixture(),
        })
        .expect("terminal event");
    let output = completed["response"]["output"]
        .as_array()
        .expect("output present-but-empty, never omitted");
    assert!(
        output.is_empty(),
        "no blocks streamed -> empty output array"
    );
}

/// Regression (MED #2): a function_call and a text part arriving at the SAME `output_index`
/// must NOT both open a block, and a terminal event must close that index EXACTLY once.
///
/// Before the fix, `output_item.added` tracked the tool under raw key `N` while
/// `output_text.delta` tracked text under `N + TEXT_INDEX_KEY_OFFSET`, so a tool AND a text
/// block could both open at the same wire index. `close_open_blocks` then mapped both keys back
/// to IR index `N` and (with no dedup) emitted TWO `BlockStop{N}` — a duplicate
/// `content_block_stop` the Anthropic writer relays for an already-closed index.
#[test]
fn test_same_output_index_tool_and_text_single_open_single_close() {
    let mut state = crate::ir::StreamDecodeState::default();

    // Open a tool block at output_index 0.
    let added = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 0,
            "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "call_x", "name": "f"}
        }),
        &mut state,
    );
    let starts_after_tool = added
        .iter()
        .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { .. }))
        .count();
    assert_eq!(
        starts_after_tool, 1,
        "tool open emits exactly one BlockStart"
    );

    // A text delta arrives at the SAME output_index 0. It must NOT open a second block, and
    // must NOT route a TextDelta into the open tool block.
    let text = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "hi"}),
        &mut state,
    );
    assert!(
        text.is_empty(),
        "text delta at an index already held by a tool block must emit nothing, got {text:?}"
    );
    assert!(
        !state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
        "no text key must be opened at an index already held by a tool"
    );

    // Exactly one key is open for index 0 (the raw tool key).
    assert_eq!(
        state.open_tools.len(),
        1,
        "exactly one open marker for the shared index"
    );

    // A terminal event must close index 0 exactly ONCE.
    let completed = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
        &mut state,
    );
    let stops_at_0 = completed
        .iter()
        .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { index: 0 }))
        .count();
    assert_eq!(
        stops_at_0, 1,
        "terminal must emit EXACTLY ONE BlockStop for the shared index, got {completed:?}"
    );
}

/// Regression (MED #2, dedup layer): even if two open keys for the same IR index somehow
/// coexist in `open_tools` (raw `N` and `N + TEXT_INDEX_KEY_OFFSET`), the terminal drain must
/// collapse them to a SINGLE `BlockStop{N}`. This pins the `sort`+`dedup` in `close_open_blocks`
/// directly: before the dedup fix this drain produced two `BlockStop{N}`.
#[test]
fn test_terminal_drain_dedups_colliding_keys() {
    let mut state = crate::ir::StreamDecodeState::default();
    // Directly seed both keys for IR index 3 to exercise the drain's dedup in isolation.
    state.open_tools.insert(3);
    state.open_tools.insert(3 + TEXT_INDEX_KEY_OFFSET);

    let events = reader_read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({"response": {"status": STATUS_COMPLETED}}),
        &mut state,
    );
    let stops_at_3 = events
        .iter()
        .filter(|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { index: 3 }))
        .count();
    assert_eq!(
            stops_at_3, 1,
            "colliding tool+text keys for one IR index must drain to exactly one BlockStop, got {events:?}"
        );
    assert!(
        state.open_tools.is_empty(),
        "terminal drain must clear all open keys"
    );
}

/// Regression (MED #2, symmetric guard): a tool item must not open at an `output_index` already
/// held by an OPEN TEXT block. Before the fix, `output_item.added` only checked the raw key, so
/// a text block open under `N + TEXT_INDEX_KEY_OFFSET` did not block a tool open at raw `N`.
#[test]
fn test_tool_open_suppressed_when_text_block_open_at_index() {
    let mut state = crate::ir::StreamDecodeState::default();
    // Open a TEXT block at index 0.
    let text = reader_read_response_events(
        EVT_OUTPUT_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "a"}),
        &mut state,
    );
    assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    assert_eq!(text.len(), 2);

    // A function_call item arrives at the same index 0 -> must NOT open a tool block.
    let added = reader_read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 0,
            "item": {"type": ITEM_TYPE_FUNCTION_CALL, "call_id": "call_y", "name": "g"}
        }),
        &mut state,
    );
    assert!(
        !added
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { .. })),
        "tool open at an index already held by a text block must emit no BlockStart, got {added:?}"
    );
    assert!(
        !state.open_tools.contains(&0),
        "no raw tool key may be opened at an index already held by a text block"
    );
}

/// Regression (LOW #9): `synth_token` must emit ONLY base62 characters, drawn uniformly via
/// rejection sampling (no biased `byte % 62`). We assert the character class strictly, and run
/// a targeted check of the EXACT bias `byte % 62` introduces: 256 = 4*62 + 8, so under the old
/// reduction bytes wrap such that base62 digits at indices 0..=7 get FIVE source bytes each
/// (`d, d+62, d+124, d+186, d+248`) while indices 8..=61 get only FOUR — a 5/4 = 1.25x
/// over-representation of the first 8 alphabet positions. Rejection sampling drops bytes >= 248,
/// so every index gets exactly four source bytes and the two groups have EQUAL expected
/// frequency. We compare the mean count of the biased group (indices 0..=7) against the
/// unbiased group (indices 8..=61) over a large sample: under the fix the ratio is ≈1.0; under
/// the old code it is ≈1.25, far outside the tolerance band.
#[test]
fn test_synth_token_uniform_base62_only() {
    let alphabet: std::collections::HashSet<char> = BASE62.iter().map(|&b| b as char).collect();
    // Per-alphabet-INDEX counts (index into BASE62), so we can isolate the exact biased group.
    let mut counts = [0usize; 62];
    let char_to_index: std::collections::HashMap<char, usize> = BASE62
        .iter()
        .enumerate()
        .map(|(i, &b)| (b as char, i))
        .collect();

    // 20_000 tokens * 48 chars = 960_000 samples. With ~15.5k expected per digit, the standard
    // deviation per digit is ~124 (<1%), so a 25% group-mean gap is overwhelmingly significant.
    for _ in 0..20_000 {
        let tok = synth_token::<48>();
        assert_eq!(tok.len(), 48, "token width must be exactly N");
        for c in tok.chars() {
            assert!(
                alphabet.contains(&c),
                "synth_token produced a non-base62 char: {c:?}"
            );
            counts[char_to_index[&c]] += 1;
        }
    }

    // Every base62 digit must have appeared at least once.
    assert!(
        counts.iter().all(|&n| n > 0),
        "all 62 base62 digits should appear in a large uniform sample, counts={counts:?}"
    );

    // Mean frequency of the would-be-biased group (alphabet indices 0..=7) vs the rest.
    let biased_group: f64 = counts[0..8].iter().sum::<usize>() as f64 / 8.0;
    let rest_group: f64 = counts[8..62].iter().sum::<usize>() as f64 / 54.0;
    let ratio = biased_group / rest_group;
    // Fixed code: ratio ≈ 1.0. Old `byte % 62`: ratio ≈ 1.25. A 5% band cleanly separates them
    // while absorbing ordinary CSPRNG variance (the per-group means concentrate far tighter than
    // 5% at this sample size).
    assert!(
        (0.95..=1.05).contains(&ratio),
        "first-8 base62 digits must not be over-represented (group ratio={ratio:.4}; \
             ~1.25 indicates the biased `byte % 62` reduction). counts={counts:?}"
    );
}

// PF-H1: `tool_choice: "required"` must round-trip through the Responses reader into the IR
// union and back out the writer — not silently degrade to `auto`/omitted on the seam.
#[test]
fn test_responses_tool_choice_required_roundtrips() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": "hi"}],
        "tool_choice": "required",
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&json).expect("read_request");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
    // It must NOT also linger in `extra` (modeled key).
    assert!(!ir.extra.contains_key("tool_choice"));

    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("tool_choice").and_then(|v| v.as_str()),
        Some("required")
    );
}

// PF-H1: a targeted `{"type":"function","name":"X"}` (the Responses flat shape) must preserve the
// pinned tool name through the IR and re-emit it in the same flat shape.
#[test]
fn test_responses_tool_choice_specific_function() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "function", "name": "get_weather"},
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&json).expect("read_request");
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    let tc = out.get("tool_choice").expect("tool_choice emitted");
    assert_eq!(tc.get("type").and_then(|v| v.as_str()), Some("function"));
    assert_eq!(tc.get("name").and_then(|v| v.as_str()), Some("get_weather"));
}

// A request with no `tool_choice` must yield `None` (omitted) and the writer must NOT synthesize
// a spurious directive — preserving the "absent stays absent" contract.
#[test]
fn test_responses_tool_choice_absent_is_none() {
    let json = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": "hi"}],
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&json).expect("read_request");
    assert_eq!(ir.tool_choice, None);
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    assert!(out.get("tool_choice").is_none());
}

/// Build a minimal IR request for writer tests, with every Phase-0 / sampling field None/empty so
/// individual tests can set just the one knob under test.
fn empty_ir_request() -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: Vec::new(),
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop: Vec::new(),
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

// H1 REASONING: a non-stream Responses `reasoning` output item must read into an IR Thinking block
// (text from `content[].reasoning_text`, signature from `encrypted_content`) AND write back as a
// `reasoning` item — a full round-trip, so reasoning survives both directions of the seam.
#[test]
fn test_reasoning_item_thinking_round_trip() {
    let body = serde_json::json!({
        "id": "resp_r",
        "status": STATUS_COMPLETED,
        "model": "o3",
        "output": [
            {
                "type": ITEM_TYPE_REASONING,
                "id": "rs_1",
                "summary": [],
                "content": [{"type": CONTENT_TYPE_REASONING_TEXT, "text": "let me think step by step"}],
                "encrypted_content": "ENC_BLOB_123"
            },
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "the answer"}]
            }
        ],
        "usage": {"input_tokens": 5, "output_tokens": 7}
    });
    let reader = ResponsesReader;
    let ir = reader.read_response(&body).expect("read_response");
    // The reasoning item became a Thinking block carrying both text and the encrypted_content
    // mapped into the signature slot.
    let thinking = ir
        .content
        .iter()
        .find_map(|b| match b {
            crate::ir::IrBlock::Thinking {
                text, signature, ..
            } => Some((text, signature)),
            _ => None,
        })
        .expect("a Thinking block read from the reasoning item");
    assert_eq!(thinking.0, "let me think step by step");
    assert_eq!(thinking.1.as_deref(), Some("ENC_BLOB_123"));

    // Write back: the Thinking block must re-emit a native `reasoning` output item with the text
    // under `content[].reasoning_text` and the signature back in `encrypted_content`.
    let writer = ResponsesWriter;
    let out = writer.write_response(&ir);
    let reasoning = out["output"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["type"] == "reasoning")) // golden wire-contract literal (kept bare on purpose)
        .expect("a reasoning output item written back");
    assert_eq!(
        reasoning["content"][0]["type"],
        "reasoning_text", // golden wire-contract literal (kept bare on purpose)
        "reasoning text part typed reasoning_text"
    );
    assert_eq!(
        reasoning["content"][0]["text"], "let me think step by step",
        "reasoning text round-trips"
    );
    assert_eq!(
        reasoning["encrypted_content"], "ENC_BLOB_123",
        "signature round-trips into encrypted_content"
    );
}

/// Fix #6 (request-input reasoning): a prior-turn `reasoning` INPUT item must read into an IR
/// assistant Thinking block (no longer silently dropped) AND the writer must re-emit it as a
/// top-level `reasoning` input item — a same-protocol Responses->Responses request round-trip.
#[test]
fn reasoning_input_item_round_trips_through_request() {
    let body = serde_json::json!({
        "model": "o3",
        "input": [
            {"role": "user", "content": [{"type": CONTENT_TYPE_INPUT_TEXT, "text": "q"}]},
            {
                "type": ITEM_TYPE_REASONING,
                "id": "rs_in",
                "summary": [],
                "content": [{"type": CONTENT_TYPE_REASONING_TEXT, "text": "prior reasoning"}],
                "encrypted_content": "ENC_IN_42"
            },
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "a"}]
            }
        ]
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&body).expect("read_request");

    // The reasoning input item is preserved as an assistant Thinking block (NOT dropped).
    let thinking = ir
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            crate::ir::IrBlock::Thinking {
                text, signature, ..
            } => Some((text, signature)),
            _ => None,
        })
        .expect("a Thinking block decoded from the reasoning input item");
    assert_eq!(thinking.0, "prior reasoning");
    assert_eq!(thinking.1.as_deref(), Some("ENC_IN_42"));

    // Writer re-emits a top-level `reasoning` input item (round-trip).
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    let reasoning = out["input"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["type"] == "reasoning")) // golden wire-contract literal (kept bare on purpose)
        .expect("a reasoning input item written back");
    assert_eq!(reasoning["content"][0]["text"], "prior reasoning");
    assert_eq!(reasoning["encrypted_content"], "ENC_IN_42");
}

// H6: `usage.input_tokens_details.cached_tokens` must read into the IR `cache_read_input_tokens`
// and write back to the same nested Responses location (the Bedrock-shared cache-read field).
#[test]
fn test_cached_tokens_mapping() {
    let body = serde_json::json!({
        "id": "resp_c",
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [{
            "type": ITEM_TYPE_MESSAGE,
            "role": "assistant",
            "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
        }],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 10,
            "input_tokens_details": {"cached_tokens": 64}
        }
    });
    let reader = ResponsesReader;
    let ir = reader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(64),
        "cached_tokens read into cache_read_input_tokens"
    );

    // Write back: the cache count re-emits under usage.input_tokens_details.cached_tokens.
    let writer = ResponsesWriter;
    let out = writer.write_response(&ir);
    assert_eq!(
        out["usage"]["input_tokens_details"]["cached_tokens"], 64,
        "cache_read_input_tokens written back to cached_tokens"
    );

    // A response with NO cache details must NOT gain a spurious cached_tokens (None stays absent).
    let no_cache = serde_json::json!({
        "id": "resp_n", "status": STATUS_COMPLETED, "model": "gpt-4o",
        "output": [{"type":ITEM_TYPE_MESSAGE,"role":"assistant","content":[{"type":CONTENT_TYPE_OUTPUT_TEXT,"text":"x"}]}],
        "usage": {"input_tokens": 1, "output_tokens": 1}
    });
    let ir2 = reader.read_response(&no_cache).expect("read_response");
    assert_eq!(ir2.usage.cache_read_input_tokens, None);
    let out2 = writer.write_response(&ir2);
    assert!(
        out2["usage"].get("input_tokens_details").is_none(),
        "no cache details => no input_tokens_details emitted"
    );
}

// M5 STOP: the Responses create API models no `stop` param, so the writer must NOT emit one even
// when the IR carries stop sequences (they are warned-and-dropped, not silently leaked).
#[test]
fn test_stop_not_emitted_on_responses() {
    let mut req = empty_ir_request();
    req.messages.push(crate::ir::IrMessage {
        role: crate::ir::IrRole::User,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
    });
    req.stop = vec!["STOP".to_string(), "END".to_string()];
    let writer = ResponsesWriter;
    let out = writer.write_request(&req);
    assert!(
        out.get("stop").is_none(),
        "/v1/responses models no stop param; it must not be emitted: {out}"
    );
    assert!(
        out.get("stop_sequences").is_none(),
        "no stop_sequences either"
    );
}

// SAMPLING: frequency_penalty / presence_penalty / seed / n are NOT modeled by the Responses
// create API, so the writer must omit them even when the IR carries values (lossy-by-target).
#[test]
fn test_unsupported_sampling_params_omitted() {
    let mut req = empty_ir_request();
    req.messages.push(crate::ir::IrMessage {
        role: crate::ir::IrRole::User,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
    });
    req.frequency_penalty = Some(0.5);
    req.presence_penalty = Some(0.3);
    req.seed = Some(42);
    req.n = Some(3);
    let writer = ResponsesWriter;
    let out = writer.write_request(&req);
    for key in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            out.get(key).is_none(),
            "{key} is unsupported on /v1/responses and must be omitted: {out}"
        );
    }
}

// M1 response_format <-> text.format. A Responses `text.format` json_schema (FLAT) must read into
// the canonical nested IR shape, and the writer must re-flatten it back under `text.format`.
#[test]
fn test_response_format_text_format_round_trip() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": "hi"}],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "out",
                "schema": {"type": "object"},
                "strict": true
            },
            "verbosity": "low"
        }
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&body).expect("read_request");
    // Canonicalized into the typed IR (no protocol-shaped Value).
    let rf = ir
        .response_format
        .as_ref()
        .expect("response_format promoted");
    assert!(rf.json);
    assert_eq!(rf.name.as_deref(), Some("out"));
    assert_eq!(
        rf.schema.as_ref().and_then(|s| s.get("type")),
        Some(&serde_json::json!("object"))
    );
    assert_eq!(rf.strict, Some(true));
    // The non-format `text` sub-key (verbosity) survives via extra.
    assert_eq!(
        ir.extra.get("text").and_then(|t| t.get("verbosity")),
        Some(&serde_json::json!("low")),
        "text.verbosity preserved in extra"
    );
    // `text` must NOT leak its format into extra (the writer rebuilds it).
    assert!(
        ir.extra.get("text").and_then(|t| t.get("format")).is_none(),
        "text.format must be promoted, not left in extra"
    );

    // Write back: text.format flat shape, merged with the preserved verbosity.
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    let fmt = &out["text"]["format"];
    assert_eq!(fmt["type"], "json_schema", "flat text.format type");
    assert_eq!(fmt["name"], "out", "name flattened beside type");
    assert_eq!(fmt["schema"]["type"], "object");
    assert_eq!(fmt["strict"], true);
    assert!(
        fmt.get("json_schema").is_none(),
        "Responses text.format is FLAT, no nested json_schema key: {fmt}"
    );
    assert_eq!(
        out["text"]["verbosity"], "low",
        "verbosity merged alongside format"
    );
}

// L5: a Responses `input_image` given by `file_id` (no image_url) must NOT become an empty Image
// block — it carries the file_id faithfully and round-trips back to the `file_id` form.
#[test]
fn test_input_image_file_id_round_trip() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "input": [{
            "type": "input_image",
            "file_id": "file-abc123"
        }]
    });
    let reader = ResponsesReader;
    let ir = reader.read_request(&body).expect("read_request");
    let file_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .find_map(|b| match b {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Vendor { vendor, value },
                ..
            } if *vendor == "responses" => value
                .get("file_id")
                .and_then(|i| i.as_str())
                .map(String::from),
            _ => None,
        })
        .expect("a responses-vendor Image block from the file_id image");
    assert_eq!(file_id, "file-abc123", "file_id preserved");

    // Write back: re-emits the native file_id form, not an image_url. The writer emits the
    // CANONICAL message-wrapped form (`{type:message, role, content:[{type:input_image,...}]}`),
    // so the input_image lives inside a message's `content`, not at the top of `input[]`.
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    let image_item = out["input"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("content").and_then(|c| c.as_array()))
        .flatten()
        .find(|c| c["type"] == "input_image")
        .expect("an input_image content block written back");
    assert_eq!(image_item["file_id"], "file-abc123", "file_id round-trips");
    assert!(
        image_item.get("image_url").is_none(),
        "a file_id image must not gain a spurious image_url: {image_item}"
    );
}

// H1 REASONING (stream): a reasoning output-item lifecycle (added/delta/done) must read into a
// Thinking BlockStart + ThinkingDelta + BlockStop, and the writer must re-emit native reasoning
// stream events from those IR events (`output_item.added`/`reasoning_text.delta`/`.done`).
#[test]
fn test_streaming_reasoning_round_trip() {
    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // output_item.added (reasoning) at index 0 opens a Thinking BlockStart.
    let added = reader.read_response_events(
        EVT_OUTPUT_ITEM_ADDED,
        &serde_json::json!({
            "output_index": 0,
            "item": {"type": ITEM_TYPE_REASONING, "id": "rs_1"}
        }),
        &mut state,
    );
    assert!(
        added.iter().any(|e| matches!(
            e,
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Thinking
            }
        )),
        "reasoning item.added opens a Thinking block at index 0: {added:?}"
    );

    // reasoning_text.delta carries a ThinkingDelta.
    let delta = reader.read_response_events(
        EVT_REASONING_TEXT_DELTA,
        &serde_json::json!({"output_index": 0, "delta": "pondering"}),
        &mut state,
    );
    assert!(
        delta.iter().any(|e| matches!(
            e,
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta(t)
            } if t == "pondering"
        )),
        "reasoning_text.delta yields a ThinkingDelta: {delta:?}"
    );

    // Writer side: a Thinking BlockStart emits a native reasoning output_item.added.
    let writer = ResponsesWriter;
    let (etype, payload) = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Thinking,
        })
        .expect("Thinking BlockStart emits a frame");
    assert_eq!(etype, "response.output_item.added"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(payload["item"]["type"], "reasoning"); // golden wire-contract literal (kept bare on purpose)

    // A ThinkingDelta emits a native reasoning_text.delta.
    let (etype2, payload2) = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::ThinkingDelta("pondering".to_string()),
        })
        .expect("ThinkingDelta emits a frame");
    assert_eq!(etype2, "response.reasoning_text.delta"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(payload2["delta"], "pondering");

    // BlockStop closes it as a reasoning output_item.done carrying the assembled text.
    let (etype3, payload3) = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
        .expect("Thinking BlockStop emits a frame");
    assert_eq!(etype3, "response.output_item.done"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(payload3["item"]["type"], "reasoning"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(payload3["item"]["content"][0]["text"], "pondering");
}

// H6 (stream): a streamed terminal `response.completed` carrying
// usage.input_tokens_details.cached_tokens must surface it on the IR MessageDelta usage, and the
// writer's MessageDelta must re-emit it on the terminal event.
#[test]
fn test_streaming_cached_tokens_round_trip() {
    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader.read_response_events(
        EVT_RESPONSE_COMPLETED,
        &serde_json::json!({
            "response": {
                "status": STATUS_COMPLETED,
                "usage": {
                    "input_tokens": 50,
                    "output_tokens": 5,
                    "input_tokens_details": {"cached_tokens": 32}
                }
            }
        }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("a MessageDelta with usage");
    assert_eq!(usage.cache_read_input_tokens, Some(32));

    // Writer re-emits cached_tokens on the terminal event's inner response.usage.
    let writer = ResponsesWriter;
    let (_etype, payload) = writer
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 50,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: Some(32),
            },
        })
        .expect("MessageDelta emits a terminal frame");
    assert_eq!(
        payload["response"]["usage"]["input_tokens_details"]["cached_tokens"], 32,
        "streamed terminal re-emits cached_tokens: {payload}"
    );
}

/// Non-stream `read_response` cache-token NORMALIZATION (ir.rs:457): the Responses API's
/// `input_tokens` is a TOTAL that INCLUDES the cached prefix, so the reader SUBTRACTS
/// `input_tokens_details.cached_tokens` to leave `input_tokens` UNCACHED and stores the cached
/// count additively in `cache_read_input_tokens` (the OpenAI-family convention).
#[test]
fn read_response_subtracts_cached_prefix_from_input_tokens() {
    let body = serde_json::json!({
        "id": "resp_abc",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [{
            "type": ITEM_TYPE_MESSAGE,
            "role": "assistant",
            "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
        }],
        "usage": {
            "input_tokens": 150,
            "output_tokens": 5,
            "input_tokens_details": {"cached_tokens": 100}
        }
    });
    let resp = ResponsesReader.read_response(&body).expect("read_response");
    assert_eq!(
        resp.usage.input_tokens, 50,
        "input_tokens must be wire input(150) MINUS cached(100) = 50 (uncached)"
    );
    assert_eq!(resp.usage.cache_read_input_tokens, Some(100));
    assert_eq!(resp.usage.output_tokens, 5);
    // billable re-sums to the original wire input total (50 + 100) + output 5 = 155.
    assert_eq!(resp.usage.billable_tokens(), 155);
}

/// The write side RECONSTRUCTS the wire shape: it ADDS the cached prefix BACK onto the uncached IR
/// `input_tokens` to re-derive the Responses TOTAL `input_tokens`, and re-emits the FLAT
/// `input_tokens_details.cached_tokens`. Pins the exact inverse of the read normalization.
#[test]
fn write_response_reconstructs_input_tokens_total_with_cached_details() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 50,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(100),
        },
        model: Some("gpt-4o".to_string()),
        id: Some("resp_abc".to_string()),
        created: Some(1_700_000_000),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let writer = ResponsesWriter;
    let out = writer.write_response(&resp);
    assert_eq!(
        out["usage"]["input_tokens"],
        serde_json::json!(150),
        "input_tokens must re-add the cached prefix: uncached(50) + cached(100) = 150"
    );
    assert_eq!(out["usage"]["output_tokens"], serde_json::json!(5));
    assert_eq!(
        out["usage"]["input_tokens_details"]["cached_tokens"],
        serde_json::json!(100)
    );
}

/// `incomplete_details.reason` normalization must be EXHAUSTIVE (ir.rs:186): `max_output_tokens`→
/// MaxTokens, `content_filter`→Safety, `refusal`→Refusal, and any unknown/future reason→Other (no
/// String payload). Pins the whole codec plus its egress inverse (MaxTokens/Safety render the turn
/// `incomplete`; everything else is `completed`).
#[test]
fn incomplete_reason_codec_is_exhaustive() {
    use crate::ir::IrStopReason as S;
    assert_eq!(
        read_responses_incomplete_reason(INCOMPLETE_REASON_MAX_OUTPUT),
        S::MaxTokens
    );
    assert_eq!(
        read_responses_incomplete_reason(INCOMPLETE_REASON_CONTENT_FILTER),
        S::Safety
    );
    assert_eq!(read_responses_incomplete_reason("refusal"), S::Refusal);
    assert_eq!(
        read_responses_incomplete_reason("some_future_reason"),
        S::Other
    );

    // Egress: only MaxTokens/Safety render `incomplete`; the reason projects to the native token.
    assert_eq!(write_responses_status(S::MaxTokens), STATUS_INCOMPLETE);
    assert_eq!(write_responses_status(S::Safety), STATUS_INCOMPLETE);
    assert_eq!(write_responses_status(S::ToolUse), STATUS_COMPLETED);
    assert_eq!(write_responses_status(S::EndTurn), STATUS_COMPLETED);
    assert_eq!(
        write_responses_incomplete_reason(S::MaxTokens),
        INCOMPLETE_REASON_MAX_OUTPUT
    );
    assert_eq!(
        write_responses_incomplete_reason(S::Safety),
        INCOMPLETE_REASON_CONTENT_FILTER
    );
    assert_eq!(
        write_responses_incomplete_reason(S::Other),
        INCOMPLETE_REASON_OTHER
    );
}

/// A full `read_response` with `status:"incomplete"` + `incomplete_details.reason:"content_filter"`
/// surfaces `IrStopReason::Safety`, and a `max_output_tokens` reason surfaces `MaxTokens` — the
/// truncation/moderation signal lives in `incomplete_details`, not the flat status.
#[test]
fn read_response_incomplete_details_promote_stop_reason() {
    let mk = |reason: &str| {
        serde_json::json!({
            "id": "resp_x",
            "object": OBJ_RESPONSE,
            "created_at": 1,
            "status": STATUS_INCOMPLETE,
            "model": "gpt-4o",
            "incomplete_details": {"reason": reason},
            "output": [{
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "partial"}]
            }],
            "usage": {"input_tokens": 3, "output_tokens": 1}
        })
    };
    assert_eq!(
        ResponsesReader
            .read_response(&mk(INCOMPLETE_REASON_CONTENT_FILTER))
            .expect("read")
            .stop_reason,
        Some(crate::ir::IrStopReason::Safety)
    );
    assert_eq!(
        ResponsesReader
            .read_response(&mk(INCOMPLETE_REASON_MAX_OUTPUT))
            .expect("read")
            .stop_reason,
        Some(crate::ir::IrStopReason::MaxTokens)
    );
}

/// A `response_format` json_schema round-trips read→IR→write through the Responses FLAT
/// `text.format` shape (name/schema/strict/description sit BESIDE `type`, not nested under
/// `json_schema` like OpenAI Chat). The IR canonicalizes it so the two OpenAI-family wire shapes
/// stay isolated and neither leaks cross-protocol (ir.rs:348).
#[test]
fn text_format_json_schema_flat_round_trips() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"]
    });
    let body = serde_json::json!({
        "model": "gpt-4o",
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
        "text": {"format": {
            "type": "json_schema",
            "name": "Answer",
            "schema": schema,
            "strict": true,
            "description": "an answer"
        }}
    });
    let ir = ResponsesReader.read_request(&body).expect("read_request");
    let rf = ir
        .response_format
        .as_ref()
        .expect("text.format canonicalizes into the typed IR");
    assert!(rf.json);
    assert_eq!(rf.name.as_deref(), Some("Answer"));
    assert_eq!(rf.strict, Some(true));
    assert_eq!(rf.description.as_deref(), Some("an answer"));
    assert_eq!(rf.schema.as_ref(), Some(&schema));

    // WRITE re-emits the FLAT Responses text.format shape (fields beside type, not nested).
    let writer = ResponsesWriter;
    let out = writer.write_request(&ir);
    let fmt = out
        .pointer("/text/format")
        .expect("text.format must be emitted");
    assert_eq!(
        fmt.get("type").and_then(|t| t.as_str()),
        Some("json_schema")
    );
    assert_eq!(fmt.get("name").and_then(|n| n.as_str()), Some("Answer"));
    assert_eq!(fmt.get("schema"), Some(&schema));
    assert_eq!(fmt.get("strict").and_then(|s| s.as_bool()), Some(true));
    // The FLAT shape must NOT nest under a json_schema key (that is the Chat-Completions shape).
    assert!(
        fmt.get("json_schema").is_none(),
        "Responses text.format is FLAT — must not nest under json_schema: {out}"
    );
}
