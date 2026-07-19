use super::*;

#[test]
fn cohere_stop_reason_codec_round_trips_and_never_leaks() {
    use crate::ir::IrStopReason as S;
    // Native tokens round-trip through the typed IR.
    assert_eq!(read_cohere_stop_reason(COHERE_FINISH_ERROR), S::Error);
    assert_eq!(write_cohere_stop_reason(S::Error), "ERROR"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        read_cohere_stop_reason(COHERE_FINISH_ERROR_TOXIC),
        S::Safety
    );
    assert_eq!(write_cohere_stop_reason(S::Safety), "ERROR_TOXIC"); // golden wire-contract literal (kept bare on purpose)
                                                                    // A reason with no Cohere analog (`refusal`) or an unknown native token (`ERROR_LIMIT` →
                                                                    // Other) degrades to the safe terminal COMPLETE rather than leak an off-spec finish_reason.
    assert_eq!(read_cohere_stop_reason("ERROR_LIMIT"), S::Other);
    assert_eq!(write_cohere_stop_reason(S::Refusal), "COMPLETE"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_cohere_stop_reason(S::Other), "COMPLETE"); // golden wire-contract literal (kept bare on purpose)
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
                    id: "t1".to_string(),
                    name: "f".to_string(),
                    input: serde_json::json!({"x": 1}),
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "result text".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
        ],
        tools: vec![crate::ir::IrTool {
            name: "f".to_string(),
            description: Some("..".to_string()),
            input_schema: serde_json::json!({}),
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

    let writer = CohereWriter;
    let json = writer.write_request(&ir);

    assert!(json.get("messages").is_some());
    let msgs = json.get("messages").unwrap().as_array().unwrap();
    // system prompt (from IrRequest.system) is prepended as a leading system message
    assert_eq!(msgs[0].get("role"), Some(&serde_json::json!("system")));
    assert_eq!(
        msgs[0].get("content"),
        Some(&serde_json::json!("You are helpful."))
    );
    assert_eq!(msgs[1].get("role"), Some(&serde_json::json!("user")));
    assert_eq!(msgs[2].get("role"), Some(&serde_json::json!("assistant")));

    let tool_calls = msgs[2].get("tool_calls").unwrap().as_array().unwrap();
    assert_eq!(
        tool_calls[0]
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str()),
        Some("f")
    );

    let tools_arr = json.get("tools").unwrap().as_array().unwrap();
    assert_eq!(
        tools_arr[0]
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str()),
        Some("f")
    );

    assert_eq!(json.get("max_tokens"), Some(&serde_json::json!(1024)));
    assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
}

#[test]
fn test_read_request_roundtrip() {
    let ir = crate::ir::IrRequest {
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
                    text: "user msg".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Text {
                    text: "assistant msg".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
        ],
        tools: vec![],
        max_tokens: Some(512),
        temperature: Some(0.7),
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: true,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };

    let writer = CohereWriter;
    let reader = CohereReader;
    let json = writer.write_request(&ir);
    let ir2 = reader
        .read_request(&json)
        .expect("read_request should succeed");

    assert_eq!(ir, ir2);
}

#[test]
fn test_read_response() {
    let json = serde_json::json!({
        "id": "msg_123",
        "finish_reason": COHERE_FINISH_TOOL_CALL,
        "message": {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "tool_use", "id": "t1", "name": "get_weather", "input": {"location": "SF"}}
            ]
        },
        "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
    });

    let reader = CohereReader;
    let resp = reader
        .read_response(&json)
        .expect("read_response should succeed");

    assert_eq!(resp.role, crate::ir::IrRole::Assistant);
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
    assert_eq!(resp.usage.input_tokens, 10);
    // The upstream `id` is captured verbatim into the IR (same-protocol identity fidelity).
    assert_eq!(resp.id.as_deref(), Some("msg_123"));
}

#[test]
fn test_write_response_roundtrip() {
    // Carries a real upstream id; same-protocol read→write must preserve it byte-identically.
    let json = serde_json::json!({
        "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
        "finish_reason": COHERE_FINISH_COMPLETE,
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
        "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
    });

    let reader = CohereReader;
    let writer = CohereWriter;
    let resp = reader
        .read_response(&json)
        .expect("read_response should succeed");
    let json2 = writer.write_response(&resp);

    assert_eq!(json, json2);
}

#[test]
fn test_stream_fanout() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // message-start
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_MESSAGE_START, "delta": {"message": {"role": "assistant"}}}),
        &mut state,
    );
    assert_eq!(evs.len(), 1);
    assert!(matches!(
        evs[0],
        crate::ir::IrStreamEvent::MessageStart { .. }
    ));

    // content-start
    let evs = reader.read_response_events("", &serde_json::json!({"type": ET_CONTENT_START, "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}), &mut state);
    assert_eq!(evs.len(), 1);
    assert!(matches!(
        evs[0],
        crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text
        }
    ));

    // content-delta x2
    let evs = reader.read_response_events("", &serde_json::json!({"type": ET_CONTENT_DELTA, "index": 0, "delta": {"message": {"content": "he"}}}), &mut state);
    assert_eq!(evs.len(), 1);
    if let crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta(ref t),
    } = &evs[0]
    {
        assert_eq!(t, "he");
    }

    let evs = reader.read_response_events("", &serde_json::json!({"type": ET_CONTENT_DELTA, "index": 0, "delta": {"message": {"content": "llo"}}}), &mut state);
    assert_eq!(evs.len(), 1);
    if let crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta(ref t),
    } = &evs[0]
    {
        assert_eq!(t, "llo");
    }

    // content-end
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_CONTENT_END, "index": 0}),
        &mut state,
    );
    assert_eq!(evs.len(), 1);
    assert!(matches!(
        evs[0],
        crate::ir::IrStreamEvent::BlockStop { index: 0 }
    ));

    // message-end with usage
    let evs = reader.read_response_events("", &serde_json::json!({"type": ET_MESSAGE_END, "delta": {"finish_reason": COHERE_FINISH_COMPLETE, "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}}}), &mut state);
    assert_eq!(evs.len(), 2);
    if let crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(ref s),
        ref usage,
        ..
    } = &evs[0]
    {
        assert_eq!(*s, crate::ir::IrStopReason::EndTurn);
        assert_eq!(usage.input_tokens, 10);
    }
    assert!(matches!(evs[1], crate::ir::IrStreamEvent::MessageStop));
}

#[test]
fn test_cross_protocol_system_prompt_preserved_to_cohere() {
    // An Anthropic request carries its system prompt in the top-level `system` field, which
    // the reader canonicalizes into IrRequest.system. Cohere's writer must re-emit it as a
    // leading system-role message — otherwise the system prompt is silently dropped when
    // translating Anthropic → Cohere.
    let anthropic_body = serde_json::json!({
        "model": "x",
        "system": "You are terse.",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    });
    let ir = AnthropicReader
        .read_request(&anthropic_body)
        .expect("anthropic read_request");
    assert!(
        !ir.system.is_empty(),
        "anthropic system must land in IrRequest.system"
    );
    let writer = CohereWriter;
    let cohere = writer.write_request(&ir);
    let msgs = cohere.get("messages").unwrap().as_array().unwrap();
    assert_eq!(
        msgs[0].get("role").and_then(|r| r.as_str()),
        Some("system"),
        "Cohere must emit the system prompt as a leading system message"
    );
    assert_eq!(
        msgs[0].get("content").and_then(|c| c.as_str()),
        Some("You are terse.")
    );
    assert_eq!(msgs[1].get("role").and_then(|r| r.as_str()), Some("user"));
}

#[test]
fn test_write_response_event() {
    let writer = CohereWriter;

    // BlockDelta TextDelta("hi") → content-delta frame
    let ev = IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    };
    let result = writer.write_response_event(&ev);
    assert!(result.is_some());
    let (_, data) = result.unwrap();
    assert_eq!(
        data.get("type").and_then(|t| t.as_str()),
        Some("content-delta") // golden wire-contract literal (kept bare on purpose)
    );
    // content-delta carries the text at delta.message.content.text (an object), matching the
    // native Cohere v2 stream and the content-start shape.
    assert_eq!(
        data.get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str()),
        Some("hi")
    );
    assert_eq!(
        data.get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.get("type"))
            .and_then(|t| t.as_str()),
        Some("text")
    );
}

/// Regression: a response carrying several parallel `ToolUse` blocks must surface ALL of them
/// in `tool_calls`. The previous per-iteration `out.insert(...)` overwrote the key and silently
/// dropped every call but the last.
#[test]
fn test_write_response_preserves_parallel_tool_calls() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::ToolUse {
                id: "t1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            },
            crate::ir::IrBlock::ToolUse {
                id: "t2".to_string(),
                name: "get_time".to_string(),
                input: serde_json::json!({"tz": "PST"}),
                cache_control: None,
            },
            crate::ir::IrBlock::ToolUse {
                id: "t3".to_string(),
                name: "get_news".to_string(),
                input: serde_json::json!({}),
                cache_control: None,
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 2,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };

    let writer = CohereWriter;
    let json = writer.write_response(&resp);
    // tool_calls are nested under the `message` object (native Cohere v2 shape).
    let tool_calls = json
        .get("message")
        .and_then(|m| m.get("tool_calls"))
        .and_then(|v| v.as_array())
        .expect("tool_calls array must be present under message");
    assert_eq!(tool_calls.len(), 3, "all parallel tool calls must survive");
    let ids: Vec<&str> = tool_calls
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(ids, ["t1", "t2", "t3"]);
}

/// Regression: an assistant message whose only block is a `ToolUse` (surfaced via `tool_calls`)
/// must NOT emit `content: []`. The `content` key should be omitted entirely.
#[test]
fn test_write_request_sole_tooluse_omits_empty_content() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "t1".to_string(),
                name: "f".to_string(),
                input: serde_json::json!({"x": 1}),
                cache_control: None,
            }],
        }],
        tools: vec![],
        max_tokens: Some(64),
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

    let writer = CohereWriter;
    let json = writer.write_request(&ir);
    let msgs = json.get("messages").unwrap().as_array().unwrap();
    let assistant = &msgs[0];
    assert!(
        assistant.get("content").is_none(),
        "sole-ToolUse message must omit content rather than emit []"
    );
    assert!(
        assistant.get("tool_calls").is_some(),
        "the tool call must still be present"
    );
}

/// Multiple text blocks in one message must serialize as a text-part array (not be collapsed),
/// while a single text block stays a bare string.
#[test]
fn test_write_request_text_block_shapes() {
    let single = crate::ir::IrRequest {
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
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let writer = CohereWriter;
    let j = writer.write_request(&single);
    assert_eq!(
        j.get("messages").unwrap().as_array().unwrap()[0].get("content"),
        Some(&serde_json::json!("hi"))
    );

    let multi = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "a".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Text {
                    text: "b".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
            ],
        }],
        ..single
    };
    let j = writer.write_request(&multi);
    let content = j.get("messages").unwrap().as_array().unwrap()[0]
        .get("content")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(content.len(), 2);
    assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("a"));
    assert_eq!(content[1].get("text").and_then(|t| t.as_str()), Some("b"));
}

/// `read_request` must not allocate a temporary empty Vec when `tools` is absent, and must
/// produce no tools either way.
#[test]
fn test_read_request_missing_tools() {
    let json = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = CohereReader
        .read_request(&json)
        .expect("read_request should succeed");
    assert!(ir.tools.is_empty());
}

/// The NATIVE Cohere v2 error envelope is a bare `{"message": <detail>}` — NOT the generic
/// `{"error":{"message","type"}}`, and NOT carrying a synthesized `id`. The generic `kind` must
/// NOT leak into the body (a native SDK never reads a typed error category from a Cohere body;
/// it reads `message`), and no `id` field must be emitted (real Cohere error bodies carry none,
/// and this reader's `extract_error` never reads `id`).
#[test]
fn test_write_error_native_cohere_envelope() {
    let writer = CohereWriter;
    let v = writer.write_error(404, "not_found", "model 'x' not found");

    // Serializes (no panic) and re-parses as valid JSON.
    let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
    let reparsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

    assert_eq!(
        reparsed.get("message").and_then(|m| m.as_str()),
        Some("model 'x' not found"),
        "native Cohere error carries the detail under top-level `message`"
    );
    assert!(
        reparsed.get("error").is_none(),
        "must NOT use the generic `error` wrapper"
    );
    assert!(
        reparsed.get("type").is_none() && reparsed.get("code").is_none(),
        "Cohere conveys the error category via HTTP status, not a typed body field"
    );
    assert!(
        reparsed.get("id").is_none(),
        "real Cohere error bodies carry no synthesized id"
    );
    // The body must be exactly the single `message` key.
    assert_eq!(
        reparsed.as_object().map(|o| o.len()),
        Some(1),
        "native Cohere error body is a bare {{\"message\": ...}}"
    );
}

/// Same-protocol (Cohere → Cohere) passthrough must preserve the upstream response `id` exactly
/// — capturing it on read and re-emitting the identical value on write.
#[test]
fn test_same_protocol_roundtrip_preserves_id() {
    let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
    let json = serde_json::json!({
        "id": upstream_id,
        "finish_reason": COHERE_FINISH_COMPLETE,
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
        "usage": {"tokens": {"input_tokens": 3, "output_tokens": 1}}
    });

    let resp = CohereReader
        .read_response(&json)
        .expect("read_response should succeed");
    assert_eq!(
        resp.id.as_deref(),
        Some(upstream_id),
        "upstream id captured verbatim into the IR"
    );

    let writer = CohereWriter;
    let out = writer.write_response(&resp);
    assert_eq!(
        out.get("id").and_then(|i| i.as_str()),
        Some(upstream_id),
        "the same id must be re-emitted on write (same-protocol fidelity)"
    );
}

/// Same-protocol stream passthrough preserves the message-start `id`.
#[test]
fn test_same_protocol_stream_roundtrip_preserves_id() {
    let upstream_id = "c14c80c3-18eb-4519-9460-6c92edd8cfb4";
    let mut state = crate::ir::StreamDecodeState::default();
    let evs = CohereReader.read_response_events(
        "",
        &serde_json::json!({
            "id": upstream_id,
            "type": ET_MESSAGE_START,
            "delta": {"message": {"role": "assistant"}}
        }),
        &mut state,
    );
    assert_eq!(evs.len(), 1);
    let captured = match &evs[0] {
        crate::ir::IrStreamEvent::MessageStart { id, .. } => id.clone(),
        other => panic!("expected MessageStart, got {other:?}"),
    };
    assert_eq!(captured.as_deref(), Some(upstream_id));

    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&evs[0])
        .expect("message-start must serialize");
    assert_eq!(
        frame.get("id").and_then(|i| i.as_str()),
        Some(upstream_id),
        "stream message-start id must round-trip verbatim"
    );
}

/// Cross-protocol write (the backend supplied NO id — `IrResponse.id == None`) must SYNTHESIZE a
/// valid, non-empty Cohere id without panicking, so a native Cohere SDK still reads a string.
#[test]
fn test_cross_protocol_write_synthesizes_valid_id() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hello".to_string(),
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

    let writer = CohereWriter;
    let out = writer.write_response(&resp);
    let id = out
        .get("id")
        .and_then(|i| i.as_str())
        .expect("synthesized id must be present as a string");
    assert!(!id.is_empty(), "synthesized id must be non-empty");
    assert!(
        is_uuid_shaped(id),
        "synthesized id must be a bare UUID (no `cohere-` prefix), got {id}"
    );
}

/// Test helper: validate the 8-4-4-4-12 lowercase-hex UUID layout that native Cohere ids use.
fn is_uuid_shaped(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    let expected_lens = [8usize, 4, 4, 4, 12];
    groups.len() == 5
        && groups.iter().zip(expected_lens.iter()).all(|(g, &len)| {
            g.len() == len
                && g.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

/// Test helper: validate that a UUID string is a proper RFC-4122 UUIDv4 — version nibble `4`
/// (first char of the 3rd group) and variant nibble in `{8,9,a,b}` (`10xx`, first char of the
/// 4th group). Real Cohere ids are v4, so a synthesized id must satisfy this.
fn is_uuid_v4(s: &str) -> bool {
    if !is_uuid_shaped(s) {
        return false;
    }
    let groups: Vec<&str> = s.split('-').collect();
    let version_ok = groups[2].starts_with('4');
    let variant_ok = matches!(
        groups[3].bytes().next(),
        Some(b'8') | Some(b'9') | Some(b'a') | Some(b'b')
    );
    version_ok && variant_ok
}

/// Regression (MEDIUM/conformance): the synthesized id must be a bare UUID (8-4-4-4-12 hex),
/// indistinguishable from a native Cohere id — NOT a `cohere-<secs>-<counter>` token, which a
/// client comparing against the documented UUID shape could use as a proxy tell.
#[test]
fn test_synthesized_id_is_uuid_shaped() {
    let id = synthesize_cohere_id();
    assert!(
        is_uuid_shaped(&id),
        "synthesized id must match the UUID layout, got {id}"
    );
    assert!(
        !id.starts_with("cohere-"),
        "synthesized id must NOT carry a literal prefix, got {id}"
    );
}

/// Regression (HIGH/conformance): the synthesized id must be a PROPER RFC-4122 UUIDv4 — version
/// nibble `4` and variant bits `10xx` — because real Cohere ids are v4. The previous
/// `secs << 32 ^ counter` layout almost never landed `4` in the version position and left the
/// variant unconstrained, so a client validating the id as a UUIDv4 saw an invalid value (a
/// deterministic proxy tell). Sample many ids: the stamping is deterministic, so EVERY one must
/// pass regardless of the random/counter bits underneath.
#[test]
fn test_synthesized_id_is_valid_uuid_v4() {
    for _ in 0..1000 {
        let id = synthesize_cohere_id();
        assert!(
            is_uuid_v4(&id),
            "synthesized id must be a valid RFC-4122 UUIDv4 (version nibble 4, variant 10xx), \
                 got {id}"
        );
    }
}

/// Regression (HIGH/security): the synthesized id must NOT embed the server clock. The previous
/// layout placed `secs << 32` in the high 32 bits, so the first UUID group leaked the unix
/// second. Mint two ids and assert their first groups differ from a unix-second-derived value —
/// more robustly, assert the first group is not equal to the current/last-second seconds in hex
/// (the old code produced exactly that). With CSPRNG seeding the first group is random.
#[test]
fn test_synthesized_id_does_not_leak_timestamp() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The old leaky layout put `(secs as u32)` straight into the first 8 hex chars.
    let leaked_prefix = format!("{:08x}", secs as u32);
    // Sample several: a single random collision is astronomically unlikely, but sampling makes
    // the intent (no deterministic clock prefix) unambiguous.
    let mut matched = 0u32;
    for _ in 0..256 {
        let id = synthesize_cohere_id();
        let first_group = id.split('-').next().unwrap_or("");
        if first_group == leaked_prefix {
            matched += 1;
        }
    }
    assert_eq!(
        matched, 0,
        "first UUID group must not deterministically equal the unix-second hex {leaked_prefix} \
             (server-clock leak)"
    );
}

/// Synthesized ids are unique across a burst by virtue of CSPRNG entropy alone — `synthesize_
/// cohere_id` is a PURE RFC-4122 UUIDv4 (122 random bits, ~5.3e36 values) with NO monotonic
/// counter overlay (a counter folded into any fixed region would be a low-entropy structural
/// tell a native random v4 never carries — see the fn doc-comment). This test therefore asserts
/// what the code actually guarantees: a burst of ids are all distinct AND every one is a
/// well-formed UUIDv4. It does NOT assert a counter backstop, because none exists by design.
#[test]
fn test_synthesized_ids_are_unique() {
    const N: usize = 4096;
    let mut seen = std::collections::HashSet::with_capacity(N);
    for _ in 0..N {
        let id = synthesize_cohere_id();
        assert!(
            is_uuid_v4(&id),
            "each synthesized id must be a well-formed UUIDv4, got {id}"
        );
        assert!(
            seen.insert(id.clone()),
            "CSPRNG-seeded synthesized ids must be unique across a burst; collision on {id}"
        );
    }
}

/// A well-formed credential produces a single `Authorization: Bearer <key>` header.
#[test]
fn test_auth_headers_valid_key_emits_bearer() {
    let headers = crate::proto::bearer_auth_headers("cohere", "valid-key-123");
    assert_eq!(headers.len(), 1, "exactly one auth header");
    assert_eq!(headers[0].0.as_str(), "authorization");
    assert_eq!(
        headers[0].1.to_str().expect("valid header bytes"),
        "Bearer valid-key-123"
    );
}

/// Regression (MEDIUM/security): a credential carrying bytes `HeaderValue::from_str` rejects
/// (e.g. a newline injected by a config system) must OMIT the header entirely — NOT emit an
/// empty `Authorization: ` value. The empty-Bearer form silently 401s the lane with no operator
/// signal and is a backend-detectable tell. Mirrors
/// `gemini.rs::test_auth_headers_invalid_key_omits_header_no_empty_value`.
#[test]
fn test_auth_headers_invalid_key_omits_header_no_empty_value() {
    let headers = crate::proto::bearer_auth_headers("cohere", "bad\nkey");
    assert!(
        headers.is_empty(),
        "an invalid credential must omit the auth header entirely, got {headers:?}"
    );
}

/// A NUL control byte in the credential is also rejected and the header omitted (not emitted as
/// an empty value).
#[test]
fn test_auth_headers_control_byte_key_omits_header() {
    let headers = crate::proto::bearer_auth_headers("cohere", "key\u{0000}bad");
    assert!(
        headers.is_empty(),
        "a control-byte credential must omit the auth header entirely, got {headers:?}"
    );
}

/// Regression (MEDIUM/conformance): a Cohere->Cohere passthrough where the upstream returned
/// `ERROR_TOXIC` (content-moderation stop) must NOT be downgraded to `ERROR` (infrastructure
/// failure). The reader normalises `ERROR_TOXIC` to IR `safety`; the writer must map `safety`
/// back to `ERROR_TOXIC` so the moderation signal round-trips. Covers both the non-streaming
/// `write_response` and the streaming `message-end` paths.
#[test]
fn test_safety_finish_reason_writes_error_toxic_non_stream() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "moderated".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("r1".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let writer = CohereWriter;
    let body = writer.write_response(&resp);
    assert_eq!(
        body.get("finish_reason").and_then(|v| v.as_str()),
        Some("ERROR_TOXIC"), // golden wire-contract literal (kept bare on purpose)
        "IR safety must write back as the native content-moderation stop ERROR_TOXIC"
    );

    // Round-trips: ERROR_TOXIC reads back to IR safety (the reader normalises only ERROR_TOXIC
    // to safety; the generic ERROR is NOT a moderation signal — see the ERROR round-trip test).
    let back = CohereReader
        .read_response(&body)
        .expect("read self-written body");
    assert_eq!(back.stop_reason, Some(crate::ir::IrStopReason::Safety));
}

#[test]
fn test_safety_finish_reason_writes_error_toxic_stream() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("message-end must serialize");
    assert_eq!(
        frame
            .get("delta")
            .and_then(|d| d.get("finish_reason"))
            .and_then(|v| v.as_str()),
        Some("ERROR_TOXIC"), // golden wire-contract literal (kept bare on purpose)
        "streamed safety stop must emit ERROR_TOXIC, not ERROR"
    );
}

/// Regression (MED #8): the readers must NOT fold the generic `ERROR` finish_reason into the
/// content-moderation `safety` bucket. Only `ERROR_TOXIC` is the moderation signal; a generic
/// `ERROR` (infrastructure failure) must fall through to the lowercase passthrough (-> IR
/// `error`), and round-trip back to the native `ERROR` via the writer's `to_uppercase` arm.
/// Before the fix BOTH `ERROR` and `ERROR_TOXIC` mapped to `safety`, so a Cohere->Cohere
/// passthrough silently rewrote a server error as a fabricated content-moderation stop. Covers
/// both readers (streaming `message-end` and non-streaming `read_response`) and both write-back
/// paths.
#[test]
fn test_generic_error_does_not_fold_into_safety_and_round_trips() {
    let reader = CohereReader;

    // --- Non-streaming reader (read_response) ---
    // ERROR must read back as IR `error`, NOT `safety`.
    let err_body = serde_json::json!({
        "finish_reason": COHERE_FINISH_ERROR,
        "message": { "content": [] },
        "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
    });
    let err_ir = reader.read_response(&err_body).expect("read ERROR body");
    assert_eq!(
        err_ir.stop_reason,
        Some(crate::ir::IrStopReason::Error),
        "generic ERROR must read back as IR `error`, not `safety`"
    );
    // ERROR_TOXIC still reads back as `safety`.
    let toxic_body = serde_json::json!({
        "finish_reason": COHERE_FINISH_ERROR_TOXIC,
        "message": { "content": [] },
        "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
    });
    let toxic_ir = reader
        .read_response(&toxic_body)
        .expect("read ERROR_TOXIC body");
    assert_eq!(
        toxic_ir.stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "ERROR_TOXIC must still read back as IR `safety`"
    );

    // Write-back round-trips: IR `error` -> native `ERROR`; IR `safety` -> native `ERROR_TOXIC`.
    let writer = CohereWriter;
    let err_resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: Vec::new(),
        stop_reason: Some(crate::ir::IrStopReason::Error),
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("e1".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let err_out = writer.write_response(&err_resp);
    assert_eq!(
        err_out.get("finish_reason").and_then(|v| v.as_str()),
        Some("ERROR"), // golden wire-contract literal (kept bare on purpose)
        "IR `error` must write back as the native generic `ERROR`, not `ERROR_TOXIC`"
    );

    // --- Streaming reader (message-end) ---
    let mut state = crate::ir::StreamDecodeState::default();
    let err_frame = serde_json::json!({
        "type": ET_MESSAGE_END,
        "delta": { "finish_reason": COHERE_FINISH_ERROR, "usage": { "tokens": {} } }
    });
    let evs = reader.read_response_events("", &err_frame, &mut state);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::MessageDelta { stop_reason, .. }
                if stop_reason == &Some(crate::ir::IrStopReason::Error)
        )),
        "streamed generic ERROR must decode to IR `error`, not `safety`, got {evs:?}"
    );
    let mut state2 = crate::ir::StreamDecodeState::default();
    let toxic_frame = serde_json::json!({
        "type": ET_MESSAGE_END,
        "delta": { "finish_reason": COHERE_FINISH_ERROR_TOXIC, "usage": { "tokens": {} } }
    });
    let toxic_evs = reader.read_response_events("", &toxic_frame, &mut state2);
    assert!(
        toxic_evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::MessageDelta { stop_reason, .. }
                if stop_reason == &Some(crate::ir::IrStopReason::Safety)
        )),
        "streamed ERROR_TOXIC must still decode to IR `safety`, got {toxic_evs:?}"
    );
}

/// Regression (MED #9): an upstream-controlled stream tool-call frame `index` of `usize::MAX`
/// (or any huge value) must NOT collide with `TEXT_BLOCK_SEEN_SENTINEL` (== `usize::MAX`) and
/// corrupt tool tracking. Every read site clamps the wire index to `MAX_TOOL_FRAME_INDEX`, well
/// below the sentinel, so a tool block still opens at a real IR index and the sentinel's
/// text-high-water meaning is preserved. Before the fix, a `usize::MAX` frame_idx was inserted
/// into `open_tools`, became indistinguishable from the sentinel, and broke `cohere_lookup_tool_ir_index`.
#[test]
fn test_huge_tool_frame_index_clamped_below_sentinel() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // A tool-call-start whose wire index is usize::MAX (the sentinel value).
    let huge = u64::MAX;
    let start = serde_json::json!({
        "type": ET_TOOL_CALL_START,
        "index": huge,
        "delta": { "message": { "tool_calls": {
            "id": "call_huge",
            "type": "function",
            "function": { "name": "f", "arguments": "{}" }
        }}}
    });
    let evs = reader.read_response_events("", &start, &mut state);

    // The clamp must keep the recorded frame index strictly below the sentinel so it is never
    // confused with the text-high-water marker.
    assert!(
        !state.open_tools.contains(&TEXT_BLOCK_SEEN_SENTINEL),
        "a huge wire index must never be recorded as the sentinel value"
    );
    assert!(
        state
            .open_tools
            .iter()
            .filter(|&&e| e != TEXT_BLOCK_SEEN_SENTINEL)
            .all(|&e| tool_entry_frame(e) <= MAX_TOOL_FRAME_INDEX as usize),
        "every recorded tool frame index must be clamped to MAX_TOOL_FRAME_INDEX, got {:?}",
        state.open_tools
    );

    // The clamped frame still opens exactly one tool BlockStart (no corruption / no drop).
    let starts = evs
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
        .count();
    assert_eq!(
        starts, 1,
        "a clamped huge-index tool-call-start must open exactly one block, got {evs:?}"
    );

    // The whole tool lifecycle (delta + end at the same huge index) resolves to the SAME IR
    // index and closes cleanly — proving the clamp is applied consistently at all three sites.
    let delta = serde_json::json!({
        "type": ET_TOOL_CALL_DELTA,
        "index": huge,
        "delta": { "message": { "tool_calls": {
            "function": { "arguments": "more" }
        }}}
    });
    let delta_evs = reader.read_response_events("", &delta, &mut state);
    assert_eq!(
        delta_evs
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockDelta { .. }))
            .count(),
        1,
        "a clamped tool-call-delta must forward to the open block, got {delta_evs:?}"
    );
    let end = serde_json::json!({ "type": ET_TOOL_CALL_END, "index": huge });
    let end_evs = reader.read_response_events("", &end, &mut state);
    assert_eq!(
        end_evs
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
            .count(),
        1,
        "a clamped tool-call-end must close the open block, got {end_evs:?}"
    );
}

/// Regression (MEDIUM/correctness): a mid-stream `IrStreamEvent::Error` on a Cohere-ingress
/// stream must terminate with the NATIVE Cohere v2 error shape — a `message-end` frame whose
/// `finish_reason` is `ERROR` — NOT a non-native `type: "error"` out-of-band frame (which a
/// strict Cohere SDK ignores or rejects, silently dropping the error, and which is a
/// protocol-indistinguishability tell). A content-moderation signal maps to `ERROR_TOXIC`; any
/// other signal maps to the generic `ERROR`. The emitted frame must round-trip through this
/// protocol's OWN reader back to the IR `safety` stop reason.
#[test]
fn test_stream_error_emits_native_message_end_not_error_event() {
    let writer = CohereWriter;

    // Generic infrastructure error -> ERROR.
    let infra = IrStreamEvent::Error(crate::proto::IrError {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: Some("internal_server_error".to_string()),
        retry_after: None,
    });
    let (event_type, frame) = writer
        .write_response_event(&infra)
        .expect("Error must serialize to a native frame");
    // The SSE `event:` field is empty for Cohere v2 (the type lives in the JSON `type` key).
    assert_eq!(event_type, "");
    assert_eq!(
        frame.get("type").and_then(|v| v.as_str()),
        Some("message-end"), // golden wire-contract literal (kept bare on purpose)
        "Cohere v2 has no `type: error` event; a mid-stream error terminates with message-end"
    );
    assert_ne!(
        frame.get("type").and_then(|v| v.as_str()),
        Some("error"),
        "the non-native `type: error` frame must not be emitted"
    );
    // The native message-end frame carries ONLY `type` + `delta`; a top-level `message` field
    // is a proxy fingerprint a genuine Cohere v2 stream never emits. Assert its absence
    // explicitly.
    assert!(
        frame.get("message").is_none(),
        "error message-end must not carry a top-level `message` field (proxy fingerprint), \
             got {frame:?}"
    );
    assert_eq!(
        frame.get("delta").and_then(|d| d.as_object()).map(|d| {
            let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
            keys.sort_unstable();
            keys
        }),
        Some(vec!["finish_reason", "usage"]),
        "error message-end `delta` must carry exactly `finish_reason` and `usage`, \
             mirroring the native MessageDelta shape"
    );
    // Native message-end always includes delta.usage.tokens.{input_tokens,output_tokens}; the
    // error frame must too (an absent usage is itself a fingerprint).
    let err_tokens = frame
        .get("delta")
        .and_then(|d| d.get("usage"))
        .and_then(|u| u.get("tokens"))
        .expect("error message-end must carry delta.usage.tokens");
    assert_eq!(
        err_tokens.get("input_tokens").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        err_tokens.get("output_tokens").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        frame
            .get("delta")
            .and_then(|d| d.get("finish_reason"))
            .and_then(|v| v.as_str()),
        Some("ERROR"), // golden wire-contract literal (kept bare on purpose)
        "an infrastructure error maps to the native ERROR finish_reason"
    );
    // Round-trips through the reader back to IR `error` (the generic infra-failure passthrough).
    // The reader maps ONLY `ERROR_TOXIC` to `safety`; a generic `ERROR` must NOT be folded into
    // the moderation bucket (MED #8) — it falls through to the lowercase passthrough -> `error`.
    let mut state = crate::ir::StreamDecodeState::default();
    let decoded = CohereReader.read_response_events("", &frame, &mut state);
    assert!(
        decoded.iter().any(|e| matches!(
            e,
            IrStreamEvent::MessageDelta { stop_reason, .. }
                if stop_reason == &Some(crate::ir::IrStopReason::Error)
        )),
        "emitted message-end must decode back to a generic `error` stop, got {decoded:?}"
    );

    // Content-moderation signal -> ERROR_TOXIC.
    let toxic = IrStreamEvent::Error(crate::proto::IrError {
        class: crate::breaker::StatusClass::ClientError,
        provider_signal: Some("content_filter_safety".to_string()),
        retry_after: None,
    });
    let (_, toxic_frame) = writer
        .write_response_event(&toxic)
        .expect("Error must serialize");
    assert_eq!(
        toxic_frame
            .get("delta")
            .and_then(|d| d.get("finish_reason"))
            .and_then(|v| v.as_str()),
        Some("ERROR_TOXIC"), // golden wire-contract literal (kept bare on purpose)
        "a content-moderation signal maps to the native ERROR_TOXIC finish_reason"
    );
    assert!(
        toxic_frame.get("message").is_none(),
        "toxic error message-end must not carry a top-level `message` field"
    );

    // An absent provider_signal still produces a native ERROR termination (never `type: error`).
    let bare = IrStreamEvent::Error(crate::proto::IrError {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: None,
        retry_after: None,
    });
    let (_, bare_frame) = writer
        .write_response_event(&bare)
        .expect("Error must serialize");
    assert_eq!(
        bare_frame.get("type").and_then(|v| v.as_str()),
        Some("message-end") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        bare_frame
            .get("delta")
            .and_then(|d| d.get("finish_reason"))
            .and_then(|v| v.as_str()),
        Some("ERROR") // golden wire-contract literal (kept bare on purpose)
    );
    assert!(
        bare_frame.get("message").is_none(),
        "bare error message-end must not carry a top-level `message` field"
    );
}

/// Regression (MEDIUM/correctness): `read_response` must tolerate a missing `usage` object,
/// falling back to zero counts rather than hard-erroring with a `ClientError`. A
/// Cohere-compatible backend (mock/staging/proxy) that omits `usage` is an upstream
/// response-format quirk, not a caller mistake; Bedrock and Gemini both handle this leniently.
#[test]
fn test_read_response_missing_usage_defaults_to_zero() {
    let json = serde_json::json!({
        "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
        "finish_reason": COHERE_FINISH_COMPLETE,
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}]
        }
        // NOTE: no `usage` key at all.
    });
    let resp = CohereReader
        .read_response(&json)
        .expect("missing usage must not hard-error (zero-usage fallback)");
    assert_eq!(resp.usage.input_tokens, 0);
    assert_eq!(resp.usage.output_tokens, 0);
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::EndTurn));

    // A present-but-empty usage object (no `tokens`) is also tolerated.
    let json_empty_usage = serde_json::json!({
        "finish_reason": COHERE_FINISH_COMPLETE,
        "message": { "role": "assistant", "content": [{"type": "text", "text": "hi"}] },
        "usage": {}
    });
    let resp2 = CohereReader
        .read_response(&json_empty_usage)
        .expect("empty usage object must not hard-error");
    assert_eq!(resp2.usage.input_tokens, 0);
    assert_eq!(resp2.usage.output_tokens, 0);
}

/// Regression (HIGH/conformance): `write_response` must nest `tool_calls` INSIDE the `message`
/// object (native Cohere v2 shape, `response.message.tool_calls`) — not at the top level. The
/// emitted body must round-trip through this protocol's OWN `read_response`, which reads tool
/// calls from `message.tool_calls`, so a Cohere -> Cohere passthrough keeps every parallel call.
#[test]
fn test_write_response_tool_calls_nested_and_roundtrip() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Text {
                text: "calling tools".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
            crate::ir::IrBlock::ToolUse {
                id: "t1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            },
            crate::ir::IrBlock::ToolUse {
                id: "t2".to_string(),
                name: "get_time".to_string(),
                input: serde_json::json!({"tz": "PST"}),
                cache_control: None,
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: crate::ir::IrUsage {
            input_tokens: 4,
            output_tokens: 6,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("resp-1".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };

    let writer = CohereWriter;
    let body = writer.write_response(&resp);

    // tool_calls live under message, NOT at the top level.
    assert!(
        body.get("tool_calls").is_none(),
        "tool_calls must NOT be at the top level"
    );
    let nested = body
        .get("message")
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
        .expect("tool_calls must be nested under message");
    assert_eq!(nested.len(), 2, "both parallel tool calls survive");

    // Round-trips through this protocol's own reader: every tool call comes back.
    let back = CohereReader
        .read_response(&body)
        .expect("read_response of self-written body");
    let tool_uses: Vec<(&str, &str)> = back
        .content
        .iter()
        .filter_map(|b| {
            if let crate::ir::IrBlock::ToolUse { id, name, .. } = b {
                Some((id.as_str(), name.as_str()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        tool_uses,
        [("t1", "get_weather"), ("t2", "get_time")],
        "Cohere -> Cohere tool-call passthrough must preserve every call"
    );
    assert_eq!(back.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
}

/// Regression (MEDIUM/conformance): the streaming `content-delta` frame must carry text at
/// `delta.message.content.text` (an object), matching `content-start` and the native Cohere v2
/// stream — not a bare string. A native SDK reads `content.text`.
#[test]
fn test_write_response_event_content_delta_is_object() {
    let ev = IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("chunk".to_string()),
    };
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("content-delta must serialize");
    let content = frame
        .get("delta")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.get("content"))
        .expect("content present");
    assert!(
        content.is_object(),
        "content-delta content must be an object, got {content}"
    );
    assert_eq!(content.get("type").and_then(|t| t.as_str()), Some("text"));
    assert_eq!(content.get("text").and_then(|t| t.as_str()), Some("chunk"));
}

/// Regression (HIGH/correctness): the content-delta WRITER emits `delta.message.content` as a
/// `{type:text, text:…}` object (the native Cohere v2 shape), so the READER must decode that
/// exact object back to a TextDelta. Before the object branch was added, the reader handled only
/// the bare-string and array forms, so the writer's own frame round-tripped to ZERO events —
/// streamed assistant text was silently dropped on the Cohere read/proxy path. Lock the
/// writer→reader symmetry.
#[test]
fn test_content_delta_writer_reader_roundtrip_object_shape() {
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        })
        .expect("content-delta must serialize");
    // Sanity: the writer really emitted the object shape this test guards.
    assert!(
        frame
            .pointer("/delta/message/content")
            .is_some_and(|c| c.is_object()),
        "writer must emit object-shaped content: {frame}"
    );
    // Feed the writer's own frame back through the reader.
    let mut state = crate::ir::StreamDecodeState::default();
    let evs = CohereReader.read_response_events("", &frame, &mut state);
    let decoded_text: Option<String> = evs.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            delta: crate::ir::IrDelta::TextDelta(t),
            ..
        } => Some(t.clone()),
        _ => None,
    });
    assert_eq!(
        decoded_text.as_deref(),
        Some("hi"),
        "object-shaped content-delta must round-trip to the original text, got events: {evs:?}"
    );
}

/// REAL Cohere v2 content-delta carries `delta.message.content = {"text": …}` with NO `type`
/// field (only content-start has one) — captured shape, pinned by the acceptance harness's
/// native-stream mock. The reader must decode it; requiring `type == "text"` silently dropped
/// every streamed chunk from a real Cohere backend.
#[test]
fn test_content_delta_real_cohere_shape_no_type_field() {
    let frame: serde_json::Value = serde_json::from_str(
        r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"hi"}}}}"#,
    )
    .unwrap();
    let mut state = crate::ir::StreamDecodeState::default();
    let evs = CohereReader.read_response_events("", &frame, &mut state);
    let decoded: Option<String> = evs.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            delta: crate::ir::IrDelta::TextDelta(t),
            ..
        } => Some(t.clone()),
        _ => None,
    });
    assert_eq!(
        decoded.as_deref(),
        Some("hi"),
        "the real (type-less) content-delta shape must decode, got events: {evs:?}"
    );
}

/// Regression (LOW/correctness): a streaming tool call (tool-call-start / tool-call-delta /
/// tool-call-end) must NOT be swallowed by a catch-all — it maps onto the IR block lifecycle.
#[test]
fn test_stream_tool_call_events_mapped() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // start
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {
                "id": "call_1",
                "type": "function",
                "function": {"name": "get_weather", "arguments": ""}
            }}}
        }),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "tool-call-start must emit a BlockStart");
    match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::ToolUse { id, name },
        } => {
            assert_eq!(*index, 0);
            assert_eq!(id, "call_1");
            assert_eq!(name, "get_weather");
        }
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    }

    // delta (streamed arguments)
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_DELTA,
            "index": 0,
            "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"city\":"}}}}
        }),
        &mut state,
    );
    assert_eq!(evs.len(), 1);
    match &evs[0] {
        crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta(args),
        } => assert_eq!(args, "{\"city\":"),
        other => panic!("expected InputJsonDelta, got {other:?}"),
    }

    // end
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_CALL_END, "index": 0}),
        &mut state,
    );
    assert_eq!(evs.len(), 1);
    assert!(matches!(
        evs[0],
        crate::ir::IrStreamEvent::BlockStop { index: 0 }
    ));
    // tool-call-end emits the BlockStop but intentionally does NOT remove the frame's entry
    // from `open_tools`: the recorded packed entry is what keeps each tool's ASSIGNED IR index
    // stable for its lifetime (and the insertion slot of any LATER tool stable), so the set
    // grows monotonically across the stream.
    assert_eq!(
        cohere_lookup_tool_ir_index(&state, 0),
        Some(0),
        "the closed tool's assigned IR index is retained to keep later tool indices stable"
    );
}

/// Regression (LOW #12 + #13): a `tool-call-start` that arrives BEFORE any text content frame
/// must NOT collide with the text block on IR index 0. Before the fix the text block was
/// hardcoded to IR index 0, so a tool that opened first (and legitimately claimed 0 via
/// `cohere_assign_tool_ir_index` when no text had been seen) and the later text block BOTH
/// emitted a `BlockStart` at index 0 — two open frames at the same index, which a downstream
/// ingress writer mis-correlates. The text block now claims a DYNAMIC index by order of first
/// appearance (`state.text_index`, mirroring the Gemini reader): the tool keeps index 0 and the
/// text block takes index 1. Asserts the tool gets 0, text gets 1, the indices never overlap, and
/// the text block closes at the index it actually opened (1, not a hardcoded 0).
#[test]
fn test_stream_tool_before_text_no_index_collision() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // Tool opens FIRST — claims IR index 0 (no text seen yet).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": ""}
            }}}
        }),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "tool-call-start emits one BlockStart");
    match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::ToolUse { id, name },
        } => {
            assert_eq!(*index, 0, "the first-arriving tool claims IR index 0");
            assert_eq!(id, "call_1");
            assert_eq!(name, "lookup");
        }
        other => panic!("expected tool BlockStart, got {other:?}"),
    }

    // Text content opens AFTER the tool — must take the NEXT free index (1), not collide on 0.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_CONTENT_START, "index": 0}),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "content-start emits one text BlockStart");
    let text_idx = match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::Text,
        } => *index,
        other => panic!("expected text BlockStart, got {other:?}"),
    };
    assert_eq!(
        text_idx, 1,
        "the text block must claim index 1 (off the tool-claimed 0), not collide on 0"
    );
    assert_ne!(
        text_idx, 0,
        "text must never reuse the tool-claimed IR index 0"
    );

    // A text delta rides the SAME dynamic index, not a hardcoded 0.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_CONTENT_DELTA,
            "index": 0,
            "delta": {"message": {"content": {"type": "text", "text": "hi"}}}
        }),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "content-delta emits one text delta");
    match &evs[0] {
        crate::ir::IrStreamEvent::BlockDelta {
            index,
            delta: crate::ir::IrDelta::TextDelta(t),
        } => {
            assert_eq!(*index, 1, "the text delta rides the assigned index 1");
            assert_eq!(t, "hi");
        }
        other => panic!("expected text BlockDelta, got {other:?}"),
    }

    // content-end closes the text block at the index it actually opened (1), not 0.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_CONTENT_END, "index": 0}),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "content-end emits one BlockStop");
    assert!(
        matches!(evs[0], crate::ir::IrStreamEvent::BlockStop { index: 1 }),
        "the text block closes at its assigned index 1, not a hardcoded 0; got {:?}",
        evs[0]
    );

    // The tool's index 0 is still independently resolvable — no overlap occurred.
    assert_eq!(
        cohere_lookup_tool_ir_index(&state, 0),
        Some(0),
        "the tool retains its distinct IR index 0"
    );

    // And the canonical text-before-tool ordering still keeps text at 0 / tool at 1 on a fresh
    // stream (the fix must not regress the common case). A text block still OPEN when the tool
    // arrives (no intervening content-end — the tool-plan shape) is closed FIRST with a BlockStop at
    // its index 0, then the tool opens at index 1, so the emitted stream stays balanced.
    let mut state2 = crate::ir::StreamDecodeState::default();
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_CONTENT_START, "index": 0}),
        &mut state2,
    );
    assert!(matches!(
        evs[0],
        crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text
        }
    ));
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {
                "id": "c2", "type": "function",
                "function": {"name": "f", "arguments": ""}
            }}}
        }),
        &mut state2,
    );
    assert!(
        matches!(&evs[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
        "the still-open text block must close at index 0 before the tool opens, got {evs:?}"
    );
    match &evs[1] {
        crate::ir::IrStreamEvent::BlockStart { index, .. } => assert_eq!(
            *index, 1,
            "text-before-tool: text keeps 0, tool takes 1 (no regression)"
        ),
        other => panic!("expected tool BlockStart, got {other:?}"),
    }
}

/// Regression (1.4.0 audit, translation): once the leading tool-plan text block is CLOSED by the
/// first `tool-call-start`, an out-of-spec upstream that resumes text (another `tool-plan-delta` or a
/// `content-delta`) must NOT reopen it. Reopening would emit a second `content_block_start`/delta at
/// the already-stopped index — an unbalanced stream on an Anthropic egress. The `text_block_closed`
/// latch drops the stray frames instead.
#[test]
fn test_stream_text_not_reopened_after_close() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Leading tool-plan opens a text block at index 0 (BlockStart + BlockDelta).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_PLAN_DELTA,
            "delta": {"message": {"tool_plan": "think"}}
        }),
        &mut state,
    );
    assert!(
        matches!(
            evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ),
        "tool-plan opens the leading text block at index 0, got {evs:?}"
    );

    // tool-call-start closes the still-open text block (BlockStop{0}) and opens the tool at index 1.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {
                "id": "c1", "type": "function",
                "function": {"name": "f", "arguments": ""}
            }}}
        }),
        &mut state,
    );
    assert!(
        matches!(&evs[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
        "tool-call-start closes the plan text block at index 0, got {evs:?}"
    );

    // A resumed tool-plan-delta AFTER the close is dropped — no reopen, no delta into a stopped index.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_PLAN_DELTA,
            "delta": {"message": {"tool_plan": "more"}}
        }),
        &mut state,
    );
    assert!(
        evs.is_empty(),
        "a tool-plan-delta after the text block closed must be dropped, got {evs:?}"
    );

    // Likewise a content-delta after the close is dropped (would otherwise be an unbalanced start/delta).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_CONTENT_DELTA,
            "delta": {"message": {"content": "resumed"}}
        }),
        &mut state,
    );
    assert!(
        evs.is_empty(),
        "a content-delta after the text block closed must be dropped, got {evs:?}"
    );
}

/// An unknown Cohere stream event type is a documented no-op (no events, no panic) — the named
/// fallthrough arm must not break the stream.
#[test]
fn test_stream_unknown_event_is_noop() {
    let mut state = crate::ir::StreamDecodeState::default();
    let evs = CohereReader.read_response_events(
        "",
        &serde_json::json!({"type": "citation-start", "index": 0}),
        &mut state,
    );
    assert!(evs.is_empty(), "unknown event types produce no IR events");
}

/// Regression (MEDIUM/performance): `extract_error` derives both fields from a SINGLE parse.
/// Behavioral check that both fields are still populated from one body.
#[test]
fn test_extract_error_single_parse_both_fields() {
    let body = br#"{"message": "boom", "error_type": "invalid_request"}"#;
    let err = CohereReader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(err.provider_code.as_deref(), Some("boom"));
    assert_eq!(err.structured_type.as_deref(), Some("invalid_request"));
    assert_eq!(err.http_status, 400);
}

/// Regression (PLUS #17, med-completeness): production `extract_error` must synthesize the
/// canonical `context_length_exceeded` provider code for an oversized-request error so the
/// breaker (`normalize_raw_error`) classifies it as `StatusClass::ContextLength` and fails over
/// without penalty. Before the fix `extract_error` carried the raw `message` string as the
/// provider code (the breaker could not recognize it → plain 400 ClientError, no failover); only
/// the `#[cfg(test)] classify()` helper — which does not run in production — recognized the
/// signal. This test feeds real Cohere v2 oversized-context error bodies and asserts the
/// production path yields `context_length_exceeded`, AND that the breaker then routes it to
/// ContextLength.
#[test]
fn test_extract_error_synthesizes_context_length_in_production() {
    let reader = CohereReader;

    // Several real-shaped Cohere v2 oversized-request error bodies (free-text `message`, generic
    // `error_type`). Each must normalize to the canonical code in PRODUCTION extract_error.
    let bodies: &[&[u8]] = &[
            br#"{"message": "too many tokens: the request exceeds the model's context window", "error_type": "invalid_request_error"}"#,
            br#"{"message": "the input is too long for the requested model; please reduce the prompt"}"#,
            br#"{"message": "requested 200000 tokens but the maximum is 128000 tokens for this model"}"#,
            br#"{"message": "prompt exceeds the maximum context length"}"#,
        ];

    let empty_map = std::collections::HashMap::new();
    for body in bodies {
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
                raw.provider_code.as_deref(),
                Some("context_length_exceeded"),
                "production extract_error must synthesize the canonical context-length code for body {}",
                String::from_utf8_lossy(body)
            );

        // The breaker must then route the canonical code to ContextLength (fail over, no penalty)
        // rather than treating the 400 as a plain ClientError.
        let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
        assert_eq!(
            signal.class,
            crate::breaker::StatusClass::ContextLength,
            "breaker must map the synthesized code to ContextLength for body {}",
            String::from_utf8_lossy(body)
        );
    }
}

/// A non-context-length Cohere error body must NOT be misclassified as context-length: the raw
/// `message` is preserved as the provider code and the breaker does not route it to
/// ContextLength (guards against the substring scan over-matching).
#[test]
fn test_extract_error_non_context_length_message_preserved() {
    let reader = CohereReader;
    let body = br#"{"message": "invalid api key", "error_type": "invalid_request_error"}"#;
    let raw = reader.extract_error(StatusCode::UNAUTHORIZED, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("invalid api key"),
        "a non-context-length message must be carried verbatim"
    );
    let signal = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
    assert_ne!(
        signal.class,
        crate::breaker::StatusClass::ContextLength,
        "a non-context-length error must not be classified as ContextLength"
    );
}

/// Regression (MED #8): the `too long` arm of `body_signals_context_length` must be
/// co-constrained to a token/context/input qualifier. A bare `contains("too long")` over-matched
/// ANY message containing "too long" (e.g. "request URL too long", "value too long for column")
/// and mis-synthesized the canonical `context_length_exceeded` code — triggering a no-penalty
/// ContextLength failover for an unrelated client error. This asserts the generic "too long"
/// bodies are NOT classified ContextLength, while genuine oversized-context "too long" bodies
/// still are.
#[test]
fn test_too_long_only_classifies_context_length_when_qualified() {
    let reader = CohereReader;
    let empty = std::collections::HashMap::new();

    // Generic "too long" errors with NO token/context/input qualifier: must NOT be ContextLength.
    let non_context: &[&[u8]] = &[
        br#"{"message": "the requested URL is too long", "error_type": "invalid_request_error"}"#,
        br#"{"message": "value too long for column name", "error_type": "invalid_request_error"}"#,
        br#"{"message": "the password you provided is too long"}"#,
    ];
    for body in non_context {
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_ne!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a generic 'too long' message must not synthesize the context-length code: {}",
            String::from_utf8_lossy(body)
        );
        let signal = crate::breaker::normalize_raw_error(&raw, &empty);
        assert_ne!(
            signal.class,
            crate::breaker::StatusClass::ContextLength,
            "a generic 'too long' message must not classify as ContextLength: {}",
            String::from_utf8_lossy(body)
        );
    }

    // Genuine oversized-context "too long" errors (qualified by token/context/input): still
    // classified ContextLength so the no-penalty failover still fires.
    let context: &[&[u8]] = &[
        br#"{"message": "the input is too long for the requested model"}"#,
        br#"{"message": "your prompt is too long: it exceeds the model context window"}"#,
        br#"{"message": "message too long, too many tokens"}"#,
    ];
    for body in context {
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a qualified 'too long' (context) message must synthesize the context-length code: {}",
            String::from_utf8_lossy(body)
        );
        let signal = crate::breaker::normalize_raw_error(&raw, &empty);
        assert_eq!(
            signal.class,
            crate::breaker::StatusClass::ContextLength,
            "a qualified 'too long' (context) message must classify as ContextLength: {}",
            String::from_utf8_lossy(body)
        );
    }
}

/// Regression (MEDIUM/conformance): a non-streaming request must OMIT the `stream` key entirely
/// (matching a native client relying on the `false` default), and a streaming request must emit
/// `"stream": true`. Always injecting `"stream": false` was a proxy tell and a same-protocol
/// passthrough fidelity break.
#[test]
fn test_write_request_stream_field_conditional() {
    let base = crate::ir::IrRequest {
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
        response_format: None,
        extra: serde_json::Map::new(),
    };

    let writer = CohereWriter;
    let non_streaming = writer.write_request(&base);
    assert!(
        non_streaming.get("stream").is_none(),
        "non-streaming request must omit the `stream` key, got {non_streaming}"
    );

    let streaming = writer.write_request(&crate::ir::IrRequest {
        stream: true,
        ..base
    });
    assert_eq!(
        streaming.get("stream"),
        Some(&serde_json::json!(true)),
        "streaming request must emit `\"stream\": true`"
    );
}

/// Regression (MEDIUM/conformance): a non-streaming Cohere -> Cohere passthrough must NOT GAIN a
/// `stream` field the native client never sent. Reading a body without `stream` then writing it
/// must yield a body still without `stream`.
#[test]
fn test_stream_field_roundtrip_omitted() {
    let native = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = CohereReader
        .read_request(&native)
        .expect("read_request should succeed");
    assert!(!ir.stream, "absent `stream` reads as false");
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert!(
        out.get("stream").is_none(),
        "round-trip must not inject a `stream` field, got {out}"
    );
}

/// Regression (MEDIUM/conformance): the streaming `message-end` frame must carry token usage at
/// `delta.usage.tokens.{input_tokens,output_tokens}` (native Cohere v2 shape) so a Cohere SDK
/// client tracking billing/rate-limit data is not silently zeroed.
#[test]
fn test_write_response_event_message_end_carries_usage() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 42,
            output_tokens: 7,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("message-end must serialize");
    assert_eq!(
        frame.get("type").and_then(|t| t.as_str()),
        Some("message-end") // golden wire-contract literal (kept bare on purpose)
    );
    let tokens = frame
        .get("delta")
        .and_then(|d| d.get("usage"))
        .and_then(|u| u.get("tokens"))
        .expect("delta.usage.tokens must be present");
    assert_eq!(
        tokens.get("input_tokens").and_then(|v| v.as_u64()),
        Some(42)
    );
    assert_eq!(
        tokens.get("output_tokens").and_then(|v| v.as_u64()),
        Some(7)
    );
}

/// Regression (MEDIUM/conformance): when upstream usage is zero (no data), the message-end frame
/// still emits the `tokens` object with zero values rather than omitting the key.
#[test]
fn test_write_response_event_message_end_zero_usage_present() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("message-end must serialize");
    let tokens = frame
        .get("delta")
        .and_then(|d| d.get("usage"))
        .and_then(|u| u.get("tokens"))
        .expect("delta.usage.tokens must be present even with zero usage");
    assert_eq!(tokens.get("input_tokens").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        tokens.get("output_tokens").and_then(|v| v.as_u64()),
        Some(0)
    );
}

/// The message-end stream frame round-trips usage through this protocol's own reader: the usage
/// written into `delta.usage.tokens` is read back identically.
#[test]
fn test_message_end_usage_stream_roundtrip() {
    let usage = crate::ir::IrUsage {
        input_tokens: 11,
        output_tokens: 3,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage.clone(),
        })
        .expect("message-end must serialize");

    let mut state = crate::ir::StreamDecodeState::default();
    let evs = CohereReader.read_response_events("", &frame, &mut state);
    let back = evs
        .iter()
        .find_map(|e| {
            if let IrStreamEvent::MessageDelta { usage, .. } = e {
                Some(usage.clone())
            } else {
                None
            }
        })
        .expect("a MessageDelta must come back");
    assert_eq!(back.input_tokens, 11);
    assert_eq!(back.output_tokens, 3);
}

/// Regression (LOW/correctness): a Tool-role message carrying plain text ALONGSIDE a ToolResult
/// must not silently drop the text — it is folded into the emitted tool message content.
#[test]
fn test_tool_role_text_alongside_result_not_dropped() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Tool,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "note".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "result".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
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
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    let msgs = out.get("messages").unwrap().as_array().unwrap();
    assert_eq!(msgs.len(), 1, "one tool message emitted");
    let content = msgs[0].get("content").and_then(|c| c.as_str()).unwrap();
    assert!(
        content.contains("note") && content.contains("result"),
        "both the message-level text and the tool result text must survive, got {content}"
    );
    assert_eq!(
        msgs[0].get("tool_call_id").and_then(|v| v.as_str()),
        Some("t1")
    );
}

/// Regression (writer-side join): a ToolResult whose content is SPLIT across multiple text blocks
/// must be joined into the Cohere `content` string with NO separator (matching read_request's
/// `.join("")`) — a phantom space would corrupt a base64 / split-JSON tool-result payload on a
/// round-trip. The reader join was tested; this guards the WRITER site (cohere.rs).
#[test]
fn test_tool_result_multi_block_content_joins_without_space() {
    let ir = crate::ir::IrRequest {
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
                        text: "foo".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Text {
                        text: "bar".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
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
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    let msgs = out.get("messages").unwrap().as_array().unwrap();
    let content = msgs[0].get("content").and_then(|c| c.as_str()).unwrap();
    assert_eq!(
        content, "foobar",
        "multi-block ToolResult content must join with NO separator (a phantom space corrupts \
             split payloads on round-trip), got {content:?}"
    );
}

/// Regression (LOW/correctness): a degenerate Tool-role message with text but NO ToolResult
/// block must still emit its text rather than producing nothing at all.
#[test]
fn test_tool_role_text_without_result_not_dropped() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Tool,
            content: vec![crate::ir::IrBlock::Text {
                text: "orphan tool text".to_string(),
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
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    let msgs = out.get("messages").unwrap().as_array().unwrap();
    assert_eq!(
        msgs.len(),
        1,
        "a Tool turn with text but no ToolResult must still emit a message"
    );
    assert_eq!(msgs[0].get("role").and_then(|r| r.as_str()), Some("tool"));
    assert_eq!(
        msgs[0].get("content").and_then(|c| c.as_str()),
        Some("orphan tool text")
    );
}

/// Regression (LOW #11/correctness): a degenerate Tool-role message with MULTIPLE text blocks
/// but NO ToolResult must emit `content` as a joined STRING, not a JSON text-part array. The old
/// code forwarded `content_val` (a JSON array for >1 text block), producing an invalid Cohere
/// tool message; the fix stringifies the blocks like the ToolResult path.
#[test]
fn test_tool_role_multi_text_without_result_is_string() {
    let ir = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::Tool,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "a".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Text {
                    text: "b".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
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
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    let msgs = out.get("messages").unwrap().as_array().unwrap();
    assert_eq!(
        msgs.len(),
        1,
        "a Tool turn with multiple text blocks but no ToolResult must emit one message"
    );
    assert_eq!(msgs[0].get("role").and_then(|r| r.as_str()), Some("tool"));
    assert_eq!(
        msgs[0].get("content").and_then(|c| c.as_str()),
        Some("ab"),
        "multi-block degenerate Tool content must be a joined string (NO separator, matching \
             read_request's `.join(\"\")` — a phantom space would corrupt split payloads on a \
             round-trip), not a JSON array"
    );
}

/// Regression (HIGH/dead-code): `write_error` is a LIVE vtable-dispatched trait method, not
/// test-only scaffolding. Reaching it via a `&dyn ProtocolWriter` (the exact runtime path used
/// at the Cohere-ingress error sites) must produce the native bare `{"message": ...}` envelope.
#[test]
fn test_write_error_via_trait_object_is_live_path() {
    let writer: Box<dyn ProtocolWriter> = Box::new(CohereWriter);
    let v = writer.write_error(401, "authentication_error", "bad key");
    assert_eq!(
        v.get("message").and_then(|m| m.as_str()),
        Some("bad key"),
        "the vtable-dispatched write_error must emit the native Cohere envelope"
    );
    assert_eq!(
        v.as_object().map(|o| o.len()),
        Some(1),
        "native Cohere error body is a bare single-key {{\"message\": ...}}"
    );
}

/// Regression (MEDIUM/conformance): a Cohere v2 `tool`-role message whose `content` is the
/// native object-array shape (`[{"type":"text","text":...}]`, plus a typed `document` block)
/// must NOT be silently dropped. The previous `filter_map(|b| b.as_str())` returned None for
/// every object element, yielding empty tool-result content and corrupting the conversation on
/// passthrough/egress.
#[test]
fn test_read_request_tool_content_object_array_preserved() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": [
                    {"type": "text", "text": "first part"},
                    {"type": "text", "text": "second part"},
                    {"type": "document", "document": {"id": "d1", "data": "doc body"}}
                ]
            }
        ]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Tool)
        .expect("tool message present");
    let tool_result = tool_msg
        .content
        .iter()
        .find_map(|b| match b {
            crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
            _ => None,
        })
        .expect("ToolResult block present");
    let text = match tool_result.first() {
        Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
        other => panic!("expected text block in tool result, got {other:?}"),
    };
    assert!(
        text.contains("first part"),
        "text block text must be preserved: {text}"
    );
    assert!(
        text.contains("second part"),
        "all text blocks must be joined: {text}"
    );
    assert!(
        text.contains("doc body"),
        "non-text typed (document) block must be serialized, not dropped: {text}"
    );
}

/// Fix #5 (fidelity): the Cohere reader must concatenate tool-content text blocks with NO
/// separator. The OpenAI/Anthropic writers concatenate text with `""`, so a space inserted here
/// would corrupt content split across blocks on a Cohere->OpenAI->Cohere round-trip (a phantom
/// space appears at each former block boundary). Two adjacent text blocks `"foo"` + `"bar"` must
/// read back as `"foobar"`, not `"foo bar"`.
#[test]
fn test_read_request_tool_text_blocks_join_without_space() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": [
                    {"type": "text", "text": "foo"},
                    {"type": "text", "text": "bar"}
                ]
            }
        ]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let tool_result = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Tool)
        .and_then(|m| {
            m.content.iter().find_map(|b| match b {
                crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
                _ => None,
            })
        })
        .expect("ToolResult block present");
    let text = match tool_result.first() {
        Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
        other => panic!("expected text block in tool result, got {other:?}"),
    };
    assert_eq!(
        text, "foobar",
        "adjacent tool-content text blocks must join with no inserted space"
    );
}

/// Regression (MEDIUM/conformance): the bare-string tool-content array shape must keep working
/// alongside the new object-array handling.
#[test]
fn test_read_request_tool_content_string_array_still_works() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_2",
                "content": ["alpha", "beta"]
            }
        ]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Tool)
        .expect("tool message present");
    let tool_result = tool_msg
        .content
        .iter()
        .find_map(|b| match b {
            crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
            _ => None,
        })
        .expect("ToolResult block present");
    let text = match tool_result.first() {
        Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
        other => panic!("expected text block in tool result, got {other:?}"),
    };
    // Fix #5: concatenate with NO separator (the OpenAI/Anthropic writers concat text blocks
    // with `""`); a space here corrupts content split across blocks on a round-trip.
    assert_eq!(text, "alphabeta");
}

/// Regression (HIGH/correctness): Cohere v2 streams each tool call as a complete
/// start/delta(s)/end sequence, closing the first tool BEFORE starting the second. The IR block
/// index assigned to each tool must stay distinct and stable for the tool's whole lifetime. The
/// prior scheme derived the index from the live rank of `frame_idx` in a set that shrank on
/// `tool-call-end`, so the second tool-call-start saw `len()==0` and reused the first tool's IR
/// index — silently merging two distinct tool calls onto one block. Feed two full sequences and
/// assert two DISTINCT BlockStart indices that match their deltas/stops.
#[test]
fn test_stream_two_sequential_tool_calls_get_distinct_indices() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // --- Tool 1: start (frame index 0) ---
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {
                "id": "call_a",
                "type": "function",
                "function": {"name": "get_weather", "arguments": ""}
            }}}
        }),
        &mut state,
    );
    let idx1 = match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::ToolUse { id, .. },
        } => {
            assert_eq!(id, "call_a");
            *index
        }
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    };

    // Tool 1 delta + end (closing the first tool BEFORE the second starts — the trigger).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_DELTA,
            "index": 0,
            "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"a\":1}"}}}}
        }),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx1
    ));
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_CALL_END, "index": 0}),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockStop { index } if *index == idx1
    ));

    // --- Tool 2: start (frame index 1), AFTER tool 1 closed ---
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 1,
            "delta": {"message": {"tool_calls": {
                "id": "call_b",
                "type": "function",
                "function": {"name": "get_time", "arguments": ""}
            }}}
        }),
        &mut state,
    );
    let idx2 = match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::ToolUse { id, .. },
        } => {
            assert_eq!(id, "call_b");
            *index
        }
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    };

    // The core assertion: the two tool calls occupy DISTINCT IR block indices.
    assert_ne!(
        idx1, idx2,
        "two sequential streamed tool calls must get distinct IR block indices"
    );

    // Tool 2's delta and end resolve to ITS index, not tool 1's.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_DELTA,
            "index": 1,
            "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"b\":2}"}}}}
        }),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockDelta { index, .. } if *index == idx2
    ));
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_CALL_END, "index": 1}),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockStop { index } if *index == idx2
    ));
}

/// Regression (LOW #9): a tool call's IR block index is ASSIGNED at `tool-call-start` and is
/// IMMUTABLE for the tool's whole lifetime — it must NOT change because a LATER tool arrives
/// with a smaller (non-monotonic) wire `frame_idx`. The prior scheme RECOMPUTED the index as the
/// live rank of `frame_idx` among recorded frames, so a second tool whose wire index sorts
/// BEFORE an earlier still-tracked tool retroactively bumped that earlier tool's rank: its
/// `tool-call-end` then resolved to a different IR index than its `tool-call-start`/`delta`,
/// emitting BlockStop for a block that was never opened and leaving the real block unclosed.
///
/// Feed two interleaved tool calls where the SECOND tool's wire index (5) is LARGER but the
/// THIRD's (2) is SMALLER than the first (10), all opened before any closes, and assert that each
/// tool's start, delta, and end frames all resolve to the SAME IR index the start was assigned.
#[test]
fn test_stream_tool_ir_index_stable_under_non_monotonic_frame_indices() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    let start = |wire: u64, id: &str| {
        serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": wire,
            "delta": {"message": {"tool_calls": {
                "id": id,
                "type": "function",
                "function": {"name": "f", "arguments": ""}
            }}}
        })
    };
    let start_idx = |evs: &[IrStreamEvent]| match evs.first() {
        Some(IrStreamEvent::BlockStart { index, .. }) => *index,
        other => panic!("expected a BlockStart, got {other:?}"),
    };

    // Open three tools with DELIBERATELY non-monotonic wire indices: 10, then 5, then 2.
    let a_idx = start_idx(&reader.read_response_events("", &start(10, "call_a"), &mut state));
    let b_idx = start_idx(&reader.read_response_events("", &start(5, "call_b"), &mut state));
    let c_idx = start_idx(&reader.read_response_events("", &start(2, "call_c"), &mut state));

    // Assignment is by INSERTION ORDER, so the three tools get distinct, contiguous indices
    // regardless of their (descending) wire indices.
    assert_eq!(
        (a_idx, b_idx, c_idx),
        (0, 1, 2),
        "tool IR indices must be assigned by insertion order, not wire-index rank"
    );

    // For each tool, its delta and end (resolved LATER, after the out-of-order siblings were
    // recorded) must still land on the SAME index its start was assigned. Under the old
    // live-rank scheme, tool A (wire 10) would have ranked 0 at start but 2 by end (because
    // wires 5 and 2 were inserted below it), shifting its close to the wrong block.
    for (wire, expected) in [(10u64, a_idx), (5, b_idx), (2, c_idx)] {
        let delta = serde_json::json!({
            "type": ET_TOOL_CALL_DELTA,
            "index": wire,
            "delta": {"message": {"tool_calls": {"function": {"arguments": "{}"}}}}
        });
        let devs = reader.read_response_events("", &delta, &mut state);
        assert!(
            matches!(devs.first(), Some(IrStreamEvent::BlockDelta { index, .. }) if *index == expected),
            "delta for wire {wire} must resolve to its assigned IR index {expected}, got {devs:?}"
        );

        let end = serde_json::json!({ "type": ET_TOOL_CALL_END, "index": wire });
        let eevs = reader.read_response_events("", &end, &mut state);
        assert!(
            matches!(eevs.first(), Some(IrStreamEvent::BlockStop { index }) if *index == expected),
            "end for wire {wire} must close its assigned IR index {expected}, got {eevs:?}"
        );
    }
}

/// A leading text block must push tool blocks to IR index 1+ while keeping each tool distinct.
#[test]
fn test_stream_tool_indices_offset_by_open_text_block() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // Open a text block at index 0.
    reader.read_response_events(
            "",
            &serde_json::json!({"type": ET_CONTENT_START, "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            &mut state,
        );

    let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": ET_TOOL_CALL_START,
                "index": 0,
                "delta": {"message": {"tool_calls": {"id": "c1", "type": "function", "function": {"name": "f1", "arguments": ""}}}}
            }),
            &mut state,
        );
    // The still-open text block (no intervening content-end) closes at index 0 first, then the
    // tool opens at index 1 — the emitted stream stays balanced.
    assert!(
        matches!(&evs[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
        "the open text block must close at index 0 before the first tool opens, got {evs:?}"
    );
    let idx1 = match &evs[1] {
        crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
        other => panic!("expected BlockStart, got {other:?}"),
    };
    assert_eq!(idx1, 1, "first tool follows the open text block at index 0");

    reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_CALL_END, "index": 0}),
        &mut state,
    );

    let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": ET_TOOL_CALL_START,
                "index": 1,
                "delta": {"message": {"tool_calls": {"id": "c2", "type": "function", "function": {"name": "f2", "arguments": ""}}}}
            }),
            &mut state,
        );
    let idx2 = match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
        other => panic!("expected BlockStart, got {other:?}"),
    };
    assert_eq!(
        idx2, 2,
        "second tool gets the next distinct index after the first"
    );
    assert_ne!(idx1, idx2);
}

/// Regression (HIGH/correctness): a text content block that has CLOSED before the first
/// tool-call-start must still reserve IR index 0 — the tool block must NOT reuse index 0. Native
/// Cohere v2 emits the full text block (content-start/delta/end) before any tool call, so by the
/// time the tool arrives `text_block_open` is already false; keying the tool base offset on that
/// live flag previously collapsed the first tool back onto index 0, emitting two BlockStart
/// frames at index 0 on a normal text-then-tool turn. The base must instead reflect that a text
/// block was EVER opened this stream.
#[test]
fn test_stream_tool_after_closed_text_block_does_not_reuse_index_zero() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // Text block: start at index 0 ...
    let evs = reader.read_response_events(
            "",
            &serde_json::json!({"type": ET_CONTENT_START, "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            &mut state,
        );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text
        }
    ));

    // ... and CLOSE it before any tool arrives (the trigger for the defect).
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_CONTENT_END, "index": 0}),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockStop { index: 0 }
    ));
    assert!(
        !state.text_block_open,
        "content-end must clear the live text_block_open flag"
    );

    // Now the first tool starts. It must land at IR index 1, NOT reuse the closed text block's 0.
    let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": ET_TOOL_CALL_START,
                "index": 0,
                "delta": {"message": {"tool_calls": {"id": "call_a", "type": "function", "function": {"name": "f", "arguments": ""}}}}
            }),
            &mut state,
        );
    let tool_idx = match &evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            index,
            block: crate::ir::IrBlockMeta::ToolUse { .. },
        } => *index,
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    };
    assert_eq!(
        tool_idx, 1,
        "a tool following a CLOSED text block must not reuse the text block's IR index 0"
    );

    // The tool's delta and end resolve to the same index 1, never back to 0.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_CALL_END, "index": 0}),
        &mut state,
    );
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockStop { index: 1 }
    ));
}

/// Regression (MEDIUM/performance): the modeled-key set is built once and shared, and still
/// contains exactly the keys this reader models — so request fields like those stay out of
/// `extra` while unknown keys are preserved. Calling it twice returns the same backing set.
#[test]
fn test_modeled_keys_built_once_and_complete() {
    let a = cohere_modeled_keys();
    let b = cohere_modeled_keys();
    assert!(
        std::ptr::eq(a, b),
        "modeled-key set must be a shared singleton"
    );
    for k in [
        "model",
        "messages",
        "tools",
        "max_tokens",
        "temperature",
        "stream",
    ] {
        assert!(a.contains(k), "{k} must be a modeled key");
    }
    // An unknown key is NOT modeled (so it round-trips through `extra`).
    assert!(!a.contains("unknown_passthrough_key"));
}

/// Regression (MEDIUM/conformance): a cross-protocol stream delivering tool calls to a
/// Cohere-ingress client must emit native `tool-call-start` / `tool-call-delta` frames. The
/// writer previously returned None for BlockStart{ToolUse} and BlockDelta{InputJsonDelta}, so a
/// Cohere client watching for streaming tool calls received nothing.
#[test]
fn test_write_response_event_emits_tool_call_frames() {
    let writer = CohereWriter;

    // BlockStart{ToolUse} → tool-call-start carrying id/name and an empty-string arguments.
    let start = IrStreamEvent::BlockStart {
        index: 2,
        block: crate::ir::IrBlockMeta::ToolUse {
            id: "call_x".to_string(),
            name: "get_weather".to_string(),
        },
    };
    let (_, frame) = writer
        .write_response_event(&start)
        .expect("BlockStart ToolUse must emit a frame");
    assert_eq!(
        frame.get("type").and_then(|t| t.as_str()),
        Some("tool-call-start") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
    let tc = frame
        .get("delta")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .expect("tool_calls present");
    assert_eq!(tc.get("id").and_then(|v| v.as_str()), Some("call_x"));
    assert_eq!(tc.get("type").and_then(|v| v.as_str()), Some("function"));
    assert_eq!(
        tc.get("function")
            .and_then(|f| f.get("name"))
            .and_then(|v| v.as_str()),
        Some("get_weather")
    );
    assert_eq!(
        tc.get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(|v| v.as_str()),
        Some(""),
        "the reader accumulates argument deltas onto this opening empty string"
    );

    // BlockDelta{InputJsonDelta} → tool-call-delta carrying the argument fragment.
    let delta = IrStreamEvent::BlockDelta {
        index: 2,
        delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
    };
    let (_, frame) = writer
        .write_response_event(&delta)
        .expect("BlockDelta InputJsonDelta must emit a frame");
    assert_eq!(
        frame.get("type").and_then(|t| t.as_str()),
        Some("tool-call-delta") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(frame.get("index").and_then(|i| i.as_u64()), Some(2));
    assert_eq!(
        frame
            .get("delta")
            .and_then(|d| d.get("message"))
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.get("function"))
            .and_then(|f| f.get("arguments"))
            .and_then(|v| v.as_str()),
        Some("{\"city\":\"SF\"}")
    );
}

/// The writer's emitted tool-call-start/delta frames round-trip through this protocol's OWN
/// reader: a BlockStart{ToolUse} + BlockDelta(args) re-read yields the same id/name/arguments.
#[test]
fn test_writer_tool_call_frames_roundtrip_through_reader() {
    let writer = CohereWriter;
    let (_, start_frame) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_z".to_string(),
                name: "lookup".to_string(),
            },
        })
        .expect("start frame");
    let (_, delta_frame) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
        })
        .expect("delta frame");

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;
    let start_evs = reader.read_response_events("", &start_frame, &mut state);
    match &start_evs[0] {
        crate::ir::IrStreamEvent::BlockStart {
            block: crate::ir::IrBlockMeta::ToolUse { id, name },
            ..
        } => {
            assert_eq!(id, "call_z");
            assert_eq!(name, "lookup");
        }
        other => panic!("expected BlockStart ToolUse, got {other:?}"),
    }
    let delta_evs = reader.read_response_events("", &delta_frame, &mut state);
    match &delta_evs[0] {
        crate::ir::IrStreamEvent::BlockDelta {
            delta: crate::ir::IrDelta::InputJsonDelta(args),
            ..
        } => assert_eq!(args, "{\"q\":1}"),
        other => panic!("expected InputJsonDelta, got {other:?}"),
    }
}

/// Thinking/Image stream blocks have no native Cohere v2 frame shape, so the writer suppresses
/// them (returns None) rather than emitting a fabricated non-native frame.
#[test]
fn test_write_response_event_thinking_and_image_blocks_suppressed() {
    let writer = CohereWriter;
    assert!(writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Thinking,
        })
        .is_none());
    assert!(writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Image,
        })
        .is_none());
    assert!(writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::ThinkingDelta("x".to_string()),
        })
        .is_none());
}

/// Regression (HIGH/correctness): a Cohere `tool`-role message's `content` must be decoded
/// EXACTLY ONCE — into the ToolResult's inner content — and NOT also into a stray top-level
/// Text block. The generic top-level content loop previously ran for every non-system role
/// (including Tool), so one tool message produced both a top-level Text block AND a ToolResult
/// holding the identical text. Assert the IR carries a single ToolResult and no top-level Text.
#[test]
fn test_read_request_tool_content_not_double_decoded() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": [{"type": "text", "text": "the result"}]
            }
        ]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Tool)
        .expect("tool message present");

    // No stray top-level Text block on the Tool message.
    let stray_text = tool_msg
        .content
        .iter()
        .any(|b| matches!(b, crate::ir::IrBlock::Text { .. }));
    assert!(
        !stray_text,
        "tool message must NOT carry a top-level Text block (content belongs to the ToolResult)"
    );

    // Exactly one ToolResult, carrying the text once.
    let tool_results: Vec<&Vec<crate::ir::IrBlock>> = tool_msg
        .content
        .iter()
        .filter_map(|b| match b {
            crate::ir::IrBlock::ToolResult { content, .. } => Some(content),
            _ => None,
        })
        .collect();
    assert_eq!(tool_results.len(), 1, "exactly one ToolResult block");
    let inner = match tool_results[0].first() {
        Some(crate::ir::IrBlock::Text { text, .. }) => text.clone(),
        other => panic!("expected text in tool result, got {other:?}"),
    };
    assert_eq!(inner, "the result");
}

/// Regression (HIGH/correctness): a Cohere -> Cohere round-trip of a tool message must NOT
/// duplicate the tool-result text. The double-decode caused the egress writer (whose Tool
/// branch folds leftover top-level text into the first ToolResult) to emit the same text twice
/// in the outgoing `content` string. Assert the text appears exactly once after a full
/// read_request -> write_request cycle.
#[test]
fn test_tool_message_roundtrip_no_duplicate_text() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": [{"type": "text", "text": "UNIQUEMARKER"}]
            }
        ]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    let msgs = out.get("messages").unwrap().as_array().unwrap();
    let tool_msg = msgs
        .iter()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
        .expect("a tool message must be emitted");
    let content = tool_msg
        .get("content")
        .and_then(|c| c.as_str())
        .expect("tool content string");
    assert_eq!(
        content.matches("UNIQUEMARKER").count(),
        1,
        "tool-result text must appear exactly once (no double-decode duplication), got {content}"
    );
    assert_eq!(
        tool_msg.get("tool_call_id").and_then(|v| v.as_str()),
        Some("call_1")
    );
}

/// Regression (MEDIUM/correctness): `max_tokens` must be narrowed with `u32::try_from`, NOT a
/// bare `as u32`. A value above `u32::MAX` previously wrapped to a small nonsense cap and was
/// forwarded to Cohere; it must now drop to `None` (no cap) rather than a truncated wrap. A
/// valid in-range value still parses, and a zero/negative value is still rejected.
#[test]
fn test_read_request_max_tokens_out_of_range_drops_to_none() {
    let reader = CohereReader;

    // u32::MAX + 1 must NOT wrap to 0 (or any truncated value): it drops to None.
    let over = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": (u32::MAX as i64) + 1
    });
    let ir = reader
        .read_request(&over)
        .expect("read_request should succeed");
    assert_eq!(
        ir.max_tokens, None,
        "an out-of-range max_tokens must drop to None, not wrap under `as u32`"
    );

    // A far-larger value likewise drops rather than truncating into the valid u32 range.
    let huge = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": i64::MAX
    });
    let ir = reader
        .read_request(&huge)
        .expect("read_request should succeed");
    assert_eq!(ir.max_tokens, None);

    // The exact u32::MAX boundary is in range and preserved.
    let max_in_range = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": u32::MAX as i64
    });
    let ir = reader
        .read_request(&max_in_range)
        .expect("read_request should succeed");
    assert_eq!(ir.max_tokens, Some(u32::MAX));

    // A normal value still parses through unchanged.
    let normal = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1024
    });
    let ir = reader
        .read_request(&normal)
        .expect("read_request should succeed");
    assert_eq!(ir.max_tokens, Some(1024));

    // Zero/negative are still rejected by the `v > 0` filter (unchanged behavior).
    let zero = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 0
    });
    assert_eq!(
        reader.read_request(&zero).expect("ok").max_tokens,
        None,
        "zero max_tokens is rejected"
    );
    let neg = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": -5
    });
    assert_eq!(
        reader.read_request(&neg).expect("ok").max_tokens,
        None,
        "negative max_tokens is rejected"
    );
}

/// Regression (MEDIUM/correctness): `k` (top_k) must be narrowed with `u32::try_from`, NOT a
/// bare `as u32`. A value above `u32::MAX` previously wrapped to a small nonsense sampling cap
/// (e.g. 4294967296 -> 0, 4294967297 -> 1) that was forwarded to Cohere, diverging from a
/// direct Cohere call; it must now drop to `None` (no cap forwarded) instead of wrapping. A
/// valid in-range value, including the exact `u32::MAX` boundary, is preserved.
#[test]
fn test_read_request_top_k_out_of_range_drops_to_none() {
    let reader = CohereReader;

    // u32::MAX + 1 must NOT wrap to 0: it drops to None.
    let over = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "k": (u32::MAX as u64) + 1
    });
    assert_eq!(
        reader.read_request(&over).expect("ok").top_k,
        None,
        "an out-of-range top_k must drop to None, not wrap under `as u32`"
    );

    // u32::MAX + 2 must NOT wrap to 1 either.
    let over2 = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "k": (u32::MAX as u64) + 2
    });
    assert_eq!(reader.read_request(&over2).expect("ok").top_k, None);

    // A far-larger value likewise drops rather than truncating into the valid u32 range.
    let huge = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "k": u64::MAX
    });
    assert_eq!(reader.read_request(&huge).expect("ok").top_k, None);

    // The exact u32::MAX boundary is in range and preserved.
    let max_in_range = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "k": u32::MAX as u64
    });
    assert_eq!(
        reader.read_request(&max_in_range).expect("ok").top_k,
        Some(u32::MAX)
    );

    // A normal value still parses through unchanged.
    let normal = serde_json::json!({
        "model": "command",
        "messages": [{"role": "user", "content": "hi"}],
        "k": 40
    });
    assert_eq!(reader.read_request(&normal).expect("ok").top_k, Some(40));
}

/// Regression (LOW/robustness): `state.open_tools` is never shrunk, so an upstream streaming an
/// unbounded number of distinct `tool-call-start` frame indices must not grow it without bound.
/// Past `MAX_TRACKED_TOOL_FRAMES` new frames stop being recorded, keeping the set capped while
/// every realistic stream (a handful of tools) is unaffected.
#[test]
fn test_open_tools_growth_is_capped() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;
    for frame_idx in 0..(MAX_TRACKED_TOOL_FRAMES + 50) {
        reader.read_response_events(
            "",
            &serde_json::json!({
                "type": ET_TOOL_CALL_START,
                "index": frame_idx,
                "delta": {"message": {"tool_calls": {
                    "id": format!("call_{frame_idx}"),
                    "type": "function",
                    "function": {"name": "f", "arguments": ""}
                }}}
            }),
            &mut state,
        );
    }
    assert!(
        state.open_tools.len() <= MAX_TRACKED_TOOL_FRAMES,
        "open_tools must be capped at MAX_TRACKED_TOOL_FRAMES, got {}",
        state.open_tools.len()
    );
}

/// Regression (HIGH/conformance): a `BlockStop` that closes a TOOL-CALL block (one opened by a
/// `tool-call-start` frame) must emit `tool-call-end`, NOT `content-end`. A native Cohere v2 SDK
/// distinguishes content events from tool-call events by type; closing a tool block with the
/// text `content-end` event leaves the tool call never terminated and breaks cross-protocol
/// streaming tool use.
#[test]
fn test_block_stop_closes_tool_block_with_tool_call_end() {
    let writer = CohereWriter;
    // Open a tool-call block at index 0.
    let (_, start) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_1".to_string(),
                name: "get_weather".to_string(),
            },
        })
        .expect("tool-call-start must emit");
    assert_eq!(
        start.get("type").and_then(|t| t.as_str()),
        Some("tool-call-start") // golden wire-contract literal (kept bare on purpose)
    );
    // Closing it must use tool-call-end at the SAME index.
    let (_, stop) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("tool block stop must emit");
    assert_eq!(
        stop.get("type").and_then(|t| t.as_str()),
        Some("tool-call-end"), // golden wire-contract literal (kept bare on purpose)
        "a tool-call block must close with tool-call-end, not content-end"
    );
    assert_eq!(stop.get("index").and_then(|i| i.as_u64()), Some(0));
}

/// Regression (HIGH/conformance): a `BlockStop` that closes a TEXT block (one opened by a
/// `content-start`/text `BlockStart`) must still emit `content-end`. Only tool-call blocks use
/// `tool-call-end`.
#[test]
fn test_block_stop_closes_text_block_with_content_end() {
    let writer = CohereWriter;
    // Open a text block at index 0.
    let (_, start) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("content-start must emit");
    assert_eq!(
        start.get("type").and_then(|t| t.as_str()),
        Some("content-start") // golden wire-contract literal (kept bare on purpose)
    );
    let (_, stop) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("text block stop must emit");
    assert_eq!(
        stop.get("type").and_then(|t| t.as_str()),
        Some("content-end"), // golden wire-contract literal (kept bare on purpose)
        "a text block must close with content-end"
    );
    assert_eq!(stop.get("index").and_then(|i| i.as_u64()), Some(0));
}

/// Regression (HIGH/conformance): a mixed stream (text block at index 0, then a tool-call block
/// at index 1) must close EACH block with its own correct end event — `content-end` for the text
/// index and `tool-call-end` for the tool index — based on which kind opened that index.
#[test]
fn test_block_stop_mixed_text_and_tool_close_events() {
    let writer = CohereWriter;
    // Text block at index 0.
    writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("text start");
    // Tool block at index 1.
    writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_2".to_string(),
                name: "lookup".to_string(),
            },
        })
        .expect("tool start");

    let (_, stop_text) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("text stop");
    assert_eq!(
        stop_text.get("type").and_then(|t| t.as_str()),
        Some("content-end"), // golden wire-contract literal (kept bare on purpose)
        "index 0 (text) must close with content-end"
    );

    let (_, stop_tool) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
        .expect("tool stop");
    assert_eq!(
        stop_tool.get("type").and_then(|t| t.as_str()),
        Some("tool-call-end"), // golden wire-contract literal (kept bare on purpose)
        "index 1 (tool) must close with tool-call-end"
    );
}

/// The writer's tool open/close pair round-trips through this protocol's OWN reader: a
/// BlockStart{ToolUse} followed by a BlockStop emits `tool-call-start` then `tool-call-end`,
/// which the reader maps back to a BlockStart{ToolUse} then a BlockStop.
#[test]
fn test_tool_block_open_close_roundtrip_through_reader() {
    let writer = CohereWriter;
    let (_, start_frame) = writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_z".to_string(),
                name: "lookup".to_string(),
            },
        })
        .expect("start frame");
    let (_, stop_frame) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("stop frame");
    assert_eq!(
        stop_frame.get("type").and_then(|t| t.as_str()),
        Some("tool-call-end") // golden wire-contract literal (kept bare on purpose)
    );

    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;
    let start_evs = reader.read_response_events("", &start_frame, &mut state);
    assert!(matches!(
        &start_evs[0],
        crate::ir::IrStreamEvent::BlockStart {
            block: crate::ir::IrBlockMeta::ToolUse { .. },
            ..
        }
    ));
    let stop_evs = reader.read_response_events("", &stop_frame, &mut state);
    assert!(
        matches!(&stop_evs[0], crate::ir::IrStreamEvent::BlockStop { .. }),
        "tool-call-end must map back to a BlockStop, got {stop_evs:?}"
    );
}

/// A tool index is consumed on close: a second `BlockStop` at the same index (an over-eager or
/// duplicate close) must NOT re-report `tool-call-end`. After the open-text-tracking fix (MED #4)
/// an index that is tracked by NEITHER the open-tool set NOR the open-text set emits no frame at
/// all, rather than falling through to an orphan `content-end` with no matching `content-start`.
#[test]
fn test_block_stop_tool_index_consumed_on_close() {
    let writer = CohereWriter;
    writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 3,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "c".to_string(),
                name: "f".to_string(),
            },
        })
        .expect("start");
    let (_, first) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 3 })
        .expect("first stop");
    assert_eq!(
        first.get("type").and_then(|t| t.as_str()),
        Some("tool-call-end") // golden wire-contract literal (kept bare on purpose)
    );
    // The tool marker was consumed and no text block was ever opened at index 3, so a second
    // close is an untracked index → no frame (no orphan content-end).
    let second = writer.write_response_event(&IrStreamEvent::BlockStop { index: 3 });
    assert!(
            second.is_none(),
            "a tool index consumed on first close must emit no frame on a duplicate close, got {second:?}"
        );
}

/// Regression (MEDIUM/conformance): the non-streaming `write_response` path must write IR
/// `stop_reason = "stop_sequence"` back as the native `STOP_SEQUENCE`, NOT `COMPLETE`. The
/// reader maps `STOP_SEQUENCE` -> IR `stop_sequence` and `COMPLETE` -> IR `end_turn`, so
/// collapsing both IR reasons onto `COMPLETE` made the round-trip asymmetric and masked a
/// stop-sequence stop as a normal end-of-turn for a Cohere client.
#[test]
fn test_write_response_stop_sequence_maps_to_stop_sequence() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::StopSequence),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("c14c80c3-18eb-4519-9460-6c92edd8cfb4".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let writer = CohereWriter;
    let out = writer.write_response(&resp);
    assert_eq!(
        out.get("finish_reason").and_then(|r| r.as_str()),
        Some("STOP_SEQUENCE"), // golden wire-contract literal (kept bare on purpose)
        "IR stop_sequence must serialize as native STOP_SEQUENCE, not COMPLETE"
    );
}

/// Companion: IR `end_turn` still maps to `COMPLETE` (the split must not regress the normal
/// end-of-turn case).
#[test]
fn test_write_response_end_turn_maps_to_complete() {
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
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("c14c80c3-18eb-4519-9460-6c92edd8cfb4".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let writer = CohereWriter;
    let out = writer.write_response(&resp);
    assert_eq!(
        out.get("finish_reason").and_then(|r| r.as_str()),
        Some("COMPLETE") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Regression (MEDIUM/conformance): the streaming `MessageDelta` path must likewise write IR
/// `stop_sequence` back as native `STOP_SEQUENCE` (not `COMPLETE`) in the message-end frame.
#[test]
fn test_stream_message_delta_stop_sequence_maps_to_stop_sequence() {
    let writer = CohereWriter;
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::StopSequence),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 2,
                output_tokens: 3,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        })
        .expect("message-end frame");
    assert_eq!(
        frame
            .get("delta")
            .and_then(|d| d.get("finish_reason"))
            .and_then(|r| r.as_str()),
        Some("STOP_SEQUENCE"), // golden wire-contract literal (kept bare on purpose)
        "streamed IR stop_sequence must serialize as native STOP_SEQUENCE, not COMPLETE"
    );
}

/// Full round-trip: a native Cohere `STOP_SEQUENCE` read into IR must write back as
/// `STOP_SEQUENCE` through both response paths — proving the reader/writer mapping is now
/// symmetric for stop-sequence stops (the asymmetry to guard against).
#[test]
fn test_stop_sequence_roundtrips_symmetrically() {
    let reader = CohereReader;
    let native = serde_json::json!({
        "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
        "finish_reason": COHERE_FINISH_STOP_SEQUENCE,
        "message": { "role": "assistant", "content": [{ "type": "text", "text": "x" }] },
        "usage": { "tokens": { "input_tokens": 1, "output_tokens": 1 } }
    });
    let ir = reader.read_response(&native).expect("read native response");
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::StopSequence));

    let writer = CohereWriter;
    let out = writer.write_response(&ir);
    assert_eq!(
        out.get("finish_reason").and_then(|r| r.as_str()),
        Some("STOP_SEQUENCE"), // golden wire-contract literal (kept bare on purpose)
        "STOP_SEQUENCE must survive a Cohere -> IR -> Cohere round-trip unchanged"
    );
}

/// Test helper: count `BlockStart` events whose IR index equals `idx`.
fn count_block_starts_at(evs: &[IrStreamEvent], idx: usize) -> usize {
    evs.iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { index, .. } if *index == idx))
        .count()
}

/// Regression (LOW #17): a DUPLICATE `tool-call-start` for a frame index that is already open
/// must be a no-op. The pre-fix code emitted a fresh `BlockStart` unconditionally on every
/// `tool-call-start`, so a backend that re-sent the start frame for an already-open tool block
/// produced two `BlockStart` events at the same IR index — a spurious second opening frame for
/// one block. After the fix the second start emits nothing.
#[test]
fn test_duplicate_tool_call_start_is_noop() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    let start = serde_json::json!({
        "type": ET_TOOL_CALL_START,
        "index": 0,
        "delta": { "message": { "tool_calls": {
            "id": "call_1",
            "type": "function",
            "function": { "name": "get_weather", "arguments": "" }
        }}}
    });

    let first = reader.read_response_events("", &start, &mut state);
    // First start opens the block exactly once (text never appeared, so tool IR index is 0).
    assert_eq!(
        count_block_starts_at(&first, 0),
        1,
        "first tool-call-start must open the block once"
    );

    let second = reader.read_response_events("", &start, &mut state);
    assert_eq!(
        count_block_starts_at(&second, 0),
        0,
        "a duplicate tool-call-start for an already-open frame must emit no BlockStart"
    );
    assert!(
        second.is_empty(),
        "a duplicate tool-call-start must be a complete no-op, got {second:?}"
    );
}

/// Regression (LOW #18): a `tool-call-start` for a frame BEYOND `MAX_TRACKED_TOOL_FRAMES` must
/// emit NO tool block events. The pre-fix code skipped *recording* the over-cap frame but still
/// computed an IR index via `cohere_assign_tool_ir_index` and emitted a `BlockStart` for it. Because
/// the frame was never recorded, that index equalled the rank of the highest *tracked* tool —
/// a collision producing a second `BlockStart` at an already-used IR index. After the fix an
/// untracked frame emits nothing (and its later delta/end are likewise dropped).
#[test]
fn test_over_cap_tool_call_start_emits_no_block() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Saturate the tracked set with distinct frame indices [0, MAX_TRACKED_TOOL_FRAMES).
    for f in 0..MAX_TRACKED_TOOL_FRAMES {
        let start = serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": f,
            "delta": { "message": { "tool_calls": {
                "id": format!("call_{f}"),
                "type": "function",
                "function": { "name": "f", "arguments": "" }
            }}}
        });
        let _ = reader.read_response_events("", &start, &mut state);
    }
    assert_eq!(state.open_tools.len(), MAX_TRACKED_TOOL_FRAMES);

    // A genuinely new frame past the cap: must produce NO events and not collide with the
    // highest tracked tool's IR index (MAX_TRACKED_TOOL_FRAMES - 1).
    let over = serde_json::json!({
        "type": ET_TOOL_CALL_START,
        "index": MAX_TRACKED_TOOL_FRAMES + 5,
        "delta": { "message": { "tool_calls": {
            "id": "call_over",
            "type": "function",
            "function": { "name": "f", "arguments": "abc" }
        }}}
    });
    let evs = reader.read_response_events("", &over, &mut state);
    assert!(
        evs.is_empty(),
        "an over-cap tool-call-start must emit no block events, got {evs:?}"
    );
    assert_eq!(
        count_block_starts_at(&evs, MAX_TRACKED_TOOL_FRAMES - 1),
        0,
        "an over-cap tool-call-start must not collide with the highest tracked tool's index"
    );
}

/// Regression (LOW #19): content-start / content-delta / content-end must NORMALIZE the text
/// block to IR index 0 regardless of the raw upstream wire `index`. The pre-fix code forwarded
/// the wire `index` verbatim, so a backend that numbered its single text block at (say) wire
/// index 2 produced a text `BlockStart`/`BlockDelta`/`BlockStop` at IR index 2 — while a tool
/// block (which assumes text is at IR index 0) takes IR index 1 after it, leaving index 0 unused
/// and the text/tool indices misaligned. After the fix the text block is always at IR index 0
/// and the tool block lands at IR index 1.
#[test]
fn test_text_block_normalized_to_ir_index_zero() {
    let reader = CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Backend numbers the text content block at a NON-ZERO wire index.
    let cs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_CONTENT_START,
            "index": 2,
            "delta": { "message": { "content": { "type": "text", "text": "" } } }
        }),
        &mut state,
    );
    match cs.as_slice() {
        [IrStreamEvent::BlockStart { index, block }] => {
            assert_eq!(
                *index, 0,
                "text BlockStart must be normalized to IR index 0"
            );
            assert!(matches!(block, crate::ir::IrBlockMeta::Text));
        }
        other => panic!("expected one text BlockStart, got {other:?}"),
    }

    let cd = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_CONTENT_DELTA,
            "index": 2,
            "delta": { "message": { "content": { "type": "text", "text": "hi" } } }
        }),
        &mut state,
    );
    match cd.as_slice() {
        [IrStreamEvent::BlockDelta { index, delta }] => {
            assert_eq!(
                *index, 0,
                "text BlockDelta must be normalized to IR index 0"
            );
            assert!(matches!(delta, crate::ir::IrDelta::TextDelta(t) if t == "hi"));
        }
        other => panic!("expected one text BlockDelta, got {other:?}"),
    }

    let ce = reader.read_response_events(
        "",
        &serde_json::json!({ "type": ET_CONTENT_END, "index": 2 }),
        &mut state,
    );
    match ce.as_slice() {
        [IrStreamEvent::BlockStop { index }] => {
            assert_eq!(*index, 0, "text BlockStop must be normalized to IR index 0");
        }
        other => panic!("expected one text BlockStop, got {other:?}"),
    }

    // A tool block that follows the (now-closed) text block must take IR index 1, NOT reuse the
    // wire index 2 the text block carried.
    let ts = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": { "message": { "tool_calls": {
                "id": "t1",
                "type": "function",
                "function": { "name": "f", "arguments": "" }
            }}}
        }),
        &mut state,
    );
    assert_eq!(
        count_block_starts_at(&ts, 1),
        1,
        "the tool block must open at IR index 1 (after the text block at index 0)"
    );
    assert_eq!(
        count_block_starts_at(&ts, 2),
        0,
        "the tool block must NOT reuse the text block's non-zero wire index"
    );
}

/// Regression (MED #3 / LOW #11): a non-request-size status (e.g. 429) whose free-text body
/// mentions token counts must NOT be reclassified as the no-penalty `ContextLength` class. The
/// body-scan override in `extract_error` is now gated on a request-size status (400 / 413), so a
/// rate-limit failure keeps its `RateLimit` disposition and stays subject to the breaker. Against
/// the old (ungated) code this stream reclassified to ContextLength and escaped the breaker.
#[test]
fn test_rate_limit_body_mentioning_tokens_is_not_context_length() {
    let reader = CohereReader;
    // A 429 whose message free-text mentions a maximum token count (the exact phrasing the
    // context-length scan keys on) must stay a rate-limit failure.
    let body = br#"{"message":"You have exceeded the maximum number of tokens per minute for your trial key"}"#;
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);

    // The override must NOT fire: provider_code keeps the raw message, not the canonical
    // context-length code.
    assert_ne!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 429 body mentioning tokens must not be reclassified as context_length_exceeded"
    );

    // End-to-end through the breaker: the canonical class is RateLimit, not ContextLength.
    let sig = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
    assert_eq!(
            sig.class,
            StatusClass::RateLimit,
            "a 429 body mentioning tokens must normalize to RateLimit so the breaker penalizes the lane"
        );

    // The `#[cfg(test)] classify()` helper must agree (status checked before the phrasing).
    let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, body);
    assert_eq!(signal.class, StatusClass::RateLimit);
}

/// A genuine oversized-request failure (HTTP 400 with context-length phrasing) must still
/// override to the canonical `context_length_exceeded` code and normalize to `ContextLength`.
/// Guards that the status gate did not break the real context-length path.
#[test]
fn test_bad_request_body_mentioning_tokens_is_context_length() {
    let reader = CohereReader;
    let body = br#"{"message":"too many tokens: the request exceeds the maximum context length"}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 400 oversized-request body must still override to the canonical code"
    );
    let sig = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
    assert_eq!(sig.class, StatusClass::ContextLength);

    let signal = reader.classify(StatusCode::BAD_REQUEST, body);
    assert_eq!(signal.class, StatusClass::ContextLength);
}

/// Regression (MED #4): a cross-protocol `Thinking` block carries NO opening frame on the Cohere
/// stream (its `BlockStart` maps to `None`), so its `BlockStop` must emit NOTHING — not an orphan
/// `content-end` with no matching `content-start`. Against the old code the `BlockStop` fell
/// through to an unconditional `content-end`.
#[test]
fn test_thinking_blockstop_emits_no_orphan_content_end() {
    let writer = CohereWriter;

    // Thinking BlockStart → no frame.
    let start = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::Thinking,
    });
    assert!(
        start.is_none(),
        "a Thinking BlockStart must not emit an opening frame"
    );

    // Thinking BlockStop → no frame (the orphan-content-end defect).
    let stop = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });
    assert!(
        stop.is_none(),
        "a Thinking BlockStop must emit no frame (no orphan content-end)"
    );
}

/// A normal Text block still emits a balanced `content-start` / `content-end` pair — the
/// open-text tracking must not suppress legitimate text closes.
#[test]
fn test_text_block_emits_balanced_content_start_and_end() {
    let writer = CohereWriter;

    let start = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::Text,
    });
    let (_, start_data) = start.expect("Text BlockStart must emit a content-start frame");
    assert_eq!(
        start_data.get("type").and_then(|t| t.as_str()),
        Some("content-start") // golden wire-contract literal (kept bare on purpose)
    );

    let stop = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });
    let (_, stop_data) = stop.expect("Text BlockStop must emit a content-end frame");
    assert_eq!(
        stop_data.get("type").and_then(|t| t.as_str()),
        Some("content-end") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Minimal IR request carrying a single tool and an explicit `tool_choice`, for the PF-H1
/// round-trip tests below.
fn ir_with_tool_choice(tc: Option<crate::ir::IrToolChoice>) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
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
        tools: vec![crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: None,
            input_schema: serde_json::json!({}),
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

#[test]
fn test_cohere_tool_choice_required_roundtrips() {
    // REQUIRED reads into the IR union and re-emits as the native enum string (PF-H1).
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": COHERE_TOOL_CHOICE_REQUIRED
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));

    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("tool_choice").and_then(|v| v.as_str()),
        Some("REQUIRED") // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_cohere_tool_choice_none() {
    // NONE round-trips to the IR `None` variant (forbid tools), distinct from omission.
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": COHERE_TOOL_CHOICE_NONE
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::None));

    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("tool_choice").and_then(|v| v.as_str()),
        Some("NONE") // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_cohere_tool_choice_specific_degrades_to_required() {
    // Cohere cannot pin ONE tool; a targeted IrToolChoice::Tool (e.g. translated from an OpenAI
    // `tool_choice:{type:function,...}`) must degrade to REQUIRED — force *some* tool — NOT
    // silently drop to auto. This is the load-bearing PF-H1 behavior on a lossy-by-target hop.
    let ir = ir_with_tool_choice(Some(crate::ir::IrToolChoice::Tool {
        name: "get_weather".to_string(),
    }));
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("tool_choice").and_then(|v| v.as_str()),
        Some("REQUIRED"), // golden wire-contract literal (kept bare on purpose)
        "a forced specific tool must degrade to REQUIRED, never to auto"
    );
}

#[test]
fn test_cohere_tool_choice_auto_omitted() {
    // Auto is Cohere's default — the writer must omit the field entirely (emitting "auto" would
    // be invalid for Cohere v2), and an absent inbound tool_choice reads as None (the Option).
    let ir = ir_with_tool_choice(Some(crate::ir::IrToolChoice::Auto));
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert!(
        out.get("tool_choice").is_none(),
        "Auto must omit tool_choice (it is Cohere's default)"
    );

    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    assert_eq!(ir.tool_choice, None);
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert!(out.get("tool_choice").is_none());
}

// PF-M1: OpenAI/Responses ingress accepts temperature up to 2.0, but Cohere's native range is
// [0.0, 1.0] and rejects >1 with a hard 400 ValidationException. The writer must clamp.
#[test]
fn test_cohere_writer_clamps_temperature_above_one() {
    let mut ir = ir_with_tool_choice(None);
    ir.temperature = Some(1.8);
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.get("temperature").and_then(|v| v.as_f64()),
        Some(1.0),
        "an OpenAI-ingress temperature of 1.8 must clamp to 1.0 on the Cohere writer; got {out}"
    );
}

// M2: the temperature clamp must be NON-SILENT — `clamp_temperature_for_cohere` returns
// `(clamped, was_clamped)` and `was_clamped` is true IFF the value actually changed, so the
// writer can `warn!` only on a real mutation. Unit-tested without a tracing subscriber.
#[test]
fn test_clamp_temperature_for_cohere_signals_on_change() {
    // Above range: clamped to 1.0 and flagged.
    assert_eq!(clamp_temperature_for_cohere(1.8), (1.0, true));
    assert_eq!(clamp_temperature_for_cohere(2.0), (1.0, true));
    // Below range: clamped to 0.0 and flagged.
    assert_eq!(clamp_temperature_for_cohere(-0.5), (0.0, true));
    // In range: untouched and NOT flagged (no spurious warn on a valid value).
    assert_eq!(clamp_temperature_for_cohere(0.7), (0.7, false));
    assert_eq!(clamp_temperature_for_cohere(0.0), (0.0, false));
    assert_eq!(clamp_temperature_for_cohere(1.0), (1.0, false));
    // Non-finite is total + passthrough (defensive; unreachable via valid JSON).
    let (nan_out, nan_flag) = clamp_temperature_for_cohere(f64::NAN);
    assert!(nan_out.is_nan() && !nan_flag);
}

// Cross-protocol response_format correctness is structural now (the typed `IrResponseFormat`
// can't hold a foreign shape) and covered end-to-end by `response_format_cross_protocol_matrix`
// in proto/mod.rs.

// SAMPLING: frequency_penalty / presence_penalty / seed / response_format survive a
// same-protocol Cohere->Cohere read->write round-trip in their native top-level shapes, and are
// pulled out of `extra` (modeled keys) so they do NOT double-emit.
#[test]
fn test_cohere_sampling_controls_survive_roundtrip() {
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}],
        "frequency_penalty": 0.5,
        "presence_penalty": 0.25,
        "seed": 42,
        "response_format": {"type": "json_object"}
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    assert_eq!(ir.frequency_penalty, Some(0.5));
    assert_eq!(ir.presence_penalty, Some(0.25));
    assert_eq!(ir.seed, Some(42));
    assert_eq!(
        ir.response_format,
        Some(crate::ir::IrResponseFormat {
            json: true,
            schema: None,
            name: None,
            strict: None,
            description: None,
        })
    );
    // Modeled keys must NOT linger in `extra` (or the writer would double-emit them).
    assert!(!ir.extra.contains_key("frequency_penalty"));
    assert!(!ir.extra.contains_key("presence_penalty"));
    assert!(!ir.extra.contains_key("seed"));
    assert!(!ir.extra.contains_key("response_format"));

    let out = {
        let __w = CohereWriter;
        __w.write_request(&ir)
    };
    assert_eq!(out.get("frequency_penalty"), Some(&serde_json::json!(0.5)));
    assert_eq!(out.get("presence_penalty"), Some(&serde_json::json!(0.25)));
    assert_eq!(out.get("seed"), Some(&serde_json::json!(42)));
    assert_eq!(
        out.get("response_format"),
        Some(&serde_json::json!({"type": "json_object"}))
    );
}

// H7: a Cohere v2 image content part (`{"type":"image_url","image_url":{"url":...}}`) reads into
// `IrBlock::Image` and writes back as the same native part — both a base64 data-URI image (split
// into a real MIME media_type + base64 data) and a bare https URL (preserved under the
// "image_url" sentinel).
#[test]
fn test_cohere_image_content_part_read_write_roundtrip() {
    let data_uri = "data:image/png;base64,aGVsbG8=";
    let body = serde_json::json!({
        "model": "command-a-vision",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "what is this?"},
                {"type": "image_url", "image_url": {"url": data_uri}},
                {"type": "image_url", "image_url": {"url": "https://example.com/cat.jpg"}}
            ]
        }]
    });
    let ir = CohereReader
        .read_request(&body)
        .expect("read_request should succeed");
    let content = &ir.messages[0].content;
    // Text + 2 images, in order.
    assert!(matches!(content[0], crate::ir::IrBlock::Text { .. }));
    match &content[1] {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, "aGVsbG8=");
        }
        other => panic!("expected base64 Image, got {other:?}"),
    }
    match &content[2] {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => {
            // A non-data URL is preserved verbatim as the typed Url source.
            assert_eq!(url, "https://example.com/cat.jpg");
        }
        other => panic!("expected url Image, got {other:?}"),
    }

    // Write back: the user message content must be an array carrying the text part then both
    // image parts in native `image_url` shape, reconstructing the original URLs.
    let out = {
        let __w = CohereWriter;
        __w.write_request(&ir)
    };
    let msgs = out.get("messages").and_then(|m| m.as_array()).unwrap();
    let parts = msgs[0].get("content").and_then(|c| c.as_array()).unwrap();
    assert_eq!(parts[0].get("type").and_then(|t| t.as_str()), Some("text"));
    assert_eq!(
        parts[1].get("type").and_then(|t| t.as_str()),
        Some("image_url")
    );
    assert_eq!(
        parts[1]
            .get("image_url")
            .and_then(|iu| iu.get("url"))
            .and_then(|u| u.as_str()),
        Some(data_uri),
        "base64 image must reconstruct its original data URI"
    );
    assert_eq!(
        parts[2]
            .get("image_url")
            .and_then(|iu| iu.get("url"))
            .and_then(|u| u.as_str()),
        Some("https://example.com/cat.jpg"),
        "url image must emit its raw URL verbatim"
    );
}

/// Cohere's `finish_reason` codec: the generic infra-failure `ERROR` maps to `IrStopReason::Error`
/// (distinct from the content-moderation `ERROR_TOXIC` → `Safety`), and it re-emits as `ERROR` on
/// egress — `Error` is a first-class IR reason (ir.rs:211) so an upstream infra stop is not
/// conflated with a safety block. Also pins that an unmodeled token degrades to `Other` on read
/// and `COMPLETE` on write (never leaked verbatim into Cohere's closed enum).
#[test]
fn finish_reason_error_and_unknown_codec() {
    use crate::ir::IrStopReason as S;
    // ERROR (infra) vs ERROR_TOXIC (moderation) must NOT be conflated.
    assert_eq!(read_cohere_stop_reason(COHERE_FINISH_ERROR), S::Error);
    assert_eq!(
        read_cohere_stop_reason(COHERE_FINISH_ERROR_TOXIC),
        S::Safety
    );
    // Error round-trips back to the native ERROR token.
    assert_eq!(write_cohere_stop_reason(S::Error), COHERE_FINISH_ERROR);
    // An unmodeled native token degrades to Other on read...
    assert_eq!(read_cohere_stop_reason("SOME_FUTURE_REASON"), S::Other);
    // ...and Other (plus the no-analog Refusal/PauseTurn) degrades to COMPLETE on egress.
    assert_eq!(write_cohere_stop_reason(S::Other), COHERE_FINISH_COMPLETE);
    assert_eq!(write_cohere_stop_reason(S::Refusal), COHERE_FINISH_COMPLETE);
    assert_eq!(
        write_cohere_stop_reason(S::PauseTurn),
        COHERE_FINISH_COMPLETE
    );
}

/// A full non-stream `read_response` carrying `finish_reason: "ERROR"` surfaces
/// `IrStopReason::Error` (an upstream-error terminated generation, ir.rs:211), and a
/// `write_response` re-emits the native `ERROR` token — so a Cohere infra stop survives the seam.
#[test]
fn read_write_response_error_finish_reason_round_trips() {
    let body = serde_json::json!({
        "id": "c-123",
        "finish_reason": COHERE_FINISH_ERROR,
        "message": {"role": "assistant", "content": [{"type": "text", "text": ""}]},
        "usage": {"tokens": {"input_tokens": 4, "output_tokens": 0}}
    });
    let resp = CohereReader.read_response(&body).expect("read_response");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Error));
    let writer = CohereWriter;
    let out = writer.write_response(&resp);
    assert_eq!(
        out.get("finish_reason").and_then(|v| v.as_str()),
        Some("ERROR") // golden wire-contract literal (kept bare on purpose)
    );
}

/// The `tool_choice` union maps to Cohere v2's uppercase native strings: `Required`→`REQUIRED`,
/// `None`→`NONE`, `Auto`→omitted (the v2 default). A targeted `Tool{name}` has NO Cohere analog
/// (no named-tool choice in v2) and degrades to `REQUIRED` — preserving the load-bearing "must
/// call a tool" intent rather than silently dropping to auto.
#[test]
fn tool_choice_maps_to_cohere_native_strings() {
    let mk = |tc: Option<crate::ir::IrToolChoice>| {
        let mut req = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            ..Default::default()
        };
        req.tool_choice = tc;
        let writer = CohereWriter;
        writer.write_request(&req)
    };
    assert_eq!(
        mk(Some(crate::ir::IrToolChoice::Required))
            .get("tool_choice")
            .and_then(|v| v.as_str()),
        Some("REQUIRED")
    );
    assert_eq!(
        mk(Some(crate::ir::IrToolChoice::None))
            .get("tool_choice")
            .and_then(|v| v.as_str()),
        Some("NONE")
    );
    // A specific tool degrades to REQUIRED (documented lossy-by-target — v2 has no named choice).
    assert_eq!(
        mk(Some(crate::ir::IrToolChoice::Tool {
            name: "f".to_string()
        }))
        .get("tool_choice")
        .and_then(|v| v.as_str()),
        Some("REQUIRED")
    );
    // Auto is the default and is OMITTED (a request that never forced a tool gains no directive).
    assert!(
        mk(Some(crate::ir::IrToolChoice::Auto))
            .get("tool_choice")
            .is_none(),
        "Auto must be omitted, not emitted"
    );
    assert!(mk(None).get("tool_choice").is_none());
}

/// A `response_format` json_schema round-trips read→IR→write. Cohere's native shape puts the
/// schema DIRECTLY under `json_schema` (not nested under `.schema` like OpenAI); the reader
/// canonicalizes it into the typed `IrResponseFormat` and the writer re-emits Cohere's shape — so
/// a same-protocol structured-output request stays faithful and a cross-protocol one cannot leak a
/// foreign shape (ir.rs:348).
#[test]
fn response_format_json_schema_round_trips_cohere_shape() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"city": {"type": "string"}},
        "required": ["city"]
    });
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}],
        "response_format": {"type": "json_object", "json_schema": schema}
    });
    let ir = CohereReader.read_request(&body).expect("read_request");
    let rf = ir
        .response_format
        .as_ref()
        .expect("response_format canonicalizes into the typed IR");
    assert!(rf.json, "json_object must set json=true");
    assert_eq!(
        rf.schema.as_ref(),
        Some(&schema),
        "the schema sits directly under json_schema in Cohere's shape"
    );
    // It must NOT linger in extra.
    assert!(!ir.extra.contains_key("response_format"));

    // WRITE re-emits Cohere's native json_object + json_schema shape (schema directly under key).
    let writer = CohereWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/response_format/type")
            .and_then(|t| t.as_str()),
        Some("json_object")
    );
    assert_eq!(out.pointer("/response_format/json_schema"), Some(&schema));
}

/// Cohere v2 has NO `n`/`num_generations` parameter (it was a v1 field, removed in v2 — ir.rs:46).
/// Even when the IR carries `n`, the writer must NOT emit it, and the reader never sets it — so a
/// cross-protocol request carrying `n` does not produce an invalid Cohere body.
#[test]
fn n_candidate_count_never_emitted_on_cohere() {
    let mut req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        ..Default::default()
    };
    req.n = Some(3);
    let writer = CohereWriter;
    let out = writer.write_request(&req);
    assert!(
        out.get("n").is_none() && out.get("num_generations").is_none(),
        "Cohere v2 models no n/num_generations; it must never be emitted: {out}"
    );

    // And the reader never sets `n` from a Cohere body.
    let body = serde_json::json!({
        "model": "command-r",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = CohereReader.read_request(&body).expect("read_request");
    assert_eq!(ir.n, None, "the Cohere reader must never populate n");
}

/// audit finding #7 (streaming symmetry): the STREAMING Cohere reader must preserve
/// `tool-plan-delta` the same way the non-stream `read_response` folds `message.tool_plan` — as a
/// LEADING Text block ahead of the tool call. Without it a STREAMING Cohere→X hop lost the
/// assistant's pre-tool-call reasoning while the non-stream hop preserved it.
#[test]
fn test_stream_tool_plan_delta_becomes_leading_text_before_tool_call() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = CohereReader;

    // message-start
    reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_MESSAGE_START, "delta": {"message": {"role": "assistant"}}}),
        &mut state,
    );

    // tool-plan-delta x2 — opens the leading Text block at index 0 on first appearance, then a
    // TextDelta per token.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_PLAN_DELTA, "delta": {"message": {"tool_plan": "I will "}}}),
        &mut state,
    );
    assert!(
        matches!(
            &evs[0],
            crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        ),
        "first tool-plan-delta must open a leading Text block at index 0, got {evs:?}"
    );
    assert!(
        matches!(
            &evs[1],
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta(t)
            } if t == "I will "
        ),
        "the plan token must be a TextDelta, got {evs:?}"
    );

    let evs = reader.read_response_events(
        "",
        &serde_json::json!({"type": ET_TOOL_PLAN_DELTA, "delta": {"message": {"tool_plan": "check the weather."}}}),
        &mut state,
    );
    assert_eq!(evs.len(), 1, "a subsequent token emits only a TextDelta");
    assert!(matches!(
        &evs[0],
        crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta(t)
        } if t == "check the weather."
    ));

    // tool-call-start — Cohere sends NO content-end for the plan, so the tool-call-start must first
    // CLOSE the leading plan Text block (BlockStop at index 0) — otherwise it would leak an
    // unbalanced content_block_start on an Anthropic egress — then open the tool at index 1. This
    // mirrors the non-stream fold: the plan is the LEADING block and the tool follows it.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {"id": "t1", "type": "function", "function": {"name": "get_weather", "arguments": ""}}}}
        }),
        &mut state,
    );
    assert!(
        matches!(&evs[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
        "the tool-call-start must close the open plan Text block at index 0 first, got {evs:?}"
    );
    assert!(
        matches!(
            &evs[1],
            crate::ir::IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::ToolUse { id, name }
            } if id == "t1" && name == "get_weather"
        ),
        "the tool must open at index 1, after the leading plan Text at index 0, got {evs:?}"
    );
}

/// audit finding #7 (known writer limitation): the IR carries a folded `tool_plan` as a plain
/// leading `IrBlock::Text` with no distinguishing flag, so an X→Cohere hop re-emits it as `content`,
/// NOT as the native `tool_plan` slot. This test pins that documented, non-lossy behavior (the text
/// survives; only its native slot is reshaped) so a future accidental change is caught.
#[test]
fn test_write_response_reemits_folded_tool_plan_as_content_not_tool_plan() {
    let writer = CohereWriter;
    let resp = crate::ir::IrResponse {
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Text {
                text: "First I will check the weather.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
            crate::ir::IrBlock::ToolUse {
                id: "t1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "SF"}),
                cache_control: None,
            },
        ],
        stop_reason: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
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
    let out = writer.write_response(&resp);
    let message = out.get("message").expect("message");
    assert!(
        message.get("tool_plan").is_none(),
        "the IR cannot distinguish a folded tool_plan from a plain leading Text, so it is NOT \
         re-emitted as tool_plan: {out}"
    );
    let content = message
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content array");
    assert!(
        content
            .iter()
            .any(|b| b.get("text").and_then(|t| t.as_str())
                == Some("First I will check the weather.")),
        "the reasoning text must survive as a content text block: {out}"
    );
}

/// audit finding #7 follow-up (MAJOR, balanced-stream): drive a REAL Cohere v2 tool-plan stream
/// (`message-start` → `tool-plan-delta`× → `tool-call-start`/`-delta`/`-end` → `message-end`)
/// through the ANTHROPIC writer and assert every `content_block_start` has a matching
/// `content_block_stop`. The `tool-plan-delta` arm opens a LEADING text block that Cohere never
/// closes with `content-end`; without the `tool-call-start` auto-close it would emit a dangling
/// `content_block_start(index 0)` on Anthropic egress (an unbalanced stream / proxy-signature tell).
/// This is the first cross-writer coverage — the other cohere stream tests exercise reader internals
/// only.
#[test]
fn test_stream_tool_plan_to_anthropic_writer_is_balanced() {
    let reader = CohereReader;
    let writer = crate::proto::anthropic::AnthropicWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    // The native Cohere v2 tool-use stream frame sequence, in order.
    let frames = vec![
        serde_json::json!({"type": ET_MESSAGE_START, "delta": {"message": {"role": "assistant"}}}),
        serde_json::json!({"type": ET_TOOL_PLAN_DELTA, "delta": {"message": {"tool_plan": "I will "}}}),
        serde_json::json!({"type": ET_TOOL_PLAN_DELTA, "delta": {"message": {"tool_plan": "check the weather."}}}),
        serde_json::json!({
            "type": ET_TOOL_CALL_START,
            "index": 0,
            "delta": {"message": {"tool_calls": {"id": "t1", "type": "function", "function": {"name": "get_weather", "arguments": ""}}}}
        }),
        serde_json::json!({
            "type": ET_TOOL_CALL_DELTA,
            "index": 0,
            "delta": {"message": {"tool_calls": {"function": {"arguments": "{\"city\":\"SF\"}"}}}}
        }),
        serde_json::json!({"type": ET_TOOL_CALL_END, "index": 0}),
        serde_json::json!({"type": ET_MESSAGE_END, "delta": {"finish_reason": "COMPLETE"}}),
    ];

    let mut starts = 0usize;
    let mut stops = 0usize;
    for frame in &frames {
        for ev in reader.read_response_events("", frame, &mut state) {
            if let Some((event_type, _payload)) = writer.write_response_event(&ev) {
                if event_type == "content_block_start" {
                    starts += 1;
                } else if event_type == "content_block_stop" {
                    stops += 1;
                }
            }
        }
    }

    // Two blocks open on Anthropic egress: the leading plan Text (index 0) and the tool_use (index
    // 1). Both must close — a dangling text block was the defect.
    assert_eq!(
        starts, 2,
        "expected two content_block_start frames (plan text + tool_use)"
    );
    assert_eq!(
        starts, stops,
        "every content_block_start must have a matching content_block_stop (balanced stream); \
         got {starts} start(s) and {stops} stop(s)"
    );
}
