
use super::*;
use crate::ir::{IrBlock, IrBlockMeta, IrDelta, IrMessage, IrRole, IrStreamEvent, IrUsage};

/// The streaming `include_usage` trailer must be its OWN chunk, not folded onto the finish
/// chunk. `split_openai_trailing_usage` lifts a folded `usage` off a finish chunk and re-homes it
/// onto a native-shape trailing usage-only chunk (`{choices:[], usage}`) that mirrors the stream
/// identity, leaving the finish chunk usage-free.
#[test]
fn test_split_openai_trailing_usage_unfolds_finish_chunk() {
    // A finish chunk as the OpenAI writer folds it: non-null finish_reason AND a top-level usage.
    let mut finish = serde_json::json!({
        "id": "chatcmpl-abc",
        "object": OBJ_CHUNK,
        "created": 1234,
        "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_STOP}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
    });
    let trailing =
        split_openai_trailing_usage(&mut finish).expect("a usage-bearing finish chunk must split");

    // The finish chunk no longer carries usage but keeps its finish_reason.
    assert!(
        finish.get("usage").is_none(),
        "usage must be lifted OFF the finish chunk: {finish}"
    );
    assert_eq!(
        finish.pointer("/choices/0/finish_reason"),
        Some(&serde_json::json!(FINISH_STOP)),
        "finish chunk keeps its finish_reason"
    );

    // The trailing chunk is native-shape: same identity, EMPTY choices, the usage object.
    assert_eq!(trailing.get("id"), Some(&serde_json::json!("chatcmpl-abc")));
    assert_eq!(trailing.get("created"), Some(&serde_json::json!(1234)));
    assert_eq!(trailing.get("model"), Some(&serde_json::json!("gpt-4o")));
    assert_eq!(
        trailing.get("object"),
        Some(&serde_json::json!("chat.completion.chunk")) // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        trailing.get("choices"),
        Some(&serde_json::json!([])),
        "trailing usage chunk carries an EMPTY choices array (native shape)"
    );
    assert_eq!(
        trailing.get("usage"),
        Some(&serde_json::json!({"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}))
    );
}

/// A chunk WITHOUT a folded usage (every non-finish chunk, and a finish chunk that never
/// folded one) is left untouched — the split is a no-op on the common path.
#[test]
fn test_split_openai_trailing_usage_noop_without_usage() {
    // A finish chunk with no usage.
    let mut finish = serde_json::json!({
        "object": OBJ_CHUNK,
        "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_STOP}]
    });
    assert!(
        split_openai_trailing_usage(&mut finish).is_none(),
        "no usage → no split"
    );

    // A mid-stream content chunk that somehow carries usage but no terminal finish_reason is also
    // left alone (defensive: the writer only folds onto the finish chunk).
    let mut mid = serde_json::json!({
        "object": OBJ_CHUNK,
        "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": null}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    });
    assert!(
        split_openai_trailing_usage(&mut mid).is_none(),
        "usage on a non-finish chunk is not split (defensive)"
    );
    assert!(
        mid.get("usage").is_some(),
        "non-finish chunk left untouched"
    );
}

fn text_block(text: &str) -> IrBlock {
    IrBlock::Text {
        text: text.to_string(),
        cache_control: None,
        citations: Vec::new(),
    }
}

// --- Streaming: parallel tool calls must keep distinct, stable indices (fix: index passthrough)

#[test]
fn stream_tool_use_block_start_uses_ir_index() {
    let w = OpenAiWriter;
    let ev = IrStreamEvent::BlockStart {
        index: 2,
        block: IrBlockMeta::ToolUse {
            id: "call_b".to_string(),
            name: "lookup".to_string(),
        },
    };
    let (_, chunk) = w
        .write_response_event(&ev)
        .expect("tool-use start emits a chunk");
    let tc = &chunk["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(tc["index"], serde_json::json!(2));
    assert_eq!(tc["id"], serde_json::json!("call_b"));
    assert_eq!(tc["function"]["name"], serde_json::json!("lookup"));
}

#[test]
fn stream_input_json_delta_uses_ir_index() {
    let w = OpenAiWriter;
    let ev = IrStreamEvent::BlockDelta {
        index: 3,
        delta: IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
    };
    let (_, chunk) = w
        .write_response_event(&ev)
        .expect("json delta emits a chunk");
    let tc = &chunk["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(tc["index"], serde_json::json!(3));
    assert_eq!(tc["function"]["arguments"], serde_json::json!("{\"q\":1}"));
}

#[test]
fn stream_parallel_tool_calls_do_not_collide_at_index_zero() {
    let w = OpenAiWriter;
    let mk_start = |idx: usize, id: &str| IrStreamEvent::BlockStart {
        index: idx,
        block: IrBlockMeta::ToolUse {
            id: id.to_string(),
            name: "f".to_string(),
        },
    };
    let mk_delta = |idx: usize, frag: &str| IrStreamEvent::BlockDelta {
        index: idx,
        delta: IrDelta::InputJsonDelta(frag.to_string()),
    };

    let s1 = w.write_response_event(&mk_start(1, "a")).unwrap().1;
    let s2 = w.write_response_event(&mk_start(2, "b")).unwrap().1;
    let d1 = w.write_response_event(&mk_delta(1, "x")).unwrap().1;
    let d2 = w.write_response_event(&mk_delta(2, "y")).unwrap().1;

    let idx = |v: &serde_json::Value| v["choices"][0]["delta"]["tool_calls"][0]["index"].clone();
    // Two distinct tool calls keep distinct indices...
    assert_ne!(idx(&s1), idx(&s2));
    // ...and each argument fragment routes to the index of its matching start.
    assert_eq!(idx(&s1), idx(&d1));
    assert_eq!(idx(&s2), idx(&d2));
}

// --- read_request: system messages at any position promote to top-level system (fixes 2 & 3)

#[test]
fn read_request_promotes_non_leading_system_message() {
    let body = serde_json::json!({
        "model": "gpt-x",
        "messages": [
            { "role": "user", "content": "hello" },
            { "role": "system", "content": "be terse" },
            { "role": "assistant", "content": "ok" }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    // The mid-conversation system turn lands in the top-level system field...
    assert_eq!(ir.system.len(), 1);
    assert_eq!(ir.system[0], text_block("be terse"));
    // ...and never appears as a System-role IrMessage inside the messages array.
    assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
    assert_eq!(ir.messages.len(), 2);
}

#[test]
fn read_request_concatenates_multiple_system_messages() {
    let body = serde_json::json!({
        "messages": [
            { "role": "system", "content": "first" },
            { "role": "user", "content": "hi" },
            { "role": "system", "content": "second" }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.system, vec![text_block("first"), text_block("second")]);
    assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
}

// --- read_request: degenerate (content-less) system message must not vanish (fix 4)

#[test]
fn read_request_preserves_contentless_system_message() {
    let body = serde_json::json!({
        "messages": [
            { "role": "system" },
            { "role": "user", "content": "hi" }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.system, vec![text_block("")]);
}

#[test]
fn read_request_preserves_empty_array_system_message() {
    let body = serde_json::json!({
        "messages": [
            { "role": "system", "content": [] },
            { "role": "user", "content": "hi" }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.system, vec![text_block("")]);
}

// --- read_request: the "developer" role (OpenAI o1/o3 system-equivalent) is accepted and
//     promoted to the top-level system field, not 400ed by the role catch-all.

#[test]
fn read_request_developer_role_feeds_system_not_rejected() {
    let body = serde_json::json!({
        "model": "o3",
        "messages": [
            { "role": "developer", "content": "be precise" },
            { "role": "user", "content": "hi" }
        ]
    });
    // Old code returned Err(400) on the unknown "developer" role; it must now parse.
    let ir = OpenAiReader
        .read_request(&body)
        .expect("developer role must not 400");
    // The developer turn carries the system prompt and lands in the top-level system field...
    assert_eq!(ir.system, vec![text_block("be precise")]);
    // ...and is never surfaced as a System-role IrMessage inside the messages array.
    assert!(ir.messages.iter().all(|m| m.role != IrRole::System));
}

// --- read_request: `max_completion_tokens` is a modeled output-token cap

#[test]
fn read_request_promotes_max_completion_tokens_into_ir() {
    // A request carrying only the modern `max_completion_tokens` (the field reasoning models
    // require) must populate the modeled IR `max_tokens` so it survives the cross-protocol seam.
    let body = serde_json::json!({
        "model": "o3",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_completion_tokens": 256
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.max_tokens, Some(256));
    // It must NOT also linger in `extra` (which is cleared at the seam and would otherwise make
    // the writer emit a conflicting duplicate).
    assert!(!ir.extra.contains_key("max_completion_tokens"));
}

#[test]
fn read_request_prefers_max_tokens_over_max_completion_tokens() {
    // When both are present the legacy `max_tokens` wins (it is the explicit primary field);
    // neither lingers in `extra`.
    let body = serde_json::json!({
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 100,
        "max_completion_tokens": 999
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.max_tokens, Some(100));
    assert!(!ir.extra.contains_key("max_tokens"));
    assert!(!ir.extra.contains_key("max_completion_tokens"));
}

#[test]
fn read_request_ignores_nonpositive_max_completion_tokens() {
    // A zero/negative cap is invalid and must not populate the IR (mirrors the `max_tokens` filter).
    let body = serde_json::json!({
        "messages": [{ "role": "user", "content": "hi" }],
        "max_completion_tokens": 0
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.max_tokens, None);
}

// --- write_request: the modeled cap re-emits as `max_tokens`; a `max_completion_tokens` ingress
//     value survives the read→write round-trip via the IR field

/// Regression: a ToolResult whose content is multiple Text blocks
/// (e.g. from an Anthropic tool_result content array) must serialize to OpenAI `content` by
/// CONCATENATION with NO separator — matching the read path (`push_str`, no separator). Joining
/// with a space injected spurious spaces (`["A","B"]` → `"A B"`), corrupting boundary-sensitive
/// content (base64 / split JSON) on the cross-protocol round-trip.
#[test]
fn write_request_tool_result_multi_text_concatenates_without_separator() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Tool,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: vec![text_block("AAA"), text_block("BBB")],
                is_error: false,
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
    let out = OpenAiWriter.write_request(&req);
    let tool_msg = out["messages"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["role"] == "tool"))
        .expect("a tool-role message");
    assert_eq!(
        tool_msg["content"], "AAABBB",
        "multi-text ToolResult content must concatenate with NO separator, got {}",
        tool_msg["content"]
    );
}

#[test]
fn write_request_forces_logprobs_flag_when_only_top_logprobs_present() {
    // A source request carrying only the top-count (no enabling flag) — e.g. read from Gemini's
    // independent `logprobs` field — must emit `logprobs: true` on OpenAI egress, or the API
    // rejects it with "logprobs must be true when top_logprobs is set".
    let mut ir = OpenAiReader
        .read_request(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{ "role": "user", "content": "hi" }],
            "top_logprobs": 5
        }))
        .expect("parses");
    ir.logprobs = None; // only the top-count is set
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["logprobs"], true, "enabling flag must be forced");
    assert_eq!(out["top_logprobs"], 5);
}

#[test]
fn write_request_emits_max_tokens_from_modeled_cap() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![text_block("hi")],
        }],
        tools: Vec::new(),
        max_tokens: Some(512),
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
    let out = OpenAiWriter.write_request(&req);
    assert_eq!(out["max_tokens"], serde_json::json!(512));
    // No stray `max_completion_tokens` (it is folded into the single modeled cap).
    assert!(out
        .as_object()
        .expect("object")
        .get("max_completion_tokens")
        .is_none());
}

#[test]
fn max_completion_tokens_survives_read_write_roundtrip() {
    // An ingress request carrying only `max_completion_tokens` is promoted into the IR cap.
    // On a SAME-protocol OpenAI->OpenAI passthrough (extra intact) it must re-emit the SOURCE key
    // `max_completion_tokens` — OpenAI's o1/o3 reasoning models REQUIRE it and 400 on `max_tokens`.
    let body = serde_json::json!({
        "messages": [{ "role": "user", "content": "hi" }],
        "max_completion_tokens": 777
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["max_completion_tokens"],
        serde_json::json!(777),
        "same-protocol passthrough must preserve the source `max_completion_tokens` key"
    );
    // And it must NOT also emit `max_tokens` (a reasoning model 400s on a conflicting duplicate).
    assert!(
        out.as_object().expect("object").get("max_tokens").is_none(),
        "must not emit `max_tokens` alongside the preserved `max_completion_tokens`"
    );
    // The busbar-internal sentinel never leaks onto the wire.
    assert!(out
        .as_object()
        .expect("object")
        .get(MAX_COMPLETION_TOKENS_SENTINEL)
        .is_none());
}

#[test]
fn max_completion_tokens_maps_to_max_tokens_cross_protocol() {
    // On the CROSS-protocol seam `extra` is cleared (the sentinel vanishes with it), so the
    // cap re-emits as the canonical `max_tokens` — other protocols have no `max_completion_tokens`.
    // Mirror the seam by clearing extra before the write.
    let body = serde_json::json!({
        "messages": [{ "role": "user", "content": "hi" }],
        "max_completion_tokens": 777
    });
    let mut ir = OpenAiReader.read_request(&body).expect("parses");
    ir.extra.clear(); // the translate seam clears extra on a cross-protocol hop
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["max_tokens"],
        serde_json::json!(777),
        "cross-protocol egress emits the canonical `max_tokens`"
    );
    assert!(
        out.as_object()
            .expect("object")
            .get("max_completion_tokens")
            .is_none(),
        "cross-protocol egress must not carry `max_completion_tokens`"
    );
}

#[test]
fn response_format_survives_same_protocol_roundtrip() {
    // Phase 0: `response_format` (json_object / json_schema / structured output) is now a first-class
    // IR field (read verbatim into `ir.response_format`), so it leaves `extra` and survives both a
    // same-protocol OpenAI->OpenAI passthrough AND the cross-protocol seam (which clears `extra`).
    let body = serde_json::json!({
        "messages": [{ "role": "user", "content": "hi" }],
        "response_format": {
            "type": RESP_FORMAT_JSON_SCHEMA,
            "json_schema": {"name": "out", "schema": {"type": "object"}}
        }
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    // It is promoted to the typed field, NOT left lingering in extra.
    assert!(
        !ir.extra.contains_key("response_format"),
        "response_format must be promoted to the typed IR field, not left in extra"
    );
    assert_eq!(
        ir.response_format,
        Some(crate::ir::IrResponseFormat {
            json: true,
            schema: Some(serde_json::json!({"type": "object"})),
            name: Some("out".to_string()),
            strict: None,
            description: None,
        })
    );
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["response_format"],
        serde_json::json!({
            "type": "json_schema", // golden wire-contract literal (kept bare on purpose)
            "json_schema": {"name": "out", "schema": {"type": "object"}}
        }),
        "response_format must round-trip on a same-protocol OpenAI passthrough"
    );
}

#[test]
fn write_request_omits_token_cap_when_absent() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![text_block("hi")],
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
    let out = OpenAiWriter.write_request(&req);
    let obj = out.as_object().expect("object");
    assert!(obj.get("max_completion_tokens").is_none());
    assert!(obj.get("max_tokens").is_none());
}

// --- write_request: ToolUse on a non-assistant message must not be dropped (fix 6)

#[test]
fn write_request_keeps_tool_use_on_user_message() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::ToolUse {
                id: "t9".to_string(),
                name: "search".to_string(),
                input: serde_json::json!({"q": "rust"}),
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages array");
    let user_msg = &msgs[0];
    let tcs = user_msg["tool_calls"]
        .as_array()
        .expect("tool_calls preserved on user message");
    assert_eq!(tcs.len(), 1);
    assert_eq!(tcs[0]["id"], serde_json::json!("t9"));
    assert_eq!(tcs[0]["function"]["name"], serde_json::json!("search"));
    assert_eq!(
        tcs[0]["function"]["arguments"],
        serde_json::json!("{\"q\":\"rust\"}")
    );
}

/// Regression (MEDIUM/correctness): a Tool-role message carrying ONLY ToolResult blocks must
/// emit ONLY the flat `{"role":"tool",...}` entries — `msg_obj` is NOT pushed (no spurious
/// `{"role":"tool","content":null}` entry).
#[test]
fn write_request_pure_tool_result_message_emits_only_flat_entries() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Tool,
            content: vec![IrBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: vec![text_block("42")],
                is_error: false,
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages array");
    assert_eq!(
        msgs.len(),
        1,
        "pure tool-result must yield exactly one entry"
    );
    assert_eq!(msgs[0]["role"], serde_json::json!("tool"));
    assert_eq!(msgs[0]["tool_call_id"], serde_json::json!("call_1"));
    assert_eq!(msgs[0]["content"], serde_json::json!("42"));
}

/// Regression (MEDIUM/correctness): a Tool-role message carrying BOTH a ToolResult block AND
/// non-ToolResult content (Text here, plus a ToolUse) must NOT silently drop the non-ToolResult
/// content. Previously the `msg_obj` (carrying the Text content and `tool_calls`) was never
/// pushed on the Tool-role path, dropping it. The fix surfaces it as an additional message entry.
#[test]
fn write_request_tool_role_mixed_content_not_dropped() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Tool,
            content: vec![
                IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![text_block("result")],
                    is_error: false,
                    cache_control: None,
                },
                text_block("stray narration"),
                IrBlock::ToolUse {
                    id: "call_2".to_string(),
                    name: "lookup".to_string(),
                    input: serde_json::json!({"k": "v"}),
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages array");
    // One flat tool-result entry, plus the msg_obj carrying the stray text + tool_calls.
    assert_eq!(
        msgs.len(),
        2,
        "tool-result entry + the non-dropped mixed-content entry, got {msgs:?}"
    );
    // The flat tool-result entry.
    let flat = msgs
        .iter()
        .find(|m| m.get("tool_call_id").is_some())
        .expect("flat tool-result entry present");
    assert_eq!(flat["tool_call_id"], serde_json::json!("call_1"));
    // The non-ToolResult content was surfaced, not dropped.
    let carried = msgs
        .iter()
        .find(|m| m.get("tool_calls").is_some())
        .expect("the non-ToolResult content (text + tool_calls) must not be dropped");
    let tcs = carried["tool_calls"].as_array().expect("tool_calls array");
    assert_eq!(tcs[0]["id"], serde_json::json!("call_2"));
    // The stray text survives in the carried message's content array.
    let content = carried["content"]
        .as_array()
        .expect("stray text content survives as an array");
    assert!(
        content
            .iter()
            .any(|c| c["type"] == "text" && c["text"] == "stray narration"),
        "stray text must survive, got {content:?}"
    );
}

/// Regression: a Gemini `functionResponse` decodes to an IrRole::User message carrying
/// a ToolResult block (Anthropic tool_results live on a User-role message too). The OpenAI writer
/// must emit a flat `{"role":"tool",...}` entry for it — keyed on the ToolResult block, NOT on the
/// message role. Previously the emission was gated on IrRole::Tool, so the result was SILENTLY
/// DROPPED on Gemini→OpenAI / Anthropic→OpenAI. Fails against the old code (no tool message), passes
/// after.
#[test]
fn write_request_tool_result_on_user_message_emits_tool_message() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::ToolResult {
                tool_use_id: "call_42".to_string(),
                content: vec![text_block("the answer is 42")],
                is_error: false,
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages array");
    // Exactly one flat tool-result entry; the now-empty User msg_obj (content null, no tool_calls)
    // is NOT re-pushed, so the ToolResult is neither dropped nor duplicated.
    assert_eq!(
        msgs.len(),
        1,
        "exactly the flat tool-result entry, got {msgs:?}"
    );
    let tool_msg = &msgs[0];
    assert_eq!(
        tool_msg["role"], "tool",
        "a ToolResult on a User-role message must become an OpenAI tool message, got {tool_msg:?}"
    );
    assert_eq!(tool_msg["tool_call_id"], serde_json::json!("call_42"));
    assert_eq!(tool_msg["content"], serde_json::json!("the answer is 42"));
}

// --- write_response: content collected once; null when no text (fix 5 regression guard)

#[test]
fn write_response_joins_text_blocks_and_keeps_tool_calls() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![
            text_block("Hello "),
            text_block("world"),
            IrBlock::ToolUse {
                id: "c1".to_string(),
                name: "fn".to_string(),
                input: serde_json::json!({"a": 1}),
                cache_control: None,
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: IrUsage {
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
    let out = OpenAiWriter.write_response(&resp);
    let msg = &out["choices"][0]["message"];
    assert_eq!(msg["content"], serde_json::json!("Hello world"));
    assert_eq!(msg["tool_calls"][0]["id"], serde_json::json!("c1"));
    assert_eq!(
        out["choices"][0]["finish_reason"],
        serde_json::json!("tool_calls") // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn write_response_content_null_when_no_text() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::ToolUse {
            id: "c1".to_string(),
            name: "fn".to_string(),
            input: serde_json::json!({}),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: IrUsage {
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
    };
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(
        out["choices"][0]["message"]["content"],
        serde_json::Value::Null
    );
}

// --- Task 1: native OpenAI error envelope shape ---

#[test]
fn write_error_native_openai_shape() {
    let v = OpenAiWriter.write_error(404, ERR_TYPE_NOT_FOUND, "model 'gpt-z' not found");
    // Exact native shape: error.{message,type,param,code}, with param/code null.
    assert_eq!(
        v["error"]["message"],
        serde_json::json!("model 'gpt-z' not found")
    );
    assert_eq!(v["error"]["type"], serde_json::json!("not_found_error")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(v["error"]["param"], serde_json::Value::Null);
    assert_eq!(v["error"]["code"], serde_json::Value::Null);
    // Must be JSON-serializable (served as application/json) and have exactly the error object.
    let s = serde_json::to_string(&v).expect("serializes");
    let re: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    assert!(re.get("error").is_some());
}

#[test]
fn write_error_maps_kind_vocabulary() {
    // Known generic kinds map onto OpenAI's own error-type vocabulary.
    for (kind, want) in [
        ("auth", ERR_TYPE_AUTHENTICATION),
        ("rate_limit", ERR_TYPE_RATE_LIMIT),
        ("forbidden", ERR_TYPE_PERMISSION),
        ("invalid_request", ERR_TYPE_INVALID_REQUEST),
        (
            crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH,
            ERR_TYPE_INVALID_REQUEST,
        ),
    ] {
        let v = OpenAiWriter.write_error(400, kind, "x");
        assert_eq!(v["error"]["type"], serde_json::json!(want), "kind={kind}");
    }
}

#[test]
fn write_error_empty_kind_falls_back_to_status_bucket() {
    // Empty kind with a 5xx status derives "server_error"; with a 4xx, "invalid_request_error".
    let v5 = OpenAiWriter.write_error(503, "", "down");
    assert_eq!(v5["error"]["type"], serde_json::json!("server_error")); // golden wire-contract literal (kept bare on purpose)
    let v4 = OpenAiWriter.write_error(400, "", "bad");
    assert_eq!(
        v4["error"]["type"],
        serde_json::json!("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
}

// --- Task 2: identity-field fidelity ---

#[test]
fn read_response_captures_upstream_identity() {
    let body = serde_json::json!({
        "id": "chatcmpl-abc123",
        "object": OBJ_COMPLETION,
        "created": 1_700_000_000u64,
        "model": "gpt-4o",
        "system_fingerprint": "fp_deadbeef",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": FINISH_STOP
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4}
    });
    let ir = OpenAiReader.read_response(&body).expect("read_response");
    assert_eq!(ir.id.as_deref(), Some("chatcmpl-abc123"));
    assert_eq!(ir.created, Some(1_700_000_000));
    assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
    assert_eq!(ir.system_fingerprint.as_deref(), Some("fp_deadbeef"));
}

#[test]
fn same_protocol_roundtrip_preserves_identity() {
    // OpenAI → IR → OpenAI must preserve id/created/system_fingerprint/model exactly.
    let body = serde_json::json!({
        "id": "chatcmpl-xyz789",
        "object": OBJ_COMPLETION,
        "created": 1_711_111_111u64,
        "model": "gpt-4o-mini",
        "system_fingerprint": "fp_cafef00d",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": FINISH_STOP
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2}
    });
    let ir = OpenAiReader.read_response(&body).expect("read_response");
    let out = OpenAiWriter.write_response(&ir);
    assert_eq!(out["id"], serde_json::json!("chatcmpl-xyz789"));
    assert_eq!(out["object"], serde_json::json!("chat.completion")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(out["created"], serde_json::json!(1_711_111_111u64));
    assert_eq!(out["model"], serde_json::json!("gpt-4o-mini"));
    assert_eq!(out["system_fingerprint"], serde_json::json!("fp_cafef00d"));
    // total_tokens is synthesized as prompt + completion.
    assert_eq!(out["usage"]["total_tokens"], serde_json::json!(12));
}

#[test]
fn cross_protocol_write_synthesizes_valid_id() {
    // IR with no identity (cross-protocol: backend supplied none) must still emit a
    // protocol-correct id ("chatcmpl-...") and a created timestamp, without panicking.
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hello")],
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
    let out = OpenAiWriter.write_response(&resp);
    let id = out["id"].as_str().expect("synthesized id is a string");
    assert!(
        id.starts_with("chatcmpl-"), // golden wire-contract literal (kept bare on purpose)
        "synthesized id has the right prefix: {id}"
    );
    assert!(
        id.len() > "chatcmpl-".len(), // golden wire-contract literal (kept bare on purpose)
        "synthesized id has a token body"
    );
    assert!(
        out["created"].as_u64().is_some(),
        "created synthesized as unix secs"
    );
    // No system_fingerprint fabricated on cross-protocol responses.
    assert!(out.get("system_fingerprint").is_none());
}

// --- `model` is required + non-nullable; cross-protocol (model: None) responses must
//     stamp a fallback rather than omit the field ---

#[test]
fn cross_protocol_write_response_emits_fallback_model() {
    // A Bedrock-egress -> OpenAI-ingress buffered response carries `model: None`. The native
    // chat.completion schema requires a non-nullable `model` string, so the writer must emit a
    // present, non-null fallback (never omit the key).
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hi")],
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
    let out = OpenAiWriter.write_response(&resp);
    let obj = out.as_object().expect("response object");
    assert!(
        obj.contains_key("model"),
        "model key must always be present"
    );
    let model = out["model"].as_str().expect("model is a non-null string");
    assert!(!model.is_empty(), "model fallback is non-empty: {model}");
    assert_eq!(out["model"], serde_json::json!(DEFAULT_MODEL));
}

#[test]
fn write_response_preserves_upstream_model_over_fallback() {
    // A same-protocol passthrough must keep the upstream model verbatim, not the fallback.
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hi")],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("gpt-4o-mini".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(out["model"], serde_json::json!("gpt-4o-mini"));
}

#[test]
fn stream_message_start_emits_fallback_model_when_none() {
    // The opening chunk's `model` is required + non-nullable; a cross-protocol stream with
    // `model: None` must stamp the fallback rather than omit the field.
    let no_model = IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&no_model)
        .expect("message start emits a chunk");
    let obj = chunk.as_object().expect("chunk object");
    assert!(
        obj.contains_key("model"),
        "model key must always be present"
    );
    let model = chunk["model"].as_str().expect("model is a non-null string");
    assert!(!model.is_empty(), "model fallback is non-empty: {model}");
    assert_eq!(chunk["model"], serde_json::json!(DEFAULT_MODEL));
}

#[test]
fn stream_message_start_preserves_upstream_model_over_fallback() {
    let with_model = IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: Some("gpt-4o-2024-08-06".to_string()),
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&with_model)
        .expect("message start emits a chunk");
    assert_eq!(chunk["model"], serde_json::json!("gpt-4o-2024-08-06"));
}

#[test]
fn synth_completion_ids_are_unique() {
    // Two synthesized ids minted back-to-back must differ (atomic counter guarantees it).
    let a = synth_completion_id();
    let b = synth_completion_id();
    assert_ne!(a, b);
    assert!(a.starts_with("chatcmpl-") && b.starts_with("chatcmpl-")); // golden wire-contract literal (kept bare on purpose)
}

#[test]
fn stream_message_start_emits_identity() {
    // Streaming MessageStart carries id/created/model into the opening chunk; synthesized when None.
    let with_id = IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: Some("chatcmpl-stream1".to_string()),
        created: Some(1_722_222_222),
        model: Some("gpt-4o".to_string()),
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&with_id)
        .expect("message start emits a chunk");
    assert_eq!(chunk["id"], serde_json::json!("chatcmpl-stream1"));
    assert_eq!(chunk["object"], serde_json::json!("chat.completion.chunk")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(chunk["created"], serde_json::json!(1_722_222_222u64));
    assert_eq!(chunk["model"], serde_json::json!("gpt-4o"));

    // Cross-protocol: no identity → synthesized id + created, still a valid chunk.
    let no_id = IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (_, chunk2) = OpenAiWriter
        .write_response_event(&no_id)
        .expect("message start emits a chunk");
    assert!(chunk2["id"]
        .as_str()
        .map(|s| s.starts_with("chatcmpl-")) // golden wire-contract literal (kept bare on purpose)
        .unwrap_or(false));
    assert!(chunk2["created"].as_u64().is_some());
}

#[test]
fn stream_read_captures_chunk_identity() {
    // The first streaming chunk's top-level id/created/model land in the MessageStart IR event.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-stream9",
            "object": OBJ_CHUNK,
            "created": 1_733_333_333u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
        }),
        &mut st,
    );
    let start = ev
        .iter()
        .find(|e| matches!(e, IrStreamEvent::MessageStart { .. }))
        .expect("MessageStart emitted");
    match start {
        IrStreamEvent::MessageStart {
            id, created, model, ..
        } => {
            assert_eq!(id.as_deref(), Some("chatcmpl-stream9"));
            assert_eq!(*created, Some(1_733_333_333));
            assert_eq!(model.as_deref(), Some("gpt-4o"));
        }
        _ => unreachable!(),
    }
}

// --- total_tokens must saturate, never overflow-panic/wrap ---

#[test]
fn write_response_total_tokens_saturates_on_overflow() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("x")],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: u64::MAX,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    // Must not panic (debug) or wrap (release); saturates at u64::MAX.
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(out["usage"]["total_tokens"], serde_json::json!(u64::MAX));
}

// --- sampling params must round-trip through extra, not be dropped ---

#[test]
fn read_request_preserves_sampling_params_in_extra() {
    let body = serde_json::json!({
        "model": "gpt-x",
        "messages": [{ "role": "user", "content": "hi" }],
        "top_p": 0.9,
        "frequency_penalty": 0.5,
        "presence_penalty": 0.25,
        "stop": ["\n\n"],
        "n": 2,
        "logit_bias": { "50256": -100 }
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    // top_p and stop are now PROMOTED to first-class IR fields (universally-modeled sampling
    // controls that must translate across the cross-protocol seam), so they leave `extra` and
    // land in the typed fields.
    assert!(!ir.extra.contains_key("top_p"));
    assert!(!ir.extra.contains_key("stop"));
    assert_eq!(ir.top_p, Some(0.9_f64));
    assert_eq!(ir.stop, vec!["\n\n".to_string()]);
    // Phase 0: penalties / seed / n / response_format are now PROMOTED to first-class IR fields too,
    // so they leave `extra` and land in the typed fields. Only `logit_bias` (no IR field) stays in
    // `extra` (still re-emitted on a same-protocol passthrough, still stripped cross-protocol).
    assert!(!ir.extra.contains_key("frequency_penalty"));
    assert!(!ir.extra.contains_key("presence_penalty"));
    assert!(!ir.extra.contains_key("n"));
    assert_eq!(ir.frequency_penalty, Some(0.5_f64));
    assert_eq!(ir.presence_penalty, Some(0.25_f64));
    assert_eq!(ir.n, Some(2));
    assert_eq!(
        ir.extra.get("logit_bias"),
        Some(&serde_json::json!({ "50256": -100 }))
    );
    // And they reach the upstream body on write: promoted controls via the typed fields, the
    // rest via the extra-forwarding loop.
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["top_p"], serde_json::json!(0.9));
    assert_eq!(out["stop"], serde_json::json!(["\n\n"]));
    assert_eq!(out["frequency_penalty"], serde_json::json!(0.5));
    assert_eq!(out["n"], serde_json::json!(2));
}

// --- tool-call-only assistant turn → content: null, not [] ---

#[test]
fn write_request_tool_call_only_assistant_has_null_content() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Assistant,
            content: vec![IrBlock::ToolUse {
                id: "t1".to_string(),
                name: "search".to_string(),
                input: serde_json::json!({"q": "x"}),
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
    let out = OpenAiWriter.write_request(&req);
    let msg = &out["messages"][0];
    assert_eq!(msg["content"], serde_json::Value::Null);
    assert_eq!(msg["tool_calls"][0]["id"], serde_json::json!("t1"));
}

// --- image_url parsing honors the IR base64 contract ---

#[test]
fn read_block_data_uri_splits_media_type_and_payload() {
    let block = serde_json::json!({
        "type": "image_url",
        "image_url": { "url": "data:image/png;base64,AAAB" }
    });
    let ir = read_openai_block(&block).expect("parses");
    match ir {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, "AAAB");
        }
        other => panic!("expected Image, got {other:?}"),
    }
}

#[test]
fn read_block_https_url_kept_verbatim_with_sentinel() {
    let block = serde_json::json!({
        "type": "image_url",
        "image_url": { "url": "https://example.com/cat.png" }
    });
    let ir = read_openai_block(&block).expect("parses");
    match ir {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => {
            assert_eq!(url, "https://example.com/cat.png");
        }
        other => panic!("expected Image, got {other:?}"),
    }
}

#[test]
fn image_url_round_trips_through_writer() {
    for url in ["data:image/png;base64,AAAB", "https://example.com/cat.png"] {
        let source = super::parse_image_url(url);
        assert_eq!(super::image_url_from_ir(&source).as_deref(), Some(url));
    }
}

// --- streaming Error type maps to a real OpenAI error type ---

#[test]
fn stream_error_uses_enumerated_openai_type() {
    let cases = [
        (crate::breaker::StatusClass::RateLimit, ERR_TYPE_RATE_LIMIT),
        (crate::breaker::StatusClass::Auth, ERR_TYPE_AUTHENTICATION),
        (
            crate::breaker::StatusClass::Billing,
            ERR_TYPE_INSUFFICIENT_QUOTA,
        ),
        (
            crate::breaker::StatusClass::ClientError,
            ERR_TYPE_INVALID_REQUEST,
        ),
        (
            crate::breaker::StatusClass::ContextLength,
            ERR_TYPE_INVALID_REQUEST,
        ),
        (
            crate::breaker::StatusClass::ServerError,
            ERR_TYPE_SERVER_ERROR,
        ),
        (
            crate::breaker::StatusClass::Overloaded,
            ERR_TYPE_SERVER_ERROR,
        ),
        (crate::breaker::StatusClass::Timeout, ERR_TYPE_SERVER_ERROR),
        (crate::breaker::StatusClass::Network, ERR_TYPE_SERVER_ERROR),
    ];
    for (class, want) in cases {
        let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
            class,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("error emits a chunk");
        assert_eq!(
            chunk["error"]["type"],
            serde_json::json!(want),
            "class={class:?}"
        );
        assert_eq!(chunk["error"]["message"], serde_json::json!("boom"));
        // Never the bogus literal "error".
        assert_ne!(chunk["error"]["type"], serde_json::json!("error")); // golden wire-contract literal (kept bare on purpose)
    }
}

// --- extract_error parses the body once, deriving both fields ---

#[test]
fn extract_error_derives_code_and_type_single_parse() {
    let body =
        br#"{"error":{"message":"nope","type":"invalid_request_error","code":"model_not_found"}}"#;
    let raw = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(raw.provider_code.as_deref(), Some("model_not_found"));
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(raw.http_status, 400);
    // Non-JSON body yields None for both, without panicking.
    let raw2 = OpenAiReader.extract_error(StatusCode::BAD_GATEWAY, b"<html>502</html>");
    assert!(raw2.provider_code.is_none());
    assert!(raw2.structured_type.is_none());
}

/// Regression: a context-length overflow signalled ONLY in the prose `message` with a
/// null `code` must still synthesize `provider_code = "context_length_exceeded"` so the breaker
/// pipeline triggers oversized-request failover instead of penalizing a healthy lane. Fails
/// against the old code, which keyed solely on the structured `code` and returned `None` here.
#[test]
fn extract_error_synthesizes_context_length_from_prose_message() {
    let body = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens. Please reduce the length of the messages.","type":"invalid_request_error","param":"messages","code":null}}"#;
    let raw = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a prose-only maximum-context-length message must synthesize the canonical code"
    );
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );

    // A structured code still takes precedence and is never overwritten by the message scan.
    let body2 = br#"{"error":{"message":"too long","type":"invalid_request_error","code":"context_length_exceeded"}}"#;
    let raw2 = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body2);
    assert_eq!(
        raw2.provider_code.as_deref(),
        Some("context_length_exceeded")
    );

    // An unrelated 400 with no context-length phrasing must NOT be misclassified as oversized.
    let body3 = br#"{"error":{"message":"invalid value for parameter temperature","type":"invalid_request_error","code":null}}"#;
    let raw3 = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, body3);
    assert!(
        raw3.provider_code.is_none(),
        "a non-context-length 400 must not be tagged context_length_exceeded"
    );
}

/// Regression: the context-length message scan was OVER-BROAD — it ORed weak tokens
/// `(token|context) && (too long|exceeds|maximum)`, so unrelated errors that merely mention a
/// `maximum` and a `token` (or are `too long` over some non-context budget) misclassified as
/// ContextLength and triggered a no-penalty failover. The fix requires a CO-LOCATED
/// context-length phrase and gates to the oversized HTTP statuses (mirroring openai_responses.rs /
/// anthropic.rs). These cases FAIL against the old OR-of-weak-tokens code.
#[test]
fn extract_error_context_length_scan_is_precise_no_false_positives() {
    // FALSE-POSITIVE GUARD 1: a per-day token QUOTA / rate-limit message pairs `maximum` with
    // `tokens` but is NOT a context overflow. Old code: matched. New code: must not.
    let quota = br#"{"error":{"message":"You have reached the maximum number of tokens allowed per day for this organization.","type":"insufficient_quota","code":null}}"#;
    let raw_quota = OpenAiReader.extract_error(StatusCode::TOO_MANY_REQUESTS, quota);
    assert!(
        raw_quota.provider_code.is_none(),
        "a token-quota rate-limit message must NOT be tagged context_length_exceeded"
    );

    // FALSE-POSITIVE GUARD 2: a generic 400 that mentions `token` and `exceeds` but NOT a
    // context phrase (`exceeds` co-located only with an unrelated noun). Old code matched on the
    // bare `token` + `exceeds` pair; new code requires `exceeds` near `context`/`token limit`.
    let generic = br#"{"error":{"message":"The provided JWT token exceeds the allowed audience set.","type":"invalid_request_error","code":null}}"#;
    let raw_generic = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, generic);
    assert!(
        raw_generic.provider_code.is_none(),
        "an unrelated `token`+`exceeds` message must NOT be tagged context_length_exceeded"
    );

    // FALSE-POSITIVE GUARD 3: even an EXPLICIT context-length phrase on a non-oversized status
    // (e.g. a 500 echoing a prior message) must not reclassify the failure as ContextLength.
    let wrong_status = br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"server_error","code":null}}"#;
    let raw_wrong = OpenAiReader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, wrong_status);
    assert!(
        raw_wrong.provider_code.is_none(),
        "a 5xx mentioning context length must NOT be reclassified as context_length_exceeded"
    );

    // TRUE POSITIVE 1: the canonical prose phrase on a 400 still synthesizes the code.
    let real = br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens.","type":"invalid_request_error","code":null}}"#;
    let raw_real = OpenAiReader.extract_error(StatusCode::BAD_REQUEST, real);
    assert_eq!(
        raw_real.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a real maximum-context-length 400 must still synthesize the canonical code"
    );

    // TRUE POSITIVE 2: a 413 payload-too-large carrying `exceeds`+`token limit` also synthesizes.
    let real_413 = br#"{"error":{"message":"Request exceeds the token limit for this model.","type":"invalid_request_error","code":null}}"#;
    let raw_413 = OpenAiReader.extract_error(StatusCode::PAYLOAD_TOO_LARGE, real_413);
    assert_eq!(
        raw_413.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 413 with `exceeds`+`token limit` must synthesize the canonical code"
    );
}

// --- non-text system blocks are projected explicitly, not silently dropped ---

#[test]
fn write_request_non_text_system_block_does_not_vanish_silently() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![
            text_block("be terse"),
            IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: "image/png".to_string(),
                    data: "AAAB".to_string(),
                },
                cache_control: None,
            },
        ],
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![text_block("hi")],
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages");
    // Both system blocks produce a system message (text forwarded, image projected to "").
    assert_eq!(msgs[0]["role"], serde_json::json!("system"));
    assert_eq!(msgs[0]["content"], serde_json::json!("be terse"));
    assert_eq!(msgs[1]["role"], serde_json::json!("system"));
    assert_eq!(msgs[1]["content"], serde_json::json!(""));
}

// --- synthesized ids must match the native length AND base62 alphabet ---

#[test]
fn synth_completion_id_matches_native_length_and_alphabet() {
    // Native OpenAI chat-completion ids are `chatcmpl-` + 24 base62 chars (33 chars total). A
    // too-short or wrong-alphabet suffix is an SDK-/tooling-visible proxy tell.
    let id = synth_completion_id();
    let suffix = id
        .strip_prefix("chatcmpl-") // golden wire-contract literal (kept bare on purpose)
        .expect("synthesized id has the chatcmpl- prefix");
    assert_eq!(
        suffix.len(),
        COMPLETION_ID_TOKEN_LEN,
        "suffix is exactly the native 24-char width: {id}"
    );
    assert_eq!(id.len(), "chatcmpl-".len() + 24, "total length is 33: {id}"); // golden wire-contract literal (kept bare on purpose)
                                                                              // Exactly one hyphen (the prefix's) — no internal field delimiter.
    assert_eq!(id.matches('-').count(), 1, "no internal delimiter: {id}");
    // Every suffix char is in the base62 alphabet [0-9A-Za-z].
    assert!(
        suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
        "suffix is base62: {id}"
    );
}

#[test]
fn synth_completion_id_burst_is_unique_and_unbiased() {
    // The base62 fill must use rejection sampling, not `byte % 62`. The old modulo
    // map gave residues 0..=7 (alphabet chars '0'..='7') 5/256 mass vs 4/256 for the other 54, a
    // ~25% over-representation that a uniform native vendor id never shows. This test mints a large
    // burst and asserts (a) every id is unique and (b) the leading-eight chars are NOT systematically
    // over-represented in the suffix histogram. Against the biased code the over-represented bucket
    // share would land far above the uniform expectation and trip the bound; the unbiased fill stays
    // within it.
    use std::collections::HashSet;
    const N: usize = 20_000;
    let mut seen = HashSet::with_capacity(N);
    // Count, over all suffix characters, how many fall in the formerly-over-represented set 0..=7.
    let mut low_bucket: u64 = 0;
    let mut total_chars: u64 = 0;
    for _ in 0..N {
        let id = synth_completion_id();
        assert_eq!(
            id.len(),
            "chatcmpl-".len() + COMPLETION_ID_TOKEN_LEN, // golden wire-contract literal (kept bare on purpose)
            "{id}"
        );
        let suffix = id
            .strip_prefix("chatcmpl-") // golden wire-contract literal (kept bare on purpose)
            .expect("synthesized id carries the chatcmpl- prefix");
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "suffix is base62: {id}"
        );
        for b in suffix.bytes() {
            total_chars += 1;
            // '0'..='7' are the eight chars residues 0..=7 map to under the alphabet.
            if (b'0'..=b'7').contains(&b) {
                low_bucket += 1;
            }
        }
        assert!(seen.insert(id.clone()), "duplicate synthesized id: {id}");
    }
    assert_eq!(seen.len(), N, "all {N} synthesized ids are unique");
    // Uniform expectation: 8 of 62 alphabet chars => 8/62 ≈ 12.90% of characters.
    // Biased (old) expectation: 8 * (5/256) ≈ 15.63%. We assert the observed share stays below a
    // 14% threshold — comfortably above the uniform mean (sampling noise over ~480k chars is tiny)
    // and comfortably below the biased mean, so the test fails on the old code and passes on the new.
    let share = low_bucket as f64 / total_chars as f64;
    assert!(
        share < 0.14,
        "char share for residues 0..=7 was {share:.4}; uniform≈0.1290, biased≈0.1563 — \
             a value at/above 0.14 indicates `byte % 62` bias regressed"
    );
}

#[test]
fn synth_completion_id_unique_even_with_identical_entropy() {
    // The monotonic counter guarantees uniqueness independent of the RNG: minting many ids in a
    // tight loop (where the timestamp does not advance) must never collide. The counter is folded
    // MSB-first into the leading chars, so adjacent ids differ in those positions.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        let id = synth_completion_id();
        assert_eq!(id.len(), "chatcmpl-".len() + 24); // golden wire-contract literal (kept bare on purpose)
        assert!(seen.insert(id.clone()), "duplicate synthesized id: {id}");
    }
}

// --- streaming MessageDelta with no stop_reason emits finish_reason null ---

#[test]
fn stream_message_delta_none_stop_reason_serializes_null_not_empty_string() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: None,
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("message delta emits a chunk");
    let fr = &chunk["choices"][0]["finish_reason"];
    // Must be JSON null, never the empty string (a non-spec value strict SDKs reject).
    assert_eq!(*fr, serde_json::Value::Null);
    assert_ne!(*fr, serde_json::json!(""));
}

#[test]
fn stream_message_delta_maps_stop_reasons_to_openai_enum() {
    use crate::ir::IrStopReason as S;
    let cases = [
        (Some(S::EndTurn), serde_json::json!("stop")),
        (Some(S::StopSequence), serde_json::json!("stop")),
        (Some(S::MaxTokens), serde_json::json!("length")),
        (Some(S::ToolUse), serde_json::json!("tool_calls")),
        (Some(S::Safety), serde_json::json!("content_filter")),
    ];
    for (stop_reason, want) in cases {
        let ev = IrStreamEvent::MessageDelta {
            stop_reason,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, chunk) = OpenAiWriter
            .write_response_event(&ev)
            .expect("message delta emits a chunk");
        assert_eq!(
            chunk["choices"][0]["finish_reason"], want,
            "stop_reason={stop_reason:?}"
        );
    }
}

// --- ToolResult block on a non-tool message is not emitted as content,
//     and the match has no `_ =>` catch-all (compile-time exhaustiveness is the real guard) ---

#[test]
fn write_request_assistant_tool_result_block_not_emitted_as_content() {
    // A ToolResult must never leak into the message *content* array on any role. The
    // ToolResult ALSO surfaces as a flat `{"role":"tool",...}` entry regardless of role (a
    // Gemini/Anthropic tool result rides on a non-Tool message), so this asserts both: the content
    // array carries only the text block, and a separate tool message carries the result.
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Assistant,
            content: vec![
                text_block("answer"),
                IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![text_block("ignored")],
                    is_error: false,
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
    let out = OpenAiWriter.write_request(&req);
    let msgs = out["messages"].as_array().expect("messages array");
    // The assistant message: its content array carries ONLY the text block, never the ToolResult.
    let assistant = msgs
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant message present");
    let content = assistant["content"]
        .as_array()
        .expect("assistant content array");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], serde_json::json!("text"));
    assert_eq!(content[0]["text"], serde_json::json!("answer"));
    // The ToolResult surfaces as a separate flat tool entry, not silently dropped.
    let tool_msg = msgs
        .iter()
        .find(|m| m["role"] == "tool")
        .expect("ToolResult must surface as a flat tool message");
    assert_eq!(tool_msg["tool_call_id"], serde_json::json!("t1"));
    assert_eq!(tool_msg["content"], serde_json::json!("ignored"));
}

#[test]
fn write_request_thinking_block_dropped_from_message_content() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Assistant,
            content: vec![
                IrBlock::Thinking {
                    text: "secret reasoning".to_string(),
                    signature: None,
                    redacted: false,
                    cache_control: None,
                },
                text_block("visible"),
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
    let out = OpenAiWriter.write_request(&req);
    let content = out["messages"][0]["content"]
        .as_array()
        .expect("content array");
    // Thinking is lossy on OpenAI; only the text block is emitted.
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["text"], serde_json::json!("visible"));
}

// --- array content with unwrap-free parse still reads every block ---

#[test]
fn read_request_array_content_reads_all_blocks() {
    let body = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [
                { "type": "text", "text": "one" },
                { "type": "text", "text": "two" }
            ]
        }]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.messages.len(), 1);
    assert_eq!(
        ir.messages[0].content,
        vec![text_block("one"), text_block("two")]
    );
}

#[test]
fn read_response_empty_string_content_yields_no_text_block() {
    // An empty-string content must not produce a Text block (the unwrap-free path preserves the
    // prior emptiness guard).
    let body = serde_json::json!({
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": ""},
            "finish_reason": FINISH_STOP
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 0}
    });
    let ir = OpenAiReader.read_response(&body).expect("read_response");
    assert!(ir
        .content
        .iter()
        .all(|b| !matches!(b, IrBlock::Text { .. })));
}

// --- trailing usage-only stream chunk is captured, not discarded ---

#[test]
fn stream_trailing_usage_only_chunk_emits_message_delta_with_usage() {
    // include_usage convention: a SEPARATE trailing chunk carries top-level `usage` with an
    // EMPTY `choices` array and no finish_reason. The prior code read usage only inside the
    // finish_reason branch, so this chunk's usage was silently dropped. It must now surface as a
    // MessageDelta carrying the real token counts.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    // Prime the stream with a normal first chunk so `started` is set (MessageStart already out).
    let _ = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-u1",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": null}]
        }),
        &mut st,
    );
    // Trailing usage-only chunk: empty choices, no finish_reason, top-level usage present.
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-u1",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "prompt_tokens_details": { "cached_tokens": 3 }
            }
        }),
        &mut st,
    );
    let delta = evs
        .iter()
        .find(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
        .expect("trailing usage chunk yields a MessageDelta");
    match delta {
        IrStreamEvent::MessageDelta {
            stop_reason,
            stop_sequence,
            usage,
        } => {
            // In-progress finish per the chunk shape (no finish_reason on a usage-only chunk).
            assert_eq!(*stop_reason, None);
            assert_eq!(*stop_sequence, None);
            // A2 normalization: input_tokens is UNCACHED (prompt_tokens 11 - cached 3 = 8);
            // cache_read carries the cached prefix additively.
            assert_eq!(usage.input_tokens, 8);
            assert_eq!(usage.output_tokens, 7);
            assert_eq!(usage.cache_read_input_tokens, Some(3));
        }
        _ => unreachable!(),
    }
    // A usage-only chunk must NOT terminate the message (the finish chunk / [DONE] does that).
    assert!(!evs.iter().any(|e| matches!(e, IrStreamEvent::MessageStop)));
}

#[test]
fn stream_usage_on_finish_chunk_still_captured() {
    // The combined case (usage present on the finish_reason chunk) must keep working: usage
    // flows into the terminal MessageDelta and a MessageStop closes the message.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-u2",
            "created": 1_700_000_001u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_STOP}],
            "usage": { "prompt_tokens": 5, "completion_tokens": 2 }
        }),
        &mut st,
    );
    let delta = evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => Some((*stop_reason, usage.clone())),
            _ => None,
        })
        .expect("finish chunk yields a MessageDelta");
    assert_eq!(delta.0, Some(crate::ir::IrStopReason::EndTurn));
    assert_eq!(delta.1.input_tokens, 5);
    assert_eq!(delta.1.output_tokens, 2);
    assert!(evs.iter().any(|e| matches!(e, IrStreamEvent::MessageStop)));
}

// --- in-stream Error envelope includes code/param null ---

#[test]
fn stream_error_envelope_includes_null_code_and_param() {
    // The in-stream error body must match the native OpenAI shape (and this writer's non-stream
    // `write_error`): error.{message,type,code,param} with code/param JSON null.
    let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::RateLimit,
        provider_signal: Some("slow down".to_string()),
        retry_after: None,
    });
    let (_, chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("error emits a chunk");
    assert_eq!(chunk["error"]["message"], serde_json::json!("slow down"));
    assert_eq!(
        chunk["error"]["type"],
        serde_json::json!("rate_limit_error") // golden wire-contract literal (kept bare on purpose)
    );
    // The two fields the prior code omitted, present and explicitly null.
    assert_eq!(chunk["error"]["code"], serde_json::Value::Null);
    assert_eq!(chunk["error"]["param"], serde_json::Value::Null);
    // And present as KEYS (null value), not merely absent — strict destructuring relies on this.
    let err_obj = chunk["error"].as_object().expect("error object");
    assert!(err_obj.contains_key("code"));
    assert!(err_obj.contains_key("param"));
}

#[test]
fn stream_error_shape_matches_write_error_shape() {
    // The set of keys in the in-stream error object must equal the non-stream `write_error`
    // envelope's key set — a divergence is itself a detectable proxy tell.
    let ev = IrStreamEvent::Error(crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::Auth,
        provider_signal: Some("nope".to_string()),
        retry_after: None,
    });
    let (_, stream_chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("error emits a chunk");
    let non_stream = OpenAiWriter.write_error(401, "auth", "nope");
    let mut stream_keys: Vec<&String> = stream_chunk["error"]
        .as_object()
        .expect("stream error object")
        .keys()
        .collect();
    let mut non_stream_keys: Vec<&String> = non_stream["error"]
        .as_object()
        .expect("non-stream error object")
        .keys()
        .collect();
    stream_keys.sort();
    non_stream_keys.sort();
    assert_eq!(stream_keys, non_stream_keys);
}

// --- non-stream write_response always emits finish_reason ---

#[test]
fn write_response_emits_null_finish_reason_when_stop_reason_none() {
    // A cross-protocol response whose upstream provided no stop reason (stop_reason: None) must
    // still carry a `finish_reason` KEY, serialized as JSON null — never omitted.
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("partial")],
        stop_reason: None,
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
    let out = OpenAiWriter.write_response(&resp);
    let choice = out["choices"][0].as_object().expect("choice object");
    assert!(
        choice.contains_key("finish_reason"),
        "finish_reason key must always be present"
    );
    assert_eq!(choice["finish_reason"], serde_json::Value::Null);
}

#[test]
fn write_response_maps_finish_reason_enum_values() {
    use crate::ir::IrStopReason as S;
    let cases = [
        (Some(S::EndTurn), serde_json::json!("stop")),
        (Some(S::StopSequence), serde_json::json!("stop")),
        (Some(S::MaxTokens), serde_json::json!("length")),
        (Some(S::ToolUse), serde_json::json!("tool_calls")),
        (Some(S::Safety), serde_json::json!("content_filter")),
        // Reasons with no OpenAI analog must degrade to the SDK-safe `stop`, never leak into the
        // closed `finish_reason` enum (F2 conformance fix).
        (Some(S::Refusal), serde_json::json!("stop")),
        (Some(S::Error), serde_json::json!("stop")),
        (Some(S::PauseTurn), serde_json::json!("stop")),
        (None, serde_json::Value::Null),
    ];
    for (stop_reason, want) in cases {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: IrRole::Assistant,
            content: vec![text_block("x")],
            stop_reason,
            usage: IrUsage {
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
        };
        let out = OpenAiWriter.write_response(&resp);
        assert_eq!(
            out["choices"][0]["finish_reason"], want,
            "stop_reason={stop_reason:?}"
        );
    }
}

// --- streaming tool-call index must not overflow the IR index ---

#[test]
fn stream_tool_call_index_u64_max_does_not_panic_or_wrap() {
    // A crafted/proxied chunk with `"index": u64::MAX` must not panic (debug) or wrap to a
    // near-zero IR index (release). The index is clamped to MAX_TOOL_INDEX before the
    // `oai_idx + text_base + offset` arithmetic, so the emitted BlockStart index stays bounded.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-ov",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": u64::MAX,
                    "id": "call_x",
                    "function": { "name": "f", "arguments": "{}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    // A BlockStart is emitted with a bounded index (clamped 127, no text block so text_base=0,
    // no thinking offset), never wrapping to a tiny value.
    let start_idx = evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart { index, .. } => Some(*index),
            _ => None,
        })
        .expect("clamped tool-call still opens a block");
    assert_eq!(start_idx, MAX_TOOL_INDEX as usize);
    // The matching argument delta routes to the same bounded index.
    let delta_idx = evs.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            index,
            delta: IrDelta::InputJsonDelta(_),
        } => Some(*index),
        _ => None,
    });
    assert_eq!(delta_idx, Some(start_idx));
}

#[test]
fn stream_tool_call_index_close_does_not_overflow_on_finish() {
    // The finish-path close loop computes the same `oai_idx + text_base + offset`; with a
    // clamped index it must close at the matching bounded IR index without panicking/wrapping.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let _ = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-c",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": u64::MAX,
                    "id": "call_y",
                    "function": { "name": "g", "arguments": "{}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-c",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_TOOL_CALLS}]
        }),
        &mut st,
    );
    let stop_idx = evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        })
        .expect("open tool block is closed on finish");
    assert_eq!(stop_idx, MAX_TOOL_INDEX as usize);
}

/// C3: when a tool opens BEFORE any text, then text arrives, a later tool-argument delta must be
/// emitted at the IR index the tool's BlockStart was RECORDED with (`tool_ir_index`), NOT a
/// recomputed `ir_idx` (which shifts once text is present). Emitting at the recomputed index would
/// point the arg JSON at the wrong block and corrupt the tool call cross-protocol.
#[test]
fn stream_tool_arg_delta_uses_recorded_block_start_index() {
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    // Chunk 1: tool opens first (claims its BlockStart IR index, recorded in tool_ir_index).
    let open_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-c3", "created": 1_700_000_000u64, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "id": "call_a",
                "function": {"name": "f", "arguments": ""}
            }]}, "finish_reason": null}]
        }),
        &mut st,
    );
    let tool_start_idx = open_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: crate::ir::IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .expect("tool BlockStart");
    // Chunk 2: text arrives AFTER the tool opened (shifts the recomputed tool base).
    let _ = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-c3", "created": 1_700_000_000u64, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": null}]
        }),
        &mut st,
    );
    // Chunk 3: more tool args for the SAME tool (oai index 0).
    let arg_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-c3", "created": 1_700_000_000u64, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0,
                "function": {"arguments": "{\"x\":1}"}
            }]}, "finish_reason": null}]
        }),
        &mut st,
    );
    let arg_idx = arg_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::InputJsonDelta(_),
            } => Some(*index),
            _ => None,
        })
        .expect("tool arg InputJsonDelta");
    assert_eq!(
        arg_idx, tool_start_idx,
        "C3: arg delta must land at the recorded BlockStart index ({tool_start_idx}), not a \
             recomputed index ({arg_idx})"
    );
}

// --- tool-call IR indices reserve a text slot ONLY when text appears (cross-protocol sibling
//     of the Cohere dynamic-text-index fix). Under the old unconditional `+1` text base, a
//     tool-only stream emitted 1-based tool indices, breaking cross-protocol tool-call ordering
//     for writers that key on the IR block index.

#[test]
fn stream_tool_only_yields_zero_based_tool_indices() {
    // No text block ever opens, so the first tool call must claim IR index 0 (text_base = 0),
    // NOT index 1. Fails against the old `oai_idx + 1 + offset` arithmetic.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let start_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-to",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": 0,
                    "id": "call_a",
                    "function": { "name": "f", "arguments": "{\"x\":1}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let start_idx = start_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .expect("tool-only stream opens a tool block");
    assert_eq!(
        start_idx, 0,
        "tool-only stream must be 0-based, not 1-based"
    );
    // Argument delta routes to the same 0 index.
    let delta_idx = start_evs.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            index,
            delta: IrDelta::InputJsonDelta(_),
        } => Some(*index),
        _ => None,
    });
    assert_eq!(delta_idx, Some(0));
    // ...and the finish-path BlockStop closes at the SAME 0 index.
    let finish_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-to",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_TOOL_CALLS}]
        }),
        &mut st,
    );
    let stop_idx = finish_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        })
        .expect("tool block is closed on finish");
    assert_eq!(
        stop_idx, 0,
        "tool BlockStop must pair with its 0-based start"
    );
}

#[test]
fn stream_text_then_tool_keeps_text_at_zero_tool_after() {
    // A text+tool stream keeps text at index 0 and places the tool at index 1 (text_base = 1).
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    // Text first → opens at index 0.
    let text_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tt",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "content": "hello" },
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let text_idx = text_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::Text,
            } => Some(*index),
            _ => None,
        })
        .expect("text block opens");
    assert_eq!(text_idx, 0, "text owns index 0");
    // Then a tool call → must open at index 1 (just past the text block).
    let tool_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tt",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": 0,
                    "id": "call_b",
                    "function": { "name": "g", "arguments": "{}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let tool_idx = tool_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .expect("tool block opens after text");
    assert_eq!(tool_idx, 1, "tool follows the text block at index 1");
    // Finish closes text at 0 and the tool at 1.
    let finish_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tt",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_TOOL_CALLS}]
        }),
        &mut st,
    );
    let stops: Vec<usize> = finish_evs
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        })
        .collect();
    assert!(stops.contains(&0), "text BlockStop at 0: {stops:?}");
    assert!(stops.contains(&1), "tool BlockStop at 1: {stops:?}");
}

// --- tool_call FIRST, then text, then finish. Text must not collide with the already-open
//     tool's index, and every BlockStart must pair with a BlockStop at the SAME index
//     (the finish-path close must not recompute a divergent base). ---

#[test]
fn stream_tool_then_text_no_index_collision_and_stops_pair() {
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();

    // Tool call FIRST (oai index 0) → opens at IR index 0 (no text seen yet, so text_base = 0).
    let tool_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tf",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": 0,
                    "id": "call_a",
                    "function": { "name": "f", "arguments": "{}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let tool_idx = tool_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .expect("tool block opens first");
    assert_eq!(tool_idx, 0, "tool-first claims index 0");

    // Text arrives AFTER the tool. It must NOT reuse index 0 (the tool holds it); it lands just
    // past the open tools at index 1.
    let text_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tf",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "content": "hello" },
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let text_idx = text_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::Text,
            } => Some(*index),
            _ => None,
        })
        .expect("text block opens after tool");
    assert_eq!(
        text_idx, 1,
        "text lands past the open tool, not colliding at 0"
    );
    assert_ne!(text_idx, tool_idx, "text and tool must not share an index");

    // A second tool (oai index 1) arrives after text → text_base is now 1, so it lands at
    // index 1 + 1 = 2 (no collision with text at 1 or tool0 at 0).
    let tool2_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tf",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{
                    "index": 1,
                    "id": "call_b",
                    "function": { "name": "g", "arguments": "{}" }
                }]},
                "finish_reason": null
            }]
        }),
        &mut st,
    );
    let tool2_idx = tool2_evs
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .expect("second tool opens");
    assert_eq!(tool2_idx, 2, "second tool lands past text");

    // Finish: every BlockStart index emitted above must be matched by a BlockStop at the SAME
    // index. The old finish-path recomputed text_base (now 1, since text is present) and applied
    // it to the FIRST tool — pushing its BlockStop to index 1 (tool0 opened at 0) and clobbering
    // text's stop, so the multiset of stops diverged from the starts.
    let finish_evs = reader.read_response_events(
        "",
        &serde_json::json!({
            "id": "chatcmpl-tf",
            "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_TOOL_CALLS}]
        }),
        &mut st,
    );
    let mut stops: Vec<usize> = finish_evs
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        })
        .collect();
    stops.sort_unstable();
    // tool0 → 0, text → 1, tool1 → 2: each opened block closed exactly once at its open index.
    assert_eq!(
        stops,
        vec![0, 1, 2],
        "every BlockStart pairs with a BlockStop at the same index: {stops:?}"
    );
}

// --- open_tools cardinality is capped per stream ---

#[test]
fn stream_open_tools_is_capped() {
    // A pathological backend emitting many unique tool-call indices must not grow `open_tools`
    // (or the BlockStart count) without bound. After feeding more than MAX_OPEN_TOOLS distinct
    // indices, the tracked set is capped and no further BlockStart events are emitted.
    let reader = OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let mut block_starts = 0usize;
    for i in 0..(MAX_OPEN_TOOLS as u64 + 50) {
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "id": "chatcmpl-cap",
                "created": 1_700_000_000u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "tool_calls": [{
                        // Distinct indices, all within the clamp ceiling so the cap (not the
                        // clamp) is what limits growth here.
                        "index": i.min(MAX_TOOL_INDEX),
                        "id": format!("call_{i}"),
                        "function": { "name": "f", "arguments": "{}" }
                    }]},
                    "finish_reason": null
                }]
            }),
            &mut st,
        );
        block_starts += evs
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
            .count();
    }
    // The set never exceeds the cap...
    assert!(st.open_tools.len() <= MAX_OPEN_TOOLS);
    // ...and the number of distinct opened blocks is bounded by the clamp ceiling (indices were
    // saturated at MAX_TOOL_INDEX, so the distinct count is MAX_TOOL_INDEX + 1 = 128 = the cap).
    assert!(block_starts <= MAX_OPEN_TOOLS);
}

// --- synthetic chatcmpl id must not carry an internal field-separator hyphen.

#[test]
fn synth_completion_id_has_single_hyphen_after_prefix() {
    let id = synth_completion_id();
    assert!(
        id.starts_with("chatcmpl-"), // golden wire-contract literal (kept bare on purpose)
        "id must keep the native prefix: {id}"
    );
    // Native ids have exactly one hyphen (the one in `chatcmpl-`); the token after the prefix is
    // pure base62 with no internal delimiter. An extra hyphen is a structural proxy tell.
    assert_eq!(
        id.matches('-').count(),
        1,
        "synthetic id has an internal field separator: {id}"
    );
    let token = id.strip_prefix("chatcmpl-").expect("prefix present"); // golden wire-contract literal (kept bare on purpose)
    assert!(!token.is_empty(), "token after prefix must be non-empty");
    assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric()),
        "token must be base62 ([0-9A-Za-z]), got: {token}"
    );
}

#[test]
fn synth_completion_ids_are_distinct_within_process() {
    // The monotonic atomic counter alone guarantees distinctness even when minted back-to-back
    // within the same second (where the timestamp field is identical).
    let a = synth_completion_id();
    let b = synth_completion_id();
    assert_ne!(a, b);
}

// --- OpenAI tool-message content given as an array of parts must not be dropped.

#[test]
fn read_request_reads_array_form_tool_message_content() {
    let body = serde_json::json!({
        "model": "gpt-x",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_42",
                "content": [
                    { "type": "text", "text": "part one " },
                    { "type": "text", "text": "part two" }
                ]
            }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == IrRole::Tool)
        .expect("tool message present");
    let result = tool_msg
        .content
        .iter()
        .find_map(|b| match b {
            IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => Some((tool_use_id.clone(), content.clone())),
            _ => None,
        })
        .expect("tool result block present");
    assert_eq!(result.0, "call_42");
    // The array parts are concatenated; the prior string-only path collapsed this to "".
    assert_eq!(result.1, vec![text_block("part one part two")]);
}

#[test]
fn read_request_reads_string_form_tool_message_content() {
    let body = serde_json::json!({
        "model": "gpt-x",
        "messages": [
            { "role": "tool", "tool_call_id": "call_7", "content": "plain string" }
        ]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == IrRole::Tool)
        .expect("tool message present");
    let content = tool_msg
        .content
        .iter()
        .find_map(|b| match b {
            IrBlock::ToolResult { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool result block present");
    assert_eq!(content, vec![text_block("plain string")]);
}

// --- a bad-key 401 must emit `code: "invalid_api_key"`, not `code: null`.

#[test]
fn write_error_emits_invalid_api_key_code_for_auth_failure() {
    let w = OpenAiWriter;
    let body = w.write_error(401, ERR_TYPE_AUTHENTICATION, "Incorrect API key provided");
    assert_eq!(
        body["error"]["type"],
        serde_json::json!("authentication_error") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(body["error"]["code"], serde_json::json!("invalid_api_key"));
    assert_eq!(body["error"]["param"], serde_json::Value::Null);
}

#[test]
fn write_error_keeps_null_code_for_non_auth_errors() {
    let w = OpenAiWriter;
    for (status, kind) in [
        (400u16, ERR_TYPE_INVALID_REQUEST),
        (429, ERR_TYPE_RATE_LIMIT),
        (500, ERR_TYPE_SERVER_ERROR),
    ] {
        let body = w.write_error(status, kind, "boom");
        assert_eq!(
            body["error"]["code"],
            serde_json::Value::Null,
            "non-auth error must keep code: null (kind={kind})"
        );
    }
}

#[test]
fn stream_error_auth_event_carries_invalid_api_key_code() {
    let w = OpenAiWriter;
    let ev = IrStreamEvent::Error(IrError {
        class: crate::breaker::StatusClass::Auth,
        provider_signal: Some("bad key".to_string()),
        retry_after: None,
    });
    let (_, chunk) = w
        .write_response_event(&ev)
        .expect("error event emits a body");
    assert_eq!(
        chunk["error"]["type"],
        serde_json::json!("authentication_error") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(chunk["error"]["code"], serde_json::json!("invalid_api_key"));
}

// --- streaming Billing error -> insufficient_quota (type AND code), not permission_error ---

#[test]
fn stream_error_billing_event_maps_to_insufficient_quota() {
    let w = OpenAiWriter;
    let ev = IrStreamEvent::Error(IrError {
        class: crate::breaker::StatusClass::Billing,
        provider_signal: Some("over quota".to_string()),
        retry_after: None,
    });
    let (_, chunk) = w
        .write_response_event(&ev)
        .expect("error event emits a body");
    // Quota exhaustion is `insufficient_quota`, NOT the access-control `permission_error`.
    assert_eq!(
        chunk["error"]["type"],
        serde_json::json!("insufficient_quota") // golden wire-contract literal (kept bare on purpose)
    );
    assert_ne!(
        chunk["error"]["type"],
        serde_json::json!("permission_error") // golden wire-contract literal (kept bare on purpose)
    );
    // Native OpenAI pairs the matching machine-readable code.
    assert_eq!(
        chunk["error"]["code"],
        serde_json::json!("insufficient_quota") // golden wire-contract literal (kept bare on purpose)
    );
    // The streaming Billing mapping matches the non-stream `write_error("insufficient_quota")`.
    let non_stream = w.write_error(429, ERR_TYPE_INSUFFICIENT_QUOTA, "over quota");
    assert_eq!(
        chunk["error"]["type"], non_stream["error"]["type"],
        "stream and non-stream billing type must agree"
    );
    assert_eq!(
        chunk["error"]["code"], non_stream["error"]["code"],
        "stream and non-stream billing code must agree"
    );
}

// --- terminal MessageDelta carries real token usage on a translated stream ---

#[test]
fn stream_message_delta_emits_usage_when_counts_nonzero() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 12,
            output_tokens: 34,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("message delta emits a chunk");
    // finish_reason still maps correctly...
    assert_eq!(
        chunk["choices"][0]["finish_reason"],
        serde_json::json!("stop")
    );
    // ...and the terminal chunk now carries native-shaped token usage instead of dropping it.
    assert_eq!(chunk["usage"]["prompt_tokens"], serde_json::json!(12));
    assert_eq!(chunk["usage"]["completion_tokens"], serde_json::json!(34));
    assert_eq!(chunk["usage"]["total_tokens"], serde_json::json!(46));
}

#[test]
fn stream_message_delta_omits_usage_when_all_counts_zero() {
    // A same-protocol passthrough without include_usage carries zeroed usage in the IR; do not
    // stamp a usage object onto a stream that never asked for one.
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("message delta emits a chunk");
    assert!(
        chunk.get("usage").is_none(),
        "zero usage must not emit a usage object: {chunk}"
    );
}

// --- tool objects must use the nested Chat Completions shape ---

fn req_with_tool(
    input_schema: serde_json::Value,
    description: Option<&str>,
) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: Vec::new(),
        tools: vec![crate::ir::IrTool {
            name: "get_weather".to_string(),
            description: description.map(String::from),
            input_schema,
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
    }
}

#[test]
fn write_request_tools_use_nested_function_shape() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"city": {"type": "string"}}
    });
    let req = req_with_tool(schema.clone(), Some("Look up the weather"));
    let out = OpenAiWriter.write_request(&req);
    let tool = &out["tools"][0];
    // Native Chat Completions shape: {"type":"function","function":{name,description,parameters}}.
    assert_eq!(tool["type"], serde_json::json!("function")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(tool["function"]["name"], serde_json::json!("get_weather"));
    assert_eq!(
        tool["function"]["description"],
        serde_json::json!("Look up the weather")
    );
    assert_eq!(tool["function"]["parameters"], schema);
    // name/parameters/description must NOT appear flat at the top level (the off-spec shape).
    assert!(tool.get("name").is_none(), "name must not be flat");
    assert!(
        tool.get("parameters").is_none(),
        "parameters must not be flat"
    );
    assert!(
        tool.get("description").is_none(),
        "description must not be flat"
    );
}

#[test]
fn write_request_tool_round_trips_through_read_openai_tool() {
    // The writer's nested output must be readable by the reader (writer is the reader's inverse).
    let schema = serde_json::json!({"type": "object"});
    let req = req_with_tool(schema.clone(), Some("desc"));
    let out = OpenAiWriter.write_request(&req);
    let ir = read_openai_tool(&out["tools"][0]).expect("nested tool parses");
    assert_eq!(ir.name, "get_weather");
    assert_eq!(ir.description.as_deref(), Some("desc"));
    assert_eq!(ir.input_schema, schema);
}

#[test]
fn write_request_tool_without_description_omits_it_inside_function() {
    let req = req_with_tool(serde_json::json!({"type": "object"}), None);
    let out = OpenAiWriter.write_request(&req);
    let func = &out["tools"][0]["function"];
    assert!(func.get("description").is_none());
    // parameters always present (defaults to {} when schema is null) inside `function`.
    assert!(func.get("parameters").is_some());
}

#[test]
fn write_request_tool_null_schema_defaults_to_empty_object_in_function() {
    let req = req_with_tool(serde_json::Value::Null, None);
    let out = OpenAiWriter.write_request(&req);
    assert_eq!(
        out["tools"][0]["function"]["parameters"],
        serde_json::json!({})
    );
}

// --- overloaded kind maps to a native OpenAI error type (503 = server_error) ---

#[test]
fn write_error_overloaded_maps_to_server_error() {
    // The all-lanes-exhausted / request-timeout 503 path passes kind "overloaded" to every
    // ingress writer; OpenAI has no "overloaded" type, so it must map to native server_error.
    for kind in [
        "overloaded",
        ERR_TYPE_OVERLOADED,
        "service_unavailable",
        "unavailable",
        "transient",
        "timeout",
        "network",
        "5xx",
    ] {
        let v = OpenAiWriter.write_error(503, kind, "Service overloaded");
        assert_eq!(
            v["error"]["type"],
            serde_json::json!("server_error"), // golden wire-contract literal (kept bare on purpose)
            "kind={kind} must map to server_error"
        );
        // No Anthropic-vocabulary leak: the literal token must never appear as the type.
        assert_ne!(v["error"]["type"], serde_json::json!("overloaded"));
        assert_eq!(v["error"]["code"], serde_json::Value::Null);
    }
}

#[test]
fn write_error_insufficient_quota_keeps_type_and_sets_code() {
    // The over-budget governance path passes "insufficient_quota"; real OpenAI sets BOTH the type
    // and the code to that value.
    let v = OpenAiWriter.write_error(429, ERR_TYPE_INSUFFICIENT_QUOTA, "quota exceeded");
    assert_eq!(v["error"]["type"], serde_json::json!("insufficient_quota")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(v["error"]["code"], serde_json::json!("insufficient_quota"));
    // golden wire-contract literal (kept bare on purpose)
}

// --- refusal content blocks degrade gracefully instead of erroring ---

#[test]
fn read_openai_block_refusal_maps_to_text() {
    let block = serde_json::json!({"type": "refusal", "refusal": "I cannot help with that."});
    let ir = read_openai_block(&block).expect("refusal must not error");
    match ir {
        crate::ir::IrBlock::Text { text, .. } => {
            assert_eq!(text, "I cannot help with that.")
        }
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn read_openai_block_unknown_type_degrades_to_empty_text() {
    // A future/unknown content-part type must not break otherwise-valid history.
    let block = serde_json::json!({"type": "some_future_part", "foo": "bar"});
    let ir = read_openai_block(&block).expect("unknown type must degrade, not error");
    match ir {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, ""),
        other => panic!("expected empty Text, got {other:?}"),
    }
}

// --- finish_reason normalization (content_filter -> safety, function_call -> tool_use) ---

fn response_with_finish(finish: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-x",
        "object": OBJ_COMPLETION,
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": finish
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    })
}

#[test]
fn read_response_normalizes_content_filter_to_safety() {
    let ir = OpenAiReader
        .read_response(&response_with_finish(FINISH_CONTENT_FILTER))
        .expect("parses");
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::Safety));
}

#[test]
fn read_response_normalizes_function_call_to_tool_use() {
    let ir = OpenAiReader
        .read_response(&response_with_finish(FINISH_FUNCTION_CALL))
        .expect("parses");
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
}

#[test]
fn write_response_safety_round_trips_to_content_filter() {
    // The canonical `safety` token must serialize back to OpenAI's native `content_filter`.
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hi")],
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        usage: IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("gpt-4o".to_string()),
        id: Some("chatcmpl-x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(
        out["choices"][0]["finish_reason"],
        serde_json::json!("content_filter")
    );
}

#[test]
fn stream_message_delta_safety_round_trips_to_content_filter() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        stop_sequence: None,
        usage: IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, chunk) = OpenAiWriter
        .write_response_event(&ev)
        .expect("message delta emits a chunk");
    assert_eq!(
        chunk["choices"][0]["finish_reason"],
        serde_json::json!("content_filter")
    );
}

#[test]
fn stream_read_normalizes_content_filter_to_safety() {
    let chunk = serde_json::json!({
        "id": "chatcmpl-x",
        "object": OBJ_CHUNK,
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {}, "finish_reason": FINISH_CONTENT_FILTER}]
    });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = OpenAiReader.read_response_events("", &chunk, &mut state);
    let stop = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
        _ => None,
    });
    assert_eq!(stop, Some(crate::ir::IrStopReason::Safety));
}

// Regression: the singular `read_response_event` must not be a dead `None` stub that silently
// drops every event. It now delegates to the fan-out and surfaces the first IR event, so a
// chunk that carries a role delta yields a MessageStart rather than vanishing.
#[test]
fn singular_read_response_event_delegates_to_fanout() {
    let chunk = serde_json::json!({
        "id": "chatcmpl-x",
        "object": OBJ_CHUNK,
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
    });
    let ev = OpenAiReader.read_response_event("", &chunk);
    assert!(
        matches!(ev, Some(IrStreamEvent::MessageStart { .. })),
        "singular event must surface the fan-out's first event, got {ev:?}"
    );
}

// Regression: a chunk that produces no IR events (the `[DONE]` sentinel) yields None from the
// singular adapter — confirming the delegation is faithful at the empty boundary.
#[test]
fn singular_read_response_event_empty_chunk_yields_none() {
    let done = serde_json::Value::String(crate::proto::SSE_DONE_SENTINEL.to_string());
    assert!(OpenAiReader.read_response_event("", &done).is_none());
}

// Regression (HIGH): under `stream_options:{include_usage:true}` the OpenAI API sets
// `usage: null` on EVERY non-final chunk. `Value::get("usage")` returns `Some(Null)` for that,
// so without the object-filter the reader synthesized `Some(IrUsage{0,..})` and emitted a
// spurious mid-stream `MessageDelta` on every content chunk. A content chunk carrying
// `usage: null` must yield only the text events — NO MessageDelta.
#[test]
fn null_usage_on_content_chunk_emits_no_message_delta() {
    let mut state = crate::ir::StreamDecodeState::default();
    let chunk = serde_json::json!({
        "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": null}],
        "usage": null
    });
    let evs = OpenAiReader.read_response_events("", &chunk, &mut state);
    assert!(
        !evs.iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "usage:null content chunk must not emit a MessageDelta, got {evs:?}"
    );
    assert!(
            evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta { delta: crate::ir::IrDelta::TextDelta(t), .. } if t == "hello"
            )),
            "text content must still decode, got {evs:?}"
        );
}

// Regression (MEDIUM): the reader is ingress-AGNOSTIC, so it must faithfully translate the
// trailing `include_usage` usage-only chunk (empty `choices`, real top-level `usage`) into a
// `MessageDelta{stop_reason: None, usage}` carrying the REAL token counts — Bedrock ingress folds
// exactly this into its single `metadata` frame. (The cross-protocol ORDERING concern — this
// delta arriving after the finish chunk's `MessageStop` — is handled in `StreamTranslate` for
// non-eventstream ingress, not here.)
#[test]
fn trailing_usage_only_chunk_emits_message_delta_with_real_tokens() {
    let mut state = crate::ir::StreamDecodeState::default();
    let mut all = Vec::new();
    // content chunk (usage:null), finish chunk (finish_reason, usage:null), trailing usage chunk.
    for chunk in [
        serde_json::json!({"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}],"usage":null}),
        serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":FINISH_STOP}],"usage":null}),
        serde_json::json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}),
    ] {
        all.extend(OpenAiReader.read_response_events("", &chunk, &mut state));
    }
    // The trailing usage-only chunk yields a MessageDelta with stop_reason:None and real tokens.
    let trailing = all.iter().rev().find_map(|e| match e {
        IrStreamEvent::MessageDelta {
            stop_reason: None,
            usage,
            ..
        } => Some(usage.clone()),
        _ => None,
    });
    let usage =
        trailing.expect("trailing usage-only chunk must emit a stop_reason:None MessageDelta");
    assert_eq!(
        usage.input_tokens, 7,
        "real prompt tokens must survive, got {usage:?}"
    );
    assert_eq!(
        usage.output_tokens, 3,
        "real completion tokens must survive, got {usage:?}"
    );
    // And exactly one terminal MessageStop (from the finish chunk).
    assert_eq!(
        all.iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStop))
            .count(),
        1
    );
}

// Regression: a 200 completion body that omits `usage` entirely must still read back
// successfully with a zero-usage fallback — never a hard `IrError` (which forward.rs would
// swallow into a spurious 500, discarding the valid 200 body). Mirrors the Gemini/Cohere
// readers. Against the old hard-fail code this `.expect` panics; after the fix it passes.
#[test]
fn read_response_tolerates_missing_usage() {
    let body = serde_json::json!({
        "id": "chatcmpl-x",
        "object": OBJ_COMPLETION,
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": FINISH_STOP
        }]
        // NOTE: no "usage" field.
    });
    let ir = OpenAiReader
        .read_response(&body)
        .expect("a 200 body with no usage must read back, not hard-fail");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 0);
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    // The rest of the response still parsed.
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::EndTurn));
    assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
}

// Regression: a non-JSON tool `arguments` value (stored by the reader as
// `Value::String(raw)` when the upstream sent malformed/partial argument text) must be emitted
// verbatim, NOT re-serialized via `serde_json::to_string` (which would JSON-encode the string a
// second time and double-encode the wire payload). Covers both write sites.
#[test]
fn write_request_string_tool_arguments_emitted_verbatim() {
    let raw = "not-json {oops".to_string();
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "do_it".to_string(),
                input: serde_json::Value::String(raw.clone()),
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
    let out = OpenAiWriter.write_request(&req);
    let args = &out["messages"][0]["tool_calls"][0]["function"]["arguments"];
    assert_eq!(
        args,
        &serde_json::Value::String(raw),
        "string tool arguments must be emitted verbatim, not double-encoded, got {args}"
    );
}

#[test]
fn write_response_string_tool_arguments_emitted_verbatim() {
    let raw = "not-json {oops".to_string();
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![crate::ir::IrBlock::ToolUse {
            id: "call_1".to_string(),
            name: "do_it".to_string(),
            input: serde_json::Value::String(raw.clone()),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("gpt-4o".to_string()),
        id: Some("chatcmpl-x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = OpenAiWriter.write_response(&resp);
    let args = &out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"];
    assert_eq!(
        args,
        &serde_json::Value::String(raw),
        "string tool arguments must be emitted verbatim, not double-encoded, got {args}"
    );
}

// Regression: a reasoning delta arriving AFTER the text block has opened must NOT be
// honored as a Thinking-at-index-0 block. Doing so would flip `reasoning_seen`, bumping `offset`
// from 0 to 1, and retroactively shift the IR index of the already-opened text block — corrupting
// BlockStart/BlockStop pairing. The late reasoning delta must be dropped: no BlockStart{index:0},
// no thinking BlockDelta, and `reasoning_seen`/`offset` must stay put.
#[test]
fn late_reasoning_delta_after_text_does_not_shift_indices() {
    let mut state = crate::ir::StreamDecodeState::default();
    // First chunk opens the text block at index 0 (no reasoning seen yet).
    let c1 = serde_json::json!({
        "id": "chatcmpl-x", "object": OBJ_CHUNK, "created": 1u64, "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": null}]
    });
    let evs1 = OpenAiReader.read_response_events("", &c1, &mut state);
    assert!(
        evs1.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text
            }
        )),
        "text block must open at index 0, got {evs1:?}"
    );
    assert!(state.text_block_open);
    assert!(!state.reasoning_seen);

    // A late reasoning delta now arrives. It must be IGNORED (answer phase already started).
    let c2 = serde_json::json!({
        "choices": [{"index": 0, "delta": {"reasoning_content": "late thought"}, "finish_reason": null}]
    });
    let evs2 = OpenAiReader.read_response_events("", &c2, &mut state);
    assert!(
        !evs2.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Thinking,
                ..
            }
        )),
        "late reasoning must NOT open a thinking block, got {evs2:?}"
    );
    assert!(
        !evs2.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::ThinkingDelta(_),
                ..
            }
        )),
        "late reasoning must NOT emit a ThinkingDelta, got {evs2:?}"
    );
    assert!(
        !state.reasoning_seen,
        "late reasoning must NOT flip reasoning_seen (which would shift already-opened indices)"
    );
    assert!(!state.thinking_block_open);

    // A subsequent text delta must still land on index 0 — proving the index was not shifted.
    let c3 = serde_json::json!({
        "choices": [{"index": 0, "delta": {"content": " world"}, "finish_reason": null}]
    });
    let evs3 = OpenAiReader.read_response_events("", &c3, &mut state);
    let text_idx = evs3.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            index,
            delta: crate::ir::IrDelta::TextDelta(_),
        } => Some(*index),
        _ => None,
    });
    assert_eq!(
        text_idx,
        Some(0),
        "text must stay at index 0 after a stray late reasoning delta, got {evs3:?}"
    );
}

// Companion: a reasoning delta that legitimately precedes any answer content still opens the
// Thinking block at index 0 (the gate must not break the normal reasoning-first path).
#[test]
fn early_reasoning_delta_still_opens_thinking_at_index_0() {
    let mut state = crate::ir::StreamDecodeState::default();
    let c = serde_json::json!({
        "id": "chatcmpl-x", "object": OBJ_CHUNK, "created": 1u64, "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {"reasoning_content": "thinking..."}, "finish_reason": null}]
    });
    let evs = OpenAiReader.read_response_events("", &c, &mut state);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Thinking
            }
        )),
        "early reasoning must open a thinking block at index 0, got {evs:?}"
    );
    assert!(state.reasoning_seen);
}

#[test]
fn logprobs_only_chunk_closes_thinking_before_opening_text() {
    // A reasoning backend can stream a logprobs-only chunk (no content delta) while a thinking
    // block is still open. The reader must close the thinking block (BlockStop{index:0}) BEFORE
    // opening the text block, so the two blocks are never open simultaneously.
    let mut state = crate::ir::StreamDecodeState::default();
    // (a) open a thinking block.
    let c1 = serde_json::json!({
        "id": "chatcmpl-x", "object": OBJ_CHUNK, "created": 1u64, "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {"reasoning_content": "thinking..."}, "finish_reason": null}]
    });
    let _ = OpenAiReader.read_response_events("", &c1, &mut state);
    assert!(state.thinking_block_open, "thinking block should be open");

    // (b) a chunk with NO content delta but choice-level logprobs.content populated.
    let c2 = serde_json::json!({
        "id": "chatcmpl-x", "object": OBJ_CHUNK, "created": 1u64, "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "delta": {},
            "logprobs": {"content": [{"token": "Hi", "logprob": -0.1, "bytes": [72, 105]}]},
            "finish_reason": null
        }]
    });
    let evs = OpenAiReader.read_response_events("", &c2, &mut state);

    // The thinking block's BlockStop{index:0} must appear, and it must come before the text
    // BlockStart — i.e. no two blocks are ever open at once.
    let stop_pos = evs
        .iter()
        .position(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 }));
    let start_pos = evs.iter().position(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Text,
                ..
            }
        )
    });
    let stop_pos = stop_pos.unwrap_or_else(|| {
        panic!("thinking block must close with BlockStop{{index:0}}, got {evs:?}")
    });
    let start_pos = start_pos
        .unwrap_or_else(|| panic!("logprobs-only chunk must open a text block, got {evs:?}"));
    assert!(
        stop_pos < start_pos,
        "thinking BlockStop must precede text BlockStart (no two blocks open at once), got {evs:?}"
    );
    assert!(!state.thinking_block_open, "thinking block must be closed");
    assert!(state.text_block_open, "text block must be open");
}

// Regression: `max_tokens` / `max_completion_tokens` must be narrowed with a
// bounds-checked `u32::try_from`, NOT a raw `as u32`. A value above `u32::MAX` previously
// truncated (wrapped) into a tiny token cap; it must now be rejected (None), never wrapped.
#[test]
fn max_tokens_above_u32_max_is_rejected_not_truncated() {
    let reader = OpenAiReader;
    // u32::MAX + 1 = 4_294_967_296. A raw `as u32` would wrap this to 0.
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 4_294_967_296u64
    });
    let ir = reader.read_request(&body).expect("request parses");
    assert_eq!(
        ir.max_tokens, None,
        "max_tokens above u32::MAX must be rejected (None), not truncated to {:?}",
        ir.max_tokens
    );

    // The same rule applies to the modern `max_completion_tokens` field.
    let body2 = serde_json::json!({
        "model": "o3",
        "messages": [{"role": "user", "content": "hi"}],
        "max_completion_tokens": 4_294_967_296u64
    });
    let ir2 = reader.read_request(&body2).expect("request parses");
    assert_eq!(
        ir2.max_tokens, None,
        "max_completion_tokens above u32::MAX must be rejected, not truncated"
    );

    // A sane in-range value still survives unchanged.
    let body3 = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1024u64
    });
    let ir3 = reader.read_request(&body3).expect("request parses");
    assert_eq!(ir3.max_tokens, Some(1024));
}

// --- auth_headers: invalid credential bytes fall back to an empty value without panic, and a
//     valid key produces the expected single `authorization: Bearer` header.

fn header_value(headers: &[(HeaderName, HeaderValue)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.as_str() == name)
        .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
}

#[test]
fn auth_headers_valid_key_emits_bearer_authorization() {
    let headers = OpenAiWriter.auth_headers("sk-openai-good-key");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer sk-openai-good-key")
    );
    assert_eq!(headers.len(), 1, "openai auth emits a single header");
}

#[test]
fn auth_headers_invalid_key_omits_header_no_panic() {
    // A key whose bytes are invalid for an HTTP header value (an embedded newline). The writer
    // must not panic; under the warn+OMIT policy (`proto::bearer_auth_headers`) it now OMITS the
    // header entirely (empty Vec) rather than emitting an empty `authorization` value — the empty
    // value was both a syntactically invalid header and a fingerprinting tell. A warn line (not
    // asserted here) tells the operator the lane credential bytes are invalid.
    let headers = OpenAiWriter.auth_headers("sk-openai-bad\nkey");
    assert!(
        header_value(&headers, "authorization").is_none(),
        "invalid key must OMIT the authorization header, not emit an empty value"
    );
    assert!(headers.is_empty(), "no headers emitted on a bad key");
}

// --- tool_choice is a first-class IR control; it must round-trip, not degrade to auto ---

#[test]
fn test_openai_tool_choice_required_roundtrips() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": "required",
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
    // It must NOT linger in `extra` (that would double-emit and not survive the seam).
    assert!(!ir.extra.contains_key("tool_choice"));
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["tool_choice"], serde_json::json!("required"));
}

#[test]
fn test_openai_tool_choice_specific_function() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": TOOL_TYPE_FUNCTION, "function": {"name": "get_weather"}},
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["tool_choice"],
        serde_json::json!({"type": "function", "function": {"name": "get_weather"}}) // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_openai_tool_choice_absent_is_none() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.tool_choice, None);
    let out = OpenAiWriter.write_request(&ir);
    assert!(
        out.get("tool_choice").is_none(),
        "no tool_choice should be emitted when the caller omitted it"
    );
}

/// Minimal valid `IrRequest` for writer-side tool_choice/temperature tests.
fn test_ir_request() -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![text_block("hi")],
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
    }
}

// H6: the `"auto"` and `"none"` string forms had no read→write round-trip coverage.
#[test]
fn test_openai_tool_choice_auto_roundtrips() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": "auto",
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Auto));
    assert!(!ir.extra.contains_key("tool_choice"));
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["tool_choice"], serde_json::json!("auto"));
}

#[test]
fn test_openai_tool_choice_none_roundtrips() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": "none",
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::None));
    assert!(!ir.extra.contains_key("tool_choice"));
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["tool_choice"], serde_json::json!("none"));
}

// H7: the Anthropic→OpenAI tool_choice direction (auto/none/any/tool) — pinned from the OpenAI
// side because the OpenAI writer is the egress here. Mirrors the OpenAI→Anthropic tests that
// live in anthropic.rs.
#[test]
fn test_anthropic_to_openai_tool_choice_directions() {
    use crate::ir::IrToolChoice;
    let cases = [
        (IrToolChoice::Auto, serde_json::json!("auto")),
        (IrToolChoice::None, serde_json::json!("none")),
        // Anthropic `{"type":"any"}` reads to IR `Required`, which the OpenAI writer emits as
        // the `"required"` string.
        (IrToolChoice::Required, serde_json::json!("required")),
        (
            IrToolChoice::Tool {
                name: "get_weather".to_string(),
            },
            serde_json::json!({"type": "function", "function": {"name": "get_weather"}}), // golden wire-contract literal (kept bare on purpose)
        ),
    ];
    for (tc, expected) in cases {
        let ir = crate::ir::IrRequest {
            tool_choice: Some(tc.clone()),
            ..test_ir_request()
        };
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(out["tool_choice"], expected, "tool_choice {tc:?}");
    }
}

// M5: unknown / structurally-invalid tool_choice values must map to `None` (NOT silently to
// Auto/Required). This guards a future refactor from forcing tool calls on a malformed input.
#[test]
fn test_openai_tool_choice_unknown_string_is_none() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": "definitely_not_a_real_mode",
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(
        ir.tool_choice, None,
        "an unrecognized tool_choice string must degrade to None, never Auto/Required"
    );
}

#[test]
fn test_openai_tool_choice_unknown_object_is_none() {
    // An object whose `type` is not `function` (e.g. a hallucinated/future shape) → None.
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "something_else"},
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.tool_choice, None);
}

// --- Phase 0: frequency_penalty / presence_penalty / seed / n / response_format as first-class
// IR fields. Each proves: OpenAI body -> IR carries it; IR -> OpenAI body re-emits it; and that
// they leave `extra` (promoted, not lingering). ---

#[test]
fn phase0_sampling_fields_read_into_ir() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "frequency_penalty": 0.5,
        "presence_penalty": -0.25,
        "seed": 42,
        "n": 3,
        "response_format": { "type": RESP_FORMAT_JSON_OBJECT }
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.frequency_penalty, Some(0.5_f64));
    assert_eq!(ir.presence_penalty, Some(-0.25_f64));
    assert_eq!(ir.seed, Some(42_i64));
    assert_eq!(ir.n, Some(3_u32));
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
    // Promoted out of `extra` — none should linger (else they'd double-emit on write).
    assert!(!ir.extra.contains_key("frequency_penalty"));
    assert!(!ir.extra.contains_key("presence_penalty"));
    assert!(!ir.extra.contains_key("seed"));
    assert!(!ir.extra.contains_key("n"));
    assert!(!ir.extra.contains_key("response_format"));
}

#[test]
fn phase0_sampling_fields_written_from_ir() {
    let ir = crate::ir::IrRequest {
        frequency_penalty: Some(1.5),
        presence_penalty: Some(-2.0),
        seed: Some(1234),
        n: Some(4),
        response_format: Some(crate::ir::IrResponseFormat {
            json: true,
            schema: Some(serde_json::json!({"type": "object"})),
            name: Some("out".to_string()),
            strict: None,
            description: None,
        }),
        ..test_ir_request()
    };
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["frequency_penalty"], serde_json::json!(1.5));
    assert_eq!(out["presence_penalty"], serde_json::json!(-2.0));
    assert_eq!(out["seed"], serde_json::json!(1234));
    assert_eq!(out["n"], serde_json::json!(4));
    assert_eq!(
        out["response_format"],
        serde_json::json!({
            "type": "json_schema", // golden wire-contract literal (kept bare on purpose)
            "json_schema": {"name": "out", "schema": {"type": "object"}}
        }),
        "response_format must be re-emitted verbatim"
    );
}

// Cross-protocol response_format correctness is covered structurally by the typed IR
// (`IrResponseFormat`) — a foreign shape can no longer EXIST in the IR — and end-to-end by the
// `response_format_cross_protocol_matrix` test in proto/mod.rs (every source reader → typed IR →
// every target writer).

#[test]
fn phase0_sampling_fields_omitted_when_absent() {
    // None on every Phase 0 field => the writer emits none of the keys.
    let out = OpenAiWriter.write_request(&test_ir_request());
    let obj = out.as_object().expect("object");
    assert!(obj.get("frequency_penalty").is_none());
    assert!(obj.get("presence_penalty").is_none());
    assert!(obj.get("seed").is_none());
    assert!(obj.get("n").is_none());
    assert!(obj.get("response_format").is_none());
}

#[test]
fn phase0_sampling_fields_roundtrip_same_protocol() {
    // OpenAI -> IR -> OpenAI preserves every Phase 0 field byte-for-byte.
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "frequency_penalty": 0.75,
        "presence_penalty": 0.1,
        "seed": -7,
        "n": 2,
        "response_format": { "type": RESP_FORMAT_JSON_OBJECT }
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["frequency_penalty"], serde_json::json!(0.75));
    assert_eq!(out["presence_penalty"], serde_json::json!(0.1));
    assert_eq!(out["seed"], serde_json::json!(-7));
    assert_eq!(out["n"], serde_json::json!(2));
    assert_eq!(
        out["response_format"],
        serde_json::json!({ "type": "json_object" }) // golden wire-contract literal (kept bare on purpose)
    );
}

/// D2: a Responses `file_id` image (the FILE_ID_IMAGE_SENTINEL media_type) reaching the OpenAI
/// egress is an unresolvable cross-vendor reference. It must be SKIPPED — NOT emitted as a corrupt
/// `data:file_id;base64,<id>` image_url. The user message's content must carry no image part.
#[test]
fn test_write_request_file_id_image_dropped_not_corrupted() {
    let writer = OpenAiWriter;
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
                    text: "describe this".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor {
                        vendor: "responses",
                        value: serde_json::json!({ "file_id": "file-abc123" }),
                    },
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
        !wire.contains("file-abc123") && !wire.contains("file_id"),
        "a file_id image must not leak onto the OpenAI wire (no corrupt image_url); got {wire}"
    );
    // The text part still survives; no image part is present.
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("user message content array");
    assert!(
        content
            .iter()
            .all(|p| p.get("type").and_then(|t| t.as_str()) != Some("image_url")),
        "no image_url part may be emitted for a file_id image; got {out}"
    );
    assert!(
        content
            .iter()
            .any(|p| p.get("type").and_then(|t| t.as_str()) == Some("text")),
        "the text part must still survive; got {out}"
    );
}

/// HIGH (asymmetric twin of the file_id leak): a Bedrock S3-source image (the IMAGE_S3_SENTINEL
/// media_type, `data` = serialized s3Location JSON) reaching the OpenAI egress is an unresolvable
/// cross-vendor reference. It must be SKIPPED — NOT emitted as a corrupt `data:image_s3;base64,`
/// image_url that leaks the s3Location JSON + a busbar fingerprint onto the OpenAI wire.
#[test]
fn test_write_request_image_s3_dropped_not_corrupted() {
    let writer = OpenAiWriter;
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
                    text: "describe this".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor {
                        vendor: "bedrock",
                        value: serde_json::json!({ "format": "png", "s3Location": { "uri": "s3://bucket/key.png" } }),
                    },
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
        !wire.contains("image_s3")
            && !wire.contains("s3://bucket/key.png")
            && !wire.contains("s3Location"),
        "an image_s3 image must not leak onto the OpenAI wire (no corrupt image_url); got {wire}"
    );
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("user message content array");
    assert!(
        content
            .iter()
            .all(|p| p.get("type").and_then(|t| t.as_str()) != Some("image_url")),
        "no image_url part may be emitted for an image_s3 image; got {out}"
    );
    assert!(
        content
            .iter()
            .any(|p| p.get("type").and_then(|t| t.as_str()) == Some("text")),
        "the text part must still survive; got {out}"
    );
}

#[test]
fn test_modeled_request_keys_is_stable_singleton() {
    let a = modeled_request_keys();
    let b = modeled_request_keys();
    assert!(
        std::ptr::eq(a, b),
        "modeled_request_keys must return the same cached set, not rebuild per call"
    );
    for k in [
        "model",
        "messages",
        "tools",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
        "stream",
        "tool_choice",
        "frequency_penalty",
        "presence_penalty",
        "seed",
        "n",
        "response_format",
        "user",
        "parallel_tool_calls",
        "logprobs",
        "top_logprobs",
        "reasoning_effort",
    ] {
        assert!(a.contains(k), "modeled key set must contain {k}");
    }
}

/// Non-stream `read_response` cache-token NORMALIZATION (ir.rs:457): OpenAI's `prompt_tokens` is a
/// TOTAL that INCLUDES the cached prefix, so the reader must SUBTRACT `cached_tokens` to leave
/// `input_tokens` UNCACHED and store the cached count additively in `cache_read_input_tokens`.
/// This is the OpenAI-family half of the normalization (opposite of Anthropic/Bedrock, whose
/// cache fields are already additive and stored as-is).
#[test]
fn read_response_subtracts_cached_prefix_from_prompt_tokens() {
    let body = serde_json::json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion",
        "created": 1_700_000_000_u64,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": FINISH_STOP
        }],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 5,
            "total_tokens": 105,
            "prompt_tokens_details": {"cached_tokens": 80}
        }
    });
    let resp = OpenAiReader.read_response(&body).expect("read_response");
    assert_eq!(
        resp.usage.input_tokens, 20,
        "input_tokens must be prompt_tokens(100) MINUS cached(80) = 20 (uncached)"
    );
    assert_eq!(resp.usage.cache_read_input_tokens, Some(80));
    assert_eq!(resp.usage.output_tokens, 5);
    assert_eq!(resp.usage.cache_creation_input_tokens, None);
    // billable_tokens re-sums to the original wire total input (20 + 80) + output 5 = 105.
    assert_eq!(resp.usage.billable_tokens(), 105);
}

/// The write side RECONSTRUCTS the native wire shape: it must ADD the cached prefix BACK onto the
/// uncached IR `input_tokens` to re-derive OpenAI's TOTAL `prompt_tokens`, and re-emit
/// `prompt_tokens_details.cached_tokens`. Pins the exact inverse of the read normalization so a
/// read→write round-trip reproduces the original `prompt_tokens`.
#[test]
fn write_response_reconstructs_prompt_tokens_total_with_cached_details() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hi")],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: 20,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(80),
        },
        model: Some("gpt-4o".to_string()),
        id: Some("chatcmpl-abc".to_string()),
        created: Some(1_700_000_000),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(
        out["usage"]["prompt_tokens"],
        serde_json::json!(100),
        "prompt_tokens must re-add the cached prefix: uncached(20) + cached(80) = 100"
    );
    assert_eq!(out["usage"]["completion_tokens"], serde_json::json!(5));
    assert_eq!(out["usage"]["total_tokens"], serde_json::json!(105));
    assert_eq!(
        out["usage"]["prompt_tokens_details"]["cached_tokens"],
        serde_json::json!(80)
    );
}

/// A cache-free response must NOT emit a spurious `prompt_tokens_details` object — matching the
/// native OpenAI shape (the details object appears only when a cache read occurred).
#[test]
fn write_response_omits_cached_details_when_no_cache_read() {
    let mut resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![text_block("hi")],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: 7,
            output_tokens: 3,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("gpt-4o".to_string()),
        id: Some("chatcmpl-x".to_string()),
        created: Some(1),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(out["usage"]["prompt_tokens"], serde_json::json!(7));
    assert!(
        out["usage"].get("prompt_tokens_details").is_none(),
        "no cache read means no prompt_tokens_details object"
    );
    // And a Some(0) cache read still emits the details object with 0 (native shape carries it).
    resp.usage.cache_read_input_tokens = Some(0);
    let out2 = OpenAiWriter.write_response(&resp);
    assert_eq!(
        out2["usage"]["prompt_tokens_details"]["cached_tokens"],
        serde_json::json!(0)
    );
}

/// A `response_format` json_schema directive must round-trip read→IR→write byte-faithful: the
/// nested `{type:"json_schema", json_schema:{name,schema,strict,description}}` OpenAI shape reads
/// into the typed `IrResponseFormat` and writes back to the same nested shape (the canonicalized
/// carrier that stops a foreign shape from being echoed cross-protocol — ir.rs:348).
#[test]
fn response_format_json_schema_round_trips() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"]
    });
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "Person",
                "schema": schema,
                "strict": true,
                "description": "a person"
            }
        }
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    let rf = ir
        .response_format
        .as_ref()
        .expect("response_format must canonicalize into the typed IR");
    assert!(rf.json);
    assert_eq!(rf.name.as_deref(), Some("Person"));
    assert_eq!(rf.strict, Some(true));
    assert_eq!(rf.description.as_deref(), Some("a person"));
    assert_eq!(rf.schema.as_ref(), Some(&schema));
    // It must NOT linger in `extra` (that would double-emit / leak the source shape cross-hop).
    assert!(!ir.extra.contains_key("response_format"));

    // WRITE re-emits the native nested json_schema shape.
    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["response_format"]["type"],
        serde_json::json!("json_schema")
    );
    assert_eq!(
        out["response_format"]["json_schema"]["name"],
        serde_json::json!("Person")
    );
    assert_eq!(out["response_format"]["json_schema"]["schema"], schema);
    assert_eq!(
        out["response_format"]["json_schema"]["strict"],
        serde_json::json!(true)
    );
}

/// An UNKNOWN native `finish_reason` (a token OpenAI may add after this build) reads to
/// `IrStopReason::Other` (ir.rs:186 — no String payload, nothing foreign to carry), and on egress
/// `Other` degrades to the SDK-safe `stop` rather than leaking an off-enum value a strict client
/// SDK rejects.
#[test]
fn read_response_unknown_finish_reason_maps_to_other_and_degrades_to_stop() {
    assert_eq!(
        read_openai_stop_reason("some_future_reason"),
        crate::ir::IrStopReason::Other
    );
    let body = serde_json::json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "some_future_reason"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    });
    let resp = OpenAiReader.read_response(&body).expect("read_response");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Other));
    let out = OpenAiWriter.write_response(&resp);
    assert_eq!(
        out["choices"][0]["finish_reason"],
        serde_json::json!("stop"),
        "Other must degrade to the safe stop default, never leak the foreign token"
    );
}

/// Multi-element `stop` must emit as a JSON ARRAY on the wire (not a bare string), and an empty
/// `stop` vec must be OMITTED entirely (ir.rs:57 — a request that never carried stops must not
/// gain a spurious empty `stop` on translation).
#[test]
fn write_request_stop_sequences_array_and_empty_omitted() {
    let mut req = test_ir_request();
    req.stop = vec![".".to_string(), "!".to_string()];
    let out = OpenAiWriter.write_request(&req);
    assert_eq!(
        out["stop"],
        serde_json::json!([".", "!"]),
        "multi-element stop must serialize as an array"
    );

    // Empty stop → no `stop` key emitted.
    let mut empty = test_ir_request();
    empty.stop = vec![];
    let out_empty = OpenAiWriter.write_request(&empty);
    assert!(
        out_empty.get("stop").is_none(),
        "an empty stop vec must be omitted, not emitted as []"
    );
}
