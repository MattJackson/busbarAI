
use super::*;
use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent, IrUsage, StreamDecodeState};
use serde_json::json;

// OpenAI flat stream → Anthropic-shaped IR events. Exact-sequence decode asserts
// (ungameable: the expected Vec is derived from the state-machine spec, not from output).
#[test]
fn test_openai_read_fanout_text() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"role":"assistant"}}]}),
        json!({"choices":[{"delta":{"content":"Hel"}}]}),
        json!({"choices":[{"delta":{"content":"lo"}}]}),
        json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }
    assert_eq!(
        events,
        vec![
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None
            },
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("Hel".to_string())
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("lo".to_string())
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None
                },
            },
            IrStreamEvent::MessageStop,
        ]
    );
}

#[test]
fn test_openai_read_fanout_tool_call() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"loc\":\"SF\"}"}}]}}]}),
        json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }
    assert_eq!(
        events,
        vec![
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None
            },
            // Tool-only stream (no text) is 0-based — text reserves index 0 ONLY
            // when text actually appears. Previously asserted the buggy 1-based index.
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string()
                }
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta(String::new())
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta("{\"loc\":\"SF\"}".to_string())
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::ToolUse),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None
                },
            },
            IrStreamEvent::MessageStop,
        ]
    );
}

#[test]
fn test_openai_read_fanout_cached_tokens() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    events.extend(reader.read_response_events(
        "",
        &json!({"choices":[{"delta":{"content":"hi"}}]}),
        &mut st,
    ));
    events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":7}}}),
            &mut st,
        ));
    let usage = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage.clone()),
            _ => None,
        })
        .expect("MessageDelta present");
    assert_eq!(
        usage.cache_read_input_tokens,
        Some(7),
        "cached_tokens → cache_read"
    );
    assert_eq!(
        usage.cache_creation_input_tokens, None,
        "OpenAI has no cache-creation split"
    );
    // A2 normalization: input_tokens is UNCACHED (prompt_tokens 100 - cached 7 = 93).
    assert_eq!(usage.input_tokens, 93);
    assert_eq!(usage.output_tokens, 50);
    // Billing is unchanged for OpenAI-family: billable = uncached(93) + cache_read(7) + out(50)
    // = 150 = the pre-A2 prompt_total(100) + output(50). No double-count, no regression.
    assert_eq!(usage.billable_tokens(), 150);
}

#[test]
fn test_anthropic_read_events_wraps_singular() {
    let reader = AnthropicReader;
    let mut st = StreamDecodeState::default();
    let data =
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}});
    let single = reader.read_response_event("content_block_delta", &data);
    let plural = reader.read_response_events("content_block_delta", &data, &mut st);
    assert_eq!(
        plural,
        single.into_iter().collect::<Vec<_>>(),
        "Anthropic plural wraps singular 1:1"
    );
    assert_eq!(plural.len(), 1);
    // ping → empty
    assert_eq!(
        reader.read_response_events("ping", &json!({}), &mut st),
        Vec::<IrStreamEvent>::new()
    );
}
