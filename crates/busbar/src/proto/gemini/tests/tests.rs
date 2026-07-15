use super::*;
use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, StreamDecodeState};

fn collect_stream(chunks: &[serde_json::Value]) -> Vec<IrStreamEvent> {
    let reader = GeminiReader;
    let mut state = StreamDecodeState::default();
    let mut events = Vec::new();
    for chunk in chunks {
        events.extend(reader.read_response_events("", chunk, &mut state));
    }
    events
}

/// Regression: a streamed functionCall MUST produce a matching BlockStop for its tool block.
/// Previously the tool index was never recorded in `state.open_tools`, so the finishReason
/// drain (which is the only thing that closes tool blocks) left an orphaned BlockStart.
#[test]
fn test_stream_tool_block_is_closed() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);

    // Find the tool BlockStart and capture its index.
    let tool_start_idx = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { name, .. },
        } if name == "get_weather" => Some(*index),
        _ => None,
    });
    let idx = tool_start_idx.expect("tool BlockStart must be emitted");

    // The same index MUST be closed by a BlockStop.
    let closed = events
        .iter()
        .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx));
    assert!(
        closed,
        "tool block {idx} was opened but never closed: {events:?}"
    );

    // Balance check: every BlockStart has a matching BlockStop.
    let starts = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
        .count();
    let stops = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
        .count();
    assert_eq!(starts, stops, "unbalanced block events: {events:?}");
}

/// Regression: a Gemini stream chunk with `candidateCount > 1` (multiple candidates each
/// carrying their own `finishReason`) MUST still produce EXACTLY ONE terminal sequence —
/// one MessageDelta and one MessageStop — not one per candidate. The reader previously looped
/// over every candidate and emitted a full close+MessageDelta+MessageStop sequence per
/// candidate, so a downstream ingress writer saw duplicate `message_stop`/`message_delta`
/// frames on a single stream (a protocol violation). The reader now mirrors the non-streaming
/// `read_response`, which reads `candidates[0]` only.
#[test]
fn test_stream_multiple_candidates_emit_single_terminal_sequence() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": "first"}]},
                "finishReason": GEMINI_FINISH_STOP
            },
            {
                "content": {"role": "model", "parts": [{"text": "second"}]},
                "finishReason": GEMINI_FINISH_STOP
            },
            {
                "content": {"role": "model", "parts": [{"text": "third"}]},
                "finishReason": GEMINI_FINISH_MAX_TOKENS
            }
        ]
    })]);

    let message_stops = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::MessageStop))
        .count();
    assert_eq!(
        message_stops, 1,
        "exactly one MessageStop expected regardless of candidateCount: {events:?}"
    );

    let message_deltas = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
        .count();
    assert_eq!(
        message_deltas, 1,
        "exactly one MessageDelta expected regardless of candidateCount: {events:?}"
    );

    // Only the first candidate's text is surfaced; the others are ignored entirely.
    let text: String = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::TextDelta(t),
                ..
            } => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "first", "only candidates[0] text should be emitted");

    // The single MessageStop must be the LAST event in the stream.
    assert!(
        matches!(events.last(), Some(IrStreamEvent::MessageStop)),
        "MessageStop must terminate the stream: {events:?}"
    );

    // Block events stay balanced (no per-candidate index churn).
    let starts = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
        .count();
    let stops = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
        .count();
    assert_eq!(starts, stops, "unbalanced block events: {events:?}");
}

/// Regression: text + tool in the same response use distinct, stable indices (text=0, tool=1)
/// and BOTH are closed.
#[test]
fn test_stream_text_and_tool_indices_stable_and_closed() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"text": "hello"},
                    {"functionCall": {"name": "f", "args": {}}}
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);

    let text_start = events.iter().any(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            }
        )
    });
    assert!(text_start, "text block must open at index 0");

    let tool_start = events.iter().any(|e| {
        matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse { .. }
            }
        )
    });
    assert!(tool_start, "tool block must open at index 1");

    assert!(
        events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 })),
        "text block (0) must be closed"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 1 })),
        "tool block (1) must be closed"
    );
}

/// Regression (verification of the R20 #6 fix): a functionCall part BEFORE the first text part
/// must NOT collide on IR index 0. The fix keyed the tool base on the live `text_block_open` flag,
/// which is false at tool time in this ordering, so the tool took 0 AND text later took 0 — two
/// BlockStart frames at index 0 (a protocol violation a strict Anthropic SDK rejects). Index-by-
/// first-appearance: the tool takes 0, text takes the next free slot (1); each index opened and
/// closed exactly once.
#[test]
fn test_stream_tool_before_text_no_index_collision() {
    // Both intra-chunk (functionCall before text in the same parts array) AND inter-chunk.
    for chunks in [
        vec![serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [
                    {"functionCall": {"name": "f", "args": {}}},
                    {"text": "hello"}
                ]},
                "finishReason": GEMINI_FINISH_STOP
            }]
        })],
        vec![
            serde_json::json!({"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]}}]}),
            serde_json::json!({"candidates":[{"content":{"role":"model","parts":[{"text":"hello"}]},"finishReason": GEMINI_FINISH_STOP}]}),
        ],
    ] {
        let events = collect_stream(&chunks);
        // Exactly one BlockStart per index; no two BlockStarts share an index.
        let mut start_indices: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        let n = start_indices.len();
        start_indices.sort_unstable();
        start_indices.dedup();
        assert_eq!(
            start_indices.len(),
            n,
            "no two BlockStart frames may share an index; got duplicate in {events:?}"
        );
        // Tool took index 0 (it appeared first); text took index 1.
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::ToolUse { .. }
                }
            )),
            "tool (first to appear) must take index 0: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::Text
                }
            )),
            "text (after the tool) must take index 1: {events:?}"
        );
        // Both blocks are closed at their own index.
        assert!(events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 })));
        assert!(events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index: 1 })));
    }
}

/// Regression: tool block indices stay stable when the functionCall arrives in a different
/// chunk than the finishReason (per-chunk local reset previously corrupted this).
#[test]
fn test_stream_tool_index_stable_across_chunks() {
    let events = collect_stream(&[
        serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "f", "args": {"a": 1}}}]
                }
            }]
        }),
        serde_json::json!({
            "candidates": [{ "finishReason": GEMINI_FINISH_STOP }]
        }),
    ]);

    let start_idx = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { .. },
        } => Some(*index),
        _ => None,
    });
    let idx = start_idx.expect("tool BlockStart must be emitted");
    // No text block opened this stream, so the tool owns index 0 (contiguous from 0);
    // reserving 0 for an absent text block would leave a permanent hole.
    assert_eq!(idx, 0, "tool-only stream: tool block must take index 0");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
        "tool block opened in chunk 1 must be closed by finishReason in chunk 2: {events:?}"
    );
}

/// Regression: two functionCalls in a tool-only response get distinct, contiguous indices
/// (0 and 1 — no text block opened, so nothing reserves index 0) and both close.
#[test]
fn test_stream_two_tools_distinct_indices() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"functionCall": {"name": "a", "args": {}}},
                    {"functionCall": {"name": "b", "args": {}}}
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);

    let mut tool_indices: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .collect();
    tool_indices.sort_unstable();
    assert_eq!(
        tool_indices,
        vec![0, 1],
        "tool-only stream: two tools must take contiguous indices 0,1"
    );

    for idx in [0usize, 1usize] {
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
            "tool block {idx} must be closed"
        );
    }
}

/// Regression for MED #6: a tool-only streaming response must produce content block indices
/// contiguous from 0. Previously the first tool index was `1 + open_tools.len()`, which reserved
/// index 0 for a text block that never opened — leaving IR index 0 permanently empty and content
/// indices non-contiguous (0 hole, then 1..n). Now the base is keyed on whether a text block
/// actually opened (`usize::from(state.text_block_open)`), so a tool-only stream starts at 0.
#[test]
fn test_stream_tool_only_indices_contiguous_from_zero() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"functionCall": {"name": "a", "args": {}}},
                    {"functionCall": {"name": "b", "args": {}}}
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);

    // No text block must open: a tool-only response carries no text part.
    assert!(
        !events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: IrBlockMeta::Text,
                ..
            }
        )),
        "tool-only stream must not open a text block: {events:?}"
    );

    let mut tool_indices: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .collect();
    tool_indices.sort_unstable();
    assert_eq!(
            tool_indices,
            vec![0, 1],
            "tool-only stream: content indices must be contiguous from 0 (no reserved-but-empty 0): {events:?}"
        );

    // Both tool blocks must be closed at their own indices.
    for idx in [0usize, 1usize] {
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::BlockStop { index } if *index == idx)),
            "tool block {idx} must be closed: {events:?}"
        );
    }
}

/// Regression for MED #6 (interleaving): when a text block DOES open, the reserved index 0
/// must still hold, and tool blocks follow at 1..n — the fix must not regress text+tool order.
#[test]
fn test_stream_text_then_tool_keeps_text_at_zero() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"text": "hi"},
                    {"functionCall": {"name": "a", "args": {}}},
                    {"functionCall": {"name": "b", "args": {}}}
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);

    assert!(
        events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            }
        )),
        "text block must open at index 0: {events:?}"
    );

    let mut tool_indices: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(*index),
            _ => None,
        })
        .collect();
    tool_indices.sort_unstable();
    assert_eq!(
        tool_indices,
        vec![1, 2],
        "text+tool stream: tools must follow text at indices 1,2: {events:?}"
    );
}

/// Regression: the tool BlockStart now BUFFERS the name and emits NO frame; a native Gemini
/// stream carries a tool call as a single `functionCall` part, so the name must NOT appear in a
/// separate opening frame (that produced a two-part split a native client never sees).
#[test]
fn test_writer_tool_blockstart_emits_no_frame() {
    let writer = GeminiWriter;
    let ev = IrStreamEvent::BlockStart {
        index: 1,
        block: IrBlockMeta::ToolUse {
            id: String::new(),
            name: "get_weather".to_string(),
        },
    };
    assert!(
        writer.write_response_event(&ev).is_none(),
        "tool BlockStart must buffer the name and emit no separate frame"
    );
}

/// The text BlockStart still produces no frame (Gemini inlines text parts).
#[test]
fn test_writer_text_blockstart_is_none() {
    let writer = GeminiWriter;
    let ev = IrStreamEvent::BlockStart {
        index: 0,
        block: IrBlockMeta::Text,
    };
    assert!(writer.write_response_event(&ev).is_none());
}

/// HIGH (asymmetric twin of the file_id leak): a Bedrock S3-source image (IMAGE_S3_SENTINEL
/// media_type, `data` = serialized s3Location JSON) reaching the Gemini egress must be SKIPPED,
/// NOT emitted as a corrupt `inlineData{mimeType:"image_s3"}` part that leaks the s3Location JSON
/// + a busbar fingerprint onto the Gemini wire.
#[test]
fn test_write_request_image_s3_dropped_not_corrupted() {
    let writer = GeminiWriter;
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
        "an image_s3 image must not leak onto the Gemini wire (no corrupt inlineData part); \
             got {wire}"
    );
    assert!(
        !wire.contains("inlineData") && !wire.contains("fileData"),
        "no inlineData/fileData part may be emitted for an image_s3 image; got {wire}"
    );
    assert!(
        wire.contains("describe this"),
        "the text part must still survive; got {wire}"
    );
}

/// Helper: drive a sequence of IR events through ONE GeminiWriter (preserving its per-stream
/// tool buffer) and return only the emitted `functionCall` parts (the `{name, args}` objects),
/// in wire order. This is the shape a native google-genai client decodes off the stream.
fn collect_function_calls(events: &[IrStreamEvent]) -> Vec<serde_json::Value> {
    let writer = GeminiWriter;
    let mut calls = Vec::new();
    for ev in events {
        if let Some((_, chunk)) = writer.write_response_event(ev) {
            if let Some(parts) = chunk
                .pointer("/candidates/0/content/parts")
                .and_then(|p| p.as_array())
            {
                for part in parts {
                    if let Some(fc) = part.get(FIELD_FUNCTION_CALL) {
                        calls.push(fc.clone());
                    }
                }
            }
        }
    }
    calls
}

/// Regression: a tool BlockStart + one whole-JSON InputJsonDelta + BlockStop emits EXACTLY ONE
/// native `functionCall` part carrying BOTH the buffered name and the args. The part is written
/// on BlockStop (the flush point), not on the BlockStart or the delta.
#[test]
fn test_writer_tool_call_emits_single_name_and_args_part() {
    let calls = collect_function_calls(&[
        IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
        },
        IrStreamEvent::BlockStop { index: 1 },
    ]);
    assert_eq!(
        calls.len(),
        1,
        "tool call must emit exactly one functionCall part: {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/name").and_then(|n| n.as_str()),
        Some("get_weather"),
        "part must carry the buffered name: {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/args/city").and_then(|c| c.as_str()),
        Some("SF"),
        "part must carry the args: {calls:?}"
    );
}

/// Regression: the `arguments` JSON arrives SPLIT across MULTIPLE partial-
/// JSON InputJsonDelta fragments (the normal OpenAI/Anthropic streaming behavior — the reader
/// emits one InputJsonDelta per upstream `arguments` fragment, none coalesced). The fragments
/// individually do NOT parse (`{"lo`, `c":"SF","u":1}`); the writer MUST reassemble them and emit
/// EXACTLY ONE functionCall part whose `args` is the fully reassembled object — not one (empty-
/// args) part per fragment.
#[test]
fn test_writer_tool_call_reassembles_split_json_args() {
    let calls = collect_function_calls(&[
        IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("{\"lo".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("c\":\"SF\",\"unit".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("\":\"C\"}".to_string()),
        },
        IrStreamEvent::BlockStop { index: 1 },
    ]);
    assert_eq!(
        calls.len(),
        1,
        "multi-fragment args must still emit exactly ONE functionCall part: {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/name").and_then(|n| n.as_str()),
        Some("get_weather"),
        "part name must be non-empty after reassembly: {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/args/loc").and_then(|c| c.as_str()),
        Some("SF"),
        "args must be the FULLY reassembled object, not a partial fragment: {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/args/unit").and_then(|c| c.as_str()),
        Some("C"),
        "every reassembled arg key must survive: {calls:?}"
    );
}

/// Regression: TWO parallel tool blocks in one stream, with their
/// BlockStarts NOT strictly interleaved with their own BlockStops (the OpenAI reader emits
/// BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2)). The
/// single-slot buffer this replaced would clobber tool 1 when tool 2's BlockStart arrived. Each
/// tool must flush its OWN name + args as a distinct functionCall part.
#[test]
fn test_writer_parallel_tool_calls_keep_distinct_names_and_args() {
    let calls = collect_function_calls(&[
        IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_weather".to_string(),
            },
        },
        IrStreamEvent::BlockStart {
            index: 2,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "get_time".to_string(),
            },
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("{\"city\":".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 2,
            delta: IrDelta::InputJsonDelta("{\"tz\":\"UTC\"}".to_string()),
        },
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("\"SF\"}".to_string()),
        },
        IrStreamEvent::BlockStop { index: 1 },
        IrStreamEvent::BlockStop { index: 2 },
    ]);
    assert_eq!(
        calls.len(),
        2,
        "two parallel tool calls must emit two functionCall parts: {calls:?}"
    );
    // Tool 1 flushed on its BlockStop (emitted first).
    assert_eq!(
        calls[0].pointer("/name").and_then(|n| n.as_str()),
        Some("get_weather"),
        "first flushed part must keep tool 1's name (not clobbered by tool 2): {calls:?}"
    );
    assert_eq!(
        calls[0].pointer("/args/city").and_then(|c| c.as_str()),
        Some("SF"),
        "tool 1's interleaved split args must reassemble: {calls:?}"
    );
    assert_eq!(
        calls[1].pointer("/name").and_then(|n| n.as_str()),
        Some("get_time"),
        "second flushed part must keep tool 2's name: {calls:?}"
    );
    assert_eq!(
        calls[1].pointer("/args/tz").and_then(|c| c.as_str()),
        Some("UTC"),
        "tool 2's args must survive: {calls:?}"
    );
}

/// Regression: a zero-argument tool call (BlockStart then BlockStop with NO InputJsonDelta) must
/// still emit one `{name, args:{}}` part on the BlockStop flush — the call is never lost.
#[test]
fn test_writer_tool_call_empty_args_flushed_on_stop() {
    let writer = GeminiWriter;
    assert!(writer
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: String::new(),
                name: "ping".to_string(),
            },
        })
        .is_none());
    let (_, chunk) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
        .expect("zero-arg tool call must flush a functionCall frame on BlockStop");
    let func = chunk
        .pointer("/candidates/0/content/parts/0/functionCall")
        .expect("functionCall part");
    assert_eq!(
        func.pointer("/name").and_then(|n| n.as_str()),
        Some("ping"),
        "flushed frame must carry the name: {chunk}"
    );
    assert!(
        func.get("args").map(|a| a.is_object()).unwrap_or(false),
        "flushed frame must carry an (empty) args object: {chunk}"
    );
}

/// Regression: neither the BlockStart nor the args delta emits a frame — the functionCall part
/// is written ONCE, on BlockStop. Guards against re-introducing a per-fragment emit.
#[test]
fn test_writer_tool_call_no_frame_before_block_stop() {
    let writer = GeminiWriter;
    assert!(
        writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: String::new(),
                    name: "get_weather".to_string(),
                },
            })
            .is_none(),
        "tool BlockStart must emit no frame"
    );
    assert!(
        writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".to_string()),
            })
            .is_none(),
        "args delta must accumulate, not emit a frame"
    );
    assert!(
        writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .is_some(),
        "BlockStop must flush the single functionCall frame"
    );
}

/// extract_error parses the body once and derives both the provider code and structured type.
/// The real Gemini API returns `error.code` as a JSON INTEGER (google.rpc.Status), so the
/// fixture uses `429` (not `"429"`); `provider_code` must be the stringified integer.
#[test]
fn test_extract_error_single_parse_fields() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
    assert_eq!(raw.http_status, 429);
    assert_eq!(raw.provider_code.as_deref(), Some("429"));
    assert_eq!(
        raw.structured_type.as_deref(),
        Some(GRPC_RESOURCE_EXHAUSTED)
    );
    // classify()/extract_error do not see headers, so retry_after is sourced elsewhere.
    assert_eq!(raw.retry_after_secs, None);
}

/// Regression (R5): an integer `error.code` (the real Gemini shape) must be stringified into
/// `provider_code` — NOT silently dropped to the gRPC status name. Previously `code` was read
/// via `.as_str()`, which returns None on a number, so a real 429 surfaced as
/// "RESOURCE_EXHAUSTED" and broke breaker/metrics comparisons against numeric strings.
#[test]
fn test_extract_error_integer_code_is_stringified() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":503,"status":"UNAVAILABLE","message":"overloaded"}}"#;
    let raw = reader.extract_error(StatusCode::SERVICE_UNAVAILABLE, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("503"),
        "integer code must be stringified, not fall back to status"
    );
    assert_eq!(raw.structured_type.as_deref(), Some(GRPC_UNAVAILABLE));
}

/// A string-typed `code` (some proxies emit one) is still accepted as the secondary path.
#[test]
fn test_extract_error_string_code_still_accepted() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":"429","status":"RESOURCE_EXHAUSTED"}}"#;
    let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
    assert_eq!(raw.provider_code.as_deref(), Some("429"));
}

/// When `code` is absent, extract_error falls back to `status` for the provider code.
#[test]
fn test_extract_error_status_fallback() {
    let reader = GeminiReader;
    let body = br#"{"error":{"status":"PERMISSION_DENIED"}}"#;
    let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
    assert_eq!(raw.provider_code.as_deref(), Some(GRPC_PERMISSION_DENIED));
    assert_eq!(raw.structured_type.as_deref(), Some(GRPC_PERMISSION_DENIED));
}

/// Regression (R21 #17, ContextLength reachability): a real Gemini oversized-context error is a
/// 400 `INVALID_ARGUMENT` whose MESSAGE carries the token-overflow text — there is no distinct
/// google.rpc.Code for it. `extract_error` (the PRODUCTION path; `classify` is `#[cfg(test)]`
/// only) must synthesize the canonical `context_length_exceeded` provider code so the breaker
/// (breaker.rs) maps it to StatusClass::ContextLength and fails over WITHOUT penalty,
/// instead of treating the bare `"400"` code as a lane-penalizing ClientError. Before the fix
/// `provider_code` was the bare HTTP-status int and this assertion failed.
#[test]
fn test_extract_error_oversized_context_yields_canonical_code() {
    let reader = GeminiReader;
    // Native Gemini token-overflow envelope (google.rpc.Status, INVALID_ARGUMENT 400).
    let body = br#"{"error":{"code":400,"message":"The input token count (1050000) exceeds the maximum number of tokens allowed (1048576).","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(raw.http_status, 400);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "oversized-context 400 must synthesize the canonical code so the breaker fails over"
    );
    // The structured google.rpc.Code name is preserved unchanged.
    assert_eq!(raw.structured_type.as_deref(), Some(GRPC_INVALID_ARGUMENT));
}

/// A second real-world phrasing the official API emits ("input is longer than the maximum number
/// of tokens") must also synthesize the canonical code — mirroring the `classify()` substring set.
#[test]
fn test_extract_error_oversized_context_alternate_phrasing() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":400,"message":"input is longer than the maximum number of tokens","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded")
    );
}

/// A NON-context-length 400 (e.g. a malformed field) must NOT be misclassified as context-length:
/// the canonical override fires only on the token-overflow text, so an unrelated INVALID_ARGUMENT
/// keeps its bare status code (here `"400"`) and stays a lane-penalizing ClientError. Guards the
/// override against over-broad matching.
#[test]
fn test_extract_error_unrelated_invalid_argument_keeps_status_code() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":400,"message":"Invalid value at 'contents[0].role'.","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("400"),
        "a non-context-length 400 must not be misclassified as context_length_exceeded"
    );
}

/// Regression (R24 MED #3, dead-credential failover): a Gemini bad EGRESS key surfaces as an
/// HTTP 400 `INVALID_ARGUMENT` carrying `reason: API_KEY_INVALID` (google.rpc.ErrorInfo) plus an
/// "API key not valid" message. A bare 400 normalizes to ClientFault — records nothing, never
/// benches/fails over the lane — so a lane wired to a dead key keeps serving guaranteed
/// auth-rejections. `extract_error` must re-shape it so the breaker classifies it as
/// Auth → HardDown (park + fail over). Asserted end-to-end through `normalize_raw_error` +
/// `classify` against an EMPTY error_map (the shipped Gemini map has no auth entry), proving the
/// fix is operator-config-independent.
#[test]
fn test_extract_error_bad_api_key_classifies_as_auth_harddown() {
    let reader = GeminiReader;
    // Native Gemini bad-key envelope: 400 INVALID_ARGUMENT, ErrorInfo reason API_KEY_INVALID.
    let body = br#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com"}]}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    // Re-shaped to the canonical Auth-classifying HTTP status so the breaker benches the lane.
    assert_eq!(
        raw.http_status, 401,
        "a dead Gemini key must re-shape to the Auth-classifying status, not relay 400"
    );
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("auth"),
        "bad-key 400 must synthesize the canonical auth provider_code"
    );
    // Normalize against an EMPTY error_map → must still land on Auth → HardDown.
    let empty_map = std::collections::HashMap::new();
    let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert!(
        matches!(sig.class, StatusClass::Auth),
        "bad Gemini key must classify as Auth, got {:?}",
        sig.class
    );
    assert!(
        matches!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::HardDown
        ),
        "a dead credential must HardDown the lane so it parks and fails over"
    );
}

/// The documented machine-readable `API_KEY_INVALID` reason can also accompany a 403
/// `PERMISSION_DENIED` (a key lacking access). It must classify the same way.
#[test]
fn test_extract_error_bad_api_key_permission_denied_is_auth() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":403,"message":"Permission denied: API key not valid.","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}"#;
    let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
    assert_eq!(raw.http_status, 401);
    assert_eq!(raw.provider_code.as_deref(), Some("auth"));
    let empty_map = std::collections::HashMap::new();
    let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert!(matches!(sig.class, StatusClass::Auth));
}

/// PRECISION GUARD: a GENERIC `INVALID_ARGUMENT` 400 (a real field-validation error, no api-key
/// signal) must NOT be misclassified as auth — it stays a lane-healthy ClientFault that records
/// nothing and relays verbatim. Without a precise heuristic the override would bench healthy lanes
/// on every malformed caller request.
#[test]
fn test_extract_error_generic_invalid_argument_stays_client_fault() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":400,"message":"Invalid value at 'contents[0].role' (TYPE_ENUM), \"banana\"","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    // Untouched: real 400, bare status code, no auth synthesis.
    assert_eq!(
        raw.http_status, 400,
        "a generic validation 400 must NOT be re-shaped to the auth status"
    );
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("400"),
        "a generic INVALID_ARGUMENT must keep its bare status code, not become auth"
    );
    let empty_map = std::collections::HashMap::new();
    let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert!(
        matches!(sig.class, StatusClass::ClientError),
        "a generic validation 400 must stay ClientError, got {:?}",
        sig.class
    );
    assert!(
        matches!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::ClientFault
        ),
        "a generic validation 400 must stay a no-penalty ClientFault"
    );
}

/// PRECISION GUARD: a bare `PERMISSION_DENIED` with NO api-key text (e.g. the existing
/// status-fallback fixture shape) must NOT be re-shaped — the prose heuristic requires an explicit
/// "api key" + invalid/expired signal, so a permission error without that text stays as-is and is
/// classified by HTTP status alone.
#[test]
fn test_extract_error_bare_permission_denied_not_treated_as_bad_key() {
    let reader = GeminiReader;
    let body = br#"{"error":{"status":"PERMISSION_DENIED"}}"#;
    let raw = reader.extract_error(StatusCode::FORBIDDEN, body);
    // http_status is the real 403, provider_code falls back to the status name — unchanged.
    assert_eq!(raw.http_status, 403);
    assert_eq!(raw.provider_code.as_deref(), Some(GRPC_PERMISSION_DENIED));
}

/// Malformed (non-JSON) error bodies yield None fields without panicking.
#[test]
fn test_extract_error_non_json_body() {
    let reader = GeminiReader;
    let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, b"upstream exploded");
    assert_eq!(raw.http_status, 500);
    assert_eq!(raw.provider_code, None);
    assert_eq!(raw.structured_type, None);
}

/// The native Gemini error envelope is google.rpc.Status-shaped:
/// `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`. `code` is the HTTP status
/// int, `status` is the canonical google.rpc.Code name. A known `kind` maps to the matching
/// name; the body is valid JSON the official SDK can decode into `APIError.code`/`.status`.
#[test]
fn test_write_error_native_gemini_envelope() {
    let writer = GeminiWriter;
    let v = writer.write_error(404, "not_found", "model 'x' not found");
    // Round-trips as JSON (no panic).
    let serialized = serde_json::to_string(&v).expect("write_error must serialize");
    let reparsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("write_error must be valid JSON");
    assert_eq!(reparsed["error"]["code"], serde_json::json!(404));
    assert_eq!(
        reparsed["error"]["message"],
        serde_json::json!("model 'x' not found")
    );
    assert_eq!(reparsed["error"]["status"], serde_json::json!("NOT_FOUND"));
    // The generic envelope's `type` field must NOT appear (this is the native shape).
    assert!(
        reparsed["error"].get("type").is_none(),
        "native gemini envelope must not carry an OpenAI-style `type`: {v}"
    );
}

/// `kind` is mapped onto the google.rpc.Code vocabulary (e.g. rate-limit → RESOURCE_EXHAUSTED).
#[test]
fn test_write_error_kind_maps_to_status_vocabulary() {
    let writer = GeminiWriter;
    let v = writer.write_error(429, "rate_limit_error", "slow down");
    assert_eq!(v["error"]["code"], serde_json::json!(429));
    assert_eq!(
        v["error"]["status"],
        serde_json::json!("RESOURCE_EXHAUSTED") // golden wire-contract literal (kept bare on purpose)
    );

    let v = writer.write_error(400, "invalid_request_error", "bad");
    assert_eq!(v["error"]["status"], serde_json::json!("INVALID_ARGUMENT"));
    // golden wire-contract literal (kept bare on purpose)
}

/// An unrecognized `kind` falls back to the HTTP-status-derived google.rpc.Code name (never a
/// non-canonical `status` string a native SDK would choke on). Exercises the no-catch-all path.
#[test]
fn test_write_error_unknown_kind_falls_back_to_http_status() {
    let writer = GeminiWriter;
    let v = writer.write_error(403, "totally_made_up_kind", "nope");
    assert_eq!(v["error"]["status"], serde_json::json!("PERMISSION_DENIED")); // golden wire-contract literal (kept bare on purpose)
                                                                              // A 5xx with an unknown kind maps to INTERNAL.
    let v = writer.write_error(502, "totally_made_up_kind", "bad gateway");
    assert_eq!(v["error"]["status"], serde_json::json!("INTERNAL")); // golden wire-contract literal (kept bare on purpose)
}

/// Regression (R15): the emitted `code`/`status` pair must always be an INTERNALLY CONSISTENT
/// google.rpc.Status pairing — the real Generative Language API never emits `code:503` with
/// `status:INTERNAL`. On a cross-protocol upstream 503 the relay collapses the subtype onto a
/// generic 5xx `kind` (`api_error`→INTERNAL); when that kind-derived name's canonical HTTP status
/// disagrees with the actual `code`, the HTTP status drives the pairing (503→UNAVAILABLE) so the
/// two stay consistent. The bare `overloaded` alias `cross_protocol_error_kind` emits for a 503
/// also resolves to UNAVAILABLE.
#[test]
fn test_write_error_code_status_pair_stays_consistent() {
    let writer = GeminiWriter;

    // 503 relayed as the generic `api_error` kind (would have been INTERNAL) → HTTP status wins.
    let v = writer.write_error(503, "api_error", "upstream overloaded");
    assert_eq!(v["error"]["code"], serde_json::json!(503));
    assert_eq!(
        v["error"]["status"],
        serde_json::json!("UNAVAILABLE"), // golden wire-contract literal (kept bare on purpose)
        "code:503 must pair with UNAVAILABLE, never INTERNAL: {v}"
    );

    // The bare `overloaded` alias (cross_protocol_error_kind's 503 kind) maps to UNAVAILABLE.
    let v = writer.write_error(503, "overloaded", "upstream overloaded");
    assert_eq!(v["error"]["status"], serde_json::json!("UNAVAILABLE")); // golden wire-contract literal (kept bare on purpose)

    // A genuine 500 with `api_error` stays INTERNAL (consistent: INTERNAL pairs with 500).
    let v = writer.write_error(500, "api_error", "boom");
    assert_eq!(v["error"]["code"], serde_json::json!(500));
    assert_eq!(v["error"]["status"], serde_json::json!("INTERNAL")); // golden wire-contract literal (kept bare on purpose)

    // A 504 relayed as `timeout` stays DEADLINE_EXCEEDED (canonical 504 == 504).
    let v = writer.write_error(504, "timeout", "slow");
    assert_eq!(v["error"]["status"], serde_json::json!("DEADLINE_EXCEEDED")); // golden wire-contract literal (kept bare on purpose)

    // A kind whose canonical status disagrees with the code (auth→401 vs code 403) lets the HTTP
    // status drive so the pair stays a real google.rpc pairing (403→PERMISSION_DENIED).
    let v = writer.write_error(403, "auth", "denied");
    assert_eq!(v["error"]["code"], serde_json::json!(403));
    assert_eq!(v["error"]["status"], serde_json::json!("PERMISSION_DENIED"));
    // golden wire-contract literal (kept bare on purpose)
}

/// Same-protocol (Gemini→Gemini) passthrough preserves the upstream `responseId` and
/// `modelVersion` exactly: read_response captures them, write_response emits them verbatim.
#[test]
fn test_response_identity_roundtrip_preserves_id_and_model() {
    let reader = GeminiReader;
    let writer = GeminiWriter;
    let upstream = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hi"}]},
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1},
        "modelVersion": "gemini-1.5-pro-002",
        "responseId": "abc-XYZ-123_opaque"
    });
    let ir = reader.read_response(&upstream).expect("read_response");
    assert_eq!(ir.id.as_deref(), Some("abc-XYZ-123_opaque"));
    assert_eq!(ir.model.as_deref(), Some("gemini-1.5-pro-002"));

    let wire = writer.write_response(&ir);
    assert_eq!(
        wire[FIELD_RESPONSE_ID],
        serde_json::json!("abc-XYZ-123_opaque"),
        "responseId must be preserved verbatim on same-protocol passthrough: {wire}"
    );
    assert_eq!(
        wire[FIELD_MODEL_VERSION],
        serde_json::json!("gemini-1.5-pro-002"),
        "modelVersion must be preserved verbatim: {wire}"
    );
    // Gemini bodies carry no `created`; we must not fabricate one.
    assert!(
        wire.get("created").is_none(),
        "must not synthesize a `created` field Gemini never emits: {wire}"
    );
}

/// F2 conformance: a foreign / novel IR stop_reason (`refusal` from Responses, `error` from
/// Cohere) must NOT upper-case-leak into `finishReason` (e.g. "REFUSAL"/"ERROR" are outside
/// Gemini's `FinishReason` enum and a strict google-genai client rejects them). It maps to the
/// native `OTHER` member, on both the whole-body and streamed paths.
#[test]
fn foreign_stop_reason_maps_to_other_not_verbatim() {
    use crate::ir::IrStopReason as S;
    let writer = GeminiWriter;
    for foreign in [S::Refusal, S::Error, S::Other] {
        let ir = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "x".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(foreign),
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
        let wire = writer.write_response(&ir);
        assert_eq!(
            wire["candidates"][0]["finishReason"],
            serde_json::json!("OTHER"), // golden wire-contract literal (kept bare on purpose)
            "whole-body: foreign stop_reason {foreign:?} must map to OTHER: {wire}"
        );
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(foreign),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (_, frame) = writer
            .write_response_event(&ev)
            .expect("MessageDelta must emit a frame");
        assert_eq!(
            frame["candidates"][0]["finishReason"],
            serde_json::json!("OTHER"), // golden wire-contract literal (kept bare on purpose)
            "streamed: foreign stop_reason {foreign:?} must map to OTHER: {frame}"
        );
    }
}

/// Cross-protocol write where a non-Gemini backend reader DID set a response id (the normal
/// cross-protocol case — OpenAI `chatcmpl-…`, Anthropic `msg_…`) emits it as `responseId`, so a
/// native `google-genai` SDK reading `GenerateContentResponse.response_id` always sees a value.
/// No panic; the emitted value matches the IR id verbatim.
#[test]
fn test_response_identity_cross_protocol_emits_foreign_id() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
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
        id: Some("chatcmpl-abc123".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire[FIELD_RESPONSE_ID],
        serde_json::json!("chatcmpl-abc123"),
        "a cross-protocol response id must surface as responseId: {wire}"
    );
}

/// Fidelity guard: when the IR carries NO id (a native Gemini body that omitted `responseId`, or
/// a backend with no identity at all), `write_response` must NOT fabricate one — emitting a
/// `responseId` would make a native passthrough distinguishable from the real response. The
/// field is optional in the Gemini schema, so omission is SDK-valid. No panic.
#[test]
fn test_response_identity_none_id_is_omitted_not_fabricated() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
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
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert!(
        wire.get(FIELD_RESPONSE_ID).is_none(),
        "must not fabricate a responseId when the IR carries none: {wire}"
    );
}

/// The streaming reader captures the stream identity from the first chunk into MessageStart,
/// and the streaming writer emits it back (synthesizing when absent) — same-protocol fidelity.
#[test]
fn test_stream_message_start_captures_and_emits_identity() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hi"}]}
        }],
        "modelVersion": "gemini-1.5-flash",
        "responseId": "stream-abc-1"
    })]);
    let start = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageStart { id, model, .. } => Some((id.clone(), model.clone())),
            _ => None,
        })
        .expect("MessageStart emitted");
    assert_eq!(start.0.as_deref(), Some("stream-abc-1"));
    assert_eq!(start.1.as_deref(), Some("gemini-1.5-flash"));

    // The writer emits a leading identity frame carrying the captured responseId.
    let writer = GeminiWriter;
    let frame = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: start.0.clone(),
            created: None,
            model: start.1.clone(),
        })
        .expect("MessageStart must emit an identity frame");
    assert_eq!(
        frame.1[FIELD_RESPONSE_ID],
        serde_json::json!("stream-abc-1"),
        "stream MessageStart frame must carry responseId: {}",
        frame.1
    );
}

/// Cross-protocol fidelity (stream): a MessageStart with NO identity (the post-strip state on a
/// cross-protocol Gemini-ingress stream — `StreamTranslate` clears the foreign id/model) must
/// still SYNTHESIZE a `responseId`, because a native google-genai SDK reads `chunk.response_id`
/// off the first chunk. Emitting no frame (the old behavior) left the client with no responseId on
/// any cross-protocol Gemini stream — a detectable fidelity gap. Mirrors the non-stream
/// `write_response` synthesis. (Same-protocol Gemini streams never reach this writer — they pass
/// through byte-for-byte — so this only affects the cross-protocol path.)
#[test]
fn test_stream_message_start_no_identity_synthesizes_response_id() {
    let writer = GeminiWriter;
    let frame = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        })
        .expect("a synthesized-identity MessageStart must emit a frame");
    assert!(
        frame
            .1
            .get(FIELD_RESPONSE_ID)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "post-strip MessageStart must synthesize a responseId: {}",
        frame.1
    );
}

/// Regression: `write_request` must NOT inject a top-level `stream` field. The native Gemini
/// GenerateContentRequest has no such field (streaming is URL-selected); injecting it makes the
/// request non-native and can trigger INVALID_ARGUMENT on the real API.
#[test]
fn test_write_request_omits_stream_field() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
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
        stream: true,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let wire = writer.write_request(&req);
    assert!(
        wire.get("stream").is_none(),
        "write_request must not serialise a top-level `stream` field: {wire}"
    );
}

/// Regression: a NATIVE request (which never carries `stream`) must produce a body with no
/// `stream` member — i.e. the writer no longer injects one unconditionally. The streaming
/// intent (`IrRequest.stream == true`) must NOT leak into the body even when set.
#[test]
fn test_native_request_without_stream_stays_streamless() {
    let reader = GeminiReader;
    // Native Gemini request — no `stream` field.
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
    });
    let mut ir = reader.read_request(&body).expect("read_request");
    // Caller wants streaming (URL-selected), but it must not reach the body.
    ir.stream = true;
    assert!(
        !ir.extra.contains_key("stream"),
        "a native request carries no stream in extra: {:?}",
        ir.extra
    );
    let writer = GeminiWriter;
    let wire = writer.write_request(&ir);
    assert!(
        wire.get("stream").is_none(),
        "stream intent must not be serialised into the body: {wire}"
    );
}

/// Regression (R25 LOW #10, REFINE the R24 bad-key heuristic): an `INVALID_ARGUMENT` 400 whose
/// prose contains the bare word "invalid" AND names an "api key" but is NOT a bad-key error
/// (a field-validation message that references an api-key-shaped field) must stay a lane-healthy
/// ClientFault. The earlier heuristic accepted a bare "invalid" token, so it would have benched a
/// HEALTHY lane on this. The refined heuristic requires a SPECIFIC bad-key phrase.
#[test]
fn test_extract_error_invalid_word_near_api_key_stays_client_fault() {
    let reader = GeminiReader;
    // A generic validation 400: "invalid" + "api key" both present, but no bad-key phrase.
    let body = br#"{"error":{"code":400,"message":"Invalid value at 'request.api key field' (TYPE_STRING)","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
            raw.http_status, 400,
            "a generic validation 400 that merely mentions 'invalid' near 'api key' must NOT re-shape to auth"
        );
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("400"),
        "the bare status code must be preserved, not synthesized to auth"
    );
    let empty_map = std::collections::HashMap::new();
    let sig = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert!(
        matches!(sig.class, StatusClass::ClientError),
        "must stay ClientError, got {:?}",
        sig.class
    );
    assert!(
        matches!(
            crate::breaker::classify(&sig),
            crate::breaker::Disposition::ClientFault
        ),
        "must stay a no-penalty ClientFault"
    );
}

/// Companion to the refinement: an EXPIRED-key prose message ("API key expired") with no
/// machine-readable reason must STILL be detected as auth — the refined phrase set covers it.
#[test]
fn test_extract_error_expired_api_key_prose_is_auth() {
    let reader = GeminiReader;
    let body = br#"{"error":{"code":400,"message":"API key expired. Please renew the API key.","status":"INVALID_ARGUMENT"}}"#;
    let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
    assert_eq!(
        raw.http_status, 401,
        "an 'API key expired' prose message must re-shape to the auth status"
    );
    assert_eq!(raw.provider_code.as_deref(), Some("auth"));
}

/// Regression (R25 MED #2, updated for H2): a thinking-only assistant turn must NOT vanish from
/// `contents` — dropping it would collapse user/model alternation (two user turns adjacent) and
/// 400 the real Gemini API. Post-H2 the Thinking block is now emitted as a native `thought:true`
/// part (reasoning is no longer dropped), so the model turn survives by carrying that thought part
/// rather than the old empty-text placeholder. The alternation invariant (3 surviving turns) is
/// what this guards.
#[test]
fn test_write_request_thinking_only_turn_survives_with_placeholder() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "first".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Thinking {
                    text: "internal reasoning".to_string(),
                    signature: None,
                    redacted: false,
                    cache_control: None,
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "second".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
        ],
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
    let wire = writer.write_request(&req);
    let contents = wire
        .get("contents")
        .and_then(|v| v.as_array())
        .expect("contents array must exist");
    // All THREE turns must survive — the thinking-only model turn must not be dropped.
    assert_eq!(
        contents.len(),
        3,
        "thinking-only model turn must survive so user/model alternation is preserved: {wire}"
    );
    let model_turn = &contents[1];
    assert_eq!(
        model_turn.get("role").and_then(|v| v.as_str()),
        Some("model"),
        "the surviving turn must carry the model role: {model_turn}"
    );
    let parts = model_turn
        .get("parts")
        .and_then(|v| v.as_array())
        .expect("the surviving turn must carry a parts array");
    assert_eq!(
        parts.len(),
        1,
        "thinking-only turn carries exactly one part: {model_turn}"
    );
    // Post-H2: the Thinking block emits a native thought part (not dropped → not a placeholder).
    assert_eq!(
        parts[0].get("text").and_then(|v| v.as_str()),
        Some("internal reasoning"),
        "the thought part must carry the reasoning text: {model_turn}"
    );
    assert_eq!(
        parts[0].get("thought"),
        Some(&serde_json::json!(true)),
        "the surviving part must be a thought part: {model_turn}"
    );
}

/// Regression (R25 LOW #11): a tool result that parses to JSON `null` (the upstream omitted the
/// response object) must NOT be emitted as `functionResponse.response: null`. Gemini's
/// `response` is a protobuf Struct and requires a JSON OBJECT; a null is rejected (400). The
/// writer must coerce a null parse result to an empty Struct `{}`.
#[test]
fn test_write_request_null_tool_result_coerced_to_struct() {
    let writer = GeminiWriter;
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
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "get_weather".to_string(),
                // A literal "null" payload — valid JSON that parses to Value::Null.
                content: vec![crate::ir::IrBlock::Text {
                    text: "null".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
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
    let wire = writer.write_request(&req);
    let response = wire
        .get("contents")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("parts"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.get("functionResponse"))
        .and_then(|fr| fr.get("response"))
        .expect("functionResponse.response must exist");
    assert!(
        response.is_object(),
        "a null tool-result payload must be coerced to a Struct (object), got: {response}"
    );
    assert!(
        !response.is_null(),
        "functionResponse.response must never be null: {wire}"
    );
}

/// A bare-scalar tool result ("42") must likewise be coerced to a Struct — wrapped under
/// `{"output": <value>}` so the content survives — never emitted as a raw scalar.
#[test]
fn test_write_request_scalar_tool_result_coerced_to_struct() {
    let writer = GeminiWriter;
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
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "compute".to_string(),
                content: vec![crate::ir::IrBlock::Text {
                    text: "42".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
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
    let wire = writer.write_request(&req);
    let response = wire
        .get("contents")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("parts"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.get("functionResponse"))
        .and_then(|fr| fr.get("response"))
        .expect("functionResponse.response must exist");
    assert!(
        response.is_object(),
        "a scalar tool-result payload must be coerced to a Struct, got: {response}"
    );
    assert_eq!(
        response.get("output").and_then(|v| v.as_i64()),
        Some(42),
        "the scalar value must survive under the `output` key: {response}"
    );
}

/// Regression: Gemini's `Content.role` is OPTIONAL. A single-turn request that omits `role`
/// (a common native shape, accepted by the real API and the official SDK as an implicit user
/// turn) must NOT be hard-rejected. Previously `read_request` mapped any non-`user`/`model`
/// role (including absent/empty) to a `ClientError`, 400ing a request the real API serves —
/// and diverging from the streaming reader, which already treats an empty role as a model turn.
#[test]
fn test_read_request_absent_role_defaults_to_user() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"parts": [{"text": "hi"}]}]
    });
    let ir = reader
        .read_request(&body)
        .expect("a role-less content must be accepted as a user turn, not rejected");
    assert_eq!(ir.messages.len(), 1, "one message expected: {ir:?}");
    assert_eq!(
        ir.messages[0].role,
        crate::ir::IrRole::User,
        "an absent role must default to user: {ir:?}"
    );
}

/// An explicitly EMPTY role string (`"role": ""`) is likewise treated as a user turn, matching
/// the absent-role case and the streaming reader's `role_val.is_empty()` leniency.
#[test]
fn test_read_request_empty_role_defaults_to_user() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "", "parts": [{"text": "hi"}]}]
    });
    let ir = reader
        .read_request(&body)
        .expect("an empty role must be accepted as a user turn, not rejected");
    assert_eq!(
        ir.messages[0].role,
        crate::ir::IrRole::User,
        "an empty role must default to user: {ir:?}"
    );
}

/// A genuinely unexpected NON-EMPTY role string is still a hard client error — the leniency is
/// scoped to the absent/empty case (the real API's optional-role default), not to arbitrary
/// role values.
#[test]
fn test_read_request_unknown_nonempty_role_still_rejected() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "function", "parts": [{"text": "hi"}]}]
    });
    assert!(
        reader.read_request(&body).is_err(),
        "an unexpected non-empty role must still be rejected"
    );
}

/// Regression: `model` is preserved in `extra` exactly once (no duplicate insert) and survives
/// the read path because it is excluded from the loop via `modeled_keys`.
#[test]
fn test_read_request_model_preserved_in_extra_once() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "model": "gemini-1.5-pro"
    });
    let ir = reader.read_request(&body).expect("read_request");
    assert_eq!(
        ir.extra.get("model"),
        Some(&serde_json::json!("gemini-1.5-pro")),
        "model must be preserved in extra: {:?}",
        ir.extra
    );
}

/// Regression: a ToolResult whose content is multi-part PLAIN TEXT (not JSON) must be wrapped in
/// `{"output": <text>}` rather than silently discarded as an empty `{}` object.
#[test]
fn test_write_request_tool_result_plaintext_wrapped_not_dropped() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "get_weather".to_string(),
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "sunny".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Text {
                        text: "and warm".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                ],
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
    let wire = writer.write_request(&req);
    let resp = wire
        .pointer("/contents/0/parts/0/functionResponse/response")
        .expect("functionResponse.response must be present");
    assert_ne!(
        resp,
        &serde_json::json!({}),
        "plain-text tool result must not be discarded as empty object: {wire}"
    );
    assert_eq!(
        resp.get("output").and_then(|o| o.as_str()),
        Some("sunny and warm"),
        "plain-text tool result must be wrapped as {{\"output\": text}}: {wire}"
    );
}

/// A ToolResult whose joined text IS valid JSON is forwarded structurally (not wrapped).
#[test]
fn test_write_request_tool_result_json_passthrough() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "f".to_string(),
                content: vec![crate::ir::IrBlock::Text {
                    text: "{\"temp\":21}".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
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
    let wire = writer.write_request(&req);
    let temp = wire
        .pointer("/contents/0/parts/0/functionResponse/response/temp")
        .and_then(|v| v.as_i64());
    assert_eq!(temp, Some(21), "JSON tool result must pass through: {wire}");
}

/// Regression: a cross-protocol response with NO foreign id but a populated `created` (the
/// boundary signal `proxy engine` leaves intact after stripping `id`) must SYNTHESIZE a
/// Gemini-shaped `responseId` so a native SDK always sees a value. Previously omitted entirely.
#[test]
fn test_response_identity_cross_protocol_synthesizes_id_when_created_set() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
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
        id: None,
        created: Some(1_700_000_000),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    let synth = wire
        .get(FIELD_RESPONSE_ID)
        .and_then(|v| v.as_str())
        .expect("cross-protocol response (created set, id none) must synthesize responseId");
    assert!(
        !synth.is_empty(),
        "synthesized responseId must be non-empty: {wire}"
    );
}

/// Regression: the in-stream Error frame emits the FULL google.rpc.Status envelope
/// (`code` int + UPPER_SNAKE `status` + message), not a message-only object, so a Gemini SDK
/// can branch on `error.status`/`error.code`. Class → code/status is exhaustive (no catch-all).
#[test]
fn test_stream_error_emits_full_google_rpc_status() {
    let writer = GeminiWriter;
    let err = crate::proto::IrError {
        class: StatusClass::RateLimit,
        provider_signal: Some("slow down".to_string()),
        retry_after: None,
    };
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::Error(err))
        .expect("Error event must emit a frame");
    assert_eq!(
        frame.pointer("/error/code"),
        Some(&serde_json::json!(429)),
        "frame: {frame}"
    );
    assert_eq!(
        frame.pointer("/error/status").and_then(|s| s.as_str()),
        Some("RESOURCE_EXHAUSTED"), // golden wire-contract literal (kept bare on purpose)
        "frame: {frame}"
    );
    assert_eq!(
        frame.pointer("/error/message").and_then(|m| m.as_str()),
        Some("slow down"),
        "frame: {frame}"
    );
}

/// A server-error class maps to 500/INTERNAL in the stream error envelope.
#[test]
fn test_stream_error_server_error_maps_internal() {
    let writer = GeminiWriter;
    let err = crate::proto::IrError {
        class: StatusClass::ServerError,
        provider_signal: None,
        retry_after: None,
    };
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::Error(err))
        .expect("Error event must emit a frame");
    assert_eq!(frame.pointer("/error/code"), Some(&serde_json::json!(500)));
    assert_eq!(
        frame.pointer("/error/status").and_then(|s| s.as_str()),
        Some("INTERNAL") // golden wire-contract literal (kept bare on purpose)
    );
    // No provider_signal → default message, no panic.
    assert_eq!(
        frame.pointer("/error/message").and_then(|m| m.as_str()),
        Some("error")
    );
}

/// A cross-protocol stream that carries only a model (no id) surfaces `modelVersion` AND a
/// synthesized `responseId` on the leading frame — a native SDK reads both `chunk.model_version`
/// and `chunk.response_id` off the first chunk.
#[test]
fn test_stream_message_start_model_only_emits_model_version() {
    let writer = GeminiWriter;
    let frame = writer
        .write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: Some("gemini-1.5-pro".to_string()),
        })
        .expect("a model-bearing MessageStart must emit a frame");
    assert_eq!(
        frame.1[FIELD_MODEL_VERSION],
        serde_json::json!("gemini-1.5-pro"),
        "frame must carry modelVersion: {}",
        frame.1
    );
    assert!(
        frame
            .1
            .get(FIELD_RESPONSE_ID)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "no id → responseId synthesized so the SDK still sees one: {}",
        frame.1
    );
}

// --- Round 3 fix 1: functionCall ToolUse blocks must carry a non-empty, stable id ---

/// Regression: a Gemini `functionCall` in `read_request` must produce a NON-EMPTY tool-use id
/// (Gemini carries none). Previously `id: String::new()` made cross-protocol Anthropic/OpenAI
/// egress emit an empty `id`/`tool_use_id`, which those APIs reject / mis-correlate.
#[test]
fn test_read_request_functioncall_gets_nonempty_id() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{
            "role": "model",
            "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let id = ir.messages[0].content.iter().find_map(|b| match b {
        crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
        _ => None,
    });
    let id = id.expect("ToolUse block must be present");
    assert!(!id.is_empty(), "synthesized tool-use id must be non-empty");
}

/// Regression: two `functionCall`s sharing the SAME function name in one request must get
/// DISTINCT non-empty ids (the call index disambiguates) so `tool_result` routing cannot
/// collapse them on cross-protocol egress.
#[test]
fn test_read_request_same_name_tool_calls_get_distinct_ids() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{
            "role": "model",
            "parts": [
                {"functionCall": {"name": "search", "args": {"q": "a"}}},
                {"functionCall": {"name": "search", "args": {"q": "b"}}}
            ]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let ids: Vec<String> = ir.messages[0]
        .content
        .iter()
        .filter_map(|b| match b {
            crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 2, "two tool-use blocks expected");
    assert!(ids.iter().all(|i| !i.is_empty()), "ids must be non-empty");
    assert_ne!(
        ids[0], ids[1],
        "repeated function name must still yield distinct ids: {ids:?}"
    );
}

/// Regression: the synthesized id is DETERMINISTIC for a given (index, name) — two reads of the
/// same request body produce the same ids (stable within a request lifetime).
#[test]
fn test_read_request_tool_call_id_is_deterministic() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{
            "role": "model",
            "parts": [{"functionCall": {"name": "f", "args": {}}}]
        }]
    });
    let id_of = |r: &GeminiReader| {
        r.read_request(&body).unwrap().messages[0]
            .content
            .iter()
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
                _ => None,
            })
            .unwrap()
    };
    assert_eq!(id_of(&reader), id_of(&reader), "id must be deterministic");
}

/// Regression: the same-protocol ToolResult correlation key stays the function NAME (the writer
/// round-trips it into `functionResponse.name`), NOT the synthetic ToolUse id. Guards against a
/// regression where the synth id leaks onto the result name and breaks Gemini→Gemini passthrough.
#[test]
fn test_read_request_functionresponse_tool_use_id_is_name() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"functionResponse": {"name": "get_weather", "response": {"t": 21}}}]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let tid = ir.messages[0].content.iter().find_map(|b| match b {
        crate::ir::IrBlock::ToolResult { tool_use_id, .. } => Some(tool_use_id.clone()),
        _ => None,
    });
    assert_eq!(
        tid.as_deref(),
        Some("get_weather"),
        "result correlation key must remain the function name for same-protocol round-trip"
    );
}

/// Regression: a `functionCall` in `read_response` (non-stream) must also carry a non-empty id.
#[test]
fn test_read_response_functioncall_gets_nonempty_id() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "f", "args": {}}}]
            },
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    });
    let ir = reader.read_response(&body).expect("read_response");
    let id = ir.content.iter().find_map(|b| match b {
        crate::ir::IrBlock::ToolUse { id, .. } => Some(id.clone()),
        _ => None,
    });
    assert!(
        id.is_some_and(|i| !i.is_empty()),
        "response ToolUse must carry a non-empty id"
    );
}

/// Regression (MEDIUM/correctness): a SAFETY-filtered Gemini candidate carries only
/// `finishReason` + `safetyRatings` and NO `content` field. `read_response` must decode it as an
/// empty-content response with the mapped stop reason, NOT hard-fail (which proxy engine turned into
/// a spurious 500). Mirrors the streaming reader's `if let Some(content)` tolerance.
#[test]
fn test_read_response_safety_filtered_candidate_no_content_is_ok() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "finishReason": GEMINI_FINISH_SAFETY,
            "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}]
        }],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 0}
    });
    let ir = reader
        .read_response(&body)
        .expect("safety-filtered candidate (no content) must decode, not error");
    assert!(
        ir.content.is_empty(),
        "filtered candidate has no content blocks, got {:?}",
        ir.content
    );
    assert!(
        ir.stop_reason.is_some(),
        "the SAFETY finishReason must still map to a stop_reason"
    );
}

/// Regression (MED, completeness): a PROMPT-blocked Gemini stream chunk carries a top-level
/// `promptFeedback.blockReason`, NO `candidates`, and NO `error`. The reader must surface it as a
/// PROPER TERMINAL SEQUENCE — MessageStart, then a `safety` MessageDelta + MessageStop — not a
/// bare MessageStart followed by EOF (which left the downstream client on a hung, non-terminated
/// stream with an empty response). Old code emitted only MessageStart and never terminated.
#[test]
fn test_stream_prompt_block_emits_terminal_sequence() {
    let events = collect_stream(&[serde_json::json!({
        "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
    })]);

    // Exactly one MessageStart, one MessageDelta, one MessageStop — a complete terminal stream.
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStart { .. }))
            .count(),
        1,
        "prompt-block stream must emit exactly one MessageStart: {events:?}"
    );
    let stop_reason = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
        _ => None,
    });
    assert_eq!(
        stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "prompt-block must surface a `safety` stop_reason: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(IrStreamEvent::MessageStop)),
        "the stream must terminate with MessageStop: {events:?}"
    );
    // No stray content blocks for a blocked prompt.
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStart { .. })),
        "a blocked prompt must not open any content block: {events:?}"
    );
}

/// Regression (LOW #10, bug): a MID-STREAM prompt-block arm must close any blocks opened by
/// earlier chunks before emitting its terminal MessageDelta/MessageStop. A normal text chunk
/// opens a content block (BlockStart{0}); a following `promptFeedback.blockReason` SAFETY chunk
/// (NO candidates) previously emitted the terminal MessageDelta/MessageStop WITHOUT closing that
/// open block, leaving an unbalanced IR stream (orphaned BlockStart). The fixed arm mirrors the
/// finishReason path: the second chunk must emit exactly [BlockStop{0}, MessageDelta{safety},
/// MessageStop].
#[test]
fn test_stream_mid_stream_prompt_block_closes_open_text_block() {
    let reader = GeminiReader;
    let mut state = StreamDecodeState::default();

    // Chunk 1: a normal text chunk opens a content block.
    let first = reader.read_response_events(
        "",
        &serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "hello"}], "role": "model"}
            }]
        }),
        &mut state,
    );
    assert!(
        first
            .iter()
            .any(|e| matches!(e, IrStreamEvent::BlockStart { index: 0, .. })),
        "first chunk must open block 0: {first:?}"
    );
    assert!(
        state.text_block_open,
        "text block must remain open after the first chunk: {first:?}"
    );

    // Chunk 2: a mid-stream prompt-block (NO candidates) must close block 0, then terminate.
    let second = reader.read_response_events(
        "",
        &serde_json::json!({
            "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
        }),
        &mut state,
    );

    let stop_reason = second.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
        _ => None,
    });
    assert!(
        matches!(
            second.as_slice(),
            [
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta { .. },
                IrStreamEvent::MessageStop,
            ]
        ),
        "mid-stream prompt-block must emit [BlockStop{{0}}, MessageDelta, MessageStop]: {second:?}"
    );
    assert_eq!(
        stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "the terminal MessageDelta must carry a `safety` stop_reason: {second:?}"
    );
    assert!(
        !state.text_block_open,
        "the open text block flag must be cleared after the prompt-block close: {second:?}"
    );
}

/// Regression (MED, completeness): a PROMPT-blocked NON-STREAMING Gemini body (top-level
/// `promptFeedback.blockReason`, NO `candidates`, NO `error`) must decode to an empty-content
/// response with a `safety` stop reason, NOT hard-fail with `ir_parse` (which the old
/// absent-candidates arm did → a spurious client error with no surfaced reason).
#[test]
fn test_read_response_prompt_block_is_safety_stop_not_error() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "promptFeedback": {
            "blockReason": GEMINI_FINISH_PROHIBITED_CONTENT,
            "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}]
        },
        "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 0}
    });
    let ir = reader
        .read_response(&body)
        .expect("prompt-blocked body must decode, not error");
    assert!(
        ir.content.is_empty(),
        "a blocked prompt has no content blocks, got {:?}",
        ir.content
    );
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "a blocked prompt must surface a `safety` stop_reason"
    );
    assert_eq!(ir.usage.input_tokens, 9, "usage must still be surfaced");
}

/// Regression: a candidates-absent body with NEITHER an error NOR a promptFeedback.blockReason is
/// still a malformed envelope and MUST hard-fail — the prompt-block arm must not swallow it.
#[test]
fn test_read_response_candidates_absent_without_block_still_errors() {
    let reader = GeminiReader;
    let body = serde_json::json!({"usageMetadata": {"promptTokenCount": 1}});
    assert!(
        reader.read_response(&body).is_err(),
        "a candidates-absent body with no block reason must still error"
    );
}

/// Regression (LOW, bug): a STREAMING zero-arg `functionCall` (no `args` field) must emit an
/// empty JSON OBJECT `{}` as its InputJsonDelta, NOT `null`. Serializing `null` produced an
/// invalid tool-input shape on cross-protocol egress.
#[test]
fn test_stream_zero_arg_function_call_emits_empty_object_not_null() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"functionCall": {"name": "ping"}}]},
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);
    let args_json = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockDelta {
            delta: IrDelta::InputJsonDelta(s),
            ..
        } => Some(s.clone()),
        _ => None,
    });
    assert_eq!(
        args_json.as_deref(),
        Some("{}"),
        "zero-arg streamed functionCall must serialize to `{{}}`, not `null`: {events:?}"
    );
}

/// Regression (LOW, bug): a NON-STREAMING zero-arg `functionCall` (no `args` field) must decode
/// to an empty-object `input` (`{}`), NOT `null`.
#[test]
fn test_read_response_zero_arg_function_call_input_is_empty_object_not_null() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"functionCall": {"name": "ping"}}]},
            "finishReason": GEMINI_FINISH_STOP
        }]
    });
    let ir = reader.read_response(&body).expect("read_response");
    let input = ir.content.iter().find_map(|b| match b {
        crate::ir::IrBlock::ToolUse { input, .. } => Some(input.clone()),
        _ => None,
    });
    assert_eq!(
        input,
        Some(serde_json::Value::Object(serde_json::Map::new())),
        "zero-arg functionCall input must be `{{}}`, not null: {:?}",
        ir.content
    );
}

/// Regression: the streaming `BlockStart` for a tool block must carry a non-empty synthesized
/// id (Gemini streams carry none) so the Anthropic/OpenAI stream writers emit a usable id.
#[test]
fn test_stream_tool_blockstart_id_is_nonempty() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "f", "args": {}}}]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);
    let id = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            block: IrBlockMeta::ToolUse { id, .. },
            ..
        } => Some(id.clone()),
        _ => None,
    });
    assert!(
        id.is_some_and(|i| !i.is_empty()),
        "stream tool BlockStart must carry a non-empty id"
    );
}

// --- Round 3 fix 2: `stream` round-trip semantics + accurate comment ---

/// Regression / documentation guard for the corrected `stream` comment. A source `stream` is
/// captured into the typed `IrRequest.stream` (used only by path selection) AND preserved in
/// `extra` for byte-identical round-trip (exactly like `model`), so the writer echoes it back.
/// This is the behavior `src/proto/mod.rs::test_gemini_roundtrip_identity` (a non-owned test)
/// enforces. The Round-3 finding's prescribed "drop stream from extra" would break that
/// byte-identity invariant; the real defect (a FALSE comment claiming stream was excluded from
/// extra) is fixed by making the comment accurate instead.
#[test]
fn test_read_request_source_stream_round_trips_via_extra() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "stream": true
    });
    let ir = reader.read_request(&body).expect("read_request");
    assert!(ir.stream, "stream must be captured into IrRequest.stream");
    assert_eq!(
        ir.extra.get("stream"),
        Some(&serde_json::json!(true)),
        "a source `stream` is preserved in extra for round-trip identity (like model): {:?}",
        ir.extra
    );
    let writer = GeminiWriter;
    let wire = writer.write_request(&ir);
    assert_eq!(
        wire.get("stream"),
        Some(&serde_json::json!(true)),
        "source `stream` round-trips onto the egress body via extra: {wire}"
    );
}

/// Regression: a NATIVE Gemini request carries no `stream`, so neither `extra` nor the egress
/// body gains one even when the caller wants streaming (URL-selected). Guards the writer's
/// "never synthesizes a stream member from req.stream" invariant.
#[test]
fn test_read_request_native_no_stream_stays_absent() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
    });
    let mut ir = reader.read_request(&body).expect("read_request");
    ir.stream = true; // caller wants streaming; must not reach the body
    assert!(
        !ir.extra.contains_key("stream"),
        "native request carries no stream in extra: {:?}",
        ir.extra
    );
    let writer = GeminiWriter;
    let wire = writer.write_request(&ir);
    assert!(
        wire.get("stream").is_none(),
        "stream intent must not be synthesized onto a native body: {wire}"
    );
}

/// Regression (R6, class D — integer-overflow on a cast): a `maxOutputTokens` above `u32::MAX`
/// must NOT silently truncate (wrap) into a tiny token cap. The bounds-checked `u32::try_from`
/// drops an out-of-range value to `None`, so the request carries no cap and the backend applies
/// its default — never a mangled one. A bare `as u32` would have wrapped `5_000_000_000` to
/// `705_032_704`, a cap the caller never asked for.
#[test]
fn test_read_request_max_output_tokens_overflow_drops_to_none() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"maxOutputTokens": 5_000_000_000i64}
    });
    let ir = reader.read_request(&body).expect("read_request");
    assert_eq!(
        ir.max_tokens, None,
        "an out-of-u32-range maxOutputTokens must drop to None, not truncate"
    );

    // An in-range value still round-trips faithfully.
    let body_ok = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"maxOutputTokens": 1024}
    });
    let ir_ok = reader.read_request(&body_ok).expect("read_request");
    assert_eq!(
        ir_ok.max_tokens,
        Some(1024),
        "in-range cap must be preserved"
    );
}

// --- Round 3 fix 3: bogus snake_case `tool_config` removed; native `toolConfig` round-trips ---

/// Regression: native Gemini `toolConfig` (camelCase) is NOT in `modeled_keys`, so it
/// round-trips through `extra` and back onto the wire unchanged. The old bogus snake_case
/// `tool_config` modeled-key entry (which matched no real field) has been removed.
#[test]
fn test_read_request_native_tool_config_round_trips_via_extra() {
    let reader = GeminiReader;
    let tool_config = serde_json::json!({
        "functionCallingConfig": {"mode": "ANY"}
    });
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "toolConfig": tool_config.clone()
    });
    let ir = reader.read_request(&body).expect("read_request");
    assert_eq!(
        ir.extra.get("toolConfig"),
        Some(&tool_config),
        "native toolConfig must round-trip through extra: {:?}",
        ir.extra
    );
    let writer = GeminiWriter;
    let wire = writer.write_request(&ir);
    assert_eq!(
        wire.get("toolConfig"),
        Some(&tool_config),
        "toolConfig must be re-emitted on the wire: {wire}"
    );
}

/// Regression (R15): unmodeled `generationConfig` sub-fields (`responseMimeType` for JSON mode,
/// `thinkingConfig` for extended thinking, `candidateCount`, `seed`, …) MUST survive read→write
/// instead of being silently dropped. The reader keeps the raw `generationConfig` in `extra`; the
/// writer overlays the 5 typed fields onto it. Both the typed fields AND every unmodeled sub-field
/// must appear on the re-emitted body.
#[test]
fn test_generation_config_unmodeled_subfields_survive_roundtrip() {
    let reader = GeminiReader;
    let writer = GeminiWriter;
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {
            "maxOutputTokens": 256,
            "temperature": 0.3,
            "responseMimeType": MIME_APPLICATION_JSON,
            "thinkingConfig": {"thinkingBudget": 1024},
            "candidateCount": 2,
            "seed": 42
        }
    });

    let ir = reader.read_request(&body).expect("read_request");
    // The raw generationConfig is preserved in extra (not modeled-out).
    assert!(
        ir.extra.contains_key("generationConfig"),
        "raw generationConfig must be preserved in extra: {:?}",
        ir.extra
    );
    // The 5 typed sub-fields are still promoted.
    assert_eq!(ir.max_tokens, Some(256));
    assert_eq!(ir.temperature, Some(0.3));

    let wire = writer.write_request(&ir);
    let gc = wire
        .get("generationConfig")
        .and_then(|g| g.as_object())
        .expect("generationConfig must be emitted");
    // Typed overlays present.
    assert_eq!(gc.get("maxOutputTokens"), Some(&serde_json::json!(256)));
    assert_eq!(gc.get("temperature"), Some(&serde_json::json!(0.3)));
    // Unmodeled sub-fields preserved (the defect was silently dropping these).
    assert_eq!(
        gc.get(FIELD_RESPONSE_MIME_TYPE),
        Some(&serde_json::json!(MIME_APPLICATION_JSON)),
        "responseMimeType (JSON mode) must survive: {wire}"
    );
    assert_eq!(
        gc.get("thinkingConfig"),
        Some(&serde_json::json!({"thinkingBudget": 1024})),
        "thinkingConfig (extended thinking) must survive: {wire}"
    );
    assert_eq!(gc.get("candidateCount"), Some(&serde_json::json!(2)));
    assert_eq!(gc.get("seed"), Some(&serde_json::json!(42)));
    // The raw generationConfig must NOT also appear as a duplicate top-level extra echo (the
    // writer skips it in the extra merge loop).
    assert_eq!(
        wire.as_object()
            .map(|o| o.keys().filter(|k| *k == "generationConfig").count()),
        Some(1),
        "generationConfig must appear exactly once: {wire}"
    );
}

/// Regression (R15): the typed IR fields OVERLAY the raw extra copy — if the IR's typed
/// `max_tokens` differs from the raw `generationConfig.maxOutputTokens` (e.g. a cross-protocol
/// edit), the typed value wins, mirroring BedrockWriter's inferenceConfig overlay.
#[test]
fn test_generation_config_typed_fields_override_raw_extra() {
    let writer = GeminiWriter;
    let mut extra = serde_json::Map::new();
    extra.insert(
        "generationConfig".to_string(),
        serde_json::json!({"maxOutputTokens": 100, "responseMimeType": "text/plain"}),
    );
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
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: Vec::new(),
        max_tokens: Some(999),
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
        extra,
    };
    let wire = writer.write_request(&ir);
    let gc = wire
        .get("generationConfig")
        .and_then(|g| g.as_object())
        .expect("generationConfig must be emitted");
    assert_eq!(
        gc.get("maxOutputTokens"),
        Some(&serde_json::json!(999)),
        "typed max_tokens must overlay the raw extra value: {wire}"
    );
    assert_eq!(
        gc.get(FIELD_RESPONSE_MIME_TYPE),
        Some(&serde_json::json!("text/plain")),
        "unmodeled sub-field must survive the overlay: {wire}"
    );
}

// --- Round 3 fix 4: streamed and whole-body usageMetadata include totalTokenCount ---

/// Regression: the streamed `MessageDelta` usage frame must include `totalTokenCount`
/// (= prompt + candidates), matching the native final-chunk shape.
#[test]
fn test_stream_message_delta_includes_total_token_count() {
    let writer = GeminiWriter;
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 7,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("MessageDelta must emit a frame");
    assert_eq!(
        frame.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(12)),
        "streamed usage must carry totalTokenCount = prompt + candidates: {frame}"
    );
    assert_eq!(
        frame.pointer("/usageMetadata/promptTokenCount"),
        Some(&serde_json::json!(7))
    );
    assert_eq!(
        frame.pointer("/usageMetadata/candidatesTokenCount"),
        Some(&serde_json::json!(5))
    );
}

/// The streamed total saturates (never overflow-panics) on pathological counts — guards the
/// `saturating_add` on the request path.
#[test]
fn test_stream_message_delta_total_token_count_saturates() {
    let writer = GeminiWriter;
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: u64::MAX,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("MessageDelta must emit a frame");
    assert_eq!(
        frame.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(u64::MAX)),
        "totalTokenCount must saturate, not wrap/panic: {frame}"
    );
}

/// Regression (R5): on the CROSS-protocol egress path (signalled by a populated `created` — the
/// boundary marker a non-Gemini backend reader leaves, since Gemini bodies carry no timestamp)
/// the whole-body `write_response` usageMetadata MUST include `totalTokenCount` (= prompt +
/// candidates). A native Gemini `generateContent` body always carries the sum, and the value is a
/// faithfully derived total (not a fabricated field). Earlier it was omitted, leaving the
/// google-genai SDK's `total_token_count` at None/0 for cross-protocol callers.
#[test]
fn test_write_response_includes_total_token_count_cross_protocol() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 5,
            output_tokens: 3,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: Some(1_700_000_000), // cross-protocol boundary signal
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(8)),
        "cross-protocol usage must carry totalTokenCount = prompt + candidates: {wire}"
    );
    assert_eq!(
        wire.pointer("/usageMetadata/promptTokenCount"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        wire.pointer("/usageMetadata/candidatesTokenCount"),
        Some(&serde_json::json!(3))
    );
}

/// Fidelity guard: a SAME-protocol read→write (no `created` — native Gemini bodies carry no
/// timestamp) must NOT inject `totalTokenCount` the upstream omitted, so the round-trip stays
/// byte-identical. (Production same-protocol passthrough bypasses the writer entirely; this
/// guards the in-IR read→write identity invariant `test_gemini_read_write_response_roundtrip`
/// in mod.rs depends on.)
#[test]
fn test_write_response_omits_total_token_count_same_protocol() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 5,
            output_tokens: 3,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: None, // same-protocol: no boundary signal
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert!(
        wire.pointer("/usageMetadata/totalTokenCount").is_none(),
        "same-protocol round-trip must omit totalTokenCount for byte-identity: {wire}"
    );
}

/// The cross-protocol whole-body total saturates (never overflow-panics) on pathological counts.
#[test]
fn test_write_response_total_token_count_saturates() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: Vec::new(),
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: u64::MAX,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: None,
        created: Some(1_700_000_000), // cross-protocol
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(u64::MAX)),
        "totalTokenCount must saturate, not wrap/panic: {wire}"
    );
}

// --- Round 9 fix (conformance): totalTokenCount also emits when the boundary signal is `model`
//     (not just `created`), so Anthropic/Cohere backends — whose readers return `created: None`
//     but DO populate `model` — no longer drop the total for a Gemini client. ---

/// Regression (R9): a cross-protocol response from a backend whose reader sets `created: None`
/// but `model: Some(..)` (the Anthropic and Cohere shape) MUST still carry
/// `usageMetadata.totalTokenCount`. Before R9 the gate keyed on `created` alone, so these three-
/// of-five backends produced a usageMetadata block lacking the total, leaving the google-genai
/// SDK's `total_token_count` at None and breaking client-side billing.
#[test]
fn test_write_response_includes_total_token_count_when_only_model_present() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 11,
            output_tokens: 4,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        // Anthropic/Cohere cross-protocol shape: model survives, created/id are None.
        model: Some("claude-opus-4-8".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(15)),
        "model-only cross-protocol boundary must still carry totalTokenCount: {wire}"
    );
    assert_eq!(
        wire.pointer("/usageMetadata/promptTokenCount"),
        Some(&serde_json::json!(11))
    );
    assert_eq!(
        wire.pointer("/usageMetadata/candidatesTokenCount"),
        Some(&serde_json::json!(4))
    );
}

/// The model-only cross-protocol total saturates (never overflow-panics) on pathological counts,
/// guarding the `saturating_add` on this newly-reachable branch of the request path.
#[test]
fn test_write_response_model_only_total_token_count_saturates() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: Vec::new(),
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: u64::MAX,
            output_tokens: 7,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("command-r".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire.pointer("/usageMetadata/totalTokenCount"),
        Some(&serde_json::json!(u64::MAX)),
        "totalTokenCount must saturate, not wrap/panic: {wire}"
    );
}

// --- Round 9 fix (performance): modeled_keys is hoisted to a process-global OnceLock. ---

/// Regression (R9): the modeled-key set is a stable process-global — repeated calls return the
/// SAME backing allocation (proving it is built once, not per request) and the set's membership
/// is exactly the modeled top-level keys, so unmodeled keys still flow to `extra`.
#[test]
fn test_modeled_request_keys_is_stable_singleton() {
    let a = modeled_request_keys();
    let b = modeled_request_keys();
    assert!(
        std::ptr::eq(a, b),
        "modeled_request_keys must return the same cached set, not rebuild per call"
    );
    for k in [
        "contents",
        "tools",
        "systemInstruction",
        "model",
        crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY,
    ] {
        assert!(a.contains(k), "modeled key set must contain {k}");
    }
    // An arbitrary caller field is NOT modeled, so the reader sweeps it into `extra`.
    assert!(!a.contains("toolConfig"), "toolConfig must not be modeled");
    // `generationConfig` is INTENTIONALLY not modeled-out of `extra`: the reader keeps the raw
    // object so the writer can overlay the 5 typed fields and preserve unmodeled sub-fields.
    assert!(
        !a.contains("generationConfig"),
        "generationConfig must NOT be modeled-out of extra (raw object is preserved for overlay)"
    );
}

/// Regression (R9): hoisting the set must not change read behavior — an unmodeled top-level key
/// still round-trips through `extra`, and the modeled `model` key is preserved exactly once.
#[test]
fn test_read_request_unmodeled_key_still_flows_to_extra_after_hoist() {
    let reader = GeminiReader;
    let j = serde_json::json!({
        "model": "gemini-pro",
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}}
    });
    let ir = reader
        .read_request(&j)
        .expect("read_request should succeed");
    assert_eq!(
        ir.extra.get("toolConfig"),
        Some(&serde_json::json!({"functionCallingConfig": {"mode": "AUTO"}})),
        "unmodeled toolConfig must be preserved in extra"
    );
    assert_eq!(
        ir.extra.get("model"),
        Some(&serde_json::json!("gemini-pro")),
        "modeled `model` is preserved in extra exactly once for round-trip identity"
    );
    assert!(
        !ir.extra.contains_key("contents"),
        "modeled `contents` must NOT leak into extra"
    );
}

// --- Round 5 fix: tool_use stop reason maps to STOP (Gemini has no TOOL_USE enum member) ---

/// Regression: a buffered `write_response` with stop_reason=tool_use (the canonical value every
/// other protocol's reader emits for a tool-call turn) must emit finishReason "STOP", NOT the
/// invalid "TOOL_USE" the old upper-casing fallback produced.
#[test]
fn test_write_response_tool_use_maps_to_stop() {
    let writer = GeminiWriter;
    let ir = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::ToolUse {
            id: "call_1".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"city": "SF"}),
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
    };
    let wire = writer.write_response(&ir);
    assert_eq!(
        wire.pointer("/candidates/0/finishReason")
            .and_then(|f| f.as_str()),
        Some("STOP"), // golden wire-contract literal (kept bare on purpose)
        "tool_use must map to STOP, never TOOL_USE: {wire}"
    );
}

/// Regression: the streamed `MessageDelta` with stop_reason=tool_use also emits finishReason
/// "STOP" (matching native Gemini, whose FinishReason enum has no TOOL_USE member).
#[test]
fn test_stream_message_delta_tool_use_maps_to_stop() {
    let writer = GeminiWriter;
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_, frame) = writer
        .write_response_event(&ev)
        .expect("MessageDelta must emit a frame");
    assert_eq!(
        frame
            .pointer("/candidates/0/finishReason")
            .and_then(|f| f.as_str()),
        Some("STOP"), // golden wire-contract literal (kept bare on purpose)
        "streamed tool_use must map to STOP, never TOOL_USE: {frame}"
    );
}

// --- Round 5 fix: image_url sentinel emitted as native fileData URI, not corrupt base64 ---

/// Regression: an IR Image carrying the `"image_url"` media_type SENTINEL (a remote https URL
/// stored verbatim by the OpenAI/Responses readers) must be emitted as Gemini `fileData{fileUri}`
/// — the native URL reference — NOT as `inlineData` with the URL stuffed into the base64 `data`
/// field and a bogus `mimeType: "image_url"`.
#[test]
fn test_write_request_image_url_sentinel_emits_file_data() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
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
                source: crate::ir::IrImageSource::Url("https://example.com/cat.png".to_string()),
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
    let wire = writer.write_request(&req);
    assert_eq!(
        wire.pointer("/contents/0/parts/0/fileData/fileUri")
            .and_then(|u| u.as_str()),
        Some("https://example.com/cat.png"),
        "image_url sentinel must emit native fileData.fileUri: {wire}"
    );
    assert!(
        wire.pointer("/contents/0/parts/0/inlineData").is_none(),
        "sentinel URL must NOT be emitted as base64 inlineData: {wire}"
    );
}

/// A real base64 image (a genuine mimeType) still emits as `inlineData` — the sentinel branch
/// must not divert legitimate base64 payloads.
#[test]
fn test_write_request_base64_image_still_inline_data() {
    let writer = GeminiWriter;
    let req = crate::ir::IrRequest {
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
                    media_type: "image/png".to_string(),
                    data: "aGVsbG8=".to_string(),
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
    let wire = writer.write_request(&req);
    assert_eq!(
        wire.pointer("/contents/0/parts/0/inlineData/mimeType")
            .and_then(|m| m.as_str()),
        Some("image/png"),
        "base64 image must stay inlineData: {wire}"
    );
    assert_eq!(
        wire.pointer("/contents/0/parts/0/inlineData/data")
            .and_then(|d| d.as_str()),
        Some("aGVsbG8="),
    );
}

/// Round-trip: a native Gemini `fileData{fileUri}` part reads into the typed `Url` image source
/// and the writer re-emits it as `fileData{fileUri}` verbatim (same-protocol fidelity).
#[test]
fn test_file_data_image_round_trips_via_url() {
    let reader = GeminiReader;
    let writer = GeminiWriter;
    let body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"fileData": {"fileUri": "gs://bucket/img.jpg"}}]
        }]
    });
    let ir = reader.read_request(&body).expect("read_request");
    let url = ir.messages[0].content.iter().find_map(|b| match b {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => Some(url.clone()),
        _ => None,
    });
    assert_eq!(
        url.as_deref(),
        Some("gs://bucket/img.jpg"),
        "fileData must read into the typed Url source: {ir:?}"
    );
    let wire = writer.write_request(&ir);
    assert_eq!(
        wire.pointer("/contents/0/parts/0/fileData/fileUri")
            .and_then(|u| u.as_str()),
        Some("gs://bucket/img.jpg"),
        "fileData must round-trip verbatim: {wire}"
    );
}

// --- Round 14 fix: synth_response_id is an opaque CSPRNG token of native Gemini shape ---

/// Regression (HIGH/conformance): a synthesized `responseId` must be a native-shaped opaque
/// token — mixed-case alphanumeric base62 of native length, with NO hyphen separator and NO
/// lowercase-hex-only restriction. The old `format!("{:x}-{:x}", unix_now_secs(), seq)` form was
/// structurally distinguishable (the `-` plus `[0-9a-f]`-only class is a shape no native id has)
/// AND leaked the proxy host clock in its leading hex segment. Assert the shape never regresses.
#[test]
fn test_synth_response_id_is_opaque_native_shape() {
    let id = synth_response_id();
    assert_eq!(
        id.len(),
        RESPONSE_ID_TOKEN_LEN,
        "synthesized responseId must be exactly the native token length: {id}"
    );
    assert!(
        !id.contains('-'),
        "synthesized responseId must carry NO hyphen separator (a non-native tell): {id}"
    );
    assert!(
        id.chars().all(|c| c.is_ascii_alphanumeric()),
        "synthesized responseId must be mixed-case alphanumeric (no `-`/`_`): {id}"
    );
    // A lowercase-hex-only token (`[0-9a-f]*`) is the old timestamp-hex tell. Across a batch the
    // synthesized ids must NOT be confinable to that class — at least one carries an uppercase
    // letter or a digit/letter outside `[0-9a-f]`, proving the wider base62 character class.
    let saw_non_hex = (0..64).map(|_| synth_response_id()).any(|s| {
        s.chars()
            .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
    });
    assert!(
        saw_non_hex,
        "synthesized responseIds must draw from mixed-case base62, not lowercase-hex only"
    );
}

/// The synthesized id must embed NO unix-second prefix: the old form's leading segment WAS the
/// server clock. Mint two ids and assert neither equals the hex of the current unix second (the
/// old leading segment), and that they are not hyphen-delimited time+counter pairs.
#[test]
fn test_synth_response_id_leaks_no_timestamp() {
    let now_hex = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    for _ in 0..16 {
        let id = synth_response_id();
        assert!(
            !id.starts_with(&now_hex),
            "synthesized responseId must not lead with the unix-second hex (clock leak): {id}"
        );
        assert!(
            !id.contains('-'),
            "synthesized responseId must not be a hyphenated time-counter pair: {id}"
        );
    }
}

/// Two consecutive synthesized ids differ because the whole 16-char base62 token is drawn from
/// `getrandom` (~95 bits of entropy) — guards the collision-free per-process uniqueness property.
#[test]
fn test_synth_response_id_distinct_consecutive() {
    let a = synth_response_id();
    let b = synth_response_id();
    assert_ne!(a, b, "consecutive synthesized ids must differ: {a} vs {b}");
}

/// Regression (LOW/quality, R18): the base62 reduction must be UNBIASED. The old body mapped each
/// random byte with a bare `byte % 62`; because `256 % 62 != 0`, the 8 symbols reachable from the
/// partial final block (bytes `248..=255` → residues `0..=7`) were drawn at 5/256 while the other
/// 54 symbols were drawn at 4/256 — a ~25% over-representation of those 8 symbols. Rejection
/// sampling (reject bytes `>= 248`) flattens that. Draw a large burst, tally per-symbol frequency,
/// and assert the over-represented class is NOT systematically inflated: the mean frequency of the
/// 8 formerly-hot symbols must stay close to the mean of the other 54. Under the OLD biased code
/// the hot/cold ratio is ~1.25 and this assertion fails; under rejection sampling it is ~1.0.
#[test]
fn test_synth_response_id_base62_is_unbiased() {
    use std::collections::HashMap;
    // Symbols reachable from residues 0..=7 (the formerly over-represented class).
    let hot: Vec<char> = RESPONSE_ID_ALPHABET[..8]
        .iter()
        .map(|&b| b as char)
        .collect();

    let mut counts: HashMap<char, u64> = HashMap::new();
    let mut total: u64 = 0;
    for _ in 0..40_000 {
        for c in synth_response_id().chars() {
            *counts.entry(c).or_insert(0) += 1;
            total += 1;
        }
    }
    assert!(total > 0, "burst produced no symbols");

    let hot_sum: u64 = hot.iter().map(|c| *counts.get(c).unwrap_or(&0)).sum();
    let cold_sum: u64 = counts
        .iter()
        .filter(|(c, _)| !hot.contains(c))
        .map(|(_, n)| *n)
        .sum();
    // Per-symbol means: 8 hot symbols vs 54 cold symbols.
    let hot_mean = hot_sum as f64 / hot.len() as f64;
    let cold_count = 62 - hot.len();
    let cold_mean = cold_sum as f64 / cold_count as f64;
    assert!(cold_mean > 0.0, "no cold-symbol samples observed");
    let ratio = hot_mean / cold_mean;
    // Unbiased ≈ 1.0; old biased code ≈ 1.25. A generous window catches the bias while tolerating
    // ordinary sampling noise over ~640k symbols.
    assert!(
        (0.90..=1.10).contains(&ratio),
        "base62 reduction is biased: hot/cold per-symbol frequency ratio {ratio:.4} \
             (hot_mean {hot_mean:.1}, cold_mean {cold_mean:.1}) — expected ~1.0 from unbiased \
             rejection sampling, ~1.25 indicates the old `byte % 62` bias regressed"
    );
}

/// Uniqueness burst (R18): a large run of synthesized ids must be collision-free in practice (each
/// is ~95 bits). Mint a burst and assert every id is distinct and native-shaped.
#[test]
fn test_synth_response_id_uniqueness_burst() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for _ in 0..50_000 {
        let id = synth_response_id();
        assert_eq!(id.len(), RESPONSE_ID_TOKEN_LEN, "non-native length: {id}");
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric()),
            "non-base62 char in id: {id}"
        );
        assert!(
            seen.insert(id.clone()),
            "synthesized responseId collided: {id}"
        );
    }
}

/// Regression (HIGH/performance): `state.open_tools` is only drained on a `finishReason` chunk,
/// so an upstream that streams an unbounded run of `functionCall` parts WITHOUT a finishReason
/// must not grow it without bound. Past `MAX_GEMINI_TOOL_FRAMES` new tool frames stop being
/// recorded (and their events suppressed), keeping the set capped while every realistic stream
/// (a handful of tools) is unaffected. Mirrors the Cohere reader's cap regression.
#[test]
fn test_stream_open_tools_growth_is_capped() {
    let reader = GeminiReader;
    let mut state = StreamDecodeState::default();
    // Feed many functionCall parts across many chunks, never sending a finishReason so the
    // drain path never runs — the only thing that can keep the set bounded is the cap.
    for n in 0..(MAX_GEMINI_TOOL_FRAMES + 200) {
        reader.read_response_events(
            "",
            &serde_json::json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                    }
                }]
            }),
            &mut state,
        );
    }
    assert!(
        state.open_tools.len() <= MAX_GEMINI_TOOL_FRAMES,
        "open_tools must be capped at MAX_GEMINI_TOOL_FRAMES, got {}",
        state.open_tools.len()
    );
}

/// The cap must NOT perturb a realistic stream: a small number of tool calls are all recorded
/// and each gets a matching BlockStart it can close on finishReason.
#[test]
fn test_stream_open_tools_under_cap_records_all() {
    let reader = GeminiReader;
    let mut state = StreamDecodeState::default();
    let mut starts = 0usize;
    for n in 0..3 {
        for ev in reader.read_response_events(
            "",
            &serde_json::json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{"functionCall": {"name": format!("f{n}"), "args": {}}}]
                    }
                }]
            }),
            &mut state,
        ) {
            if matches!(ev, IrStreamEvent::BlockStart { .. }) {
                starts += 1;
            }
        }
    }
    assert_eq!(state.open_tools.len(), 3, "all 3 tool frames recorded");
    assert_eq!(starts, 3, "each tool frame emits exactly one BlockStart");
}

/// A well-formed credential yields exactly one `x-goog-api-key` header carrying the verbatim key.
#[test]
fn test_auth_headers_valid_key_emits_x_goog_api_key() {
    let writer = GeminiWriter;
    let headers = writer.auth_headers("AIzaSyValidKey123");
    assert_eq!(headers.len(), 1, "one auth header for a valid key");
    assert_eq!(headers[0].0.as_str(), "x-goog-api-key");
    assert_eq!(headers[0].1.to_str().ok(), Some("AIzaSyValidKey123"));
}

/// MEDIUM/security regression: a credential whose bytes are invalid for an HTTP header value
/// (here an embedded newline) must NOT be silently swallowed into an empty `x-goog-api-key`
/// value. The writer omits the header entirely (empty vec) and never panics on the request path.
/// The accompanying `tracing::warn!` (not asserted here) gives the operator the diagnostic the
/// empty-header behavior lacked.
#[test]
fn test_auth_headers_invalid_key_omits_header_no_empty_value() {
    let writer = GeminiWriter;
    let headers = writer.auth_headers("bad\nkey");
    assert!(
        headers.is_empty(),
        "an invalid-byte credential must omit the auth header, not emit an empty value: \
             {headers:?}"
    );
}

/// An ASCII control byte other than the newline above (here a NUL) is also rejected, exercising
/// the control-character class of header-invalid byte the validation guards against.
#[test]
fn test_auth_headers_control_byte_key_omits_header() {
    let writer = GeminiWriter;
    let headers = writer.auth_headers("key\u{0000}bad");
    assert!(
        headers.is_empty(),
        "a control-byte credential must omit the auth header: {headers:?}"
    );
}

/// HIGH/correctness regression: a Tool-role IR message carries `ToolResult` blocks, which the
/// writer emits as Gemini `functionResponse` parts. In the native GenerateContentRequest schema
/// a `functionResponse` turn MUST be sent under `role:"user"` — the `model` role is exclusively
/// the assistant turn (which produces `functionCall`s). Mapping Tool → "model" emits a
/// non-native shape the real Gemini API / google-genai SDK rejects (400 INVALID_ARGUMENT). The
/// turn carrying the `functionResponse` must therefore have `role == "user"`, matching the
/// Bedrock writer's `toolResult` handling.
#[test]
fn test_tool_role_maps_to_user_for_function_response() {
    let writer = GeminiWriter;
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
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "get_weather".to_string(),
                content: vec![crate::ir::IrBlock::Text {
                    text: "{\"temp\":21}".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
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

    let wire = writer.write_request(&req);
    let content = &wire["contents"][0];

    assert_eq!(
        content["role"], "user",
        "a Tool-role message carrying a functionResponse must be emitted under role:\"user\", \
             never \"model\": {wire}"
    );
    // The functionResponse part must still be present and correctly shaped under that turn.
    let fr = &content["parts"][0]["functionResponse"];
    assert_eq!(
        fr["name"], "get_weather",
        "functionResponse must name the tool: {wire}"
    );
    assert_eq!(
        fr["response"]["temp"], 21,
        "structured JSON tool output must be forwarded verbatim: {wire}"
    );
}

/// HIGH/correctness regression: an Assistant-role message carrying a `functionCall` (ToolUse)
/// must still be emitted under `role:"model"` — the fix to the Tool role must NOT regress the
/// assistant mapping, since `functionCall`s are exclusively a model-turn shape.
#[test]
fn test_assistant_tool_use_stays_model_role() {
    let writer = GeminiWriter;
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
            content: vec![crate::ir::IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({ "city": "SF" }),
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

    let wire = writer.write_request(&req);
    let content = &wire["contents"][0];
    assert_eq!(
        content["role"], "model",
        "an Assistant functionCall turn must stay role:\"model\": {wire}"
    );
    assert_eq!(
        content["parts"][0][FIELD_FUNCTION_CALL]["name"], "get_weather",
        "functionCall must be preserved under the model turn: {wire}"
    );
}

/// Regression (MEDIUM/correctness): an inline `{"error":{...}}` google.rpc.Status object
/// delivered as a 200-status SSE data chunk mid-stream MUST surface as a single
/// `IrStreamEvent::Error` (mapped from `error.status`) rather than being silently swallowed.
/// Before the fix the reader emitted a bare MessageStart and then nothing — a hung,
/// non-terminated stream — because the chunk carried no `candidates`.
#[test]
fn test_stream_inline_error_envelope_surfaces_ir_error() {
    let events = collect_stream(&[serde_json::json!({
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (e.g. check quota).",
            "status": GRPC_RESOURCE_EXHAUSTED
        }
    })]);

    // Exactly one event, an Error mapped to RateLimit, carrying the upstream message. NO
    // MessageStart precedes it (an error-only chunk must not emit a stray start frame).
    match events.as_slice() {
        [IrStreamEvent::Error(err)] => {
            assert_eq!(err.class, StatusClass::RateLimit, "events: {events:?}");
            assert_eq!(
                err.provider_signal.as_deref(),
                Some("Resource has been exhausted (e.g. check quota)."),
                "events: {events:?}"
            );
        }
        other => panic!("expected exactly one IrStreamEvent::Error, got {other:?}"),
    }
}

/// An inline error whose `status` is absent falls back to the numeric `code` mapping (503 →
/// Overloaded), and a missing/unknown code defaults to ServerError — never silently dropped.
#[test]
fn test_stream_inline_error_code_fallback_and_default() {
    // status absent → 503 maps to Overloaded.
    let by_code = collect_stream(&[serde_json::json!({
        "error": { "code": 503, "message": "backend overloaded" }
    })]);
    match by_code.as_slice() {
        [IrStreamEvent::Error(err)] => {
            assert_eq!(err.class, StatusClass::Overloaded, "events: {by_code:?}")
        }
        other => panic!("expected one Error, got {other:?}"),
    }

    // Neither status nor a recognized code → ServerError default (safe, breaker-tripping).
    let bare = collect_stream(&[serde_json::json!({
        "error": { "message": "something failed" }
    })]);
    match bare.as_slice() {
        [IrStreamEvent::Error(err)] => {
            assert_eq!(err.class, StatusClass::ServerError, "events: {bare:?}");
            assert_eq!(
                err.provider_signal.as_deref(),
                Some("something failed"),
                "events: {bare:?}"
            );
        }
        other => panic!("expected one Error, got {other:?}"),
    }
}

/// `gemini_error_status_class` prefers the UPPER_SNAKE `status` over the numeric `code`, and an
/// unrecognized status string falls through to the code mapping.
#[test]
fn test_gemini_error_status_class_mapping() {
    assert_eq!(
        gemini_error_status_class(Some(GRPC_UNAVAILABLE), Some(503)),
        StatusClass::Overloaded
    );
    assert_eq!(
        gemini_error_status_class(Some(GRPC_UNAUTHENTICATED), Some(401)),
        StatusClass::Auth
    );
    assert_eq!(
        gemini_error_status_class(Some(GRPC_PERMISSION_DENIED), Some(403)),
        StatusClass::Billing
    );
    assert_eq!(
        gemini_error_status_class(Some(GRPC_DEADLINE_EXCEEDED), Some(504)),
        StatusClass::Timeout
    );
    assert_eq!(
        gemini_error_status_class(Some(GRPC_INVALID_ARGUMENT), Some(400)),
        StatusClass::ClientError
    );
    // status wins over code: an INTERNAL status with a (nonsensical) 429 code is ServerError.
    assert_eq!(
        gemini_error_status_class(Some(GRPC_INTERNAL), Some(429)),
        StatusClass::ServerError
    );
    // Unknown status string → fall through to the numeric code (429 → RateLimit).
    assert_eq!(
        gemini_error_status_class(Some("SOME_FUTURE_CODE"), Some(429)),
        StatusClass::RateLimit
    );
}

/// Regression (MEDIUM/conformance): the Gemini bad-key auth-failure envelope MUST carry the
/// canonical `error.details[]` array with a google.rpc.ErrorInfo whose `reason` is
/// `API_KEY_INVALID`. The `google-genai` SDK keys auth handling off `details[].reason`, so the
/// real Generative Language API always populates it on the bad-key 400. The triple of (status
/// 400, INVALID_ARGUMENT, the canonical bad-key message) is exactly what
/// `auth.rs::unauthorized_response` produces for a Gemini-inferred path.
#[test]
fn test_write_error_bad_key_carries_api_key_invalid_details() {
    let writer = GeminiWriter;
    let envelope = writer.write_error(
        400,
        "invalid_request_error",
        crate::proto::gemini::GEMINI_BAD_KEY_MESSAGE,
    );

    assert_eq!(
        envelope.pointer("/error/code"),
        Some(&serde_json::json!(400)),
        "envelope: {envelope}"
    );
    assert_eq!(
        envelope.pointer("/error/status").and_then(|s| s.as_str()),
        Some("INVALID_ARGUMENT"), // golden wire-contract literal (kept bare on purpose)
        "envelope: {envelope}"
    );
    let detail = envelope
        .pointer("/error/details/0")
        .expect("bad-key envelope must carry error.details[0]");
    assert_eq!(
        detail.get("@type").and_then(|t| t.as_str()),
        Some("type.googleapis.com/google.rpc.ErrorInfo"), // golden wire-contract literal (kept bare on purpose)
        "detail: {detail}"
    );
    assert_eq!(
        detail.get("reason").and_then(|r| r.as_str()),
        Some("API_KEY_INVALID"), // golden wire-contract literal (kept bare on purpose)
        "detail: {detail}"
    );
    assert_eq!(
        detail.get("domain").and_then(|d| d.as_str()),
        Some("googleapis.com"),
        "detail: {detail}"
    );
    assert_eq!(
        detail.pointer("/metadata/service").and_then(|s| s.as_str()),
        Some("generativelanguage.googleapis.com"),
        "detail: {detail}"
    );
}

/// A NON-auth 400/INVALID_ARGUMENT (e.g. a generic malformed-request body) must NOT grow the
/// API_KEY_INVALID details array — real Google does not carry that reason on a non-key 400, so
/// over-filling it would itself be a tell. Only the canonical bad-key message triggers details.
#[test]
fn test_write_error_generic_invalid_argument_has_no_details() {
    let writer = GeminiWriter;
    let envelope = writer.write_error(400, "invalid_request_error", "Invalid value at 'contents'.");
    assert_eq!(
        envelope.pointer("/error/status").and_then(|s| s.as_str()),
        Some("INVALID_ARGUMENT"), // golden wire-contract literal (kept bare on purpose)
        "envelope: {envelope}"
    );
    assert!(
        envelope.pointer("/error/details").is_none(),
        "a non-bad-key 400 must NOT carry API_KEY_INVALID details: {envelope}"
    );
}

/// HIGH/correctness regression: on a CROSS-protocol multi-turn tool call (Anthropic/OpenAI
/// ingress → Gemini egress) the IR's ToolUse carries a SYNTHETIC `call_<hash>` id and the matching
/// ToolResult's `tool_use_id` carries that SAME synthetic id — NOT the real function name. Gemini
/// correlates a `functionResponse` to its `functionCall` strictly BY NAME (no ids), so the emitted
/// `functionResponse.name` MUST equal the `functionCall.name` (`get_weather`), NOT the hash.
/// Before the fix the writer emitted the hash verbatim, so the backend could not correlate and
/// every cross-protocol→Gemini multi-turn tool call broke. The writer resolves the real name from
/// an id→name map built across all request messages.
#[test]
fn test_write_request_cross_protocol_function_response_name_matches_call() {
    let writer = GeminiWriter;
    let synthetic_id = "call_00000000deadbeef".to_string();
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![
            // Assistant turn: the tool CALL carries a synthetic id, real name `get_weather`.
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: synthetic_id.clone(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({ "city": "SF" }),
                    cache_control: None,
                }],
            },
            // Tool turn: the RESULT references the call by the SAME synthetic id (cross-protocol
            // seam keeps the id, not the name).
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: synthetic_id.clone(),
                    content: vec![crate::ir::IrBlock::Text {
                        text: "{\"temp\":21}".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            },
        ],
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

    let wire = writer.write_request(&req);
    let call_name = wire
        .pointer("/contents/0/parts/0/functionCall/name")
        .and_then(|n| n.as_str());
    let resp_name = wire
        .pointer("/contents/1/parts/0/functionResponse/name")
        .and_then(|n| n.as_str());
    assert_eq!(
        call_name,
        Some("get_weather"),
        "functionCall.name must be the real tool name: {wire}"
    );
    assert_eq!(
        resp_name,
        Some("get_weather"),
        "functionResponse.name must resolve to the real function name (matching \
             functionCall.name), NOT the synthetic call_<hash> id: {wire}"
    );
    assert_eq!(
        call_name, resp_name,
        "Gemini correlates by name: functionResponse.name MUST equal functionCall.name: {wire}"
    );
}

/// Same-protocol (Gemini→Gemini) regression guard for the fix above: when the ToolResult's
/// `tool_use_id` is ALREADY the function name (the reader's same-protocol behavior) and there is no
/// matching ToolUse id in the request, the writer must FALL BACK to that name verbatim — the
/// id→name map lookup must not blank it out.
#[test]
fn test_write_request_same_protocol_function_response_name_falls_back_to_id() {
    let writer = GeminiWriter;
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
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "get_weather".to_string(),
                content: vec![crate::ir::IrBlock::Text {
                    text: "{\"temp\":21}".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
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
    let wire = writer.write_request(&req);
    assert_eq!(
        wire.pointer("/contents/0/parts/0/functionResponse/name")
            .and_then(|n| n.as_str()),
        Some("get_weather"),
        "same-protocol functionResponse.name must fall back to the tool_use_id (the name): {wire}"
    );
}

/// LOW/completeness regression: a STREAMING chunk with an EMPTY `candidates: []` array (rather than
/// an absent array) alongside a top-level `promptFeedback.blockReason` must still route into the
/// prompt-block terminal arm — MessageStart, then a `safety` MessageDelta + MessageStop. Before the
/// fix `candidates_absent` keyed only on array-PRESENCE, so `[]` slipped past the arm and the
/// stream emitted a bare un-terminated frame.
#[test]
fn test_stream_empty_candidates_array_prompt_block_terminates() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [],
        "promptFeedback": {"blockReason": GEMINI_FINISH_SAFETY},
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 0}
    })]);
    let stop_reason = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => *stop_reason,
        _ => None,
    });
    assert_eq!(
        stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "an empty candidates[] + blockReason stream must surface a `safety` stop: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(IrStreamEvent::MessageStop)),
        "the empty-candidates prompt-block stream must terminate with MessageStop: {events:?}"
    );
}

/// LOW/completeness regression: a NON-STREAMING body with an EMPTY `candidates: []` array plus a
/// top-level `promptFeedback.blockReason` must decode to an empty-content `safety` response, NOT
/// hard-fail `candidates.is_empty()` into a spurious `ir_parse` error (the old behavior, since
/// `candidates_absent` treated `[]` as present and skipped the prompt-block arm).
#[test]
fn test_read_response_empty_candidates_array_prompt_block_is_safety_stop() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [],
        "promptFeedback": {"blockReason": GEMINI_FINISH_PROHIBITED_CONTENT},
        "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 0}
    });
    let ir = reader
        .read_response(&body)
        .expect("empty-candidates prompt-blocked body must decode, not error");
    assert!(
        ir.content.is_empty(),
        "a blocked prompt has no content blocks, got {:?}",
        ir.content
    );
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "an empty candidates[] + blockReason body must surface a `safety` stop_reason"
    );
}

/// Guard: an EMPTY `candidates: []` with NO block reason and NO error is still a malformed
/// envelope and MUST hard-fail (the broadened `candidates_absent` routes it into the prompt-block
/// arm, which finds no reason and falls through to the existing empty-array hard-fail below).
#[test]
fn test_read_response_empty_candidates_array_without_block_still_errors() {
    let reader = GeminiReader;
    let body = serde_json::json!({"candidates": [], "usageMetadata": {"promptTokenCount": 1}});
    assert!(
        reader.read_response(&body).is_err(),
        "an empty candidates[] body with no block reason must still error"
    );
}

/// Regression (MED #2): Gemini has no TOOL_USE finishReason — a tool-call turn ends with STOP.
/// `read_response` mapped STOP → `end_turn` unconditionally, so the IR carried `end_turn` next to
/// a `ToolUse` block, which leaked on cross-protocol egress (Anthropic relays `end_turn`; OpenAI
/// maps it to `"stop"`). When a `ToolUse` block is present, the buffered reader MUST promote
/// `end_turn` → `tool_use`. Fails against the old unconditional mapping.
#[test]
fn test_read_response_stop_with_function_call_is_tool_use() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    });
    let ir = reader
        .read_response(&body)
        .expect("tool-call STOP body must decode");
    assert!(
        ir.content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. })),
        "the response must carry a ToolUse block: {:?}",
        ir.content
    );
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::ToolUse),
        "STOP + functionCall must read back as `tool_use`, not `end_turn`"
    );
}

/// Companion guard (MED #2): a plain STOP with NO tool block must stay `end_turn`. The promotion
/// must be gated on a ToolUse block being present, not applied to every STOP.
#[test]
fn test_read_response_plain_stop_stays_end_turn() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hello"}]},
            "finishReason": GEMINI_FINISH_STOP
        }]
    });
    let ir = reader.read_response(&body).expect("plain STOP must decode");
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::EndTurn),
        "a plain STOP with no tool block must stay `end_turn`"
    );
}

/// Regression (MED #2, streaming sibling): the streaming reader mapped STOP → `end_turn` on the
/// terminal MessageDelta unconditionally, leaking `end_turn` for a tool-call turn on the streamed
/// cross-protocol path. When tool blocks were opened this run (`state.open_tools` non-empty at the
/// finishReason handler), the terminal stop_reason MUST be `tool_use`. Fails against old code.
#[test]
fn test_stream_stop_with_function_call_terminal_is_tool_use() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]
            },
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);
    let stop = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
        _ => None,
    });
    assert_eq!(
        stop.flatten(),
        Some(crate::ir::IrStopReason::ToolUse),
        "streamed STOP + functionCall must terminate with `tool_use`: {events:?}"
    );
}

/// Companion guard (MED #2, streaming): a plain STOP stream with no tool block must terminate
/// with `end_turn` (no spurious promotion when `state.open_tools` is empty).
#[test]
fn test_stream_plain_stop_terminal_stays_end_turn() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hello"}]},
            "finishReason": GEMINI_FINISH_STOP
        }]
    })]);
    let stop = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
        _ => None,
    });
    assert_eq!(
        stop.flatten(),
        Some(crate::ir::IrStopReason::EndTurn),
        "a plain STOP stream must terminate with `end_turn`: {events:?}"
    );
}

/// Regression (LOW #10): a `ToolUse.input` that is a JSON ARRAY must be coerced to a valid Gemini
/// `functionCall.args` OBJECT (Gemini `args` is a protobuf Struct). The old code passed an array
/// through verbatim (`input.is_array()` branch), producing a backend-rejected request. After the
/// fix the array is wrapped under `{"args": <value>}`. Asserts BOTH writers (request + response).
#[test]
fn test_tool_use_array_input_coerced_to_object_args() {
    let block = crate::ir::IrBlock::ToolUse {
        id: "call_1".to_string(),
        name: "do_thing".to_string(),
        input: serde_json::json!([1, 2, 3]),
        cache_control: None,
    };

    // write_request path
    let writer = GeminiWriter;
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
            content: vec![block.clone()],
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
    let wire = writer.write_request(&req);
    let args = wire
        .pointer("/contents/0/parts/0/functionCall/args")
        .expect("functionCall.args must be present");
    assert!(
        args.is_object(),
        "request functionCall.args MUST be an object (Gemini Struct), got: {args}"
    );
    assert_eq!(
        args.pointer("/args"),
        Some(&serde_json::json!([1, 2, 3])),
        "array input must be wrapped under `args`: {args}"
    );

    // write_response path
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![block],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
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
    };
    let rwire = writer.write_response(&resp);
    let rargs = rwire
        .pointer("/candidates/0/content/parts/0/functionCall/args")
        .expect("response functionCall.args must be present");
    assert!(
        rargs.is_object(),
        "response functionCall.args MUST be an object, got: {rargs}"
    );
    assert_eq!(
        rargs.pointer("/args"),
        Some(&serde_json::json!([1, 2, 3])),
        "array input must be wrapped under `args` in the response too: {rargs}"
    );
}

/// Companion guard (LOW #10): an OBJECT `ToolUse.input` must pass through byte-identical so the
/// same-protocol Gemini→Gemini round-trip stays lossless (no `{"args": ...}` wrapping).
#[test]
fn test_tool_use_object_input_passes_through_unchanged() {
    let writer = GeminiWriter;
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::ToolUse {
            id: "call_1".to_string(),
            name: "do_thing".to_string(),
            input: serde_json::json!({"city": "SF", "unit": "C"}),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
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
    };
    let rwire = writer.write_response(&resp);
    let rargs = rwire
        .pointer("/candidates/0/content/parts/0/functionCall/args")
        .expect("functionCall.args must be present");
    assert_eq!(
        rargs,
        &serde_json::json!({"city": "SF", "unit": "C"}),
        "object input must pass through unchanged (no `args` wrapper): {rargs}"
    );
}

// ---- PF-H1: Gemini tool_choice (functionCallingConfig) round-trips ----

fn gemini_read(body: serde_json::Value) -> crate::ir::IrRequest {
    GeminiReader
        .read_request(&body)
        .expect("gemini read_request")
}

#[test]
fn tool_choice_any_required_roundtrips() {
    let ir = gemini_read(serde_json::json!({
        "contents": [],
        "toolConfig": {"functionCallingConfig": {"mode": "ANY"}}
    }));
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
    let writer = GeminiWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out["toolConfig"]["functionCallingConfig"],
        serde_json::json!({"mode": "ANY"})
    );
}

#[test]
fn tool_choice_specific_tool_roundtrips() {
    let ir = gemini_read(serde_json::json!({
        "contents": [],
        "toolConfig": {"functionCallingConfig":
            {"mode": "ANY", "allowedFunctionNames": ["get_weather"]}}
    }));
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
    let writer = GeminiWriter;
    let out = writer.write_request(&ir);
    assert_eq!(
        out["toolConfig"]["functionCallingConfig"],
        serde_json::json!({"mode": "ANY", "allowedFunctionNames": ["get_weather"]})
    );
}

/// Fix #10 (fidelity): `ANY` + `allowedFunctionNames` with N>1 names cannot be expressed by the
/// IR's single-tool `Tool` variant. Rather than fabricating `Tool{name: first}` (inventing a
/// stricter constraint the request never made), it must degrade to `Required` (call SOME tool) —
/// a true superset of the allow-list. A SINGLE name still maps to `Tool{name}` (unchanged).
#[test]
fn tool_choice_multi_name_allowlist_relaxes_to_required() {
    let ir = gemini_read(serde_json::json!({
        "contents": [],
        "toolConfig": {"functionCallingConfig":
            {"mode": "ANY", "allowedFunctionNames": ["get_weather", "get_time"]}}
    }));
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Required),
        "a multi-name allow-list must relax to Required, not Tool{{name: first}}"
    );

    // A single-name allow-list is still representable and must stay a targeted Tool.
    let ir_one = gemini_read(serde_json::json!({
        "contents": [],
        "toolConfig": {"functionCallingConfig":
            {"mode": "ANY", "allowedFunctionNames": ["get_weather"]}}
    }));
    assert_eq!(
        ir_one.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
}

#[test]
fn tool_choice_none_and_auto_roundtrip() {
    for (mode, variant) in [
        ("AUTO", crate::ir::IrToolChoice::Auto),
        ("NONE", crate::ir::IrToolChoice::None),
    ] {
        let ir = gemini_read(serde_json::json!({
            "contents": [],
            "toolConfig": {"functionCallingConfig": {"mode": mode}}
        }));
        assert_eq!(ir.tool_choice, Some(variant));
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], mode);
    }
}

#[test]
fn tool_choice_absent_emits_no_function_calling_config() {
    let ir = gemini_read(serde_json::json!({"contents": []}));
    assert_eq!(ir.tool_choice, None);
    let writer = GeminiWriter;
    let out = writer.write_request(&ir);
    assert!(
        out.get("toolConfig")
            .and_then(|tc| tc.get("functionCallingConfig"))
            .is_none(),
        "absent tool_choice must NOT synthesize a functionCallingConfig"
    );
}

#[test]
fn tool_choice_no_duplicate_function_calling_config() {
    // Same-protocol passthrough: the raw toolConfig is preserved in `extra` AND the writer
    // overlays a fresh functionCallingConfig — there must be exactly ONE in the output (the
    // overlay replaces, never duplicates).
    let ir = gemini_read(serde_json::json!({
        "contents": [],
        "toolConfig": {"functionCallingConfig": {"mode": "ANY"}}
    }));
    let writer = GeminiWriter;
    let out = writer.write_request(&ir);
    let s = serde_json::to_string(&out).unwrap();
    assert_eq!(
        s.matches("functionCallingConfig").count(),
        1,
        "exactly one functionCallingConfig must appear, got: {s}"
    );
}

// ---- PF-M2: Gemini finishReason mapping ----

#[test]
fn finish_reason_maps_gemini_only_reasons_to_canonical() {
    use crate::ir::IrStopReason as S;
    // The Gemini-only reasons map to canonical IR stop reasons (NOT a verbatim lowercase token).
    assert_eq!(
        map_gemini_finish_reason(GEMINI_FINISH_RECITATION),
        S::Safety
    );
    assert_eq!(map_gemini_finish_reason("IMAGE_SAFETY"), S::Safety);
    assert_eq!(map_gemini_finish_reason("SPII"), S::Safety);
    // A malformed function call is a FAILED generation with no runnable tool call — it maps to
    // `error`, NOT `tool_use` (which would tell the client to execute a call that doesn't exist).
    assert_eq!(
        map_gemini_finish_reason(GEMINI_FINISH_MALFORMED_FUNCTION_CALL),
        S::Error
    );
    // Unenumerated reasons map to `Other` (the writer projects it to the native OTHER member).
    assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_OTHER), S::Other);
    assert_eq!(map_gemini_finish_reason("LANGUAGE"), S::Other);
    // The direct ones still map.
    assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_STOP), S::EndTurn);
    assert_eq!(
        map_gemini_finish_reason(GEMINI_FINISH_MAX_TOKENS),
        S::MaxTokens
    );
    assert_eq!(map_gemini_finish_reason(GEMINI_FINISH_SAFETY), S::Safety);
}

#[test]
fn finish_reason_recitation_in_response_is_safety() {
    // End-to-end through read_response: a RECITATION finishReason surfaces as the canonical
    // `safety` stop_reason, which the Anthropic/OpenAI writers recognize.
    let body = serde_json::json!({
        "candidates": [{
            "content": {"parts": [{"text": "x"}], "role": "model"},
            "finishReason": GEMINI_FINISH_RECITATION
        }],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    });
    let resp = GeminiReader.read_response(&body).expect("read_response");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Safety));
}

/// End-to-end through read_response: a MALFORMED_FUNCTION_CALL finishReason surfaces as the
/// canonical `error` stop_reason (a failed generation with no runnable tool call) — NOT `tool_use`.
/// Guards that the read_response path actually routes through `map_gemini_finish_reason` (the unit
/// test alone would not catch a read_response site that bypassed the mapping).
#[test]
fn finish_reason_malformed_function_call_in_response_is_error() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {"parts": [{"text": "x"}], "role": "model"},
            "finishReason": GEMINI_FINISH_MALFORMED_FUNCTION_CALL
        }],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    });
    let resp = GeminiReader.read_response(&body).expect("read_response");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Error));
}

/// The STREAMING reader (read_response_events) routes finishReason through the SAME
/// `map_gemini_finish_reason`, so a MALFORMED_FUNCTION_CALL terminal chunk must surface
/// stop_reason=Error on the MessageDelta — guarding the stream call site, not just the unit fn.
#[test]
fn finish_reason_malformed_function_call_stream_is_error() {
    let chunks = vec![serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "x"}]},
            "finishReason": GEMINI_FINISH_MALFORMED_FUNCTION_CALL
        }],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    })];
    let events = collect_stream(&chunks);
    let stop = events.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { stop_reason, .. } => Some(*stop_reason),
        _ => None,
    });
    assert_eq!(
        stop,
        Some(Some(crate::ir::IrStopReason::Error)),
        "streamed MALFORMED_FUNCTION_CALL must terminate stop_reason=Error; got {events:?}"
    );
}

// ---- C4: context-length override is status-gated ----

#[test]
fn context_length_override_only_fires_on_400_or_413() {
    let token_body =
        br#"{"error":{"code":429,"message":"input is longer than the maximum number of tokens"}}"#;
    // A 429 with token-phrased body must NOT be reclassified to context_length_exceeded — the
    // breaker must still record the rate-limit fault.
    let err = GeminiReader.extract_error(StatusCode::TOO_MANY_REQUESTS, token_body);
    assert_ne!(
        err.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 429 with token-phrased body must NOT be mis-dispositioned as ContextLength (C4)"
    );
    // The same body on a real 400 IS the canonical context-length signal.
    let body_400 =
        br#"{"error":{"code":400,"message":"input is longer than the maximum number of tokens"}}"#;
    let err = GeminiReader.extract_error(StatusCode::BAD_REQUEST, body_400);
    assert_eq!(
        err.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 400 with the token-overflow message must classify as context_length_exceeded"
    );
    // ...and on a 413 as well.
    let err = GeminiReader.extract_error(StatusCode::PAYLOAD_TOO_LARGE, token_body);
    assert_eq!(
        err.provider_code.as_deref(),
        Some("context_length_exceeded")
    );
}

// ===================================================================================
// Integration gaps — sampling / response_format / reasoning / cache / image / schema
// (cross-protocol survival). Each test proves a read+write site round-trips a control
// that previously degraded to the target default on the cross-protocol seam.
// ===================================================================================

/// Minimal IR request with a single user "hi" turn and all controls defaulted. Tests mutate the
/// field(s) under test so the assertion targets exactly one gap.
fn base_ir_request() -> crate::ir::IrRequest {
    crate::ir::IrRequest {
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
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    }
}

// --- Gap 1: sampling controls via generationConfig ---

/// OpenAI→Gemini: an IR carrying frequency/presence penalties, seed, and n MUST emit them in
/// Gemini's native generationConfig shape (frequencyPenalty/presencePenalty/seed/candidateCount).
#[test]
fn test_write_request_sampling_controls_emit_generation_config() {
    let mut req = base_ir_request();
    req.frequency_penalty = Some(0.5);
    req.presence_penalty = Some(-0.25);
    req.seed = Some(42);
    req.n = Some(3);
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&req)
    };
    let gc = wire
        .get("generationConfig")
        .expect("generationConfig must be emitted");
    assert_eq!(gc.get("frequencyPenalty"), Some(&serde_json::json!(0.5)));
    assert_eq!(gc.get("presencePenalty"), Some(&serde_json::json!(-0.25)));
    assert_eq!(gc.get("seed"), Some(&serde_json::json!(42)));
    assert_eq!(
        gc.get("candidateCount"),
        Some(&serde_json::json!(3)),
        "n maps to Gemini candidateCount: {wire}"
    );
}

/// None sampling controls emit NOTHING (no spurious zero penalties / seed on a plain request).
#[test]
fn test_write_request_sampling_controls_omitted_when_none() {
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&base_ir_request())
    };
    if let Some(gc) = wire.get("generationConfig") {
        assert!(gc.get("frequencyPenalty").is_none());
        assert!(gc.get("presencePenalty").is_none());
        assert!(gc.get("seed").is_none());
        assert!(gc.get("candidateCount").is_none());
    }
}

/// Gemini→IR: native generationConfig sampling controls promote into the typed IR fields, and a
/// read→write round-trips them (same-protocol fidelity).
#[test]
fn test_read_request_sampling_controls_promote_and_round_trip() {
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {
            "frequencyPenalty": 0.7,
            "presencePenalty": 0.1,
            "seed": 99,
            "candidateCount": 2
        }
    });
    let ir = GeminiReader.read_request(&body).expect("read_request");
    assert_eq!(ir.frequency_penalty, Some(0.7));
    assert_eq!(ir.presence_penalty, Some(0.1));
    assert_eq!(ir.seed, Some(99));
    assert_eq!(ir.n, Some(2), "candidateCount promotes to IR n");

    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&ir)
    };
    let gc = wire.get("generationConfig").expect("generationConfig");
    assert_eq!(gc.get("frequencyPenalty"), Some(&serde_json::json!(0.7)));
    assert_eq!(gc.get("presencePenalty"), Some(&serde_json::json!(0.1)));
    assert_eq!(gc.get("seed"), Some(&serde_json::json!(99)));
    assert_eq!(gc.get("candidateCount"), Some(&serde_json::json!(2)));
}

// --- Gap 2 (M1): response_format ↔ responseSchema/responseMimeType ---

/// Gemini→IR→Gemini: native responseMimeType + responseSchema read into the normalized IR
/// response_format object and round-trip back into generationConfig.
#[test]
fn test_response_format_round_trips_native_gemini() {
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {
            "responseMimeType": MIME_APPLICATION_JSON,
            "responseSchema": {"type": "object", "properties": {"x": {"type": "string"}}}
        }
    });
    let ir = GeminiReader.read_request(&body).expect("read_request");
    let rf = ir
        .response_format
        .as_ref()
        .expect("response_format must be populated");
    assert!(
        rf.json,
        "application/json mime must read as a JSON directive"
    );
    assert!(rf.schema.is_some(), "responseSchema must be carried");

    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&ir)
    };
    let gc = wire.get("generationConfig").expect("generationConfig");
    assert_eq!(
        gc.get(FIELD_RESPONSE_MIME_TYPE),
        Some(&serde_json::json!("application/json")) // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        gc.pointer("/responseSchema/properties/x/type"),
        Some(&serde_json::json!("string")),
        "responseSchema must round-trip: {wire}"
    );
}

/// A JSON structured-output directive (from any source protocol — here a typed IR carrying a
/// schema) maps onto Gemini responseMimeType + responseSchema, with JSON-Schema keywords Gemini
/// rejects (e.g. `$schema`) stripped by `sanitize_gemini_schema`.
#[test]
fn test_response_format_maps_to_gemini_and_sanitizes_schema() {
    let mut req = base_ir_request();
    req.response_format = Some(crate::ir::IrResponseFormat {
        json: true,
        schema: Some(serde_json::json!({
            "type": "object",
            "$schema": "http://json-schema.org/draft-07/schema#"
        })),
        name: None,
        strict: None,
        description: None,
    });
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&req)
    };
    let gc = wire.get("generationConfig").expect("generationConfig");
    assert_eq!(
        gc.get(FIELD_RESPONSE_MIME_TYPE),
        Some(&serde_json::json!("application/json")), // golden wire-contract literal (kept bare on purpose)
        "json_schema type maps to application/json: {wire}"
    );
    assert_eq!(
        gc.pointer("/responseSchema/type"),
        Some(&serde_json::json!("object"))
    );
    assert!(
        gc.pointer("/responseSchema/$schema").is_none(),
        "rejected JSON-Schema keyword $schema must be stripped from responseSchema: {wire}"
    );
}

// --- Gap 3 (H2): reasoning thought parts ↔ IrBlock::Thinking ---

/// A Gemini response `thought:true` part with a `thoughtSignature` reads into IrBlock::Thinking
/// (text + signature), and write_response re-emits it as a `{text, thought:true,
/// thoughtSignature}` part — full round-trip with the signature preserved.
#[test]
fn test_thought_part_round_trips_through_ir_thinking() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [
                {"text": "let me reason", "thought": true, "thoughtSignature": "sig-abc"},
                {"text": "the answer"}
            ]},
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    });
    let resp = GeminiReader.read_response(&body).expect("read_response");
    // First block is Thinking with text + signature; second is plain Text.
    match &resp.content[0] {
        crate::ir::IrBlock::Thinking {
            text, signature, ..
        } => {
            assert_eq!(text, "let me reason");
            assert_eq!(signature.as_deref(), Some("sig-abc"));
        }
        other => panic!("expected Thinking block, got {other:?}"),
    }
    assert!(matches!(
        &resp.content[1],
        crate::ir::IrBlock::Text { text, .. } if text == "the answer"
    ));

    let wire = {
        let __w = GeminiWriter;
        __w.write_response(&resp)
    };
    let part0 = wire
        .pointer("/candidates/0/content/parts/0")
        .expect("first part");
    assert_eq!(part0.get("text"), Some(&serde_json::json!("let me reason")));
    assert_eq!(part0.get("thought"), Some(&serde_json::json!(true)));
    assert_eq!(
        part0.get("thoughtSignature"),
        Some(&serde_json::json!("sig-abc")),
        "thoughtSignature must round-trip: {wire}"
    );
}

/// A Thinking block in a REQUEST assistant turn round-trips through write_request as a thought
/// part with its signature (cross-protocol reasoning survives into a Gemini request).
#[test]
fn test_thinking_block_round_trips_in_write_request() {
    let mut req = base_ir_request();
    req.messages.push(crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Thinking {
            text: "thinking...".to_string(),
            signature: Some("sig-1".to_string()),
            redacted: false,
            cache_control: None,
        }],
    });
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&req)
    };
    // Assistant turn is the 2nd contents entry (role "model").
    let parts = wire
        .pointer("/contents/1/parts")
        .and_then(|p| p.as_array())
        .expect("model parts");
    let thought = &parts[0];
    assert_eq!(thought.get("text"), Some(&serde_json::json!("thinking...")));
    assert_eq!(thought.get("thought"), Some(&serde_json::json!(true)));
    assert_eq!(
        thought.get("thoughtSignature"),
        Some(&serde_json::json!("sig-1")),
        "request-side thought signature must round-trip: {wire}"
    );
}

// --- Gap 4 (H6): cachedContentTokenCount → cache_read_input_tokens ---

/// Gemini usageMetadata.cachedContentTokenCount maps into the IR cache_read_input_tokens field
/// (the same field Bedrock/Anthropic cache-read map to), surviving the cross-protocol seam.
#[test]
fn test_cached_content_token_count_reads_into_cache_read() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hi"}]},
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 5,
            "cachedContentTokenCount": 80
        }
    });
    let resp = GeminiReader.read_response(&body).expect("read_response");
    assert_eq!(
        resp.usage.cache_read_input_tokens,
        Some(80),
        "cachedContentTokenCount must map to cache_read_input_tokens"
    );
    // Absent cache count stays None.
    let body_no_cache = serde_json::json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": GEMINI_FINISH_STOP}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
    });
    let resp2 = GeminiReader
        .read_response(&body_no_cache)
        .expect("read_response");
    assert_eq!(resp2.usage.cache_read_input_tokens, None);
}

// --- Gap 5 (L1): fileData reads into the typed Url source ---

/// A Gemini `fileData` part (with or without a mimeType) is a remote URL reference → reads into
/// the typed `Url` source and re-emits as `fileData{fileUri}`. The optional `mimeType` hint is not
/// carried on this path; that is operationally lossless — Gemini's `fileData.mimeType` is optional
/// (inferred from the URI), so the backend accepts the part and a native client is unaffected.
#[test]
fn test_file_data_reads_into_url_source_and_round_trips() {
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [
            {"fileData": {"fileUri": "gs://bucket/img.png", "mimeType": "image/png"}}
        ]}]
    });
    let ir = GeminiReader.read_request(&body).expect("read_request");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => assert_eq!(url, "gs://bucket/img.png"),
        other => panic!("expected Image(Url), got {other:?}"),
    }
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&ir)
    };
    assert_eq!(
        wire.pointer("/contents/0/parts/0/fileData/fileUri"),
        Some(&serde_json::json!("gs://bucket/img.png")),
        "fileUri must round-trip as a fileData reference: {wire}"
    );
}

/// Regression guard: a fileData WITHOUT a mimeType (bare remote URI) still falls back to the
/// image_url sentinel and re-emits as fileData{fileUri} (no spurious mimeType).
#[test]
fn test_file_data_without_mime_type_uses_sentinel() {
    let body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"fileData": {"fileUri": "https://x/i.jpg"}}]}]
    });
    let ir = GeminiReader.read_request(&body).expect("read_request");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => {
            assert_eq!(url, "https://x/i.jpg");
        }
        other => panic!("expected Image, got {other:?}"),
    }
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&ir)
    };
    assert_eq!(
        wire.pointer("/contents/0/parts/0/fileData/fileUri"),
        Some(&serde_json::json!("https://x/i.jpg"))
    );
    assert!(
        wire.pointer("/contents/0/parts/0/fileData/mimeType")
            .is_none(),
        "sentinel image must not gain a bogus mimeType: {wire}"
    );
}

// --- Gap 6 (L3): tool input_schema strips Gemini-rejected JSON-Schema keywords ---

/// A cross-protocol tool def carrying JSON-Schema keywords Gemini 400-rejects ($schema,
/// additionalProperties, $ref, …) must be stripped on write so the tool def survives instead of
/// hard-failing — recursively, including nested object/array schemas.
#[test]
fn test_write_request_strips_rejected_schema_keywords() {
    let mut req = base_ir_request();
    req.tools.push(crate::ir::IrTool {
        name: "get_weather".to_string(),
        description: Some("w".to_string()),
        input_schema: serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "loc": {"type": "string"},
                "nested": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {"$ref": {"type": "string"}}
                }
            },
            "required": ["loc"]
        }),
        cache_control: None,
    });
    let wire = {
        let __w = GeminiWriter;
        __w.write_request(&req)
    };
    let params = wire
        .pointer("/tools/0/functionDeclarations/0/parameters")
        .expect("parameters");
    assert!(
        params.get("$schema").is_none(),
        "$schema must be stripped: {wire}"
    );
    assert!(
        params.get("additionalProperties").is_none(),
        "top-level additionalProperties must be stripped: {wire}"
    );
    // Survivors preserved.
    assert_eq!(params.get("type"), Some(&serde_json::json!("object")));
    assert_eq!(params.get("required"), Some(&serde_json::json!(["loc"])));
    assert_eq!(
        params.pointer("/properties/loc/type"),
        Some(&serde_json::json!("string"))
    );
    // Recursion: nested additionalProperties stripped, nested properties kept.
    assert!(
        params
            .pointer("/properties/nested/additionalProperties")
            .is_none(),
        "nested additionalProperties must be stripped recursively: {wire}"
    );
    assert_eq!(
        params.pointer("/properties/nested/type"),
        Some(&serde_json::json!("object"))
    );
}

/// `sanitize_gemini_schema` leaves a clean Gemini-native schema untouched and walks arrays.
#[test]
fn test_sanitize_gemini_schema_preserves_clean_and_walks_arrays() {
    let clean = serde_json::json!({
        "type": "object",
        "anyOf": [{"type": "string"}, {"type": "number", "$comment": "drop me"}]
    });
    let out = sanitize_gemini_schema(&clean);
    assert_eq!(out.get("type"), Some(&serde_json::json!("object")));
    assert_eq!(
        out.pointer("/anyOf/0/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        out.pointer("/anyOf/1/$comment").is_none(),
        "rejected keyword in an array element must be stripped: {out}"
    );
    assert_eq!(
        out.pointer("/anyOf/1/type"),
        Some(&serde_json::json!("number"))
    );
}

/// D4: the Gemini stream WRITE path must emit a streamed reasoning part for a `ThinkingDelta`
/// (`{text, thought:true}`) and carry the signature for a `SignatureDelta`
/// (`{thought:true, thoughtSignature}`), mirroring the non-stream `write_response` thinking shape.
/// Previously both returned None, silently dropping a cross-protocol reasoning stream.
#[test]
fn test_stream_thinking_and_signature_deltas_emit_thought_parts() {
    let writer = GeminiWriter;

    // ThinkingDelta → a `thought:true` text part on a candidates chunk.
    let think = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::ThinkingDelta("let me reason".to_string()),
        })
        .expect("a ThinkingDelta must emit a streamed thought chunk, not None");
    let think_part = think
        .1
        .pointer("/candidates/0/content/parts/0")
        .expect("thought chunk must carry a part");
    assert_eq!(
        think_part.pointer("/text").and_then(|t| t.as_str()),
        Some("let me reason"),
        "streamed thought part must carry the reasoning text: {think_part}"
    );
    assert_eq!(
        think_part.pointer("/thought"),
        Some(&serde_json::json!(true)),
        "streamed thought part must be flagged thought:true: {think_part}"
    );

    // SignatureDelta → a `thought:true` part bearing the opaque `thoughtSignature`.
    let sig = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::SignatureDelta("sig-xyz".to_string()),
        })
        .expect("a SignatureDelta must emit a streamed thought chunk, not None");
    let sig_part = sig
        .1
        .pointer("/candidates/0/content/parts/0")
        .expect("signature chunk must carry a part");
    assert_eq!(
        sig_part
            .pointer("/thoughtSignature")
            .and_then(|s| s.as_str()),
        Some("sig-xyz"),
        "streamed signature part must carry the thoughtSignature: {sig_part}"
    );
    assert_eq!(
        sig_part.pointer("/thought"),
        Some(&serde_json::json!(true)),
        "streamed signature part must be flagged thought:true: {sig_part}"
    );
}

/// L2: a Gemini response carrying `candidates[].citationMetadata.citationSources[]` must read
/// into IrCitation(s) on the answer's Text block (url/title/indices preserved), and a CROSS-
/// protocol Anthropic egress must re-emit them as `web_search_result_location` citations carrying
/// the url/title — closing the grounding-citation gap that previously dropped them entirely.
#[test]
fn gemini_citation_metadata_reads_and_projects_to_anthropic() {
    let reader = GeminiReader;
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"text": "The sky is blue."}]
            },
            "citationMetadata": {
                "citationSources": [
                    {
                        "startIndex": 0,
                        "endIndex": 15,
                        "uri": "https://example.com/sky",
                        "title": "Why the sky is blue",
                        "license": ""
                    }
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 4,
            "totalTokenCount": 9
        }
    });
    let ir = reader.read_response(&body).expect("read_response");
    // Citations land on the Text block with neutral fields populated.
    let citations = ir
        .content
        .iter()
        .find_map(|b| match b {
            crate::ir::IrBlock::Text { citations, .. } if !citations.is_empty() => Some(citations),
            _ => None,
        })
        .expect("citations must be attached to the Text block");
    assert_eq!(citations.len(), 1);
    assert_eq!(citations[0].url.as_deref(), Some("https://example.com/sky"));
    assert_eq!(citations[0].title.as_deref(), Some("Why the sky is blue"));
    assert_eq!(citations[0].start_index, Some(0));
    assert_eq!(citations[0].end_index, Some(15));

    // Cross-protocol Anthropic egress carries url + title.
    let aw = crate::proto::anthropic::AnthropicWriter;
    let wire = aw.write_response(&ir);
    let c = wire
        .pointer("/content")
        .and_then(|c| c.as_array())
        .and_then(|blocks| blocks.iter().find_map(|b| b.pointer("/citations/0")))
        .expect("Anthropic egress must carry the citation");
    assert_eq!(
        c.get("type").and_then(|v| v.as_str()),
        Some("web_search_result_location")
    );
    assert_eq!(
        c.get("url").and_then(|v| v.as_str()),
        Some("https://example.com/sky")
    );
    assert_eq!(
        c.get("title").and_then(|v| v.as_str()),
        Some("Why the sky is blue")
    );
}

/// L2: same-protocol Gemini→IR→Gemini citation round-trip re-emits candidate-level
/// citationMetadata (verbatim source via `raw`), and a response WITHOUT citations stays free of a
/// `citationMetadata` key.
#[test]
fn gemini_citations_roundtrip_and_absent_unaffected() {
    let reader = GeminiReader;
    let writer = GeminiWriter;
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Answer."}]},
            "citationMetadata": {
                "citationSources": [
                    {"startIndex": 1, "endIndex": 7, "uri": "https://src/x", "title": "X"}
                ]
            },
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
    });
    let mut ir = reader.read_response(&body).expect("read_response");
    // Force the cross-protocol boundary signal so the Gemini writer runs the full egress path.
    ir.created = Some(1);
    let wire = writer.write_response(&ir);
    let src = wire
        .pointer("/candidates/0/citationMetadata/citationSources/0")
        .expect("citationMetadata re-emitted at candidate level");
    assert_eq!(
        src.get("uri").and_then(|v| v.as_str()),
        Some("https://src/x")
    );
    assert_eq!(src.get("startIndex").and_then(|v| v.as_i64()), Some(1));

    // No citations → no citationMetadata key.
    let plain_body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Plain."}]},
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
    });
    let mut plain_ir = reader.read_response(&plain_body).expect("read_response");
    plain_ir.created = Some(1);
    let plain_wire = writer.write_response(&plain_ir);
    assert!(
        plain_wire
            .pointer("/candidates/0/citationMetadata")
            .is_none(),
        "no citationMetadata for a citation-free response; got {plain_wire}"
    );
}

/// L2-5 STREAMING citations, cross-protocol: a Gemini stream chunk carrying candidate-level
/// `citationMetadata.citationSources[]` must read into an `IrDelta::CitationsDelta` on the answer
/// text block, and a cross-protocol Anthropic egress must re-emit it as a native
/// `content_block_delta`/`citations_delta` event carrying the url/title — closing the streaming
/// grounding-citation gap that previously dropped the citation entirely.
#[test]
fn stream_gemini_citation_metadata_projects_to_anthropic_citations_delta() {
    // Gemini delivers citations on a (late) chunk, here alongside the finishReason.
    let events = collect_stream(&[
        serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "The sky is blue."}]}
            }]
        }),
        serde_json::json!({
            "candidates": [{
                "citationMetadata": {
                    "citationSources": [
                        {
                            "startIndex": 0,
                            "endIndex": 15,
                            "uri": "https://example.com/sky",
                            "title": "Why the sky is blue"
                        }
                    ]
                },
                "finishReason": GEMINI_FINISH_STOP
            }],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 4}
        }),
    ]);

    // A CitationsDelta lands on the answer text block, neutral fields populated.
    let (cite_idx, citations) = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::CitationsDelta(cs),
            } if !cs.is_empty() => Some((*index, cs.clone())),
            _ => None,
        })
        .expect("a CitationsDelta must be emitted for a streamed Gemini citation");
    assert_eq!(citations.len(), 1);
    assert_eq!(citations[0].url.as_deref(), Some("https://example.com/sky"));
    assert_eq!(citations[0].title.as_deref(), Some("Why the sky is blue"));
    assert_eq!(citations[0].start_index, Some(0));
    assert_eq!(citations[0].end_index, Some(15));

    // The citation block index must be opened by a BlockStart and closed by a BlockStop —
    // the stream stays balanced.
    assert!(
        events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart { index, .. } if *index == cite_idx
        )),
        "citation block must be opened: {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStop { index } if *index == cite_idx
        )),
        "citation block must be closed: {events:?}"
    );

    // Cross-protocol Anthropic egress: the CitationsDelta becomes a native
    // content_block_delta/citations_delta carrying the synthesized Anthropic citation.
    let aw = crate::proto::anthropic::AnthropicWriter;
    let delta_ev = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::CitationsDelta(_),
                ..
            } => aw.write_response_event(e),
            _ => None,
        })
        .expect("Anthropic writer must emit a frame for the CitationsDelta");
    assert_eq!(delta_ev.0, "content_block_delta");
    // One citation → a single citations_delta body (not an array).
    let citation = delta_ev
        .1
        .pointer("/delta/citation")
        .expect("body must carry delta.citation");
    assert_eq!(
        delta_ev.1.pointer("/delta/type").and_then(|t| t.as_str()),
        Some("citations_delta")
    );
    assert_eq!(
        citation.get("type").and_then(|v| v.as_str()),
        Some("web_search_result_location")
    );
    assert_eq!(
        citation.get("url").and_then(|v| v.as_str()),
        Some("https://example.com/sky")
    );
    assert_eq!(
        citation.get("title").and_then(|v| v.as_str()),
        Some("Why the sky is blue")
    );
}

/// L2-5 STREAMING citations, reverse direction: an `IrDelta::CitationsDelta` (as an Anthropic
/// stream reader would produce) must project onto a native Gemini `citationMetadata.citationSources`
/// chunk when written by the Gemini writer — and the shape-gate must REBUILD the Gemini source from
/// the neutral fields rather than leak the foreign Anthropic `raw` through.
#[test]
fn stream_anthropic_citation_projects_to_gemini_citation_metadata() {
    let writer = GeminiWriter;
    // A CitationsDelta whose `raw` is an ANTHROPIC-shaped object (a Gemini→Anthropic would never
    // produce this; here we model the Anthropic→Gemini direction). The Gemini writer must NOT
    // emit the Anthropic `raw` verbatim — it has no Gemini uri/index keys — and must synthesize
    // a Gemini source from the neutral fields instead.
    let cit = crate::ir::IrCitation {
        kind: Some("web_search_result_location".to_string()),
        cited_text: None,
        title: Some("Doc Title".to_string()),
        url: Some("https://anthropic.example/doc".to_string()),
        document_index: None,
        start_index: Some(3),
        end_index: Some(9),
        encrypted_index: Some("enc-xyz".to_string()),
        raw: Some(serde_json::json!({
            "type": "web_search_result_location",
            "url": "https://anthropic.example/doc",
            "title": "Doc Title",
            "encrypted_index": "enc-xyz"
        })),
    };
    let ev = IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::CitationsDelta(vec![cit]),
    };
    let (_, body) = writer
        .write_response_event(&ev)
        .expect("Gemini writer must emit a citationMetadata chunk for a CitationsDelta");
    let src = body
        .pointer("/candidates/0/citationMetadata/citationSources/0")
        .expect("chunk must carry candidate-level citationSources");
    // Synthesized from neutral fields — NOT the Anthropic raw (which has no `uri`).
    assert_eq!(
        src.get("uri").and_then(|v| v.as_str()),
        Some("https://anthropic.example/doc")
    );
    assert_eq!(src.get("title").and_then(|v| v.as_str()), Some("Doc Title"));
    assert_eq!(src.get("startIndex").and_then(|v| v.as_i64()), Some(3));
    assert_eq!(src.get("endIndex").and_then(|v| v.as_i64()), Some(9));
    // The foreign Anthropic `type` tag must NOT leak into the Gemini source.
    assert!(
        src.get("type").is_none(),
        "Anthropic `raw` must not leak through the Gemini writer: {src}"
    );
}

/// L2-5: a Gemini stream with NO citations must be unaffected — no `CitationsDelta` is produced,
/// and the block balance is unchanged.
#[test]
fn stream_gemini_no_citations_unaffected() {
    let events = collect_stream(&[serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Plain answer."}]},
            "finishReason": GEMINI_FINISH_STOP
        }],
        "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}
    })]);
    assert!(
        !events.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::CitationsDelta(_),
                ..
            }
        )),
        "a citation-free stream must not produce a CitationsDelta: {events:?}"
    );
    let starts = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStart { .. }))
        .count();
    let stops = events
        .iter()
        .filter(|e| matches!(e, IrStreamEvent::BlockStop { .. }))
        .count();
    assert_eq!(starts, stops, "unbalanced block events: {events:?}");
}

/// Each `IrToolChoice` variant must round-trip through Gemini's native
/// `toolConfig.functionCallingConfig` shape (the tool-selection directive is a headline
/// cross-protocol control — ir.rs:82): AUTO↔Auto, NONE↔None, ANY↔Required, and
/// ANY+allowedFunctionNames:[n]↔Tool{n}. A dropped/degraded directive silently reverts forced tool
/// use to the target's default on the seam.
#[test]
fn tool_choice_variants_round_trip_via_function_calling_config() {
    let cases = [
        (crate::ir::IrToolChoice::Auto, "AUTO", None),
        (crate::ir::IrToolChoice::None, "NONE", None),
        (crate::ir::IrToolChoice::Required, "ANY", None),
        (
            crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string(),
            },
            "ANY",
            Some("get_weather"),
        ),
    ];
    for (variant, expect_mode, expect_name) in cases {
        // WRITE: the union projects to the native functionCallingConfig object.
        let wire = write_gemini_tool_choice(&variant);
        assert_eq!(
            wire.pointer("/mode").and_then(|m| m.as_str()),
            Some(expect_mode),
            "mode mismatch for {variant:?}"
        );
        if let Some(name) = expect_name {
            assert_eq!(
                wire.pointer("/allowedFunctionNames/0")
                    .and_then(|n| n.as_str()),
                Some(name)
            );
        } else {
            assert!(
                wire.get("allowedFunctionNames").is_none(),
                "no allowedFunctionNames expected for {variant:?}"
            );
        }
        // READ back through the native toolConfig shape reproduces the same union.
        let tool_config = serde_json::json!({"functionCallingConfig": wire});
        assert_eq!(
            read_gemini_tool_choice(Some(&tool_config)),
            Some(variant.clone()),
            "round-trip failed for {variant:?}"
        );
    }
}

/// A multi-name `allowedFunctionNames` (a SUBSET restriction the IR cannot express) must relax to
/// `Required` (call SOME tool — a true superset), NOT fabricate a stricter single-tool constraint
/// the request never made.
#[test]
fn tool_choice_multi_allowed_names_relaxes_to_required() {
    let tool_config = serde_json::json!({
        "functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["a", "b"]}
    });
    assert_eq!(
        read_gemini_tool_choice(Some(&tool_config)),
        Some(crate::ir::IrToolChoice::Required),
        "a 2-name allow-list has no IR analog; must degrade to Required, not Tool{{first}}"
    );
}

/// An UNKNOWN native `finishReason` (a future/novel Gemini token) maps to `IrStopReason::Other`
/// (ir.rs:186 — no String payload), and on egress `Other` degrades to the honest native `OTHER`
/// enum member, never an off-spec upper-cased token a strict client rejects.
#[test]
fn unknown_finish_reason_maps_to_other_and_writes_native_other() {
    assert_eq!(
        map_gemini_finish_reason("SOME_FUTURE_REASON"),
        crate::ir::IrStopReason::Other
    );
    // Egress: Other -> the valid native OTHER member.
    assert_eq!(
        write_gemini_stop_reason(crate::ir::IrStopReason::Other),
        GEMINI_FINISH_OTHER
    );
    // MALFORMED_FUNCTION_CALL is a modeled abnormal stop -> Error (not Other).
    assert_eq!(
        map_gemini_finish_reason(GEMINI_FINISH_MALFORMED_FUNCTION_CALL),
        crate::ir::IrStopReason::Error
    );
}

/// cachedContentTokenCount NORMALIZATION, WRITE side (the read side is covered by
/// `test_cached_content_token_count_reads_into_cache_read`): the IR stores UNCACHED input, so the
/// writer must ADD the cached prefix BACK to re-derive Gemini's TOTAL `promptTokenCount` and
/// re-emit `cachedContentTokenCount`. Pins the inverse of the read normalization (ir.rs:457).
#[test]
fn write_response_reconstructs_prompt_token_count_with_cached() {
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
            input_tokens: 20,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(80),
        },
        model: Some("gemini-2.0-flash".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = {
        let w = GeminiWriter;
        w.write_response(&resp)
    };
    let um = out.get("usageMetadata").expect("usageMetadata present");
    assert_eq!(
        um.get(FIELD_PROMPT_TOKEN_COUNT),
        Some(&serde_json::json!(100)),
        "promptTokenCount must re-add cached: uncached(20) + cached(80) = 100"
    );
    assert_eq!(
        um.get(FIELD_CACHED_CONTENT_TOKEN_COUNT),
        Some(&serde_json::json!(80))
    );
    assert_eq!(
        um.get(FIELD_CANDIDATES_TOKEN_COUNT),
        Some(&serde_json::json!(5))
    );
    // totalTokenCount is emitted (model present -> cross-protocol boundary signal): 100 + 5.
    assert_eq!(
        um.get(FIELD_TOTAL_TOKEN_COUNT),
        Some(&serde_json::json!(105))
    );
}

/// A system prompt must survive read→IR→write: Gemini's `systemInstruction.parts[]` reads into
/// `IrRequest.system` and writes back to the same native container (the system prompt is a headline
/// cross-protocol feature).
#[test]
fn system_instruction_round_trips_through_ir_system() {
    let body = serde_json::json!({
        "systemInstruction": {"parts": [{"text": "You are terse."}]},
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
    });
    let ir = GeminiReader.read_request(&body).expect("read_request");
    assert_eq!(
        ir.system.len(),
        1,
        "systemInstruction must feed IrRequest.system"
    );
    match &ir.system[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "You are terse."),
        other => panic!("expected a Text system block, got {other:?}"),
    }
    // WRITE re-emits the native systemInstruction.parts[] container.
    let out = {
        let w = GeminiWriter;
        w.write_request(&ir)
    };
    assert_eq!(
        out.pointer("/systemInstruction/parts/0/text")
            .and_then(|t| t.as_str()),
        Some("You are terse."),
        "IrRequest.system must write back to systemInstruction.parts[]"
    );
}
