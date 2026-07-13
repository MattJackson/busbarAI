use crate::ir::{IrBlock, IrResponse, IrRole, IrUsage};
use crate::proto::bedrock::bedrock_response_to_eventstream;

/// A bedrock-ingress ConverseStream request answered by a BUFFERED (non-SSE) 2xx is rewrapped
/// into the native binary eventstream frame sequence — not an `application/json` Converse body
/// the AWS SDK's stream decoder cannot parse. Assert the synthesized bytes decode into the
/// expected native ConverseStream frame sequence (messageStart … messageStop, metadata).
#[test]
fn buffered_response_wraps_into_converse_stream_frames() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::Text {
            text: "hello world".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(42));
    assert!(!bytes.is_empty(), "must emit eventstream frames");

    // Decode the frames using the same decoder the wire uses.
    let frames = crate::eventstream::drain_frames(&mut bytes);
    let names: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(names.first(), Some(&"messageStart"));
    assert!(names.contains(&"contentBlockStart"));
    assert!(names.contains(&"contentBlockDelta"));
    assert!(names.contains(&"contentBlockStop"));
    assert!(names.contains(&"messageStop"));
    // The trailing metadata frame carries token usage.
    let metadata = frames
        .iter()
        .find(|(t, _)| t == "metadata")
        .expect("metadata frame");
    let payload: serde_json::Value = serde_json::from_slice(&metadata.1).expect("json");
    assert_eq!(payload["usage"]["inputTokens"], 11);
    assert_eq!(payload["usage"]["outputTokens"], 7);
    assert_eq!(payload["usage"]["totalTokens"], 18);
    // HIGH (R9): a real ConverseStream `metadata` event ALWAYS carries `metrics.latencyMs`
    // (the SDK surfaces it via `ConverseStreamMetadataEvent::metrics()`). The buffered-synthesis
    // path must inject it too — `None` here would be a deterministic proxy tell. Mirrors the
    // live StreamTranslate path assertion in proto/mod.rs.
    assert_eq!(
        payload["metrics"]["latencyMs"].as_u64(),
        Some(42),
        "buffered metadata frame must carry metrics.latencyMs like the live path: {payload}"
    );
}

/// MEDIUM (R9, forward.rs): the `IrBlock::ToolUse` arm of `bedrock_response_to_eventstream`
/// must synthesize native ConverseStream tool-use framing — a `contentBlockStart` carrying
/// `start.toolUse.{toolUseId,name}` and a `contentBlockDelta` carrying `delta.toolUse.input` — so a
/// native AWS SDK ConverseStream client receiving a buffered cross-protocol tool-call completion can
/// decode it. The happy-path test only exercises a `Text` block; this covers the tool arm.
#[test]
fn buffered_tool_use_wraps_into_converse_stream_tool_frames() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::ToolUse {
            id: "toolu_abc123".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"city": "Paris"}),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: IrUsage {
            input_tokens: 5,
            output_tokens: 9,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(7));
    let frames = crate::eventstream::drain_frames(&mut bytes);

    // contentBlockStart must carry the tool identity nested under start.toolUse.
    let start = frames
        .iter()
        .find(|(t, _)| t == "contentBlockStart")
        .expect("contentBlockStart frame");
    let start_payload: serde_json::Value =
        serde_json::from_slice(&start.1).expect("json contentBlockStart");
    assert_eq!(
        start_payload["start"]["toolUse"]["toolUseId"], "toolu_abc123",
        "tool start carries toolUseId: {start_payload}"
    );
    assert_eq!(
        start_payload["start"]["toolUse"]["name"], "get_weather",
        "tool start carries name: {start_payload}"
    );

    // contentBlockDelta must carry the serialized tool input under delta.toolUse.input.
    let delta = frames
        .iter()
        .find(|(t, _)| t == "contentBlockDelta")
        .expect("contentBlockDelta frame");
    let delta_payload: serde_json::Value =
        serde_json::from_slice(&delta.1).expect("json contentBlockDelta");
    let input_str = delta_payload["delta"]["toolUse"]["input"]
        .as_str()
        .expect("tool input is a serialized JSON string");
    let input: serde_json::Value = serde_json::from_str(input_str).expect("input decodes to JSON");
    assert_eq!(
        input["city"], "Paris",
        "tool input round-trips through the delta: {delta_payload}"
    );
}

/// REGRESSION (R15 MEDIUM, test-coverage): a MULTI-block buffered cross-protocol completion (the
/// canonical 'assistant says something then calls a tool') must emit a DISTINCT, monotonically
/// increasing `contentBlockIndex` per block — 0 for block 0, 1 for block 1, 2 for block 2. A real
/// AWS Bedrock ConverseStream keys its per-block streaming reassembly off that index; a collision
/// or failure to advance (e.g. a refactor replacing `.enumerate()` with a fixed `0`) would make
/// the SDK merge or misorder blocks — silent content corruption. The single-block tests above
/// cannot catch this because index 0 is correct trivially.
#[test]
fn buffered_multi_block_assigns_distinct_monotonic_content_block_indices() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![
            IrBlock::Text {
                text: "Let me check the weather.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
            IrBlock::ToolUse {
                id: "toolu_abc123".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "Paris"}),
                cache_control: None,
            },
            IrBlock::Text {
                text: "One moment.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::ToolUse),
        usage: IrUsage {
            input_tokens: 12,
            output_tokens: 20,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(99));
    let frames = crate::eventstream::drain_frames(&mut bytes);
    let names: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();

    // (a) Frame ordering: messageStart, then per-block start/delta/stop triples (one per block),
    // then messageStop, then metadata — the native ConverseStream envelope.
    assert_eq!(names.first(), Some(&"messageStart"), "frames: {names:?}");
    let block_frames: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with("contentBlock"))
        .collect();
    assert_eq!(
        block_frames,
        vec![
            "contentBlockStart",
            "contentBlockDelta",
            "contentBlockStop",
            "contentBlockStart",
            "contentBlockDelta",
            "contentBlockStop",
            "contentBlockStart",
            "contentBlockDelta",
            "contentBlockStop",
        ],
        "three blocks must each emit a start/delta/stop triple in order: {names:?}"
    );
    let stop_pos = names
        .iter()
        .position(|n| *n == "messageStop")
        .expect("messageStop");
    let meta_pos = names
        .iter()
        .position(|n| *n == "metadata")
        .expect("metadata");
    assert!(
        stop_pos < meta_pos,
        "messageStop precedes metadata: {names:?}"
    );
    let last_block_pos = names
        .iter()
        .rposition(|n| n.starts_with("contentBlock"))
        .expect("a contentBlock frame");
    assert!(
        last_block_pos < stop_pos,
        "all content blocks precede messageStop: {names:?}"
    );

    // (b) contentBlockIndex is distinct and monotonically increasing across blocks: every
    // content* frame carries the index of its block — 0,0,0 then 1,1,1 then 2,2,2 in emission
    // order. Collect the index off each content frame and assert the per-block grouping.
    let block_indices: Vec<u64> = frames
        .iter()
        .filter(|(t, _)| t.starts_with("contentBlock"))
        .map(|(t, body)| {
            let v: serde_json::Value = serde_json::from_slice(body).expect("content frame JSON");
            v["contentBlockIndex"]
                .as_u64()
                .unwrap_or_else(|| panic!("{t} frame must carry contentBlockIndex: {v}"))
        })
        .collect();
    assert_eq!(
        block_indices,
        vec![0, 0, 0, 1, 1, 1, 2, 2, 2],
        "each block's three frames carry its own distinct, monotonic index; never colliding"
    );
}

/// REGRESSION (R16 MEDIUM, conformance): a buffered cross-protocol completion whose IR carried a
/// ToolUse block but NO explicit `stop_reason` must synthesize `messageStop.stopReason ==
/// "tool_use"`, not the old unconditional `end_turn`. A native Bedrock Converse reports `tool_use`
/// for a tool-call turn, and an AWS SDK consumer keys agentic control flow off it — defaulting to
/// `end_turn` would silently break the tool re-invocation loop.
#[test]
fn buffered_tool_use_with_absent_stop_reason_defaults_to_tool_use() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::ToolUse {
            id: "toolu_xyz".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"city": "Paris"}),
            cache_control: None,
        }],
        // The hazard: upstream omitted a stop reason on the cross-protocol 2xx.
        stop_reason: None,
        usage: IrUsage {
            input_tokens: 5,
            output_tokens: 9,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(3));
    let frames = crate::eventstream::drain_frames(&mut bytes);
    let stop = frames
        .iter()
        .find(|(t, _)| t == "messageStop")
        .expect("messageStop frame");
    let payload: serde_json::Value = serde_json::from_slice(&stop.1).expect("json messageStop");
    assert_eq!(
        payload["stopReason"], "tool_use",
        "absent stop_reason with a ToolUse block must default to tool_use, not end_turn: {payload}"
    );
}

/// REGRESSION (R16 MEDIUM, conformance): the companion to the test above — a TEXT-only completion
/// with an absent `stop_reason` must STILL default to `end_turn` (no tool call → no tool_use). This
/// guards against an over-broad fix that would mislabel a plain text completion as `tool_use`.
#[test]
fn buffered_text_only_with_absent_stop_reason_defaults_to_end_turn() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::Text {
            text: "All done.".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: None,
        usage: IrUsage {
            input_tokens: 3,
            output_tokens: 4,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(3));
    let frames = crate::eventstream::drain_frames(&mut bytes);
    let stop = frames
        .iter()
        .find(|(t, _)| t == "messageStop")
        .expect("messageStop frame");
    let payload: serde_json::Value = serde_json::from_slice(&stop.1).expect("json messageStop");
    assert_eq!(
        payload["stopReason"], "end_turn",
        "absent stop_reason with no tool call must remain end_turn: {payload}"
    );
}

/// REGRESSION (R16 MEDIUM, conformance): an EXPLICIT `stop_reason` always wins over the
/// content-derived default — a ToolUse block alongside an explicit `end_turn` keeps `end_turn`.
#[test]
fn buffered_explicit_stop_reason_overrides_content_default() {
    let ir = IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::ToolUse {
            id: "toolu_xyz".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"city": "Paris"}),
            cache_control: None,
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: IrUsage {
            input_tokens: 5,
            output_tokens: 9,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("anthropic.claude-3".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(3));
    let frames = crate::eventstream::drain_frames(&mut bytes);
    let stop = frames
        .iter()
        .find(|(t, _)| t == "messageStop")
        .expect("messageStop frame");
    let payload: serde_json::Value = serde_json::from_slice(&stop.1).expect("json messageStop");
    assert_eq!(
        payload["stopReason"], "end_turn",
        "explicit stop_reason must override the content-derived default: {payload}"
    );
}
