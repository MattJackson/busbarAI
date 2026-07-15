use super::*;
use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent};

// read_response decode - Gemini generateContent response with text + functionCall
#[test]
fn test_gemini_read_response_decode() {
    let j = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"text": "The weather in San Francisco is sunny."},
                    {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
                ]
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 15,
            "candidatesTokenCount": 8
        }
    });

    let reader = GeminiReader;
    let resp = reader.read_response(&j).expect("should parse");

    // Assert content: Text + ToolUse
    assert_eq!(resp.content.len(), 2);

    if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
        assert_eq!(text, "The weather in San Francisco is sunny.");
    } else {
        panic!("expected Text block");
    }

    if let crate::ir::IrBlock::ToolUse {
        id: _, name, input, ..
    } = &resp.content[1]
    {
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
    } else {
        panic!("expected ToolUse block");
    }

    // Assert stop_reason: Gemini has no TOOL_USE finishReason — a tool-call turn ends with STOP.
    // Because this response carries a ToolUse block, the reader promotes the mapped `end_turn` →
    // the canonical `tool_use` (matching every other protocol's reader and keeping cross-protocol
    // egress correct). The Gemini writer maps `tool_use` back to STOP, so same-protocol stays
    // lossless.
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));

    // Assert usage: promptTokenCount→input_tokens, candidatesTokenCount→output_tokens
    assert_eq!(resp.usage.input_tokens, 15);
    assert_eq!(resp.usage.output_tokens, 8);
}

// whole-response round-trip - write_response(read_response(j)) == j
#[test]
fn test_gemini_read_write_response_roundtrip() {
    let j = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"text": "Hello, world!"}]
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 3
        }
    });

    let reader = GeminiReader;
    let writer = GeminiWriter;

    let ir = reader.read_response(&j).expect("should parse");
    let roundtrip = writer.write_response(&ir);

    // Round-trip must be byte-identical for canonical text-only fixture
    assert_eq!(roundtrip, j, "whole-response round-trip must be identical");
}

// CLASS regression companion to the cross-protocol seam fix
// (proxy engine::test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id):
// the SAME-protocol minimal roundtrip must stay LOSSLESS. A native Gemini body that legitimately
// omits `responseId` and any timestamp reads into an IR with `id`/`created`/`model` all `None`
// (the cross-protocol boundary signal is NOT set, because this path never crosses the seam — the
// seam only stamps a synthesized `created` on a cross-protocol hop). The writer must therefore
// emit NEITHER a synthesized `responseId` NOR `usageMetadata.totalTokenCount`, so a Gemini→Gemini
// read→write is byte-identical and a minimal native body never gains fabricated identity.
#[test]
fn test_gemini_same_protocol_minimal_response_omits_synthesized_identity() {
    let j = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hi"}]},
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 3
        }
    });

    let reader = GeminiReader;
    let writer = GeminiWriter;
    let ir = reader.read_response(&j).expect("should parse");
    // The minimal native body carries no identity signal at all.
    assert_eq!(ir.id, None, "no responseId in the minimal native body");
    assert_eq!(ir.created, None, "Gemini bodies carry no timestamp");
    assert_eq!(ir.model, None, "no modelVersion in the minimal body");

    let out = writer.write_response(&ir);
    assert!(
        out.get("responseId").is_none(),
        "minimal same-protocol roundtrip must NOT synthesize a responseId: {out}"
    );
    assert!(
        out["usageMetadata"].get("totalTokenCount").is_none(),
        "minimal same-protocol roundtrip must NOT inject totalTokenCount: {out}"
    );
    // And the whole body stays byte-identical to the native input.
    assert_eq!(
        out, j,
        "Gemini→Gemini minimal response roundtrip must remain byte-identical"
    );
}

// Regression: the trait-default `read_response_event` (singular) must NOT be a dead `None`
// stub for protocols whose live path is the plural fan-out. Before this fix Gemini/Cohere/
// Responses/Bedrock each overrode the singular with `None`, silently swallowing any event a
// generic caller passed through it. The shared default now delegates to `read_response_events`
// over fresh state and surfaces the FIRST IR event. Pin that on Gemini as the class witness.
#[test]
fn test_singular_read_response_event_delegates_for_fanout_protocols() {
    let reader = GeminiReader;
    let chunk = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hello"}]},
            "finishReason": null
        }]
    });
    // Singular path (trait default) must yield the same first event the fan-out produces,
    // never a silent None.
    let singular = reader.read_response_event("", &chunk);
    let mut st = crate::ir::StreamDecodeState::default();
    let plural_first = reader
        .read_response_events("", &chunk, &mut st)
        .into_iter()
        .next();
    assert!(
        singular.is_some(),
        "default singular read_response_event must not be a dead None stub"
    );
    assert_eq!(
        singular, plural_first,
        "default singular must equal the fan-out's first event"
    );
    // The default holds for any input (incl. an empty object): singular tracks the fan-out's
    // first event exactly, and never panics.
    let empty = serde_json::json!({});
    let mut st2 = crate::ir::StreamDecodeState::default();
    assert_eq!(
        GeminiReader.read_response_event("", &empty),
        GeminiReader
            .read_response_events("", &empty, &mut st2)
            .into_iter()
            .next(),
        "default singular must track the fan-out's first event on any input"
    );
}

// stream fan-out - feed Gemini chunk sequence through StreamDecodeState
#[test]
fn test_gemini_read_response_events_stream_fanout() {
    let reader = GeminiReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Chunk 1: text delta (role+text)
    let chunk1 = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hello"}]},
            "finishReason": null
        }]
    });

    // Chunk 2: more text delta
    let chunk2 = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": ", world!"}]},
            "finishReason": null
        }]
    });

    // Chunk 3: finish with STOP + usageMetadata
    let chunk3 = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": []},
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5
        }
    });

    let mut events: Vec<IrStreamEvent> = Vec::new();

    for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
        events.extend(reader.read_response_events("", &chunk, &mut state));
    }

    // Assert exact event sequence: MessageStart, BlockStart{0,Text}, BlockDelta×2, BlockStop{0}, MessageDelta{end_turn,usage}, MessageStop
    assert_eq!(events.len(), 7);

    assert!(matches!(
        events[0],
        IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            ..
        }
    ));

    assert!(matches!(
        events[1],
        IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Text
        }
    ));

    if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[2] {
        assert_eq!(*idx, 0);
        if let IrDelta::TextDelta(text) = delta {
            assert_eq!(text, "Hello");
        } else {
            panic!("expected TextDelta");
        }
    } else {
        panic!("expected BlockDelta");
    }

    if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[3] {
        assert_eq!(*idx, 0);
        if let IrDelta::TextDelta(text) = delta {
            assert_eq!(text, ", world!");
        } else {
            panic!("expected TextDelta");
        }
    } else {
        panic!("expected BlockDelta");
    }

    assert!(matches!(events[4], IrStreamEvent::BlockStop { index: 0 }));

    if let IrStreamEvent::MessageDelta {
        stop_reason, usage, ..
    } = &events[5]
    {
        assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::EndTurn));
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    } else {
        panic!("expected MessageDelta");
    }

    assert!(matches!(events[6], IrStreamEvent::MessageStop));
}

// write_response_event - BlockDelta TextDelta → candidates[0].content.parts[0].text
#[test]
fn test_gemini_write_response_event_text_delta() {
    let writer = GeminiWriter;

    let ev = IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
    };

    let result = writer.write_response_event(&ev);
    assert!(result.is_some());

    let (_, chunk) = result.unwrap();

    // Assert structure: candidates[0].content.parts[0].text == "hi"
    let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
    assert_eq!(candidates.len(), 1);

    let candidate = &candidates[0];
    let content = candidate.get("content").unwrap();

    assert_eq!(content.get("role").and_then(|r| r.as_str()), Some("model"));

    let parts_arr = content.get("parts").and_then(|p| p.as_array()).unwrap();
    assert_eq!(parts_arr.len(), 1);

    let part = &parts_arr[0];
    assert_eq!(part.get("text").and_then(|t| t.as_str()), Some("hi"));
}

// write_response_event - MessageDelta{end_turn} → finishReason "STOP"
#[test]
fn test_gemini_write_response_event_message_delta() {
    let writer = GeminiWriter;

    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };

    let result = writer.write_response_event(&ev);
    assert!(result.is_some());

    let (_, chunk) = result.unwrap();

    // Assert finishReason == "STOP"
    let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
    assert_eq!(candidates.len(), 1);

    let candidate = &candidates[0];
    assert_eq!(
        candidate.get("finishReason").and_then(|r| r.as_str()),
        Some("STOP")
    );

    // Assert usageMetadata present
    assert!(chunk.get("usageMetadata").is_some());
}

// stream fan-out with functionCall - ToolUse via functionCall
#[test]
fn test_gemini_read_response_events_function_call() {
    let reader = GeminiReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Chunk with text delta
    let chunk1 = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Let me check"}]},
            "finishReason": null
        }]
    });

    // Chunk with functionCall (Gemini sends whole args, not streamed)
    let chunk2 = serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {"text": ""},
                    {"functionCall": {"name": "get_weather", "args": {"location": "SF"}}}
                ]
            },
            "finishReason": null
        }]
    });

    // Chunk with finishReason STOP
    let chunk3 = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": []},
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 20,
            "candidatesTokenCount": 10
        }
    });

    let mut events: Vec<IrStreamEvent> = Vec::new();

    for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
        events.extend(reader.read_response_events("", &chunk, &mut state));
    }

    // Verify we have MessageStart + BlockStart{Text} + text delta + ToolUse block + tool args delta + blocks stop + MessageDelta + MessageStop
    assert!(events.len() >= 6);

    // Find the ToolUse-related events
    let mut found_tool_block_start = false;
    let mut found_tool_args_delta = false;

    for event in &events {
        match event {
            IrStreamEvent::BlockStart {
                index: _,
                block: crate::ir::IrBlockMeta::ToolUse { id: _, name },
                ..
            } => {
                if *name == "get_weather" {
                    found_tool_block_start = true;
                }
            }

            IrStreamEvent::BlockDelta {
                delta: IrDelta::InputJsonDelta(json_str),
                ..
            } => {
                // Parse and check args contain location
                if let Ok(args) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if args.get("location").is_some() {
                        found_tool_args_delta = true;
                    }
                }
            }
            _ => {}
        }
    }

    assert!(found_tool_block_start, "should have ToolUse BlockStart");
    assert!(
        found_tool_args_delta,
        "should have InputJsonDelta with args"
    );
}

// --- 1.0 streaming-conformance regression tests (cross-protocol seam) ----------------------

/// Helper: split a concatenated OpenAI SSE byte stream into its per-frame JSON chunk objects
/// (skipping the `[DONE]` sentinel and any keepalive). Mirrors `parse_sse_frame`'s framing.
fn openai_sse_chunks(bytes: &[u8]) -> Vec<serde_json::Value> {
    let text = std::str::from_utf8(bytes).expect("openai SSE is utf-8");
    let mut chunks = Vec::new();
    for frame in text.split("\n\n") {
        let Some(rest) = frame.lines().find_map(|l| l.strip_prefix("data:")) else {
            continue;
        };
        let payload = rest.strip_prefix(' ').unwrap_or(rest).trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
            chunks.push(v);
        }
    }
    chunks
}

/// Finding (OpenAI per-chunk identity): the real OpenAI API repeats the top-level
/// `id`/`created`/`model` on EVERY `chat.completion.chunk`, not just the opening role chunk. An
/// Anthropic egress stream translated to an OpenAI ingress must therefore carry the SAME
/// `id`/`created`/`model` on every emitted chunk — a single stream identity, never a fresh id per
/// chunk and never an identity-less later chunk (a detectable shape divergence).
#[test]
fn test_openai_ingress_per_chunk_identity_repeated() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("openai ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_backend\",\"role\":\"assistant\",\"model\":\"claude-x\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
    raw.extend(t.finish());

    let chunks = openai_sse_chunks(&raw);
    assert!(
        chunks.len() >= 2,
        "expected multiple chunks; got {}",
        chunks.len()
    );
    // Every chunk is a chat.completion.chunk carrying the SAME id/created/model.
    let first_id = chunks[0]
        .get("id")
        .and_then(|v| v.as_str())
        .expect("first chunk has an id")
        .to_string();
    // Synthesized (cross-protocol) id must be a native chatcmpl- shape, NOT the foreign msg_.
    assert!(
        first_id.starts_with("chatcmpl-"),
        "cross-protocol id must be a native chatcmpl- id; got {first_id}"
    );
    let first_created = chunks[0].get("created").and_then(|v| v.as_u64());
    assert!(first_created.is_some(), "first chunk has a created");
    for (i, c) in chunks.iter().enumerate() {
        assert_eq!(
            c.get("object").and_then(|v| v.as_str()),
            Some("chat.completion.chunk"),
            "chunk {i} object; got {c}"
        );
        assert_eq!(
            c.get("id").and_then(|v| v.as_str()),
            Some(first_id.as_str()),
            "chunk {i} must repeat the SAME stream id; got {c}"
        );
        assert_eq!(
            c.get("created").and_then(|v| v.as_u64()),
            first_created,
            "chunk {i} must repeat the SAME created; got {c}"
        );
        assert_eq!(
            c.get("model").and_then(|v| v.as_str()),
            Some("claude-x"),
            "chunk {i} must repeat the stream model; got {c}"
        );
    }
    // The foreign backend id must never leak to the OpenAI client.
    assert!(
        !raw.windows(b"msg_backend".len())
            .any(|w| w == b"msg_backend"),
        "foreign backend id must be stripped on cross-protocol ingress"
    );
}

/// MEDIUM/test-coverage: the OpenAI ingress chunk-identity replay (now behind the `StreamFraming`
/// vtable, in `proto/openai_chat.rs`) skips any
/// frame that is not a `chat.completion.chunk` (no `object` field). The in-band ERROR envelope the
/// OpenAI writer emits mid-stream (`{"error":{...}}`, no `object`) must therefore pass through
/// UNCHANGED — no synthetic `id`/`created` injected, which would corrupt the error JSON shape a
/// strict SDK rejects. Drive an anthropic egress → OpenAI ingress stream with a real opening chunk
/// (to LATCH the stream identity) followed by a mid-stream error event, then assert the resulting
/// error frame carries neither `id` nor `created`.
#[test]
fn test_openai_ingress_mid_stream_error_envelope_unchanged_by_identity() {
    let mut t = StreamTranslate::new("openai", "anthropic").expect("openai ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            // Opening chunk: latches id/created/model in the OpenAI stream framing.
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\",\"model\":\"claude-x\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            // Mid-stream error: the writer emits an in-band `{"error":{...}}` envelope (no `object`).
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"upstream overloaded\"}}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
    raw.extend(t.finish());

    let chunks = openai_sse_chunks(&raw);
    // There must be at least one error envelope; locate it.
    let error_frame = chunks
        .iter()
        .find(|c| c.get("error").is_some())
        .expect("a mid-stream error envelope must be emitted to the OpenAI client");
    // The guard must have left it untouched: NO synthetic id/created injected onto the error.
    assert!(
            error_frame.get("id").is_none(),
            "error envelope must NOT receive an injected `id` (would corrupt the shape); got {error_frame}"
        );
    assert!(
        error_frame.get("created").is_none(),
        "error envelope must NOT receive an injected `created`; got {error_frame}"
    );
    assert!(
        error_frame.get("object").is_none(),
        "error envelope is not a chat.completion.chunk and carries no `object`; got {error_frame}"
    );
    // And the error body itself is well-formed (the writer's standard in-band shape).
    assert!(
        error_frame
            .get("error")
            .and_then(|e| e.get("type"))
            .and_then(|v| v.as_str())
            .is_some(),
        "error envelope must carry an `error.type`; got {error_frame}"
    );
    // The chat.completion.chunk frames before the error still carry a latched identity (proving
    // identity injection IS active on real chunks — the guard is selective, not globally off).
    let had_identity_chunk = chunks.iter().any(|c| {
        c.get("object").and_then(|v| v.as_str()) == Some("chat.completion.chunk")
            && c.get("id").is_some()
    });
    assert!(
        had_identity_chunk,
        "real chat.completion.chunk frames must still carry the latched id (guard is selective)"
    );
}

/// Finding (bedrock messageStop+metadata fan-out, real latencyMs): a bedrock->bedrock stream must
/// round-trip — the egress reader collapses the native two-frame stop/usage split into ONE
/// combined IR MessageDelta, and the ingress writer fan-out RE-SPLITS it back into the native
/// `messageStop` + `metadata` frame pair (metadata carrying the real usage AND a real
/// `metrics.latencyMs`). This proves the reader collapse and writer fan-out are exact inverses.
#[test]
fn test_bedrock_to_bedrock_stream_roundtrips_stop_and_metadata() {
    // Same-protocol returns None (native passthrough), so drive the cross-protocol seam with a
    // foreign egress that still produces the combined delta. Use openai egress → bedrock ingress:
    // a single OpenAI final chunk carries finish_reason + usage, the reader emits ONE combined
    // MessageDelta, and the bedrock-ingress fan-out must produce messageStop + metadata.
    assert!(
        StreamTranslate::new("bedrock", "bedrock").is_none(),
        "bedrock->bedrock needs no translator (native passthrough)"
    );

    let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
    let mut raw: Vec<u8> = Vec::new();
    for frame in [
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
    raw.extend(t.finish());

    let mut buf = raw.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "all frames decode cleanly; {} left",
        buf.len()
    );
    let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
    // The combined delta fans out to a messageStop FOLLOWED by a metadata frame.
    let stop_pos = types
        .iter()
        .position(|t| *t == "messageStop")
        .expect("messageStop frame present");
    let meta_pos = types
        .iter()
        .position(|t| *t == "metadata")
        .expect("metadata frame present");
    assert!(
        stop_pos < meta_pos,
        "messageStop must precede metadata (native order); got {types:?}"
    );
    // The metadata frame carries the real usage and a real latencyMs (not a fabricated 0-tell).
    let meta = frames
        .iter()
        .find(|(et, _)| et == "metadata")
        .expect("metadata frame");
    let mv: serde_json::Value = serde_json::from_slice(&meta.1).expect("valid metadata JSON");
    assert_eq!(
        mv.pointer("/usage/inputTokens").and_then(|x| x.as_u64()),
        Some(7),
        "usage inputTokens; got {mv}"
    );
    assert_eq!(
        mv.pointer("/usage/outputTokens").and_then(|x| x.as_u64()),
        Some(3),
        "usage outputTokens; got {mv}"
    );
    assert!(
        mv.pointer("/metrics/latencyMs")
            .and_then(|x| x.as_u64())
            .is_some(),
        "metadata must carry a real metrics.latencyMs; got {mv}"
    );
    // The messageStop frame carries the mapped stop reason.
    let stop = frames
        .iter()
        .find(|(et, _)| et == "messageStop")
        .expect("messageStop frame");
    let sv: serde_json::Value = serde_json::from_slice(&stop.1).expect("valid messageStop JSON");
    assert_eq!(
        sv.get("stopReason").and_then(|x| x.as_str()),
        Some("end_turn"),
        "stop reason maps to end_turn; got {sv}"
    );
}

/// Change A (was R7): on a BEDROCK-ingress cross-protocol stream the translator's OUTPUT is binary
/// eventstream framing, so the deleted JSON byte-scanner would have mis-parsed the
/// length-prefixes/CRC32s and zeroed token accounting. Billing now reads `translate.usage()` — the
/// IR A-tap accumulated from the structured IR events BEFORE the binary writer runs — so the usage
/// is correct regardless of the output framing. This asserts the A-tap carries the real
/// `input`/`output` tokens while the binary `feed`/`finish` OUTPUT is genuinely binary frames.
#[test]
fn test_bedrock_ingress_ir_usage_carries_real_tokens() {
    let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
    let mut binary_out: Vec<u8> = Vec::new();
    for frame in [
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4}}\n\n",
            "data: [DONE]\n\n",
        ] {
            binary_out.extend(t.feed(frame.as_bytes()));
        }
    binary_out.extend(t.finish());

    // The IR A-tap (billing source) carries the real usage, sourced from the structured IR.
    let usage = t.usage().expect("A-tap captured terminal usage");
    assert_eq!(
        usage.input_tokens, 11,
        "A-tap reads input tokens from the IR"
    );
    assert_eq!(
        usage.output_tokens, 4,
        "A-tap reads output tokens from the IR"
    );

    // The translator OUTPUT really is binary eventstream framing (NOT a JSON document): the usage
    // is read from the IR above, never by brace-scanning these binary frames.
    assert!(!binary_out.is_empty(), "binary frames were emitted");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&binary_out).is_err(),
        "translator output is binary eventstream framing, not a JSON document"
    );
    // The frames decode as real AWS eventstream frames (proving they are binary-framed, not SSE).
    let mut buf = binary_out.clone();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        frames.iter().any(|(et, _)| et == "metadata"),
        "binary output contains the eventstream metadata frame"
    );
}
