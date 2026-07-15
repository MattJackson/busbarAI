use crate::proto::StreamTranslate;

/// Drive a SAME-PROTOCOL streaming translator with `frames` and return the IR A-tap (input, output)
/// tokens — the exact value the streaming billing arm reads via `translate.usage()`.
fn same_proto_usage(proto: &str, frames: &[&[u8]]) -> (u64, u64) {
    let mut t = StreamTranslate::new_same_proto(proto).expect("same-proto translator");
    for f in frames {
        let _ = t.feed(f);
    }
    let _ = t.finish();
    let u = t.usage().expect("A-tap captured terminal usage").clone();
    (u.input_tokens, u.output_tokens)
}

/// Drive a CROSS-PROTOCOL streaming translator (egress → ingress) and return the IR A-tap tokens.
fn cross_proto_usage(ingress: &str, egress: &str, frames: &[&[u8]]) -> (u64, u64) {
    let mut t = StreamTranslate::new(ingress, egress).expect("cross-proto translator");
    for f in frames {
        let _ = t.feed(f);
    }
    let _ = t.finish();
    let u = t.usage().expect("A-tap captured terminal usage").clone();
    (u.input_tokens, u.output_tokens)
}

/// Decode a NON-STREAM body through `proto`'s reader (the same-proto non-stream billing path #4:
/// the body is relayed verbatim, billing reads `ir.usage`) and return the billed (input, output).
fn nonstream_usage(proto: &str, body: &[u8]) -> (u64, u64) {
    let p = crate::proto::protocol_for(proto).expect("known proto");
    let v: serde_json::Value = crate::json::parse(body).expect("json body");
    let ir = p.reader().read_response(&v).expect("read_response");
    (ir.usage.input_tokens, ir.usage.output_tokens)
}

// ---- STREAMING × SAME-PROTO (billing via translate.usage()) ----

#[test]
fn stream_same_proto_anthropic_start_usage_backfill() {
    // Anthropic puts input on message_start, output on message_delta — exercises the start-usage
    // backfill the A-tap reads AFTER. Prior UsageTap numbers: (11, 7).
    assert_eq!(
            same_proto_usage(
                "anthropic",
                &[
                    b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n",
                    b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}\n\n",
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                ],
            ),
            (11, 7),
        );
}

#[test]
fn stream_same_proto_openai_include_usage_split() {
    // OpenAI include_usage splits the finish chunk (no usage) from the trailing usage-only chunk —
    // exercises the A-tap merge that ignores the first zero. Prior UsageTap numbers: (13, 9).
    assert_eq!(
            same_proto_usage(
                "openai",
                &[
                    b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
                    b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                    b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":13,\"completion_tokens\":9,\"total_tokens\":22}}\n\n",
                    crate::proto::SSE_DONE_FRAME,
                ],
            ),
            (13, 9),
        );
}

#[test]
fn stream_same_proto_gemini() {
    // Prior UsageTap numbers: (15, 4).
    assert_eq!(
            same_proto_usage(
                "gemini",
                &[
                    b"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hi\"}]}}]}\n\n",
                    b"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"\"}]}}],\"usageMetadata\":{\"promptTokenCount\":15,\"candidatesTokenCount\":4,\"totalTokenCount\":19}}\n\n",
                ],
            ),
            (15, 4),
        );
}

#[test]
fn stream_same_proto_cohere() {
    // Prior UsageTap numbers: (17, 6).
    assert_eq!(
            same_proto_usage(
                "cohere",
                &[
                    b"event: message-start\ndata: {\"type\":\"message-start\",\"id\":\"co_1\"}\n\n",
                    b"event: message-end\ndata: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":17,\"output_tokens\":6}}}}\n\n",
                ],
            ),
            (17, 6),
        );
}

#[test]
fn stream_same_proto_bedrock_binary_eventstream() {
    // Bedrock binary eventstream same-proto: the A-tap reads the IR decoded from the binary frames.
    // Prior byte-scanner numbers: (31, 12).
    use crate::eventstream::encode_frame;
    let mut start = Vec::new();
    start.extend(encode_frame("messageStart", br#"{"role":"assistant"}"#));
    let mut stop = Vec::new();
    stop.extend(encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
    let mut meta = Vec::new();
    meta.extend(encode_frame(
        "metadata",
        br#"{"usage":{"inputTokens":31,"outputTokens":12},"metrics":{"latencyMs":5}}"#,
    ));
    assert_eq!(
        same_proto_usage("bedrock", &[&start, &stop, &meta]),
        (31, 12),
    );
}

#[test]
fn stream_same_proto_responses_corrected_higher() {
    // CORRECTED (expected behavior change): Responses STREAMING nests usage under `response.usage`
    // on the `response.completed` frame. The deleted byte-scanner read only a TOP-LEVEL `usage`, so
    // it reported (0, 0) and UNDER-BILLED. The IR reader reads the nested usage correctly, so the
    // A-tap — and now billing — reports the real (21, 8). This is the one number that differs from
    // the prior UsageTap value, and it is a FIX (Responses streaming was under-billed before).
    assert_eq!(
            same_proto_usage(
                "responses",
                &[
                    b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
                    b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":21,\"output_tokens\":8}}}\n\n",
                ],
            ),
            (21, 8),
        );
}

// ---- STREAMING × CROSS-PROTO (billing via translate.usage()) ----

#[test]
fn stream_cross_proto_anthropic_egress_to_openai_ingress() {
    // Cross-proto streaming still bills via the A-tap. Anthropic egress → OpenAI ingress: the
    // start-usage input backfill survives the seam, so billing sees the full (11, 7).
    assert_eq!(
            cross_proto_usage(
                "openai",
                "anthropic",
                &[
                    b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n",
                    b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}\n\n",
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                ],
            ),
            (11, 7),
        );
}

// ---- NON-STREAM × SAME-PROTO (billing path #4: read_response → ir.usage) ----

#[test]
fn nonstream_same_proto_all_protocols() {
    // The NEW non-stream same-proto billing path (#4): the body relays verbatim, billing reads the
    // egress reader's `ir.usage`. Each asserts the prior UsageTap (input, output).
    assert_eq!(
            nonstream_usage(
                "openai",
                br#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":9}}"#,
            ),
            (13, 9),
        );
    assert_eq!(
            nonstream_usage(
                "anthropic",
                br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":7}}"#,
            ),
            (11, 7),
        );
    assert_eq!(
            nonstream_usage(
                "gemini",
                br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":15,"candidatesTokenCount":4,"totalTokenCount":19}}"#,
            ),
            (15, 4),
        );
    assert_eq!(
            nonstream_usage(
                "responses",
                br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":21,"output_tokens":8}}"#,
            ),
            (21, 8),
        );
}
