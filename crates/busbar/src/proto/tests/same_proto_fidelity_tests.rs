use super::StreamTranslate;

// Feed `input` (in one or more chunks) through a same-proto translator and return the
// concatenated `feed`+`finish` output. `chunks` lets a test prove cross-chunk reassembly is still
// verbatim (frames split across transport boundaries).
fn run_same_proto(proto: &str, chunks: &[&[u8]]) -> (Vec<u8>, StreamTranslate) {
    let mut t = StreamTranslate::new_same_proto(proto).expect("same-proto translator");
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(&t.feed(c));
    }
    out.extend_from_slice(&t.finish());
    (out, t)
}

fn concat(chunks: &[&[u8]]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}

#[test]
fn anthropic_sse_round_trip_byte_exact() {
    // Native Anthropic SSE: input on message_start, output on message_delta.
    let frames: &[&[u8]] = &[
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n",
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}\n\n",
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ];
    let (out, t) = run_same_proto("anthropic", frames);
    assert_eq!(
        out,
        concat(frames),
        "anthropic same-proto SSE must be byte-exact"
    );
    let u = t.usage().expect("anthropic A-tap usage");
    // Backfill: input from message_start (11), output from message_delta (7).
    assert_eq!((u.input_tokens, u.output_tokens), (11, 7));
}

#[test]
fn openai_bare_data_round_trip_byte_exact() {
    // OpenAI bare `data:` frames + `include_usage` trailing usage chunk + [DONE]. This fidelity test
    // pins the VERBATIM re-emit for a client that OPTED IN to streaming usage (R3-A-b): the trailing
    // usage-only chunk is exactly what that client asked for, so it must pass through byte-for-byte.
    // (The opted-OUT case, where that same chunk is STRIPPED, is covered by
    // `stream_translate_tests::same_proto_openai_opted_out_strips_trailing_usage_chunk`.)
    let frames: &[&[u8]] = &[
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":13,\"completion_tokens\":9,\"total_tokens\":22}}\n\n",
            b"data: [DONE]\n\n",
        ];
    let mut t = StreamTranslate::new_same_proto("openai").expect("same-proto translator");
    t.set_client_include_usage(true);
    let mut out = Vec::new();
    for c in frames {
        out.extend_from_slice(&t.feed(c));
    }
    out.extend_from_slice(&t.finish());
    assert_eq!(
        out,
        concat(frames),
        "openai bare data: opted-in same-proto must be byte-exact (incl the trailing usage chunk + [DONE])"
    );
    let u = t.usage().expect("openai A-tap usage");
    assert_eq!((u.input_tokens, u.output_tokens), (13, 9));
}

#[test]
fn gemini_sse_round_trip_byte_exact() {
    // Gemini SSE (`?alt=sse`): usageMetadata on the terminal chunk.
    let frames: &[&[u8]] = &[
            b"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hi\"}]}}]}\n\n",
            b"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"\"}]}}],\"usageMetadata\":{\"promptTokenCount\":15,\"candidatesTokenCount\":4,\"totalTokenCount\":19}}\n\n",
        ];
    let (out, t) = run_same_proto("gemini", frames);
    assert_eq!(
        out,
        concat(frames),
        "gemini same-proto SSE must be byte-exact"
    );
    let u = t.usage().expect("gemini A-tap usage");
    assert_eq!((u.input_tokens, u.output_tokens), (15, 4));
}

#[test]
fn cohere_sse_round_trip_byte_exact() {
    // Cohere v2 SSE: tokens.input_tokens / tokens.output_tokens on the message-end event.
    let frames: &[&[u8]] = &[
            b"event: message-start\ndata: {\"type\":\"message-start\",\"id\":\"co_1\"}\n\n",
            b"event: content-delta\ndata: {\"type\":\"content-delta\",\"index\":0,\"delta\":{\"message\":{\"content\":{\"text\":\"hi\"}}}}\n\n",
            b"event: message-end\ndata: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":17,\"output_tokens\":6}}}}\n\n",
        ];
    let (out, t) = run_same_proto("cohere", frames);
    assert_eq!(
        out,
        concat(frames),
        "cohere same-proto SSE must be byte-exact"
    );
    let u = t.usage().expect("cohere A-tap usage");
    assert_eq!((u.input_tokens, u.output_tokens), (17, 6));
}

#[test]
fn responses_sse_round_trip_byte_exact() {
    // OpenAI Responses SSE: usage on response.completed's inner response.usage.
    let frames: &[&[u8]] = &[
            b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":21,\"output_tokens\":8}}}\n\n",
        ];
    let (out, t) = run_same_proto("responses", frames);
    assert_eq!(
        out,
        concat(frames),
        "responses same-proto SSE must be byte-exact"
    );
    let u = t.usage().expect("responses A-tap usage");
    assert_eq!((u.input_tokens, u.output_tokens), (21, 8));
}

#[test]
fn bedrock_binary_eventstream_round_trip_byte_exact() {
    // Binary application/vnd.amazon.eventstream — re-emit the ORIGINAL frame
    // bytes, NEVER re-encode (any CRC32 / length-prefix divergence is an undecodable frame).
    use crate::eventstream::encode_frame;
    let mut input = Vec::new();
    input.extend(encode_frame("messageStart", br#"{"role":"assistant"}"#));
    input.extend(encode_frame(
        "contentBlockDelta",
        br#"{"contentBlockIndex":0,"delta":{"text":"hi"}}"#,
    ));
    input.extend(encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
    input.extend(encode_frame(
        "metadata",
        br#"{"usage":{"inputTokens":31,"outputTokens":12},"metrics":{"latencyMs":5}}"#,
    ));

    // Feed in two arbitrary chunks to prove cross-poll reassembly is still verbatim.
    let mid = input.len() / 2;
    let (out, t) = run_same_proto("bedrock", &[&input[..mid], &input[mid..]]);
    assert_eq!(
        out, input,
        "bedrock same-proto binary eventstream must be re-emitted byte-for-byte (no re-encode)"
    );
    let u = t.usage().expect("bedrock A-tap usage");
    assert_eq!((u.input_tokens, u.output_tokens), (31, 12));
}

#[test]
fn same_proto_cross_chunk_split_is_verbatim() {
    // A frame split across the chunk boundary (partial first feed) must still re-emit verbatim.
    let whole: &[u8] = b"data: {\"id\":\"chatcmpl-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n";
    let split = whole.len() / 2;
    let (out, _t) = run_same_proto("openai", &[&whole[..split], &whole[split..]]);
    assert_eq!(
        out, whole,
        "a frame split across feeds must re-emit byte-exact once complete"
    );
}

/// BENCHMARK (design §f): same-proto streaming per-feed latency / throughput. The short-circuit's
/// whole point is that it does NOT re-serialize the IR back to wire — it re-emits the retained
/// original bytes. So the meaningful no-regression baseline is the RE-SERIALIZING translator (the
/// cross-proto path that runs the egress reader → ingress writer → reframe pipeline for every
/// frame). This bench proves the same-proto SHORT-CIRCUIT is at least as fast as that full
/// re-serialize path (it must be: it skips the writer + reframe), AND reports the raw verbatim
/// memcpy floor for reference. Covers an SSE path AND the binary eventstream path explicitly.
/// In-crate `Instant` bench (pattern store.rs); `#[ignore]` so it never runs in the normal
/// suite (timing is environment-sensitive). Run with:
///   cargo test --release bench_same_proto_short_circuit -- --ignored --nocapture
#[test]
#[ignore]
fn bench_same_proto_short_circuit() {
    use crate::eventstream::encode_frame;

    // Build one realistic OpenAI SSE stream and one bedrock binary eventstream, each as a Vec of
    // per-feed chunks (one frame per chunk — the per-feed latency unit).
    let openai_frames: Vec<Vec<u8>> = (0..32)
            .map(|i| {
                format!(
                    "data: {{\"id\":\"chatcmpl-b\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"tok{i} \"}},\"finish_reason\":null}}]}}\n\n"
                )
                .into_bytes()
            })
            .collect();
    let bedrock_frames: Vec<Vec<u8>> = (0..32)
        .map(|i| {
            encode_frame(
                "contentBlockDelta",
                format!("{{\"contentBlockIndex\":0,\"delta\":{{\"text\":\"tok{i} \"}}}}")
                    .as_bytes(),
            )
        })
        .collect();

    // Raw verbatim memcpy floor (what `FirstByteBody` did on the legacy `translate == None` path).
    fn bench_memcpy(frames: &[Vec<u8>], iters: u64) -> f64 {
        let start = std::time::Instant::now();
        for _ in 0..iters {
            let mut out: Vec<u8> = Vec::new();
            for f in frames {
                out.extend_from_slice(std::hint::black_box(f));
            }
            std::hint::black_box(out);
        }
        start.elapsed().as_nanos() as f64 / iters as f64
    }

    // Run a stream through a translator built by `ctor`. Used for both the same-proto short-circuit
    // (no re-serialize) and the cross-proto re-serialize baseline, so the only difference measured
    // is the re-serialize work the short-circuit avoids.
    fn bench_translator(ctor: &dyn Fn() -> StreamTranslate, frames: &[Vec<u8>], iters: u64) -> f64 {
        let start = std::time::Instant::now();
        for _ in 0..iters {
            let mut t = ctor();
            let mut out: Vec<u8> = Vec::new();
            for f in frames {
                out.extend_from_slice(&t.feed(std::hint::black_box(f)));
            }
            out.extend_from_slice(&t.finish());
            std::hint::black_box(out);
        }
        start.elapsed().as_nanos() as f64 / iters as f64
    }

    let iters = 50_000u64;
    // (label, short-circuit ctor, RE-SERIALIZE baseline ctor, frames)
    // The re-serialize baseline is a CROSS-proto translator over the SAME egress frames — it runs
    // the full reader→writer→reframe pipeline, which is exactly the cost the short-circuit elides.
    let openai_sc = || StreamTranslate::new_same_proto("openai").unwrap();
    let openai_xproto = || StreamTranslate::new("openai", "anthropic").unwrap();
    let bedrock_sc = || StreamTranslate::new_same_proto("bedrock").unwrap();
    let bedrock_xproto = || StreamTranslate::new("anthropic", "bedrock").unwrap(); // bedrock EGRESS frames

    // Warm up.
    let _ = bench_memcpy(&openai_frames, 2_000);
    let _ = bench_translator(&openai_sc, &openai_frames, 2_000);
    let _ = bench_translator(&openai_xproto, &openai_frames, 2_000);

    for (label, sc_ctor, xproto_ctor, frames) in [
        (
            "openai-sse",
            &openai_sc as &dyn Fn() -> StreamTranslate,
            &openai_xproto as &dyn Fn() -> StreamTranslate,
            &openai_frames,
        ),
        (
            "bedrock-eventstream",
            &bedrock_sc as &dyn Fn() -> StreamTranslate,
            &bedrock_xproto as &dyn Fn() -> StreamTranslate,
            &bedrock_frames,
        ),
    ] {
        let memcpy = bench_memcpy(frames, iters);
        let sc = bench_translator(sc_ctor, frames, iters);
        let reserialize = bench_translator(xproto_ctor, frames, iters);
        println!(
            "BENCH same_proto[{label}] ({} frames/stream, {iters} streams): memcpy floor \
                 {memcpy:.0} ns/stream | short-circuit {sc:.0} ns/stream | re-serialize baseline \
                 {reserialize:.0} ns/stream => short-circuit is {:.2}x the re-serialize cost",
            frames.len(),
            sc / reserialize.max(1.0)
        );
        // NO REGRESSION: the short-circuit skips the egress writer + reframe, so it must be at
        // least as fast as the full re-serialize path (a generous 1.25x margin absorbs timing
        // noise). A short-circuit that accidentally re-serialized would land AT or ABOVE the
        // re-serialize baseline and fail this.
        assert!(
            sc <= reserialize * 1.25,
            "same_proto[{label}] short-circuit {sc:.0} ns is NOT faster than the re-serialize \
                 baseline {reserialize:.0} ns — the verbatim short-circuit regressed (did it \
                 re-serialize the IR instead of re-emitting original bytes?)"
        );
    }
}
