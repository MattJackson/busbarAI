
//! Cross-protocol logprobs (OpenAI<->Gemini): the ask (request) and the data (response,
//! buffered AND streaming) must cross the seam in both directions via the neutral IR.
use crate::proto::{Protocol, ProtocolReader};

fn gemini_body_with_logprobs() -> serde_json::Value {
    serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hi"}]},
            "finishReason": "STOP",
            "logprobsResult": {
                "chosenCandidates": [
                    {"token": "Hi", "logProbability": -0.031},
                    {"token": "!", "logProbability": -0.87}
                ],
                "topCandidates": [
                    {"candidates": [
                        {"token": "Hi", "logProbability": -0.031},
                        {"token": "Hello", "logProbability": -3.5}
                    ]},
                    {"candidates": [
                        {"token": "!", "logProbability": -0.87},
                        {"token": ".", "logProbability": -1.2}
                    ]}
                ]
            }
        }],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2}
    })
}

/// Gemini backend -> OpenAI caller (buffered): `logprobsResult` becomes
/// `choices[0].logprobs.content[]`, chosen+top zipped, bytes synthesized from UTF-8.
#[test]
fn openai_logprobs_codec_round_trips_bytes_and_top() {
    // Direct read/write of the OpenAI logprobs codec: bytes and top_logprobs survive, and a
    // missing `bytes` is synthesized from the token's UTF-8 on write.
    use crate::proto::openai_chat::{read_openai_logprobs, write_openai_logprobs};
    let src = serde_json::json!({"content": [
        {"token": "Hi", "logprob": -0.1, "bytes": [72, 105],
         "top_logprobs": [{"token": "Hi", "logprob": -0.1, "bytes": [72, 105]},
                          {"token": "Yo", "logprob": -2.0, "bytes": [89, 111]}]}
    ]});
    let ir = read_openai_logprobs(Some(&src));
    assert_eq!(ir.len(), 1);
    assert_eq!(ir[0].token, "Hi");
    assert_eq!(ir[0].bytes.as_deref(), Some(&[72u8, 105][..]));
    assert_eq!(ir[0].top.len(), 2);
    let back = write_openai_logprobs(&ir);
    assert_eq!(back["content"][0]["token"], "Hi");
    assert_eq!(back["content"][0]["bytes"], serde_json::json!([72, 105]));
    assert_eq!(back["content"][0]["top_logprobs"][1]["token"], "Yo");

    // bytes synthesized from UTF-8 when the source (e.g. Gemini) carried none.
    let no_bytes = vec![crate::ir::IrTokenLogprob {
        token: "Hi".into(),
        logprob: -0.1,
        bytes: None,
        top: vec![],
    }];
    let out = write_openai_logprobs(&no_bytes);
    assert_eq!(out["content"][0]["bytes"], serde_json::json!([72, 105]));
}

#[test]
fn gemini_logprobs_reach_openai_caller() {
    let ir = Protocol::gemini()
        .reader()
        .read_response(&gemini_body_with_logprobs())
        .expect("parses");
    assert_eq!(ir.logprobs.len(), 2);
    assert_eq!(ir.logprobs[0].token, "Hi");
    assert_eq!(ir.logprobs[0].top.len(), 2);

    let out = Protocol::openai().writer().write_response(&ir);
    let content = &out["choices"][0]["logprobs"]["content"];
    assert_eq!(content[0]["token"], "Hi");
    assert_eq!(content[0]["logprob"], -0.031);
    assert_eq!(content[0]["bytes"], serde_json::json!([72, 105])); // "Hi" UTF-8
    assert_eq!(content[0]["top_logprobs"][1]["token"], "Hello");
    assert_eq!(content[1]["token"], "!");
}

/// OpenAI backend -> Gemini caller (buffered): `choices[0].logprobs.content[]` becomes
/// `candidates[0].logprobsResult` with parallel chosen/top arrays.
#[test]
fn tts_instructions_prefix_the_prompt_not_language_code() {
    // OpenAI TTS `instructions` (free-text style) must steer via the prompt, not corrupt
    // Gemini's speechConfig.languageCode (a BCP-47 field).
    let ir = crate::ir::variant::IrReq::Speech(crate::ir::audio::SpeechReq {
        model: "gemini-2.5-flash-preview-tts".into(),
        input: "hello there".into(),
        voice: "Kore".into(),
        instructions: Some("speak cheerfully".into()),
        ..Default::default()
    });
    let out = crate::handlers::request_handler("gemini")
        .and_then(|rh| rh.operation_handler(crate::operation::Operation::Speech))
        .unwrap()
        .write_request(&ir);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        v["contents"][0]["parts"][0]["text"],
        "speak cheerfully: hello there"
    );
    assert!(
        v["generationConfig"]["speechConfig"]
            .get("languageCode")
            .is_none(),
        "instructions must not land in languageCode: {v}"
    );
}

#[test]
fn top_logprobs_clamped_to_gemini_max_on_egress() {
    // A cross-protocol logprobs ask with OpenAI's max (20) must be clamped to Gemini's 5, not
    // forwarded to a 400 on older models.
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "logprobs": true, "top_logprobs": 20
    });
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&body)
        .expect("parses");
    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(out["generationConfig"]["logprobs"], 5);
    assert_eq!(out["generationConfig"]["responseLogprobs"], true);
}

#[test]
fn top_logprobs_zero_omits_gemini_logprobs_count_but_forces_response_logprobs() {
    // OpenAI `top_logprobs: 0` ("chosen token, no alternatives") must NOT emit `logprobs: 0`
    // (Gemini 400s on it) but must still force `responseLogprobs: true`.
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "logprobs": true, "top_logprobs": 0
    });
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&body)
        .expect("parses");
    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(out["generationConfig"]["responseLogprobs"], true);
    assert!(
        out["generationConfig"].get("logprobs").is_none(),
        "logprobs:0 must be omitted, not sent (Gemini 400s): {out}"
    );

    // A non-zero count is emitted normally.
    let body3 = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "logprobs": true, "top_logprobs": 3
    });
    let ir3 = crate::proto::openai_chat::OpenAiReader
        .read_request(&body3)
        .expect("parses");
    let out3 = Protocol::gemini().writer().write_request(&ir3);
    assert_eq!(out3["generationConfig"]["logprobs"], 3);
    assert_eq!(out3["generationConfig"]["responseLogprobs"], true);
}

#[test]
fn openai_logprobs_reach_gemini_caller() {
    let body = serde_json::json!({
        "id": "chatcmpl-x", "object": "chat.completion", "created": 1, "model": "m",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hi"},
            "logprobs": {"content": [
                {"token": "Hi", "logprob": -0.05, "bytes": [72, 105],
                 "top_logprobs": [{"token": "Hi", "logprob": -0.05, "bytes": [72, 105]}]}
            ]},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1}
    });
    let ir = Protocol::openai()
        .reader()
        .read_response(&body)
        .expect("parses");
    assert_eq!(ir.logprobs.len(), 1);
    assert_eq!(ir.logprobs[0].bytes.as_deref(), Some(&[72u8, 105][..]));

    let out = Protocol::gemini().writer().write_response(&ir);
    let lr = &out["candidates"][0]["logprobsResult"];
    assert_eq!(lr["chosenCandidates"][0]["token"], "Hi");
    assert_eq!(lr["chosenCandidates"][0]["logProbability"], -0.05);
    assert_eq!(lr["topCandidates"][0]["candidates"][0]["token"], "Hi");
}

/// A response WITHOUT logprobs gains nothing on translation in either direction.
#[test]
fn absence_gains_nothing() {
    let mut body = gemini_body_with_logprobs();
    body["candidates"][0]
        .as_object_mut()
        .unwrap()
        .remove("logprobsResult");
    let ir = Protocol::gemini().reader().read_response(&body).unwrap();
    assert!(ir.logprobs.is_empty());
    let out = Protocol::openai().writer().write_response(&ir);
    assert!(
        out["choices"][0].get("logprobs").is_none(),
        "no logprobs from the backend -> no logprobs key emitted: {out}"
    );
}

/// STREAMING, Gemini backend -> OpenAI caller: a chunk's `logprobsResult` becomes an OpenAI
/// chunk carrying `choices[0].logprobs.content[]` (alongside the text delta's own chunk).
#[test]
fn gemini_stream_logprobs_reach_openai_caller() {
    let chunk = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hi"}]},
            "logprobsResult": {
                "chosenCandidates": [{"token": "Hi", "logProbability": -0.031}]
            }
        }]
    });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = Protocol::gemini()
        .reader()
        .read_response_events("", &chunk, &mut state);
    let lp_event = events
        .iter()
        .find(|e| {
            matches!(
                e,
                crate::ir::IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::LogprobsDelta(_),
                    ..
                }
            )
        })
        .expect("a LogprobsDelta must be decoded from the chunk");

    let openai = Protocol::openai();
    let (_, frame) = openai
        .writer()
        .write_response_event(lp_event)
        .expect("openai writer must emit a logprobs chunk");
    assert_eq!(frame["choices"][0]["logprobs"]["content"][0]["token"], "Hi");
    assert_eq!(frame["choices"][0]["delta"], serde_json::json!({}));
}

/// A Gemini stream carrying BOTH a `thought:true` part AND a `logprobsResult` in the same
/// chunk must not collide the logprobs' text block on index 0 with the thinking block. The
/// thinking block owns 0; the text block (opened by the logprobs arm) must land at index 1.
#[test]
fn stream_thinking_plus_logprobs_do_not_collide_on_index_zero() {
    let chunk = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "reasoning", "thought": true}]},
            "logprobsResult": {
                "chosenCandidates": [{"token": "Hi", "logProbability": -0.03}]
            }
        }]
    });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = Protocol::gemini()
        .reader()
        .read_response_events("", &chunk, &mut state);
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};
    // Thinking block opened at 0.
    assert!(events.iter().any(|e| matches!(
        e,
        IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Thinking
        }
    )));
    // The logprobs text block must open at 1, never 0.
    let lp_start = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::Text,
        } => Some(*index),
        _ => None,
    });
    assert_eq!(
        lp_start,
        Some(1),
        "logprobs text block must not collide with thinking at 0"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::LogprobsDelta(_)
        }
    )));
}

/// STREAMING, OpenAI backend -> Gemini caller: a chunk's `choices[0].logprobs` becomes a
/// Gemini chunk candidate carrying `logprobsResult`.
#[test]
fn openai_stream_logprobs_reach_gemini_caller() {
    let chunk = serde_json::json!({
        "id": "chatcmpl-x", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{
            "index": 0,
            "delta": {"content": "Hi"},
            "logprobs": {"content": [{"token": "Hi", "logprob": -0.05}]},
            "finish_reason": null
        }]
    });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = Protocol::openai()
        .reader()
        .read_response_events("", &chunk, &mut state);
    let lp_event = events
        .iter()
        .find(|e| {
            matches!(
                e,
                crate::ir::IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::LogprobsDelta(_),
                    ..
                }
            )
        })
        .expect("a LogprobsDelta must be decoded from the chunk");

    let gemini = Protocol::gemini();
    let (_, frame) = gemini
        .writer()
        .write_response_event(lp_event)
        .expect("gemini writer must emit a logprobsResult chunk");
    assert_eq!(
        frame["candidates"][0]["logprobsResult"]["chosenCandidates"][0]["token"],
        "Hi"
    );
}
