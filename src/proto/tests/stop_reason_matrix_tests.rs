
//! Regression net for the stop_reason bug class (closed by the typed `IrStopReason`). EVERY
//! variant, projected by EVERY writer, must land on a value VALID in that protocol's finish enum —
//! never an off-spec token. A writer physically cannot leak a foreign value (it matches a typed
//! enum exhaustively); this guards the projections.
use super::*;
use crate::ir::{IrBlock, IrResponse, IrRole, IrStopReason, IrUsage};

fn resp(reason: IrStopReason) -> IrResponse {
    IrResponse {
        logprobs: Vec::new(),
        role: IrRole::Assistant,
        content: vec![IrBlock::Text {
            text: "x".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(reason),
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
    }
}

const ALL: [IrStopReason; 9] = [
    IrStopReason::EndTurn,
    IrStopReason::StopSequence,
    IrStopReason::MaxTokens,
    IrStopReason::ToolUse,
    IrStopReason::Safety,
    IrStopReason::Refusal,
    IrStopReason::PauseTurn,
    IrStopReason::Error,
    IrStopReason::Other,
];

#[test]
fn every_writer_emits_only_valid_native_finish_tokens() {
    let openai_ok = ["stop", "length", "tool_calls", "content_filter"];
    let anthropic_ok = [
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "tool_use",
        "pause_turn",
        "refusal",
    ];
    let gemini_ok = ["STOP", "MAX_TOKENS", "SAFETY", "OTHER"];
    let bedrock_ok = [
        "end_turn",
        "tool_use",
        "max_tokens",
        "stop_sequence",
        "content_filtered",
    ];
    let cohere_ok = [
        "COMPLETE",
        "STOP_SEQUENCE",
        "MAX_TOKENS",
        "TOOL_CALL",
        "ERROR_TOXIC",
        "ERROR",
    ];
    let responses_ok = ["completed", "incomplete"];
    let cohere_writer = CohereWriter;
    let gemini_writer = GeminiWriter;
    let responses_writer = ResponsesWriter;
    for r in ALL {
        let o = OpenAiWriter.write_response(&resp(r));
        let fr = o["choices"][0]["finish_reason"].as_str().unwrap();
        assert!(openai_ok.contains(&fr), "openai leaked {fr:?} for {r:?}");

        let a = AnthropicWriter.write_response(&resp(r));
        let sr = a["stop_reason"].as_str().unwrap();
        assert!(
            anthropic_ok.contains(&sr),
            "anthropic leaked {sr:?} for {r:?}"
        );

        let g = gemini_writer.write_response(&resp(r));
        let gr = g["candidates"][0]["finishReason"].as_str().unwrap();
        assert!(gemini_ok.contains(&gr), "gemini leaked {gr:?} for {r:?}");

        let b = BedrockWriter.write_response(&resp(r));
        let br = b["stopReason"].as_str().unwrap();
        assert!(bedrock_ok.contains(&br), "bedrock leaked {br:?} for {r:?}");

        let c = cohere_writer.write_response(&resp(r));
        let cr = c["finish_reason"].as_str().unwrap();
        assert!(cohere_ok.contains(&cr), "cohere leaked {cr:?} for {r:?}");

        let re = responses_writer.write_response(&resp(r));
        let rs = re["status"].as_str().unwrap();
        assert!(
            responses_ok.contains(&rs),
            "responses leaked {rs:?} for {r:?}"
        );
    }
}
