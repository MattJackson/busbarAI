
use crate::proto::Protocol;

/// Structural class fix: on a CROSS-protocol request hop the source-protocol-only passthrough
/// keys swept into `IrRequest.extra` (e.g. OpenAI `logit_bias`) must NOT reach the foreign
/// egress backend body. The seam in `forward_with_pool` clears `ir.extra` before the egress
/// `write_request`; this mirrors that exact sequence (reader → clear → writer).
/// (`logprobs`/`top_logprobs` are now FIRST-CLASS IR fields — carried to protocols that model
/// them (Gemini) and never emitted by ones that don't (Anthropic) — so this test asserts both
/// halves of the new contract too.)
#[test]
fn cross_protocol_strips_source_only_extra_keys() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
        "logprobs": true,
        "top_logprobs": 5,
        "logit_bias": {"50256": -100}
    });
    let openai = Protocol::openai();
    let mut ir = openai.reader().read_request(&body).expect("read");
    // logit_bias (token IDs are tokenizer-specific, unmappable) still rides extra;
    // logprobs/top_logprobs are promoted out of it.
    assert!(ir.extra.contains_key("logit_bias"));
    assert!(!ir.extra.contains_key("logprobs"));
    assert!(!ir.extra.contains_key("top_logprobs"));
    assert_eq!(ir.logprobs, Some(true));
    assert_eq!(ir.top_logprobs, Some(5));

    // The cross-protocol seam clears extra before handing to the foreign writer.
    ir.extra.clear();
    // Anthropic has no logprobs concept: its writer must not emit any spelling of it.
    let anthropic = Protocol::anthropic();
    let out = anthropic.writer().write_request(&ir);
    let obj = out.as_object().expect("object body");
    assert!(
        !obj.contains_key("logprobs"),
        "logprobs must not leak onto an Anthropic backend body"
    );
    assert!(!obj.contains_key("top_logprobs"));
    assert!(!obj.contains_key("logit_bias"));
    assert!(obj.contains_key("messages"));

    // Gemini DOES model it: the ask arrives in Gemini's native generationConfig spellings.
    let gemini = Protocol::gemini();
    let gout = gemini.writer().write_request(&ir);
    assert_eq!(
        gout["generationConfig"]["responseLogprobs"],
        serde_json::json!(true),
        "the logprobs ask must carry to Gemini as responseLogprobs"
    );
    assert_eq!(gout["generationConfig"]["logprobs"], serde_json::json!(5));
}

/// SAME-protocol openai→openai must still carry `logprobs` (now via the first-class IR field
/// rather than `extra`) and the genuinely-unmapped `logit_bias` (still via `extra`).
#[test]
fn same_protocol_passthrough_preserves_extra_keys() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "logprobs": true,
        "logit_bias": {"50256": -100},
        "n": 3
    });
    let openai = Protocol::openai();
    let ir = openai.reader().read_request(&body).expect("read");
    // No clear() here — same-protocol passthrough never hits the cross-protocol seam.
    let out = openai.writer().write_request(&ir);
    let obj = out.as_object().expect("object body");
    assert_eq!(
        obj.get("logprobs"),
        Some(&serde_json::json!(true)),
        "same-protocol openai→openai must preserve logprobs"
    );
    assert_eq!(
        obj.get("logit_bias"),
        Some(&serde_json::json!({"50256": -100}))
    );
    assert_eq!(obj.get("n"), Some(&serde_json::json!(3)));
}
