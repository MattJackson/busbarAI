
//! The gated cross-protocol reasoning/thinking carry. The GATE lives at
//! `IrReq::prepare_for_egress` (per-lane `reasoning` flag); these tests cover the codec halves
//! (read the ask, project it) plus the gate itself, the clamp, and the sampling-knob omission.
use super::{AnthropicReader, AnthropicWriter};
use crate::ir::variant::{EgressPrep, IrReq};
use crate::ir::{IrReasoningAsk, IrReasoningEffort};
use crate::proto::{Protocol, ProtocolReader, ProtocolWriter};

fn openai_effort_body(effort: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 32000,
        "reasoning_effort": effort
    })
}

/// OpenAI `reasoning_effort` word -> Anthropic `thinking` budget via the table.
#[test]
fn openai_effort_projects_to_anthropic_budget() {
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&openai_effort_body("high"))
        .expect("parses");
    assert_eq!(
        ir.reasoning,
        Some(IrReasoningAsk::Effort(IrReasoningEffort::High))
    );
    assert!(!ir.extra.contains_key("reasoning_effort"));

    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["thinking"]["type"], "enabled");
    assert_eq!(out["thinking"]["budget_tokens"], 16384);
}

/// Anthropic budget -> Gemini `thinkingBudget` is a straight number copy; and Gemini's
/// dynamic -1 round-trips to Gemini verbatim while projecting to Anthropic as medium.
#[test]
fn budgets_copy_between_anthropic_and_gemini() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 16000,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 6000}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(ir.reasoning, Some(IrReasoningAsk::Budget(6000)));
    assert!(
        !ir.extra.contains_key("thinking"),
        "promoted thinking must not also ride extra"
    );
    let gout = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(
        gout["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        6000
    );

    let gbody = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"thinkingConfig": {"thinkingBudget": -1}}
    });
    let gir = Protocol::gemini()
        .reader()
        .read_request(&gbody)
        .expect("parses");
    assert_eq!(gir.reasoning, Some(IrReasoningAsk::Dynamic));
    let back = Protocol::gemini().writer().write_request(&gir);
    assert_eq!(
        back["generationConfig"]["thinkingConfig"]["thinkingBudget"], -1,
        "dynamic must round-trip to Gemini as its native -1"
    );
}

/// A numeric budget projected onto a WORD protocol bucketizes through the same table.
#[test]
fn budget_bucketizes_to_effort_words() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 16000,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 6000}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = crate::proto::openai_chat::OpenAiWriter.write_request(&ir);
    // 6000 sits between low (4096) and medium (8192) -> "low" (largest entry reached).
    assert_eq!(out["reasoning_effort"], "low");
}

/// The Anthropic clamp: budget must leave >=1024 answer tokens under max_tokens; too-small
/// max_tokens drops the ask entirely (no thinking key, and sampling knobs survive).
#[test]
fn anthropic_clamps_and_drops_by_max_tokens() {
    // Clamped: high (16384) under max_tokens 4096 -> 3072.
    let mut body = openai_effort_body("high");
    body["max_tokens"] = serde_json::json!(4096);
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&body)
        .expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["thinking"]["budget_tokens"], 3072);

    // Dropped: max_tokens 1500 leaves <1024 of thinking -> no thinking key at all.
    let mut small = openai_effort_body("high");
    small["max_tokens"] = serde_json::json!(1500);
    let ir2 = crate::proto::openai_chat::OpenAiReader
        .read_request(&small)
        .expect("parses");
    let out2 = AnthropicWriter.write_request(&ir2);
    assert!(
        out2.get("thinking").is_none(),
        "no room -> no thinking: {out2}"
    );
}

/// Anthropic rejects temperature/top_k alongside thinking: both are omitted (observably via
/// warn) when the ask is emitted, and present when it is not.
#[test]
fn thinking_omits_incompatible_sampling_knobs() {
    let mut body = openai_effort_body("low");
    body["temperature"] = serde_json::json!(0.5);
    body["top_p"] = serde_json::json!(0.9);
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&body)
        .expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["thinking"]["budget_tokens"], 4096);
    assert!(
        out.get("temperature").is_none(),
        "temperature != 1 must be omitted with thinking: {out}"
    );
    assert!(
        out.get("top_p").is_none(),
        "top_p must be omitted with thinking (Anthropic 400s on it): {out}"
    );

    // Without a reasoning ask the same temperature is emitted normally.
    let mut plain = openai_effort_body("low");
    plain.as_object_mut().unwrap().remove("reasoning_effort");
    plain["temperature"] = serde_json::json!(0.5);
    let ir2 = crate::proto::openai_chat::OpenAiReader
        .read_request(&plain)
        .expect("parses");
    let out2 = AnthropicWriter.write_request(&ir2);
    assert_eq!(out2["temperature"], 0.5);
}

/// Anthropic rejects top_k modifications alongside thinking: top_k must be dropped when the
/// thinking ask is emitted, while `thinking` itself is present. Driven from an Anthropic-native
/// request (where `top_k` is a first-class IR field) carrying both a thinking budget and top_k.
#[test]
fn thinking_omits_top_k() {
    let body = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8192,
        "thinking": {"type": "enabled", "budget_tokens": 4096},
        "top_k": 40
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    // Precondition: top_k arrived as a first-class field (not stranded in extra).
    assert_eq!(ir.top_k, Some(40), "top_k must be read as first-class");
    let out = AnthropicWriter.write_request(&ir);
    assert!(
        out.get("thinking").is_some(),
        "thinking must be emitted: {out}"
    );
    assert!(
        out.get("top_k").is_none(),
        "top_k must be dropped with thinking (Anthropic 400s on it): {out}"
    );

    // Without a reasoning ask the same top_k is emitted normally.
    let plain = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8192,
        "top_k": 40
    });
    let ir2 = AnthropicReader.read_request(&plain).expect("parses");
    let out2 = AnthropicWriter.write_request(&ir2);
    assert_eq!(out2["top_k"], 40);
}

/// THE GATE: prepare_for_egress clears the ask when the lane did not claim the capability and
/// stamps the budget table when it did. Absence of an ask is untouched either way.
#[test]
fn seam_gate_clears_or_stamps() {
    let prep = |allowed: bool| EgressPrep {
        ingress_protocol: "openai",
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 32000,
        reasoning_allowed: allowed,
        reasoning_budgets: [1024, 2048, 3072, 4096],
        prompt_caching_allowed: true,
    };
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&openai_effort_body("high"))
        .expect("parses");

    let mut gated = IrReq::Chat(ir.clone());
    gated.prepare_for_egress(&prep(false));
    let IrReq::Chat(gated) = gated else {
        unreachable!()
    };
    assert_eq!(
        gated.reasoning, None,
        "unflagged lane must never see the ask"
    );

    let mut allowed = IrReq::Chat(ir);
    allowed.prepare_for_egress(&prep(true));
    let IrReq::Chat(allowed) = allowed else {
        unreachable!()
    };
    assert_eq!(
        allowed.reasoning,
        Some(IrReasoningAsk::Effort(IrReasoningEffort::High))
    );
    assert_eq!(allowed.reasoning_budgets, Some([1024, 2048, 3072, 4096]));
    // The operator's table (not the defaults) drives the projection.
    let out = AnthropicWriter.write_request(&allowed);
    assert_eq!(out["thinking"]["budget_tokens"], 4096);
}

/// CROSS-protocol Gemini egress MUST request `includeThoughts: true` alongside the budget, or
/// a real Gemini backend spends the budget but returns no thought parts (empty carry).
#[test]
fn gemini_cross_protocol_egress_requests_include_thoughts() {
    // openai reader -> IR carries a reasoning ask and NO native gemini generationConfig,
    // so the gemini writer takes the synthesized (cross-protocol) path.
    let ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&openai_effort_body("high"))
        .expect("parses");
    let out = Protocol::gemini().writer().write_request(&ir);
    let tc = &out["generationConfig"]["thinkingConfig"];
    assert_eq!(
        tc["includeThoughts"], true,
        "must ask Gemini to return thoughts: {out}"
    );
    assert!(tc.get("thinkingBudget").is_some());
}

/// Responses `reasoning: {effort}` reads into the ask and re-emits from the typed field.
#[test]
fn responses_effort_round_trips() {
    let body = serde_json::json!({
        "model": "m", "input": "hi",
        "reasoning": {"effort": "medium"}
    });
    let ir = Protocol::responses()
        .reader()
        .read_request(&body)
        .expect("parses");
    assert_eq!(
        ir.reasoning,
        Some(IrReasoningAsk::Effort(IrReasoningEffort::Medium))
    );
    // Cross-protocol: extra cleared -> the typed field emits the native shape.
    let mut cleared = ir.clone();
    cleared.extra.clear();
    let out = Protocol::responses().writer().write_request(&cleared);
    assert_eq!(out["reasoning"]["effort"], "medium");
    // Anthropic egress: medium -> 8192.
    let mut with_max = cleared;
    with_max.max_tokens = Some(32000);
    let aout = AnthropicWriter.write_request(&with_max);
    assert_eq!(aout["thinking"]["budget_tokens"], 8192);
}

/// A tiny cross-protocol budget (below the `low` table entry) must NOT emit the o-series-
/// invalid `reasoning_effort: "minimal"` on OpenAI egress — it maps to `"low"` to avoid a 400.
#[test]
fn small_budget_maps_to_low_not_minimal_on_openai() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 16000,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 1500}  // below low (4096)
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = crate::proto::openai_chat::OpenAiWriter.write_request(&ir);
    assert_eq!(
        out["reasoning_effort"], "low",
        "must not emit o-series-invalid 'minimal'"
    );
}

/// A disabled-form `thinking` param is NOT promoted (stays in extra for same-proto fidelity)
/// and no foreign target gains an ask from it.
#[test]
fn disabled_thinking_stays_in_extra() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "disabled"}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(ir.reasoning, None);
    assert!(ir.extra.contains_key("thinking"));
    let gout = Protocol::gemini().writer().write_request(&{
        let mut c = ir.clone();
        c.extra.clear();
        c
    });
    assert!(gout["generationConfig"].get("thinkingConfig").is_none());
}
