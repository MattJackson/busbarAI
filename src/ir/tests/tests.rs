use super::*;

#[test]
fn reasoning_effort_parse_round_trips_and_rejects_unknown() {
    for w in ["minimal", "low", "medium", "high"] {
        assert_eq!(IrReasoningEffort::parse(w).unwrap().as_str(), w);
    }
    assert!(IrReasoningEffort::parse("verylow").is_none());
    assert!(IrReasoningEffort::parse("").is_none());
    // OpenAI-safe projection folds the o-series-invalid `minimal` to `low`.
    assert_eq!(
        IrReasoningEffort::Minimal.as_openai_reasoning_effort(),
        "low"
    );
    assert_eq!(IrReasoningEffort::High.as_openai_reasoning_effort(), "high");
}

#[test]
fn reasoning_ask_to_budget_and_to_effort_use_the_table() {
    let table = [1000u32, 4000, 8000, 16000];
    use IrReasoningAsk::*;
    use IrReasoningEffort::*;
    // effort word -> budget
    assert_eq!(Effort(Minimal).to_budget(table), 1000);
    assert_eq!(Effort(High).to_budget(table), 16000);
    // Dynamic projects to the medium budget.
    assert_eq!(Dynamic.to_budget(table), 8000);
    // numeric budget passes through
    assert_eq!(Budget(1234).to_budget(table), 1234);
    // budget -> effort bucketizes at the table thresholds (largest reached wins)
    assert_eq!(Budget(500).to_effort(table), Minimal);
    assert_eq!(Budget(4000).to_effort(table), Low);
    assert_eq!(Budget(8001).to_effort(table), Medium);
    assert_eq!(Budget(99999).to_effort(table), High);
    // Dynamic -> medium; an effort word -> itself
    assert_eq!(Dynamic.to_effort(table), Medium);
    assert_eq!(Effort(High).to_effort(table), High);
}

#[test]
fn test_ir_usage_zero_baseline_bills_zero() {
    // The documented all-zero baseline must bill zero — asserting through billable_tokens()
    // exercises the saturating sum, not the field literals themselves (which would be tautological).
    let u = IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    assert_eq!(u.billable_tokens(), 0);
}

/// `billable_tokens` sums all four token fields with `saturating_add` (the operands are
/// upstream-controlled). Assert at the definition site: the basic sum, the all-zero/None case,
/// and that an overflow across the addends SATURATES rather than panicking (debug) / wrapping.
#[test]
fn test_billable_tokens_sum_and_saturation() {
    // Basic provider-agnostic sum: uncached input + cache_read + cache_creation + output.
    let u = IrUsage {
        input_tokens: 10,
        output_tokens: 5,
        cache_read_input_tokens: Some(3),
        cache_creation_input_tokens: Some(2),
    };
    assert_eq!(u.billable_tokens(), 20);

    // All-zero / None → 0 (the common no-cache OpenAI-family case is input+output only).
    let z = IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    assert_eq!(z.billable_tokens(), 0);

    // Overflow across the cache addends must SATURATE at u64::MAX, never panic/wrap.
    let big = IrUsage {
        input_tokens: u64::MAX,
        output_tokens: 1,
        cache_read_input_tokens: Some(1),
        cache_creation_input_tokens: Some(1),
    };
    assert_eq!(big.billable_tokens(), u64::MAX);
}

#[test]
fn test_stream_decode_state_default() {
    // The OpenAI flat-stream synthesizer relies on these initial values: nothing started, no
    // blocks open, no tool indices, no reasoning yet.
    let st = StreamDecodeState::default();
    assert!(!st.started);
    assert!(!st.text_block_open);
    assert!(st.text_index.is_none());
    assert!(st.open_tools.is_empty());
    assert!(!st.reasoning_seen);
    assert!(!st.thinking_block_open);
    assert!(st.pending_stop_reason.is_none());
    assert!(st.tool_ir_index.is_empty());
}

#[test]
fn test_ir_role_partial_eq_distinguishes_variants() {
    // PartialEq/Eq must treat all four roles as distinct (role confusion would mis-map
    // system/user/assistant/tool turns across protocols).
    let all = [
        IrRole::System,
        IrRole::User,
        IrRole::Assistant,
        IrRole::Tool,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(a == b, i == j, "role eq mismatch at ({i},{j})");
        }
    }
}

#[test]
fn test_read_stop_sequences_drops_empty_strings() {
    // "Empty Vec == omitted" contract: a degenerate input that carries only empty stop
    // sequences must collapse to an empty Vec, not a one-element vec holding "", so it never
    // emits a spurious `stop: [""]` on cross-protocol translation.
    let bare_empty = Value::String(String::new());
    assert!(
        read_stop_sequences(Some(&bare_empty)).is_empty(),
        "bare empty string should collapse to empty Vec (== omitted)"
    );

    let arr_empty = Value::Array(vec![Value::String(String::new())]);
    assert!(
        read_stop_sequences(Some(&arr_empty)).is_empty(),
        "[\"\"] should collapse to empty Vec (== omitted)"
    );

    // Empty elements are dropped from a mixed array while real stops survive in order.
    let mixed = Value::Array(vec![
        Value::String("STOP".into()),
        Value::String(String::new()),
        Value::Null,
        Value::String("END".into()),
    ]);
    assert_eq!(
        read_stop_sequences(Some(&mixed)),
        vec!["STOP".to_string(), "END".to_string()],
        "empty/non-string elements dropped; real stops kept in order"
    );

    // Non-empty inputs are unaffected.
    let bare = Value::String("HALT".into());
    assert_eq!(read_stop_sequences(Some(&bare)), vec!["HALT".to_string()]);
    assert!(read_stop_sequences(None).is_empty());
}

#[test]
fn test_ir_delta_variants_distinct() {
    // Two different delta variants carrying the same string are NOT equal — the variant carries
    // semantic meaning (text vs thinking vs tool-input-json vs signature) on the egress path.
    assert_ne!(
        IrDelta::TextDelta("x".into()),
        IrDelta::ThinkingDelta("x".into())
    );
    assert_ne!(
        IrDelta::InputJsonDelta("x".into()),
        IrDelta::SignatureDelta("x".into())
    );
    assert_eq!(
        IrDelta::TextDelta("x".into()),
        IrDelta::TextDelta("x".into())
    );
}

// PF-L5: `IrToolChoice` is the protocol-neutral pivot for every reader/writer's tool_choice
// mapping, so its variant identity must be precise — distinct variants are never equal, a
// targeted `Tool` is keyed on its name, and clone preserves the variant.
#[test]
fn test_ir_tool_choice_variant_equality() {
    // Distinct directives are never conflated.
    assert_ne!(IrToolChoice::Auto, IrToolChoice::None);
    assert_ne!(IrToolChoice::Auto, IrToolChoice::Required);
    assert_ne!(IrToolChoice::None, IrToolChoice::Required);
    assert_ne!(
        IrToolChoice::Required,
        IrToolChoice::Tool { name: "f".into() }
    );
    // A targeted tool is keyed on its name.
    assert_eq!(
        IrToolChoice::Tool {
            name: "get_weather".into()
        },
        IrToolChoice::Tool {
            name: "get_weather".into()
        }
    );
    assert_ne!(
        IrToolChoice::Tool { name: "a".into() },
        IrToolChoice::Tool { name: "b".into() }
    );
    // Clone is a faithful round-trip of the variant.
    let tc = IrToolChoice::Tool { name: "x".into() };
    assert_eq!(tc.clone(), tc);
}
