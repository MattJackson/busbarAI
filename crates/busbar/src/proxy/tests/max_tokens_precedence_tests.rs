use crate::ir::variant::{EgressPrep, IrReq};
use crate::ir::IrRequest;
use crate::proto::Protocol;
use crate::state::Lane;
use std::collections::HashMap;
use std::sync::Arc;

// An Anthropic lane (its writer `requires_max_tokens()` is true) with a given per-model default.
fn anthropic_lane(default_max_tokens: Option<u32>) -> Lane {
    Lane {
        reasoning: false,
        prompt_caching: false,
        default_max_tokens,
        model: "claude".to_string(),
        provider: "anthropic".to_string(),
        base_url: "https://api.anthropic.com".to_string(),
        api_key: "k".to_string(),
        protocol: Arc::new(Protocol::anthropic()),
        max: 1,
        error_map: Arc::new(HashMap::new()),
        context_max: None,
        path: None,
        auth: None,
        health: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

/// `default_max_tokens` resolution precedence on the translation seam (only fires when the source
/// omitted `max_tokens` AND the egress protocol REQUIRES it): per-model lane default wins → else
/// the global `limits.default_max_tokens` (the `global` arg) → else the historical 4096 (which is
/// just the value the global itself defaults to). This pins all three rungs.
#[test]
fn per_model_then_global_then_4096() {
    let global = 8192; // a non-4096 global to prove it is consulted distinctly.
                       // The defaulting now lives on the IR (`IrReq::prepare_for_egress`) — the engine passes the
                       // lane's resolved primitives. Drive it exactly as the translate seam does.
    let prep = |lane: &Lane, global: u32| EgressPrep {
        ingress_protocol: "openai",
        egress_requires_max_tokens: lane.protocol.writer().requires_max_tokens(),
        lane_default_max_tokens: lane.default_max_tokens,
        global_default_max_tokens: global,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
    };
    let apply = |ir: IrRequest, lane: &Lane, global: u32| -> Option<u32> {
        let mut req = IrReq::Chat(ir);
        req.prepare_for_egress(&prep(lane, global));
        match req {
            IrReq::Chat(c) => c.max_tokens,
            _ => unreachable!(),
        }
    };

    // 1. Per-model set → per-model wins over the global.
    assert_eq!(
        apply(IrRequest::default(), &anthropic_lane(Some(1234)), global),
        Some(1234),
        "per-model default must win"
    );

    // 2. Per-model unset → fall back to the global.
    assert_eq!(
        apply(IrRequest::default(), &anthropic_lane(None), global),
        Some(global),
        "with no per-model default, the global limit must be used"
    );

    // 3. Per-model unset AND global left at its historical default → 4096.
    assert_eq!(
        apply(
            IrRequest::default(),
            &anthropic_lane(None),
            crate::proto::DEFAULT_MAX_TOKENS
        ),
        Some(4096),
        "with neither per-model nor a custom global, the 4096 fallback must be used"
    );

    // 4. A caller-supplied value is NEVER overridden by any default.
    assert_eq!(
        apply(
            IrRequest {
                max_tokens: Some(7),
                ..IrRequest::default()
            },
            &anthropic_lane(Some(1234)),
            global
        ),
        Some(7),
        "an explicit caller max_tokens must be preserved over every default"
    );
}
