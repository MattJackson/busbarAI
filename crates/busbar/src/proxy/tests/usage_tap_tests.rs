use super::{record_ir_usage, stable_hash, UsageSink};
use crate::ir::IrUsage;
use std::sync::Arc;

/// `apply_rewrite_to_body` replaces the `messages` array + injects tools on a chat-shaped body,
/// and is FAIL-SAFE — a body with no `messages` array (or an empty rewrite) is left UNTOUCHED and
/// returns false, so the request proceeds with the original body.
#[test]
fn apply_rewrite_to_body_swaps_messages_and_is_fail_safe() {
    use crate::hooks::wire::RewriteReply;

    // Chat-shaped body → messages replaced, tool injected (appended to existing tools).
    let mut v = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "a very long original prompt"}],
        "tools": [{"name": "existing"}]
    });
    let rw = RewriteReply {
        messages: vec![serde_json::json!({"role": "user", "content": "compressed"})],
        tools: vec![serde_json::json!({"name": "headroom_retrieve"})],
    };
    assert!(super::apply_rewrite_to_body(&mut v, &rw, "openai"));
    assert_eq!(
        v["messages"],
        serde_json::json!([{"role":"user","content":"compressed"}])
    );
    assert_eq!(
        v["tools"].as_array().unwrap().len(),
        2,
        "tool injected, existing kept"
    );
    assert_eq!(v["model"], "m", "unrelated fields untouched");

    // No `messages` array (e.g. gemini `contents`) → untouched, returns false.
    let mut g = serde_json::json!({"contents": [{"parts": []}]});
    let before = g.clone();
    assert!(!super::apply_rewrite_to_body(&mut g, &rw, "openai"));
    assert_eq!(g, before, "non-chat body left untouched (fail-safe)");

    // Empty rewrite → untouched, false.
    let mut v2 = serde_json::json!({"messages": [{"role":"user","content":"x"}]});
    let before2 = v2.clone();
    let empty = RewriteReply {
        messages: vec![],
        tools: vec![],
    };
    assert!(!super::apply_rewrite_to_body(&mut v2, &empty, "openai"));
    assert_eq!(v2, before2);
}

/// Per-dialect rewrite rendering: bedrock re-frames into content BLOCKS (the load-bearing arm
/// — a verbatim insert corrupts its shape), gemini into contents/parts with the role mapping,
/// responses into the input list; a non-text rewrite message aborts untouched.
#[test]
fn apply_rewrite_renders_per_dialect() {
    use crate::hooks::wire::RewriteReply;
    let rw = RewriteReply {
        messages: vec![
            serde_json::json!({"role": "user", "content": "compressed"}),
            serde_json::json!({"role": "assistant", "content": "prior"}),
        ],
        tools: vec![],
    };

    // bedrock: {role, content:[{text}]} blocks.
    let mut b = serde_json::json!({"messages": [{"role":"user","content":[{"text":"orig"}]}]});
    assert!(super::apply_rewrite_to_body(&mut b, &rw, "bedrock"));
    assert_eq!(b["messages"][0]["content"][0]["text"], "compressed");
    assert_eq!(b["messages"][1]["content"][0]["text"], "prior");

    // gemini: contents/parts + assistant→model.
    let mut g = serde_json::json!({"contents": [{"role":"user","parts":[{"text":"orig"}]}]});
    assert!(super::apply_rewrite_to_body(&mut g, &rw, "gemini"));
    assert_eq!(g["contents"][0]["parts"][0]["text"], "compressed");
    assert_eq!(g["contents"][1]["role"], "model");

    // responses: input list (string input replaced).
    let mut r = serde_json::json!({"input": "orig"});
    assert!(super::apply_rewrite_to_body(&mut r, &rw, "responses"));
    assert_eq!(r["input"][0]["content"], "compressed");

    // Fail-safe: a rewrite message with NON-string content aborts a re-framing dialect
    // untouched.
    let blocky = RewriteReply {
        messages: vec![serde_json::json!({"role":"user","content":[{"type":"text"}]})],
        tools: vec![],
    };
    let mut b2 = serde_json::json!({"messages": [{"role":"user","content":[{"text":"orig"}]}]});
    let before = b2.clone();
    assert!(!super::apply_rewrite_to_body(&mut b2, &blocky, "bedrock"));
    assert_eq!(b2, before, "non-text rewrite leaves bedrock untouched");
}

/// REGRESSION (audit c1r14): the gemini rewrite-hook role vocabulary must round-trip. Gemini
/// assistant turns are natively `role: "model"`; the projection now CANONICALIZES that to
/// `assistant` (so the hook sees canonical IR), AND the write-back accepts BOTH `assistant` and
/// `model` — so a hook that echoes the role it received no longer corrupts assistant turns into
/// user turns.
#[test]
fn gemini_rewrite_role_round_trips_model_and_assistant() {
    use crate::hooks::wire::RewriteReply;

    // Projection canonicalizes the gemini-native `model` role to `assistant`.
    let g_body = serde_json::json!({
        "contents": [
            {"role": "user", "parts": [{"text": "hi"}]},
            {"role": "model", "parts": [{"text": "hello"}]}
        ]
    });
    let p = super::build_prompt_projection(&g_body, "gemini");
    assert_eq!(
        p.messages[1].0, "assistant",
        "a gemini `model` turn must project as canonical `assistant`, not leak `model`"
    );

    // Write-back: a hook reply echoing the gemini-native `model` role must map back to `model`,
    // NOT fall through to `user`.
    let echo_model = RewriteReply {
        messages: vec![
            serde_json::json!({"role": "user", "content": "u"}),
            serde_json::json!({"role": "model", "content": "m"}),
        ],
        tools: vec![],
    };
    let mut g = serde_json::json!({"contents": [{"role":"user","parts":[{"text":"orig"}]}]});
    assert!(super::apply_rewrite_to_body(&mut g, &echo_model, "gemini"));
    assert_eq!(
        g["contents"][1]["role"], "model",
        "a hook echoing `model` must round-trip to `model`, not corrupt to `user`"
    );
    // Canonical `assistant` still works too.
    let echo_assistant = RewriteReply {
        messages: vec![serde_json::json!({"role": "assistant", "content": "a"})],
        tools: vec![],
    };
    let mut g2 = serde_json::json!({"contents": [{"role":"user","parts":[{"text":"orig"}]}]});
    assert!(super::apply_rewrite_to_body(
        &mut g2,
        &echo_assistant,
        "gemini"
    ));
    assert_eq!(g2["contents"][0]["role"], "model");
}

/// `apply_global_rewrites` fires the hooks in order and each sees the prior's output (a true
/// transform chain): a two-hook chain where hook A rewrites "orig"→"A" and hook B rewrites
/// whatever it sees →"B" ends at "B", proving B ran on A's output.
#[tokio::test]
async fn apply_global_rewrites_chains_in_order() {
    use crate::hooks::wire::RewriteReply;
    use crate::hooks::{
        Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
    };

    // A mock rewrite hook that replaces the (single) message content with a fixed marker.
    struct RewriteMock(&'static str);
    #[async_trait::async_trait]
    impl RoutingPolicy for RewriteMock {
        async fn decide(
            &self,
            _r: &RoutingRequest<'_>,
            _c: &[Candidate<'_>],
            _x: &RoutingContext<'_>,
            _b: std::time::Duration,
        ) -> PolicyResult {
            Ok(RoutingDecision::Abstain)
        }
        fn name(&self) -> &'static str {
            "mock-rewrite"
        }
        async fn transform(
            &self,
            _req: &RoutingRequest<'_>,
            _budget: std::time::Duration,
        ) -> busbar_api::TransformOutcome {
            busbar_api::TransformOutcome::Rewrite(RewriteReply {
                messages: vec![serde_json::json!({"role": "user", "content": self.0})],
                tools: vec![],
            })
        }
    }

    let hooks: Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> = vec![
        (
            std::time::Duration::from_millis(50),
            Arc::new(RewriteMock("A")),
        ),
        (
            std::time::Duration::from_millis(50),
            Arc::new(RewriteMock("B")),
        ),
    ];
    let mut v = serde_json::json!({"messages": [{"role": "user", "content": "orig"}]});
    super::apply_global_rewrites(&hooks, &mut v, "pool", "anthropic", false)
        .await
        .expect("no rewrite hook rejected");
    // Last hook in the chain wins; B ran on A's rewritten body.
    assert_eq!(v["messages"][0]["content"], "B");
}

// Regression for #29: the token accrual at response completion must be attributed to the
// SAME budget window the request was admitted in (`UsageSink::charged_at`, the header-arrival
// epoch), NOT a fresh `store::now()` read at completion time. With a `daily` budget period, a
// request that arrives on day N but whose (buffered or streamed) response is accounted "now" on
// day N+1 would, under the old `now()`-based code, ledger the tokens into day N+1's window -
// splitting them from the flat per-request fee (charged into day N by `ingress::budget_check`→
// `try_charge_request_within_budget`). The fix threads `charged_at` so both land in day N. We pin
// `charged_at` to a fixed past day and assert the tokens land in THAT day's window regardless of
// the real wall clock (which is always later). (Spend is DERIVED now; with a flat cost model the
// window-attribution intent is asserted on the token ledger itself.)
#[test]
fn test_nonstream_token_fee_uses_charged_at_window_not_clock() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec, SECS_PER_DAY};

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    // No per-request fee, no rate card: token accrual changes `tokens`, never `spend_cents`.
    // Keys attribute all-time now, so the per-DAY window under test lives on the bound GROUP's
    // day bucket (a loose day budget materialises it without ever blocking).
    let groups = std::collections::BTreeMap::from([(
        "daygrp".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 1_000_000,
                per: Some(crate::config::groups::LimitWindow::Day),
                pool: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = Arc::new(crate::cost::CostModel::resolve_parts(None, 0, &groups));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("daygrp".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .expect("create key");

    // A fixed epoch on a specific UTC day, far in the past so the real clock is always a
    // different (later) day — making the bug observable: the old code charged into "today".
    let charged_at: u64 = 1_700_000_000; // 2023-11-14 (day window = 1_700_000_000/86400*86400)
    let day_window = charged_at / SECS_PER_DAY * SECS_PER_DAY;
    let today_window = crate::store::now() / SECS_PER_DAY * SECS_PER_DAY;
    assert_ne!(
        day_window, today_window,
        "test precondition: charged_at must be a different day than now, or the bug is masked"
    );

    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // `record_ir_usage` ledgers per-model tokens keyed by the lane's wire model, so it needs a
    // real Lane; build one through the TestApp lane machinery (the upstream is never contacted).
    let lane_app = crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .build();
    let lane = lane_app.lanes[0].clone();

    // A buffered completion carrying 600 input + 400 output = 1000 tokens, sourced from IrUsage
    // (Change A: billing now reads the IR usage the egress reader decoded, not a byte-scan).
    let usage = IrUsage {
        input_tokens: 600,
        output_tokens: 400,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    record_ir_usage(&usage, &sink, Some(&lane));

    // The 1000 tokens must be ledgered in the charged_at day's window of the GROUP day bucket...
    let in_window = gov
        .derived_bucket_usage(&cost, "group:daygrp@day", "day", true, charged_at)
        .expect("usage read")
        .tokens;
    assert_eq!(
        in_window, 1000,
        "token accrual must be attributed to the charged_at (header-arrival) day window"
    );
    // ...and NOT in today's window (which the old `now()`-based code would have used).
    let in_today = gov
        .derived_bucket_usage(&cost, "group:daygrp@day", "day", true, crate::store::now())
        .expect("usage read")
        .tokens;
    assert_eq!(
        in_today, 0,
        "token accrual must NOT leak into the wall-clock 'now' window (the #29 split bug)"
    );
    // The key's all-time attribution bucket sees the tokens regardless of the day (sanity).
    assert_eq!(
        gov.usage_for(&cost, &key.id, crate::store::now())
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0),
        1000
    );
}

/// REGRESSION (LOW #18, proxy engine token-sum): the buffered token-fee sum must use
/// `saturating_add` over the UPSTREAM-CONTROLLED `input_tokens`/`output_tokens`. A hostile/buggy
/// upstream that reports counts summing past `u64::MAX` would, under the old unchecked `+`, PANIC
/// on the request path in debug (and silently WRAP in release). With `saturating_add` the sum
/// clamps to `u64::MAX` and `record_ir_usage` returns without panicking.
#[test]
fn test_nonstream_token_sum_saturates_no_panic_on_overflow() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};

    let store = Arc::new(MemoryStore::new());
    // No fee, no rate card → the derived-spend math can't overflow, isolating the SUM under test.
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(crate::cost::CostModel::flat(0));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at: 1_700_000_000,
        admit: None,
    });

    // The accrual path only runs with a serving lane (no lane = nothing to attribute), so build
    // one through the TestApp lane machinery; the upstream is never contacted.
    let lane_app = crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .build();
    let lane = lane_app.lanes[0].clone();

    // input_tokens + output_tokens overflows u64: u64::MAX + 5 would panic under an unchecked `+`.
    let usage = IrUsage {
        input_tokens: u64::MAX,
        output_tokens: 5,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    // Must NOT panic (the assertion is reaching this line at all under a debug-overflow build).
    record_ir_usage(&usage, &sink, Some(&lane));
}

#[test]
fn test_stable_hash_is_deterministic() {
    // Stable across calls AND processes (unlike DefaultHasher) so session affinity survives
    // restarts. Pin the FNV-1a output to a precomputed golden so an algorithm or
    // FNV1A_OFFSET_BASIS/PRIME swap is caught directly, not merely via the indirect routing test.
    assert_eq!(stable_hash("session-abc"), 0xe909_c864_ab05_9bea);
    assert_ne!(stable_hash("session-abc"), stable_hash("session-xyz"));
}
