use super::*;
// `IntoResponse` is no longer used by the (now-delegating) production code, but the in-module
// tests build responses via `(StatusCode, body).into_response()`, which needs the trait in scope.
use axum::response::IntoResponse;

/// `query_has_alt_sse` recognizes the gemini SSE selector only as a genuine `alt=sse` pair, not
/// a substring of another param's value, and ignores order / other params.
#[test]
fn test_query_has_alt_sse() {
    assert!(query_has_alt_sse("alt=sse"));
    assert!(query_has_alt_sse("key=abc&alt=sse"));
    assert!(query_has_alt_sse("alt=sse&key=abc"));
    assert!(!query_has_alt_sse("alt=json"));
    assert!(!query_has_alt_sse(""));
    // Not fooled by a different param whose VALUE merely contains "alt=sse".
    assert!(!query_has_alt_sse("foo=alt=sse"));
    // `alt` with no value is not the SSE selector.
    assert!(!query_has_alt_sse("alt"));
}

/// Minimal governance-off App for exercising `finish` in isolation.
fn minimal_app() -> Arc<App> {
    Arc::new(App {
        lanes: vec![],
        store: Arc::new(crate::store::InMemoryStore::new(vec![])),
        by_model: std::collections::HashMap::new(),
        pools: std::collections::HashMap::new(),
        client: reqwest::Client::new(),
        auth: Arc::new(crate::auth::AuthMiddleware::new(
            &crate::config::AuthCfg::default_none(),
        )),
        rewrite_hooks: Vec::new(),
        tap_hooks: Vec::new(),
        tap_hooks_route: Vec::new(),
        tap_hooks_attempt: Vec::new(),
        tap_hooks_completion: Vec::new(),
        global_gates: Vec::new(),
        hook_registry: std::collections::HashMap::new(),
        global_hooks: Vec::new(),
        groups_registry: std::collections::BTreeMap::new(),
        base_group_names: std::collections::HashSet::new(),
        versions: Arc::new(crate::admin::versions::VersionLog::new()),
        mutation_limiter: Arc::new(crate::admin::rate::MutationLimiter::new()),
        idempotency_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        base_hook_names: std::collections::HashSet::new(),
        admin_chain: vec!["admin-tokens".to_string()],
        credential_cache: StdArc::new(crate::auth_cache::CredentialCache::new()),
        auth_scope_caps: std::collections::HashMap::new(),
        role_bindings: crate::config::RoleBindings::new(),
        config_path: None,
        providers_path: None,
        overlay_path: None,
        config_version: 0,
        failover_cfg: None,
        pool_runtime: std::collections::HashMap::new(),
        fallback_pools: std::collections::HashMap::new(),
        on_exhausted_cfgs: std::collections::HashMap::new(),
        governance: None,
        secret_resolver: std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
        cost: std::sync::Arc::new(crate::cost::CostModel::flat(1)),
        plugins_dir: std::path::PathBuf::from("plugins"),
        plugins_cfg: crate::config::PluginsCfg::default(),
        default_max_tokens: crate::config::DEFAULT_DEFAULT_MAX_TOKENS,
        reasoning_effort_budgets: [1024, 4096, 8192, 16384],
    })
}

#[test]
fn test_finish_emits_request_metrics() {
    crate::metrics::init();
    let resp = (StatusCode::OK, "ok").into_response();
    let out = finish(
        &minimal_app(),
        &crate::governance::GovCtx::default(),
        "openai",
        "mypool",
        Instant::now(),
        crate::store::now(),
        resp,
    );
    // finish must pass the response through unchanged.
    assert_eq!(out.status(), StatusCode::OK);

    let scrape = crate::metrics::render();
    assert!(
        scrape.contains(crate::metrics::REQUESTS_TOTAL),
        "finish should emit requests_total; got:\n{scrape}"
    );
    assert!(
        scrape.contains("outcome=\"ok\""),
        "a 2xx response maps to outcome=ok; got:\n{scrape}"
    );
    assert!(
        scrape.contains(crate::metrics::REQUEST_DURATION_SECONDS),
        "finish should emit the request-duration histogram; got:\n{scrape}"
    );
}

#[test]
fn test_affinity_header_defaults_to_session_id() {
    // No pool_runtime entry → default header.
    let app = minimal_app();
    assert_eq!(affinity_header_for(&app, "anypool"), "x-session-id");
}

#[test]
fn test_affinity_header_honors_configured_name() {
    let mut app = minimal_app();
    let mut pr = std::collections::HashMap::new();
    pr.insert(
        "tenant-pool".to_string(),
        crate::state::PoolRuntime {
            members: Default::default(),
            failover: None,
            affinity: Some(crate::config::AffinityCfg {
                mode: crate::config::AffinityMode::Session,
                header_name: Some("x-user-id".to_string()),
            }),
            breaker: None,
            policy: None,
            gates: Vec::new(),
            rewrite_hooks: Vec::new(),
        },
    );
    // App is behind Arc; rebuild with the populated map.
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.pool_runtime = pr;
    assert_eq!(affinity_header_for(&app, "tenant-pool"), "x-user-id");
    // A pool without an entry still falls back to the default.
    assert_eq!(affinity_header_for(&app, "other"), "x-session-id");
}

#[test]
fn test_affinity_header_session_mode_without_name_uses_default() {
    let mut app = minimal_app();
    let mut pr = std::collections::HashMap::new();
    pr.insert(
        "p".to_string(),
        crate::state::PoolRuntime {
            members: Default::default(),
            failover: None,
            affinity: Some(crate::config::AffinityCfg {
                mode: crate::config::AffinityMode::Session,
                header_name: None,
            }),
            breaker: None,
            policy: None,
            gates: Vec::new(),
            rewrite_hooks: Vec::new(),
        },
    );
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.pool_runtime = pr;
    assert_eq!(affinity_header_for(&app, "p"), "x-session-id");
}

/// Build a governance-enabled App with a single budgeted key, plus return the key so the test
/// can pass a matching GovCtx to `finish`. Just assembles the App + key; it performs no charge.
fn governed_app_with_key() -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    // 30 cents flat per request, no per-token fee (the fee now lives on the CostModel).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
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
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    inner.cost = std::sync::Arc::new(crate::cost::CostModel::flat(30));
    (app, key)
}

fn key_spend(app: &Arc<App>, key_id: &str) -> i64 {
    app.governance
        .as_ref()
        .unwrap()
        .usage_for(&app.cost, key_id, 1_700_000_000)
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0)
}

/// fix 2a: the flat fee is charged ATOMICALLY at admission, and `finish` REFUNDS it on a non-2xx
/// outcome (so the net effect remains "bill 2xx only"). A 2xx `finish` keeps the charge; each
/// non-2xx `finish` (503 / 5xx / 4xx) refunds exactly one flat fee. `finish_rejected` (governance
/// rejection, never charged) refunds nothing.
// No-runtime `#[test]`: `refund_request` now decrements the AUTHORITATIVE in-memory cell (no store
// offload), so it is observable synchronously. The admission charge is seeded via the REAL
// admission charge (`try_charge_request_within_budget`) so the charge, the refund, and the
// `usage_for` read all target the SAME authoritative cell. `at` is the fixed budget window
// `key_spend` reads.
#[test]
fn test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx() {
    crate::metrics::init();
    let (app, key) = governed_app_with_key();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let govstate = app.governance.as_ref().unwrap().clone();
    let at = 1_700_000_000u64;

    // Seed the admission charge in memory (30c flat fee) via the real admission charge.
    let charge = || {
        govstate
            .try_admit(&app.cost, &key, "", at)
            .expect("an uncapped chain admits");
    };
    charge();
    assert_eq!(
        key_spend(&app, &key.id),
        30,
        "admission charged the flat fee"
    );

    // A 2xx finish keeps the charge (no refund).
    let resp = (StatusCode::OK, "ok").into_response();
    let _ = finish(&app, &gov, "openai", "p", Instant::now(), at, resp);
    assert_eq!(
        key_spend(&app, &key.id),
        30,
        "2xx keeps the admission charge"
    );

    // Each non-2xx finish refunds exactly one flat fee. Re-charge before each.
    for status in [
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_REQUEST,
    ] {
        charge();
        assert_eq!(
            key_spend(&app, &key.id),
            60,
            "re-charged to 60 before {status}"
        );
        let resp = (status, "x").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), at, resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "{status} (non-2xx) refunds the flat fee back to 30"
        );
    }

    // A governance-rejection finish (finish_rejected) refunds NOTHING (it was never charged).
    let resp = (StatusCode::FORBIDDEN, "x").into_response();
    let _ = finish_rejected(&app, &gov, "openai", "p", Instant::now(), at, resp);
    assert_eq!(
        key_spend(&app, &key.id),
        30,
        "finish_rejected must not refund (nothing was charged)"
    );
}

/// Regression for the R3 pre-routing spurious-refund bug: a request that fails BEFORE the
/// admission charge (here a malformed JSON body) must route through `finish_rejected`, NOT
/// `finish`. With the bug it went through `finish` (refund-on-non-2xx), and `refund_request`'s
/// blind `UPDATE` decremented the spend/requests of a PRIOR, legitimately-charged request in the
/// same window — eroding the hard budget cap (repeatable → unbounded overspend). This drives the
/// REAL ingress path end-to-end (not just the `finish_rejected` unit).
// No-runtime `#[test]`: any (buggy) refund via `offload_store_write` runs INLINE here, so a
// regression is observable synchronously. The `"total"` period ⇒ window 0 regardless of the
// internal `charged_at = store::now()`, so the prior charge and any spurious refund hit one row.
#[test]
fn test_pre_routing_failure_does_not_refund_prior_charge() {
    crate::metrics::init();
    let (app, key) = governed_app_with_key();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let govstate = app.governance.as_ref().unwrap().clone();

    // A prior, legitimately-charged request: seed one flat fee (30c) of spend in the (in-memory,
    // authoritative) window via the real admission charge. `key_spend`/`usage_for` and any (buggy)
    // `refund_request` all target this same cell.
    govstate
        .try_admit(&app.cost, &key, "", 1_700_000_000)
        .expect("an uncapped chain admits");
    assert_eq!(key_spend(&app, &key.id), 30, "prior charge seeded");

    // A malformed-JSON request on the SAME key fails pre-routing (model never resolved) → 400.
    let caller = crate::auth::CallerToken(None);
    let headers = HeaderMap::new();
    let resp = futures::executor::block_on(operation_ingress(
        &app,
        &gov,
        &caller,
        &headers,
        Bytes::from_static(b"{ this is not valid json"),
        "openai",
        crate::operation::Operation::Chat,
        None,
    ));
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed body is a pre-routing 400"
    );

    // The prior charge MUST be intact: the pre-routing 400 was never charged, so it must not
    // refund (a refund would blindly erode the prior request's spend). With the bug this is 0.
    assert_eq!(
        key_spend(&app, &key.id),
        30,
        "pre-routing failure must NOT refund/erode a prior charge (would be 0 with the bug)"
    );
}

#[test]
fn test_finish_outcome_mapping_503_is_exhausted() {
    crate::metrics::init();
    let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
    let _ = finish(
        &minimal_app(),
        &crate::governance::GovCtx::default(),
        "anthropic",
        "p2",
        Instant::now(),
        crate::store::now(),
        resp,
    );
    assert!(
        crate::metrics::render().contains("outcome=\"exhausted\""),
        "503 maps to outcome=exhausted"
    );
}

// Regression for #29 (flat-fee side), updated for fix 2a: both the ATOMIC admission charge AND
// the `finish` REFUND must use the window implied by the pinned `charged_at` (header-arrival)
// epoch, NOT a fresh `store::now()`. With a `daily` key and a `charged_at` on a past day, the
// charge lands in that day; a non-2xx finish refunds in that SAME day (net 0 there), and nothing
// ever leaks into today's window. (Token-fee side: `proxy::usage_tap_tests::
// test_nonstream_token_fee_uses_charged_at_window_not_clock`.)
// No-runtime `#[test]`: the offloaded refund in `finish` runs INLINE and is observable. The
// admission charge is seeded via the real admission charge into the charged_at window.
#[test]
fn test_flat_fee_charge_and_refund_use_charged_at_window() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec, SECS_PER_DAY};
    crate::metrics::init();

    let store = std::sync::Arc::new(MemoryStore::new());
    let gov =
        std::sync::Arc::new(GovState::new(store.clone(), Some("admintok".to_string())).unwrap());
    let cost = std::sync::Arc::new(crate::cost::CostModel::flat(30)); // 30c/request
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
        .unwrap();
    let mut app = minimal_app();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.governance = Some(gov.clone());
        inner.cost = cost.clone();
    }
    let govctx = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };

    let charged_at: u64 = 1_700_000_000; // a fixed past day
    let day_window = charged_at / SECS_PER_DAY * SECS_PER_DAY;
    assert_ne!(
        day_window,
        crate::store::now() / SECS_PER_DAY * SECS_PER_DAY,
        "test precondition: charged_at must be a different day than now"
    );

    // Admission charge into the charged_at day window via the real admission charge (it lands the
    // flat fee into `budget_window("daily", charged_at)` = day_window).
    gov.try_admit(&cost, &key, "", charged_at)
        .expect("an uncapped chain admits");
    assert_eq!(
        gov.usage_for(&cost, &key.id, charged_at)
            .unwrap()
            .map(|u| u.spend_cents)
            .unwrap_or(0),
        30,
        "admission charged the flat fee into the charged_at day window"
    );

    // A non-2xx finish refunds in the SAME (charged_at) window → net 0 there.
    let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
    let _ = finish(
        &app,
        &govctx,
        "openai",
        "p",
        Instant::now(),
        charged_at,
        resp,
    );
    assert_eq!(
        gov.usage_for(&cost, &key.id, charged_at)
            .unwrap()
            .map(|u| u.spend_cents)
            .unwrap_or(0),
        0,
        "non-2xx refund must land in the charged_at window (net 0)"
    );
    let in_today = gov
        .usage_for(&cost, &key.id, crate::store::now())
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(
        in_today, 0,
        "neither charge nor refund may leak into the wall-clock 'now' window (#29)"
    );
}

/// Regression for #29 (admission-gate side): `admit_check` must evaluate the over-budget
/// condition against the SAME window the request will be charged in — the pinned `charged_at`
/// (header-arrival) epoch — NOT a fresh `store::now()`. Otherwise the admission gate and the
/// charge can land in different windows when a request straddles a window boundary: the old
/// code admitted against an empty current-day window while the spend that exhausts the budget
/// lives in the `charged_at` day.
///
/// Setup: a key bound to a GROUP with a 30c/day budget whose spend (30c) was already charged
/// into a PAST day window. Probing that past window (`charged_at` on that day) must reject
/// (spend ≥ cap); probing today's empty window (`store::now()`) must admit. The pre-fix code
/// used the latter unconditionally and so would have admitted a request that the charge then
/// overshot the cap.
#[tokio::test]
async fn test_admit_check_uses_charged_at_window_not_clock() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec, SECS_PER_DAY};
    crate::metrics::init();

    let past_day: u64 = 1_700_000_000; // a fixed past day
    let past_window = past_day / SECS_PER_DAY * SECS_PER_DAY;
    assert_ne!(
        past_window,
        crate::store::now() / SECS_PER_DAY * SECS_PER_DAY,
        "test precondition: charged_at must be a different day than now"
    );

    // Seed 30c of spend into the PAST day window through the AUTHORITATIVE in-memory path
    // (the real admission charge lands the flat fee into the group's day bucket for
    // `budget_window("day", past_day)` = past_window), so the deterministic precondition matches
    // what the in-memory admission gate reads. (Enforcement is in-memory: seeding via the store
    // alone would be invisible to `admit_check`.)
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov =
        std::sync::Arc::new(GovState::new(store.clone(), Some("admintok".to_string())).unwrap());
    let groups = std::collections::BTreeMap::from([(
        "daycap".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 30,
                per: Some(crate::config::groups::LimitWindow::Day),
                pool: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = std::sync::Arc::new(crate::cost::CostModel::resolve_parts(None, 30, &groups));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("daycap".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    gov.try_admit(&cost, &key, "", past_day)
        .expect("first request fits the cap exactly");

    let mut app = minimal_app();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.governance = Some(gov.clone());
        inner.cost = cost.clone();
    }
    let govctx = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };

    assert_eq!(
        gov.derived_bucket_usage(&cost, "group:daycap@day", "day", true, past_day)
            .unwrap()
            .spend_cents,
        30,
        "test precondition: the past day window is at the cap"
    );

    // Gate keyed off the (past) `charged_at` window sees spend ≥ cap → reject.
    let rejected = admit_check(&app, &govctx, "openai", "", past_day);
    assert!(
        rejected.is_err(),
        "admit_check must reject against the charged_at window where the spend lives (#29)"
    );
    assert_eq!(
        rejected.unwrap_err().status(),
        StatusCode::TOO_MANY_REQUESTS,
        "over-budget on an OpenAI ingress maps to 429"
    );

    // Sanity: today's window is empty, so a gate keyed off the wall clock (the OLD behaviour)
    // would have WRONGLY admitted. This proves the bug was real and the pin fixes it.
    let admitted_today = admit_check(&app, &govctx, "openai", "", crate::store::now());
    assert!(
        admitted_today.is_ok(),
        "today's window is empty; the old clock-based gate would have admitted here"
    );
}

// REMOVED: `test_budget_store_error_respects_fail_mode_knob` (and its `ErrChargeStore` double).
// The admission path (`try_charge_request_within_budget` → `charge_budget_mem`) is now an
// infallible IN-MEMORY hard-cap check-and-charge: budget enforcement no longer round-trips the
// store, so there is no admission-time store error for a fail-mode to consult. The whole
// `budget_on_store_error` knob was therefore REMOVED (config field + enum + GovState plumbing) — its
// guarantee ("hard cap even if the store errors") is now unconditional by construction, so the
// behavior this test verified no longer exists. The write-behind flusher's own store-error handling
// (re-mark dirty + retry) is covered by the governance flush tests.

// ---- universal-ingress routing tests (cohere/responses/gemini/bedrock) ----
//
// These exercise the new first-class ingress routes through the REAL router
// (`build_router`) so the full route table + auth + body-limit layers are in play, exactly as
// a native vendor SDK would hit busbar. Each test points the new ingress at a mock backend on
// a DIFFERENT protocol so the cross-protocol IR translation (request + response) runs.

use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc as StdArc;

/// Spin up the real router over a loopback listener; returns (addr, abort-handle).
async fn serve(app: StdArc<App>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// A canonical OpenAI chat-completion response body the mock backend returns, so the ingress
/// writer has a full IR to translate back into the client's native shape.
fn openai_ok_body() -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "model": "glm-4.5",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi there"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3}
    })
}

/// A canonical Anthropic message response body for an Anthropic backend.
fn anthropic_ok_body() -> serde_json::Value {
    json!({
        "id": "msg_x",
        "type": "message",
        "role": "assistant",
        "model": "claude-x",
        "content": [{"type": "text", "text": "hi there"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 5, "output_tokens": 3}
    })
}

/// Cohere client → OpenAI backend: a native Cohere `/v2/chat` request must round-trip through
/// the IR to an OpenAI backend and back, returning a 2xx the Cohere SDK can parse.
#[tokio::test]
async fn test_cohere_ingress_to_openai_backend() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: openai_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("co", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body(
            json!({
                "model": "co",
                "messages": [{"role": "user", "content": "hello"}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "cohere→openai round-trip 2xx");

    // The backend must have received a translated OpenAI chat-completion request.
    let upstream: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        upstream.get("messages").is_some(),
        "openai backend received an OpenAI-shaped body; got {upstream}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Responses client → Anthropic backend: native `/v1/responses` request round-trips to an
/// Anthropic backend and back.
#[tokio::test]
async fn test_responses_ingress_to_anthropic_backend() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: anthropic_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .pool("re", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(
            json!({
                "model": "re",
                "input": "hello",
                "max_tokens": 16
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "responses→anthropic round-trip 2xx"
    );
    let upstream: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        upstream.get("messages").is_some(),
        "anthropic backend received a messages array; got {upstream}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Gemini path parsing: `/v1beta/models/foo:generateContent` must resolve model "foo" with
/// stream=false, and `:streamGenerateContent` with stream=true. We assert the INJECTED body by
/// routing gemini→openai backend and reading the request the backend received: the model must
/// have resolved to the path model (the lane is named "foo") and a body that translated cleanly
/// proves model+stream injection happened (resolution by path model can't happen otherwise).
#[tokio::test]
async fn test_gemini_path_resolves_model_and_stream() {
    crate::metrics::init();
    // Two backend responses: one for the non-stream call, one we won't reach (stream call uses
    // a fresh state below). Keep them separate for clarity.
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: openai_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    // The lane MODEL is "foo" so that resolution via the path model proves the path parse.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    // Non-stream action.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "gemini :generateContent resolves model 'foo' and 2xx round-trips to openai"
    );
    // The backend got a non-stream OpenAI request (no top-level stream:true in the translated
    // body — gemini's writer omits it on egress, but the point is the request resolved).
    let upstream: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        upstream.get("messages").is_some(),
        "non-stream gemini request reached the openai backend; got {upstream}"
    );
    // MEDIUM/test-coverage: the CLIENT-facing response must be the native Gemini
    // `GenerateContentResponse` shape (a top-level `candidates` array), NOT the raw OpenAI
    // `choices[]` body the backend returned. A regression that skipped the IR→Gemini write step
    // (returning the upstream OpenAI body verbatim) would still be a 200 but a protocol
    // indistinguishability violation a Gemini SDK would choke on. Mirrors the streaming-case
    // `candidates` assertion in `test_gemini_stream_generate_content_no_alt_sse_is_json_array`.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("candidates").is_some(),
        "non-stream gemini ingress returns a native GenerateContentResponse (candidates[]); \
             got {body}"
    );
    assert!(
        body.get("choices").is_none(),
        "no OpenAI `choices` field may leak to a Gemini client; got {body}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Direct unit test of the injected body for the path-model core: the parsed gemini body must
/// gain `model` (from the path) and `stream` (from the action). This is the §3 "body shim".
#[test]
fn test_path_model_injects_model_and_stream_into_body() {
    // Mirror the injection ingress_path_model performs (kept here as a focused assertion on the
    // exact body mutation, independent of the HTTP/forward plumbing).
    let mut v: Value = json!({"contents": [{"role": "user", "parts": [{"text": "x"}]}]});
    let obj = v.as_object_mut().expect("native body is a JSON object");
    obj.insert("model".to_string(), Value::String("foo".to_string()));
    obj.insert("stream".to_string(), Value::Bool(true));
    assert_eq!(v["model"], "foo");
    assert_eq!(v["stream"], true);
    // And stream=false for the generateContent action.
    let mut v2: Value = json!({"contents": []});
    let obj2 = v2.as_object_mut().unwrap();
    obj2.insert("model".to_string(), Value::String("bar".to_string()));
    obj2.insert("stream".to_string(), Value::Bool(false));
    assert_eq!(v2["model"], "bar");
    assert_eq!(v2["stream"], false);
}

/// Gemini unknown action ⇒ native 404 (not a 200, not a panic).
#[tokio::test]
async fn test_gemini_unknown_action_is_404() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:countTokens"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "unknown gemini action ⇒ native 404"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "gemini error envelope is JSON; got {ct}"
    );
    handle.abort();
}

/// Bedrock `/model/foo/converse` (stream=false) resolves model "foo", routes cross-protocol to
/// an OpenAI backend, and returns native Converse JSON. The streaming binary-eventstream
/// assertion lives in `test_bedrock_converse_stream_returns_binary_eventstream`.
#[tokio::test]
async fn test_bedrock_converse_routes_and_returns_json() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: openai_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth("t")
        .body(
            json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock /converse resolves model 'foo' and round-trips to openai"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "non-stream bedrock returns JSON; got {ct}"
    );
    // HIGH/test-coverage: a real AWS Bedrock Converse (non-stream) result ALWAYS exposes a
    // request id via `*Output::request_id()`, which the AWS SDK reads from the `x-amzn-RequestId`
    // response header. busbar synthesizes one on the success path (maybe_attach_response_request_id);
    // an absent or malformed header makes the SDK's `request_id()` return None — an impossibility
    // for a native endpoint and a deterministic proxy tell. Assert the header is present AND
    // UUID-v4 shaped (8-4-4-4-12 lowercase hex), mirroring the streaming-case assertion in
    // `test_bedrock_converse_stream_returns_binary_eventstream`.
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock converse (non-stream) success carries x-amzn-RequestId")
        .to_string();
    let segs: Vec<&str> = req_id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12); got {req_id}"
    );
    assert!(
        req_id
            .chars()
            .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
        "x-amzn-RequestId is lowercase hex with dashes; got {req_id}"
    );

    // The body must be the Bedrock Converse native shape produced by the bedrock writer.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("output").is_some() || body.get("usage").is_some(),
        "bedrock Converse JSON shape returned; got {body}"
    );
    handle.abort();
    server.shutdown().await;
}

/// OpenAI-style streamed chat-completion chunks a mock backend emits (each wrapped as a `data:`
/// SSE line by `MockResponse::Sse`). The OpenAI reader decodes bare `data:`-framed chunks without
/// needing an `event:` line, so a cross-protocol ingress exercises the full reframe.
fn openai_stream_events() -> Vec<String> {
    vec![
            r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
            r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string(),
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#.to_string(),
        ]
}

/// HIGH/test-coverage: the `/model/:modelId/converse-stream` route (stream=true) must (a) resolve
/// with stream intent, (b) return `Content-Type: application/vnd.amazon.eventstream`, and (c)
/// produce a body that is a sequence of binary AWS event-stream frames `eventstream::drain_frames`
/// can cleanly decode (buffer empties, frames carry the ConverseStream event names). Routes
/// cross-protocol to a streaming OpenAI backend so the SSE→binary reframe path runs.
#[tokio::test]
async fn test_bedrock_converse_stream_returns_binary_eventstream() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;

    // Bedrock ingress → OpenAI backend (cross-protocol) so the upstream SSE stream is re-encoded
    // into the client's native binary eventstream framing.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse-stream"))
        .bearer_auth("t")
        .body(
            json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock /converse-stream resolves model 'foo' and 2xx round-trips"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/vnd.amazon.eventstream"),
        "streaming bedrock ingress is binary eventstream; got {ct}"
    );

    // HIGH/test-coverage (proxy engine streaming-success header emission): a real AWS Bedrock
    // ConverseStream response ALWAYS carries `x-amzn-RequestId` (the only request-id surface the
    // AWS SDK exposes via `*Output::request_id()`); an absent header makes that return None,
    // which a native endpoint never does, and is a proxy tell on the most security-sensitive new
    // surface. Assert the streaming-success header is present and UUID-v4 shaped (8-4-4-4-12),
    // mirroring the non-stream `test_bedrock_ingress_success_carries_amzn_request_id`.
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock converse-stream success carries x-amzn-RequestId")
        .to_string();
    let segs: Vec<&str> = req_id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12); got {req_id}"
    );
    assert!(
        req_id
            .chars()
            .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
        "x-amzn-RequestId is lowercase hex with dashes; got {req_id}"
    );

    // The body must decode as a clean sequence of binary AWS event-stream frames.
    let body = resp.bytes().await.unwrap();
    let mut buf = body.to_vec();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        !frames.is_empty(),
        "at least one binary eventstream frame must decode; body len {}",
        body.len()
    );
    assert!(
        buf.is_empty(),
        "the body must be a whole sequence of frames with no trailing partial bytes"
    );
    let event_types: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
    assert!(
        event_types.contains(&"messageStart"),
        "ConverseStream frames include messageStart; got {event_types:?}"
    );
    assert!(
        event_types.contains(&"contentBlockDelta"),
        "ConverseStream frames include contentBlockDelta; got {event_types:?}"
    );
    assert!(
        event_types.contains(&"messageStop"),
        "ConverseStream frames include messageStop; got {event_types:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/test-coverage: SAME-PROTOCOL bedrock streaming passthrough (bedrock client → bedrock
/// backend). The headline indistinguishability case: a native AWS SDK talks ConverseStream and the
/// upstream IS a Bedrock backend, so the binary `application/vnd.amazon.eventstream` body must be
/// relayed VERBATIM (no SSE→binary re-encode, no buffering) and the upstream's REAL
/// `x-amzn-RequestId` forwarded as-is — never re-synthesized. The cross-protocol stream tests
/// (OpenAI backend) only exercise the re-encode path; this one drives proxy engine's same-protocol
/// branch (`is_streaming_content_type` on the eventstream CT, verbatim FirstByteBody relay with
/// `translate=None`, upstream-CT preservation, and `upstream_amzn_id.or_else(synth)` taking the
/// upstream value). Asserts: (a) CT is `application/vnd.amazon.eventstream`, (b) the body decodes
/// via `drain_frames` with the buffer empty, (c) the response `x-amzn-RequestId` EQUALS the fixed
/// upstream id verbatim (proving it was passed through, not a freshly-minted UUID).
#[tokio::test]
async fn test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id() {
    crate::metrics::init();
    // Fixed upstream request id: NOT UUID-shaped, so a synthesized id can never accidentally
    // match it — the only way the assertion passes is verbatim passthrough.
    const UPSTREAM_REQ_ID: &str = "fixed-upstream-amzn-req-id-0001";
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::EventStream {
        frames: vec![
            ("messageStart", br#"{"role":"assistant"}"#.to_vec()),
            (
                "contentBlockDelta",
                br#"{"delta":{"text":"hi"},"contentBlockIndex":0}"#.to_vec(),
            ),
            ("messageStop", br#"{"stopReason":"end_turn"}"#.to_vec()),
            (
                "metadata",
                br#"{"usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8}}"#.to_vec(),
            ),
        ],
        amzn_request_id: UPSTREAM_REQ_ID,
    });
    let server = MockServer::new(state.clone()).await;

    // Bedrock ingress → BEDROCK backend (same-protocol). The mock only routes
    // `/v1/messages` + `/v1/chat/completions`; bedrock's native egress path is
    // `/model/{model}/converse-stream`, which the mock does not serve, so point the lane's
    // upstream path at a route the handler answers (the same-protocol relay under test is
    // path-independent — it keys off the upstream Content-Type, not the URL).
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &server.base_url())
                .provider("aws")
                .path("/v1/messages"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse-stream"))
        .bearer_auth("t")
        .body(
            json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock→bedrock converse-stream 2xx round-trip"
    );

    // (a) the upstream eventstream Content-Type is preserved verbatim.
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/vnd.amazon.eventstream"),
        "same-protocol bedrock stream preserves the upstream eventstream CT; got {ct}"
    );

    // (c) the upstream's REAL x-amzn-RequestId is forwarded VERBATIM (not a synthesized UUID).
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock converse-stream success carries x-amzn-RequestId")
        .to_string();
    assert_eq!(
        req_id, UPSTREAM_REQ_ID,
        "same-protocol passthrough must forward the upstream x-amzn-RequestId verbatim, \
             not synthesize a fresh UUID; got {req_id}"
    );

    // (b) the relayed body is the upstream's binary frames byte-for-byte: decodes via
    // drain_frames with the buffer empty, carrying the native ConverseStream event names.
    let body = resp.bytes().await.unwrap();
    let mut buf = body.to_vec();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "verbatim-relayed body must be a whole frame sequence (no trailing partial bytes); \
             {} bytes left",
        buf.len()
    );
    let event_types: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        event_types,
        vec![
            "messageStart",
            "contentBlockDelta",
            "messageStop",
            "metadata"
        ],
        "the exact upstream frame sequence is relayed verbatim, in order; got {event_types:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/test-coverage: SAME-PROTOCOL bedrock NON-STREAM passthrough (native AWS SDK speaking
/// `Converse` → a Bedrock backend). This is the most common Bedrock call pattern, and it takes a
/// COMPLETELY DIFFERENT code branch from the streaming case asserted by
/// `test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id`: a non-stream
/// `/converse` flows through the buffered/verbatim same-protocol relay (`is_sse == false`,
/// `cross_protocol == false`) where proxy engine forwards the upstream `x-amzn-RequestId` verbatim
/// (`upstream_amzn_id.or_else(synth)`). A real `Converse` body carries NO body-level identity
/// (`id`/`created`/`model` are all absent — only `output`/`stopReason`/`usage`), so the ONLY
/// request-id surface the AWS SDK exposes (`*Output::request_id()`) is the `x-amzn-RequestId`
/// response header. If that header is dropped on this path, every non-stream Bedrock call's
/// `request_id()` returns None — an impossibility against the real API and a deterministic proxy
/// tell that would stay invisible until an SDK user noticed.
///
/// A `MockResponse::Ok` cannot set a custom response header (and a synthesized fallback id would
/// not prove VERBATIM passthrough), so this test stands up a tiny ad-hoc upstream that returns a
/// native Converse JSON body with a FIXED, NON-UUID `x-amzn-RequestId` — the only way the
/// verbatim assertion can pass is true passthrough, never a freshly-minted UUID. Asserts: (a)
/// status 200, (b) the response `x-amzn-RequestId` EQUALS the upstream's fixed value verbatim,
/// (c) Content-Type is `application/json` (no SSE/eventstream reframe on a non-stream relay), (d)
/// the body carries the native Converse shape (`output`/`usage`).
#[tokio::test]
async fn test_bedrock_same_protocol_converse_non_stream_forwards_upstream_request_id() {
    crate::metrics::init();
    // Fixed upstream request id: NOT UUID-shaped, so a synthesized id can never accidentally
    // match — the assertion passes ONLY on verbatim passthrough.
    const UPSTREAM_REQ_ID: &str = "fixed-upstream-amzn-req-id-nonstream-0001";

    // Ad-hoc Bedrock-shaped upstream: a native Converse JSON body + a fixed `x-amzn-RequestId`
    // header on a 200. Served on every path so the bedrock egress writer's model-scoped path
    // reaches it (the same-protocol relay keys off the upstream Content-Type, not the URL).
    let upstream = axum::Router::new().fallback(axum::routing::any(|| async {
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", crate::proxy::APPLICATION_JSON)
            .header("x-amzn-requestid", UPSTREAM_REQ_ID)
            .body(axum::body::Body::from(
                json!({
                    "output": {
                        "message": {
                            "role": "assistant",
                            "content": [{"text": "hi there"}]
                        }
                    },
                    "stopReason": "end_turn",
                    "usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8}
                })
                .to_string(),
            ))
            .unwrap()
    }));
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_handle =
        tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });
    let upstream_base = format!("http://{upstream_addr}");

    // Bedrock ingress → BEDROCK backend (same-protocol). Point the lane at a served path; the
    // relay under test is path-independent (it keys off the upstream Content-Type).
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &upstream_base)
                .provider("aws")
                .path("/v1/messages"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth("t")
        .body(
            json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    // (a) 2xx round-trip.
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock→bedrock /converse (non-stream) 2xx round-trip"
    );

    // (c) the non-stream relay preserves the upstream JSON Content-Type (no eventstream reframe).
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "same-protocol non-stream bedrock preserves the upstream JSON CT; got {ct}"
    );

    // (b) the upstream's REAL x-amzn-RequestId is forwarded VERBATIM (not a synthesized UUID).
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock /converse (non-stream) success carries x-amzn-RequestId")
        .to_string();
    assert_eq!(
        req_id, UPSTREAM_REQ_ID,
        "same-protocol non-stream passthrough must forward the upstream x-amzn-RequestId \
             verbatim, not synthesize a fresh UUID; got {req_id}"
    );

    // (d) the body is the native Converse shape, relayed verbatim.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("output").is_some() || body.get("usage").is_some(),
        "native Converse JSON shape (output/usage) is relayed; got {body}"
    );

    handle.abort();
    upstream_handle.abort();
}

/// CORE-deferred cross-file test: a TRUE mid-stream TRANSPORT failure on a SAME-PROTOCOL
/// bedrock→bedrock streaming passthrough. The companion
/// `test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception` drives the
/// CROSS-protocol (openai-backend, SSE→binary reframe) path; this one drives the same-protocol
/// VERBATIM relay (`translate=None`): the upstream is a Bedrock backend emitting binary
/// `application/vnd.amazon.eventstream` frames that then drops the connection mid-binary-body. The
/// proxy must (a) preserve the eventstream Content-Type, (b) relay the real first frame, and (c)
/// after the first byte append a CRC-valid BINARY `:message-type: exception` frame
/// (`InternalServerException`) — NEVER SSE `event:`/`data:` ASCII text, which would yield an
/// undecodable prelude/CRC for the AWS SDK's eventstream decoder. Exercises `FirstByteBody`'s
/// `Poll::Ready(Some(Err))` arm with `is_sse=true` (eventstream upstream CT) and
/// `ingress_eventstream=true` (bedrock ingress) on the passthrough branch the cross-protocol
/// variants cannot reach.
#[tokio::test]
async fn test_bedrock_same_protocol_stream_mid_stream_transport_error_appends_binary_exception() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::EventStreamTransportError {
        ok_frames: vec![("messageStart", br#"{"role":"assistant"}"#.to_vec())],
        amzn_request_id: "fixed-upstream-amzn-req-id-err1",
    });
    let server = MockServer::new(state.clone()).await;

    // Bedrock ingress → BEDROCK backend (same-protocol verbatim relay). The mock only serves
    // `/v1/messages`; the same-protocol relay keys off the upstream Content-Type, not the URL, so
    // point the lane's upstream path at a route the mock answers.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &server.base_url())
                .provider("aws")
                .path("/v1/messages"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse-stream"))
        .bearer_auth("t")
        .body(json!({ "messages": [{"role": "user", "content": [{"text": "hi"}]}] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock→bedrock converse-stream 2xx before the mid-stream drop"
    );
    // (a) the upstream eventstream Content-Type is preserved (verbatim relay, not reframed).
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/vnd.amazon.eventstream"),
        "same-protocol bedrock stream preserves the eventstream CT; got {ct}"
    );

    let body = resp.bytes().await.unwrap();
    // (c) NO SSE ASCII may be spliced into the binary body — it must be pure binary frames.
    assert!(
        !body.windows(7).any(|w| w == b"event: ") && !body.windows(6).any(|w| w == b"data: "),
        "same-protocol bedrock mid-stream error must NOT contain SSE ASCII; body: {body:?}"
    );
    // The body decodes as a whole sequence of CRC-valid binary frames (real frame(s) + the
    // appended exception frame), with no trailing partial bytes.
    let mut buf = body.to_vec();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "body must be a whole sequence of CRC-valid frames; {} bytes left",
        buf.len()
    );
    assert!(
        !frames.is_empty(),
        "at least the first real frame decodes before the drop"
    );
    // A trailing BINARY exception frame is present (drain_frames normalizes its `:exception-type`
    // to "internalServerException"); re-scan the raw bytes to confirm the modeled-exception headers/name.
    let raw_str = String::from_utf8_lossy(&body);
    assert!(
        raw_str.contains(":exception-type"),
        "a binary :message-type:exception frame must be appended after the real frames; \
             body: {body:?}"
    );
    assert!(
        raw_str.contains("InternalServerException"),
        "the mid-stream transport failure maps to InternalServerException"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/test-coverage (proxy engine): a TRUE mid-stream transport failure on a
/// bedrock-ingress cross-protocol stream must terminate the body with a CRC-valid BINARY
/// `:message-type: exception` frame appended AFTER the real frames — never SSE `event:`/`data:`
/// ASCII (which yields an undecodable prelude/CRC for the AWS SDK). `SseTransportError` drops the
/// connection after the first frame, driving `FirstByteBody`'s `Poll::Ready(Some(Err))` arm — the
/// wiring previously exercised only by the isolated `mid_stream_error_bytes` unit test.
#[tokio::test]
async fn test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse-stream"))
        .bearer_auth("t")
        .body(json!({ "messages": [{"role": "user", "content": [{"text": "hi"}]}] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.bytes().await.unwrap();
    // No SSE ASCII anywhere in the body — it must be pure binary frames.
    assert!(
        !body.windows(7).any(|w| w == b"event: ") && !body.windows(6).any(|w| w == b"data: "),
        "bedrock-ingress mid-stream error must NOT contain SSE ASCII; body: {body:?}"
    );
    // The body decodes as a sequence of binary frames, the LAST of which is an exception frame.
    let mut buf = body.to_vec();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        buf.is_empty(),
        "body must be a whole sequence of CRC-valid frames; {} bytes left",
        buf.len()
    );
    assert!(!frames.is_empty(), "at least the first real frame decodes");
    // The trailing exception frame carries `:exception-type` instead of `:event-type`
    // (drain_frames normalizes it to the lowercased "internalServerException"); re-scan the raw
    // bytes to confirm an exception frame is present.
    let raw = body.to_vec();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(
        raw_str.contains(":exception-type"),
        "a binary exception frame must be appended after the real frames"
    );
    assert!(
        raw_str.contains("InternalServerException"),
        "the mid-stream transport failure maps to InternalServerException"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/test-coverage twin (proxy engine): the SSE-ingress (openai) mid-stream transport-failure
/// path must append a BARE `data:` error frame (NO `event:` line — openai native streams never
/// emit one mid-stream) whose `data:` is the native OpenAI error envelope.
#[tokio::test]
async fn test_openai_ingress_mid_stream_transport_error_appends_native_sse() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("gpt-4o", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({ "model": "gpt-4o", "stream": true, "messages": [] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.bytes().await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // The trailing error frame is a bare `data:` envelope, with NO `event:` line.
    assert!(
        !text.contains("event:"),
        "openai mid-stream error must be a bare data: frame (no event: line); got:\n{text}"
    );
    // The last frame's data: payload is the native OpenAI error envelope.
    let frames: Vec<&str> = text
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .collect();
    let last_data = frames
        .last()
        .and_then(|f| f.lines().find_map(|l| l.strip_prefix("data: ")))
        .expect("a trailing data: error frame");
    let v: Value = serde_json::from_str(last_data).expect("native OpenAI JSON envelope");
    assert!(
        v.get("error").is_some(),
        "OpenAI native error envelope: {v}"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/conformance regression: a SAME-PROTOCOL bedrock-ingress → bedrock-backend passthrough must
/// NOT leak the router shim keys (`model`/`stream`) that `ingress_path_model` injects into the
/// body. `forward_with_pool` skips IR translation on same-protocol, so without the strip the
/// injected keys would reach the backend (a native Bedrock Converse body carries neither, and the
/// polluted body is what gets SigV4-signed). Asserts the body the backend RECEIVED has no
/// top-level `model`/`stream`.
#[tokio::test]
async fn test_bedrock_same_protocol_passthrough_strips_shim_keys() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    // A minimal native-shaped Bedrock Converse response; same-protocol passthrough relays it
    // verbatim, so any 2xx body suffices for the round-trip.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "usage": {"inputTokens": 5, "outputTokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;

    // The mock backend only routes `/v1/messages` + `/v1/chat/completions`; point the bedrock
    // lane's upstream path there so the same-protocol passthrough request reaches the handler
    // (the shim-strip under test is path-independent). Bedrock's native egress path is
    // `/model/{model}/converse`, which the mock does not serve.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &server.base_url())
                .provider("aws")
                .path("/v1/messages"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth("t")
        .body(
            json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "bedrock→bedrock 2xx round-trip"
    );

    let upstream: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        upstream.get("model").is_none(),
        "router shim key 'model' must not leak to the bedrock backend; got {upstream}"
    );
    assert!(
        upstream.get("stream").is_none(),
        "router shim key 'stream' must not leak to the bedrock backend; got {upstream}"
    );
    // The genuine native field must survive.
    assert!(
        upstream.get("messages").is_some(),
        "native bedrock body fields survive the passthrough; got {upstream}"
    );
    handle.abort();
    server.shutdown().await;
}

/// HIGH/conformance regression: same as above for gemini-ingress → gemini-backend. The Gemini
/// writer's `rewrite_model` REINSERTS `model`, so the shim strip is the only thing keeping a
/// top-level `model`/`stream` off the native generateContent body the backend receives.
#[tokio::test]
async fn test_gemini_same_protocol_passthrough_strips_shim_keys() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;

    // The mock backend only routes `/v1/messages` + `/v1/chat/completions`; point the gemini
    // lane's upstream path there so the same-protocol passthrough request reaches the handler
    // (the shim-strip under test is path-independent). Gemini's native egress path embeds the
    // model and action, which the mock does not serve.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::gemini(), &server.base_url())
                .provider("google")
                .path("/v1/messages"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "gemini→gemini 2xx round-trip");

    let upstream: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        upstream.get("stream").is_none(),
        "router shim key 'stream' must not leak to the gemini backend; got {upstream}"
    );
    assert!(
        upstream.get("model").is_none(),
        "router shim key 'model' must not leak to the gemini backend; got {upstream}"
    );
    assert!(
        upstream.get("contents").is_some(),
        "native gemini body fields survive the passthrough; got {upstream}"
    );
    handle.abort();
    server.shutdown().await;
}

/// MEDIUM/test-coverage: the `streamGenerateContent` action injects `stream:true` and routes to a
/// streaming backend. WITH `?alt=sse` the gemini ingress contract is SSE (text/event-stream).
/// Routes gemini→openai (cross-protocol) so the request reaches the backend and is reframed.
#[tokio::test]
async fn test_gemini_stream_generate_content_alt_sse_is_event_stream() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/foo:streamGenerateContent?alt=sse"
        ))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "gemini :streamGenerateContent?alt=sse resolves and 2xx round-trips"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "gemini streaming ingress WITH ?alt=sse is SSE-framed; got {ct}"
    );
    // MEDIUM/test-coverage: text/event-stream alone does not prove the SSE FRAMES carry the
    // native Gemini `GenerateContentResponse` vocabulary. A regression that relayed the raw
    // OpenAI `chat.completion.chunk` objects verbatim would still be `text/event-stream` and
    // pass a header-only assertion — a protocol-indistinguishability break. Parse each SSE
    // `data:` payload as JSON and assert at least one carries a `candidates` array (mirroring
    // the JSON-array path's assertion in
    // `test_gemini_stream_generate_content_no_alt_sse_is_json_array`), and that none leaks the
    // OpenAI `choices` shape.
    let body = resp.text().await.unwrap();
    let payloads: Vec<serde_json::Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect();
    assert!(
        !payloads.is_empty(),
        "SSE body carries at least one JSON data: frame; got {body:?}"
    );
    assert!(
        payloads.iter().any(|c| c.get("candidates").is_some()),
        "at least one SSE frame is a native gemini GenerateContentResponse (candidates[]); \
             got {body:?}"
    );
    assert!(
        payloads.iter().all(|c| c.get("choices").is_none()),
        "no OpenAI `choices` field may leak into the gemini SSE frames; got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Round-13 HIGH/test-coverage: a MID-STREAM transport failure on a gemini
/// `:streamGenerateContent?alt=sse` request (the SSE framer, `json_array=false`) must terminate
/// the body with a NATIVE Gemini SSE error frame — `text/event-stream`, a trailing `data:`
/// payload carrying a `google.rpc.Status`-shaped envelope (`error.status`), with NO `event:`
/// line (native Gemini SSE never emits one mid-stream) and NO OpenAI `choices`/
/// `chat.completion.chunk` leak. This drives `FirstByteBody`'s `Poll::Ready(Some(Err))` arm
/// with `json_array=false`, a DISTINCT code path from the JSON-array case covered by
/// `test_gemini_json_array_mid_stream_error_closes_array_no_sse`. Routes gemini→openai with
/// `SseTransportError` so the upstream drops the connection after the first frame.
#[tokio::test]
async fn test_gemini_alt_sse_mid_stream_transport_error_appends_native_sse_frame() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/foo:streamGenerateContent?alt=sse"
        ))
        .bearer_auth("t")
        .body(json!({ "contents": [{"role": "user", "parts": [{"text": "hello"}]}] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "stream starts 2xx");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "alt=sse mid-stream error stays SSE-framed; got {ct}"
    );
    let body = resp.text().await.unwrap();
    // Native Gemini SSE never emits a named `event:` line mid-stream — only bare `data:` frames.
    assert!(
        !body.contains("event:"),
        "native gemini SSE carries no `event:` line; got {body:?}"
    );
    // The body must NOT be JSON-array framed (no brackets spliced into the SSE).
    let payloads: Vec<serde_json::Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect();
    assert!(
        !payloads.is_empty(),
        "SSE body carries at least one JSON data: frame; got {body:?}"
    );
    // No OpenAI envelope may leak into the gemini SSE frames.
    assert!(
        payloads.iter().all(|p| p.get("choices").is_none()),
        "no OpenAI `choices` field may leak into the gemini SSE frames; got {body:?}"
    );
    assert!(
        !body.contains("chat.completion.chunk"),
        "no OpenAI `chat.completion.chunk` object may leak; got {body:?}"
    );
    // The LAST `data:` payload is the native Gemini `google.rpc.Status`-shaped error envelope.
    let last = payloads
        .last()
        .unwrap_or_else(|| panic!("expected a trailing SSE error frame; got {body:?}"));
    assert!(
        last.get("error").and_then(|e| e.get("status")).is_some(),
        "trailing SSE frame is a native gemini google.rpc.Status error (error.status); \
             got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Round-13 MEDIUM/security: an UNRESOLVED model on a body-model ingress (openai) must NOT stamp
/// the raw client-supplied model string as the Prometheus `pool` label — the bounded-cardinality
/// contract (metrics.rs) requires the fixed sentinel `"unresolved"`. A regression that
/// passed the raw model through `finish` would let a single credential mint unbounded time
/// series (a memory-exhaustion DoS) and leak the attacker string into `/metrics`. Drives the
/// 404 (both-maps-miss) path through the real router and scrapes the registry.
#[tokio::test]
async fn test_unresolved_model_uses_bounded_pool_label_not_raw_string() {
    crate::metrics::init();
    // A lane/pool named "foo" exists, but the client asks for a DISTINCT unknown model so both
    // `app.pools` and `app.by_model` miss and the 404 path runs.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "foo",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    // A unique, attacker-flavored model string that is NOT a configured pool/by-model key.
    let attacker_model = "zzz-unbounded-cardinality-probe-9f3a";
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(
            json!({
                "model": attacker_model,
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "unknown model is a 404");

    let scrape = crate::metrics::render();
    // The raw attacker string must NEVER appear as a label value in the exposition.
    assert!(
        !scrape.contains(attacker_model),
        "raw client model must not become a Prometheus label; got:\n{scrape}"
    );
    // The bounded sentinel must be present instead.
    assert!(
        scrape.contains("pool=\"unresolved\""),
        "unresolved model stamps the bounded `unresolved` sentinel; got:\n{scrape}"
    );
    handle.abort();
}

/// Sum every `busbar_requests_total` counter value whose label set contains BOTH the given
/// `pool="…"` and `outcome="…"` fragments, parsed straight out of the Prometheus text exposition.
/// Used by the pre-routing-observability regressions to assert a STRICT increase (the metric was
/// actually incremented) rather than mere label presence — the only signal that distinguishes the
/// fixed code (request flows through `finish`) from the old early-return (no counter at all).
fn requests_total_for(scrape: &str, pool: &str, outcome: &str) -> u64 {
    let pool_frag = format!("pool=\"{pool}\"");
    let outcome_frag = format!("outcome=\"{outcome}\"");
    scrape
        .lines()
        .filter(|l| l.starts_with(crate::metrics::REQUESTS_TOTAL))
        .filter(|l| l.contains(&pool_frag) && l.contains(&outcome_frag))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<u64>().ok())
        .sum()
}

/// MED #4 (re-audit, completeness): a JSON-parse failure on a BODY-MODEL ingress (openai) is a
/// PRE-ROUTING error — the model is never resolved. It must still flow through `finish` so it is
/// counted in `REQUESTS_TOTAL` (and the duration histogram + request-log webhook), with the
/// bounded `pool="unresolved"` label. The old code early-returned `ingress_error` directly,
/// leaving the malformed-body request invisible to Prometheus — this test asserts a STRICT
/// increase of the `unresolved`/`client_error` counter across the request, so it fails against
/// that old behavior.
#[tokio::test]
async fn test_body_model_parse_error_is_observable() {
    crate::metrics::init();
    // No backend needed: the request never gets past the body parse.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "foo",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body("{ this is not json ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "malformed body is a 400");

    let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
    assert!(
        after > before,
        "a parse-error pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
    );
    handle.abort();
}

/// The SUCCESS half of the observability contract the pre-routing regressions lock for
/// failures: ONE served 200 strictly increments `REQUESTS_TOTAL{outcome="ok"}`, the request
/// duration histogram's count, AND `UPSTREAM_ATTEMPTS_TOTAL` for the dispatched lane — all
/// under the request's own pool label (this test's pool/lane names are unique to it, so
/// parallel tests cannot contribute to the matched samples).
#[tokio::test]
async fn test_served_request_increments_hot_path_metrics() {
    use crate::test_support::metric_sum;
    const POOL: &str = "metrics-harness-pool";
    const MODEL: &str = "metrics-harness-model";

    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: openai_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(MODEL, crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool(POOL, &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let dur_count = format!("{}_count", crate::metrics::REQUEST_DURATION_SECONDS);
    let req_before = metric_sum(
        crate::metrics::REQUESTS_TOTAL,
        &[("pool", POOL), ("outcome", "ok")],
    );
    let dur_before = metric_sum(&dur_count, &[("pool", POOL)]);
    let att_before = metric_sum(
        crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
        &[("pool", POOL), ("lane", MODEL)],
    );

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .header("content-type", "application/json")
        .body(json!({"model": POOL, "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let req_after = metric_sum(
        crate::metrics::REQUESTS_TOTAL,
        &[("pool", POOL), ("outcome", "ok")],
    );
    let dur_after = metric_sum(&dur_count, &[("pool", POOL)]);
    let att_after = metric_sum(
        crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
        &[("pool", POOL), ("lane", MODEL)],
    );
    assert!(
        req_after > req_before,
        "a served 200 must increment REQUESTS_TOTAL(outcome=ok): {req_before} -> {req_after}"
    );
    assert!(
        dur_after > dur_before,
        "a served 200 must observe the duration histogram: {dur_before} -> {dur_after}"
    );
    assert!(
        att_after > att_before,
        "a served 200 must count its upstream attempt: {att_before} -> {att_after}"
    );
    handle.abort();
    server.shutdown().await;
}

/// THE GOVERNANCE RE-KEY end-to-end (§2.3): with governance ON and an external data-plane
/// module in the chain, a role-bound principal gets a SYNTHESIZED key - its binding's pool ACL
/// admits/denies (403), an omitted `allowed_pools` grants ALL pools (C6), an explicit `[]`
/// grants nothing, and an unbound role is rejected outright (fail closed) - all keyed by the
/// principal id through the same machinery a virtual key uses. (Rate/budget caps no longer ride
/// the synthesized key: limits live on `groups:`, keys are pure auth.)
#[tokio::test]
async fn test_role_bound_principal_governed_like_a_virtual_key() {
    use crate::governance::{GovState, MemoryStore};
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    for _ in 0..3 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: openai_ok_body(),
        });
    }
    let server = MockServer::new(state.clone()).await;
    let store = StdArc::new(MemoryStore::new());
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let auth_cfg = crate::config::AuthCfg {
        chain: vec![crate::config::AuthChainEntry::bare("test-groups-module")],
        ..crate::config::AuthCfg::default_none()
    };
    let mut app = TestApp::new()
        .lane(
            LaneSpec::new(
                "rekey-model",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("gpool-a", &[(0, 1)])
        .pool("gpool-b", &[(0, 1)])
        .auth(StdArc::new(crate::auth::AuthMiddleware::new(&auth_cfg)))
        .governance(gov)
        // The old GovState carried fee 0; keep the no-charge semantics under the CostModel.
        .cost(crate::cost::CostModel::flat(0))
        .build();
    {
        let inner = StdArc::get_mut(&mut app).expect("sole owner");
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "llm-users".to_string(),
            crate::config::RoleBindingCfg {
                allowed_pools: Some(vec!["gpool-a".to_string()]),
                ..Default::default()
            },
        );
        // OMITTED allowed_pools = ALL pools (C6).
        table.insert(
            "batch".to_string(),
            crate::config::RoleBindingCfg::default(),
        );
        // Explicit [] = NO pools (the empty set, fail closed).
        table.insert(
            "locked".to_string(),
            crate::config::RoleBindingCfg {
                allowed_pools: Some(vec![]),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-groups-module".to_string(), table);
    }
    let (addr, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let send = |tok: &'static str, model: &'static str| {
        client
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth(tok)
            .header("content-type", "application/json")
            .body(
                json!({"model": model, "messages": [{"role": "user", "content": "hi"}]})
                    .to_string(),
            )
            .send()
    };

    // Pool ACL from the role binding: gpool-a serves, gpool-b is denied.
    let r = send("grp:llm-users", "gpool-a").await.unwrap();
    assert_eq!(r.status().as_u16(), 200, "granted pool serves");
    let r = send("grp:llm-users", "gpool-b").await.unwrap();
    assert_eq!(r.status().as_u16(), 403, "ungranted pool is denied");

    // OMITTED allowed_pools grants every pool (C6).
    let r = send("grp:batch", "gpool-a").await.unwrap();
    assert_eq!(r.status().as_u16(), 200, "omitted allowed_pools grants all");
    let r = send("grp:batch", "gpool-b").await.unwrap();
    assert_eq!(r.status().as_u16(), 200, "omitted allowed_pools grants all");

    // Explicit [] grants the EMPTY SET: no data-plane access at all.
    let r = send("grp:locked", "gpool-a").await.unwrap();
    assert_eq!(r.status().as_u16(), 401, "allowed_pools [] grants nothing");

    // Fail closed: an identified principal whose roles earn no binding is rejected.
    let r = send("grp:strangers", "gpool-a").await.unwrap();
    assert_eq!(r.status().as_u16(), 401, "unbound roles grant nothing");

    handle.abort();
    server.shutdown().await;
}

/// CI TIMING GATE (ignored by default; CI runs it explicitly in release mode). Serves warm-up
/// plus a measured batch through the REAL router against an instant in-process mock upstream
/// and gates the measured p50/p99 full-request latency under DELIBERATELY GENEROUS bounds —
/// busbar's real added overhead is microseconds, so these only trip on a GROSS hot-path
/// regression (accidental sync I/O, a stray sleep, an O(n²) body walk), never on runner noise.
/// Fine-grained overhead numbers stay the latency bench's job (the external
/// GetBusbar/benchmarking harness).
#[tokio::test]
#[ignore = "timing gate — run explicitly (CI: cargo test --release -- --ignored timing_gate)"]
async fn timing_gate_hot_path_p50_p99() {
    const WARMUP: usize = 100;
    const MEASURED: usize = 500;
    const P50_MAX_MS: u128 = 25;
    const P99_MAX_MS: u128 = 250;

    let state = StdArc::new(MockServerState::new());
    // One queued response per request (warm-up + measured), instant upstream.
    for _ in 0..(WARMUP + MEASURED) {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: openai_ok_body(),
        });
    }
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "timing-gate-model",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("timing-gate-pool", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/chat/completions");
    let body =
        json!({"model": "timing-gate-pool", "messages": [{"role": "user", "content": "hi"}]})
            .to_string();

    let mut samples: Vec<u128> = Vec::with_capacity(MEASURED);
    for i in 0..(WARMUP + MEASURED) {
        let start = std::time::Instant::now();
        let resp = client
            .post(&url)
            .bearer_auth("t")
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let _ = resp.bytes().await.unwrap();
        assert_eq!(
            status, 200,
            "request {i} failed — the gate measures 200s only"
        );
        if i >= WARMUP {
            samples.push(start.elapsed().as_millis());
        }
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    assert!(
        p50 <= P50_MAX_MS,
        "hot-path p50 {p50}ms exceeded the {P50_MAX_MS}ms gate — a gross regression \
             (the real overhead is microseconds; check for sync I/O / sleeps on the request path)"
    );
    assert!(
        p99 <= P99_MAX_MS,
        "hot-path p99 {p99}ms exceeded the {P99_MAX_MS}ms gate — a gross regression"
    );
    handle.abort();
    server.shutdown().await;
}

/// MED #4 (re-audit, completeness): a MISSING `model` field on a body-model ingress is likewise a
/// pre-routing failure and must flow through `finish` (bounded `pool="unresolved"`), not a silent
/// early-return. Asserts a strict counter increase, so it fails against the old early-return.
#[tokio::test]
async fn test_body_model_missing_model_is_observable() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "foo",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        // Valid JSON object, but no `model`.
        .body(json!({"messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "missing model is a 400");

    let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
    assert!(
        after > before,
        "a missing-model pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
    );
    handle.abort();
}

/// MED #4 (re-audit, completeness): a NON-OBJECT body on a PATH-MODEL ingress (bedrock) is a
/// pre-routing failure (`v.as_object_mut()` is `None`) and must flow through `finish` with the
/// bounded `pool="unresolved"` label. Asserts a strict counter increase; fails against the old
/// early-return that bypassed `finish`.
#[tokio::test]
async fn test_path_model_non_object_body_is_observable() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "foo",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

    // Valid JSON, but a top-level ARRAY (not an object) — `as_object_mut` returns `None`.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth("t")
        .body(json!([1, 2, 3]).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "non-object body is a 400");

    let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
    assert!(
        after > before,
        "a non-object-body pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
    );
    handle.abort();
}

/// MED #4 (re-audit, completeness — sibling sweep): an UNSUPPORTED gemini action (e.g.
/// `:countTokens`) rejected in `gemini_ingress` BEFORE `ingress_path_model` runs is the same
/// pre-routing observability blind spot. It must now flow through `finish` (bounded
/// `pool="unresolved"`, gemini protocol). Asserts a strict counter increase; fails against the
/// old early-return.
#[tokio::test]
async fn test_gemini_unsupported_action_is_observable() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "foo",
                crate::proto::Protocol::openai(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

    // `:countTokens` is a genuine Gemini action suffix (so the path stays gemini-classified) but
    // is NOT one of the two proxied generate actions → unsupported-action 404 in gemini_ingress.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:countTokens"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "unsupported gemini action is a 404"
    );

    let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
    assert!(
        after > before,
        "an unsupported-action pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
    );
    handle.abort();
}

/// Round-13 MEDIUM/security (unit test for `pool_label`): the bounded-label mapper returns a
/// model verbatim ONLY when it names a configured pool or by-model lane, and the fixed sentinel
/// `"unresolved"` for anything else.
#[test]
fn test_pool_label_bounds_cardinality() {
    let mut app = minimal_app();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.pools.insert(
            "mypool".to_string(),
            vec![WeightedLane {
                reasoning: None,
                idx: 0,
                weight: 1,
                attempt_timeout_ms: None,
            }],
        );
        inner.by_model.insert("mymodel".to_string(), 0);
    }
    // Configured pool name → verbatim.
    assert_eq!(pool_label(&app, "mypool"), "mypool");
    // Configured by-model lane → verbatim.
    assert_eq!(pool_label(&app, "mymodel"), "mymodel");
    // Unknown / attacker-controlled string → bounded sentinel.
    assert_eq!(pool_label(&app, "anything-else"), "unresolved"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(pool_label(&app, ""), "unresolved"); // golden wire-contract literal (kept bare on purpose)
}

/// HIGH/conformance: a native gemini `:streamGenerateContent` request WITHOUT `?alt=sse` must
/// receive the JSON-ARRAY streaming format (`Content-Type: application/json`, a `[{...},{...}]`
/// body), NOT SSE. Routes gemini→openai (cross-protocol) so the upstream SSE is reframed to
/// gemini SSE by `StreamTranslate` and then to a JSON array by the framer; the body must parse
/// as a JSON array whose elements are gemini `GenerateContentResponse` objects.
#[tokio::test]
async fn test_gemini_stream_generate_content_no_alt_sse_is_json_array() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/foo:streamGenerateContent"
        ))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "no-alt=sse stream 2xx");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "gemini streaming ingress WITHOUT ?alt=sse is JSON-array framed; got {ct}"
    );
    let body = resp.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("JSON-array body must parse; got {body:?} ({e})"));
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("body must be a JSON array; got {body:?}"));
    assert!(
        !arr.is_empty(),
        "array carries at least one chunk; got {body:?}"
    );
    // Each element is a gemini GenerateContentResponse (has `candidates`).
    assert!(
        arr.iter().any(|c| c.get("candidates").is_some()),
        "at least one chunk is a gemini GenerateContentResponse; got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Round-4 HIGH/correctness: a MID-STREAM transport failure on a gemini `:streamGenerateContent`
/// request WITHOUT `?alt=sse` (the JSON-array framer is engaged) must terminate the body as a
/// VALID JSON array — a trailing gemini-shaped error element + closing `]` — NOT raw SSE
/// `event:`/`data:` text spliced into the array (the bug: `mid_stream_error_bytes` bypassed the
/// framer, yielding an unparseable body and a protocol tell). Routes gemini→openai with
/// `SseTransportError` so the upstream drops the connection after the first frame, driving
/// `FirstByteBody`'s `Poll::Ready(Some(Err))` arm while `json_array` is active.
#[tokio::test]
async fn test_gemini_json_array_mid_stream_error_closes_array_no_sse() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/foo:streamGenerateContent"
        ))
        .bearer_auth("t")
        .body(json!({ "contents": [{"role": "user", "parts": [{"text": "hello"}]}] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "stream starts 2xx");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "JSON-array framed; got {ct}"
    );
    let body = resp.text().await.unwrap();
    // The whole body must still be a VALID JSON array (closing `]` present).
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        panic!("mid-stream-error JSON-array body must still parse as JSON; got {body:?} ({e})")
    });
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("body must be a JSON array; got {body:?}"));
    // No SSE framing anywhere — a native gemini JSON-array stream never contains `event:`/`data:`.
    assert!(
        !body.contains("event:") && !body.contains("data:"),
        "JSON-array error body must NOT contain SSE text; got {body:?}"
    );
    // The trailing element is the gemini-shaped `google.rpc.Status` error.
    assert!(
        arr.iter()
            .any(|el| el.get("error").and_then(|e| e.get("status")).is_some()),
        "array must carry a trailing gemini error element; got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Round-4 HIGH/conformance (UPDATED R9): the router-internal `__busbar_gemini_json_array` shim
/// must NEVER reach a CROSS-protocol backend. Routes gemini `:streamGenerateContent` (no
/// `?alt=sse`) → an OpenAI backend and asserts the upstream-received body carries no array shim
/// key (the bug: the gemini reader swept it into IR `extra` and the egress writer re-emitted the
/// router fingerprint onto the foreign backend).
///
/// R9 HIGH (proxy engine) correction: the egress `stream` field is NOT a router fingerprint
/// for a BODY-MODEL backend — the OpenAI writer AUTHORS `"stream": ir.stream` and the backend
/// reads it to decide whether to stream. The client called `:streamGenerateContent`, so it
/// genuinely wants streaming; `stream: true` MUST reach the OpenAI backend, otherwise the backend
/// answers non-streaming and the gemini client gets a wrong (buffered) response. The shim-key
/// strip is now gated on the EGRESS protocol, so `stream` survives for body-model egress and is
/// stripped only for path-model (gemini/bedrock) egress where it rides the URL.
#[tokio::test]
async fn test_gemini_json_array_shim_not_leaked_cross_protocol() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/foo:streamGenerateContent"
        ))
        .bearer_auth("t")
        .body(json!({ "contents": [{"role": "user", "parts": [{"text": "hello"}]}] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    // Drain the body so the upstream request fully completes and its body is recorded.
    let _ = resp.bytes().await.unwrap();

    let upstream = state
        .get_last_request_body()
        .expect("upstream received a body");
    let upstream_v: serde_json::Value =
        serde_json::from_slice(&upstream).expect("upstream body is JSON");
    assert!(
        upstream_v.get("__busbar_gemini_json_array").is_none(),
        "router shim key must not leak to a foreign backend; got {upstream_v}"
    );
    // R9 HIGH (proxy engine): the writer-authored `stream` MUST reach a body-model (OpenAI)
    // backend so it actually streams — the client called `:streamGenerateContent`. Stripping it
    // here was the bug that made the backend answer non-streaming.
    assert_eq!(
            upstream_v.get("stream").and_then(|s| s.as_bool()),
            Some(true),
            "writer-authored `stream: true` MUST reach the body-model backend so it streams; got {upstream_v}"
        );
    handle.abort();
    server.shutdown().await;
}

/// Round-4 HIGH/conformance: a CROSS-protocol stream to an Anthropic-SDK client must emit a FULL
/// `message_start` skeleton — `id` (msg_-prefixed), `type:"message"`, `content:[]`,
/// `stop_reason`/`stop_sequence` (null) — not the degenerate `{role,usage}` the
/// `has_identity`-gated writer produced once `StreamTranslate` stripped the foreign id/model.
/// Routes openai→anthropic and inspects the first `message_start` SSE frame.
#[tokio::test]
async fn test_anthropic_cross_protocol_message_start_full_skeleton() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    // Anthropic ingress → OpenAI backend (cross-protocol): StreamTranslate reframes the upstream
    // OpenAI SSE into Anthropic SSE via the writer's `write_response_event`.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/foo/v1/messages"))
        .bearer_auth("t")
        .body(
            json!({ "model": "foo", "stream": true, "messages": [], "max_tokens": 16 }).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    // Extract the `message_start` event's `data:` JSON.
    let ms_data = body
        .split("\n\n")
        .find(|f| f.contains("event: message_start"))
        .and_then(|f| f.lines().find(|l| l.starts_with("data: ")))
        .map(|l| l.trim_start_matches("data: ").to_string())
        .unwrap_or_else(|| panic!("no message_start event in stream; got {body:?}"));
    let ev: serde_json::Value = serde_json::from_str(&ms_data).expect("message_start data parses");
    let msg = ev.get("message").expect("message object");
    assert!(
        msg.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .starts_with("msg_"),
        "message_start.message.id must be a synthesized msg_ id; got {msg}"
    );
    assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
    assert!(
        msg.get("content").and_then(|c| c.as_array()).is_some(),
        "content[] must be present; got {msg}"
    );
    assert!(
        msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false),
        "stop_reason must be present (null); got {msg}"
    );
    assert!(
        msg.get("stop_sequence")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "stop_sequence must be present (null); got {msg}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Round-4 HIGH/conformance: a CROSS-protocol passthrough 401 must be RESHAPED into the ingress
/// protocol's native error envelope, not relayed verbatim from the egress provider. Anthropic
/// ingress → OpenAI backend that 401s in Passthrough mode: the client must see the Anthropic error
/// shape (`{"type":"error","error":{"type":...}}`), not the OpenAI `{"error":{...}}` shape.
#[tokio::test]
async fn test_passthrough_401_cross_protocol_reshaped_to_ingress() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Auth {
        status: StatusCode::UNAUTHORIZED,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .upstream_creds(crate::auth::UpstreamCreds::Passthrough)
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/foo/v1/messages"))
        .bearer_auth("caller-token")
        .body(json!({ "model": "foo", "messages": [], "max_tokens": 16 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        401,
        "passthrough 401 status relayed"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    // Anthropic native error envelope: top-level `type:"error"` and `error.type`.
    assert_eq!(
        body.get("type").and_then(|v| v.as_str()),
        Some("error"),
        "cross-protocol 401 must be reshaped to the Anthropic error envelope; got {body}"
    );
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|v| v.as_str()),
        Some("authentication_error"), // golden wire-contract literal (kept bare on purpose)
        "401 maps to authentication_error in the ingress envelope; got {body}"
    );
    handle.abort();
    server.shutdown().await;
}

/// MEDIUM/test-coverage: a Gemini path with NO colon (`/v1beta/models/gemini-flash`) hits the
/// malformed-path branch and must return a Gemini-shaped 404 (not a 200, not a panic).
#[tokio::test]
async fn test_gemini_malformed_path_no_colon_is_404() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/gemini-flash"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "gemini path with no colon ⇒ native 404"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "gemini error envelope is JSON; got {ct}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage: an EMPTY model (`/v1beta/models/:generateContent`) is malformed (the
/// pre-colon segment is empty) and must return a Gemini-shaped 404, not misroute.
#[tokio::test]
async fn test_gemini_empty_model_is_404() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/:generateContent"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "gemini empty model ⇒ native 404"
    );
    handle.abort();
}

/// MEDIUM/conformance regression: a request on the STABLE `/v1/models/...` Gemini surface that
/// hits an unsupported action (e.g. `countTokens`) must echo "v1" in the native NOT_FOUND
/// message — NOT the hardcoded "v1beta". The real Gemini v1 API says "v1" for this path; leaking
/// "v1beta" is a distinguishability tell against a google-generativeai SDK pinned to v1.
#[tokio::test]
async fn test_gemini_v1_surface_error_echoes_v1_not_v1beta() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;

    // Unsupported-action branch on the v1 surface.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/models/foo:countTokens"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "unsupported action ⇒ 404");
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("API version v1,") || msg.contains("API version v1 "),
        "v1-surface error must echo 'v1', not 'v1beta'; got message: {msg}"
    );
    assert!(
        !msg.contains("v1beta"),
        "v1-surface error must NOT leak 'v1beta'; got message: {msg}"
    );

    // No-colon branch on the v1 surface: a colon-less `/v1/models/{id}` is the OpenAI
    // `model.retrieve` shape on this AMBIGUOUS stable prefix, so the MEDIUM/conformance fix
    // returns the canonical OpenAI `not_found_error` envelope here (matching `proto_for_path`
    // and the method fallback), NOT a Gemini-shaped NOT_FOUND. (The Gemini-shaped no-colon 404
    // is reserved for the unambiguous `/v1beta/...` surface — see
    // `test_gemini_v1beta_surface_error_still_echoes_v1beta`.) The v1-version-echo coverage is
    // carried by the unsupported-ACTION (`countTokens`) case above, which stays Gemini-shaped.
    let resp2 = reqwest::Client::new()
        .post(format!("http://{addr}/v1/models/gemini-flash"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 404, "no-colon v1 path ⇒ 404");
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(
        body2
            .get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
        "colon-less /v1/models/{{id}} returns the canonical OpenAI not_found_error envelope, \
             not a Gemini NOT_FOUND; got {body2}"
    );

    handle.abort();
}

/// The `/v1beta/models/...` surface must still echo "v1beta" (no regression for the historical
/// full surface) — the fix is version-faithful, not a blanket rewrite.
#[tokio::test]
async fn test_gemini_v1beta_surface_error_still_echoes_v1beta() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:countTokens"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("v1beta"),
        "v1beta-surface error must still echo 'v1beta'; got: {msg}"
    );
    handle.abort();
}

/// MEDIUM/conformance regression: the AMBIGUOUS stable `/v1/models/{id}` prefix is SHARED between
/// the Gemini `:<action>` surface and the OpenAI `model.retrieve` (`/v1/models/{id}`) surface.
/// A colon-less `/v1/models/{id}` (or a `/v1/models/{id}` whose colons are NOT a Gemini action
/// suffix, e.g. an OpenAI fine-tune id `ft:gpt:org::abc`) must therefore return the canonical
/// OpenAI `not_found_error` envelope — the SAME shape the method/fallback handler emits for the
/// path — rather than a Gemini-shaped NOT_FOUND, so a client probing GET vs POST on
/// `/v1/models/{id}` cannot distinguish busbar by a divergent error shape. The unambiguous
/// `/v1beta/...` surface (Gemini-only; OpenAI has no v1beta) stays Gemini-shaped. This locks the
/// `gemini_ingress` no-colon branch's delegation to `proto::proto_for_path`.
#[tokio::test]
async fn test_gemini_v1_no_action_returns_openai_shaped_404() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;

    // (a) Colon-less stable `/v1/models/{id}` ⇒ OpenAI `not_found_error` (the model.retrieve
    // surface), NOT a Gemini NOT_FOUND.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/models/gpt-4o"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "no-action /v1/models/{{id}} ⇒ 404"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "OpenAI not-found envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
        "colon-less /v1/models/{{id}} returns the OpenAI not_found_error envelope; got {body}"
    );
    // A Gemini NOT_FOUND would carry a `status: NOT_FOUND` field; the OpenAI envelope does not.
    assert!(
        body.get("error").and_then(|e| e.get("status")).is_none(),
        "OpenAI not-found envelope has no Gemini-style `status`; got {body}"
    );

    // (b) An OpenAI fine-tune id whose segment CONTAINS colons but NO Gemini action suffix is
    // still the OpenAI surface (the action split would otherwise mis-read `:abc` as the action).
    let resp_ft = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/models/ft:gpt-3.5-turbo:my-org::abc"
        ))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_ft.status().as_u16(),
        404,
        "fine-tune id (no action) ⇒ 404"
    );
    let body_ft: serde_json::Value = resp_ft.json().await.unwrap();
    assert_eq!(
            body_ft
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
            "colon-bearing OpenAI fine-tune id (no Gemini action) ⇒ OpenAI not_found_error; got {body_ft}"
        );

    // (c) The unambiguous `/v1beta/...` surface (Gemini-only) keeps the Gemini NOT_FOUND shape
    // for a colon-less path: its envelope carries the Gemini `status: NOT_FOUND`.
    let resp_beta = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/gemini-flash"))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_beta.status().as_u16(), 404, "v1beta no-colon ⇒ 404");
    let body_beta: serde_json::Value = resp_beta.json().await.unwrap();
    assert_eq!(
        body_beta
            .get("error")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.as_str()),
        Some("NOT_FOUND"),
        "v1beta no-colon path stays Gemini-shaped (status: NOT_FOUND); got {body_beta}"
    );

    handle.abort();
}

/// Unit: `gemini_api_version` maps each ingress prefix to the token the native error echoes.
#[test]
fn test_gemini_api_version_prefix_mapping() {
    assert_eq!(
        gemini_api_version("/v1/models/foo:countTokens"),
        "v1",
        "stable surface ⇒ v1"
    );
    assert_eq!(
        gemini_api_version("/v1beta/models/foo:countTokens"),
        "v1beta",
        "beta surface ⇒ v1beta"
    );
    // Unexpected shape falls back to the historical default.
    assert_eq!(
        gemini_api_version("/weird/path"),
        "v1beta",
        "fallback ⇒ v1beta"
    );
}

/// MEDIUM/test-coverage: a model id that itself CONTAINS a colon must split on the LAST colon, so
/// `tunedModels/abc:1:generateContent` resolves model `tunedModels/abc:1` (not the action). The
/// lane is named with the colon-bearing id so a correct LAST-colon split is the only way it
/// resolves and 2xx round-trips.
#[tokio::test]
async fn test_gemini_model_with_colon_splits_on_last_colon() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: openai_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "tunedModels/abc:1",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("tunedModels/abc:1", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/tunedModels/abc:1:generateContent"
        ))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "colon-bearing model id splits on the LAST colon and resolves"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- percent_decode unit tests (MEDIUM/test-coverage) ----

/// `%3A` decodes to a literal colon.
#[test]
fn test_percent_decode_colon() {
    assert_eq!(percent_decode("%3A"), ":");
    assert_eq!(
        percent_decode("anthropic.claude-3%3A0"),
        "anthropic.claude-3:0"
    );
}

/// `%2E` decodes to a literal period, and an undecoded id passes through unchanged.
#[test]
fn test_percent_decode_period_and_plain() {
    assert_eq!(percent_decode("a%2Eb"), "a.b");
    assert_eq!(
        percent_decode("anthropic.claude-3-sonnet"),
        "anthropic.claude-3-sonnet"
    );
}

/// A malformed escape (`%` followed by non-hex digits) is left verbatim rather than dropped or
/// panicking.
#[test]
fn test_percent_decode_malformed_escape_passes_through() {
    assert_eq!(percent_decode("%XY"), "%XY");
    assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
}

/// A trailing `%` (or a `%` with too few following bytes) at end-of-string is safe — no
/// out-of-bounds index, the bytes pass through.
#[test]
fn test_percent_decode_trailing_percent_is_safe() {
    assert_eq!(percent_decode("abc%"), "abc%");
    assert_eq!(percent_decode("abc%3"), "abc%3");
}

/// LOW/conformance regression: a 404 from `forward_resolved` (unknown model) carries the
/// canonical `not_found_error` type for an OpenAI-ingress client, not the old non-canonical
/// `not_found`. Drives the real router so the body-model ingress → resolution-miss path runs.
#[tokio::test]
async fn test_unknown_model_404_uses_canonical_openai_type() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({"model": "no-such-model", "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "unknown model ⇒ 404");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
        "404 carries the canonical OpenAI not_found_error type; got {body}"
    );
    handle.abort();
}

// ---- MEDIUM/correctness: governance-rejection requests must still be `finish`ed ----

/// Build a governance-enabled App whose only key is allowed ONLY on pool `allowed-only` (so a
/// request to any other pool is pool-rejected with 403). Returns the key for the GovCtx.
fn governed_app_pool_restricted() -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "restricted".to_string(),
                allowed_pools: Some(vec!["allowed-only".to_string()]),
                group: None,
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    // The 30c flat fee lives on the CostModel now.
    inner.cost = std::sync::Arc::new(crate::cost::CostModel::flat(30));
    (app, key)
}

/// A pool-authorization rejection (403) must flow through `finish`, so it is counted in
/// `REQUESTS_TOTAL` (as `outcome=client_error`) and the duration histogram — not silently
/// early-returned. Regression for the Round-3 finding that governance rejections bypassed
/// `finish` and were invisible to Prometheus / the request-log webhook.
#[tokio::test]
async fn test_governance_rejection_is_counted_via_finish() {
    crate::metrics::init();
    let (app, key) = governed_app_pool_restricted();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };

    // Request a pool the key is NOT allowed on → 403, and the guard returns Err(response).
    let rejected = governance_guard(
        &app,
        &gov,
        "openai",
        "denied-pool",
        Instant::now(),
        crate::store::now(),
    )
    .expect_err("a disallowed pool must be rejected by the governance guard");
    assert_eq!(
        rejected.status(),
        StatusCode::FORBIDDEN,
        "pool-not-allowed ⇒ 403"
    );

    // The rejection went through `finish`: a client_error outcome is now in the scrape.
    let scrape = crate::metrics::render();
    assert!(
        scrape.contains(crate::metrics::REQUESTS_TOTAL),
        "governance rejection still emits requests_total; got:\n{scrape}"
    );
    assert!(
        scrape.contains("outcome=\"client_error\""),
        "a 403 governance rejection maps to outcome=client_error; got:\n{scrape}"
    );
    assert!(
        scrape.contains(crate::metrics::REQUEST_DURATION_SECONDS),
        "governance rejection still emits the duration histogram; got:\n{scrape}"
    );

    // No flat fee is charged for a rejected (non-2xx) request.
    assert_eq!(
        key_spend(&app, &key.id),
        0,
        "a governance-rejected request charges no flat fee"
    );
}

/// When the key is allowed on the requested pool (and within budget/rate), the guard returns
/// `None` so the caller proceeds to resolve+forward.
#[tokio::test]
async fn test_governance_guard_passes_when_allowed() {
    crate::metrics::init();
    let (app, key) = governed_app_pool_restricted();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let passed = governance_guard(
        &app,
        &gov,
        "openai",
        "allowed-only",
        Instant::now(),
        crate::store::now(),
    );
    assert!(
        matches!(passed, Ok((Some(_), _))),
        "an allowed, in-limits request is admitted AND charged (Ok(Some(grant)))"
    );
}

/// REGRESSION (audit c2r1): a request ADMITTED WITHOUT a charge (store-error fail-open) that then
/// gets a non-2xx must NOT refund — `refund_request` is a blind decrement that would erode a
/// DIFFERENT, legitimately-charged request's spend/count in the same window. `finish_admitted`
/// gates the refund on the `charged` flag from `governance_guard`.
#[tokio::test]
async fn finish_admitted_does_not_refund_an_uncharged_admit() {
    crate::metrics::init();
    let (app, key) = governed_app_pool_restricted();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let at = 1_700_000_000;
    // A PRIOR legitimate request charges the flat fee (price=30) into this window.
    let g = app.governance.as_ref().unwrap();
    assert!(g.try_admit(&app.cost, &key, "", at).is_ok());
    let charged_spend = key_spend(&app, &key.id);
    assert_eq!(charged_spend, 30, "prior request charged the flat fee");

    // A SECOND request admitted WITHOUT charge (charged=false) then fails (non-2xx). The refund
    // path must never even be entered (`refund_on_non_2xx` is false), so the first request's
    // spend is DETERMINISTICALLY untouched — no blind decrement. (The positive charged=true
    // refund is offloaded/async and is covered by the flat-fee refund tests.)
    let non2xx = (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    let out = finish_admitted(
        &app,
        &gov,
        "openai",
        "allowed-only",
        Instant::now(),
        at,
        non2xx,
        false,
    );
    assert_eq!(out.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        key_spend(&app, &key.id),
        30,
        "an uncharged admit must not refund — the prior request's spend is untouched"
    );
}

/// Read a `Response`'s full body into a String (test helper for asserting error-envelope copy).
async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// MEDIUM/security regression: the three governance rejection bodies (403 pool-not-allowed, 429
/// over-budget (400 for Bedrock), 429 rate-limited) must carry ONLY vendor-plausible copy — never the internal
/// `virtual key` vocabulary, never the key id, never the pool name. A native vendor SDK parses
/// these envelopes; leaking the key id / pool topology is both a proxy tell and an info leak.
#[tokio::test]
async fn test_governance_rejection_bodies_leak_no_internal_vocab() {
    crate::metrics::init();

    // --- 403: pool not allowed ---
    let (app, key) = governed_app_pool_restricted();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let resp =
        pool_authorized(&gov, "denied-pool", "openai").expect("disallowed pool ⇒ 403 response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_string(resp).await;
    assert_leak_free(&body, &key.id, "denied-pool");

    // --- over budget. A key with a zero budget cap is immediately over budget. The
    // body-model protocols surface this as 429 (native OpenAI/Gemini quota semantics); no
    // vendor returns 402 here. ---
    let (app2, key2) = governed_app_over_budget();
    let gov2 = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key2.clone())),
    };
    let resp = admit_check(&app2, &gov2, "openai", "", crate::store::now())
        .expect_err("a zero-budget group ⇒ over-budget response");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = body_string(*resp).await;
    assert_leak_free(&body, &key2.id, "any-pool");

    // Bedrock ingress maps the same over-budget condition to a 400-class
    // ServiceQuotaExceededException (the native AWS shape), NOT 429.
    let (app2b, key2b) = governed_app_over_budget();
    let gov2b = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key2b.clone())),
    };
    let resp = admit_check(&app2b, &gov2b, "bedrock", "", crate::store::now())
        .expect_err("a zero-budget group ⇒ over-budget response (bedrock)");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(*resp).await;
    assert!(
        body.contains("ServiceQuotaExceededException"),
        "bedrock over-budget body carries native quota exception: {body}"
    );
    assert_leak_free(&body, &key2b.id, "any-pool");
    let _ = &app2b;

    // --- 429: rate limited. A group with `requests: 0, per: minute` blocks the first request. ---
    let (app3, key3) = governed_app_rate_limited();
    let gov3 = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key3.clone())),
    };
    let resp = admit_check(&app3, &gov3, "openai", "", crate::store::now())
        .expect_err("requests=0 group ⇒ 429 response");
    let resp = *resp;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    // The Retry-After header must still be present (regression: copy change must not drop it).
    assert!(
        resp.headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_some(),
        "429 still carries Retry-After"
    );
    let body = body_string(resp).await;
    assert_leak_free(&body, &key3.id, "any-pool");

    // Silence unused-binding warnings for the apps held only to keep gov state alive.
    let _ = (&app, &app2, &app3);
}

/// Assert a client-facing error body contains none of the operator-internal identifiers or
/// governance vocabulary.
fn assert_leak_free(body: &str, key_id: &str, pool: &str) {
    assert!(
        !body.contains("virtual key"),
        "error body must not contain the 'virtual key' vocabulary; got: {body}"
    );
    assert!(
        !body.contains(key_id),
        "error body must not contain the internal key id '{key_id}'; got: {body}"
    );
    assert!(
        !body.contains(pool),
        "error body must not contain the pool name '{pool}'; got: {body}"
    );
    assert!(
        !body.to_lowercase().contains("busbar"),
        "error body must not contain the product name; got: {body}"
    );
}

/// Governance-enabled App whose only key has a zero budget cap, so it is immediately over budget.
fn governed_app_over_budget() -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "broke".to_string(),
                allowed_pools: None,
                group: Some("empty".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    // A ZERO-cap GROUP budget: the very first request is over budget (keys carry no caps).
    let groups = std::collections::BTreeMap::from([(
        "empty".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 0,
                per: Some(crate::config::groups::LimitWindow::Total),
                pool: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    inner.cost = std::sync::Arc::new(crate::cost::CostModel::resolve_parts(None, 30, &groups));
    (app, key)
}

/// Governance-enabled App whose key binds to a group with `{ requests: 0, per: minute }`, so the
/// first request is rate-limited (keys carry no caps; the group is the limiter).
fn governed_app_rate_limited() -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "throttled".to_string(),
                allowed_pools: None,
                group: Some("closed".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    let groups = std::collections::BTreeMap::from([(
        "closed".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Requests,
                amount: 0,
                per: Some(crate::config::groups::LimitWindow::Minute),
                pool: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    inner.cost = std::sync::Arc::new(crate::cost::CostModel::resolve_parts(None, 30, &groups));
    (app, key)
}

// ---- MEDIUM/conformance: bedrock ingress errors carry the x-amzn-* native headers ----

/// `ingress_error("bedrock", ...)` must attach `x-amzn-RequestId` (a UUID-shaped value) and
/// `x-amzn-errortype` (equal to the body `__type`), matching what a real AWS Bedrock runtime
/// error response always carries. Regression for the finding that busbar-synthesized Bedrock
/// errors had no `x-amzn-*` headers and left the SDK's request id empty.
#[test]
fn test_bedrock_ingress_error_has_amzn_headers() {
    let resp = ingress_error(
        "bedrock",
        StatusCode::NOT_FOUND,
        crate::proxy::KIND_NOT_FOUND,
        "The model 'x' does not exist or you do not have access to it.",
    );
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock error carries x-amzn-RequestId");
    // UUID-v4 shape: 8-4-4-4-12 lowercase hex.
    let segs: Vec<&str> = req_id.split('-').collect();
    assert_eq!(segs.len(), 5, "request id is dash-grouped: {req_id}");
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "request id is UUID-shaped: {req_id}"
    );
    assert!(
        req_id
            .chars()
            .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
        "request id is lowercase hex: {req_id}"
    );
    let errortype = resp
        .headers()
        .get("x-amzn-errortype")
        .and_then(|h| h.to_str().ok())
        .expect("bedrock error carries x-amzn-errortype");
    assert_eq!(
        errortype, "ResourceNotFoundException",
        "x-amzn-errortype maps not_found_error → ResourceNotFoundException"
    );
}

/// The `x-amzn-errortype` header must agree with the body `__type` for the kinds this router
/// emits, and a NON-bedrock protocol must NOT get the `x-amzn-*` headers (they are a Bedrock
/// tell only).
#[test]
fn test_bedrock_errortype_header_matches_body_and_others_omit() {
    for (kind, status, expected) in [
        (
            crate::proxy::KIND_INVALID_REQUEST,
            StatusCode::BAD_REQUEST,
            "ValidationException",
        ),
        (
            crate::proxy::KIND_RATE_LIMIT,
            StatusCode::TOO_MANY_REQUESTS,
            "ThrottlingException",
        ),
        (
            crate::proxy::KIND_PERMISSION,
            StatusCode::FORBIDDEN,
            "AccessDeniedException",
        ),
        (
            crate::proxy::KIND_INSUFFICIENT_QUOTA,
            StatusCode::BAD_REQUEST,
            "ServiceQuotaExceededException",
        ),
    ] {
        let resp = ingress_error("bedrock", status, kind, "m");
        let hdr = resp
            .headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert_eq!(hdr, expected, "x-amzn-errortype for kind {kind}");
        assert_eq!(
            crate::proto::bedrock::error_kind_to_bedrock_type(kind),
            expected,
            "header mapping for {kind}"
        );
    }
    // An OpenAI-ingress error must not carry the Bedrock-only headers.
    let openai = ingress_error(
        "openai",
        StatusCode::NOT_FOUND,
        crate::proxy::KIND_NOT_FOUND,
        "m",
    );
    assert!(
        openai.headers().get("x-amzn-requestid").is_none(),
        "non-bedrock protocol does not emit x-amzn-RequestId"
    );
    assert!(
        openai.headers().get("x-amzn-errortype").is_none(),
        "non-bedrock protocol does not emit x-amzn-errortype"
    );
}

// ---- MEDIUM/test-coverage: 400 native error envelopes on the new ingress routes ----

/// Bad JSON on a Cohere `/v2/chat` request ⇒ 400 with the Cohere-native error envelope
/// (`{"message": ...}`), served as application/json — not a plain-text 400 or a foreign shape.
#[tokio::test]
async fn test_cohere_bad_json_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body("not json{".to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "cohere bad json ⇒ 400");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "cohere error is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("message").is_some(),
        "cohere native error envelope has a message field; got {body}"
    );
    handle.abort();
}

/// Bad JSON on a Responses `/v1/responses` request ⇒ 400 with the Responses/OpenAI-native
/// error envelope (`{"error":{"type":...}}`).
#[tokio::test]
async fn test_responses_bad_json_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body("not json{".to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "responses bad json ⇒ 400");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("error").and_then(|e| e.get("type")).is_some(),
        "responses native error envelope has error.type; got {body}"
    );
    handle.abort();
}

/// An OpenAI `/v1/chat/completions` body that omits `model` ⇒ 400 with the OpenAI-native error
/// envelope (`{"error":{"type":"invalid_request_error",...}}`).
#[tokio::test]
async fn test_openai_missing_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({"messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "missing model ⇒ 400");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "missing-model 400 carries the OpenAI invalid_request_error type; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage: an EMPTY `"model"` string (`""`) is a distinct branch from a MISSING
/// model in `ingress_body_model`'s guard (`Some(m) if !m.is_empty()`), and must produce the SAME
/// native 400 `invalid_request_error` for every body-model protocol — NOT fall through to
/// resolution (which would surface a 404 a native SDK reads differently). If the `!m.is_empty()`
/// guard were dropped or weakened to `.is_some()`, an empty model would reach `forward_resolved`
/// and 404 on a pool/by_model miss; these three tests (openai/cohere/responses) lock the 400.
#[tokio::test]
async fn test_openai_empty_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({"model": "", "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "openai empty-model 400 carries invalid_request_error; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage twin: Cohere `/v2/chat` with `"model": ""` ⇒ native Cohere 400 envelope
/// (a BARE top-level `message`, NO `error`/`type` wrapper).
#[tokio::test]
async fn test_cohere_empty_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body(json!({"model": "", "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("message").and_then(|m| m.as_str()).is_some(),
        "cohere empty-model 400 envelope carries a bare top-level message; got {body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "cohere empty-model 400 envelope has NO error/type wrapper; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage twin: Responses `/v1/responses` with `"model": ""` ⇒ native Responses 400
/// envelope (`{"error":{"type":"invalid_request_error"}}`).
#[tokio::test]
async fn test_responses_empty_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(json!({"model": "", "input": "hi"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "responses empty-model 400 carries invalid_request_error; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage: a syntactically valid JSON body whose `"model"` is NOT a string (a
/// number / bool / null) is a distinct branch from MISSING and EMPTY in `ingress_body_model`'s
/// guard. `v.get("model").and_then(|m| m.as_str())` returns `None` for any non-string value, so
/// it MUST fall into the same native 400 `invalid_request_error` branch — never be coerced
/// (e.g. `as_str().unwrap_or("")` or a `to_string()` of the number) and passed to
/// `forward_resolved`, where a numeric "model" would 404 (model-not-found) instead of 400. A
/// native vendor API rejects a non-string `model` with a 400, so a 404 here is a status-code
/// distinguishability tell for SDK-generated requests. These three tests (openai/cohere/
/// responses) lock the 400 for the body-model protocols; each asserts the protocol's native
/// 400 envelope shape so the guard cannot be weakened to coerce a numeric model.
#[tokio::test]
async fn test_openai_numeric_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({"model": 42, "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "numeric model ⇒ 400 (not 404 from resolution)"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "openai numeric-model 400 carries invalid_request_error; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage twin: Cohere `/v2/chat` with a non-string `"model"` (here `null`) ⇒
/// native Cohere 400 envelope (a BARE top-level `message`, NO `error`/`type` wrapper). A `null`
/// model is the exact case a guard weakened to `.is_some()` would mishandle (it IS present but
/// not a string), so it must still 400 rather than fall through to a 404.
#[tokio::test]
async fn test_cohere_numeric_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body(json!({"model": null, "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "non-string model ⇒ 400 (not 404)"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("message").and_then(|m| m.as_str()).is_some(),
        "cohere non-string-model 400 envelope carries a bare top-level message; got {body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "cohere non-string-model 400 envelope has NO error/type wrapper; got {body}"
    );
    handle.abort();
}

/// MEDIUM/test-coverage twin: Responses `/v1/responses` with a non-string `"model"` (here a
/// bool) ⇒ native Responses 400 envelope (`{"error":{"type":"invalid_request_error"}}`).
#[tokio::test]
async fn test_responses_numeric_model_is_400_native_envelope() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(json!({"model": true, "input": "hi"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "non-string model ⇒ 400 (not 404)"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "responses non-string-model 400 carries invalid_request_error; got {body}"
    );
    handle.abort();
}

/// A top-level JSON ARRAY body to a Gemini ingress path hits the non-object branch in
/// `ingress_path_model` and must return a Gemini-native 400 (not panic, not 500). Gemini's
/// envelope is `{"error":{"code":...,"status":...}}`.
#[tokio::test]
async fn test_gemini_non_object_body_is_400() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
        .bearer_auth("t")
        .body(json!([1, 2]).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "gemini non-object body ⇒ 400 (not panic/500)"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "gemini error is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("error").and_then(|e| e.get("code")).is_some(),
        "gemini native error envelope has error.code; got {body}"
    );
    handle.abort();
}

/// A top-level JSON ARRAY body to a Bedrock ingress path hits the non-object branch and must
/// return a Bedrock-native 400 (`{"__type":"ValidationException",...}`) plus the x-amzn-*
/// headers — not a panic or a 500.
#[tokio::test]
async fn test_bedrock_non_object_body_is_400() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth("t")
        .body(json!([1, 2]).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "bedrock non-object body ⇒ 400 (not panic/500)"
    );
    assert!(
        resp.headers().get("x-amzn-errortype").is_some(),
        "bedrock 400 still carries x-amzn-errortype"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("__type").and_then(|t| t.as_str()),
        Some("ValidationException"),
        "bedrock non-object body ⇒ ValidationException; got {body}"
    );
    handle.abort();
}

// ---- MEDIUM/test-coverage: unknown-model 404 native envelope per protocol ----

/// Gemini unknown-model 404 must carry the Gemini-native NOT_FOUND envelope
/// (`error.status == "NOT_FOUND"`), produced by `forward_resolved`'s resolution-miss path.
#[tokio::test]
async fn test_gemini_unknown_model_404_native_shape() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/no-such:generateContent"
        ))
        .bearer_auth("t")
        .body(json!({"contents": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "gemini unknown model ⇒ 404");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.as_str()),
        Some("NOT_FOUND"),
        "gemini 404 carries error.status NOT_FOUND; got {body}"
    );
    handle.abort();
}

/// Bedrock unknown-model 404 must carry the Bedrock-native `ResourceNotFoundException` body and
/// the x-amzn-* headers.
#[tokio::test]
async fn test_bedrock_unknown_model_404_native_shape() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/no-such/converse"))
        .bearer_auth("t")
        .body(json!({"messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "bedrock unknown model ⇒ 404");
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok()),
        Some("ResourceNotFoundException"),
        "bedrock 404 x-amzn-errortype is ResourceNotFoundException"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("__type").and_then(|t| t.as_str()),
        Some("ResourceNotFoundException"),
        "bedrock 404 body __type is ResourceNotFoundException; got {body}"
    );
    handle.abort();
}

/// Cohere unknown-model 404 must carry the Cohere-native envelope (`{"message": ...}`).
#[tokio::test]
async fn test_cohere_unknown_model_404_native_shape() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body(json!({"model": "no-such-model", "messages": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "cohere unknown model ⇒ 404");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("message").and_then(|m| m.as_str()).is_some(),
        "cohere 404 carries a native message field; got {body}"
    );
    handle.abort();
}

/// Responses unknown-model 404 must carry the OpenAI-identical envelope
/// (`{"error":{"type":"not_found_error",...}}`).
#[tokio::test]
async fn test_responses_unknown_model_404_native_shape() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(json!({"model": "no-such-model", "input": "hi"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "responses unknown model ⇒ 404");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
        "responses 404 carries not_found_error type; got {body}"
    );
    handle.abort();
}

// ---- HIGH/test-coverage: streaming integration for Cohere and Responses ingress ----

/// Collect the `data:` payloads of an SSE body into a Vec of `(event_name, data_json_text)`,
/// where `event_name` is the value of the frame's `event:` line (empty string for an
/// OpenAI/Cohere-style bare-`data:` frame). `[DONE]` sentinels are skipped. Used by the
/// native-shape stream assertions below so a regression that leaked the OpenAI egress chunks
/// verbatim (which also begin `data:`) is caught.
fn sse_frames(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for frame in body.split("\n\n") {
        let mut event_name = String::new();
        let mut data: Option<String> = None;
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event_name = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim().to_string());
            }
        }
        if let Some(d) = data {
            if d == crate::proto::SSE_DONE_SENTINEL {
                continue;
            }
            out.push((event_name, d));
        }
    }
    out
}

/// A NATIVE OpenAI streamed chat-completion the mock backend emits, carrying the full identity
/// vocabulary a real OpenAI stream uses — `object: "chat.completion.chunk"`, an `id`, `created`,
/// `model`, a role/content delta walk, and a `finish_reason: "stop"` terminator. Distinct from
/// `openai_stream_events` (which omits `object`/identity to exercise the cross-protocol WRITER):
/// these realistic chunks let the openai→openai SAME-protocol passthrough below assert that the
/// native frame vocabulary survives the proxy intact.
fn openai_native_stream_events() -> Vec<String> {
    vec![
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#.to_string(),
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#.to_string(),
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}"#.to_string(),
        ]
}

/// An OpenAI `/v1/chat/completions` request with `"stream": true` must return `Content-Type:
/// text/event-stream` AND a body whose JSON `data:` frames carry the NATIVE OpenAI
/// chat-completion frame vocabulary — every chunk's `object` is `chat.completion.chunk`, no typed
/// `event:` line (that would be an Anthropic/Responses SSE tell, not chat-completion shape), and
/// the stream closes on the `[DONE]` sentinel. This is the OpenAI happy-path counterpart to
/// `test_cohere_ingress_stream_emits_native_cohere_frames`: it pins the OpenAI egress frame
/// vocabulary on the same-protocol passthrough so a regression that mangled the
/// `chat.completion.chunk` object tag, dropped the `[DONE]` terminator, or injected a foreign
/// typed-`event:` frame is caught.
#[tokio::test]
async fn test_openai_ingress_stream_emits_native_openai_frames() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_native_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("gpt-4o", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(
            json!({
                "model": "gpt-4o",
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "openai stream ⇒ 200");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "openai streaming ingress is SSE; got {ct}"
    );
    let text = resp.text().await.unwrap();

    // Native OpenAI chunks are bare `data:` frames — no typed `event:` line (a typed event would
    // be an Anthropic/Responses SSE tell, not chat-completion vocabulary).
    assert!(
        !text.contains("event:"),
        "openai chat-completion stream frames must be bare data: (no event: line); got:\n{text}"
    );

    // The stream must terminate with the native `[DONE]` sentinel.
    assert!(
        text.contains("[DONE]"), // golden wire-contract literal (kept bare on purpose)
        "openai stream must terminate with the native [DONE] sentinel; got:\n{text}"
    );

    // Every JSON data frame must carry the native `chat.completion.chunk` object tag, and there
    // must be at least one such chunk (content actually flowed).
    let objects: Vec<String> = sse_frames(&text)
        .into_iter()
        .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(&d).ok())
        .filter_map(|v| {
            v.get("object")
                .and_then(|o| o.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        !objects.is_empty(),
        "openai stream must carry at least one JSON data chunk; got:\n{text}"
    );
    assert!(
        objects.iter().all(|o| o == "chat.completion.chunk"),
        "every openai stream data chunk must be a chat.completion.chunk; got objects {objects:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// A Cohere `/v2/chat` request with `"stream": true` must return `Content-Type:
/// text/event-stream` AND a body framed as a NATIVE Cohere v2 stream — `data:` frames whose JSON
/// `type` walks `message-start` → `content-delta` → `message-end` — with NO leaked OpenAI
/// `chat.completion.chunk` objects. Routes cohere→openai (cross-protocol) so the full
/// ingress→forward→SSE-output reframe runs; a regression that passed the OpenAI egress chunks
/// through verbatim would still start `data:` but carries none of the Cohere vocabulary and is
/// caught here.
#[tokio::test]
async fn test_cohere_ingress_stream_emits_native_cohere_frames() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("co", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("co", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth("t")
        .body(
            json!({
                "model": "co",
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "cohere stream ⇒ 200");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "cohere streaming ingress is SSE; got {ct}"
    );
    let text = resp.text().await.unwrap();

    // No OpenAI egress object may leak through to a Cohere SDK.
    assert!(
        !text.contains("chat.completion.chunk"),
        "cohere stream leaked an OpenAI chat.completion.chunk object; got:\n{text}"
    );

    // Collect the JSON `type` discriminants of every data frame, in order.
    let types: Vec<String> = sse_frames(&text)
        .into_iter()
        .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(&d).ok())
        .filter_map(|v| {
            v.get("type")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        types.iter().any(|t| t == "message-start"),
        "cohere stream must open with a message-start frame; got types {types:?}"
    );
    assert!(
        types.iter().any(|t| t == "content-delta"),
        "cohere stream must carry a content-delta frame; got types {types:?}"
    );
    assert!(
        types.iter().any(|t| t == "message-end"),
        "cohere stream must close with a message-end frame; got types {types:?}"
    );
    // Ordering: message-start strictly precedes message-end (native Cohere framing).
    let start_at = types.iter().position(|t| t == "message-start");
    let end_at = types.iter().rposition(|t| t == "message-end");
    assert!(
        matches!((start_at, end_at), (Some(s), Some(e)) if s < e),
        "cohere message-start must precede message-end; got types {types:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// A Responses `/v1/responses` request with `"stream": true` must return SSE framing whose typed
/// `event:` names are the NATIVE Responses vocabulary — a `response.created` opener, a
/// `response.output_text.delta`, and a `response.completed` terminator — with NO leaked OpenAI
/// `chat.completion.chunk` objects. Routes responses→openai (cross-protocol).
#[tokio::test]
async fn test_responses_ingress_stream_emits_native_responses_events() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("re", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("re", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(
            json!({
                "model": "re",
                "stream": true,
                "input": "hello"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "responses stream ⇒ 200");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "responses streaming ingress is SSE; got {ct}"
    );
    let text = resp.text().await.unwrap();

    // No OpenAI egress object may leak through to a Responses SDK.
    assert!(
        !text.contains("chat.completion.chunk"),
        "responses stream leaked an OpenAI chat.completion.chunk object; got:\n{text}"
    );

    let events: Vec<String> = sse_frames(&text).into_iter().map(|(e, _)| e).collect();
    assert!(
        events.iter().any(|e| e == "response.created"),
        "responses stream must open with response.created; got events {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "response.output_text.delta"),
        "responses stream must carry response.output_text.delta; got events {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "response.completed"),
        "responses stream must terminate with response.completed; got events {events:?}"
    );
    // The completed terminator must be the LAST typed event (native Responses ordering).
    let created_at = events.iter().position(|e| e == "response.created");
    let completed_at = events.iter().rposition(|e| e == "response.completed");
    assert!(
        matches!((created_at, completed_at), (Some(c), Some(d)) if c < d),
        "responses response.created must precede response.completed; got events {events:?}"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- MEDIUM/test-coverage: percent-encoded Bedrock model id end-to-end ----

/// A percent-encoded Bedrock model id (`anthropic.claude-3%3Ahaiku` → `anthropic.claude-3:haiku`)
/// must be decoded by axum, resolved, and the converse-stream response re-encoded as a binary
/// AWS eventstream. This exercises the real HTTP decode + routing + binary re-encode end-to-end
/// (the unit `percent_decode` tests bypass axum's own first decode).
#[tokio::test]
async fn test_bedrock_percent_encoded_model_id_converse_stream() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    // The lane is named with the DECODED colon-bearing id so a correct end-to-end decode is the
    // only way it resolves.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "anthropic.claude-3:haiku",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("anthropic.claude-3:haiku", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/model/anthropic.claude-3%3Ahaiku/converse-stream"
        ))
        .bearer_auth("t")
        .body(json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "percent-encoded model id decodes, resolves, and 2xx round-trips"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/vnd.amazon.eventstream"),
        "decoded model resolves to a binary eventstream; got {ct}"
    );
    let body = resp.bytes().await.unwrap();
    let mut buf = body.to_vec();
    let frames = crate::eventstream::drain_frames(&mut buf);
    assert!(
        !frames.is_empty(),
        "at least one binary eventstream frame decodes for the percent-encoded model"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- HIGH/test-coverage: mid-stream transport-error E2E for Cohere and Responses ingress ----
//
// `test_sse_ingress_mid_stream_error_uses_native_framing` (proxy engine) tests the byte shape of
// `mid_stream_error_bytes` in isolation; these two drive a TRUE `SseTransportError` through the
// REAL router on the two ingress routes that previously lacked an E2E mid-stream error test
// (bedrock/openai/gemini-json-array already have theirs above). Each routes cross-protocol to an
// OpenAI backend that drops the connection after the first frame.

/// Cohere `/v2/chat` (stream:true) mid-stream transport failure: the body must terminate with a
/// NATIVE Cohere SSE error frame — a BARE `data:` frame (Cohere's native stream never emits an
/// `event:` line mid-stream) whose JSON carries the Cohere-native flat shape (a `message`, or a
/// `type`+`message`) — and must NOT regress to an OpenAI `{"error":{...}}` envelope NESTED under
/// `error` only (the leak the finding guards against would be an `event:` line or a foreign shape).
#[tokio::test]
async fn test_cohere_ingress_mid_stream_transport_error_appends_native_sse() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("co", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("co", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(
                json!({ "model": "co", "stream": true, "messages": [{"role": "user", "content": "hi"}] })
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "cohere stream starts 2xx");
    let body = resp.bytes().await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // No `event:` line anywhere — a native Cohere stream never emits one mid-stream.
    assert!(
        !text.contains("event:"),
        "cohere mid-stream error must be a bare data: frame (no event: line); got:\n{text}"
    );
    // No OpenAI egress object may leak through verbatim.
    assert!(
        !text.contains("chat.completion.chunk"),
        "cohere mid-stream error leaked an OpenAI chunk object; got:\n{text}"
    );
    // The LAST `data:` frame is the native Cohere v2 stream terminator on error: a `message-end`
    // event with `delta.finish_reason: "ERROR"` and NO top-level free-text `message` (a native
    // client never sees a proxy-detail string; the cause is logged server-side), and NOT a
    // top-level OpenAI `{"error":{...}}` shape.
    let last_data = sse_frames(&text)
        .into_iter()
        .next_back()
        .map(|(_, d)| d)
        .expect("a trailing data: error frame");
    let v: Value = serde_json::from_str(&last_data).expect("native Cohere JSON envelope");
    assert_eq!(
        v.get("type").and_then(|t| t.as_str()),
        Some("message-end"),
        "cohere mid-stream error is a native message-end frame; got {v}"
    );
    assert!(
        v.pointer("/delta/finish_reason")
            .and_then(|f| f.as_str())
            .is_some_and(|f| f.starts_with("ERROR")),
        "cohere message-end carries delta.finish_reason ERROR; got {v}"
    );
    assert!(
        v.get("message").is_none(),
        "cohere native message-end must not carry a top-level free-text message; got {v}"
    );
    handle.abort();
    server.shutdown().await;
}

/// Responses `/v1/responses` (stream:true) mid-stream transport failure: the body must terminate
/// with `event: response.failed` whose `data:` payload is the SDK-required STREAM shape
/// `{"response":{"status":"failed","error":{...}}}` — and must NOT regress to a top-level
/// `{"error":{...}}` HTTP envelope (which the official Responses stream decoder cannot locate via
/// `event.response`).
#[tokio::test]
async fn test_responses_ingress_mid_stream_transport_error_appends_response_failed() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::SseTransportError {
        ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("re", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("re", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth("t")
        .body(json!({ "model": "re", "stream": true, "input": "hi" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "responses stream starts 2xx");
    let body = resp.bytes().await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // The terminal frame is the named `response.failed` event.
    assert!(
        text.contains("event: response.failed"),
        "responses mid-stream error must terminate with event: response.failed; got:\n{text}"
    );
    // Locate the `response.failed` frame and assert its payload is the STREAM shape.
    let failed_data = sse_frames(&text)
        .into_iter()
        .find(|(ev, _)| ev == "response.failed")
        .map(|(_, d)| d)
        .expect("a response.failed data: frame");
    let v: Value = serde_json::from_str(&failed_data).expect("native Responses JSON envelope");
    assert!(
            v.get("response").is_some(),
            "responses stream error MUST wrap in a `response` object (SDK reads event.response); got {v}"
        );
    assert_eq!(
        v["response"]["status"], "failed",
        "response.status is `failed`; got {v}"
    );
    assert!(
        v["response"]["error"]["message"].is_string(),
        "the error lives inside response.error; got {v}"
    );
    assert!(
        v.get("error").is_none(),
        "responses stream error must NOT carry a top-level `error` (the HTTP envelope the stream \
             decoder cannot locate); got {v}"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- HIGH/conformance: no client-facing error message carries the wire-visible `router:` tell --

/// CLASS regression for the `router:` prefix leak. Drives the REAL router on EVERY ingress
/// protocol and asserts that NONE of the synthesized client-facing error bodies (bad JSON,
/// missing/unknown model, malformed gemini path, unsupported gemini action, non-object body,
/// provider mismatch) contains the substring `router:` anywhere — including inside the
/// per-protocol native envelope's `message`/`error.message`/`__type` fields. A native vendor
/// endpoint never returns an error whose copy begins `router:`, so its presence is a
/// deterministic proxy tell on any of the six surfaces.
#[tokio::test]
async fn test_no_client_error_message_carries_router_prefix() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // (path, body) pairs that each hit a distinct synthesized-error site across all protocols.
    let cases: Vec<(String, String)> = vec![
        // openai: bad json + missing model + unknown model.
        (
            format!("http://{addr}/v1/chat/completions"),
            "not json{".to_string(),
        ),
        (
            format!("http://{addr}/v1/chat/completions"),
            json!({"messages": []}).to_string(),
        ),
        (
            format!("http://{addr}/v1/chat/completions"),
            json!({"model": "no-such", "messages": []}).to_string(),
        ),
        // cohere unknown model.
        (
            format!("http://{addr}/v2/chat"),
            json!({"model": "no-such", "messages": []}).to_string(),
        ),
        // responses unknown model.
        (
            format!("http://{addr}/v1/responses"),
            json!({"model": "no-such", "input": "hi"}).to_string(),
        ),
        // gemini: malformed path (no colon), unsupported action, non-object body, unknown model.
        (
            format!("http://{addr}/v1beta/models/gemini-flash"),
            json!({}).to_string(),
        ),
        (
            format!("http://{addr}/v1beta/models/foo:countTokens"),
            json!({"contents": []}).to_string(),
        ),
        (
            format!("http://{addr}/v1beta/models/foo:generateContent"),
            json!([1, 2]).to_string(),
        ),
        (
            format!("http://{addr}/v1beta/models/no-such:generateContent"),
            json!({"contents": []}).to_string(),
        ),
        // bedrock: non-object body + unknown model.
        (
            format!("http://{addr}/model/foo/converse"),
            json!([1, 2]).to_string(),
        ),
        (
            format!("http://{addr}/model/no-such/converse"),
            json!({"messages": []}).to_string(),
        ),
        // anthropic named: unknown model/pool.
        (
            format!("http://{addr}/no-such/v1/messages"),
            json!({"model": "no-such", "messages": [], "max_tokens": 16}).to_string(),
        ),
    ];

    for (url, payload) in cases {
        let resp = client
            .post(&url)
            .bearer_auth("t")
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains("router:"),
            "client-facing error body for {url} (payload {payload}) leaked the `router:` tell \
                 (status {status}); got: {body}"
        );
    }
    handle.abort();
}

// ---- HIGH/test-coverage: governance pool-ACL 403 native envelope on the new ingress routes ----
//
// `test_governance_vkey_auth_and_pool_acl` (test_support.rs) and
// `test_governance_rejection_is_counted_via_finish` (above) only exercise the Anthropic ingress
// (`/v1/messages` / `/anypool/v1/messages`). The four first-class ingress routes
// (`/v2/chat`, `/v1/responses`, `/v1beta/models/...`, `/model/...`) each call `forward_resolved`
// → `governance_guard` with the route's own `proto`, so a pool-ACL 403 on those routes returns a
// PROTOCOL-NATIVE 403 envelope. These four tests drive a governance-rejected request through the
// REAL router on each route and assert the native 403 shape, so a regression in `ingress_error`
// writer dispatch / kind mapping for any of them is caught.
//
// The governance guard keys the ACL on the resolved MODEL string (the body `"model"` for
// body-model routes, the path model for path-model routes) — see `forward_resolved`. So a key
// whose `allowed_pools` does NOT contain the request model is pool-rejected with 403 BEFORE
// resolution. We still wire a matching lane+pool so the request is otherwise fully valid and the
// ONLY reason for the 403 is the ACL.

/// Build a governance-enabled router whose single virtual key is allowed ONLY on `other-pool`
/// (never on the model/pool the tests request), wired with `lane`+`pool` named `model` so the
/// request is otherwise valid. Returns `(addr, handle, secret)`.
async fn governed_pool_acl_router(
    model: &str,
    protocol: crate::proto::Protocol,
    provider: &str,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    &'static str,
) {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    // The lane needs a base_url, but the pool-ACL 403 short-circuits before any forward, so an
    // unreachable upstream is fine.
    const SECRET: &str = "sk-vk-acl-denied";
    let store = StdArc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kacl".to_string(),
            key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
            name: "acl".to_string(),
            // Allowed ONLY on a pool the requests never use → every request is pool-rejected 403.
            allowed_pools: Some(vec!["other-pool".to_string()]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
        })
        .unwrap();
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new()
        .governance(gov)
        .lane(LaneSpec::new(model, protocol, "http://127.0.0.1:1").provider(provider))
        .pool(model, &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;
    (addr, handle, SECRET)
}

/// Cohere `/v2/chat` governance pool-ACL 403 must carry the Cohere-native error envelope
/// (`{"message": ...}`), served as application/json.
#[tokio::test]
async fn test_governance_pool_acl_403_cohere_native_envelope() {
    crate::metrics::init();
    let (addr, handle, secret) =
        governed_pool_acl_router("co", crate::proto::Protocol::openai(), "zai").await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v2/chat"))
        .bearer_auth(secret)
        .body(json!({"model": "co", "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "cohere pool-ACL ⇒ 403");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "cohere 403 envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("message").and_then(|m| m.as_str()).is_some(),
        "cohere native 403 envelope has a message field; got {body}"
    );
    handle.abort();
}

/// Responses `/v1/responses` governance pool-ACL 403 must carry the OpenAI-identical error
/// envelope (`{"error":{"type":"permission_error"}}`).
#[tokio::test]
async fn test_governance_pool_acl_403_responses_native_envelope() {
    crate::metrics::init();
    let (addr, handle, secret) =
        governed_pool_acl_router("re", crate::proto::Protocol::openai(), "zai").await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth(secret)
        .body(json!({"model": "re", "input": "hi"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "responses pool-ACL ⇒ 403");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "responses 403 envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
        "responses 403 carries the permission_error type; got {body}"
    );
    handle.abort();
}

/// OpenAI `/v1/chat/completions` governance pool-ACL 403 must carry the OpenAI-native error
/// envelope (`{"error":{"type":"permission_error"}}`), served as application/json. The native
/// OpenAI ingress route (`openai_ingress` → `ingress_body_model(..., "openai")`) shares the
/// `forward_resolved` → `governance_guard` path with the other four ingresses, so a regression in
/// `ingress_error` writer dispatch / `permission_error` kind mapping for the `openai` writer is
/// caught here exactly as the symmetric four tests catch it for their protocols.
#[tokio::test]
async fn test_governance_pool_acl_403_openai_native_envelope() {
    crate::metrics::init();
    let (addr, handle, secret) =
        governed_pool_acl_router("gpt-4o", crate::proto::Protocol::openai(), "openai").await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth(secret)
        .body(
            json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "openai pool-ACL ⇒ 403");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "openai 403 envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
        "openai 403 carries the permission_error type; got {body}"
    );
    handle.abort();
}

/// Gemini `/v1beta/models/{model}:generateContent` governance pool-ACL 403 must carry the
/// Gemini-native error envelope (`{"error":{"code":403,"status":"PERMISSION_DENIED"}}`).
#[tokio::test]
async fn test_governance_pool_acl_403_gemini_native_envelope() {
    crate::metrics::init();
    let (addr, handle, secret) =
        governed_pool_acl_router("foo", crate::proto::Protocol::openai(), "zai").await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
        .bearer_auth(secret)
        .body(json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "gemini pool-ACL ⇒ 403");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "gemini 403 envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_u64()),
        Some(403),
        "gemini 403 envelope carries error.code 403; got {body}"
    );
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.as_str()),
        Some("PERMISSION_DENIED"),
        "gemini 403 envelope carries status PERMISSION_DENIED; got {body}"
    );
    handle.abort();
}

/// Bedrock `/model/{model}/converse` governance pool-ACL 403 must carry the Bedrock-native error
/// body (`{"__type":"AccessDeniedException"}`) AND the `x-amzn-errortype: AccessDeniedException`
/// header (plus `x-amzn-RequestId`), exactly as a real AWS Bedrock 403 does.
#[tokio::test]
async fn test_governance_pool_acl_403_bedrock_native_envelope() {
    crate::metrics::init();
    let (addr, handle, secret) =
        governed_pool_acl_router("foo", crate::proto::Protocol::openai(), "zai").await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/model/foo/converse"))
        .bearer_auth(secret)
        .body(json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "bedrock pool-ACL ⇒ 403");
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "bedrock 403 envelope is JSON; got {ct}"
    );
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok()),
        Some("AccessDeniedException"),
        "bedrock 403 carries x-amzn-errortype: AccessDeniedException"
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_some(),
        "bedrock 403 still carries x-amzn-RequestId"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("__type").and_then(|t| t.as_str()),
        Some("AccessDeniedException"),
        "bedrock 403 body __type is AccessDeniedException; got {body}"
    );
    handle.abort();
}

// ---- SECURITY MED #3: the allowed_pools ACL must also gate the FALLBACK pool ----
//
// A virtual key's `allowed_pools` was enforced only on the INITIAL pool. A pool configured with
// `on_exhausted = fallback_pool:B` would, on exhaustion, route the request to pool B inside
// `proxy::handle_fallback_pool` — which never re-checks the key (the `gov` context is not
// threaded that deep). So a key allowed ONLY on pool A could be served by pool B it was never
// permitted to use. The fix (`fallback_pools_authorized`, wired into `governance_guard`) walks
// the fallback chain reachable from the requested pool and re-runs the SAME `pool_authorized`
// 403 gate against every fallback pool name BEFORE any dispatch.

/// REGRESSION (SECURITY MED #3): a key restricted to pool A must be DENIED (403, the same
/// protocol-native permission envelope as the initial-pool denial) when A is configured to fail
/// over to a fallback pool B the key is NOT allowed on — even though the key passes A's own ACL
/// and A's backend would itself answer 200. Against the pre-fix code this request reached A and
/// returned 200 (the fallback ACL was never checked); with the fix it is a 403 upfront, because B
/// is reachable from A on exhaustion and the key may not use B.
#[tokio::test]
async fn test_fallback_pool_acl_denies_key_not_allowed_on_fallback_target() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    crate::metrics::init();

    // Pool A's backend would succeed (200) if the request ever reached it — proving the 403 is
    // due ONLY to the fallback-pool ACL, not to A being unreachable.
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: anthropic_ok_body(),
    });
    let server = MockServer::new(state).await;
    let a_url = server.base_url();

    const SECRET: &str = "sk-vk-fallback-acl";
    let store = StdArc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kfb".to_string(),
            key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
            name: "fb".to_string(),
            // Allowed ONLY on pool A. Pool B (the fallback target) is NOT in the list.
            allowed_pools: Some(vec!["A".to_string()]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
        })
        .unwrap();
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    // Lane 0 → pool A (reachable mock). Lane 1 → pool B (the disallowed fallback target).
    let app = TestApp::new()
        .governance(gov)
        .lane(LaneSpec::new("A", crate::proto::Protocol::anthropic(), &a_url).provider("zai"))
        .lane(
            LaneSpec::new(
                "B",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("A", &[(0, 1)])
        .pool("B", &[(1, 1)])
        // A fails over to B on exhaustion — B is exactly the pool the key may NOT use.
        .fallback_pool("B", &[(1, 1)])
        .on_exhausted(
            "A",
            crate::config::OnExhausted::FallbackPool("B".to_string()),
        )
        .build();
    let (addr, handle) = serve(app).await;

    // Request pool A via the named Anthropic ingress. The key is allowed on A, but A→B fallback
    // is configured and the key is not allowed on B, so the request must be rejected upfront.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/A/v1/messages"))
        .bearer_auth(SECRET)
        .body(json!({"model": "A", "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        403,
        "key restricted to A must be denied (not served) when A falls back to disallowed pool B"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
            "fallback-pool ACL 403 carries the SAME permission_error envelope as the initial check; got {body}"
        );
    handle.abort();
    server.shutdown().await;
}

/// COMPLEMENT to the above: a key that IS allowed on BOTH the initial pool A and its fallback
/// pool B is NOT spuriously rejected — the fallback-pool ACL walk only denies pools outside the
/// key's `allowed_pools`. The request reaches A's backend and round-trips 200. Guards against the
/// fix over-rejecting legitimate fallback configurations.
#[tokio::test]
async fn test_fallback_pool_acl_allows_key_permitted_on_both_pools() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    crate::metrics::init();

    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: anthropic_ok_body(),
    });
    let server = MockServer::new(state).await;
    let a_url = server.base_url();

    const SECRET: &str = "sk-vk-fallback-ok";
    let store = StdArc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kfb2".to_string(),
            key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
            name: "fb2".to_string(),
            // Allowed on BOTH A and the fallback target B → no ACL rejection on either.
            allowed_pools: Some(vec!["A".to_string(), "B".to_string()]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
        })
        .unwrap();
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .governance(gov)
        .lane(LaneSpec::new("A", crate::proto::Protocol::anthropic(), &a_url).provider("zai"))
        .lane(
            LaneSpec::new(
                "B",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("A", &[(0, 1)])
        .pool("B", &[(1, 1)])
        .fallback_pool("B", &[(1, 1)])
        .on_exhausted(
            "A",
            crate::config::OnExhausted::FallbackPool("B".to_string()),
        )
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/A/v1/messages"))
        .bearer_auth(SECRET)
        .body(json!({"model": "A", "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        200,
        "key allowed on both A and fallback B must NOT be rejected by the fallback ACL walk"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- MEDIUM/test-coverage: adhoc `/{provider}/{model}/v1/messages` E2E through the router ----
//
// `test_adhoc_rejects_unconfigured_provider_model` (test_support.rs) calls the handler directly,
// bypassing the router, axum `Path` extraction, the auth middleware + CallerToken extension
// wiring, and `finish` metrics accounting. These three drive the adhoc route through the REAL
// router (`build_router`) so that whole stack is covered: (a) a successful round-trip, (b) a
// provider-mismatch 400 with the Anthropic-native envelope, (c) a governance pool-ACL rejection.

/// Adhoc success: `/{provider}/{model}/v1/messages` resolves the configured provider+model lane,
/// round-trips through the router (Anthropic ingress → Anthropic backend), and returns 2xx. This
/// exercises the axum two-segment `Path((provider, model))` extraction, the auth middleware +
/// CallerToken extension wiring, and `finish` — none of which the handler-direct unit test runs.
#[tokio::test]
async fn test_adhoc_success_round_trip_via_router() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: anthropic_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/anthropic/claude-x/v1/messages"))
        .bearer_auth("t")
        .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "adhoc provider+model resolves and 2xx round-trips"
    );
    handle.abort();
    server.shutdown().await;
}

/// Adhoc provider mismatch via the router: a configured model requested under the WRONG provider
/// segment ⇒ 400 with the Anthropic-native error envelope (`{"type":"error","error":{"type":...}}`),
/// not a foreign shape or a plain-text body.
#[tokio::test]
async fn test_adhoc_provider_mismatch_400_anthropic_envelope_via_router() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("anthropic"),
        )
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/wrong-provider/claude-x/v1/messages"))
        .bearer_auth("t")
        .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "model on a mismatched provider ⇒ 400"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "adhoc 400 envelope is JSON; got {ct}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("type").and_then(|t| t.as_str()),
        Some("error"),
        "adhoc 400 is the Anthropic native error envelope; got {body}"
    );
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
        "adhoc provider-mismatch 400 carries invalid_request_error; got {body}"
    );
    handle.abort();
}

/// Adhoc governance pool-ACL rejection via the router: the adhoc handler also runs
/// `governance_guard` (keyed on the resolved MODEL). A key allowed only on `other-pool` requesting
/// the configured model ⇒ 403 with the Anthropic-native envelope, finished through `finish_rejected`. This
/// covers the governance path on the adhoc route end-to-end (untested by the handler-direct test,
/// which passes a default no-key GovCtx).
#[tokio::test]
async fn test_adhoc_governance_pool_acl_403_via_router() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    crate::metrics::init();
    const SECRET: &str = "sk-vk-adhoc-acl";
    let store = StdArc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kadhoc".to_string(),
            key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
            name: "adhoc-acl".to_string(),
            allowed_pools: Some(vec!["other-pool".to_string()]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
        })
        .unwrap();
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("anthropic"),
        )
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/anthropic/claude-x/v1/messages"))
        .bearer_auth(SECRET)
        .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "adhoc governance pool-ACL ⇒ 403"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("type").and_then(|t| t.as_str()),
        Some("error"),
        "adhoc 403 is the Anthropic native error envelope; got {body}"
    );
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
        "adhoc governance 403 carries permission_error; got {body}"
    );
    handle.abort();
}

/// MEDIUM/conformance regression: `not_found_message` shapes the model-not-found copy per the
/// INGRESS protocol. A gemini api_version yields the NATIVE Gemini string (versioned, no OpenAI
/// "The model '…'" phrasing); every other protocol (api_version `None`) keeps the canonical
/// OpenAI-style copy the OpenAI/Responses/Cohere/Anthropic SDKs expect. Guards against a future
/// edit re-leaking the OpenAI message onto the gemini surface.
#[test]
fn test_not_found_message_is_protocol_native() {
    // Gemini v1beta: native versioned message, NO OpenAI phrasing.
    let g_beta = not_found_message("gemini-1.5-pro", Some("v1beta"));
    assert_eq!(
        g_beta,
        "models/gemini-1.5-pro is not found for API version v1beta, \
             or is not supported for the task you are trying to perform."
    );
    // Gemini stable v1: the version token echoes "v1" (not a hardcoded "v1beta").
    let g_v1 = not_found_message("gemini-1.5-pro", Some("v1"));
    assert!(
        g_v1.contains("for API version v1,"),
        "stable v1 message echoes the v1 token; got {g_v1}"
    );
    assert!(
        !g_v1.contains("does not exist"),
        "gemini message must NOT use the OpenAI 'does not exist' phrasing; got {g_v1}"
    );
    // Non-gemini (None): the canonical OpenAI-style copy is preserved.
    let oai = not_found_message("gpt-4o", None);
    assert_eq!(
        oai,
        "The model 'gpt-4o' does not exist or you do not have access to it."
    );
}

/// MEDIUM/conformance: a model-not-found 404 on the gemini ingress returns the NATIVE Gemini
/// message ("models/{model} is not found for API version {api_version}, …"), with the version
/// token matching the request path — `v1beta` on the v1beta surface, `v1` on the stable v1
/// surface. NO OpenAI "The model '…' does not exist" copy may leak (a tell for SDKs matching on
/// `error.message`). Drives the real router with an empty app so resolution misses on both maps.
#[tokio::test]
async fn test_gemini_model_not_found_uses_native_message() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let (addr, handle) = serve(app).await;

    for (path, version) in [
        ("/v1beta/models/no-such-model:generateContent", "v1beta"),
        ("/v1/models/no-such-model:generateContent", "v1"),
    ] {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}{path}"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "gemini unknown-model ⇒ native 404 ({path})"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        let msg = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert_eq!(
            msg,
            format!(
                "models/no-such-model is not found for API version {version}, \
                     or is not supported for the task you are trying to perform."
            ),
            "gemini 404 carries the native versioned message ({path}); got {body}"
        );
        assert!(
            !msg.contains("does not exist"),
            "no OpenAI 'does not exist' copy may leak to a gemini client ({path}); got {body}"
        );
    }
    handle.abort();
}

/// MEDIUM/test-coverage: the STABLE v1 gemini surface (`/v1/models/*rest`) is a separately
/// registered route (main.rs) that funnels through the same `gemini_ingress` handler as v1beta.
/// This exercises a happy-path STREAMING request via the stable v1 prefix WITH `?alt=sse`, so a
/// routing regression on the v1 alias (e.g. a wildcard conflict) is caught. Mirrors
/// `test_gemini_stream_generate_content_alt_sse_is_event_stream` but on the v1 path: asserts SSE
/// framing and that the frames carry native gemini `candidates[]` (never OpenAI `choices`).
#[tokio::test]
async fn test_gemini_v1_stable_stream_generate_content_alt_sse() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/models/foo:streamGenerateContent?alt=sse"
        ))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "stable v1 :streamGenerateContent?alt=sse resolves and 2xx round-trips"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
        "stable v1 gemini streaming WITH ?alt=sse is SSE-framed; got {ct}"
    );
    let body = resp.text().await.unwrap();
    let payloads: Vec<serde_json::Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect();
    assert!(
        !payloads.is_empty(),
        "stable v1 SSE body carries at least one JSON data: frame; got {body:?}"
    );
    assert!(
        payloads.iter().any(|c| c.get("candidates").is_some()),
        "stable v1 SSE frames are native gemini GenerateContentResponse (candidates[]); \
             got {body:?}"
    );
    assert!(
        payloads.iter().all(|c| c.get("choices").is_none()),
        "no OpenAI `choices` field may leak into the stable v1 gemini SSE frames; got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

/// MEDIUM/test-coverage: the STABLE v1 gemini surface (`/v1/models/*rest`), streaming WITHOUT
/// `?alt=sse`, must return the JSON-ARRAY framing (`application/json`, a `[{...}]` body) exactly
/// like the v1beta surface. Mirrors `test_gemini_stream_generate_content_no_alt_sse_is_json_array`
/// on the v1 path so a regression isolating the stable-v1 alias is caught.
#[tokio::test]
async fn test_gemini_v1_stable_stream_generate_content_no_alt_sse() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: openai_stream_events(),
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/models/foo:streamGenerateContent"))
        .bearer_auth("t")
        .body(
            json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "stable v1 :streamGenerateContent (no alt=sse) 2xx"
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
        "stable v1 gemini streaming WITHOUT ?alt=sse is JSON-array framed; got {ct}"
    );
    let body = resp.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("JSON-array body must parse; got {body:?} ({e})"));
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("body must be a JSON array; got {body:?}"));
    assert!(
        !arr.is_empty(),
        "array carries at least one chunk; got {body:?}"
    );
    assert!(
        arr.iter().any(|c| c.get("candidates").is_some()),
        "stable v1 array chunk is a native gemini GenerateContentResponse; got {body:?}"
    );
    assert!(
        arr.iter().all(|c| c.get("choices").is_none()),
        "no OpenAI `choices` field may leak into the stable v1 JSON-array frames; got {body:?}"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- MEDIUM/test-coverage: governance 429 (rate) and over-budget paths on the new ingress ----
//
// The ingress governance suite above (`test_governance_pool_acl_403_*`) only exercises the
// pool-ACL 403 guard end-to-end. The OTHER two `governance_guard` rejections — `rate_check`
// (429 + Retry-After) and `budget_check` (over-quota) — share the same `forward_resolved`
// dispatch but map to DIFFERENT per-protocol `kind`s (`rate_limit_error` / `insufficient_quota`)
// and (for budget) DIFFERENT statuses (429 for openai/cohere/gemini, 400 for bedrock). A
// regression in either kind-to-envelope mapping on a new ingress protocol would slip past the
// 403-only set. These drive a virtual key that is over its rate cap / budget through the REAL
// router on each first-class ingress route and assert the protocol-native rejection shape.
//
// The rejection fires in `governance_guard` BEFORE model resolution, so no lane/pool/backend is
// needed — only a parseable body carrying `model` where the body-model protocols expect it.

/// Build a governance-enabled router whose single virtual key binds to a GROUP that is over its
/// limit from the first request, selected by `over`: `"requests"` (a `{ requests: 0, per: minute }`
/// limit ⇒ rate-limited) or `"budget"` (a `{ budget: 0, per: total }` limit ⇒ over quota). Keys
/// are pure auth, so the tripping limit lives on the bound group. An omitted `allowed_pools`
/// admits every pool so the ACL never short-circuits the gate under test. Returns
/// `(addr, handle, secret)`.
async fn governed_limit_router(
    over: &'static str,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    &'static str,
) {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    const SECRET: &str = "sk-vk-limit-route";
    let store = StdArc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "klimit".to_string(),
            key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
            name: "limit".to_string(),
            allowed_pools: None, // all pools; ACL never short-circuits
            enabled: true,
            created_at: 0,
            group: Some("tripped".to_string()),
            labels: Default::default(),
        })
        .unwrap();
    let gov = StdArc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let tripping = if over == "requests" {
        LimitCfg {
            metric: LimitMetric::Requests,
            amount: 0,
            per: Some(LimitWindow::Minute),
            pool: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    } else {
        LimitCfg {
            metric: LimitMetric::Budget,
            amount: 0,
            per: Some(LimitWindow::Total),
            pool: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    };
    let groups = std::collections::BTreeMap::from([(
        "tripped".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![tripping],
            ..Default::default()
        },
    )]);
    let app = TestApp::new()
        .governance(gov)
        .cost(crate::cost::CostModel::resolve_parts(None, 0, &groups))
        .build();
    let (addr, handle) = serve(app).await;
    (addr, handle, SECRET)
}

/// Each first-class ingress route: an over-RPM virtual key is rejected with a PROTOCOL-NATIVE
/// 429 (`Retry-After` set) before resolution. Asserts the per-protocol `kind`-to-envelope
/// mapping (`rate_limit_error` for the body-model/anthropic writers, the native quota envelope
/// for gemini/bedrock) that the 403-only set above does not reach.
#[tokio::test]
async fn test_governance_rate_limit_429_native_envelope_all_ingress() {
    crate::metrics::init();

    // openai / responses / cohere: body-model routes, native error envelope is JSON.
    for (path, payload) in [
        (
            "/v1/chat/completions",
            json!({"model": "m", "messages": []}),
        ),
        ("/v1/responses", json!({"model": "m", "input": "hi"})),
        ("/v2/chat", json!({"model": "m", "messages": []})),
    ] {
        let (addr, handle, secret) = governed_limit_router("requests").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}{path}"))
            .bearer_auth(secret)
            .body(payload.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 429, "{path} over-RPM ⇒ 429");
        assert!(
            resp.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "{path} 429 carries Retry-After"
        );
        handle.abort();
    }

    // gemini path-model route: native quota envelope is error.code 429 + RESOURCE_EXHAUSTED.
    {
        let (addr, handle, secret) = governed_limit_router("requests").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/m:generateContent"))
            .bearer_auth(secret)
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 429, "gemini over-RPM ⇒ 429");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("RESOURCE_EXHAUSTED"),
            "gemini 429 envelope carries RESOURCE_EXHAUSTED; got {body}"
        );
        handle.abort();
    }

    // bedrock path-model route: native 429 carries the ThrottlingException envelope + headers.
    {
        let (addr, handle, secret) = governed_limit_router("requests").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/m/converse"))
            .bearer_auth(secret)
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 429, "bedrock over-RPM ⇒ 429");
        assert!(
            resp.headers().get("x-amzn-errortype").is_some(),
            "bedrock 429 carries x-amzn-errortype header"
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_some(),
            "bedrock 429 carries x-amzn-RequestId header"
        );
        handle.abort();
    }
}

/// Each first-class ingress route: an over-budget virtual key is rejected with the protocol's
/// native quota shape before resolution. The over-quota `kind` is `insufficient_quota`; the
/// status is 429 for every protocol EXCEPT bedrock (whose native `ServiceQuotaExceededException`
/// is a 400-class error — see `budget_check`). Closes the ingress gap the 403-only set left on
/// the `budget_check` guard.
#[tokio::test]
async fn test_governance_over_budget_native_envelope_all_ingress() {
    crate::metrics::init();

    // 429-mapping protocols: openai / responses / cohere / gemini.
    for (path, payload) in [
        (
            "/v1/chat/completions",
            json!({"model": "m", "messages": []}),
        ),
        ("/v1/responses", json!({"model": "m", "input": "hi"})),
        ("/v2/chat", json!({"model": "m", "messages": []})),
        ("/v1beta/models/m:generateContent", json!({"contents": []})),
    ] {
        let (addr, handle, secret) = governed_limit_router("budget").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}{path}"))
            .bearer_auth(secret)
            .body(payload.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 429, "{path} over-budget ⇒ 429");
        handle.abort();
    }

    // bedrock: native ServiceQuotaExceededException is a 400-class error, not 429.
    {
        let (addr, handle, secret) = governed_limit_router("budget").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/m/converse"))
            .bearer_auth(secret)
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "bedrock over-budget ⇒ 400");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("ServiceQuotaExceededException"),
            "bedrock over-budget body __type is ServiceQuotaExceededException; got {body}"
        );
        handle.abort();
    }
}

// ---- MEDIUM/test-coverage: the `named` handler's `by_model` fallback branch ----
//
// `named` (`POST /<name>/v1/messages`) resolves `name` against `app.pools` first, then falls
// back to `app.by_model` (the by_model arm). The pool path is covered by
// `test_adhoc_success_round_trip_via_router` and the governance pool-ACL set; the by_model
// fallback — where `name` is a configured single-model lane with NO pool entry, routed via
// `crate::proxy::forward_with_pool` — had no test. A refactor that dropped the fallback, or fed the
// wrong model string, would go undetected. This wires ONLY a by_model lane (no `.pool(...)`),
// POSTs an Anthropic body to `/<model>/v1/messages`, and asserts the 2xx plus that the upstream
// received the (translated) forwarded request.

/// `named` by_model fallback: a single-model lane (no pool) reached via `/<model>/v1/messages`
/// round-trips through `forward_with_pool` to its backend and returns 2xx; the upstream sees the request.
#[tokio::test]
async fn test_named_by_model_fallback_round_trip_via_router() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: anthropic_ok_body(),
    });
    let server = MockServer::new(state.clone()).await;

    // Lane registered in by_model only — no `.pool(...)`, so the `named` pool lookup misses and
    // the by_model fallback arm handles the request.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .build();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/claude-x/v1/messages"))
        .bearer_auth("t")
        .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "named by_model fallback (no pool) resolves and 2xx round-trips"
    );

    // The backend must have actually received the forwarded request — proves the fallback
    // routed through `forward` rather than 404-ing on the pool miss.
    assert!(
        state.get_last_request_body().is_some(),
        "upstream received the forwarded request via the named by_model fallback"
    );
    handle.abort();
    server.shutdown().await;
}

// ---- LOW #4 (re-audit, completeness): breaker op_handler-key consistency for by_model routes ----
//
// A single-model lane (no pool) can be reached two ways:
//   1. the universal body-model ingress (`/v1/chat/completions` etc.) → `forward_resolved`'s
//      `by_model` arm, which calls `forward_with_pool` directly with the ingress protocol so a
//      cross-protocol backend is translated both ways; and
//   2. the Anthropic `/<model>/v1/messages` (`named`) / `/<provider>/<model>/v1/messages`
//      (`adhoc`) routes → `crate::proxy::forward_with_pool`, which passes `""` (the lane-default breaker
//      CELL shared by every direct/single-model route — proxy engine design intent).
//
// proxy engine records every breaker outcome against the CELL keyed by the `pool_name` argument
// (`record_transient_in(pool_name, …)`). If `forward_resolved`'s by_model arm passes the MODEL
// name as `pool_name` (the pre-fix bug) while the named/adhoc paths pass `""`, the SAME lane's
// breaker state is split across two cells purely by route shape: failures driven through the
// universal ingress would never trip (and never be seen by) the `""` op_handler that `/<model>/v1/
// messages` selects against, and vice-versa. The fix passes `""` from the by_model arm too, so
// both route shapes converge on the one lane-default OperationHandler.
//
// This drives the trip THRESHOLD worth of upstream 5xx through the universal (openai) by_model
// ingress, then asserts the `""` op_handler tripped Open while the model-keyed op_handler stayed Closed —
// the exact inverse of the pre-fix behavior, so it fails against the old code.

/// LOW #4: a by_model lane reached via the universal (openai) ingress must record breaker state
/// on the lane-default `""` OperationHandler — the SAME op_handler the `named`/`adhoc` single-model routes use —
/// not on a model-keyed OperationHandler, so a lane reached by-name and by-pool shares one breaker view.
///
/// The discriminating observable is the lane-default `""` op_handler's pending cooldown: a single
/// upstream 5xx through the by_model arm records `record_transient_in(pool_name, …)`, which sets
/// a cooldown ONLY on the OperationHandler keyed by `pool_name`. The `""` OperationHandler is the `LaneState` itself
/// (store.rs `op_handler`: `pool.is_empty()` → `self.lanes[lane]`), written by the FIX (`pool_name ==
/// ""`) and left untouched (cooldown 0) by the pre-fix code (which wrote a SEPARATE model-keyed
/// pool OperationHandler). So `cooldown_remaining_in("", 0) > 0` is true after the fix and false before it.
///
/// NOTE: the model-keyed OperationHandler is NOT a usable counter-assertion — reading `*_in(model, 0)` LAZILY
/// CREATES that OperationHandler, and a freshly-minted pool op_handler INHERITS the lane's (i.e. the `""` op_handler's)
/// current cooldown/state (store.rs `op_handler`). Under the fix it would therefore
/// inherit the non-zero `""` cooldown and read non-zero too — indistinguishable. The `""` op_handler
/// cooldown alone cleanly separates fixed from broken.
#[tokio::test]
async fn test_forward_resolved_by_model_uses_lane_default_breaker_cell() {
    crate::metrics::init();
    let state = StdArc::new(MockServerState::new());
    // One upstream 5xx is enough: a single transient failure sets a pending cooldown on the
    // routed breaker OperationHandler (the trip-to-Open threshold is irrelevant — the cooldown is recorded
    // on the very first transient, on whichever op_handler `pool_name` selects).
    let model = "glm-4.5";
    state.push(MockResponse::ServerError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: json!({"error": {"message": "boom"}}),
    });
    let server = MockServer::new(state.clone()).await;

    // Lane registered in by_model ONLY (no `.pool(...)`), so the universal ingress resolves it
    // through `forward_resolved`'s by_model arm — the site under test.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(model, crate::proto::Protocol::openai(), &server.base_url())
                .provider("zai"),
        )
        .build();
    // Hold a handle to the same App the router serves so the breaker op_handler can be inspected after
    // the request (`serve` only needs a clone of the Arc).
    let app_for_inspect = app.clone();
    let (addr, handle) = serve(app).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("t")
        .body(json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap();
    // The forward fails (single lane, no failover target) — the breaker transient is recorded
    // before the exhausted response is returned, which is all this test cares about.
    assert!(
        !resp.status().is_success(),
        "a 5xx-backed forward returns a non-2xx to the client"
    );

    // The lane-default `""` OperationHandler — the SAME op_handler the `named`/`adhoc` single-model routes select
    // against — must carry the breaker effect of the by_model forward. Under the pre-fix bug
    // (`pool_name == model`) this OperationHandler is never written and reads cooldown 0; the fix
    // (`pool_name == ""`) records here, so it reads a pending cooldown.
    assert!(
            app_for_inspect
                .store
                .cooldown_remaining_in("", 0, crate::store::now())
                > 0,
            "by_model forwards must record breaker state on the lane-default \"\" OperationHandler (the OperationHandler \
             /<model>/v1/messages selects against); a 0 cooldown means the failure was tracked under \
             a model-keyed op_handler instead, splitting breaker state by route shape"
        );

    handle.abort();
    server.shutdown().await;
}

// ─── Budget-group chain rejections at the ingress boundary (1.5.0 cost model) ────────────────────

/// Governance-enabled App whose key binds to a ZERO-cap budget group ("finance") while the key
/// itself is uncapped - the CHAIN is what blocks. The 429 body must NAME the exhausted group.
#[allow(clippy::field_reassign_with_default)]
fn governed_app_group_blocked() -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let groups = std::collections::BTreeMap::from([(
        "finance".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 0,
                per: Some(crate::config::groups::LimitWindow::Total),
                pool: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 30, &groups);
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "grouped".to_string(),
                allowed_pools: None,
                group: Some("finance".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    inner.cost = std::sync::Arc::new(cost);
    (app, key)
}

/// A GROUP-blocked admission is a 429 `insufficient_quota` whose body NAMES the exhausted budget
/// group (cost-model spec: the 429 says WHICH bucket blocked) - while still never leaking the key
/// id or the internal governance vocabulary. Nothing is charged on the rejected attempt.
#[tokio::test]
async fn test_group_blocked_429_names_the_budget_group() {
    crate::metrics::init();
    let (app, key) = governed_app_group_blocked();
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let at = crate::store::now();
    let resp = admit_check(&app, &gov, "openai", "", at)
        .expect_err("a zero-cap group blocks the whole chain");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = body_string(*resp).await;
    assert!(
        body.contains("insufficient_quota"),
        "canonical quota error type: {body}"
    );
    assert!(
        body.contains("group 'finance' budget per total exhausted"),
        "the 429 must NAME the blocking bucket (group + metric + window): {body}"
    );
    assert!(!body.contains(&key.id), "never the key id: {body}");
    // All-or-nothing: the rejected attempt charged nothing anywhere in the chain.
    let g = app.governance.as_ref().unwrap();
    assert_eq!(
        g.usage_for(&app.cost, &key.id, at)
            .unwrap()
            .unwrap()
            .requests,
        0
    );
}

/// A key naming a budget_group MISSING from this node's config FAILS CLOSED at admission (429,
/// bucket named as unconfigured) - never a silent uncapped admit.
#[tokio::test]
async fn test_missing_group_fails_closed_at_ingress() {
    crate::metrics::init();
    let (app, key) = governed_app_group_blocked();
    let mut orphan = key.clone();
    orphan.group = Some("ghost".to_string());
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(orphan)),
    };
    let resp = admit_check(&app, &gov, "openai", "", crate::store::now())
        .expect_err("a missing group must fail closed");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = body_string(*resp).await;
    assert!(
        body.contains("group 'ghost' is not configured"),
        "the missing bucket is named for the operator-facing fix: {body}"
    );
}

/// ALL-OR-NOTHING pricing at the ingress: with a rate card PRESENT, a governed request for an
/// arbitrary passthrough model (no configured pool / by-model lane, no rate entry) is rejected
/// pre-forward with a clear "no configured rate" error; configured lanes are unaffected.
#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_unpriced_passthrough_model_rejected_when_rate_card_present() {
    crate::metrics::init();
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
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
        .unwrap();
    let rate_card = std::collections::BTreeMap::from([(
        "m".to_string(),
        crate::config::RateEntryCfg::default(),
    )]);
    let cost = crate::cost::CostModel::resolve_parts(
        Some(&rate_card),
        0,
        &std::collections::BTreeMap::new(),
    );
    let mut app = minimal_app();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.governance = Some(gov);
        inner.cost = std::sync::Arc::new(cost);
    }
    let gov_ctx = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    // An arbitrary passthrough model string (not a pool, not a by-model lane, not priced).
    let resp = governance_guard(
        &app,
        &gov_ctx,
        "openai",
        "mystery-model",
        std::time::Instant::now(),
        crate::store::now(),
    )
    .expect_err("an unpriced passthrough model must be rejected pre-forward");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(*resp).await;
    assert!(
        body.contains("no configured rate for model 'mystery-model'"),
        "the rejection names the unpriced model: {body}"
    );
    // The configured by-model lane ("m" in minimal_app) still passes the pricing guard (it is
    // priced by the card), so the guard admits and charges it.
    let ok = governance_guard(
        &app,
        &gov_ctx,
        "openai",
        "m",
        std::time::Instant::now(),
        crate::store::now(),
    );
    assert!(ok.is_ok(), "a priced configured lane admits");
}

// ─── Budget downgrade at the ingress boundary (§6c on_exhaust: downgrade) ────────────────────────

/// Governance-enabled App with pools `frontier` + `value` and a group whose frontier budget
/// (25c/day at a 10c flat fee) declares `on_exhaust: downgrade, downgrade_to: value`.
#[allow(clippy::field_reassign_with_default)]
fn governed_app_downgrade(
    allowed_pools: Option<Vec<String>>,
) -> (Arc<App>, crate::governance::VirtualKey) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 25,
                per: Some(crate::config::groups::LimitWindow::Day),
                pool: Some("frontier".to_string()),
                on_exhaust: Some(crate::config::groups::OnExhaust::Downgrade),
                downgrade_to: Some("value".to_string()),
            }],
            ..Default::default()
        },
    )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 10, &groups);
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "dev".to_string(),
                allowed_pools,
                group: Some("team".to_string()),
                labels: Default::default(),
            },
            1_700_000_000,
        )
        .unwrap();
    let mut app = minimal_app();
    let inner = Arc::get_mut(&mut app).expect("sole owner");
    inner.governance = Some(gov);
    inner.cost = std::sync::Arc::new(cost);
    inner.pools.insert("frontier".to_string(), vec![]);
    inner.pools.insert("value".to_string(), vec![]);
    (app, key)
}

/// Exhausting the frontier budget DOWNGRADES instead of rejecting: the admission lands on the
/// `value` pool (returned as the effective pool so dispatch follows), and the charge lands on
/// value's participation set - the caller keeps working, on the cheaper tier.
#[tokio::test]
async fn test_budget_exhaustion_downgrades_pool() {
    let (app, key) = governed_app_downgrade(None);
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let at = crate::store::now();
    // fee=10, cap=25: two frontier admissions spend 20; the 3rd would reach 30 > 25.
    for i in 0..2 {
        let (grant, effective) = admit_check(&app, &gov, "openai", "frontier", at)
            .unwrap_or_else(|_| panic!("admission {i} under the frontier cap"));
        assert!(grant.is_some());
        assert_eq!(effective, None, "no downgrade while under the cap");
    }
    let (grant, effective) =
        admit_check(&app, &gov, "openai", "frontier", at).expect("downgraded, not rejected");
    assert!(grant.is_some(), "the downgraded admission still charges");
    assert_eq!(
        effective.as_deref(),
        Some("value"),
        "dispatch must follow the charge to the downgrade pool"
    );
}

/// The downgrade re-runs the key's pool ACL: a key restricted to `frontier` can NEVER be routed
/// into `value` by exhaustion - the request falls back to the plain budget rejection.
#[tokio::test]
async fn test_downgrade_never_bypasses_pool_acl() {
    let (app, key) = governed_app_downgrade(Some(vec!["frontier".to_string()]));
    let gov = crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(key.clone())),
    };
    let at = crate::store::now();
    assert!(admit_check(&app, &gov, "openai", "frontier", at).is_ok());
    assert!(admit_check(&app, &gov, "openai", "frontier", at).is_ok());
    let resp = admit_check(&app, &gov, "openai", "frontier", at)
        .expect_err("ACL-blocked downgrade must fall back to the budget rejection");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the caller sees the plain quota rejection, not a leaked pool"
    );
}
