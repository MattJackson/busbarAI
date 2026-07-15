//! Tests for `decide_policy_order`'s NEW seams: the `send_prompt`/`send_user` opt-in gating
//! (the flags decide whether the projections are built AND what the policy actually sees), and
//! the `RoutingDecision::Reject` → `PolicyOutcome::RejectRequest` mapping — plus the reject
//! status → error-kind mapping and its dialect-native envelope.
use super::*;
use crate::hooks::{
    Candidate, PolicyResult, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest,
};
use crate::state::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};
use std::sync::Mutex as StdMutex;

/// The prompt as the policy saw it: (flattened system, [(role, text)]).
type SeenPrompt = (Option<String>, Vec<(String, String)>);
/// The identity as the policy saw it: (key_id, key_name, end-user).
type SeenIdentity = (Option<String>, Option<String>, Option<String>);

/// What the policy saw through the seam, captured for assertion.
#[derive(Clone, Default)]
struct CapturedReq {
    prompt: Option<SeenPrompt>,
    identity: Option<SeenIdentity>,
    max_tokens: Option<u32>,
}

/// A test policy that records the projection it was handed and returns a fixed decision.
struct CapturingPolicy {
    seen: Arc<StdMutex<Option<CapturedReq>>>,
    reject: Option<(u16, String)>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CapturingPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        *self.seen.lock().unwrap() = Some(CapturedReq {
            prompt: req.prompt.as_ref().map(|p| {
                (
                    p.system.as_deref().map(str::to_string),
                    p.messages
                        .iter()
                        .map(|(r, t)| (r.to_string(), t.to_string()))
                        .collect(),
                )
            }),
            identity: req
                .identity
                .as_ref()
                .map(|i| (i.key_id.clone(), i.key_name.clone(), i.user.clone())),
            max_tokens: req.max_tokens,
        });
        Ok(match &self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status: *status,
                message: message.clone(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        "capture"
    }
}

/// Run `decide_policy_order` against a one-lane test app with the given flags/body/decision.
async fn run(
    send_prompt: bool,
    send_user: bool,
    reject: Option<(u16, String)>,
    v: Value,
) -> (PolicyOutcome, Option<CapturedReq>) {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let seen = Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: seen.clone(),
            reject,
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt,
        send_user,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let rc = RequestCtx::new(60);
    let out = decide_policy_order(
        &app,
        &resolved,
        &cands,
        &rc,
        &v,
        "p",
        "anthropic",
        false,
        None,
        None,
    )
    .await;
    let captured = seen.lock().unwrap().clone();
    (out, captured)
}

fn body() -> Value {
    serde_json::json!({
        "model": "m0",
        "system": "sys prompt",
        "user": "alice",
        "messages": [{"role": "user", "content": "hello"}]
    })
}

/// Both flags OFF (the default): the policy must see NO prompt and NO identity — the shape-only
/// contract holds at the seam itself, not just at the wire.
#[tokio::test]
async fn default_flags_project_nothing() {
    let (out, captured) = run(false, false, None, body()).await;
    let captured = captured.expect("policy must have been called");
    assert!(captured.prompt.is_none(), "send_prompt off ⇒ no prompt");
    assert!(captured.identity.is_none(), "send_user off ⇒ no identity");
    assert!(matches!(out, PolicyOutcome::Weighted), "abstain ⇒ weighted");
}

/// FIRING: a GLOBAL decision gate that rejects short-circuits the whole request — no upstream is
/// dispatched (the lane URL is a dead localhost that would fail if reached) and the caller gets the
/// gate's clamped 4xx. Proves `App.global_gates` is actually fired in `forward_with_pool_parsed`
/// before pool routing, not just resolved.
#[tokio::test]
async fn global_gate_reject_short_circuits_the_request() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/", // dead — a dispatch would fail; the reject must prevent it
        ))
        .pool("p", &[(0, 1)])
        .build();
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: Arc::new(StdMutex::new(None)),
            reject: Some((451, "blocked by global policy".to_string())),
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    // Inject the global gate (Arc refcount is 1 right after build()).
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![(0u16, gate)];

    let body =
            serde_json::to_vec(&serde_json::json!({"model": "p", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}))
                .unwrap();
    let resp = forward_with_pool(
        app.clone(),
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "p",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        451,
        "a global reject gate must short-circuit with its clamped status, before any dispatch"
    );
}

/// A GLOBAL gate that ABSTAINS does not interfere — the request proceeds past the global-gate loop
/// to normal routing (and here fails to connect to the dead lane, i.e. NOT a 451). Proves the
/// global-gate loop is a no-op on abstain.
#[tokio::test]
async fn global_gate_abstain_does_not_reject() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: Arc::new(StdMutex::new(None)),
            reject: None, // abstain
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![(0u16, gate)];

    let body =
            serde_json::to_vec(&serde_json::json!({"model": "p", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}))
                .unwrap();
    let resp = forward_with_pool(
        app.clone(),
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "p",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_ne!(
        resp.status().as_u16(),
        451,
        "an abstaining global gate must not reject the request"
    );
}

/// A canned phase-2 decision for the reconcile tests below.
enum Canned {
    Order(Vec<usize>),
    Restrict(Vec<String>),
    Reject(u16, &'static str),
}

/// A test gate returning a fixed decision — the reconcile tests' building block.
struct CannedGate {
    canned: Canned,
    name: &'static str,
}

#[async_trait::async_trait]
impl RoutingPolicy for CannedGate {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        Ok(match &self.canned {
            Canned::Order(order) => RoutingDecision::Prefer(order.clone()),
            Canned::Restrict(tags) => RoutingDecision::Restrict {
                tags_any: tags.clone(),
            },
            Canned::Reject(status, message) => RoutingDecision::Reject {
                status: *status,
                message: (*message).to_string(),
            },
        })
    }
    fn name(&self) -> &'static str {
        self.name
    }
}

/// Wrap a canned decision as a resolved gate transport (shape-only, fail-closed defaults).
fn canned_gate(canned: Canned, name: &'static str) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: Arc::new(CannedGate { canned, name }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    }
}

/// A `PoolRuntime` carrying per-lane tags (for restrict reconciles) and the pool's own gates.
fn pool_runtime_with(
    tags_by_idx: &[(usize, &[&str])],
    gates: Vec<(u16, ResolvedPolicy)>,
) -> crate::state::PoolRuntime {
    let mut members = std::collections::HashMap::new();
    for (idx, tags) in tags_by_idx {
        members.insert(
            *idx,
            crate::state::MemberMeta {
                tier: None,
                cost_per_mtok: None,
                tags: tags.iter().map(|t| t.to_string()).collect(),
            },
        );
    }
    crate::state::PoolRuntime {
        members,
        failover: None,
        affinity: None,
        breaker: None,
        policy: None,
        gates,
        rewrite_hooks: Vec::new(),
    }
}

/// REGRESSION (audit c1r13, compliance): a `Restrict` gate on the primary pool must persist onto
/// a `fallback_pool` hop, re-applied against the FALLBACK pool's own member tags. A required
/// (`on_empty: reject`) restrict fails CLOSED when no fallback lane carries the tag; a `weighted`
/// restrict is an advisory escape (skip).
#[test]
fn enforce_restricts_reapplies_compliance_tags_across_pools() {
    // Fallback pool "fb": lane 0 carries `baa`, lane 1 carries nothing.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .lane(LaneSpec::new(
            "m1",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("fb", &[(0, 1), (1, 1)])
        .pool_runtime(
            "fb",
            pool_runtime_with(&[(0, &["baa"]), (1, &[])], Vec::new()),
        )
        .build();
    let cands = vec![
        WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        },
        WeightedLane {
            reasoning: None,
            idx: 1,
            weight: 1,
            attempt_timeout_ms: None,
        },
    ];

    // A required `baa` restrict narrows the fallback pool to ONLY the tagged lane — the untagged
    // lane 1 is dropped, so the compliance constraint holds across the pool hop.
    let mut rc = RequestCtx::new(60);
    rc.active_restricts.push(RestrictConstraint {
        tags_any: vec!["baa".to_string()],
        on_empty: crate::config::PolicyOnError::Reject,
        name: "baa-gate",
    });
    let out = rc.enforce_restricts(&app, "fb", cands.clone()).unwrap();
    assert_eq!(
        out.iter().map(|w| w.idx).collect::<Vec<_>>(),
        vec![0],
        "only the baa-tagged fallback lane may survive a required restrict"
    );

    // A required restrict with NO matching fallback lane fails CLOSED (Err), never spills.
    let mut rc_reject = RequestCtx::new(60);
    rc_reject.active_restricts.push(RestrictConstraint {
        tags_any: vec!["hipaa".to_string()],
        on_empty: crate::config::PolicyOnError::Reject,
        name: "hipaa-gate",
    });
    assert!(
        rc_reject
            .enforce_restricts(&app, "fb", cands.clone())
            .is_err(),
        "a required restrict with no eligible fallback lane must fail closed, not spill"
    );

    // A `weighted` restrict with no match is an advisory escape — candidates pass unchanged.
    let mut rc_weighted = RequestCtx::new(60);
    rc_weighted.active_restricts.push(RestrictConstraint {
        tags_any: vec!["hipaa".to_string()],
        on_empty: crate::config::PolicyOnError::Weighted,
        name: "hipaa-advisory",
    });
    let out = rc_weighted
        .enforce_restricts(&app, "fb", cands.clone())
        .unwrap();
    assert_eq!(
        out.len(),
        2,
        "a weighted restrict with no eligible lane escapes (candidates unchanged)"
    );

    // No active restrict → identity.
    let rc_none = RequestCtx::new(60);
    assert_eq!(
        rc_none.enforce_restricts(&app, "fb", cands).unwrap().len(),
        2
    );
}

/// REGRESSION (audit c1r14), END-TO-END: a BASE routing-policy (`route:` hook) `Restrict` must
/// persist across a `fallback_pool` spill exactly like a gate restrict. Primary pool's only
/// baa-eligible lane is dead → the request exhausts and spills to a fallback pool whose lane is
/// NOT baa-tagged; the compliance restrict must FAIL CLOSED there, not serve the ineligible lane.
#[tokio::test]
async fn base_policy_restrict_persists_across_fallback_pool_hop() {
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                "http://localhost",
            )
            .dead("down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .pool_runtime("p", {
            let mut rt = pool_runtime_with(&[(0, &["baa"])], Vec::new());
            rt.policy = Some(canned_gate(
                Canned::Restrict(vec!["baa".to_string()]),
                "compliance",
            ));
            rt
        })
        .fallback_pool("fb", &[(1, 1)])
        .pool_runtime("fb", pool_runtime_with(&[(1, &[])], Vec::new()))
        .on_exhausted("p", crate::config::OnExhausted::FallbackPool("fb".into()))
        .build();

    let resp = forward_with_pool(
        app,
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        Bytes::from(chat_body()),
        None,
        "p",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "a base-policy compliance restrict must fail closed at the fallback boundary"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("restriction"),
        "the 503 must be the compliance fail-closed, not a generic transport 503: {text}"
    );
}

fn chat_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    }))
    .unwrap()
}

fn lanes(n: usize) -> Vec<WeightedLane> {
    (0..n)
        .map(|idx| WeightedLane {
            reasoning: None,
            idx,
            weight: 1,
            attempt_timeout_ms: None,
        })
        .collect()
}

async fn fire(app: Arc<App>, n_lanes: usize) -> Response {
    forward_with_pool(
        app,
        lanes(n_lanes),
        chat_body().into(),
        None,
        "p",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await
}

/// An Anthropic-shaped 200 whose `model` names the serving lane — the observable that tells the
/// reconcile tests WHICH lane actually got dispatched.
async fn mock_lane(model: &'static str) -> crate::test_support::MockServer {
    let state = Arc::new(crate::test_support::MockServerState::new());
    for _ in 0..4 {
        state.push(crate::test_support::MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}],
                "model": model,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    crate::test_support::MockServer::new(state).await
}

async fn body_model(resp: Response) -> String {
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v.get("model")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Build a webhook TAP transport pointed at a mock server, as the App stage-tap triple.
async fn webhook_tap() -> (
    crate::test_support::MockServer,
    Arc<crate::test_support::MockServerState>,
    (
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    ),
) {
    let state = Arc::new(crate::test_support::MockServerState::new());
    for _ in 0..4 {
        state.push(crate::test_support::MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({}),
        });
    }
    let server = crate::test_support::MockServer::new(state.clone()).await;
    let url = crate::observability::validate_routing_webhook_url(Some(&format!(
        "{}/tap",
        server.base_url()
    )))
    .expect("loopback tap url");
    let policy: Arc<dyn crate::hooks::RoutingPolicy> = Arc::new(
        crate::hooks::webhook::WebhookPolicy::new(url, reqwest::Client::new()),
    );
    (
        server,
        state,
        (std::time::Duration::from_millis(500), false, policy),
    )
}

/// Poll the mock tap server until it records a request body (taps are detached tasks).
async fn wait_for_tap_body(state: &crate::test_support::MockServerState) -> serde_json::Value {
    for _ in 0..200 {
        if let Some(body) = state.get_last_request_body() {
            return serde_json::from_slice(&body).expect("tap payload is JSON");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("tap was never delivered");
}

/// STAGE TAPS: an UNAUTHENTICATED request fires the synthetic `rejected_by_auth` completion
/// (through the real auth middleware) — audit taps see auth denials too. Requires the tokens
/// module (featureless builds have no data-plane auth to reject with).
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn completion_tap_fires_synthetic_rejected_by_auth() {
    crate::metrics::init();
    let (server, state, tap) = webhook_tap().await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .auth(Arc::new(crate::auth::AuthMiddleware::new(
            &serde_yaml::from_str::<crate::config::AuthCfg>(
                "chain: [tokens]\nclient_tokens: [good-token]\n",
            )
            .unwrap(),
        )))
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .tap_hooks_completion = vec![tap];
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/p/v1/messages"))
        .header("x-api-key", "wrong-token")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["at"], "completion");
    assert_eq!(payload["stage"]["outcome"], "rejected_by_auth");
    assert_eq!(payload["stage"]["status"], 401);
    serve.abort();
    server.shutdown().await;
}

/// REGRESSION (audit c1r6): the completion-tap `status` must be the PROTOCOL-NATIVE auth-failure
/// status the client actually receives — not a hardcoded 401. A Gemini ingress bad-key denial is
/// HTTP 400 (INVALID_ARGUMENT), so a tap watching it must see 400, matching the served response.
/// Gated on the tokens module (featureless builds have no data-plane auth to reject with).
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn completion_tap_status_is_protocol_native_gemini_400() {
    crate::metrics::init();
    let (server, state, tap) = webhook_tap().await;
    let mut app = TestApp::new()
        .auth(Arc::new(crate::auth::AuthMiddleware::new(
            &serde_yaml::from_str::<crate::config::AuthCfg>(
                "chain: [tokens]\nclient_tokens: [good-token]\n",
            )
            .unwrap(),
        )))
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .tap_hooks_completion = vec![tap];
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // Gemini ingress path + bad key → the served response is HTTP 400 (not 401).
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1beta/models/gemini-x:generateContent"
        ))
        .header("x-goog-api-key", "wrong-key")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "gemini bad-key is native 400");
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["outcome"], "rejected_by_auth");
    assert_eq!(
        payload["stage"]["status"], 400,
        "the tap status must match the client-visible native status, not a hardcoded 401"
    );
    serve.abort();
    server.shutdown().await;
}

/// STAGE TAPS: a completion tap fires with the SYNTHETIC `rejected_by_gate` outcome when a
/// decision gate rejects — audit taps see denials, not just served requests.
#[tokio::test]
async fn completion_tap_fires_synthetic_rejected_by_gate() {
    let (server, state, tap) = webhook_tap().await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.tap_hooks_completion = vec![tap];
        inner.global_gates = vec![(0u16, canned_gate(Canned::Reject(451, "denied"), "denier"))];
    }
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 451);
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["at"], "completion");
    assert_eq!(payload["stage"]["outcome"], "rejected_by_gate");
    assert_eq!(payload["stage"]["status"], 451);
    server.shutdown().await;
}

/// STAGE TAPS: a completion tap reports `ok` + the status for a served request.
#[tokio::test]
async fn completion_tap_reports_ok_outcome() {
    let (server, state, tap) = webhook_tap().await;
    let lane = mock_lane("served").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            &lane.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .tap_hooks_completion = vec![tap];
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 200);
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["at"], "completion");
    assert_eq!(payload["stage"]["outcome"], "ok");
    assert_eq!(payload["stage"]["status"], 200);
    server.shutdown().await;
    lane.shutdown().await;
}

/// STAGE TAPS: an attempt tap carries the failover story — attempt number + dispatched target.
#[tokio::test]
async fn attempt_tap_carries_attempt_story() {
    let (server, state, tap) = webhook_tap().await;
    let lane = mock_lane("served").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            &lane.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .tap_hooks_attempt = vec![tap];
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 200);
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["at"], "attempt");
    assert_eq!(payload["stage"]["attempt_number"], 1);
    // Renamed target -> model (wire audit L10: one name for one concept — the same string
    // candidates[].model carries).
    assert_eq!(payload["stage"]["model"], "m0");
    assert!(
        payload["stage"].get("previous_failure").is_none(),
        "no failure precedes the first attempt"
    );
    server.shutdown().await;
    lane.shutdown().await;
}

/// STAGE TAPS: a route tap observes the post-reconcile candidate-set size.
#[tokio::test]
async fn route_tap_reports_surviving_candidates() {
    let (server, state, tap) = webhook_tap().await;
    let lane = mock_lane("served").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            &lane.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();
    Arc::get_mut(&mut app).expect("sole owner").tap_hooks_route = vec![tap];
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 200);
    let payload = wait_for_tap_body(&state).await;
    assert_eq!(payload["stage"]["at"], "route");
    assert_eq!(payload["stage"]["remaining_candidates"], 1);
    server.shutdown().await;
    lane.shutdown().await;
}

/// A rewrite-arm test gate: abstains as a decision, rewrites the message content on transform.
struct RewritingGate(&'static str);

#[async_trait::async_trait]
impl RoutingPolicy for RewritingGate {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        Ok(crate::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "rewriter"
    }
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> busbar_api::TransformOutcome {
        busbar_api::TransformOutcome::Rewrite(crate::hooks::wire::RewriteReply {
            messages: vec![serde_json::json!({"role": "user", "content": self.0})],
            tools: vec![],
        })
    }
}

/// REGRESSION (Headroom e2e finding): a committed GLOBAL REWRITE must reach the upstream on a
/// SAME-PROTOCOL passthrough. The pristine-bytes short-circuit re-emits the retained request
/// bytes verbatim; before the fix those were the PRE-rewrite bytes, so a global compressor's
/// output was silently discarded exactly on the fast path.
#[tokio::test]
async fn same_protocol_passthrough_carries_global_rewrite() {
    let state = Arc::new(crate::test_support::MockServerState::new());
    state.push(crate::test_support::MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "model": "m0",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = crate::test_support::MockServer::new(state.clone()).await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(), // anthropic ingress → anthropic lane: same-protocol
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();
    Arc::get_mut(&mut app).expect("sole owner").rewrite_hooks = vec![(
        std::time::Duration::from_millis(500),
        Arc::new(RewritingGate("COMPRESSED")),
    )];
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 200);
    let upstream_body = state
        .get_last_request_body()
        .expect("upstream must have been dispatched");
    let v: Value = serde_json::from_slice(&upstream_body).unwrap();
    assert_eq!(
        v["messages"][0]["content"], "COMPRESSED",
        "the upstream must see the REWRITTEN body on the same-protocol fast path"
    );
    server.shutdown().await;
}

/// REGRESSION (Headroom e2e finding): a POOL-scoped `prompt: rw` gate joins the phase-1
/// transform pass — its rewrite reaches the upstream (before the fix it fired as a decision
/// gate, its rewrite reply normalized to Abstain, and the request paid its deadline for
/// nothing).
#[tokio::test]
async fn pool_scoped_rw_gate_rewrites_the_body() {
    let state = Arc::new(crate::test_support::MockServerState::new());
    state.push(crate::test_support::MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "model": "m0",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = crate::test_support::MockServer::new(state.clone()).await;
    let mut rt = pool_runtime_with(&[], Vec::new());
    rt.rewrite_hooks = vec![(
        std::time::Duration::from_millis(500),
        Arc::new(RewritingGate("POOL-COMPRESSED")),
    )];
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .pool_runtime("p", rt)
        .build();
    let resp = fire(app, 1).await;
    assert_eq!(resp.status().as_u16(), 200);
    let upstream_body = state
        .get_last_request_body()
        .expect("upstream must have been dispatched");
    let v: Value = serde_json::from_slice(&upstream_body).unwrap();
    assert_eq!(
        v["messages"][0]["content"], "POOL-COMPRESSED",
        "a pool-scoped rw gate must rewrite the dispatched body"
    );
    server.shutdown().await;
}

/// A test policy whose decide always errors — the on_error-chain tests' failing primary.
struct ErroringPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for ErroringPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        Err("deliberately broken".into())
    }
    fn name(&self) -> &'static str {
        "erroring"
    }
}

/// ON_ERROR CHAIN: a failing gate's named fallback hook FIRES and its decision is honored
/// exactly as a primary's would be (here: the fallback rejects with 451).
#[tokio::test]
async fn on_error_fallback_hook_fires_and_decides() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(ErroringPolicy),
        on_error: crate::config::PolicyOnError::Weighted,
        on_error_chain: vec![crate::hooks::FallbackHook {
            policy: Arc::new(CannedGate {
                canned: Canned::Reject(451, "fallback says no"),
                name: "backup",
            }),
            timeout: std::time::Duration::from_millis(500),
            send_prompt: false,
            send_user: false,
            on_empty: crate::config::PolicyOnError::Reject,
        }],
        timeout: std::time::Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![(0u16, gate)];
    let resp = fire(app, 1).await;
    assert_eq!(
        resp.status().as_u16(),
        451,
        "the failed gate's fallback hook must fire and its reject must be honored"
    );
}

/// ON_ERROR CHAIN: every link failing lands on the chain's reserved TERMINAL (here `reject`
/// ⇒ fail-closed 503) — never a silent proceed.
#[tokio::test]
async fn on_error_chain_exhausted_applies_terminal() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(ErroringPolicy),
        on_error: crate::config::PolicyOnError::Reject,
        on_error_chain: vec![crate::hooks::FallbackHook {
            policy: Arc::new(ErroringPolicy), // the fallback fails too
            timeout: std::time::Duration::from_millis(50),
            send_prompt: false,
            send_user: false,
            on_empty: crate::config::PolicyOnError::Reject,
        }],
        timeout: std::time::Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![(0u16, gate)];
    let resp = fire(app, 1).await;
    assert_eq!(
        resp.status().as_u16(),
        503,
        "an exhausted chain must land on the fail-closed reject terminal"
    );
}

/// RECONCILE: a pool's OWN gate (from `PoolRuntime.gates`) fires in phase 2 — its reject
/// short-circuits before dispatch, proving the pool-gate half of the chain is wired.
#[tokio::test]
async fn pool_gate_reject_fires_from_pool_runtime_gates() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/", // dead — the reject must prevent dispatch
        ))
        .pool("p", &[(0, 1)])
        .pool_runtime(
            "p",
            pool_runtime_with(
                &[],
                vec![(
                    0u16,
                    canned_gate(Canned::Reject(451, "pool gate says no"), "pg"),
                )],
            ),
        )
        .build();
    let resp = fire(app, 1).await;
    assert_eq!(
        resp.status().as_u16(),
        451,
        "a pool gate in PoolRuntime.gates must fire in the phase-2 reconcile"
    );
}

/// RECONCILE: when several gates reject at once, the LOWEST-priority gate's status/message
/// surfaces (the chain sort is the tie-break) — regardless of injection order.
#[tokio::test]
async fn reject_priority_tie_break_surfaces_lowest_priority() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    // Deliberately injected out of order: the firing site's stable sort must put 1 before 5.
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![
        (
            5u16,
            canned_gate(Canned::Reject(451, "high priority number"), "late"),
        ),
        (
            1u16,
            canned_gate(Canned::Reject(452, "low priority number"), "early"),
        ),
    ];
    let resp = fire(app, 1).await;
    assert_eq!(
        resp.status().as_u16(),
        452,
        "the lowest-priority rejecting gate must supply the surfacing status"
    );
}

/// RECONCILE: two concurrent restricts INTERSECT. Disjoint tag sets empty the intersection and
/// fail closed (the fail-closed default on_empty ⇒ 503) — never allow-all.
#[tokio::test]
async fn multi_restrict_disjoint_intersection_fails_closed() {
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "eu-lane",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .lane(LaneSpec::new(
            "baa-lane",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .pool_runtime(
            "p",
            pool_runtime_with(&[(0, &["eu"]), (1, &["baa"])], Vec::new()),
        )
        .build();
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![
        (
            0u16,
            canned_gate(Canned::Restrict(vec!["eu".to_string()]), "geo"),
        ),
        (
            1u16,
            canned_gate(Canned::Restrict(vec!["baa".to_string()]), "hipaa"),
        ),
    ];
    let resp = fire(app, 2).await;
    assert_eq!(
        resp.status().as_u16(),
        503,
        "disjoint concurrent restricts must intersect to empty and fail closed"
    );
}

/// RECONCILE: two concurrent restricts INTERSECT to the one lane carrying BOTH tags — and the
/// request dispatches to exactly that lane (the restriction bounds dispatch, not just ranking).
#[tokio::test]
async fn multi_restrict_intersection_dispatches_only_the_survivor() {
    let survivor = mock_lane("both").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "eu-only",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/", // dead: dispatching here would error, not 200
        ))
        .lane(LaneSpec::new(
            "eu-baa",
            crate::proto::Protocol::anthropic(),
            &survivor.base_url(),
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .pool_runtime(
            "p",
            pool_runtime_with(&[(0, &["eu"]), (1, &["eu", "baa"])], Vec::new()),
        )
        .build();
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![
        (
            0u16,
            canned_gate(Canned::Restrict(vec!["eu".to_string()]), "geo"),
        ),
        (
            1u16,
            canned_gate(Canned::Restrict(vec!["baa".to_string()]), "hipaa"),
        ),
    ];
    let resp = fire(app, 2).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        body_model(resp).await,
        "both",
        "dispatch must stay inside the restrict intersection"
    );
    survivor.shutdown().await;
}

/// RECONCILE index-space: an ORDER captured at t0 naming only members a concurrent RESTRICT
/// excluded filters to empty ⇒ abstain — the request proceeds on the surviving set (never a
/// strand, never a resurrected excluded member).
#[tokio::test]
async fn stale_order_filtered_against_post_restrict_set() {
    let survivor = mock_lane("kept").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "excluded",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/", // dead: the stale order names ONLY this lane
        ))
        .lane(LaneSpec::new(
            "kept-lane",
            crate::proto::Protocol::anthropic(),
            &survivor.base_url(),
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .pool_runtime(
            "p",
            pool_runtime_with(&[(0, &["a"]), (1, &["b"])], Vec::new()),
        )
        .build();
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![
        (0u16, canned_gate(Canned::Order(vec![0]), "orderer")),
        (
            1u16,
            canned_gate(Canned::Restrict(vec!["b".to_string()]), "restrictor"),
        ),
    ];
    let resp = fire(app, 2).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        body_model(resp).await,
        "kept",
        "a t0 order naming only restricted-out members must abstain to the surviving set"
    );
    survivor.shutdown().await;
}

/// RECONCILE: with two ordering gates, the LAST in the chain wins. Both lanes are healthy, so
/// whichever order wins is dispatched first with no failover — the serving lane is the proof.
#[tokio::test]
async fn order_last_in_chain_wins() {
    let alpha = mock_lane("alpha").await;
    let beta = mock_lane("beta").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "lane-a",
            crate::proto::Protocol::anthropic(),
            &alpha.base_url(),
        ))
        .lane(LaneSpec::new(
            "lane-b",
            crate::proto::Protocol::anthropic(),
            &beta.base_url(),
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .build();
    Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![
        (0u16, canned_gate(Canned::Order(vec![0, 1]), "first")),
        (1u16, canned_gate(Canned::Order(vec![1, 0]), "second")),
    ];
    let resp = fire(app, 2).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        body_model(resp).await,
        "beta",
        "the LAST ordering gate in the chain must win the reconcile"
    );
    alpha.shutdown().await;
    beta.shutdown().await;
}

/// RECONCILE: a global gate ORDER is now honored (the previously-deferred arm): a single global
/// ordering gate reorders dispatch away from config order.
#[tokio::test]
async fn global_gate_order_arm_is_honored() {
    let alpha = mock_lane("alpha").await;
    let beta = mock_lane("beta").await;
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "lane-a",
            crate::proto::Protocol::anthropic(),
            &alpha.base_url(),
        ))
        .lane(LaneSpec::new(
            "lane-b",
            crate::proto::Protocol::anthropic(),
            &beta.base_url(),
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .build();
    Arc::get_mut(&mut app).expect("sole owner").global_gates =
        vec![(0u16, canned_gate(Canned::Order(vec![1]), "prefer-b"))];
    let resp = fire(app, 2).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        body_model(resp).await,
        "beta",
        "a global ordering gate must steer dispatch (the ORDER arm is live)"
    );
    alpha.shutdown().await;
    beta.shutdown().await;
}

/// `send_prompt: true` alone: the policy sees the flattened content; identity stays absent.
#[tokio::test]
async fn send_prompt_projects_content_only() {
    let (_, captured) = run(true, false, None, body()).await;
    let captured = captured.expect("policy must have been called");
    let (system, messages) = captured.prompt.expect("send_prompt on ⇒ prompt present");
    assert_eq!(system.as_deref(), Some("sys prompt"));
    assert_eq!(messages, vec![("user".to_string(), "hello".to_string())]);
    assert!(captured.identity.is_none(), "send_user off ⇒ no identity");
}

/// `send_user: true` alone: the policy sees the body's end-user id (no governance configured,
/// so the key fields are None); the prompt stays absent.
#[tokio::test]
async fn send_user_projects_identity_only() {
    let (_, captured) = run(false, true, None, body()).await;
    let captured = captured.expect("policy must have been called");
    assert!(captured.prompt.is_none(), "send_prompt off ⇒ no prompt");
    let (key_id, key_name, user) = captured.identity.expect("send_user on ⇒ identity present");
    assert_eq!(key_id, None, "no governance ⇒ no key id");
    assert_eq!(key_name, None, "no governance ⇒ no key name");
    assert_eq!(user.as_deref(), Some("alice"));
}

/// A policy Reject flows through the seam as `PolicyOutcome::RejectRequest` with the policy's
/// exact status/message and its name — NOT through `on_error` (a rejection is a decision, not
/// a failure).
#[tokio::test]
async fn reject_decision_maps_to_reject_request_outcome() {
    let (out, _) = run(true, false, Some((451, "PII detected".to_string())), body()).await;
    match out {
        PolicyOutcome::RejectRequest {
            status,
            message,
            name,
        } => {
            assert_eq!(status, 451);
            assert_eq!(message, "PII detected");
            assert_eq!(name, "capture");
        }
        other => panic!(
            "expected RejectRequest, got a different outcome: {}",
            outcome_kind(&other)
        ),
    }
}

fn outcome_kind(o: &PolicyOutcome) -> &'static str {
    match o {
        PolicyOutcome::Order { .. } => "Order",
        PolicyOutcome::Weighted => "Weighted",
        PolicyOutcome::Reject => "Reject",
        PolicyOutcome::RejectRequest { .. } => "RejectRequest",
        PolicyOutcome::Restrict { .. } => "Restrict",
    }
}

/// An absurd caller `max_tokens` (> u32::MAX) SATURATES in the projection instead of wrapping
/// to a small number — the SIZE signal must still read "huge ask" to the policy.
#[tokio::test]
async fn max_tokens_saturates_not_wraps() {
    let v = serde_json::json!({
        "model": "m0",
        "max_tokens": 5_000_000_000u64,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let (_, captured) = run(false, false, None, v).await;
    let captured = captured.expect("policy must have been called");
    assert_eq!(captured.max_tokens, Some(u32::MAX));
}

/// `send_user` with GOVERNANCE configured: the caller's secret resolves to its key record and
/// the policy sees the key's `id`/`name` — while the secret itself never appears anywhere in
/// the projection.
#[tokio::test]
async fn send_user_projects_governance_key_identity() {
    use crate::governance::{GovState, NewKeySpec, SqliteStore};
    let store = std::sync::Arc::new(SqliteStore::open_in_memory().expect("in-memory store"));
    let gov = std::sync::Arc::new(GovState::new(store, 0, 0, None).expect("gov state"));
    let (key, secret) = gov
        .create_key(
            NewKeySpec {
                name: "sales-team".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "monthly".to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1,
        )
        .expect("create key");

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    let seen = Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: seen.clone(),
            reject: None,
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: true,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let rc = RequestCtx::new(60);
    let v = body();
    decide_policy_order(
        &app,
        &resolved,
        &cands,
        &rc,
        &v,
        "p",
        "anthropic",
        false,
        Some(&secret),
        None,
    )
    .await;
    let captured = seen.lock().unwrap().clone().expect("policy called");
    let (key_id, key_name, user) = captured.identity.expect("identity present");
    assert_eq!(key_id.as_deref(), Some(key.id.as_str()));
    assert_eq!(key_name.as_deref(), Some("sales-team"));
    assert_eq!(user.as_deref(), Some("alice"));
    // The secret NEVER rides the projection, under any configuration.
    assert_ne!(key_id.as_deref(), Some(secret.as_str()));
    assert_ne!(key_name.as_deref(), Some(secret.as_str()));
}

/// REGRESSION (audit c1r10): a GROUP/SSO principal's token is not a virtual-key secret, so the
/// `decide_policy_order` token `lookup` MISSES — but the auth layer already synthesized a key
/// for it (`GovCtx.key`, threaded as `resolved_gov_key`). The identity projection must fall back
/// to that synthesized key so `send_user` policies see the caller, instead of silently `None`.
#[tokio::test]
async fn send_user_falls_back_to_synthesized_group_key_identity() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let seen = Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: seen.clone(),
            reject: None,
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: true,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    // A synthesized principal key exactly as the auth layer builds one for a group/SSO caller:
    // id/name carry the principal, key_hash is a non-secret marker never inserted into by_hash.
    let synth = crate::governance::VirtualKey {
        id: "eng-oncall".to_string(),
        key_hash: "principal:eng-oncall".to_string(),
        name: "eng-oncall".to_string(),
        allowed_pools: vec![],
        max_budget_cents: None,
        budget_period: "total".to_string(),
        rpm_limit: None,
        tpm_limit: None,
        enabled: true,
        created_at: 0,
    };
    let rc = RequestCtx::new(60);
    let v = body();
    // caller_token is the RAW SSO bearer — NOT a virtual-key secret, so lookup would miss.
    decide_policy_order(
        &app,
        &resolved,
        &cands,
        &rc,
        &v,
        "p",
        "anthropic",
        false,
        Some("sso-jwt-not-a-vkey-secret"),
        Some(&synth),
    )
    .await;
    let captured = seen.lock().unwrap().clone().expect("policy called");
    let (key_id, key_name, _user) = captured.identity.expect("identity present");
    assert_eq!(
        key_id.as_deref(),
        Some("eng-oncall"),
        "a group principal's synthesized key id must project, not fall through to None"
    );
    assert_eq!(key_name.as_deref(), Some("eng-oncall"));
}

/// REGRESSION (audit c1r11): the named / ad-hoc anthropic routes go through `forward_with_pool`,
/// which carries NO resolved key — so the c1r10 fallback never fired there and a group principal
/// on `/{pool}/v1/messages` was still routing-signal-blind. `forward_with_pool_keyed` threads
/// `GovCtx.key` down; this exercises that path end-to-end via a pool's `send_user` policy.
#[tokio::test]
async fn forward_with_pool_keyed_threads_group_key_to_pool_policy() {
    let seen = Arc::new(StdMutex::new(None));
    let policy = ResolvedPolicy::Policy {
        policy: Arc::new(CapturingPolicy {
            seen: seen.clone(),
            reject: None,
        }),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: true,
        on_empty: crate::config::PolicyOnError::Reject,
    };
    let mut rt = pool_runtime_with(&[(0, &[])], Vec::new());
    rt.policy = Some(policy);
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .pool_runtime("p", rt)
        .build();
    let synth = crate::governance::VirtualKey {
        id: "eng-oncall".to_string(),
        key_hash: "principal:eng-oncall".to_string(),
        name: "eng-oncall".to_string(),
        allowed_pools: vec![],
        max_budget_cents: None,
        budget_period: "total".to_string(),
        rpm_limit: None,
        tpm_limit: None,
        enabled: true,
        created_at: 0,
    };
    let body = Bytes::from(serde_json::to_vec(&body()).unwrap());
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    // The forward will fail to reach the fake upstream, but the routing policy captures FIRST.
    // caller_token is a non-vkey SSO bearer → lookup misses; only the threaded key can save it.
    let _ = forward_with_pool_keyed(
        app,
        cands,
        body,
        Some("sso-jwt-not-a-vkey-secret"),
        Some(&synth),
        "p",
        None,
        "anthropic",
        crate::handlers::chat("anthropic"),
        None,
    )
    .await;
    let captured = seen.lock().unwrap().clone().expect("pool policy ran");
    let (key_id, _name, _user) = captured.identity.expect("identity present");
    assert_eq!(
        key_id.as_deref(),
        Some("eng-oncall"),
        "forward_with_pool_keyed must thread the group key into the pool policy, not pass None"
    );
}

/// DEFENSE IN DEPTH at the seam: the shipped transports clamp/sanitize in `wire::normalize`,
/// but a policy impl can construct `RoutingDecision::Reject` directly — the mapping arm
/// re-clamps the status AND re-sanitizes the message, so no policy can mint a 5xx/success or
/// a log/client-injecting message through the reject path.
#[tokio::test]
async fn reject_status_and_message_resanitized_at_the_seam() {
    let (out, _) = run(
        false,
        false,
        Some((500, "evil\r\ninjected\u{202E}spoof".to_string())),
        body(),
    )
    .await;
    match out {
        PolicyOutcome::RejectRequest {
            status, message, ..
        } => {
            assert_eq!(status, 403);
            assert_eq!(message, "evilinjectedspoof", "seam must re-sanitize");
        }
        other => panic!(
            "expected RejectRequest, got a different outcome: {}",
            outcome_kind(&other)
        ),
    }
}

/// A hook 408 reject rides the Anthropic writer as the `timeout` typed error — the remaining
/// mapped kind not covered by the 451/429 envelope tests.
#[tokio::test]
async fn reject_408_maps_to_anthropic_timeout_envelope() {
    use http_body_util::BodyExt as _;
    let resp = ingress_error(
        "anthropic",
        StatusCode::from_u16(408).unwrap(),
        reject_kind_for_status(408),
        "guardrail: request deadline",
    );
    assert_eq!(resp.status().as_u16(), 408);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // The Anthropic writer's typed literal for KIND_TIMEOUT.
    assert_eq!(v["error"]["type"], "timeout_error");
    assert_eq!(v["error"]["message"], "guardrail: request deadline");
}

/// The FULL forward path: a request into a pool whose policy REJECTS comes back as the
/// dialect-native 4xx — hook status preserved, mapped error kind, sanitized message — with no
/// upstream dispatched (the lane's base_url is unroutable; reaching it would not yield a 451).
/// Closes the seam→response gap: everything from `forward_with_pool` through the
/// `RejectRequest` arm and `ingress_error` runs for real.
#[tokio::test]
async fn reject_rides_the_full_forward_path() {
    use http_body_util::BodyExt as _;
    let seen = Arc::new(StdMutex::new(None));
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://unused.invalid",
        ))
        .pool("pa", &[(0, 1)])
        .pool_runtime(
            "pa",
            crate::state::PoolRuntime {
                members: Default::default(),
                failover: None,
                affinity: None,
                breaker: None,
                policy: Some(ResolvedPolicy::Policy {
                    policy: Arc::new(CapturingPolicy {
                        seen: seen.clone(),
                        reject: Some((451, "PII detected".to_string())),
                    }),
                    on_error: crate::config::PolicyOnError::default(),
                    on_error_chain: Vec::new(),
                    timeout: std::time::Duration::from_millis(500),
                    send_prompt: false,
                    send_user: false,
                    on_empty: crate::config::PolicyOnError::Reject,
                }),
                gates: Vec::new(),
                rewrite_hooks: Vec::new(),
            },
        )
        .build();
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "pa",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 5
    }))
    .unwrap();
    let resp = forward_with_pool(
        app.clone(),
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        451,
        "the hook's status must reach the caller"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["type"], "error");
    assert_eq!(v["error"]["type"], "invalid_request_error"); // reject_kind_for_status(451)
    assert_eq!(v["error"]["message"], "PII detected");
    assert!(
        seen.lock().unwrap().is_some(),
        "the policy must actually have decided"
    );
}

/// The reject status → dialect error KIND mapping: an SDK caller must catch the right typed
/// exception class for the status the hook chose.
#[test]
fn reject_kind_mapping_matches_status_semantics() {
    assert_eq!(reject_kind_for_status(401), KIND_AUTHENTICATION);
    assert_eq!(reject_kind_for_status(403), KIND_PERMISSION);
    assert_eq!(reject_kind_for_status(404), KIND_NOT_FOUND);
    assert_eq!(reject_kind_for_status(408), KIND_TIMEOUT);
    assert_eq!(reject_kind_for_status(429), KIND_RATE_LIMIT);
    for other in [400, 422, 451, 499] {
        assert_eq!(reject_kind_for_status(other), KIND_INVALID_REQUEST);
    }
}

/// A hook reject rides `ingress_error` into a DIALECT-NATIVE envelope: the sanitized message
/// must appear verbatim in the error body, with the mapped kind and the hook's exact status —
/// here through the Anthropic writer (the ingress the reject tests route with).
#[tokio::test]
async fn reject_message_reaches_anthropic_error_body() {
    use http_body_util::BodyExt as _;
    let status = 451u16;
    let resp = ingress_error(
        "anthropic",
        StatusCode::from_u16(status).unwrap(),
        reject_kind_for_status(status),
        "PII detected in message 3",
    );
    assert_eq!(resp.status().as_u16(), 451);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["type"], "error");
    assert_eq!(
        v["error"]["message"], "PII detected in message 3",
        "the hook's sanitized reject message must reach the client verbatim"
    );
}

/// The same reject through the BEDROCK ingress writer: a valid Bedrock error envelope with the
/// `x-amzn-errortype` header — the reject path takes whatever dialect the caller spoke.
#[tokio::test]
async fn reject_produces_bedrock_native_envelope() {
    use http_body_util::BodyExt as _;
    let resp = ingress_error(
        "bedrock",
        StatusCode::from_u16(429).unwrap(),
        reject_kind_for_status(429),
        "quota guardrail: try later",
    );
    assert_eq!(resp.status().as_u16(), 429);
    assert!(
        resp.headers().get("x-amzn-errortype").is_some(),
        "Bedrock error envelope must carry x-amzn-errortype"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["message"], "quota guardrail: try later",
        "Bedrock error body carries the message field"
    );
}
