
use super::{forward_with_pool, KIND_INVALID_REQUEST};
use crate::store::{now as store_now, BreakerState};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// REGRESSION (H1): on the degraded FallbackPool path, `forward_once` must record breaker outcomes
/// against the ROUTING POOL cell — NOT the default `""` cell. The fallback caller selects the
/// member via the pool cell and CAS-wins a single-flight HalfOpen probe on it; recording on `""`
/// left the pool cell wedged HalfOpen + `probe_in_flight` forever, benching the lane.
///
/// Case A — a fallback 2xx must CLOSE the POOL cell. The fb pool cell starts expired-Open (→
/// HalfOpen on dispatch); a served 200 must drive it HalfOpen→Closed (and leave the default cell
/// untouched, proving the recording targeted the pool cell, not `""`).
#[tokio::test]
async fn test_forward_once_fallback_2xx_closes_pool_cell_not_default() {
    // Fallback-pool member's upstream serves a clean 200.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    // Lane 0 = primary pool member, marked dead so the primary pool is EXHAUSTED → FallbackPool.
    // Lane 1 = the fallback-pool member that actually serves.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    // Drive the "fb" pool cell for lane 1 into expired-Open (cooldown_until in the PAST), so the
    // FallbackPool dispatch's `acquire_for_dispatch_in` transitions it Open→HalfOpen and CAS-wins
    // the recovery probe — the precise state H1 wedges.
    app.store.force_open_in("fb", 1, t0.saturating_sub(10));
    assert!(
        matches!(
            app.store.breaker_state_in("fb", 1),
            BreakerState::Open { .. }
        ),
        "precondition: fb pool cell is expired-Open"
    );

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        app.clone(),
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "FallbackPool must serve the 2xx"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The POOL cell must now be CLOSED (HalfOpen probe succeeded). Before the fix the success was
    // recorded on the "" cell, so the pool cell stayed HalfOpen forever.
    assert!(
        matches!(app.store.breaker_state_in("fb", 1), BreakerState::Closed),
        "fb POOL cell must close on a 2xx served via forward_once (H1); got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // And the recording must NOT have touched the default "" cell (it was never tripped here).
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (recording targeted the pool cell, not \"\")"
    );
    server.shutdown().await;
}

/// REGRESSION (H1) Case B — a fallback transport error must OPEN the POOL cell. The fb pool cell
/// starts expired-Open (→ HalfOpen on dispatch); a pre-response transport error (unreachable
/// member) must reopen the POOL cell (HalfOpen→Open), re-arming its cooldown — not the default
/// `""` cell. Before the fix the reopen hit `""`, leaving the pool cell wedged HalfOpen forever.
#[tokio::test]
async fn test_forward_once_fallback_transport_error_opens_pool_cell() {
    let t0 = store_now();
    // Lane 0 = dead primary (exhausts the primary pool). Lane 1 = fallback member pointed at an
    // unreachable address so the upstream call fails pre-response (transport error).
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1", // connect-refused → forward_once Err(transport) arm
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    app.store.force_open_in("fb", 1, t0.saturating_sub(10));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        app.clone(),
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    // The fb member is unreachable and the chain exhausts → a 5xx/503 to the client; the precise
    // status is not the assertion — the breaker state of the POOL cell is.
    let _ = response.status();
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The POOL cell must be OPEN (the failed half-open probe reopened it with a fresh cooldown).
    assert!(
        matches!(
            app.store.breaker_state_in("fb", 1),
            BreakerState::Open { .. }
        ),
        "fb POOL cell must reopen on a transport error via forward_once (H1); got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // The default "" cell must be untouched (still Closed) — the recording targeted the pool cell.
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (transport-error recording targeted the pool cell)"
    );
}

/// REGRESSION (HIGH #1 — the probe-LEAK class). A fallback-pool member that returns a NON-2xx
/// must leave its POOL cell USABLE, not wedged HalfOpen. `forward_once`'s same-protocol non-2xx
/// branch relays the error verbatim and records NO breaker outcome, so the single-flight
/// HalfOpen probe the fallback dispatch CAS-won on the pool cell is still in flight at the early
/// return. Without an explicit `release_probe_in` the cell stays HalfOpen + `probe_in_flight`
/// forever — every later request finds the probe "taken" and the lane is benched until the slow
/// out-of-band prober rescues it. The fix releases the probe (HalfOpen→Open, flag cleared,
/// expired cooldown intact) so the cell is immediately probe-eligible again.
///
/// Discriminator: after the non-2xx, the pool cell must be back to `Open` (NOT `HalfOpen`) AND
/// a fresh dispatch acquisition must be able to re-win the probe. Against the old code the cell
/// is wedged `HalfOpen` and the re-acquire returns false.
#[tokio::test]
async fn test_forward_once_fallback_non2xx_leaves_pool_cell_usable() {
    // The fallback member's upstream serves a 4xx (a non-2xx the degraded path relays verbatim,
    // recording no breaker outcome — the path that leaked the probe).
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::ServerError {
            status: StatusCode::BAD_REQUEST,
            body: json!({ "type": "error", "error": { "type": KIND_INVALID_REQUEST, "message": "bad" } }),
        });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    // Drive the "fb" pool cell into expired-Open so the FallbackPool dispatch CAS-wins the
    // single-flight HalfOpen recovery probe — the precise state the leak wedges.
    app.store.force_open_in("fb", 1, t0.saturating_sub(10));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        app.clone(),
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    // The verbatim non-2xx is relayed to the client (the status is not the point — the cell is).
    assert_eq!(
        response.status().as_u16(),
        400,
        "FallbackPool must relay the upstream non-2xx verbatim"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The probe must have been RELEASED: the pool cell is Open again (not wedged HalfOpen).
    assert!(
        !matches!(app.store.breaker_state_in("fb", 1), BreakerState::HalfOpen),
        "fb POOL cell must NOT be wedged HalfOpen after a non-2xx (HIGH #1 probe leak); got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // Cooldown-backoff fix: a non-2xx on a HalfOpen probe now RECORDS a transient failure (before
    // releasing the probe), which bumps the cooldown via exponential backoff — exactly like the
    // MAIN forward path's non-2xx branch. So the cell is Open but with a FUTURE cooldown: an
    // immediate re-acquire is refused (no base-interval re-probe with zero backoff anymore).
    // Before this fix the cooldown stayed expired and this returned true.
    assert!(
        !app.store.acquire_for_dispatch_in("fb", 1, store_now()),
        "fb POOL cell cooldown must be extended by backoff after a non-2xx probe failure \
             (no immediate re-probe)"
    );
    // Once the backoff cooldown elapses, the Open cell re-admits exactly one probe again — the
    // slot is not permanently benched, just backed off. A far-future instant clears the cooldown.
    assert!(
        app.store
            .acquire_for_dispatch_in("fb", 1, store_now().saturating_add(86_400)),
        "fb POOL cell must be re-acquirable once the backoff cooldown elapses"
    );
    // The default "" cell is never touched by the degraded path's recordings.
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (degraded path targets the pool cell only)"
    );
    server.shutdown().await;
}

/// REGRESSION (LOW #22): an A<->B FallbackPool cycle must terminate via the visited-pool guard,
/// NOT recurse back into the originating pool. The guard in `handle_fallback_pool` only
/// checks/marks the FALLBACK pool name, so an A->B->A chain was not caught on the second hop:
/// when B fell back to A, the guard saw A as unvisited and RE-ENTERED A's members. The fix marks
/// the ORIGINATING pool at the top of `handle_exhaustion_for_pool`, so the hop back to A is
/// recognized as a cycle and terminates with 503.
///
/// Discriminator topology: pool A's ORIGINATING member (lane 0) is dead and pool B's member
/// (lane 1) is dead, so both pools exhaust and the chain is A->B->A. Pool A is ALSO reachable as
/// a FALLBACK target whose member (lane 2) is a LIVE upstream serving 200. With the fix the
/// second hop to A is caught by the guard and the request 503s WITHOUT ever dispatching lane 2.
/// Against the old code the un-guarded re-entry into A dispatches lane 2 and returns 200 — so a
/// 200 here is the regression signature.
#[tokio::test]
async fn test_fallback_pool_a_b_a_cycle_terminates_via_guard() {
    // Lane 2 (pool A's FALLBACK member) is a live upstream that would serve 200 if the cycle
    // erroneously re-entered pool A. The guard must prevent that dispatch entirely.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        // Lane 0: pool A's ORIGINATING member — dead, so pool A exhausts on entry.
        .lane(
            LaneSpec::new(
                "a-origin",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        // Lane 1: pool B's member — dead, so pool B exhausts and falls back to A.
        .lane(
            LaneSpec::new(
                "b-member",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        // Lane 2: pool A's FALLBACK member — LIVE. Only reached if the cycle re-enters A (bug).
        .lane(LaneSpec::new(
            "a-fallback",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("A", &[(0, 1)])
        // A reachable as a fallback target routes to the live lane 2; B routes to the dead lane 1.
        .fallback_pool("A", &[(2, 1)])
        .fallback_pool("B", &[(1, 1)])
        // A -> B -> A cycle.
        .on_exhausted("A", crate::config::OnExhausted::FallbackPool("B".into()))
        .on_exhausted("B", crate::config::OnExhausted::FallbackPool("A".into()))
        .build();

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        app.clone(),
        // Originating candidate set for pool A = its dead member (lane 0) → A exhausts.
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "A",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    let status = response.status().as_u16();
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The A<->B cycle must terminate at the guard with 503 — NOT recurse back into A and serve
    // the live lane-2 200. A 200 here means the second-hop guard missed the cycle (the bug).
    assert_eq!(
        status, 503,
        "an A<->B fallback cycle must terminate via the visited-pool guard (503), not \
             re-enter pool A and serve its live member (200); got {status}"
    );
    server.shutdown().await;
}

/// REGRESSION (LOW #25): the upstream/breaker METRIC pool label must resolve to the ROUTED
/// MODEL name for the default (`""`) breaker cell — the cell shared by every direct/ad-hoc
/// (single-model) route via `forward()` — so those series correlate with `REQUESTS_TOTAL`
/// (which labels model-routed traffic by model, never `""`). For a NAMED pool the label is the
/// pool name verbatim. The breaker-CELL key is NOT repointed by this helper (that stays `""`);
/// only the metric LABEL is decoupled, which is exactly what `metric_pool_label` computes.
#[test]
fn test_metric_pool_label_resolves_model_for_default_cell() {
    use super::metric_pool_label;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-sonnet",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1",
        ))
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto::Protocol::openai(),
            "http://127.0.0.1:1",
        ))
        .build();

    // Default ("") cell → the routed lane's MODEL name (so upstream metrics align with
    // REQUESTS_TOTAL's model label instead of an empty-string series).
    assert_eq!(
        metric_pool_label(&app, "", 0),
        "claude-sonnet",
        "default-cell traffic must be labeled by the routed model, not the empty cell key"
    );
    assert_eq!(
        metric_pool_label(&app, "", 1),
        "gpt-4o",
        "the label tracks the specific routed lane's model"
    );
    // A NAMED pool keeps its pool name verbatim (bounded, operator-controlled label).
    assert_eq!(
        metric_pool_label(&app, "prod-pool", 0),
        "prod-pool",
        "named-pool traffic stays labeled by its pool name"
    );
}
