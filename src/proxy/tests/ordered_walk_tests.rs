
//! Tests for the routing-policy ORDERED WALK in `pick_among` (the audit-sensitive seam). The walk
//! must dispatch in the policy's ranked order while honoring EXACTLY the same health filter SWRR
//! honors (a tripped / dead / at-capacity preferred lane is skipped to the next), and fall through
//! to SWRR when no ranked lane qualifies — never stranding an unranked-but-healthy lane.
use super::{pick_among, RequestCtx};
use crate::state::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};

fn three_lane_app() -> std::sync::Arc<crate::state::App> {
    TestApp::new()
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
        .lane(LaneSpec::new(
            "m2",
            crate::proto::Protocol::anthropic(),
            "http://localhost",
        ))
        .pool("p", &[(0, 1), (1, 1), (2, 1)])
        .build()
}

fn cands() -> Vec<WeightedLane> {
    vec![
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
        WeightedLane {
            reasoning: None,
            idx: 2,
            weight: 1,
            attempt_timeout_ms: None,
        },
    ]
}

/// DRAIN: a `weight: 0` member must NOT be selected via the session-affinity sticky
/// fast-path — mirroring SWRR (`select_weighted_for`) and the routing-policy walk, which both
/// already exclude weight 0. Before the fix the sticky path consulted only dead/budget/breaker
/// (never weight), so a session whose hash landed on a drained-but-breaker-healthy member kept
/// pinning to it on the NORMAL path, silently defeating the operator's drain. Missed initially
/// because no prior test paired a non-None affinity key with a weight-0 candidate.
#[tokio::test]
async fn sticky_affinity_never_selects_zero_weight_drained_member() {
    let app = three_lane_app();
    // Single candidate, weight 0 (fully drained). The affinity key hashes to pos 0 (the only
    // candidate), so the sticky path is exercised ON the drained lane. With the drain gate it is
    // skipped, and SWRR (which also excludes weight 0) finds nothing → None. WITHOUT the gate this
    // returned `Some((0, _))` — the bug. (Deterministic: 1 candidate ⇒ pos is always 0.)
    let drained_only = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 0,
        attempt_timeout_ms: None,
    }];
    let mut rc = RequestCtx::new(60);
    let picked = pick_among(&app, &drained_only, &mut rc, Some("session-abc"), "p", None).await;
    assert!(
        picked.is_none(),
        "a drained (weight 0) member must never be stickily selected; got {:?}",
        picked.map(|(i, _)| i)
    );

    // Realistic drain: lane 0 drained, lane 1 healthy. For EVERY affinity key the result is lane 1
    // — whatever the hash position, the drained lane 0 is never returned (skipped on the sticky
    // path, excluded by SWRR), and selection falls through to the healthy lane.
    let drained_and_healthy = vec![
        WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 0,
            attempt_timeout_ms: None,
        },
        WeightedLane {
            reasoning: None,
            idx: 1,
            weight: 1,
            attempt_timeout_ms: None,
        },
    ];
    for key in ["s1", "s2", "session-xyz", "abc", "00000", "user-42"] {
        let mut rc = RequestCtx::new(60);
        let (idx, _permit) = pick_among(&app, &drained_and_healthy, &mut rc, Some(key), "p", None)
            .await
            .expect("the healthy lane is selectable");
        assert_eq!(
            idx, 1,
            "key {key:?} must route to the healthy lane, never the drained (weight 0) one"
        );
    }
}

/// The walk dispatches to the FIRST ranked lane that is healthy: order [2,0,1] all-healthy ⇒ 2.
#[tokio::test]
async fn ordered_walk_picks_first_preferred_when_healthy() {
    let app = three_lane_app();
    let mut rc = RequestCtx::new(60);
    let order = [2usize, 0, 1];
    let (idx, _permit) = pick_among(&app, &cands(), &mut rc, None, "p", Some(&order))
        .await
        .expect("a healthy preferred lane is selected");
    assert_eq!(idx, 2, "the #1 ranked healthy lane must be chosen");
}

/// A tripped (Open) preferred lane is SKIPPED to the next ranked lane — same health filter as SWRR.
#[tokio::test]
async fn ordered_walk_skips_tripped_preferred_to_next() {
    let app = three_lane_app();
    // Trip lane 2 (the #1 preference) Open with a cooldown well past the REAL wall clock that
    // `pick_among` reads (it passes `state::now()` to `ready_in`/SWRR), so the lane is not
    // breaker-ready. No test clock here — everything uses the real clock consistently.
    app.store
        .force_open_in("p", 2, crate::state::now() + 1_000_000);
    let mut rc = RequestCtx::new(60);
    let order = [2usize, 0, 1];
    let (idx, _permit) = pick_among(&app, &cands(), &mut rc, None, "p", Some(&order))
        .await
        .expect("falls to the next ranked lane");
    assert_eq!(
        idx, 0,
        "a tripped #1 preference is skipped to the #2 (lane 0)"
    );
}

/// An EXCLUDED preferred lane (already tried this request) is skipped to the next ranked lane.
#[tokio::test]
async fn ordered_walk_skips_excluded_preferred() {
    let app = three_lane_app();
    let mut rc = RequestCtx::new(60);
    rc.exclude(2); // lane 2 already tried
    let order = [2usize, 0, 1];
    let (idx, _permit) = pick_among(&app, &cands(), &mut rc, None, "p", Some(&order))
        .await
        .expect("excluded #1 falls to next");
    assert_eq!(idx, 0, "an excluded #1 preference is skipped");
}

/// When NO ranked lane qualifies (the policy ranked only lane 2, and it is tripped), the walk falls
/// THROUGH to SWRR over the remaining candidates — an unranked-but-healthy lane is still reachable.
#[tokio::test]
async fn ordered_walk_falls_through_to_swrr_when_no_preferred_ready() {
    let app = three_lane_app();
    app.store
        .force_open_in("p", 2, crate::state::now() + 1_000_000); // the only ranked lane is tripped
    let mut rc = RequestCtx::new(60);
    let order = [2usize]; // ranked subset of one, now unhealthy
    let (idx, _permit) = pick_among(&app, &cands(), &mut rc, None, "p", Some(&order))
        .await
        .expect("SWRR finds an unranked healthy lane");
    assert!(
        idx == 0 || idx == 1,
        "an unranked-but-healthy lane (0 or 1) must still be reachable via SWRR, got {idx}"
    );
}

/// An empty order (the contract's normalized Abstain shape never produces this, but defend it):
/// the walk has nothing preferred, so it falls straight through to SWRR.
#[tokio::test]
async fn ordered_walk_empty_order_is_swrr() {
    let app = three_lane_app();
    let mut rc = RequestCtx::new(60);
    let order: [usize; 0] = [];
    let (idx, _permit) = pick_among(&app, &cands(), &mut rc, None, "p", Some(&order))
        .await
        .expect("empty order behaves as SWRR");
    assert!(idx <= 2);
}

/// C2 (weight:0 drain): a policy that ranks a DRAINED (weight 0) lane #1 must NOT dispatch to it.
/// SWRR skips weight-0; the ordered walk now mirrors that, so the walk skips the drained #1 lane
/// to the next healthy ranked lane.
#[tokio::test]
async fn ordered_walk_skips_weight_zero_drained_preferred() {
    let app = three_lane_app();
    // Lane 2 drained (weight 0); 0 and 1 still serve.
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
        WeightedLane {
            reasoning: None,
            idx: 2,
            weight: 0,
            attempt_timeout_ms: None,
        },
    ];
    let mut rc = RequestCtx::new(60);
    // Policy ranks the drained lane #1.
    let order = [2usize, 0, 1];
    let (idx, _permit) = pick_among(&app, &cands, &mut rc, None, "p", Some(&order))
        .await
        .expect("a non-drained ranked lane is selected");
    assert_ne!(
        idx, 2,
        "a weight-0 (drained) lane must NOT be dispatched to"
    );
    assert_eq!(
        idx, 0,
        "the walk skips the drained #1 to the next ranked lane (0)"
    );
}

/// C2 corollary: when EVERY ranked candidate is drained (weight 0), the walk dispatches nothing
/// (it falls through to SWRR, which also skips weight-0, and SWRR finds none) — a fully-drained
/// set must not serve traffic.
#[tokio::test]
async fn ordered_walk_all_weight_zero_selects_none() {
    let app = three_lane_app();
    let cands = vec![
        WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 0,
            attempt_timeout_ms: None,
        },
        WeightedLane {
            reasoning: None,
            idx: 1,
            weight: 0,
            attempt_timeout_ms: None,
        },
        WeightedLane {
            reasoning: None,
            idx: 2,
            weight: 0,
            attempt_timeout_ms: None,
        },
    ];
    let mut rc = RequestCtx::new(60);
    let order = [0usize, 1, 2];
    let picked = pick_among(&app, &cands, &mut rc, None, "p", Some(&order)).await;
    assert!(
        picked.is_none(),
        "a fully-drained candidate set must select no lane, got {:?}",
        picked.map(|(i, _)| i)
    );
}
