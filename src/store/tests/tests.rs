
use super::*;

fn make_lane_data(id: usize, max_permits: usize) -> LaneData {
    LaneData {
        model: format!("model-{}", id),
        provider: format!("provider-{}", id),
        max: max_permits,
        sem: Arc::new(Semaphore::new(max_permits)),
        limited: false,
        budget: -1,
        cooldown_until: 0,
        streak: 0,
        dead: false,
        dead_reason: String::new(),
        ok: 0,
        err: 0,
        client_fault: 0,
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
    }
}

/// D1 CARRY-OVER: health state follows the lane's stable IDENTITY across a store rebuild —
/// not its array position. A tripped per-pool breaker, hard-down latch, latency EWMA, and
/// counters all survive a rebuild that REORDERS the lane set and inserts a new lane in front;
/// the new lane starts fresh; a removed lane's snapshot is dropped.
#[test]
fn test_health_state_follows_identity_across_rebuild() {
    set_now_for_test(1000);
    // Store A: lanes [model-0, model-1] at idx 0/1.
    let a = InMemoryStore::new(vec![make_lane_data(0, 10), make_lane_data(1, 10)]);
    let cfg = BreakerCfg::default();
    // Trip model-1's breaker in pool "p" (error-rate: 5/5 >= 0.5) + teach it a latency.
    for _ in 0..5 {
        a.record_transient_in("p", 1, "5xx", &cfg, None);
    }
    assert!(!a.ready_in("p", 1, 1000), "model-1 tripped in pool p");
    a.record_latency_in("p", 1, 123.0);
    let snaps = a.export_health();
    assert_eq!(snaps.len(), 2);
    let s1 = snaps.iter().find(|s| s.model == "model-1").unwrap();
    assert!(
        !s1.cells.is_empty(),
        "the tripped pool cell must be exported"
    );

    // Store B: model-9 (NEW) first, then model-1 — model-1 moved from idx 1 to idx 1→? and
    // model-0 was REMOVED. Restore from A's snapshots.
    let b = InMemoryStore::new_with_limits_restored(
        vec![make_lane_data(9, 10), make_lane_data(1, 10)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    // model-1 (now idx 1 in a DIFFERENT lane set) is still tripped in pool "p".
    assert!(
        !b.ready_in("p", 1, 1000),
        "the tripped breaker must follow model-1's identity into the new store"
    );
    // Its latency EWMA survived too.
    assert_eq!(
        b.lane_latency_ms(1),
        a.lane_latency_ms(1),
        "latency EWMA carries by identity"
    );
    // The NEW lane (idx 0) starts completely fresh.
    assert!(b.ready_in("p", 0, 1000), "a new lane starts fresh");
    assert_eq!(b.lane_latency_ms(0), None, "no inherited latency");
    // model-0's snapshot had no surviving lane — dropped without error.
    let b_snaps = b.export_health();
    assert!(b_snaps.iter().all(|s| s.model != "model-0"));

    // And the carried state keeps EVOLVING normally: cooldown expiry recovers the lane.
    set_now_for_test(1000 + 24 * 3600);
    assert!(
        b.usable_in("p", 1, 1000 + 24 * 3600),
        "a restored cooldown still expires on schedule (usable_in performs the \
             Open->HalfOpen probe transition)"
    );
}

/// D1: a restored HARD-DOWN latch (dead + reason) survives the rebuild and keeps blocking.
#[test]
fn test_hard_down_follows_identity_across_rebuild() {
    set_now_for_test(5000);
    let a = InMemoryStore::new(vec![make_lane_data(3, 4)]);
    a.record_hard_down(0, "auth rejected (HTTP 401)");
    assert!(!a.usable(0, 5000), "hard-down blocks the default cell");
    let snaps = a.export_health();
    let b = InMemoryStore::new_with_limits_restored(
        vec![make_lane_data(3, 4)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert!(!b.usable(0, 5000), "hard-down must survive the rebuild");
    let restored = &b.export_health()[0];
    // Hard-down is recoverable-by-design (sticky Open + cooldown, NOT the dead latch); the
    // reason string + the default-cell Open state are what carry.
    assert_eq!(restored.dead_reason, "auth rejected (HTTP 401)");
}

/// REGRESSION (audit c1r6): a snapshot captured while a lane's single-flight probe was in flight
/// carries `ST_HALF_OPEN`. Restoring it verbatim WEDGES the cell (HalfOpen is rejected by both
/// `cell_ready_breaker`/`cell_acquire_breaker` and no probe outcome ever runs against a restored
/// cell whose `probe_in_flight` is false), benching the lane forever when health probing is off.
/// Restore must normalize HalfOpen → Open (the sibling-create path already did).
#[test]
fn restored_halfopen_state_normalizes_to_open() {
    // The pure helper both restore sites share.
    assert_eq!(restored_breaker_state(ST_HALF_OPEN), ST_OPEN);
    assert_eq!(restored_breaker_state(ST_OPEN), ST_OPEN);
    assert_eq!(restored_breaker_state(ST_CLOSED), ST_CLOSED);

    // End to end: a snapshot with a HalfOpen lane-global state restores as Open, not wedged.
    set_now_for_test(9000);
    let a = InMemoryStore::new(vec![make_lane_data(3, 4)]);
    let mut snaps = a.export_health();
    snaps[0].breaker_state = ST_HALF_OPEN; // as if captured mid-probe
    let b = InMemoryStore::new_with_limits_restored(
        vec![make_lane_data(3, 4)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert_eq!(
        b.get_lane(0).breaker_state.load(Ordering::Relaxed),
        ST_OPEN,
        "a restored HalfOpen must become Open, or the lane wedges and never self-recovers"
    );
}

/// REGRESSION (audit c1r7): `restore_health_impl` must not overwrite a newly-LIMITED lane's cap
/// with the unlimited sentinel (-1) a prior UNLIMITED snapshot carries. `export_health` writes -1
/// for an unlimited lane; if the operator later adds `max_requests` to that lane, blindly storing
/// -1 over the fresh cap makes `lane_admissible` (`limited && budget <= 0`) reject EVERY dispatch
/// with no self-recovery. Restore is gated on `lane.limited && snap.budget >= 0`.
#[test]
fn restore_does_not_clobber_new_limit_with_unlimited_sentinel() {
    set_now_for_test(9000);
    // Snapshot taken while the lane was UNLIMITED → exports budget -1.
    let unlimited = InMemoryStore::new(vec![make_lane_data(3, 4)]);
    let snaps = unlimited.export_health();
    assert_eq!(
        snaps[0].budget, -1,
        "an unlimited lane exports the -1 sentinel"
    );

    // New config ADDS max_requests to the same identity (model-3/provider-3).
    let limited_ld = LaneData {
        limited: true,
        budget: 100,
        ..make_lane_data(3, 4)
    };
    let restored = InMemoryStore::new_with_limits_restored(
        vec![limited_ld],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert_eq!(
            restored.get_lane(0).budget.load(Ordering::Relaxed),
            100,
            "the fresh cap must survive; the unlimited -1 sentinel must NOT clobber it (lane would wedge)"
        );
    assert!(
        restored.usable(0, 9000),
        "the newly-limited lane must remain admissible, not permanently benched"
    );

    // And a genuine limited→limited carry-over still copies the REMAINING budget.
    let mut spent = snaps.clone();
    spent[0].budget = 40; // as if 60 of 100 were already spent before the snapshot
    let carried = InMemoryStore::new_with_limits_restored(
        vec![LaneData {
            limited: true,
            budget: 100,
            ..make_lane_data(3, 4)
        }],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &spent,
    );
    assert_eq!(
        carried.get_lane(0).budget.load(Ordering::Relaxed),
        40,
        "limited→limited must carry the remaining budget, not reset to the full cap"
    );

    // REGRESSION (audit c1r8): a LOWERED cap must CLAMP the carried remaining budget — carrying a
    // larger old remaining over a smaller new cap would over-serve past the operator's new hard
    // ceiling. old cap 500, 100 served → snap remaining 400; new cap 300 → must clamp to 300.
    let mut over = snaps.clone();
    over[0].budget = 400;
    let clamped = InMemoryStore::new_with_limits_restored(
        vec![LaneData {
            limited: true,
            budget: 300, // operator LOWERED max_requests
            ..make_lane_data(3, 4)
        }],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &over,
    );
    assert_eq!(
        clamped.get_lane(0).budget.load(Ordering::Relaxed),
        300,
        "a carried remaining above the NEW cap must clamp to the cap, not over-serve"
    );
}

#[test]
fn test_floor_prevents_trip() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Set a fixed time for testing
    set_now_for_test(1000);

    // min_requests is 5 by default; only record 4 errors (below floor)
    for _ in 0..4 {
        store.record_outcome_error_with_time(0, 1000);
    }

    // Still usable because below err threshold (simplified check)
    assert!(store.usable(0, 1000), "should remain usable below floor");
}

#[test]
fn test_trip_on_error_rate() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Drive the actual record path (which evaluates should_trip) — the raw
    // record_outcome_error_with_time helper only seeds the window and never trips. Default cfg:
    // error-rate, min_requests=5, threshold=0.5. Five errors → 5/5 = 1.0 >= 0.5 → trip.
    let cfg = BreakerCfg::default();
    for _ in 0..5 {
        store.record_transient(0, "5xx", &cfg, None);
    }

    let state = store.breaker_state(0);
    assert!(
            matches!(state, BreakerState::Open { .. }),
            "error-rate breaker must trip Open once min_requests met and fraction >= threshold (got {state:?})"
        );
    // The tripped lane is unusable during its cooldown.
    assert!(
        !store.usable(0, 1000),
        "a tripped (Open) lane must not be usable during its cooldown"
    );
}

/// REGRESSION (#29): `cell_record_failure` (via `record_transient`/`record_rate_limit`) must
/// RETURN `true` exactly on a logical Closed→Open trip, so the forward.rs call sites emit
/// `BREAKER_TRIPS_TOTAL` once per trip. Sub-threshold failures return `false`; the failure that
/// breaches the threshold returns `true`; further failures on the already-Open cell return `false`
/// (no multi-count); and a HalfOpen→Open reopen (failed recovery probe) is NOT a fresh trip.
#[test]
fn test_record_failure_returns_true_only_on_threshold_trip() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    // Default cfg: error-rate, min_requests=5, threshold=0.5. The first four errors are below the
    // min_requests floor → no trip → false.
    let cfg = BreakerCfg::default();
    for n in 1..=4 {
        assert!(
            !store.record_transient(0, "5xx", &cfg, None),
            "failure {n} (below min_requests floor) must NOT report a trip"
        );
    }
    // The fifth error meets min_requests with fraction 1.0 >= 0.5 → Closed→Open trip → true.
    assert!(
        store.record_transient(0, "5xx", &cfg, None),
        "the threshold-breaching failure must report a Closed→Open trip (true)"
    );
    assert!(matches!(store.breaker_state(0), BreakerState::Open { .. }));
    // A further failure while already Open is a no-op → must NOT report a (duplicate) trip.
    assert!(
        !store.record_transient(0, "5xx", &cfg, None),
        "a failure on an already-Open cell must NOT report a fresh trip (no multi-count)"
    );

    // HalfOpen→Open reopen (failed recovery probe) is NOT a fresh Closed→Open trip.
    store
        .get_lane(0)
        .breaker_state
        .store(ST_HALF_OPEN, Ordering::Relaxed);
    assert!(
        !store.record_transient(0, "5xx", &cfg, None),
        "a HalfOpen→Open reopen (failed probe) must NOT report a fresh trip"
    );
    assert!(matches!(store.breaker_state(0), BreakerState::Open { .. }));
}

/// REGRESSION (R27 LOW #12): the consecutive-failure streak bump in `cell_record_failure` must
/// happen UNDER the per-cell `transition_lock`, serialized with the should_trip/compute_cooldown
/// read — NOT as an unconditional `fetch_add` BEFORE the lock. The old pre-lock bump let
/// concurrent failures over-count the streak before the first trip read the value, inflating the
/// first-trip escalation/cooldown level.
///
/// Deterministic exposure: hold the default cell's `transition_lock`, then drive a failure from
/// another thread. With the bump RELOCATED under the lock, the spawned failure blocks at the lock
/// and the streak CANNOT advance while we hold it (stays 0). The OLD code bumped the streak before
/// taking the lock, so the streak would advance to 1 even while the lock is held — this assertion
/// fails against the old code and passes after the fix.
/// REGRESSION (audit c2r1): with `base_cooldown_secs = 1` (the minimum config_validate permits),
/// the ±10% jitter can draw −1, and the clamp floor `duration / 2 = 1/2` truncates to 0 — so a
/// tripped cell got a ZERO cooldown and re-admitted instantly (`now >= cooldown_until`), the exact
/// zero-backoff the validator rejects a static `base = 0` to prevent. The floor is now
/// `(duration/2).max(1)`. Sweep the jitter seed (via the test clock) so the −1 draw is exercised;
/// the cooldown must NEVER be 0.
#[test]
fn cooldown_never_zero_for_base_one() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let lane = store.get_lane(0).clone();
    assert_eq!(lane.streak().load(Ordering::Relaxed), 0);
    let cfg = BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 1000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };
    // span = 3 for base=1, so ~1/3 of seeds draw jitter −1; the sweep is guaranteed to hit it.
    for t in 0..600u64 {
        set_now_for_test(t);
        let cd = InMemoryStore::compute_cooldown_with_retry_after(&*lane, t, &cfg, None, 3600);
        assert!(
            cd >= 1,
            "base_cooldown_secs=1 must never yield a 0 cooldown (t={t} gave {cd})"
        );
    }
}

/// REGRESSION (audit c2r3): the exponential backoff `base * 2^streak` must SATURATE, never wrap.
/// `checked_shl` guards only the shift COUNT (>= 64), not value overflow — `10u64.checked_shl(63)`
/// is `Some(0)` — so an EVEN `base_cooldown_secs` at a high streak wrapped to a ZERO cooldown
/// (tripped cell re-admits instantly) exactly when the lane is failing hardest.
#[test]
fn backoff_saturates_not_wraps_at_high_streak() {
    set_now_for_test(0);
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let lane = store.get_lane(0).clone();
    let cfg = BreakerCfg {
        base_cooldown_secs: 10, // EVEN base — the wrap-to-0 case
        max_cooldown_secs: 3600,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };
    // Drive the streak to the danger zone (>= 63) and sweep the jitter seed.
    for streak in [63u32, 64, 100, 1000] {
        lane.streak().store(streak, Ordering::Relaxed);
        for t in 0..80u64 {
            set_now_for_test(t);
            let cd = InMemoryStore::compute_cooldown_with_retry_after(&*lane, t, &cfg, None, 3600);
            assert!(
                    cd >= 1,
                    "even base at streak {streak} must saturate toward max, never wrap to 0 (t={t} gave {cd})"
                );
        }
    }
}

#[test]
fn test_streak_bump_is_serialized_under_transition_lock() {
    set_now_for_test(1000);
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    // Consecutive mode, n=2: the streak alone drives both the trip decision and the cooldown
    // shift, so an over-counted streak is directly observable.
    let cfg = BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 1000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    // The default ("") cell IS the LaneState, which implements BreakerCellAccess — grab its
    // transition lock the same way the record path does.
    let lane = store.get_lane(0).clone();
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        0,
        "fresh lane starts with streak 0"
    );

    let guard = lock_recover(lane.transition_lock());

    // Spawn a failure that must block on the transition lock we hold. The barrier gives a
    // deterministic handshake: the spawned thread rendezvous, then immediately calls
    // `record_transient`. After the rendezvous releases, the spawned thread runs the lock-free
    // prologue of `cell_record_failure` (outcome_window push + err bump + — in the OLD code — the
    // pre-lock `streak().fetch_add(1)`) and then blocks on the transition lock we still hold.
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let store_t = Arc::clone(&store);
    let cfg_t = cfg.clone();
    let barrier_t = Arc::clone(&barrier);
    let handle = std::thread::spawn(move || {
        // Mirror the recording thread's clock (the test clock is thread-local).
        set_now_for_test(1000);
        barrier_t.wait();
        store_t.record_transient(0, "5xx", &cfg_t, None)
    });

    barrier.wait();
    // After the rendezvous, give the spawned thread a real, generous window to execute its
    // lock-free prologue and PARK on the held transition lock. Under the OLD (buggy) placement the
    // streak `fetch_add` ran BEFORE the lock, so it has already advanced to 1 by now; under the FIX
    // the bump is AFTER the lock, so the parked thread leaves the streak untouched at 0.
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert_eq!(
            lane.streak().load(Ordering::Relaxed),
            0,
            "while the transition_lock is held, a concurrent failure must NOT advance the streak — \
             the bump is serialized UNDER the lock (old code bumped it before the lock, over-counting)"
        );

    // Release the lock; the parked failure now completes, bumping the streak to exactly 1 (no
    // trip yet: 1 < n=2).
    drop(guard);
    let tripped_first = handle.join().expect("record thread panicked");
    assert!(
        !tripped_first,
        "the first failure (streak 1 < n=2) must NOT trip"
    );
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        1,
        "after the lock releases, the serialized bump lands → streak exactly 1"
    );

    // A second serialized failure reaches streak exactly 2 == n → trips, and the cooldown uses
    // shift=2 (base 10 << 2 = 40, ±10% jitter, no retry-after floor), NOT an inflated level.
    let tripped_second = store.record_transient(0, "5xx", &cfg, None);
    assert!(
        tripped_second,
        "the second failure (streak 2 == n) must trip Closed→Open"
    );
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        2,
        "two serialized failures reach streak exactly 2 at the trip, not an inflated count"
    );
    let now = crate::store::now_for_test();
    let remaining = store.cooldown_remaining(0, now);
    // shift=2 → 40s ±10% (jitter band [36,44], lower clamp duration/2=20 inert here). An inflated
    // streak (shift>=3 → >=80s) would land WELL outside this window.
    assert!(
        (36..=44).contains(&remaining),
        "first-trip cooldown must reflect shift=2 (~40s ±10%), not an inflated escalation \
             level; got {remaining}s"
    );
}

/// REGRESSION (#21): the spend/refund contract the forward path's over-refund guard relies on.
/// `spend_budget` is a NO-OP returning `false` when the budget is already 0 (never driven
/// negative), while `refund_budget` UNCONDITIONALLY fetch_adds. So an UNGUARDED refund paired with
/// a no-op spend raises the budget ABOVE its cap — which the forward path now prevents by refunding
/// only when the spend actually decremented. This asserts both halves: a real spend→refund is the
/// exact inverse (cap preserved), and a no-op spend reports `false` (the guard's signal).
#[test]
fn test_spend_refund_budget_contract() {
    // Limited lane with budget 1.
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 1;
    let store = Arc::new(InMemoryStore::new(vec![ld]));

    // A real spend decrements to 0 and reports success.
    assert!(
        store.spend_budget(0),
        "spend on a positive budget must succeed"
    );
    assert_eq!(store.get_lane(0).budget.load(Ordering::Relaxed), 0);
    // Its paired refund is the exact inverse — back to the cap of 1, never above.
    store.refund_budget(0);
    assert_eq!(
        store.get_lane(0).budget.load(Ordering::Relaxed),
        1,
        "a refund paired with a real spend must restore the cap exactly"
    );

    // Now exhaust the budget and prove the no-op spend reports `false` (the guard signal): an
    // UNGUARDED refund here would push the budget to 1 — ABOVE the now-0 effective ceiling.
    assert!(store.spend_budget(0), "spend to drain to 0");
    assert_eq!(store.get_lane(0).budget.load(Ordering::Relaxed), 0);
    let spent_again = store.spend_budget(0);
    assert!(
        !spent_again,
        "spend on an exhausted (0) budget must be a no-op reporting false"
    );
    assert_eq!(
        store.get_lane(0).budget.load(Ordering::Relaxed),
        0,
        "the no-op spend must NOT drive the budget negative"
    );
    // The forward path guards on `spent_again == false` and SKIPS the refund. Demonstrate the
    // hazard the guard avoids: an unconditional refund would over-raise the budget.
    store.refund_budget(0); // simulates the OLD unconditional refund
    assert_eq!(
        store.get_lane(0).budget.load(Ordering::Relaxed),
        1,
        "an UNGUARDED refund over-raises the budget above its effective ceiling — this is why the \
             forward path must refund ONLY when `budget_spent` is true (#21)"
    );

    // Unlimited lane: spend reports `true` (no-op success), refund is a no-op — so the forward
    // guard never over- or under-counts an unlimited lane.
    let mut un = make_lane_data(1, 10);
    un.limited = false;
    un.budget = -1;
    let ustore = Arc::new(InMemoryStore::new(vec![un]));
    assert!(
        ustore.spend_budget(0),
        "spend on an unlimited lane must report true (so the forward guard treats it as spent)"
    );
    ustore.refund_budget(0);
    assert_eq!(
        ustore.get_lane(0).budget.load(Ordering::Relaxed),
        -1,
        "refund on an unlimited lane must be a no-op (budget stays the unlimited sentinel)"
    );
}

/// REGRESSION (#12): `is_ready_any_cell` (which `/healthz` uses) must report NOT-ready when the
/// lane is circuit-broken in EVERY cell — the default `""` cell AND every per-pool cell. Under
/// sustained pool-routed failures the per-pool cells trip Open while the default cell (touched only
/// by direct/adhoc routes) may also trip via hard-down/all-cells; once nothing can serve, healthz
/// must report not-ready. The default-cell-only `is_ready` could only ever see the `""` cell.
#[test]
fn test_is_ready_any_cell_false_when_every_cell_open() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    // Trip the default cell AND two per-pool cells Open with a future cooldown — the lane is
    // serviceable nowhere.
    store.force_open_in("", 0, now + 600);
    store.force_open_in("poolA", 0, now + 600);
    store.force_open_in("poolB", 0, now + 600);
    assert!(
        !store.is_ready_any_cell(0, now),
        "is_ready_any_cell must be NOT-ready when every cell (default + all pool cells) is Open"
    );
    // Recover ONE per-pool cell: the lane is serviceable again via that pool, so healthz must flip
    // back to ready — proving the all-cells check, not a default-cell-only read.
    store.recover_lane(0);
    assert!(
        store.is_ready_any_cell(0, now),
        "after recovery the lane is serviceable in some cell → is_ready_any_cell must be ready"
    );
}

/// REGRESSION (#18, R20 redo of R19): `lane_usable_any_cell` must NOT short-circuit on the
/// lane-default (`""`) cell when the lane has per-pool cells. The default cell IS the `LaneState`,
/// starts `ST_CLOSED`/`cooldown=0`, and is written ONLY by direct/ad-hoc routes — pool-routed
/// traffic NEVER touches it, so in production it stays "ready" forever. The R19 fix iterated all
/// cells but still checked the default cell FIRST and returned early on it, so `/healthz` and
/// `/stats usable` STILL over-reported ready when every per-pool cell was Open. Here every per-pool
/// cell is tripped Open while the default cell is left UNTOUCHED (its real production state). The
/// old short-circuit returns true (over-reports ready); the fix must return false.
#[test]
fn test_is_ready_any_cell_false_when_pool_cells_open_default_untouched() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    // Materialize two per-pool cells, then trip BOTH Open. The default `""` cell is deliberately
    // left in its pristine ST_CLOSED/cooldown=0 state — exactly what pool-routed traffic leaves it.
    store.force_open_in("poolA", 0, now + 600);
    store.force_open_in("poolB", 0, now + 600);
    assert!(
        store.is_ready(0, now),
        "sanity: the untouched default cell reads ready (the over-reporting source)"
    );
    assert!(
        !store.is_ready_any_cell(0, now),
        "every per-pool cell Open → lane is unserviceable for pool traffic; the always-ready \
             default cell must NOT make is_ready_any_cell report ready"
    );
    // Recover one per-pool cell → the lane can serve via that pool again → ready.
    store.recover_lane(0);
    assert!(
        store.is_ready_any_cell(0, now),
        "after recovery a per-pool cell admits → is_ready_any_cell must be ready"
    );
}

/// REGRESSION (#18, positive/fallback case): a lane with NO per-pool cells (direct/ad-hoc-only)
/// must fall back to the lane-default cell. With the default cell Open and no pool cells present,
/// `is_ready_any_cell` must report NOT-ready; recovering the default cell flips it back to ready.
#[test]
fn test_is_ready_any_cell_falls_back_to_default_when_no_pool_cells() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    // No per-pool cells materialized: the default cell is the only routed cell.
    store.force_open_in("", 0, now + 600);
    assert!(
        !store.is_ready_any_cell(0, now),
        "no pool cells + default cell Open → lane is unserviceable → not ready"
    );
    store.recover_lane(0);
    assert!(
        store.is_ready_any_cell(0, now),
        "default cell recovered (only routed cell) → ready"
    );
}

/// REGRESSION (LOW #16, TOCTOU): `recover_lane`'s close must re-validate suppression UNDER the
/// transition lock against the cooldown the probe OBSERVED, so a concurrent hard-down that re-arms
/// a STRICTER sticky cooldown after the snapshot is NOT clobbered. Here a probe observed a tripped
/// cell with cooldown `now+600`; before the close runs, a hard-down parks the SAME cell with the
/// sticky `HARD_DOWN_COOLDOWN_SECS` cooldown. The old unconditional close would close the cell and
/// drop the hard-down (recovering a lane that must stay parked). The fix must leave the cell Open
/// with the hard-down's later cooldown intact.
#[test]
fn test_recover_close_does_not_clobber_concurrent_harddown() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let observed = now + 600; // the (transient) cooldown a successful probe snapshotted.
                              // A concurrent hard-down wins the transition lock first and arms a STRICTER sticky cooldown.
    let sticky = now + HARD_DOWN_COOLDOWN_SECS; // 100_000 + 1800, strictly later than `observed`.
    store.force_open_in("", 0, sticky);
    // Recovery close runs with the STALE observed cooldown (what the probe saw before the re-arm).
    let closed = store.recover_close_if_recoverable("", 0, now, observed);
    assert!(
            !closed,
            "a hard-down re-armed a cooldown stricter than the probe observed → recovery must NOT close"
        );
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::Open { .. }),
        "the cell must remain Open after a clobber-suppressed recovery close"
    );
    assert_eq!(
        store.cell_cooldown_until("", 0),
        sticky,
        "the hard-down's sticky cooldown must survive the racing recovery close intact"
    );
}

/// REGRESSION (LOW #16, positive case): the under-lock re-validation must STILL recover a
/// legitimately tripped cell — i.e. the fix must not over-correct. A probe observes an Open cell
/// with a future cooldown and nothing re-arms it; the recovery close (observed == live cooldown)
/// must close the cell and clear the cooldown.
#[test]
fn test_recover_close_recovers_tripped_cell_when_unraced() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let observed = now + 600;
    store.force_open_in("", 0, observed);
    // No racing transition: the probe's observed cooldown equals the live cooldown.
    let closed = store.recover_close_if_recoverable("", 0, now, observed);
    assert!(
        closed,
        "an unraced tripped cell whose cooldown the probe observed must be recovered"
    );
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::Closed),
        "the recovered cell must be Closed"
    );
    assert_eq!(
        store.cell_cooldown_until("", 0),
        0,
        "recovery must clear the observed cooldown"
    );
}

/// REGRESSION (A4): a CLOSED cell carrying an EXPIRED (past) nonzero `cooldown_until` must NOT be
/// treated as suppressed. The under-lock check used `cooldown_until > 0`, so any lapsed cooldown
/// looked "still suppressed" → a spurious `cell_closed_locked` + SWRR reset on an already-recovered
/// lane. The fix threads the caller's `now` and checks `cooldown_until > now`. Here a Closed cell
/// has a past cooldown; the recovery close must report NOT-recovered (no spurious close).
#[test]
fn test_recover_close_ignores_expired_past_cooldown_on_closed_cell() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let past_cooldown = now - 600; // nonzero but already EXPIRED relative to `now`.
                                   // Cell is Closed (default state) with a stale past cooldown left over from a prior trip.
    {
        let c = store.cell("", 0);
        let _tx = lock_recover(c.transition_lock());
        c.cooldown_until().store(past_cooldown, Ordering::Release);
        c.breaker_state().store(ST_CLOSED, Ordering::Release);
    }
    // Recovery observes the past cooldown as `observed`. Under the OLD `> 0` check this would close
    // (suppressed == true); the fix's `> now` makes it a no-op.
    let closed = store.recover_close_if_recoverable("", 0, now, past_cooldown);
    assert!(
            !closed,
            "an already-expired (past) cooldown on a Closed cell is NOT a suppression → no spurious close (A4)"
        );
}

/// REGRESSION (#12, positive case): with the default cell Open BUT one per-pool cell Closed,
/// `is_ready_any_cell` must report ready (a pool lane CAN still serve) even though the
/// default-cell-only `is_ready` reads not-ready.
#[test]
fn test_is_ready_any_cell_true_when_a_pool_cell_is_ready() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    // Materialize a per-pool cell WHILE the lane is healthy (a fresh cell inherits the lane's
    // current state, so create it before tripping the default cell) and leave it Closed.
    let _ = store.usable_in("poolA", 0, now);
    // Now trip ONLY the DEFAULT cell Open.
    store.force_open_in("", 0, now + 600);
    assert!(
        !store.is_ready(0, now),
        "default cell is Open → default-cell-only is_ready is not-ready"
    );
    assert!(
        store.is_ready_any_cell(0, now),
        "a Closed pool cell makes the lane serviceable → is_ready_any_cell must be ready"
    );
}

/// Round-4 MEDIUM/correctness: cooldown jitter must be SYMMETRIC in [-r, +r] (r = duration/10),
/// not the old (-3r, +r) skew. The old code cast the u128 FNV seed `as i64` (frequently negative)
/// before `% (2r+1)`, so the centered jitter biased SHORTER. Trip a fresh lane across many
/// distinct time-seeds and assert every resulting cooldown stays within [0.9·duration,
/// 1.1·duration] — a value below 0.9·duration is only reachable under the old skewed formula
/// (the duration/2 lower clamp does not engage at these magnitudes).
#[test]
fn test_cooldown_jitter_is_symmetric() {
    let cfg = BreakerCfg::default(); // base 15, max 120
                                     // 5 consecutive errors → streak 5 → 15<<5 saturates to max 120; r = 12.
    let expected_base = cfg.max_cooldown_secs; // 120
    let r = expected_base / 10; // 12
    let lo = expected_base - r; // 108
    let hi = expected_base + r; // 132
    let mut saw_below_base = false;
    for seed in 0..400u64 {
        // Distinct time-seed per iteration drives a distinct jitter; fresh store so streak resets.
        set_now_for_test(1_000_000 + seed * 7);
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        for _ in 0..5 {
            store.record_transient(0, "5xx", &cfg, None);
        }
        let now = crate::store::now_for_test();
        let remaining = store.cooldown_remaining(0, now);
        assert!(
            remaining >= lo && remaining <= hi,
            "cooldown {remaining}s must stay within symmetric [{lo}, {hi}] (seed {seed})"
        );
        if remaining < expected_base {
            saw_below_base = true;
        }
    }
    // The jitter must actually exercise the SHORTER side too (not just lengthen) — otherwise the
    // sign handling is broken in the other direction.
    assert!(
        saw_below_base,
        "jitter must sometimes shorten the cooldown below the base (symmetric distribution)"
    );
}

/// Round-18 LOW/correctness: a small `base_cooldown_secs` must still get a real jitter spread.
/// When `duration < 10` the old `jitter_range = duration / 10` truncated to 0, so `span == 1` and
/// EVERY trip on a tight cooldown produced the identical value — no anti-thundering-herd desync
/// exactly when the herd is densest. With the band floored at >=1s, distinct time-seeds must yield
/// MORE THAN ONE distinct cooldown. This test FAILS on the old code (single value) and passes now.
#[test]
fn test_small_base_cooldown_still_jitters() {
    // base 4, default error-rate trip (min_requests 5) so a single error does NOT trip — it stays
    // Closed and arms a streak-1 cooldown: duration = 4 << 1 = 8 (< 10 → old jitter_range == 0).
    let cfg = BreakerCfg {
        base_cooldown_secs: 4,
        max_cooldown_secs: 120,
        honor_retry_after: false,
        trip: TripConfig::default(),
    };
    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..200u64 {
        set_now_for_test(1_000_000 + seed * 13);
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        store.record_transient(0, "5xx", &cfg, None); // streak 1, no trip
        let now = crate::store::now_for_test();
        seen.insert(store.cooldown_remaining(0, now));
    }
    assert!(
        seen.len() > 1,
        "a small base_cooldown must still jitter across seeds (got single value {seen:?}); \
             old code collapsed jitter_range to 0 for duration < 10"
    );
    // Sanity: the spread stays in a sane band around the base (8), never absurd.
    let &min = seen.iter().next().expect("non-empty");
    let &max = seen.iter().next_back().expect("non-empty");
    assert!(
        (4..=12).contains(&min) && (4..=12).contains(&max),
        "jittered small cooldowns must stay near the base 8 (saw {min}..={max})"
    );
}

/// Round-18 LOW/perf: memoizing the per-pool shard MUST NOT change selection semantics. The
/// memoized `swrr_shard` returns the SAME shard index as a fresh FNV-1a of the pool name, so a
/// selection sequence over the same pools/weights is identical before and after. Assert the
/// memoized lookup agrees with the pure recompute for every pool, and that repeated selections
/// produce a stable, reproducible sequence (the SWRR distribution the shard lock guards).
#[test]
fn test_swrr_shard_memo_preserves_selection() {
    set_now_for_test(1000);
    let store = Arc::new(InMemoryStore::new(vec![
        make_lane_data(0, 10),
        make_lane_data(1, 10),
    ]));
    // The memoized shard must equal the direct FNV recompute for assorted pool names (including
    // empty and repeats) — first touch and cached hit alike.
    for pool in ["", "alpha", "beta", "alpha", "gamma-pool", "", "beta"] {
        let memo = store.swrr_shard(pool) as *const _;
        let direct = &store.swrr_shards[swrr_shard_index(pool)] as *const _;
        assert_eq!(
            memo, direct,
            "memoized shard for {pool:?} must be the same lock as a fresh FNV recompute"
        );
    }
    // Selection sequence is deterministic and unchanged by memoization: same pool/weights/now
    // give the identical lane order on repeat (the shard lock only serializes; it never alters
    // which lane SWRR picks).
    let candidates = [0usize, 1];
    let weights = [3u32, 1];
    let mut seq_a = Vec::new();
    for _ in 0..8 {
        seq_a.push(store.select_weighted_in("alpha", &candidates, &weights, 1000));
    }
    // Fresh store, identical inputs → identical sequence (SWRR is deterministic from zeroed
    // current_weight). Proves memoization left selection bit-for-bit unchanged.
    let store2 = Arc::new(InMemoryStore::new(vec![
        make_lane_data(0, 10),
        make_lane_data(1, 10),
    ]));
    let mut seq_b = Vec::new();
    for _ in 0..8 {
        seq_b.push(store2.select_weighted_in("alpha", &candidates, &weights, 1000));
    }
    assert_eq!(
        seq_a, seq_b,
        "memoized shard must not change the SWRR selection sequence"
    );
}

/// Round-18 LOW/test-coverage: pin `now_for_test`'s documented behavior. "Unset" is signalled by
/// the `IN_TEST` flag alone — so `set_now_for_test(0)` is a LEGAL mock instant (epoch 0), not a
/// silent wall-clock fallback. This FAILS on the old code (the `val != 0` guard fell back to real
/// time for an injected 0) and passes now.
#[test]
fn test_set_now_for_test_zero_is_a_legal_mock_instant() {
    set_now_for_test(0);
    assert_eq!(
        crate::store::now_for_test(),
        0,
        "set_now_for_test(0) must pin the clock to 0, not fall back to wall-clock time"
    );
    // And a normal nonzero injection still works (no regression to the common path).
    set_now_for_test(4242);
    assert_eq!(crate::store::now_for_test(), 4242);
}

#[test]
fn test_client_fault_never_trips() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // ClientFault records nothing (success doesn't increment err)
    for _ in 0..100 {
        store.record_outcome_success_with_time(0, 1000);
    }

    assert!(store.usable(0, 1000), "should remain usable");

    let snap = store.snapshot(0, 1000);
    assert_eq!(snap.err, 0, "client faults should not increment err");
}

#[test]
fn test_cooldown_expiry_to_halfopen() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Put lane in Open state with specific until time
    set_now_for_test(2000);

    store
        .get_lane(0)
        .cooldown_until
        .store(1500, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);

    // Before expiry: not usable
    assert!(
        !store.usable(0, 1499),
        "should not be usable before cooldown"
    );

    // At/after expiry: the first call to usable() transitions Open→HalfOpen and wins the probe.
    assert!(
        store.usable(0, 2001),
        "first request in HalfOpen should win probe"
    );
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::HalfOpen),
        "an expired-cooldown Open lane must transition to HalfOpen on admission (got {state:?})"
    );
}

#[test]
fn test_hard_down_long_cooldown_and_recovery() {
    // hard-down → long sticky cooldown + Open, recoverable via the
    // probe, NOT a permanent `dead` kill.
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    store.record_hard_down(0, "billing / insufficient balance");

    let ls = store.get_lane(0);
    let until = ls.cooldown_until.load(Ordering::Relaxed);
    // NOT permanently dead (that would block recovery) — the core hard-down invariant.
    assert!(
        !ls.dead.load(Ordering::Relaxed),
        "hard-down must NOT set dead — it is recoverable"
    );
    // Open state with a LONG sticky cooldown (record uses HARD_DOWN_COOLDOWN_SECS).
    assert_eq!(
        ls.breaker_state.load(Ordering::Relaxed),
        1,
        "hard-down → Open"
    );
    // (Test around the ACTUAL `until` — the #[cfg(test)] global clock races across
    // parallel tests, so an absolute `now+1800` assert would be flaky; this is robust.)
    assert!(
        until > COOLDOWN_TRANSIENT_SECS,
        "sticky cooldown, not a short transient"
    );
    // Down during the sticky cooldown; recovers via the half-open probe after it.
    assert!(
        !store.usable(0, until - 1),
        "should be down during the sticky cooldown"
    );
    assert!(
        store.usable(0, until + 1),
        "hard-down lane must recover via the half-open probe once the long cooldown expires"
    );
}

#[test]
fn test_single_flight_probe() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Set time past cooldown to trigger HalfOpen transition
    set_now_for_test(2000);

    // Put lane in Open state with expired cooldown
    store
        .get_lane(0)
        .cooldown_until
        .store(1500, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);

    // First request: should transition to HalfOpen and try to acquire probe
    let first_usable = store.usable(0, 2000);

    println!(
        "first_usable={}, probe_in_flight={}",
        first_usable,
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed)
    );

    // Second request: should see HalfOpen with probe already in flight
    let second_usable = store.usable(0, 2000);

    println!(
        "second_usable={}, probe_in_flight={}",
        second_usable,
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed)
    );

    assert!(
        first_usable || second_usable,
        "exactly one should win probe"
    );
    assert!(
        !(first_usable && second_usable),
        "only ONE request should be usable as probe"
    );
}

#[test]
fn test_probe_success_to_closed() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Put lane in HalfOpen with a probe in flight
    store
        .get_lane(0)
        .probe_in_flight
        .store(true, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(2, Ordering::Relaxed);

    // Simulate probe success: transition to Closed
    store.closed_state(0, 1500);

    assert!(
        store.usable(0, 1500),
        "should be usable after probe success"
    );

    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::Closed),
        "a successful probe must close the breaker (got {state:?})"
    );
}

#[test]
fn test_probe_failure_to_open_with_escalated_cooldown() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Set baseline streak to 2
    store.get_lane(0).streak.store(2, Ordering::Relaxed);

    set_now_for_test(1500);

    // Put lane in HalfOpen state
    store.get_lane(0).breaker_state.store(2, Ordering::Relaxed);

    let state_before = store.breaker_state(0);
    assert!(
        matches!(state_before, BreakerState::HalfOpen),
        "lane should start HalfOpen for this probe-failure scenario (got {state_before:?})"
    );

    // Simulate probe failure via record_outcome_error_with_time + open_state
    store.record_outcome_error_with_time(0, 1500);

    let cfg = BreakerCfg::default();
    store.open_state(0, 1500, &cfg);

    // After failure: should be Open with escalated cooldown
    let state_after = store.breaker_state(0);
    match state_after {
        BreakerState::Open { until } => {
            assert!(
                until > 1500 + 15,
                "cooldown should be escalated (longer than base 15s)"
            );
        }
        _ => panic!("should transition to Open on probe failure"),
    }
}

/// Regression: a failed health probe carrying a `Retry-After`
/// must honor that server-requested cooldown floor — the prober now threads `retry_after` into
/// `record_probe_failure_all_cells` instead of hardcoding `None`. A probe failing with
/// retry_after=90s (larger than the streak-0 base backoff of 15s) must set the cooldown to at
/// least the retry_after floor.
#[test]
fn test_probe_failure_honors_retry_after_floor() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(50_000);
    store.get_lane(0).streak.store(0, Ordering::Relaxed);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig::default(),
    };
    // Put the default cell in HalfOpen so a SINGLE probe failure reopens it with the BASE
    // (un-escalated) ~15s backoff — small enough that a retry_after=90 clearly dominates,
    // isolating the floor from cooldown escalation.
    store
        .get_lane(0)
        .breaker_state
        .store(ST_HALF_OPEN, Ordering::Relaxed);
    store.record_probe_failure_all_cells(0, "health-probe", &|_pool| cfg.clone(), Some(90));
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert!(
            until >= 50_000 + 90,
            "probe failure must honor the retry_after=90 floor (got cooldown_until={until}, base ~15s would be ~50015)"
        );
    // Control: identical single reopen WITHOUT retry_after lands only the base backoff, well
    // below the 90s floor — proving the floor came from the threaded retry_after, not the base.
    let store2 = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(50_000);
    store2.get_lane(0).streak.store(0, Ordering::Relaxed);
    store2
        .get_lane(0)
        .breaker_state
        .store(ST_HALF_OPEN, Ordering::Relaxed);
    store2.record_probe_failure_all_cells(0, "health-probe", &|_pool| cfg.clone(), None);
    let until_no_ra = store2.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert!(
            until_no_ra < 50_000 + 90,
            "without retry_after the cooldown must be the base backoff (< 90s floor), got {until_no_ra}"
        );
}

#[test]
fn test_exhaustive_match_no_fallback() {
    // This test verifies that BreakerState is exhaustively matched
    // by checking all variants are handled in usable() and breaker_state()

    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Closed
    store.get_lane(0).breaker_state.store(0, Ordering::Relaxed);
    assert!(store.usable(0, 1000), "Closed should be usable");

    // Open (before expiry)
    store
        .get_lane(0)
        .cooldown_until
        .store(2000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);
    assert!(!store.usable(0, 1500), "Open before expiry not usable");

    // HalfOpen - regardless of probe_in_flight, should NOT be usable
    // (only the request that won CAS during Open->HalfOpen transition is allowed through)
    store
        .get_lane(0)
        .probe_in_flight
        .store(true, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(2, Ordering::Relaxed);
    assert!(
        !store.usable(0, 1500),
        "HalfOpen not usable (only via CAS winner)"
    );
}

// (test_dead_lane_never_usable removed —: hard-down no longer sets `dead`/permanent
// kill; it is now a recoverable long-cooldown. Coverage is in
// test_hard_down_long_cooldown_and_recovery. `dead` is reserved for future budget-kill.)

#[test]
fn test_streak_reset_on_success() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Set a high streak
    store.get_lane(0).streak.store(5, Ordering::Relaxed);

    set_now_for_test(1000);

    // Record success (which resets streak) - use the public API
    store.record_success(0);

    assert_eq!(
        store.get_lane(0).streak.load(Ordering::Relaxed),
        0,
        "streak should reset on success"
    );
}

/// MEDIUM/correctness (store.rs `cell_record_success` streak reset before the HalfOpen→Closed
/// CAS): a success recorded against a cell still in ST_OPEN — reachable via the bare
/// `record_success(lane)` on the degraded-forward path — must NOT zero the streak. In Consecutive
/// mode the streak drives the escalating backoff cooldown; wiping it on a still-Open cell resets
/// the per-cell failure memory and lets a persistently-failing upstream be re-probed more
/// aggressively than designed. The reset is now gated on `state != Open`.
#[test]
fn test_success_on_open_cell_preserves_streak_for_backoff_escalation() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    // Park the default cell Open with an accumulated streak (as after several consecutive
    // failures tripped the breaker and escalation is in progress).
    store
        .get_lane(0)
        .breaker_state
        .store(ST_OPEN, Ordering::Relaxed);
    store.get_lane(0).streak.store(5, Ordering::Relaxed);

    // A bare success lands on the still-Open cell (degraded-forward path). The HalfOpen→Closed
    // CAS fails (Open ≠ HalfOpen) so no recovery occurs — and the streak must be preserved.
    store.record_success(0);

    assert_eq!(
        store.get_lane(0).streak.load(Ordering::Relaxed),
        5,
        "a success on a still-Open cell must NOT zero the streak (preserves backoff escalation)"
    );
    assert_eq!(
        store.get_lane(0).breaker_state.load(Ordering::Relaxed),
        ST_OPEN,
        "the cell must remain Open (success on Open does not recover it)"
    );

    // Sanity: a success on a CLOSED cell still resets the streak (the normal happy path).
    store
        .get_lane(0)
        .breaker_state
        .store(ST_CLOSED, Ordering::Relaxed);
    store.get_lane(0).streak.store(4, Ordering::Relaxed);
    store.record_success(0);
    assert_eq!(
        store.get_lane(0).streak.load(Ordering::Relaxed),
        0,
        "a success on a Closed cell must reset the streak"
    );
}

#[test]
fn test_consecutive_trip_mode() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(4000);

    // Drive the actual record path with a Consecutive(n=3) config so should_trip genuinely
    // fires (incrementing streak directly never evaluated the trip condition — vacuous before).
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        },
    };
    // Two failures: streak=2 < n=3 → still Closed.
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "consecutive(n=3) must NOT trip before the 3rd failure"
    );
    // Third consecutive failure: streak=3 >= n=3 → Open.
    store.record_transient(0, "5xx", &cfg, None);
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::Open { .. }),
        "with 3 consecutive errors (n=3) the breaker must trip Open (got {state:?})"
    );
}

// --- configured-breaker wiring: the pool's BreakerCfg actually drives the trip decision ---

/// A Consecutive-mode config with n=2 trips after exactly 2 transient failures via the public
/// record path — proving the configured threshold (not the hardcoded err>=5) is what fires.
#[test]
fn test_configured_consecutive_trip_fires_at_n() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(5000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    // One failure: streak=1 < n=2 → still Closed.
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "one failure must not trip a consecutive(n=2) breaker"
    );

    // Second consecutive failure: streak=2 >= n=2 → Open.
    store.record_transient(0, "5xx", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "the configured consecutive threshold (n=2) must trip on the 2nd failure"
    );
}

/// With the DEFAULT config (error-rate, min_requests=5), the same 2 failures do NOT trip —
/// confirming the config is what changed behavior above, not some unconditional rule.
#[test]
fn test_default_error_rate_does_not_trip_below_floor() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(6000);

    let cfg = BreakerCfg::default(); // error-rate, min_requests=5
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);

    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "2 failures are below the default min_requests floor (5) → no trip"
    );
}

/// An error-rate config with a low floor trips once enough windowed failures exceed the
/// configured threshold.
#[test]
fn test_configured_error_rate_trip_fires() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(7000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 100,
            threshold: 0.5,
            min_requests: 3,
            consecutive_n: 99, // irrelevant in error-rate mode
        },
    };

    store.record_transient(0, "5xx", &cfg, None); // count=1 < 3
    assert_eq!(store.breaker_state(0), BreakerState::Closed);
    store.record_transient(0, "5xx", &cfg, None); // count=2 < 3
    assert_eq!(store.breaker_state(0), BreakerState::Closed);
    store.record_transient(0, "5xx", &cfg, None); // count=3, fraction=1.0 >= 0.5 → trip
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "error-rate breaker must trip once floor is met and fraction exceeds threshold"
    );
}

/// The config→runtime conversion maps every field (and defaults honor_retry_after + an absent
/// trip block).
#[test]
fn test_config_breaker_conversion() {
    let ccfg = crate::config::BreakerCfg {
        base_cooldown_secs: 7,
        max_cooldown_secs: 99,
        trip: Some(crate::config::BreakerTripConfig {
            mode: crate::config::BreakerTripMode::Consecutive,
            window_secs: 42,
            threshold: 0.8,
            min_requests: 9,
            consecutive_n: 4,
        }),
    };
    let rcfg = BreakerCfg::from(&ccfg);
    assert_eq!(rcfg.base_cooldown_secs, 7);
    assert_eq!(rcfg.max_cooldown_secs, 99);
    assert!(rcfg.honor_retry_after, "always honored (no config knob)");
    assert!(matches!(rcfg.trip.mode, TripMode::Consecutive));
    assert_eq!(rcfg.trip.window_s, 42);
    assert_eq!(rcfg.trip.consecutive_n, 4);

    // Absent trip block → ADR-0002 defaults.
    let bare = crate::config::BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 120,
        trip: None,
    };
    let rbare = BreakerCfg::from(&bare);
    assert!(matches!(rbare.trip.mode, TripMode::ErrorRate));
    assert_eq!(rbare.trip.min_requests, 5);
}

/// Full recovery cycle: a tripped lane whose half-open probe SUCCEEDS must return to Closed and
/// be usable again. Regression for the bug where record_success left the lane stuck HalfOpen
/// (probe_in_flight never cleared) so it was admitted exactly once then locked out forever.
#[test]
fn test_half_open_success_recovers_to_closed() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(3000);

    // Lane is Open with an expired cooldown.
    store
        .get_lane(0)
        .cooldown_until
        .store(2000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);

    // First request after expiry transitions to HalfOpen and wins the single-flight probe.
    assert!(store.usable(0, 3000), "first request should win the probe");
    assert_eq!(store.breaker_state(0), BreakerState::HalfOpen);

    // The probe succeeds → recovery completes: Closed, cooldown cleared, probe released.
    store.record_success(0);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "a successful half-open probe must close the breaker"
    );
    assert!(
        store.usable(0, 3001),
        "lane must be admitted again after recovery (not stuck HalfOpen)"
    );
    assert!(
        store.usable(0, 3002),
        "and keep being admitted — recovery is sticky, not a one-shot"
    );
    assert!(
        !store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "the single-flight probe must be released on recovery"
    );
}

/// Concurrency regression for the non-CAS Open→HalfOpen transition (Round 11 HIGH). Two threads
/// racing an expired-Open cell must yield EXACTLY ONE probe winner, and the `probe_in_flight`
/// flag must never end up wedged `true` on a cell that did not retain the probe. The old code
/// did `store(ST_HALF_OPEN)` unconditionally then a separate `probe_in_flight` CAS, so a delayed
/// store could clobber a concurrent `cell_closed` and force `probe_in_flight=true` on a Closed
/// cell — permanently benching the lane on the next Open cycle. The fix makes the state move a
/// single Open→HalfOpen CAS, with only the winner setting the probe.
#[test]
fn test_concurrent_open_to_half_open_single_probe_winner() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    // Many independent races to make the (formerly ~1-in-2) interleaving overwhelmingly likely.
    for _ in 0..2000 {
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;

        // Lane Open with an already-expired cooldown — both racers are probe-eligible.
        store
            .get_lane(0)
            .cooldown_until
            .store(1000, Ordering::Relaxed);
        store
            .get_lane(0)
            .breaker_state
            .store(ST_OPEN, Ordering::Relaxed);

        let winners = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                let winners = Arc::clone(&winners);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    if store.usable(0, now) {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("racing thread must not panic");
        }

        assert_eq!(
            winners.load(Ordering::Relaxed),
            1,
            "exactly one thread must win the single-flight recovery probe"
        );
        // Winner left the cell HalfOpen with the probe held.
        assert_eq!(
            store.breaker_state(0),
            BreakerState::HalfOpen,
            "the probe winner must leave the cell HalfOpen"
        );
        assert!(
            store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
            "the winner must hold the single-flight probe"
        );
    }
}

/// Companion race: probe winner SUCCEEDS (cell → Closed, probe cleared) while a second thread is
/// concurrently attempting the Open→HalfOpen acquisition. The loser must NOT clobber the Closed
/// state nor wedge `probe_in_flight=true` on the now-Closed cell. Drives the exact interleaving
/// this guards against: a delayed transition racing a completing `cell_closed`.
#[test]
fn test_concurrent_acquire_racing_probe_success_never_wedges_flag() {
    use std::sync::Barrier;

    for _ in 0..2000 {
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;
        store
            .get_lane(0)
            .cooldown_until
            .store(1000, Ordering::Relaxed);
        store
            .get_lane(0)
            .breaker_state
            .store(ST_OPEN, Ordering::Relaxed);

        // Thread A wins the probe (deterministically, before the race) and will report success.
        // Thread B races a fresh acquisition against A's success.
        let barrier = Arc::new(Barrier::new(2));

        let store_a = Arc::clone(&store);
        let barrier_a = Arc::clone(&barrier);
        let a = std::thread::spawn(move || {
            // A acquires the probe first so the cell is HalfOpen with probe held.
            assert!(store_a.usable(0, now), "A must win the initial probe");
            barrier_a.wait();
            // A's probe succeeds → cell_closed clears probe_in_flight and writes ST_CLOSED.
            store_a.record_success(0);
        });

        let store_b = Arc::clone(&store);
        let barrier_b = Arc::clone(&barrier);
        let b = std::thread::spawn(move || {
            barrier_b.wait();
            // B races against A's success. Whatever it observes, it must never wedge the flag.
            let _ = store_b.usable(0, now);
        });

        a.join().expect("A must not panic");
        b.join().expect("B must not panic");

        // After the dust settles the cell is either Closed (A's success won) or HalfOpen (B
        // re-acquired after A closed). In neither outcome may a Closed cell hold the probe.
        let state = store.breaker_state(0);
        let probe_held = store.get_lane(0).probe_in_flight.load(Ordering::Relaxed);
        match state {
            BreakerState::Closed => assert!(
                !probe_held,
                "a Closed cell must never retain probe_in_flight=true (wedged lane)"
            ),
            BreakerState::HalfOpen => assert!(
                probe_held,
                "a HalfOpen cell that B re-acquired must hold the probe"
            ),
            BreakerState::Open { .. } => {
                // Acceptable transient end-state only if the probe is not stuck held.
                assert!(!probe_held, "an Open cell must not retain the probe flag");
            }
        }
    }
}

/// HIGH (store.rs `cell_record_success` TOCTOU): a half-open probe SUCCESS racing a concurrent
/// `record_hard_down_all_cells` (billing exhaustion / invalid credential) must NEVER silently
/// recover the lane and drop the hard-down's sticky 30-minute cooldown. Before the fix the success
/// recorder did a plain `load(HalfOpen)` then an UNCONDITIONAL `store(ST_CLOSED)` (clearing the
/// cooldown), so a hard-down landing in the window between the read and the write was clobbered —
/// the parked credential-failure lane was instantly re-readied. The CAS (HalfOpen→Closed) makes
/// success own the transition only when it wins the race; if the hard-down moved the cell to Open
/// first, success leaves the sticky cooldown intact. Invariant pinned here: the final state is
/// never a Closed cell that still carries the hard-down cooldown, and an Open end-state always
/// keeps that cooldown — i.e. the hard-down is never silently dropped.
#[test]
fn test_concurrent_success_racing_hard_down_never_drops_sticky_cooldown() {
    use std::sync::Barrier;

    for _ in 0..2000 {
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;
        // Park the cell in HalfOpen (expired prior cooldown), as if a probe was just acquired.
        store
            .get_lane(0)
            .cooldown_until
            .store(1000, Ordering::Relaxed);
        store
            .get_lane(0)
            .breaker_state
            .store(ST_HALF_OPEN, Ordering::Relaxed);
        store
            .get_lane(0)
            .probe_in_flight
            .store(true, Ordering::Relaxed);

        let barrier = Arc::new(Barrier::new(2));

        // Thread A: the half-open probe SUCCEEDS (organic recovery path).
        let store_a = Arc::clone(&store);
        let barrier_a = Arc::clone(&barrier);
        let a = std::thread::spawn(move || {
            barrier_a.wait();
            store_a.record_success(0);
        });

        // Thread B: a concurrent hard-down (billing/auth) parks the lane with a sticky cooldown.
        let store_b = Arc::clone(&store);
        let barrier_b = Arc::clone(&barrier);
        let b = std::thread::spawn(move || {
            barrier_b.wait();
            store_b.record_hard_down_all_cells(0, "billing / insufficient balance");
        });

        a.join().expect("A must not panic");
        b.join().expect("B must not panic");

        let state = store.breaker_state(0);
        let cooldown = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
        match state {
            // Success won the CAS before the hard-down's store landed: legitimate full recovery,
            // cooldown cleared. (The hard-down's store(Open) must then have lost the race; if it
            // had landed last the state would be Open, handled below.)
            BreakerState::Closed => assert_eq!(
                cooldown, 0,
                "a Closed (recovered) cell must not retain a stale cooldown"
            ),
            // The hard-down won: the sticky cooldown MUST survive — success must not have cleared
            // it. This is the exact regression: a non-CAS success would have left state Open (from
            // the hard-down) but cleared the cooldown, re-readying a parked credential-failure lane.
            BreakerState::Open { until } => {
                assert!(
                        cooldown > now,
                        "a hard-down Open cell must keep its sticky cooldown (got {cooldown}, now {now})"
                    );
                assert!(until > now, "Open until must be in the future");
            }
            BreakerState::HalfOpen => {
                panic!("cell must not remain HalfOpen after both writers ran")
            }
        }
    }
}

// ── per-(pool, lane) breaker isolation ──────────────────────────────────────────────────────

/// Tripping a lane in one pool must NOT trip the same lane in another pool, nor the lane-default
/// cell — the core promise of per-(pool, lane) isolation.
#[test]
fn test_pool_breaker_isolation() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(8000);

    // Consecutive(n=1) so a single failure trips immediately.
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 1,
        },
    };

    // Trip lane 0 in pool "A".
    store.record_transient_in("A", 0, "5xx", &cfg, None);

    assert!(
        !store.usable_in("A", 0, 8000),
        "pool A's cell must be tripped"
    );
    assert!(
        store.usable_in("B", 0, 8000),
        "pool B's cell must be unaffected by pool A's trip"
    );
    assert!(
        store.usable(0, 8000),
        "the lane-default cell must be unaffected by pool A's trip"
    );
    assert!(
        store.lane_needs_probe(0, 8000),
        "lane is suppressed in at least one cell (pool A)"
    );

    // A successful health probe recovers EVERY cell for the lane.
    store.recover_lane(0);
    assert!(
        !store.lane_needs_probe(0, 8000),
        "recover_lane must clear every cell (probe tests the shared upstream)"
    );
    assert!(store.usable_in("A", 0, 8000), "pool A recovered");
}

/// HIGH/correctness (store.rs): a failure recorded against a NAMED pool must increment the
/// lane-global `err` counter the `/stats` snapshot reports — previously only the pool=`""` path
/// bumped it, so production (named-pool) traffic reported a permanently-zero error count.
#[test]
fn test_named_pool_failure_bumps_lane_global_err() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    assert_eq!(store.snapshot(0, 1000).err, 0, "starts at zero");
    store.record_transient_in("prod-pool", 0, "5xx", &cfg, None);
    store.record_transient_in("prod-pool", 0, "5xx", &cfg, None);
    assert_eq!(
        store.snapshot(0, 1000).err,
        2,
        "named-pool failures must increment the lane-global err counter (/stats observability)"
    );
}

/// Regression (store.rs:record_failure_for): a failure recorded via the BARE/default-cell path
/// (`pool == ""`, used by the degraded forward and direct/ad-hoc routes) must count the
/// lane-global `err` EXACTLY once, not twice. For `pool == ""`, `cell("", lane)` IS the LaneState
/// itself, so `cell_record_failure` already bumps `LaneState.err`; the previous unconditional
/// second bump in `record_failure_for` double-counted every default-cell failure, inflating the
/// public `/stats` err metric 2x. Symmetric to `test_named_pool_failure_bumps_lane_global_err`.
#[test]
fn test_default_cell_failure_counts_lane_global_err_once() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    assert_eq!(store.snapshot(0, 1000).err, 0, "starts at zero");
    // Bare default-cell path (pool == "") — the degraded/direct-route record_transient.
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.snapshot(0, 1000).err,
        3,
        "default-cell failures must count err exactly once each (was 2x before the fix)"
    );
}

/// LOW #12 (store.rs:cell_closed_locked): a default-cell recovery must NOT zero the lane-global
/// `err` counter the `/stats` snapshot reports. `c.err()` for the default cell IS `LaneState.err`,
/// a PUBLIC lifetime counter that must stay monotonic (like `LaneState.ok`). The breaker FSM never
/// reads `err()` (`should_trip` keys off `outcome_window` + `streak`), so the old
/// `c.err().store(0)` in `cell_closed_locked` was dead for the FSM yet reset the stats counter on
/// every recovery, making `LaneState.err` non-monotonic. Trip the default cell with N failures (so
/// `err == N`), recover the lane, and assert `err` is STILL N — the recovery clears health
/// (streak/window/cooldown/state) but leaves the observability counter intact.
#[test]
fn test_default_cell_recovery_does_not_zero_lane_err() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Trip the default cell (bare pool=="" path) with enough failures to open the breaker. Each
    // failure bumps the lane-global err counter.
    let failures = 50u64;
    for _ in 0..failures {
        store.record_transient(0, "5xx", &cfg, None);
    }
    assert_eq!(
        store.snapshot(0, 1000).err,
        failures,
        "each default-cell failure bumps the lane-global err counter"
    );

    // Advance past the cooldown so the lane is recovery-eligible, then recover it. recover_lane
    // closes the default cell via cell_closed_if_recoverable → cell_closed_locked — the exact path
    // that previously zeroed err.
    let cooled = 1000 + store.cooldown_remaining(0, 1000) + 1;
    set_now_for_test(cooled);
    store.recover_lane(0);

    // The breaker FSM health is reset (the lane is usable again)…
    assert!(
        !store.lane_needs_probe(0, cooled),
        "recover_lane must clear the tripped default cell"
    );
    // …but the PUBLIC lifetime err counter must remain monotonic — NOT zeroed by recovery (LOW #12).
    assert_eq!(
        store.snapshot(0, cooled).err,
        failures,
        "default-cell recovery must NOT zero the lane-global err counter (must stay monotonic)"
    );
}

/// HIGH (forward.rs pick_among): a single-flight recovery probe WON via
/// `acquire_for_dispatch_in` but then NOT dispatched (permit-wait timeout / shutdown) must be
/// RELEASED via `release_probe_in`, otherwise the cell stays HalfOpen with `probe_in_flight ==
/// true` and `usable_in` benches the lane forever. After release the lane must be re-probeable.
#[test]
fn test_release_probe_reverts_undispatched_probe_winner() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Trip the lane Open via failures, then advance past the cooldown so it is probe-eligible.
    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    // Win the probe (Open → HalfOpen + probe CAS true→).
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "first dispatch wins the recovery probe"
    );
    // While the probe is in flight, a second request cannot win it (HalfOpen admits only the winner).
    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "HalfOpen with an in-flight probe admits nobody else"
    );

    // The dispatch was abandoned (e.g. permit-wait timed out) → release the probe.
    store.release_probe_in("p", 0);

    // The lane must now be re-probeable: the next request can re-win the probe rather than being
    // permanently benched.
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after release_probe_in the lane must be re-probeable (not wedged HalfOpen)"
    );
}

/// HIGH (forward.rs pick_among SESSION-AFFINITY fast path): `usable_in` is the sticky-path
/// admission call, and — like `acquire_for_dispatch_in` — it WINS the single-flight probe as a
/// SIDE EFFECT (Open→HalfOpen + probe CAS) for an expired-Open lane. If the sticky path then fails
/// to get a concurrency permit and falls through WITHOUT `release_probe_in`, the cell is wedged
/// HalfOpen + probe_in_flight and benched forever. This proves both halves of the fix's premise:
/// (1) `usable_in` really does win/consume the probe (so a release is mandatory on the no-dispatch
/// exit), and (2) `release_probe_in` un-wedges it so organic traffic resumes.
#[test]
fn test_usable_in_wins_probe_and_must_be_released_on_sticky_path() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Trip the lane Open, then advance past the cooldown so it is probe-eligible.
    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    // The sticky fast path calls `usable_in` first. For an expired-Open lane this transitions to
    // HalfOpen and CAS-WINS the probe — returning true.
    assert!(
        store.usable_in("p", 0, cooled),
        "usable_in admits (and wins the probe for) an expired-Open lane on the sticky path"
    );
    // Proof the probe was consumed as a side effect: nobody else can win it now (HalfOpen).
    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "usable_in already won the single-flight probe; the lane is now HalfOpen and benched"
    );

    // The sticky path's `try_acquire` failed (permits saturated), so the request was NOT
    // dispatched. WITHOUT the fix the cell stays wedged HalfOpen forever; the fix releases it.
    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the sticky path releases the won-but-undispatched probe, the lane is re-probeable"
    );
}

/// MEDIUM/correctness (forward.rs ClientFault arm probe leak): a HalfOpen lane that wins the
/// single-flight recovery probe and then serves a request the upstream answers with a 4xx
/// (`Disposition::ClientFault`) must NOT be left wedged. The forward path's ClientFault arm calls
/// `record_client_fault` — which by design bumps ONLY an observability counter and does NOT clear
/// `probe_in_flight` (no breaker penalty for a caller's bad input) — and then returns. Without an
/// explicit `release_probe_in` the cell stays HalfOpen + probe_in_flight, benching the recovering
/// lane until the slow out-of-band prober resets it. This test pins both halves: (1)
/// `record_client_fault` alone leaves the probe held (proving the leak is real), and (2) the
/// `release_probe_in` the forward arm now calls makes the lane re-probeable on the next cooldown.
#[test]
fn test_client_fault_on_halfopen_lane_releases_probe() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Trip the lane Open, then advance past the cooldown so it is probe-eligible.
    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    // The dispatched request CAS-wins the recovery probe (Open → HalfOpen + probe true).
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "the client-fault request wins the recovery probe"
    );

    // The upstream answered 4xx → ClientFault. The forward arm records the client fault, which is
    // (correctly) breaker-neutral: it neither trips the lane nor releases the probe.
    store.record_client_fault(0);
    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "record_client_fault must NOT release the probe (still wedged HalfOpen at this point)"
    );

    // The forward ClientFault arm now releases the probe before returning, so the recovering lane
    // is immediately re-probeable rather than benched until the out-of-band prober rescues it.
    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the ClientFault arm releases the probe the lane must be re-probeable (not wedged)"
    );
}

/// MEDIUM/correctness (forward.rs ContextLength arm probe leak): a HalfOpen lane that wins the
/// recovery probe and then serves a request the upstream rejects as too large for its context
/// window (`Disposition::ContextLength`) must NOT be left wedged. ContextLength is a client-fault
/// variant — no breaker penalty — so the arm `continue`s to failover without recording any outcome
/// that clears `probe_in_flight`. Without an explicit `release_probe_in` the cell stays HalfOpen +
/// probe_in_flight and the lane is benched for normal-size requests until the slow prober resets
/// it. Proves the forward arm's `release_probe_in` leaves the lane re-probeable.
#[test]
fn test_context_length_on_halfopen_lane_releases_probe() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Trip the lane Open, then advance past the cooldown so it is probe-eligible.
    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    // The oversized request CAS-wins the recovery probe (Open → HalfOpen + probe true).
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "the context-length request wins the recovery probe"
    );
    // The ContextLength arm records NO breaker outcome (it only excludes context-bound candidates
    // and continues), so nothing has cleared the probe — the lane is wedged at this point.
    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "no breaker outcome was recorded; the probe is still held (wedged HalfOpen)"
    );

    // The forward ContextLength arm now releases the probe before `continue`, so the lane becomes
    // probe-eligible again immediately for normal-size requests.
    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the ContextLength arm releases the probe the lane must be re-probeable (not wedged)"
    );
}

/// MEDIUM/correctness (store.rs lock sites): `lock_recover` must recover the inner data from a
/// POISONED mutex instead of panicking. A `.lock().unwrap()` on the request path would panic on a
/// poisoned mutex, cascading into a total DoS (every later request touching it also panics). The
/// data is still valid after a poison, so we recover it.
#[test]
fn test_lock_recover_recovers_from_poison() {
    let m = std::sync::Arc::new(std::sync::Mutex::new(42u32));
    // Poison the mutex: panic while holding the guard, in a separate thread so this test survives.
    let m2 = m.clone();
    let _ = std::thread::spawn(move || {
        let _g = m2.lock().unwrap();
        panic!("poison the mutex while holding the guard");
    })
    .join();
    assert!(
        m.is_poisoned(),
        "the mutex must be poisoned after the panic"
    );
    // A bare `.lock().unwrap()` would now panic; `lock_recover` returns the still-valid inner data.
    let g = lock_recover(&m);
    assert_eq!(
        *g, 42,
        "lock_recover recovers the inner value past the poison"
    );
}

/// MEDIUM/correctness (store.rs cell() inheritance): a lazily-created per-pool cell must NOT
/// inherit a sibling's HalfOpen state. HalfOpen means "some OTHER cell owns the in-flight probe";
/// a freshly-created cell is born `probe_in_flight == false`, so an inherited HalfOpen wedges it
/// (both ready/acquire return false for HalfOpen, and no probe outcome ever runs against it) until
/// an out-of-band recover_lane fires — indefinitely with health probing disabled. The fix
/// normalizes inherited HalfOpen → Open so the (already-expired) cooldown drives a fresh probe.
#[test]
fn test_new_pool_cell_does_not_inherit_wedged_halfopen() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    // Drive the lane-DEFAULT cell (pool "") to HalfOpen: trip it Open, cool down, win the probe.
    for _ in 0..50 {
        store.record_transient(0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining(0, 1000) + 1;
    set_now_for_test(cooled);
    assert!(
        store.acquire_for_dispatch_in("", 0, cooled),
        "the default cell transitions Open → HalfOpen (probe won) here"
    );

    // Now a NEW pool's first request materializes a fresh cell while the sibling is HalfOpen.
    // With the fix it is born Open (cooldown already expired) → immediately probe-eligible, NOT a
    // wedged HalfOpen. So this first dispatch must be able to WIN a probe on the new cell.
    assert!(
        store.acquire_for_dispatch_in("freshpool", 0, cooled),
        "a new pool cell created while a sibling is HalfOpen must be probe-eligible, not wedged"
    );
}

/// HIGH/security (store.rs + 562): a hostile upstream `Retry-After` near `u64::MAX` must
/// NOT overflow `now + duration` (which would wrap `cooldown_until` into the past and instantly
/// re-ready a tripped lane — a breaker bypass). The honored value is clamped to an absolute
/// ceiling, and the add is saturating, so the lane stays tripped.
#[test]
fn test_hostile_retry_after_does_not_bypass_breaker() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg {
        honor_retry_after: true,
        ..BreakerCfg::default()
    };

    // A near-u64::MAX Retry-After (the `Retry-After: 18446744073709551615` attack).
    store.record_rate_limit_in("prod-pool", 0, 1000, &cfg, Some(u64::MAX));

    // The lane must be cooled down (tripped), NOT instantly ready again.
    assert!(
        !store.usable_in("prod-pool", 0, 1000),
        "a hostile Retry-After must not wrap the cooldown into the past (breaker bypass)"
    );
    // And the cooldown must be a sane bounded value, not now+u64::MAX wrapped.
    let remaining = store.cooldown_remaining_in("prod-pool", 0, 1000);
    assert!(
        remaining > 0 && remaining <= MAX_HONORED_RETRY_AFTER_SECS,
        "cooldown must be clamped to the absolute ceiling; got {remaining}s"
    );
}

/// LOW/correctness (store.rs): a healthy member with `weight: 0` (operator drain) must
/// never be selected. Without the filter an all-zero-weight set collapses to always picking the
/// first candidate.
#[test]
fn test_zero_weight_member_is_never_selected() {
    let store = Arc::new(InMemoryStore::new(vec![
        make_lane_data(0, 10),
        make_lane_data(1, 10),
    ]));
    set_now_for_test(1000);
    // Lane 0 weight 0 (drained), lane 1 weight 1. Every selection must pick lane 1.
    for _ in 0..20 {
        let picked = store.select_weighted_in("p", &[0, 1], &[0, 1], 1000);
        assert_eq!(picked, Some(1), "zero-weight lane 0 must never be selected");
    }
    // All-zero-weight → no selectable member.
    assert_eq!(
        store.select_weighted_in("p", &[0, 1], &[0, 0], 1000),
        None,
        "an all-zero-weight set selects nothing (every member drained)"
    );
}

/// ZERO-COST-DEFAULT PERF GATE (routing-policy feature). An in-crate, deterministic micro-bench
/// of the default selection seam (`select_weighted_in`) — the hot path a `route: weighted`
/// (default) pool takes. Captured as a BASELINE before the routing-policy seam refactor and
/// re-run after Phase E to prove the default path shows no regression. `#[ignore]` so it never
/// runs in the normal suite (timing is environment-sensitive); invoke explicitly with
/// `cargo test --release bench_select_weighted_in_seam -- --ignored --nocapture`. (criterion
/// would require restructuring this binary-only crate into a lib+bin to reach `pub(crate)`
/// internals; an `Instant`-based in-crate bench measures the EXACT same code with no crate
/// surgery — the honest, low-risk way to gate the default path.)
#[test]
#[ignore]
fn bench_select_weighted_in_seam() {
    let store = Arc::new(InMemoryStore::new(vec![
        make_lane_data(0, 100),
        make_lane_data(1, 100),
        make_lane_data(2, 100),
        make_lane_data(3, 100),
    ]));
    set_now_for_test(1000);
    let cands = [0usize, 1, 2, 3];
    let weights = [5u32, 3, 1, 1];
    // Warm up.
    for _ in 0..100_000 {
        std::hint::black_box(store.select_weighted_in(
            std::hint::black_box("bench-pool"),
            std::hint::black_box(&cands),
            std::hint::black_box(&weights),
            std::hint::black_box(1000),
        ));
    }
    let iters = 2_000_000u64;
    let start = std::time::Instant::now();
    for _ in 0..iters {
        std::hint::black_box(store.select_weighted_in(
            std::hint::black_box("bench-pool"),
            std::hint::black_box(&cands),
            std::hint::black_box(&weights),
            std::hint::black_box(1000),
        ));
    }
    let elapsed = start.elapsed();
    let per = elapsed.as_nanos() as f64 / iters as f64;
    println!(
        "BENCH select_weighted_in_seam: {iters} iters in {elapsed:?} => {per:.2} ns/iter \
             (4 candidates, weighted 5:3:1:1)"
    );
}

/// Per-lane latency EWMA (routing `fastest` signal): `None` before any sample; the first sample
/// seeds the EWMA exactly; subsequent samples fold in at α; non-finite/non-positive samples are
/// ignored (never poison the signal).
#[test]
fn test_lane_latency_ewma_records_and_reads() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    // No sample yet.
    assert_eq!(store.lane_latency_ms(0), None);
    // First sample seeds the EWMA exactly.
    store.record_latency_in("p", 0, 100.0);
    assert_eq!(store.lane_latency_ms(0), Some(100.0));
    // Second sample folds in at α=0.2: 0.2*200 + 0.8*100 = 120.
    store.record_latency_in("p", 0, 200.0);
    let v = store.lane_latency_ms(0).unwrap();
    assert!((v - 120.0).abs() < 1e-9, "EWMA must be 120, got {v}");
    // Garbage samples are ignored — the signal is unchanged.
    store.record_latency_in("p", 0, f64::NAN);
    store.record_latency_in("p", 0, 0.0);
    store.record_latency_in("p", 0, -5.0);
    let v2 = store.lane_latency_ms(0).unwrap();
    assert!(
        (v2 - 120.0).abs() < 1e-9,
        "bad samples must not move the EWMA, got {v2}"
    );
}

/// MEDIUM/performance (store.rs swrr shards): the SWRR lock is now per-pool (sharded), not a
/// single global lock. Correctness must be unchanged — each pool's weighted distribution stays
/// proportional and pool-local (disjoint pools share no `current_weight` state). Drive two
/// disjoint pools and assert each independently honors its own weights.
#[test]
fn test_sharded_swrr_keeps_per_pool_distribution_proportional() {
    let store = Arc::new(InMemoryStore::new(vec![
        make_lane_data(0, 100),
        make_lane_data(1, 100),
    ]));
    set_now_for_test(1000);
    // Pool A: 3:1 over lanes 0,1. Pool B (disjoint shard usage): 1:1 over the same lanes.
    let mut a0 = 0;
    let mut a1 = 0;
    for _ in 0..40 {
        match store.select_weighted_in("pool-A", &[0, 1], &[3, 1], 1000) {
            Some(0) => a0 += 1,
            Some(1) => a1 += 1,
            _ => unreachable!(),
        }
    }
    assert_eq!(a0, 30, "pool A: 3:1 weight => 30/40 to lane 0");
    assert_eq!(a1, 10, "pool A: 3:1 weight => 10/40 to lane 1");

    let mut b0 = 0;
    let mut b1 = 0;
    for _ in 0..40 {
        match store.select_weighted_in("pool-B", &[0, 1], &[1, 1], 1000) {
            Some(0) => b0 += 1,
            Some(1) => b1 += 1,
            _ => unreachable!(),
        }
    }
    assert_eq!(b0, 20, "pool B: 1:1 weight => even split");
    assert_eq!(b1, 20, "pool B: 1:1 weight => even split");
}

/// The pool cell read path (`cell`) must return the SAME `Arc<BreakerCell>` for repeated reads of
/// an existing (pool, lane) — the read-then-write fast path must not mint a duplicate cell that
/// would split a lane's per-pool breaker state across two objects.
#[test]
fn test_cell_read_path_returns_stable_identity() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    // First touch creates the cell (write path); subsequent reads (read path) must reuse it.
    store.record_success_in("p", 0);
    store.record_transient_in("p", 0, "x", &BreakerCfg::default(), None);
    // A failure recorded through the same cell must be visible on the next read of that cell —
    // proving the read path resolves the SAME object, not a fresh Closed duplicate.
    assert!(
        store.cell_err_for_test("p", 0) >= 1,
        "the read path must resolve the existing per-pool cell, not a fresh duplicate"
    );
}

/// The concurrency budget (max_requests) is lane-global: spending it through one pool must
/// exhaust it for every pool, since they share the one upstream.
#[test]
fn test_budget_is_lane_global_across_pools() {
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 1;
    let store = Arc::new(InMemoryStore::new(vec![ld]));
    set_now_for_test(8100);

    assert!(store.spend_budget(0), "first spend succeeds");
    assert!(
        !store.spend_budget(0),
        "lifetime budget of 1 is now exhausted"
    );
    // Exhaustion is visible from every pool's view (budget is checked on the shared lane).
    assert!(
        !store.usable_in("A", 0, 8100),
        "exhausted budget blocks pool A"
    );
    assert!(
        !store.usable_in("B", 0, 8100),
        "exhausted budget blocks pool B"
    );
    assert!(
        !store.usable(0, 8100),
        "exhausted budget blocks direct route"
    );
}

/// MEDIUM/correctness (forward.rs): a body transfer that fails AFTER the 2xx headers
/// (which optimistically spent one budget unit) must REFUND that unit — no usable response was
/// delivered, so a failed transfer must not permanently drain the lane's lifetime `max_requests`
/// budget. `refund_budget` is the inverse of one `spend_budget`.
#[test]
fn test_refund_budget_restores_a_spent_unit() {
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 2;
    let store = Arc::new(InMemoryStore::new(vec![ld]));
    set_now_for_test(8100);

    assert!(store.spend_budget(0), "spend 1 of 2");
    assert!(store.spend_budget(0), "spend 2 of 2 (now exhausted)");
    assert!(!store.spend_budget(0), "budget exhausted");

    // A failed body transfer refunds one of the two optimistic spends.
    store.refund_budget(0);
    assert!(
        store.spend_budget(0),
        "after a refund the lane has one spendable unit again"
    );
    assert!(
        !store.spend_budget(0),
        "and only one — refund is not a reset"
    );
}

/// `refund_budget` on an UNLIMITED lane is a no-op (nothing was ever spent): it must not turn an
/// unlimited lane into a counted one or otherwise perturb admission.
#[test]
fn test_refund_budget_unlimited_is_noop() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)])); // budget -1 = unlimited
    set_now_for_test(8100);
    store.refund_budget(0);
    assert!(store.spend_budget(0), "unlimited lane still spends freely");
    assert!(
        store.usable(0, 8100),
        "unlimited lane still usable after refund"
    );
}

/// HIGH/correctness (forward.rs): a hard-down trips the lane in EVERY cell — the default
/// ("") cell AND every existing per-pool cell — mirroring `recover_lane`'s all-cells reach. The
/// organic forward path previously tripped only the routing pool's cell, leaving the same dead
/// upstream Closed in the default cell (read by `named`/`adhoc`/direct routes) and other pools.
#[test]
fn test_record_hard_down_all_cells_trips_default_and_every_pool() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(9000);

    // Materialize per-pool cells for two pools by touching them (a successful op creates the
    // cell lazily), so the lane has a default cell PLUS pool "A" and pool "B" cells, all Closed.
    store.record_success_in("A", 0);
    store.record_success_in("B", 0);
    assert!(store.usable(0, 9000), "default cell starts usable");
    assert!(store.usable_in("A", 0, 9000), "pool A starts usable");
    assert!(store.usable_in("B", 0, 9000), "pool B starts usable");

    // A hard-down classified on a pool-routed request must trip ALL cells, not just one pool.
    store.record_hard_down_all_cells(0, "billing / insufficient balance");

    assert!(
        !store.usable(0, 9000),
        "default cell (named/adhoc/direct routes) MUST be tripped by an all-cells hard-down"
    );
    assert!(
        !store.usable_in("A", 0, 9000),
        "pool A cell MUST be tripped"
    );
    assert!(
        !store.usable_in("B", 0, 9000),
        "pool B cell MUST be tripped"
    );
    // Recoverable (not administratively dead) — the core hard-down invariant.
    assert!(
        !store.get_lane(0).dead.load(Ordering::Relaxed),
        "hard-down must NOT set dead — it recovers via the half-open probe"
    );
}

/// MEDIUM/correctness (store.rs spend_budget): under a concurrent burst, the `max_requests`
/// lifetime cap must be a HARD ceiling — the CAS gate may never drive the budget negative. The
/// pre-fix unconditional `fetch_sub` let up to `max_concurrent` extra requests over-spend.
#[test]
fn test_spend_budget_concurrent_never_over_spends() {
    use std::thread;
    const BUDGET: i64 = 50;
    const THREADS: usize = 16;
    const PER_THREAD: usize = 100;

    let mut ld = make_lane_data(0, 10_000);
    ld.limited = true;
    ld.budget = BUDGET;
    let store = Arc::new(InMemoryStore::new(vec![ld]));

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let s = store.clone();
        handles.push(thread::spawn(move || {
            let mut wins = 0usize;
            for _ in 0..PER_THREAD {
                if s.spend_budget(0) {
                    wins += 1;
                }
            }
            wins
        }));
    }
    let total_wins: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

    // Exactly BUDGET successful spends — never more (no over-spend) and never fewer (no lost
    // decrements). The budget atomic lands at exactly 0, never negative.
    assert_eq!(
        total_wins, BUDGET as usize,
        "exactly {BUDGET} spends may succeed under contention; got {total_wins}"
    );
    assert_eq!(
        store.get_lane(0).budget.load(Ordering::Relaxed),
        0,
        "budget must settle at exactly 0 — never driven negative by a concurrent burst"
    );
}

/// Concurrency stress: many OS threads hammer the store across two pools sharing one lane.
/// Verifies (a) the lane-global `ok` atomic is exact under contention, (b) per-pool error
/// counters stay isolated and exact (no lost updates, no cross-pool bleed, no panic/deadlock in
/// the lazy pool-cell map), exercising the per-(pool,lane) machinery under real parallelism.
#[test]
fn test_concurrent_pool_isolation_stress() {
    use std::thread;

    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10_000)]));

    // A trip config that never trips, so transient errors increment the cell's `err` cleanly
    // (each just arms a brief cooldown) and we can assert exact counts.
    let cfg = BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 1,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 1,
            threshold: 2.0,           // unreachable fraction
            min_requests: usize::MAX, // never meets the floor
            consecutive_n: u32::MAX,
        },
    };

    const THREADS: usize = 8;
    const ITERS: usize = 500;

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let s = store.clone();
        let c = cfg.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..ITERS {
                // Successes route via pool "A" (also bumps the lane-global ok counter).
                s.record_success_in("A", 0);
                // Transients route via pool "B" — must NOT affect pool A's cell.
                s.record_transient_in("B", 0, "5xx", &c, None);
                // Concurrent reads against both pools + a recovery, to stir the cells.
                let t = crate::store::now();
                let _ = s.usable_in("A", 0, t);
                let _ = s.usable_in("B", 0, t);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let total = (THREADS * ITERS) as u64;
    // (a) lane-global ok atomic is exact.
    assert_eq!(
        store.snapshot(0, crate::store::now()).ok,
        total,
        "lane-global ok must be exact under concurrency"
    );
    // (b) pool isolation held under load: B saw every transient, A saw none.
    assert_eq!(
        store.cell_err_for_test("B", 0),
        total,
        "pool B's cell must have recorded every transient (no lost updates)"
    );
    assert_eq!(
        store.cell_err_for_test("A", 0),
        0,
        "pool A's cell must be untouched by pool B's transients (isolation under load)"
    );
}

/// Regression: the error-rate trip must use WINDOWED errors, not the cumulative counter. Old
/// errors that have aged out of the window must not trip a lane whose recent traffic is clean.
#[test]
fn test_error_rate_ignores_stale_errors_outside_window() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: u32::MAX,
        },
    };

    // 100 errors long ago (raw helper: seeds the window + cumulative err without evaluating).
    set_now_for_test(1000);
    for _ in 0..100 {
        store.record_outcome_error_with_time(0, 1000);
    }
    // Advance well past the 30s window, then take clean recent traffic.
    set_now_for_test(2000);
    for _ in 0..5 {
        store.record_outcome_success_with_time(0, 2000);
    }
    // One recent error arrives. Windowed view: 5 successes + 1 error = 1/6 ≈ 0.17 < 0.5 → no
    // trip. (The old cumulative-error logic would have computed min(101,6)/6 = 1.0 and tripped.)
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "stale out-of-window errors must not trip a lane on clean recent traffic"
    );
}

/// Regression: a sub-threshold transient leaves the breaker Closed but arms a soft cooldown
/// (lane unusable). Dead-mode probing must still SEE it (`lane_needs_probe`) and `recover_lane`
/// must clear the cooldown — previously a soft-cooldown lane was Closed, so the tripped-only
/// gate skipped it and a single 5xx benched the lane for the full cooldown.
#[test]
fn test_soft_cooldown_is_probeable_and_recoverable() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(9000);
    // Never trips (min_requests unreachable), so the transient only arms a soft cooldown.
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: usize::MAX,
            consecutive_n: u32::MAX,
        },
    };

    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "sub-threshold transient must NOT trip the breaker"
    );
    assert!(
        !store.usable(0, 9000),
        "but the soft cooldown makes the lane unusable"
    );
    assert!(
        store.lane_needs_probe(0, 9000),
        "dead-mode probing must see a soft-cooldown lane"
    );

    store.recover_lane(0);
    assert!(
        store.usable(0, 9000),
        "a successful probe must clear the soft cooldown"
    );
    assert!(!store.lane_needs_probe(0, 9000));
}

#[test]
fn test_try_acquire_probe_exclusivity() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Put lane in HalfOpen state manually
    store.get_lane(0).breaker_state.store(2, Ordering::Relaxed);

    // First acquisition should succeed
    assert!(
        store.try_acquire_probe(0),
        "first probe acquisition should succeed"
    );

    // Second acquisition should fail (probe already in flight)
    assert!(
        !store.try_acquire_probe(0),
        "second probe acquisition should fail"
    );
}

#[test]
fn test_clear_probe_after_success() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Acquire the probe
    assert!(store.try_acquire_probe(0), "should acquire probe");

    // Clear it (simulating successful completion)
    store.clear_probe(0);

    // Should be able to acquire again
    assert!(
        store.try_acquire_probe(0),
        "should be able to re-acquire after clear"
    );
}

#[test]
fn test_bounded_window_memory() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Add more entries than window capacity
    for i in 0..2000 {
        store.record_outcome_error_with_time(0, 1000 + i as u64);
    }

    // Window should be bounded (max ~1024 entries)
    let window = store.get_lane(0).outcome_window.lock().unwrap();
    assert!(
        window.entries.len() <= 1024,
        "outcomes window should be bounded"
    );
}

#[test]
fn test_usable_transitions_on_clock_advance() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Put lane in Open state with until = 2000
    set_now_for_test(2500);

    store
        .get_lane(0)
        .cooldown_until
        .store(2000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);

    // At time 1999: not usable (still in cooldown)
    assert!(!store.usable(0, 1999), "not usable before cooldown expires");

    // At time 2500: the first usable() call transitions Open→HalfOpen and wins the probe.
    assert!(
        store.usable(0, 2500),
        "first request in HalfOpen should win probe"
    );
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::HalfOpen),
        "an expired-cooldown Open lane must be HalfOpen after admission (got {state:?})"
    );

    // Second request sees unusable (probe already won by first)
    assert!(
        !store.usable(0, 2501),
        "second request not usable after probe acquired"
    );
}

#[test]
fn test_escalating_cooldown_on_repeated_trips() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // streak is owned by the record path now (open_state only reads it to escalate), so
    // simulate the consecutive-failure count the record path would have set.
    let cfg = BreakerCfg::default();

    // First trip after one failure: streak=1 -> cooldown ~15s.
    store.get_lane(0).streak.store(1, Ordering::Relaxed);
    store.open_state(0, 1000, &cfg);
    let until1 = store.cooldown_remaining(0, 1000);

    set_now_for_test(2000); // Advance time past first cooldown

    // Second trip after a second failure: streak=2 -> cooldown ~30s (exponential backoff).
    store.get_lane(0).streak.store(2, Ordering::Relaxed);
    store.open_state(0, 2000, &cfg);
    let until2 = store.cooldown_remaining(0, 2000);

    assert!(
        until2 > until1,
        "second cooldown should be longer than first"
    );
}

#[test]
fn test_client_fault_counter_increments_separately() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Record client faults - should NOT increment err or streak
    for _ in 0..5 {
        store.record_client_fault(0);
    }

    let snap = store.snapshot(0, 1000);
    assert_eq!(
        snap.client_fault, 5,
        "client_fault counter should increment"
    );
    assert_eq!(
        snap.err, 0,
        "err should NOT be incremented by client faults"
    );
    assert_eq!(
        snap.streak, 0,
        "streak should NOT be incremented by client faults"
    );

    // Should still be usable (no penalty)
    assert!(
        store.usable(0, 1000),
        "lane should remain usable after client faults"
    );
}

#[test]
fn test_client_fault_does_not_affect_breaker_state() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Record many client faults
    for _ in 0..100 {
        store.record_client_fault(0);
    }

    let state = store.breaker_state(0);
    assert_eq!(
        state,
        BreakerState::Closed,
        "breaker should remain Closed after client faults"
    );

    let snap = store.snapshot(0, 1000);
    assert_eq!(snap.client_fault, 100);
    assert_eq!(snap.err, 0);
}

// Honor Retry-After on transient cooldown
#[test]
fn test_retry_after_429_with_computed_backoff_lower() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Use a unique timestamp that won't collide with other tests
    set_now_for_test(70000);

    // Explicitly reset streak to 0 (fresh lane has this, but tests can race)
    store.get_lane(0).streak.store(0, Ordering::Relaxed);

    // Simulate a 429 with retry_after=30s and computed backoff < 30s (streak=0 -> base 15s)
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig::default(),
    };
    store.open_state_with_retry_after(0, 70000, &cfg, Some(30));

    // Cooldown should be max(computed_backoff=15, retry_after=30) = 30
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert!(
        until >= 70030,
        "cooldown floor should honor retry_after when larger than computed backoff (got {until})"
    );

    // Lane should be unavailable during cooldown - check at a time that's definitely before cooldown expires
    let test_now = store.get_lane(0).cooldown_until.load(Ordering::Relaxed) - 10;
    assert!(
        !store.usable(0, test_now),
        "lane should be down during retry-after period"
    );

    // Lane should become usable after cooldown expires
    assert!(
        store.usable(0, until + 1),
        "lane should become usable after retry_after expires (got usable={})",
        store.usable(0, until + 1)
    );
}

#[test]
fn test_retry_after_exceeds_max_cooldown() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Simulate a 429 with retry_after=300s which exceeds max_cooldown_secs (120)
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig::default(),
    };

    // Streak=0 -> computed backoff would be 15s but capped at 120s
    store.open_state_with_retry_after(0, 1000, &cfg, Some(300));

    // Server's explicit Retry-After is always respected even if > max_cooldown_secs
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert_eq!(
        until, 1300,
        "server retry-after must be honored even when exceeding max_cooldown"
    );

    // Lane should be unavailable for the full server-specified duration
    assert!(
        !store.usable(0, 1299),
        "lane should respect server's explicit Retry-After past cap"
    );
}

#[test]
fn test_retry_after_absent_fallback_to_computed() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Use a unique timestamp that won't collide with other tests
    set_now_for_test(60000);

    // Explicitly reset streak to 0 (fresh lane has this, but tests can race)
    store.get_lane(0).streak.store(0, Ordering::Relaxed);

    // No retry_after present -> should fall back to computed backoff (15s for streak=0)
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig::default(),
    };
    store.open_state_with_retry_after(0, 60000, &cfg, None);

    // Should use computed backoff without any server override (streak=0 -> base 15s, now jittered
    // ~±10% per the A3 fix, so assert the band around base rather than an exact value).
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert!(
            (60013..=60017).contains(&until),
            "should fall back to the (jittered ~15s) computed backoff when retry_after absent (got {until})"
        );
}

#[test]
fn test_retry_after_record_rate_limit_uses_floor() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    // Record rate limit with retry_after=45s (streak=1 -> computed would be ~30s)
    store.record_rate_limit(0, 1000, &BreakerCfg::default(), Some(45));

    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    assert_eq!(
        until, 1045,
        "record_rate_limit should honor retry_after as cooldown floor"
    );
}

#[test]
fn test_retry_after_record_transient_uses_floor() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Use a unique timestamp that won't collide with other tests
    set_now_for_test(50000);

    // Explicitly reset streak to 0 (fresh lane has this, but tests can race)
    store.get_lane(0).streak.store(0, Ordering::Relaxed);

    // Record transient error with retry_after=60s (streak=0 -> computed would be 15s)
    store.record_transient(0, "timeout", &BreakerCfg::default(), Some(60));

    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    // Should honor retry_after floor of 60s: cooldown should be at least now + 60
    // Use a wider tolerance to account for any timing variations
    assert!(
        until >= 50060,
        "record_transient should honor retry_after as cooldown floor (got {until})"
    );
}

/// When NOT honoring Retry-After, the server value is IGNORED and the computed exponential
/// backoff stands (returning the server value verbatim could SHORTEN the cooldown below the
/// backoff floor). Covers the `(false, Some(_))` branch of compute_cooldown_with_retry_after,
/// which was previously untested AND incorrectly returned the server value directly.
#[test]
fn test_retry_after_not_honored_ignores_server_value() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(80000);
    store.get_lane(0).streak.store(0, Ordering::Relaxed);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: false, // do NOT honor
        trip: TripConfig::default(),
    };
    // Server says Retry-After: 1, but not honoring → use computed backoff (15s for streak=0),
    // NOT the (shorter) server value.
    store.open_state_with_retry_after(0, 80000, &cfg, Some(1));
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    // A3 fix: the streak==0 base cooldown is now jittered (deterministic per-cell, ~±10% of the
    // 15s base), so assert the computed-backoff band around base — and crucially NOT the (shorter)
    // 1s server Retry-After value, which the `honor_retry_after=false` path must ignore.
    assert!(
        (80013..=80017).contains(&until),
        "honor_retry_after=false must ignore the 1s server value and use the (jittered ~15s) \
             computed backoff; got {until}"
    );
    assert_ne!(until, 80001, "must not use the 1s server Retry-After value");
}

/// Regression (CRITICAL): a FAILED half-open probe must NOT bench a lane forever. cell_open must
/// reset probe_in_flight; otherwise the next cooldown expiry transitions Open→HalfOpen but the
/// stale probe flag makes the CAS fail for every request, so no one can ever probe again.
#[test]
fn test_failed_probe_does_not_permanently_lock_lane() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    let cfg = BreakerCfg::default();

    // Lane Open with an expired cooldown.
    set_now_for_test(10_000);
    store
        .get_lane(0)
        .cooldown_until
        .store(9_000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);

    // First request wins the probe (Open→HalfOpen, probe acquired).
    assert!(
        store.usable(0, 10_000),
        "first request wins the half-open probe"
    );
    assert!(
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "probe should be in flight"
    );

    // The probe FAILS → reopen with a fresh cooldown. The probe flag MUST be cleared here.
    store.record_transient(0, "probe-failed", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "a failed probe reopens the breaker"
    );
    assert!(
        !store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "cell_open MUST release the probe (else the lane is locked out forever)"
    );

    // After the new cooldown expires, a request must again be able to win the probe — proving
    // the lane is NOT permanently benched.
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    set_now_for_test(until + 1);
    assert!(
            store.usable(0, until + 1),
            "lane must be probeable again after the next cooldown (not locked out by a stale probe flag)"
        );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::HalfOpen,
        "the new probe re-enters HalfOpen"
    );
}

/// Regression (HIGH): a lane that hard-downs WHILE a half-open probe is in flight must not be
/// benched forever. `record_hard_down_for` transitions the cell to Open with the long sticky
/// cooldown; if it failed to clear `probe_in_flight` (the same bug class fixed in `cell_open`),
/// the next cooldown expiry would enter HalfOpen but the probe CAS would fail for every request,
/// so the operator could fix the credential/billing and the lane would still never recover.
#[test]
fn test_hard_down_while_probing_does_not_wedge_lane() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

    // Lane Open with an expired cooldown → a request wins the half-open probe.
    set_now_for_test(50_000);
    store
        .get_lane(0)
        .cooldown_until
        .store(49_000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed);
    assert!(store.usable(0, 50_000), "request wins the half-open probe");
    assert!(
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "probe is in flight (HalfOpen)"
    );

    // The probe returns a hard-down error (billing/auth/hard-quota) → record_hard_down.
    store.record_hard_down(0, "billing / insufficient balance");
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "hard-down opens the breaker with a sticky cooldown"
    );
    // The probe flag MUST be cleared so the lane can recover.
    assert!(
        !store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "record_hard_down MUST release the probe (else the lane is locked out forever)"
    );

    // After the sticky cooldown expires (operator fixed the key/billing), a request must again
    // be able to win the probe — proving hard-down is RECOVERABLE, not a permanent kill.
    let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
    set_now_for_test(until + 1);
    assert!(
        store.usable(0, until + 1),
        "lane must be probeable again after the sticky cooldown (not wedged by a stale probe flag)"
    );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::HalfOpen,
        "the recovery probe re-enters HalfOpen"
    );
    assert!(
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "the recovery request holds the single-flight probe"
    );
}

/// Regression (HIGH): selection must NOT transition non-selected candidates Open→HalfOpen or
/// steal their single-flight probes. The filter is side-effect-free; only the one lane a caller
/// dispatches acquires the probe (via acquire_for_dispatch_in / usable). Here two lanes are Open
/// with expired cooldowns; running selection many times must leave the UNSELECTED lanes in Open
/// with no probe in flight.
#[test]
fn test_selection_does_not_steal_probes_from_unselected_lanes() {
    let (lane0, w0) = make_lane_data_with_weight(0, 10);
    let (lane1, w1) = make_lane_data_with_weight(1, 10);
    let (lane2, w2) = make_lane_data_with_weight(2, 10);
    let store = Arc::new(InMemoryStore::new(vec![lane0, lane1, lane2]));
    set_now_for_test(20_000);

    // All three Open with already-expired cooldowns (so all are "ready" but each would need a
    // probe to actually dispatch).
    for i in 0..3 {
        store
            .get_lane(i)
            .cooldown_until
            .store(19_000, Ordering::Relaxed);
        store.get_lane(i).breaker_state.store(1, Ordering::Relaxed);
    }

    let candidates = vec![0usize, 1, 2];
    let weights = vec![w0, w1, w2];

    // Run selection many times WITHOUT dispatching (no usable()/acquire on the winner).
    for _ in 0..50 {
        let _ = store.select_weighted(&candidates, &weights, 20_000);
    }

    // No lane should have been transitioned to HalfOpen and no probe should be in flight —
    // selection enumeration alone must not consume probe budget.
    for i in 0..3 {
        assert_eq!(
            store.get_lane(i).breaker_state.load(Ordering::Relaxed),
            1,
            "lane {i} must remain Open after pure selection (no Open→HalfOpen side effect)"
        );
        assert!(
            !store.get_lane(i).probe_in_flight.load(Ordering::Relaxed),
            "lane {i} must NOT have a probe in flight from mere selection enumeration"
        );
    }

    // And the dispatch path (usable) on a single chosen lane DOES acquire exactly one probe.
    assert!(store.usable(0, 20_000), "dispatch on lane 0 wins its probe");
    assert!(
        store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "the dispatched lane acquires the probe"
    );
    assert!(
        !store.get_lane(1).probe_in_flight.load(Ordering::Relaxed),
        "a non-dispatched lane still has no probe in flight"
    );
}

/// `is_ready` is the side-effect-FREE readiness check `/healthz` uses: an expired-Open lane is
/// reported ready but is NOT transitioned to HalfOpen and its probe is NOT acquired (so healthz
/// polling can't steal recovery probes from organic traffic).
#[test]
fn test_is_ready_is_side_effect_free() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(30_000);
    store
        .get_lane(0)
        .cooldown_until
        .store(29_000, Ordering::Relaxed);
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed); // Open, expired cooldown

    // Many readiness probes must not mutate state.
    for _ in 0..100 {
        assert!(
            store.is_ready(0, 30_000),
            "expired-Open lane reads as ready"
        );
    }
    assert_eq!(
        store.get_lane(0).breaker_state.load(Ordering::Relaxed),
        1,
        "is_ready must NOT transition Open→HalfOpen"
    );
    assert!(
        !store.get_lane(0).probe_in_flight.load(Ordering::Relaxed),
        "is_ready must NOT acquire the single-flight probe"
    );
}

// SWRR convergence test - 3-member pool with weights 1/2/3 should distribute exactly in that ratio
#[test]
fn test_swrr_convergence_1_2_3() {
    let (lane0, w0) = make_lane_data_with_weight(0, 10);
    let (lane1, w1) = make_lane_data_with_weight(1, 10);
    let (lane2, w2) = make_lane_data_with_weight(2, 3);

    // Weights are: lane 0 -> 1, lane 1 -> 2, lane 2 -> 3
    let store = Arc::new(InMemoryStore::new(vec![lane0, lane1, lane2]));
    set_now_for_test(1000);

    // Run SWRR selection many times and count distribution
    let candidates: Vec<usize> = vec![0, 1, 2];
    let weights: Vec<u32> = vec![w0, w1, w2];

    let mut counts = [0usize; 3];
    const N: usize = 600; // Should give exactly 1:2:3 distribution (6 per cycle)

    for _ in 0..N {
        let picked = store.select_weighted(&candidates, &weights, 1000).unwrap();
        counts[picked] += 1;
    }

    // With SWRR over weights [1,2,3], sum=6: each cycle of 6 picks gives 1+2+3=6
    // N=600 means exactly 100 cycles, so expected: lane0=100, lane1=200, lane2=300
    assert_eq!(
        counts[0], 100,
        "member 0 (weight 1) should be picked ~100 times"
    );
    assert_eq!(
        counts[1], 200,
        "member 1 (weight 2) should be picked ~200 times"
    );
    assert_eq!(
        counts[2], 300,
        "member 2 (weight 3) should be picked ~300 times"
    );

    // Verify total equals N
    let total: usize = counts.iter().sum();
    assert_eq!(total, N, "total picks should equal N");
}

// Rebalance on trip - when member 0 trips (Open), distribution should renormalize to survivors
#[test]
fn test_swrr_rebalance_on_trip() {
    let (lane0, w0) = make_lane_data_with_weight(0, 10);
    let (lane1, w1) = make_lane_data_with_weight(1, 3);

    let store = Arc::new(InMemoryStore::new(vec![lane0, lane1]));
    set_now_for_test(1000);

    // Put member 0 in Open state (tripped)
    store.get_lane(0).breaker_state.store(1, Ordering::Relaxed); // Open
    store
        .get_lane(0)
        .cooldown_until
        .store(u64::MAX, Ordering::Relaxed);

    let candidates: Vec<usize> = vec![0, 1];
    let weights: Vec<u32> = vec![w0, w1];

    // All picks should go to member 1 since member 0 is Open/unusable
    for _ in 0..100 {
        let picked = store.select_weighted(&candidates, &weights, 1000).unwrap();
        assert_eq!(picked, 1, "tripped member 0 should never be selected");
    }

    // Verify member 0 is not usable
    assert!(
        !store.usable(0, 1000),
        "member 0 in Open state should not be usable"
    );
}

/// LOW #26 (concurrency): the SWRR `current_weight` reset on breaker recovery must happen UNDER
/// the per-pool SWRR shard lock that serializes selection — NOT as a bare store inside the
/// cell-level close. The old code zeroed `current_weight` inside `cell_closed_locked` with a plain
/// `store(0)`, not holding the shard lock, so a recovery racing a selection could land its zero
/// between selection's `fetch_add` and its compensating `fetch_sub(total)`, breaking the
/// `Σ current_weight == 0` invariant.
///
/// This pins the lock discipline directly: hold the pool's SWRR shard lock on the test thread,
/// fire a recovery (`record_success_for`) on another thread, and assert the recovery's reset is
/// BLOCKED until the shard lock is released. Against the old code (reset not under the shard lock)
/// the zero lands immediately and the post-spawn assertion that `current_weight` is still stale
/// fails; against the fixed code the reset waits for the lock.
#[test]
fn test_swrr_reset_on_recovery_happens_under_shard_lock() {
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(5000);

    // Seed a stale SWRR accumulator and park the default cell HalfOpen with the probe acquired,
    // so a success drives the HalfOpen→Closed recovery that performs the reset.
    const STALE: i64 = 777;
    store
        .get_lane(0)
        .current_weight
        .store(STALE, Ordering::Relaxed);
    store
        .get_lane(0)
        .cooldown_until
        .store(1000, Ordering::Relaxed);
    store
        .get_lane(0)
        .breaker_state
        .store(ST_HALF_OPEN, Ordering::Relaxed);
    store
        .get_lane(0)
        .probe_in_flight
        .store(true, Ordering::Relaxed);

    // Signals the recovery thread has been spawned and is about to (or has) attempt the reset.
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Hold the default pool's SWRR shard lock for the whole critical section. While held, no
    // recovery may reset `current_weight` (the fix takes this same lock to zero it).
    let guard = lock_recover(store.swrr_shard(""));

    let store_r = Arc::clone(&store);
    let started_r = Arc::clone(&started);
    let recoverer = std::thread::spawn(move || {
        started_r.store(true, Ordering::Release);
        // Recovery: success on the half-open probe → HalfOpen→Closed → SWRR reset (under shard
        // lock). Blocks here until the test thread drops `guard`.
        store_r.record_success_for("", 0);
    });

    // Wait until the recovery thread is running, then give it ample opportunity to (wrongly)
    // perform the reset if it weren't gated on the shard lock.
    while !started.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
    for _ in 0..50 {
        std::thread::yield_now();
    }

    // The shard lock is still held here. Under the fix the reset cannot have happened yet.
    assert_eq!(
            store.get_lane(0).current_weight.load(Ordering::Relaxed),
            STALE,
            "SWRR reset must be blocked while the pool's shard lock is held — it must run UNDER that lock, \
             not as a bare store in cell_closed"
        );

    // Release the shard lock; the recovery may now reset and complete.
    drop(guard);
    recoverer.join().expect("recovery thread must not panic");

    assert_eq!(
        store.get_lane(0).current_weight.load(Ordering::Relaxed),
        0,
        "after recovery completes (shard lock released) the SWRR accumulator must be zeroed"
    );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "the half-open probe success must have recovered the cell to Closed"
    );
}

/// LOW #19 (bug): `record_probe_success_all_cells` must gate the SWRR reset on the
/// `cell_record_success` recovered-bool — for the default cell AND every per-pool cell — exactly
/// like its siblings `record_success_for` and `recover_lane`. The probe-success caller normally
/// runs `recover_lane` first, but only when `lane_needs_probe` is true and not against a peer that
/// re-arms a cell HalfOpen in between; if THIS push then wins the HalfOpen→Closed CAS,
/// `cell_closed_locked` re-admits the cell to selection while leaving its STALE `current_weight`
/// untouched (the close never zeroes it — only `reset_swrr_for` does). Dropping the bool skipped
/// that reset, so the recovered cell rejoined selection carrying a stale accumulator and broke the
/// pool's `Σ current_weight == 0` invariant.
///
/// Against the OLD code (bool discarded) the post-call `current_weight` stays at the seeded STALE
/// value and these assertions fail; against the fix the close drives the gated `reset_swrr_for` and
/// the accumulator reads 0.
#[test]
fn test_probe_success_all_cells_resets_swrr_on_half_open_close() {
    const STALE_DEFAULT: i64 = 555;
    const STALE_POOL: i64 = 999;
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(5000);

    // Default ("") cell and a per-pool cell, both parked HalfOpen with the probe acquired and a
    // stale SWRR accumulator. The expired cooldown (1000 < now=5000) makes them probe-recoverable.
    store.arm_half_open_stale_swrr("", 0, 1000, STALE_DEFAULT);
    store.arm_half_open_stale_swrr("pool-a", 0, 1000, STALE_POOL);

    // Probe success across all cells. With the bug, each cell closes (HalfOpen→Closed) but its
    // current_weight is never zeroed; with the fix, the gated reset zeroes both.
    store.record_probe_success_all_cells(0);

    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "default cell must recover HalfOpen→Closed on the probe success"
    );
    assert_eq!(
        store.breaker_state_in("pool-a", 0),
        BreakerState::Closed,
        "per-pool cell must recover HalfOpen→Closed on the probe success"
    );
    assert_eq!(
        store.cell_current_weight("", 0),
        0,
        "default cell's stale SWRR accumulator must be reset to 0 on the HalfOpen→Closed close \
             (LOW #19: the reset was skipped because the recovered-bool was discarded)"
    );
    assert_eq!(
        store.cell_current_weight("pool-a", 0),
        0,
        "per-pool cell's stale SWRR accumulator must be reset to 0 on the HalfOpen→Closed close \
             (LOW #19: the per-cell reset was skipped because the recovered-bool was discarded)"
    );
}

// No Open selection - verify select_weighted never returns an unusable member
#[test]
fn test_swrr_no_open_selection() {
    let (lane0, w0) = make_lane_data_with_weight(0, 10);
    let (lane1, w1) = make_lane_data_with_weight(1, 10);
    let (lane2, w2) = make_lane_data_with_weight(2, 3);

    let store = Arc::new(InMemoryStore::new(vec![lane0, lane1, lane2]));
    set_now_for_test(1000);

    // Put member 1 in Open state
    store.get_lane(1).breaker_state.store(1, Ordering::Relaxed);
    store
        .get_lane(1)
        .cooldown_until
        .store(u64::MAX, Ordering::Relaxed);

    let candidates: Vec<usize> = vec![0, 1, 2];
    let weights: Vec<u32> = vec![w0, w1, w2];

    // Run many selections and verify member 1 is never picked while Open
    for _ in 0..500 {
        if let Some(picked) = store.select_weighted(&candidates, &weights, 1000) {
            assert_ne!(picked, 1, "Open member should never be selected");
        }
    }

    // Member 0 and 2 should both get picked (renormalized to 10:3 ratio)
}

// All-down - when every member is Open, select_weighted returns None
#[test]
fn test_swrr_all_down_returns_none() {
    let (lane0, w0) = make_lane_data_with_weight(0, 10);
    let (lane1, w1) = make_lane_data_with_weight(1, 3);

    let store = Arc::new(InMemoryStore::new(vec![lane0, lane1]));
    set_now_for_test(1000);

    // Put all members in Open state
    for i in 0..2 {
        store.get_lane(i).breaker_state.store(1, Ordering::Relaxed);
        store
            .get_lane(i)
            .cooldown_until
            .store(u64::MAX, Ordering::Relaxed);
    }

    let candidates: Vec<usize> = vec![0, 1];
    let weights: Vec<u32> = vec![w0, w1];

    // Should return None when no healthy members
    assert!(
        store.select_weighted(&candidates, &weights, 1000).is_none(),
        "select_weighted should return None when all members are Open"
    );
}

/// REGRESSION (A2): out-of-band probe failures against an ALREADY-Open cell must NOT advance the
/// consecutive streak. The streak `fetch_add` used to run unconditionally before the state match,
/// so the ST_OPEN no-op arm still inflated the streak → a later HalfOpen re-trip computed an
/// over-long cooldown (`base << inflated_streak`, pinned at max). Here we batter an Open cell with
/// N failures, then drive it HalfOpen and fail once; the recomputed cooldown must reflect ONLY the
/// real consecutive count (streak==1 → base<<1), NOT N+1 (which would pin at max).
#[test]
fn test_open_cell_probe_failures_do_not_inflate_streak() {
    set_now_for_test(1_000);
    let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
    // Consecutive mode so the streak alone drives the cooldown shift; small base, large max so an
    // inflated streak would visibly pin at (or near) max while the real streak stays tiny.
    let cfg = BreakerCfg {
        base_cooldown_secs: 4,
        max_cooldown_secs: 100_000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    // Park the cell Open with an expired cooldown (so it stays Open across the probe failures).
    store.force_open_in("", 0, 0);
    let lane = store.get_lane(0).clone();
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        0,
        "starts at streak 0"
    );

    // N out-of-band probe failures against the Open cell — each must be a streak no-op.
    for _ in 0..20 {
        store.record_transient(0, "5xx", &cfg, None);
    }
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        0,
        "failures recorded against an already-Open cell must NOT advance the streak (A2)"
    );

    // Now drive the cell HalfOpen (the probe winner) and fail the probe: this is the ST_HALF_OPEN
    // arm, which bumps the streak to 1 and reopens with the escalated cooldown.
    {
        let _tx = lock_recover(lane.transition_lock());
        lane.breaker_state().store(ST_HALF_OPEN, Ordering::Release);
    }
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        lane.streak().load(Ordering::Relaxed),
        1,
        "the HalfOpen probe failure is the first real consecutive failure → streak 1"
    );

    // Cooldown reflects base<<1 == 8 with ±10% jitter floored at 1s → within [base/2, ...] but FAR
    // below max. Under the OLD bug the streak would be 21 → base<<21 saturates and pins at max.
    let until = store.cell_cooldown_until("", 0);
    let cooldown = until - 1_000; // now == 1_000
    assert!(
            cooldown < 100,
            "cooldown must reflect the real streak (~base<<1), not an inflated one pinned at max; got {cooldown}"
        );
    assert!(
        cooldown < cfg.max_cooldown_secs,
        "inflated-streak cooldown would pin at max ({}); fixed value must be well under it",
        cfg.max_cooldown_secs
    );
}

/// REGRESSION (A3): jitter must apply on the `streak == 0` base path too (first-trip /
/// sub-threshold cooldown), not only `streak > 0`. Two distinct cells with streak==0 and the SAME
/// base must get DIFFERENT cooldowns (desync via the per-cell FNV seed), each within [base/2, max].
#[test]
fn test_streak_zero_base_cooldown_is_jittered_and_desynced() {
    set_now_for_test(5_000);
    // Several lanes → several distinct default cells (distinct cell addresses feed the FNV
    // seed). The jitter band around base=200 holds only ~41 distinct values, so any TWO cells
    // collide by chance ~2.4% of the time; sampling 8 makes an all-collide false failure
    // astronomically unlikely while still proving desync.
    let store = Arc::new(InMemoryStore::new(
        (0..8).map(|i| make_lane_data(i, 10)).collect(),
    ));
    // Sub-threshold cfg: high consecutive_n / min_requests so a single failure NEVER trips — it
    // takes the sub-threshold cooldown arm with streak just bumped to... no: streak==0 base is
    // exercised directly via the cooldown-compute helper. Use a base >= 10 so the ±10% band is a
    // real spread (jitter_range = base/10 >= 1) independent of the >=1s floor.
    let cfg = BreakerCfg {
        base_cooldown_secs: 200,
        max_cooldown_secs: 100_000,
        honor_retry_after: false,
        trip: TripConfig::default(),
    };

    let cooldowns: Vec<u64> = (0..8)
        .map(|i| {
            let c = store.get_lane(i).clone();
            // Fresh: streak == 0.
            assert_eq!(c.streak().load(Ordering::Relaxed), 0);
            InMemoryStore::compute_cooldown_with_retry_after(c.as_ref(), 5_000, &cfg, None, 0)
        })
        .collect();

    // Jitter applied → the cells desync: with 8 independent per-cell seeds, they must not all
    // land on the same value.
    assert!(
            cooldowns.iter().any(|d| *d != cooldowns[0]),
            "8 streak==0 cells with the same base must not all get the SAME cooldown; jitter/desync (A3) is not applying: {cooldowns:?}"
        );
    for d in &cooldowns {
        assert!(
            (100..=100_000).contains(d),
            "jittered streak==0 cooldown must stay within [base/2, max]; got {d}"
        );
    }
}
