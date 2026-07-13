//! REGRESSION (A1): the WON-but-undispatched single-flight recovery probe must be released when
//! the `pick_among` future is dropped (client disconnect) while parked on the permit await — none
//! of the explicit early-returns run on drop. `ProbeGuard`'s `Drop` enforces that. These unit
//! tests construct the guard directly: dropping an ARMED guard must clear `probe_in_flight` (the
//! cell reverts HalfOpen→Open and is re-probeable); DISARMING it (the live-permit dispatch paths)
//! must LEAVE the probe held for the owning request.
use super::ProbeGuard;
use crate::store::{BreakerState, InMemoryStore, LaneData, StateStore};
use std::sync::Arc;
use tokio::sync::Semaphore;

fn lane(max: usize) -> LaneData {
    LaneData {
        reasoning: false,
        prompt_caching: false,
        model: "m0".into(),
        provider: "p0".into(),
        max,
        sem: Arc::new(Semaphore::new(max)),
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
    }
}

/// Park the default ("") cell as a WON probe (HalfOpen + probe_in_flight), exactly the state
/// `acquire_for_dispatch_in` leaves after winning the single-flight race.
fn win_probe(store: &Arc<InMemoryStore>) {
    // Expired-Open → the mutating acquisition transitions Open→HalfOpen and CAS-wins the probe.
    store.force_open_in("", 0, 0);
    assert!(
        store.acquire_for_dispatch_in("", 0, crate::store::now().saturating_add(86_400)),
        "precondition: this caller must WIN the single-flight probe"
    );
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::HalfOpen),
        "precondition: the won probe leaves the cell HalfOpen"
    );
}

/// Dropping an ARMED guard releases the probe (cell reverts HalfOpen→Open) — the leak A1 fixes
/// (the implicit future-drop-while-parked path).
#[test]
fn dropping_armed_guard_releases_probe() {
    let store = Arc::new(InMemoryStore::new(vec![lane(1)]));
    win_probe(&store);
    {
        let _guard = ProbeGuard {
            store: store.as_ref(),
            pool: "",
            lane: 0,
            armed: true,
        };
        // guard drops here (simulating the dropped `pick_among` future).
    }
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::Open { .. }),
        "an armed guard's Drop must release the probe (HalfOpen→Open), un-benching the lane"
    );
}

/// A DISARMED guard (the live-permit dispatch paths) leaves the probe HELD — the dispatched
/// request now owns it and will release it via its recorded outcome.
#[test]
fn disarmed_guard_leaves_probe_held() {
    let store = Arc::new(InMemoryStore::new(vec![lane(1)]));
    win_probe(&store);
    {
        let mut guard = ProbeGuard {
            store: store.as_ref(),
            pool: "",
            lane: 0,
            armed: true,
        };
        guard.armed = false; // the try_acquire / Ok(Ok(permit)) dispatch paths disarm before return.
                             // guard drops here as a no-op.
    }
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::HalfOpen),
        "a disarmed guard must NOT release the probe — the owning dispatched request holds it"
    );
}
