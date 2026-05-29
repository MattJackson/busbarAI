// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

const COOLDOWN_BASE_SECS: u64 = 15;
const COOLDOWN_MAX_SECS: u64 = 120;
const COOLDOWN_TRANSIENT_SECS: u64 = 10;

pub(crate) fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Breaker state for a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Used by StateStore trait (future usage)
pub(crate) enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Permit wrapper that holds an owned semaphore permit.
/// Must be Send + 'static and movable into FirstByteBody stream.
#[must_use]
pub(crate) struct Permit {
    #[allow(dead_code)] // Dropped via Drop impl at end of stream
    inner: tokio::sync::OwnedSemaphorePermit,
}

impl Permit {
    pub(crate) fn new(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self { inner: permit }
    }
}

/// Snapshot of lane stats for /stats endpoint.
#[derive(Debug, Clone)]
pub(crate) struct LaneSnapshot {
    pub model: String,
    pub provider: String,
    pub max_concurrent: usize,
    pub inflight: i64,
    pub free_slots: usize,
    pub ok: u64,
    pub err: u64,
    pub usable: bool,
    pub dead: bool,
    pub dead_reason: String,
    pub cooldown_remaining_s: u64,
    pub streak: u32,
    pub budget: i64,
}

/// StateStore trait - the seam for lane state access.
/// Operations, NOT field access. `lane: usize` identifies a member.
pub(crate) trait StateStore: Send + Sync + 'static {
    // health queries
    fn usable(&self, lane: usize, now: u64) -> bool;
    #[allow(dead_code)] // Used for future breaker state tracking
    fn breaker_state(&self, lane: usize) -> BreakerState;
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64;

    // outcome recording (the breaker's write path)
    #[allow(dead_code)] // Used for future success tracking
    fn record_success(&self, lane: usize);
    fn record_transient(&self, lane: usize, what: &str);
    fn record_rate_limit(&self, lane: usize, now: u64, retry_after: Option<u64>);
    fn record_hard_down(&self, lane: usize, reason: &str);

    // concurrency + budget (kept as-is conceptually)
    fn try_acquire(&self, lane: usize) -> Option<Permit>;
    #[allow(dead_code)] // Used for future budget tracking
    fn spend_budget(&self, lane: usize) -> bool; // false => exhausted

    // stats snapshot for /stats
    fn snapshot(&self, lane: usize, now: u64) -> LaneSnapshot;
}

/// InMemoryStore wraps the existing atomics/semaphores per lane.
pub(crate) struct InMemoryStore {
    lanes: Vec<Arc<LaneState>>,
}

struct LaneState {
    model: String,
    provider: String,
    max: usize,
    sem: Arc<Semaphore>,
    limited: bool,
    budget: AtomicI64,
    cooldown_until: AtomicU64,
    streak: AtomicU32,
    dead: AtomicBool,
    dead_reason: std::sync::Mutex<String>,
    inflight: AtomicI64,
    ok: AtomicU64,
    err: AtomicU64,
}

impl InMemoryStore {
    pub(crate) fn new(lanes: Vec<LaneData>) -> Self {
        let lane_states: Vec<Arc<LaneState>> = lanes
            .into_iter()
            .map(|ld| {
                Arc::new(LaneState {
                    model: ld.model,
                    provider: ld.provider,
                    max: ld.max,
                    sem: ld.sem,
                    limited: ld.limited,
                    budget: AtomicI64::new(ld.budget),
                    cooldown_until: AtomicU64::new(ld.cooldown_until),
                    streak: AtomicU32::new(ld.streak),
                    dead: AtomicBool::new(ld.dead),
                    dead_reason: std::sync::Mutex::new(ld.dead_reason),
                    inflight: AtomicI64::new(ld.inflight),
                    ok: AtomicU64::new(ld.ok),
                    err: AtomicU64::new(ld.err),
                })
            })
            .collect();
        Self { lanes: lane_states }
    }

    fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }
}

#[derive(Clone)]
pub(crate) struct LaneData {
    pub model: String,
    pub provider: String,
    pub max: usize,
    pub sem: Arc<Semaphore>,
    pub limited: bool,
    pub budget: i64,
    pub cooldown_until: u64,
    pub streak: u32,
    pub dead: bool,
    pub dead_reason: String,
    pub inflight: i64,
    pub ok: u64,
    pub err: u64,
}

impl StateStore for InMemoryStore {
    fn usable(&self, lane: usize, t: u64) -> bool {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        t >= ls.cooldown_until.load(Ordering::Relaxed)
    }

    fn breaker_state(&self, lane: usize) -> BreakerState {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return BreakerState::Open;
        }
        if ls.cooldown_until.load(Ordering::Relaxed) > now() {
            return BreakerState::HalfOpen;
        }
        BreakerState::Closed
    }

    fn cooldown_remaining(&self, lane: usize, t: u64) -> u64 {
        let ls = self.get_lane(lane);
        ls.cooldown_until.load(Ordering::Relaxed).saturating_sub(t)
    }

    fn record_success(&self, lane: usize) {
        let ls = self.get_lane(lane);
        ls.streak.store(0, Ordering::Relaxed);
        ls.ok.fetch_add(1, Ordering::Relaxed);
        if ls.limited && ls.budget.fetch_sub(1, Ordering::Relaxed) - 1 <= 0 {
            let reason = "request budget exhausted";
            ls.dead.store(true, Ordering::Relaxed);
            *ls.dead_reason.lock().unwrap() = reason.to_string();
            eprintln!("[{}] STOPPED permanently: {}", ls.model, reason);
        }
    }

    fn record_transient(&self, lane: usize, what: &str) {
        let ls = self.get_lane(lane);
        ls.cooldown_until
            .store(now() + COOLDOWN_TRANSIENT_SECS, Ordering::Relaxed);
        ls.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] transient ({}), cooldown {}s",
            ls.model, what, COOLDOWN_TRANSIENT_SECS
        );
    }

    fn record_rate_limit(&self, lane: usize, now_time: u64, _retry_after: Option<u64>) {
        let ls = self.get_lane(lane);
        let s = ls.streak.fetch_add(1, Ordering::Relaxed) + 1;
        let secs = (COOLDOWN_BASE_SECS * s as u64).min(COOLDOWN_MAX_SECS);
        ls.cooldown_until.store(now_time + secs, Ordering::Relaxed);
        ls.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] rate-limited (streak {}), cooldown {}s",
            ls.model, s, secs
        );
    }

    fn record_hard_down(&self, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        ls.dead.store(true, Ordering::Relaxed);
        *ls.dead_reason.lock().unwrap() = reason.to_string();
        eprintln!("[{}] STOPPED permanently: {}", ls.model, reason);
    }

    fn try_acquire(&self, lane: usize) -> Option<Permit> {
        let ls = self.get_lane(lane);
        match ls.sem.clone().try_acquire_owned() {
            Ok(permit) => Some(Permit::new(permit)),
            Err(_) => None,
        }
    }

    fn spend_budget(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        if !ls.limited {
            return true; // unlimited budget
        }
        ls.budget.load(Ordering::Relaxed) > 0
    }

    fn snapshot(&self, lane: usize, t: u64) -> LaneSnapshot {
        let ls = self.get_lane(lane);
        LaneSnapshot {
            model: ls.model.clone(),
            provider: ls.provider.clone(),
            max_concurrent: ls.max,
            inflight: ls.inflight.load(Ordering::Relaxed),
            free_slots: ls.sem.available_permits(),
            ok: ls.ok.load(Ordering::Relaxed),
            err: ls.err.load(Ordering::Relaxed),
            usable: self.usable(lane, t),
            dead: ls.dead.load(Ordering::Relaxed),
            dead_reason: ls.dead_reason.lock().unwrap().clone(),
            cooldown_remaining_s: self.cooldown_remaining(lane, t),
            streak: ls.streak.load(Ordering::Relaxed),
            budget: if ls.limited {
                ls.budget.load(Ordering::Relaxed)
            } else {
                -1
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_rate_limit_cooldown() {
        let sem = Arc::new(Semaphore::new(10));
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: sem.clone(),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
        };

        let store = InMemoryStore::new(vec![lane_data]);
        let t = now();

        // Initially usable
        assert!(store.usable(0, t));

        // Record rate limit
        store.record_rate_limit(0, t, None);

        // Should not be usable immediately after rate limit
        assert!(!store.usable(0, t));

        // Check cooldown remaining is positive
        let remaining = store.cooldown_remaining(0, t);
        assert!(remaining > 0, "cooldown should be positive");

        // After cooldown expires, should be usable again
        let later = t + remaining + 1;
        assert!(
            store.usable(0, later),
            "should be usable after cooldown expires"
        );
    }

    #[test]
    fn test_record_hard_down() {
        let sem = Arc::new(Semaphore::new(10));
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem,
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
        };

        let store = InMemoryStore::new(vec![lane_data]);
        let t = now();

        // Initially usable and not dead
        assert!(store.usable(0, t));
        {
            let snap = store.snapshot(0, t);
            assert!(!snap.dead, "should not be dead initially");
        }

        // Record hard down
        store.record_hard_down(0, "test reason");

        // Should not be usable and should be dead
        assert!(!store.usable(0, t));
        {
            let snap = store.snapshot(0, t);
            assert!(snap.dead, "should be dead after record_hard_down");
            assert_eq!(snap.dead_reason, "test reason", "dead reason should match");
        }
    }

    #[test]
    fn test_try_acquire() {
        let sem = Arc::new(Semaphore::new(2));
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: sem.clone(),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
        };

        let store = InMemoryStore::new(vec![lane_data]);

        // Should be able to acquire 2 permits - keep them alive
        let _permit1 = store.try_acquire(0).expect("should have permit");
        let _permit2 = store.try_acquire(0).expect("should have permit");

        // Third attempt should fail (no more permits)
        assert!(store.try_acquire(0).is_none(), "should be no permits left");
    }
}
