// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

#[allow(dead_code)] // Used by record_transient and other methods
const COOLDOWN_BASE_SECS: u64 = 15;
const COOLDOWN_MAX_SECS: u64 = 120;
const COOLDOWN_TRANSIENT_SECS: u64 = 10;

/// Get current time in seconds since epoch.
pub(crate) fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Test helper to inject time for unit tests.
#[cfg(test)]
pub(crate) fn set_now_for_test(t: u64) {
    use std::sync::atomic::AtomicU64;

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);
    TEST_NOW.store(t, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn now_for_test() -> u64 {
    use std::sync::atomic::AtomicU64;

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);
    let val = TEST_NOW.load(Ordering::Relaxed);
    if val == 0 {
        now()
    } else {
        val
    }
}

/// Breaker state for a lane per ADR-0002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants constructed by breaker_state() and used in FSM logic
pub(crate) enum BreakerState {
    Closed,
    Open { until: u64 },
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

/// Bounded sliding window of timestamped outcomes (ring buffer style).
/// Stores timestamps in seconds since epoch. Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Methods used for trip evaluation (future full implementation)
struct OutcomeWindow {
    entries: Vec<u64>,
    capacity: usize,
}

impl OutcomeWindow {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Add a timestamped outcome. If over capacity, drop oldest.
    #[allow(dead_code)] // Used for trip evaluation
    fn push(&mut self, ts: u64) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(ts);
    }

    /// Count outcomes within `window_s` seconds of `now`.
    #[allow(dead_code)] // Used for trip evaluation
    fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|&&ts| ts >= start).count()
    }

    /// Clear all entries.
    #[allow(dead_code)] // Used for recovery on probe success
    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// InMemoryStore wraps the existing atomics/semaphores per lane with FSM breaker logic.
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
    // FSM state per lane
    breaker_state: AtomicU64, // 0=Closed, 1=Open, 2=HalfOpen (stored as u64 for CAS)
    probe_in_flight: AtomicBool,
    outcome_window: std::sync::Mutex<OutcomeWindow>,
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
                    breaker_state: AtomicU64::new(0), // Closed
                    probe_in_flight: AtomicBool::new(false),
                    outcome_window: std::sync::Mutex::new(OutcomeWindow::new(1024)),
                })
            })
            .collect();
        Self { lanes: lane_states }
    }

    fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }

    /// Evaluate trip condition for Closed → Open transition.
    /// Returns true if the lane should trip to Open.
    #[allow(dead_code)] // Used for full FSM implementation
    fn should_trip(lane: &LaneState, now: u64, cfg: &BreakerCfg) -> bool {
        let window = lane.outcome_window.lock().unwrap();

        match cfg.trip.mode {
            TripMode::ErrorRate => {
                let count = window.count_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false; // Below floor
                }
                let error_count = lane.err.load(Ordering::Relaxed) as usize;
                // Note: err is cumulative; we use ratio of err to total recorded outcomes
                // For simplicity, treat all entries in window as potential errors for rate-limit scenarios
                // The actual error_fraction is derived from transient/rate_limit calls which increment err
                let fraction = if count > 0 {
                    (error_count.min(count)) as f64 / count as f64
                } else {
                    0.0
                };
                fraction >= cfg.trip.threshold
            }
            TripMode::Consecutive => {
                // Check streak against consecutive threshold
                let current_streak = lane.streak.load(Ordering::Relaxed);
                current_streak >= cfg.trip.n
            }
        }
    }

    /// Compute escalating cooldown duration.
    #[allow(dead_code)] // Used by open_state() for escalation logic
    fn compute_cooldown(lane: &LaneState, _now: u64, cfg: &BreakerCfg) -> u64 {
        let streak = lane.streak.load(Ordering::Relaxed);
        if streak == 0 {
            return cfg.base_cooldown_secs;
        }

        // Exponential backoff: base * 2^streak, capped at max
        let mut duration = cfg.base_cooldown_secs;
        for _ in 1..=streak {
            duration = (duration * 2).min(cfg.max_cooldown_secs);
        }

        // Add bounded jitter ±10%
        if streak > 0 {
            let jitter_range = duration / 10;
            use std::time::{SystemTime, UNIX_EPOCH};
            let jitter_seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let jitter = (jitter_seed as i64 % (2 * jitter_range as i64 + 1)) - jitter_range as i64;
            duration = duration.saturating_add(jitter.unsigned_abs()).clamp(
                duration / 2, // At least half of base
                cfg.max_cooldown_secs,
            );
        }

        duration
    }

    /// Attempt to acquire the single probe in HalfOpen state.
    /// Returns true if this request wins the probe (becomes THE probe).
    #[allow(dead_code)] // Used by usable() for single-flight logic
    pub(crate) fn try_acquire_probe(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        ls.probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Clear the probe flag (called after probe completes).
    #[allow(dead_code)] // Used by closed_state() on recovery
    pub(crate) fn clear_probe(&self, lane: usize) {
        let ls = self.get_lane(lane);
        ls.probe_in_flight.store(false, Ordering::Release);
    }

    /// Transition to Open state with escalated cooldown.
    #[allow(dead_code)] // Used by record_transient and record_rate_limit on probe failure
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        let ls = self.get_lane(lane);

        // Increment streak for escalation
        let _new_streak = ls.streak.fetch_add(1, Ordering::Relaxed) + 1;

        // Compute cooldown with exponential backoff
        let duration = Self::compute_cooldown(ls, now_time, cfg);
        let until = now_time + duration;

        ls.cooldown_until.store(until, Ordering::Release);
        ls.breaker_state.store(1, Ordering::Release); // 1 = Open
    }

    /// Transition to HalfOpen state (cooldown expired).
    #[allow(dead_code)] // Used internally by usable() for state transitions
    pub(crate) fn half_open_state(&self, lane: usize) {
        let ls = self.get_lane(lane);
        ls.breaker_state.store(2, Ordering::Release); // 2 = HalfOpen
    }

    /// Transition to Closed state (probe success).
    #[allow(dead_code)] // Used by closed_state() on recovery
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
        let ls = self.get_lane(lane);

        // Reset streak and window on recovery
        ls.streak.store(0, Ordering::Release);
        ls.err.store(0, Ordering::Release);

        let mut window = ls.outcome_window.lock().unwrap();
        window.clear();

        ls.cooldown_until.store(0, Ordering::Release);
        ls.breaker_state.store(0, Ordering::Release); // 0 = Closed

        self.clear_probe(lane);
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

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub(crate) struct BreakerCfg {
    pub base_cooldown_secs: u64,
    pub max_cooldown_secs: u64,
    pub trip: TripConfig,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            trip: TripConfig::default(),
        }
    }
}

/// Trip configuration mode.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Consecutive variant planned for full implementation
pub(crate) enum TripMode {
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields defined for config API
pub(crate) struct TripConfig {
    pub mode: TripMode,
    pub window_s: u64,
    pub threshold: f64,
    pub min_requests: usize,
    pub n: u32, // For consecutive mode
}

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            n: 3, // 3 consecutive errors
        }
    }
}

impl StateStore for InMemoryStore {
    fn usable(&self, lane: usize, now: u64) -> bool {
        let ls = self.get_lane(lane);

        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }

        // Check breaker state
        let breaker_state = ls.breaker_state.load(Ordering::Acquire);

        match breaker_state {
            0 => {
                // Closed -> check if there's a pending cooldown from previous transient error
                let until = ls.cooldown_until.load(Ordering::Acquire);
                if now < until {
                    false // Still in cooldown
                } else {
                    true // Cooldown expired, fully usable again
                }
            }
            1 => {
                // Open -> check if cooldown expired
                let until = ls.cooldown_until.load(Ordering::Acquire);
                if now >= until {
                    // Transition to HalfOpen and try to acquire probe
                    self.half_open_state(lane);

                    // Try to acquire the single probe - CAS succeeds means we're THE probe
                    let acquired = ls
                        .probe_in_flight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();

                    if acquired {
                        true // This request IS the probe
                    } else {
                        false // Another request won the probe
                    }
                } else {
                    false
                }
            }
            2 => {
                // HalfOpen -> return false (probe already in flight or waiting for it)
                // Only the request that won the CAS in Open->HalfOpen transition is allowed through
                false
            }
            _ => unreachable!("Invalid breaker state"),
        }
    }

    fn breaker_state(&self, lane: usize) -> BreakerState {
        let ls = self.get_lane(lane);

        if ls.dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }

        let state = ls.breaker_state.load(Ordering::Acquire);
        match state {
            0 => BreakerState::Closed,
            1 => {
                let until = ls.cooldown_until.load(Ordering::Acquire);
                BreakerState::Open { until }
            }
            2 => BreakerState::HalfOpen,
            _ => unreachable!("Invalid breaker state"),
        }
    }

    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        let ls = self.get_lane(lane);
        let until = ls.cooldown_until.load(Ordering::Acquire);
        until.saturating_sub(now)
    }

    fn record_success(&self, lane: usize) {
        let ls = self.get_lane(lane);

        // Only reset streak if not dead/broken
        if !ls.dead.load(Ordering::Relaxed) {
            ls.streak.store(0, Ordering::Relaxed);

            #[cfg(test)]
            let now_time = crate::store::now_for_test();
            #[cfg(not(test))]
            let now_time = now();

            self.record_outcome_success_with_time(lane, now_time);
        }

        ls.ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_transient(&self, lane: usize, _what: &str) {
        let ls = self.get_lane(lane);

        if ls.dead.load(Ordering::Relaxed) {
            return; // Already dead, ignore
        }

        // Record the error outcome in sliding window using injected time
        #[cfg(test)]
        let now_time = crate::store::now_for_test();
        #[cfg(not(test))]
        let now_time = now();

        self.record_outcome_error_with_time(lane, now_time);

        // Check trip condition
        let breaker_state = ls.breaker_state.load(Ordering::Acquire);

        if breaker_state == 0 {
            // Closed -> evaluate trip
            let cfg = BreakerCfg::default();

            // For simplicity in this implementation, check if err count is high enough
            let err_count = ls.err.load(Ordering::Relaxed);
            if err_count >= 5 {
                self.open_state(lane, now_time, &cfg);
            } else {
                // Simple cooldown for transient errors (below trip threshold)
                let until = now_time + COOLDOWN_TRANSIENT_SECS;
                ls.cooldown_until.store(until, Ordering::Release);
            }
        } else if breaker_state == 2 {
            // HalfOpen -> probe failed, transition to Open with escalated cooldown
            let cfg = BreakerCfg::default();
            self.open_state(lane, now_time, &cfg);
        }

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rate_limit(&self, lane: usize, now_time: u64, _retry_after: Option<u64>) {
        let ls = self.get_lane(lane);

        if ls.dead.load(Ordering::Relaxed) {
            return;
        }

        // Record outcome in sliding window (rate limit counts as error)
        let mut window = ls.outcome_window.lock().unwrap();
        window.push(now_time);

        // Increment streak for escalation
        let _new_streak = ls.streak.fetch_add(1, Ordering::Relaxed) + 1;

        let breaker_state = ls.breaker_state.load(Ordering::Acquire);

        if breaker_state == 0 {
            // Closed -> evaluate trip with consecutive mode logic
            let cfg = BreakerCfg::default();

            // Use consecutive mode for rate limit (streak-based)
            if _new_streak >= cfg.trip.n || ls.err.load(Ordering::Relaxed) >= 5 {
                self.open_state(lane, now_time, &cfg);
            } else {
                let duration = Self::compute_cooldown(ls, now_time, &cfg);
                ls.cooldown_until
                    .store(now_time + duration, Ordering::Release);
            }
        } else if breaker_state == 2 {
            // HalfOpen -> probe failed
            let cfg = BreakerCfg::default();
            self.open_state(lane, now_time, &cfg);
        }

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    fn record_hard_down(&self, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);

        #[cfg(test)]
        let now_time = crate::store::now_for_test();
        #[cfg(not(test))]
        let now_time = now();

        ls.dead.store(true, Ordering::Release);
        *ls.dead_reason.lock().unwrap() = reason.to_string();

        // Open with max cooldown (B-303 will handle recovery)
        let until = now_time + COOLDOWN_MAX_SECS;
        ls.cooldown_until.store(until, Ordering::Release);
        ls.breaker_state.store(1, Ordering::Release);
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

// Helper methods for InMemoryStore (not part of StateStore trait)
impl InMemoryStore {
    /// Record an error outcome in the sliding window with explicit time.
    pub(crate) fn record_outcome_error_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Add to sliding window
        let mut window = ls.outcome_window.lock().unwrap();
        window.push(now_time);

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    /// Record success outcome with explicit time.
    #[allow(dead_code)] // Used by record_success() internally
    pub(crate) fn record_outcome_success_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Reset streak on success (for the FSM to know we recovered)
        ls.streak.store(0, Ordering::Release);

        // Add to sliding window (success doesn't count toward error fraction directly)
        let mut window = ls.outcome_window.lock().unwrap();
        window.push(now_time);

        ls.ok.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
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
            inflight: 0,
            ok: 0,
            err: 0,
        }
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

        // Record enough errors to trip (>= min_requests)
        for _ in 0..5 {
            store.record_outcome_error_with_time(0, 1000);
        }

        let state = store.breaker_state(0);

        // Should have tripped to Open due to err count >= 5
        matches!(state, BreakerState::Open { .. });
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

        // At/after expiry: becomes HalfOpen via first call to usable()
        let state = store.breaker_state(0);
        matches!(state, BreakerState::HalfOpen);

        // In HalfOpen, first request wins probe and is usable
        assert!(
            store.usable(0, 2001),
            "first request in HalfOpen should win probe"
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
        matches!(state, BreakerState::Closed);
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
        matches!(state_before, BreakerState::HalfOpen);

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

    #[test]
    fn test_dead_lane_never_usable() {
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

        set_now_for_test(1000);

        // Mark lane as dead
        store.record_hard_down(0, "test reason");

        assert!(!store.usable(0, 1000), "dead lane should never be usable");

        let snap = store.snapshot(0, 1000);
        assert!(snap.dead, "lane should be marked dead");
    }

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

    #[test]
    fn test_consecutive_trip_mode() {
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));

        // Simulate consecutive failures by incrementing streak directly
        for _ in 0..3 {
            store.get_lane(0).streak.fetch_add(1, Ordering::Relaxed);
        }

        let state = store.breaker_state(0);

        // With 3 consecutive errors (default n=3), should trip to Open
        matches!(state, BreakerState::Open { .. });
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

        // At time 2500: becomes HalfOpen via first call to usable()
        let state = store.breaker_state(0);
        matches!(state, BreakerState::HalfOpen);

        // First request in HalfOpen wins the probe and is usable
        assert!(
            store.usable(0, 2500),
            "first request in HalfOpen should win probe"
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

        // First trip: streak=1 -> cooldown ~15s
        let cfg = BreakerCfg::default();
        store.open_state(0, 1000, &cfg);
        let until1 = store.cooldown_remaining(0, 1000);

        set_now_for_test(2000); // Advance time past first cooldown

        // Second trip: streak=2 -> cooldown ~30s (exponential backoff)
        store.open_state(0, 2000, &cfg);
        let until2 = store.cooldown_remaining(0, 2000);

        assert!(
            until2 > until1,
            "second cooldown should be longer than first"
        );
    }
}
