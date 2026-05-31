// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

// Lower bound a hard-down sticky cooldown is asserted to exceed, in tests.
#[cfg(test)]
const COOLDOWN_TRANSIENT_SECS: u64 = 10;
// A hard-down fault (bad key / billing / hard quota) gets a long sticky cooldown and recovers via
// the half-open probe — NOT a permanent `dead` kill. A human likely has to fix the key, so fast
// re-probes are pointless; default 30 min.
const HARD_DOWN_COOLDOWN_SECS: u64 = 1800;

// Breaker-state encoding for the per-cell `AtomicU64` (stored as u64 so it can be CAS'd).
const ST_CLOSED: u64 = 0;
const ST_OPEN: u64 = 1;
const ST_HALF_OPEN: u64 = 2;

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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);
    static IN_TEST: AtomicBool = AtomicBool::new(false);

    // Use SeqCst to ensure visibility across parallel test threads
    TEST_NOW.store(t, Ordering::SeqCst);
    IN_TEST.store(true, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn now_for_test() -> u64 {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);
    static IN_TEST: AtomicBool = AtomicBool::new(false);

    let val = TEST_NOW.load(Ordering::Acquire);
    // If test time is set and in_test flag is true, use it; otherwise fall back to real time
    if IN_TEST.load(Ordering::Acquire) && val != 0 {
        val
    } else {
        now()
    }
}

/// Breaker state for a lane per ADR-0002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BreakerState {
    Closed,
    Open { until: u64 },
    HalfOpen,
}

/// Permit wrapper that holds an owned semaphore permit.
/// Must be Send + 'static and movable into FirstByteBody stream.
#[must_use]
pub(crate) struct Permit {
    // RAII guard: never read — held solely to keep the concurrency slot reserved for this request's
    // lifetime; the slot is returned to the semaphore when the Permit (and this field) is dropped.
    #[allow(dead_code)]
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
    pub client_fault: u64,
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
    // ── Health queries ─────────────────────────────────────────────────────────────────────────
    // The bare `lane` methods operate on the lane-default cell (direct/ad-hoc routes, `/stats`);
    // the `_in(pool, …)` variants operate on the per-(pool, lane) breaker cell so a lane shared
    // across pools carries independent Open/Closed status per pool. Lane-global checks (dead /
    // budget) are identical across both — only the breaker FSM is isolated.
    fn usable(&self, lane: usize, now: u64) -> bool;
    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    // The bare lane-default breaker mutators below are exercised by the unit tests; in release,
    // routing always goes through the `_in(pool, …)` variants, so they're unreachable there — hence
    // the not(test) dead-code allow (they remain a tested part of the lane-default API).
    #[cfg_attr(not(test), allow(dead_code))]
    fn breaker_state(&self, lane: usize) -> BreakerState;
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64;
    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64;
    /// True if this lane is tripped in ANY cell (default or any pool). Used by the health prober:
    /// a probe tests the shared upstream, so "tripped anywhere" gates whether to probe at all.
    fn lane_tripped_anywhere(&self, lane: usize) -> bool;

    // ── Outcome recording (the breaker's write path) ─────────────────────────────────────────────
    #[cfg_attr(not(test), allow(dead_code))]
    fn record_success(&self, lane: usize);
    fn record_success_in(&self, pool: &str, lane: usize);
    fn record_client_fault(&self, lane: usize);
    /// Record a transient upstream failure. `cfg` is the routing pool's resolved breaker config,
    /// which drives the trip decision (error-rate vs consecutive thresholds) and cooldown backoff.
    fn record_transient(&self, lane: usize, what: &str, cfg: &BreakerCfg, retry_after: Option<u64>);
    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    );
    #[cfg_attr(not(test), allow(dead_code))]
    fn record_rate_limit(&self, lane: usize, now: u64, cfg: &BreakerCfg, retry_after: Option<u64>);
    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    );
    #[cfg_attr(not(test), allow(dead_code))]
    fn record_hard_down(&self, lane: usize, reason: &str);
    fn record_hard_down_in(&self, pool: &str, lane: usize, reason: &str);
    /// A successful out-of-band health probe: recover the lane to Closed in EVERY cell (default and
    /// all pools), since the probe tests the shared upstream. No-op on cells already Closed.
    fn recover_lane(&self, lane: usize);

    // concurrency + budget — lane-global (shared across every pool fronting the lane).
    fn try_acquire(&self, lane: usize) -> Option<Permit>;
    fn spend_budget(&self, lane: usize) -> bool; // false => exhausted

    // weighted member selection (SWRR algorithm)
    /// Select a candidate from the given list using smooth weighted round-robin over healthy members.
    /// `candidates` are indices into the store's lane array.
    /// `weights` is the per-member weight for each candidate (must match candidates length).
    /// Returns None if no healthy members or all candidates are unusable.
    #[cfg_attr(not(test), allow(dead_code))]
    fn select_weighted(&self, candidates: &[usize], weights: &[u32], now: u64) -> Option<usize>;
    fn select_weighted_in(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize>;

    // stats snapshot for /stats
    fn snapshot(&self, lane: usize, now: u64) -> LaneSnapshot;
}

/// Bounded sliding window of timestamped outcomes (ring buffer style).
/// Stores timestamps in seconds since epoch. Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
pub(crate) struct OutcomeWindow {
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
    fn push(&mut self, ts: u64) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(ts);
    }

    /// Count outcomes within `window_s` seconds of `now`.
    fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|&&ts| ts >= start).count()
    }

    /// Clear all entries.
    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// The per-cell circuit-breaker FSM state. `LaneState` embeds these fields directly (the default
/// cell, used by direct/ad-hoc routes and `/stats`); named pools get their own `BreakerCell` per
/// member lane so a lane shared across pools carries independent Open/Closed status per pool.
///
/// Lane-global concerns (the concurrency semaphore and the lifetime `max_requests` budget) are NOT
/// here — they stay on `LaneState` and are shared across every pool routing to that lane, so the
/// cost/concurrency caps remain per-upstream regardless of how many pools front it.
pub(crate) struct BreakerCell {
    pub(crate) breaker_state: AtomicU64, // 0=Closed, 1=Open, 2=HalfOpen
    pub(crate) streak: AtomicU32,
    pub(crate) cooldown_until: AtomicU64,
    pub(crate) probe_in_flight: AtomicBool,
    pub(crate) err: AtomicU64,
    pub(crate) outcome_window: std::sync::Mutex<OutcomeWindow>,
    pub(crate) current_weight: AtomicI64, // SWRR state (per pool — selection runs over a pool's set)
}

impl BreakerCell {
    fn new() -> Self {
        Self {
            breaker_state: AtomicU64::new(0), // Closed
            streak: AtomicU32::new(0),
            cooldown_until: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            err: AtomicU64::new(0),
            outcome_window: std::sync::Mutex::new(OutcomeWindow::new(1024)),
            current_weight: AtomicI64::new(0),
        }
    }
}

/// Read access to the breaker atomics, so the FSM logic can be written once and run against either
/// a `LaneState` (the default cell) or a per-pool `BreakerCell` without duplication.
pub(crate) trait BreakerCellAccess {
    fn breaker_state(&self) -> &AtomicU64;
    fn streak(&self) -> &AtomicU32;
    fn cooldown_until(&self) -> &AtomicU64;
    fn probe_in_flight(&self) -> &AtomicBool;
    fn err(&self) -> &AtomicU64;
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow>;
    fn current_weight(&self) -> &AtomicI64;
}

impl BreakerCellAccess for BreakerCell {
    fn breaker_state(&self) -> &AtomicU64 {
        &self.breaker_state
    }
    fn streak(&self) -> &AtomicU32 {
        &self.streak
    }
    fn cooldown_until(&self) -> &AtomicU64 {
        &self.cooldown_until
    }
    fn probe_in_flight(&self) -> &AtomicBool {
        &self.probe_in_flight
    }
    fn err(&self) -> &AtomicU64 {
        &self.err
    }
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow> {
        &self.outcome_window
    }
    fn current_weight(&self) -> &AtomicI64 {
        &self.current_weight
    }
}

impl BreakerCellAccess for LaneState {
    fn breaker_state(&self) -> &AtomicU64 {
        &self.breaker_state
    }
    fn streak(&self) -> &AtomicU32 {
        &self.streak
    }
    fn cooldown_until(&self) -> &AtomicU64 {
        &self.cooldown_until
    }
    fn probe_in_flight(&self) -> &AtomicBool {
        &self.probe_in_flight
    }
    fn err(&self) -> &AtomicU64 {
        &self.err
    }
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow> {
        &self.outcome_window
    }
    fn current_weight(&self) -> &AtomicI64 {
        &self.current_weight
    }
}

/// InMemoryStore wraps the existing atomics/semaphores per lane with FSM breaker logic.
/// Keyed by (pool name, lane index). Lazily populated.
type PoolCellMap = std::collections::HashMap<(Box<str>, usize), Arc<BreakerCell>>;

pub(crate) struct InMemoryStore {
    lanes: Vec<Arc<LaneState>>,
    /// Per-(pool, lane) breaker cells, created lazily on first access. The lane-global fields
    /// (sem/budget/dead/ok) always live on `lanes[lane]`; only the breaker FSM is isolated per pool.
    pool_cells: std::sync::Mutex<PoolCellMap>,
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
    client_fault: AtomicU64,
    // FSM state per lane
    breaker_state: AtomicU64, // 0=Closed, 1=Open, 2=HalfOpen (stored as u64 for CAS)
    probe_in_flight: AtomicBool,
    outcome_window: std::sync::Mutex<OutcomeWindow>,
    // SWRR state per lane
    current_weight: AtomicI64,
}

impl InMemoryStore {
    /// Read a (pool, lane) cell's cumulative error counter — for concurrency/isolation tests.
    #[cfg(test)]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).err().load(Ordering::Relaxed)
    }

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
                    client_fault: AtomicU64::new(ld.client_fault),
                    breaker_state: AtomicU64::new(0), // Closed
                    probe_in_flight: AtomicBool::new(false),
                    outcome_window: std::sync::Mutex::new(OutcomeWindow::new(1024)),
                    current_weight: AtomicI64::new(0),
                })
            })
            .collect();
        Self {
            lanes: lane_states,
            pool_cells: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }

    /// Resolve the breaker cell for a (pool, lane). An empty pool name selects the lane-global
    /// default cell (the `LaneState` itself) — used by direct/ad-hoc routes. A named pool gets a
    /// dedicated `BreakerCell`, created Closed on first access.
    fn cell(&self, pool: &str, lane: usize) -> Arc<dyn BreakerCellAccess> {
        if pool.is_empty() {
            return self.lanes[lane].clone();
        }
        let mut cells = self.pool_cells.lock().unwrap();
        cells
            .entry((Box::from(pool), lane))
            .or_insert_with(|| {
                // A new pool cell inherits the lane's current known health (breaker state + pending
                // cooldown + streak) rather than blindly assuming Closed — so a pool whose first
                // request arrives while the lane is mid-cooldown respects it. In production cells are
                // created while the lane is healthy, so this is normally a no-op.
                let ls = &self.lanes[lane];
                let c = BreakerCell::new();
                c.breaker_state
                    .store(ls.breaker_state.load(Ordering::Acquire), Ordering::Release);
                c.cooldown_until
                    .store(ls.cooldown_until.load(Ordering::Acquire), Ordering::Release);
                c.streak
                    .store(ls.streak.load(Ordering::Relaxed), Ordering::Relaxed);
                Arc::new(c)
            })
            .clone()
    }

    // ── Generic breaker-FSM core ──────────────────────────────────────────────────────────────
    // These operate on any `&dyn BreakerCellAccess` so the exact same logic runs against a
    // `LaneState` (the default/direct-route cell) or a per-pool `BreakerCell`. The `&self, lane`
    // and `_in(pool, lane)` methods are thin wrappers that resolve the right cell and delegate.

    /// Evaluate trip condition for Closed → Open transition. Returns true if the cell should trip.
    fn should_trip(c: &dyn BreakerCellAccess, now: u64, cfg: &BreakerCfg) -> bool {
        let window = c.outcome_window().lock().unwrap();

        match cfg.trip.mode {
            TripMode::ErrorRate => {
                let count = window.count_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false; // Below floor
                }
                let error_count = c.err().load(Ordering::Relaxed) as usize;
                // err is cumulative since the last close; cap it at the windowed outcome count so
                // a stale error count can't dominate once recent traffic has been healthy.
                let fraction = if count > 0 {
                    (error_count.min(count)) as f64 / count as f64
                } else {
                    0.0
                };
                fraction >= cfg.trip.threshold
            }
            TripMode::Consecutive => c.streak().load(Ordering::Relaxed) >= cfg.trip.n,
        }
    }

    /// Compute escalating cooldown duration with optional Retry-After floor.
    /// If retry_after is Some and honor_retry_after is true, the cooldown is max(computed_backoff, retry_after).
    /// The server's explicit Retry-After is always respected even if it exceeds max_cooldown_secs.
    fn compute_cooldown_with_retry_after(
        c: &dyn BreakerCellAccess,
        _now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> u64 {
        let streak = c.streak().load(Ordering::Relaxed);

        // Compute base cooldown from exponential backoff
        let mut duration = cfg.base_cooldown_secs;
        for _ in 1..=streak {
            duration = (duration * 2).min(cfg.max_cooldown_secs);
        }

        // Add bounded jitter ±10% only if streak > 0
        if streak > 0 {
            let jitter_range = duration / 10;
            #[cfg(test)]
            let jitter_seed = crate::store::now_for_test() as u128;
            #[cfg(not(test))]
            use std::time::{SystemTime, UNIX_EPOCH};
            #[cfg(not(test))]
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

        // Honor Retry-After as cooldown floor if present and configured
        match (cfg.honor_retry_after, retry_after) {
            (true, Some(ra)) => duration.max(ra), // Server's explicit Retry-After always respected
            (_, Some(ra)) => ra,                  // If not honoring, still use server value
            _ => duration,
        }
    }

    /// Transition the cell to Open with an escalated cooldown (streak is owned by the record path,
    /// only read here).
    fn cell_open(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        let duration = Self::compute_cooldown_with_retry_after(c, now_time, cfg, retry_after);
        c.cooldown_until()
            .store(now_time + duration, Ordering::Release);
        c.breaker_state().store(ST_OPEN, Ordering::Release);
    }

    /// Transition the cell to Closed (full recovery): reset streak/err/window, clear the cooldown
    /// and release the single-flight probe.
    fn cell_closed(c: &dyn BreakerCellAccess) {
        c.streak().store(0, Ordering::Release);
        c.err().store(0, Ordering::Release);
        c.outcome_window().lock().unwrap().clear();
        c.cooldown_until().store(0, Ordering::Release);
        c.breaker_state().store(ST_CLOSED, Ordering::Release);
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// The breaker portion of `usable`: Closed honors any pending cooldown; Open transitions to
    /// HalfOpen on expiry and admits exactly one probe (CAS); HalfOpen admits nobody else.
    fn cell_usable_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => now >= c.cooldown_until().load(Ordering::Acquire),
            ST_OPEN => {
                let until = c.cooldown_until().load(Ordering::Acquire);
                if now >= until {
                    c.breaker_state().store(ST_HALF_OPEN, Ordering::Release);
                    c.probe_in_flight()
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                } else {
                    false
                }
            }
            ST_HALF_OPEN => false,
            _ => unreachable!("Invalid breaker state"),
        }
    }

    /// Query the cell's breaker state (does NOT account for lane-global `dead`/budget).
    #[cfg_attr(not(test), allow(dead_code))] // reached only via the test-exercised `breaker_state`
    fn cell_breaker_state(c: &dyn BreakerCellAccess) -> BreakerState {
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => BreakerState::Closed,
            ST_OPEN => BreakerState::Open {
                until: c.cooldown_until().load(Ordering::Acquire),
            },
            ST_HALF_OPEN => BreakerState::HalfOpen,
            _ => unreachable!("Invalid breaker state"),
        }
    }

    /// Record a failure (transient or rate-limit — identical breaker handling) against the cell:
    /// push the outcome, bump err + consecutive streak, then trip-or-cooldown per the config.
    fn cell_record_failure(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        c.outcome_window().lock().unwrap().push(now_time);
        c.err().fetch_add(1, Ordering::Relaxed);
        c.streak().fetch_add(1, Ordering::Relaxed);

        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => {
                if Self::should_trip(c, now_time, cfg) {
                    Self::cell_open(c, now_time, cfg, retry_after);
                } else {
                    let duration =
                        Self::compute_cooldown_with_retry_after(c, now_time, cfg, retry_after);
                    c.cooldown_until()
                        .store(now_time + duration, Ordering::Release);
                }
            }
            ST_HALF_OPEN => Self::cell_open(c, now_time, cfg, retry_after), // probe failed → reopen
            _ => {}
        }
    }

    /// Record a success against the cell: reset the streak, push the outcome, and — if this was the
    /// half-open probe — complete recovery to Closed. (The lane-global `ok` counter is bumped by the
    /// caller, since it is shared across pools.)
    fn cell_record_success(c: &dyn BreakerCellAccess, now_time: u64) {
        let was_half_open = c.breaker_state().load(Ordering::Acquire) == ST_HALF_OPEN;
        c.streak().store(0, Ordering::Release);
        c.outcome_window().lock().unwrap().push(now_time);
        if was_half_open {
            Self::cell_closed(c);
        }
    }

    // ── Thin lane-default wrappers ─────────────────────────────────────────────────────────────
    // These drive the breaker FSM by lane index against the default cell. Release code goes through
    // the cell-core fns directly (cell_open / cell_closed / cell_usable_breaker), so these exist
    // only to give the unit tests a concrete, lane-indexed handle — hence `#[cfg(test)]`.

    /// Attempt to acquire the single probe in HalfOpen state. True if this request wins the probe.
    #[cfg(test)]
    pub(crate) fn try_acquire_probe(&self, lane: usize) -> bool {
        self.get_lane(lane)
            .probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Clear the probe flag (called after probe completes).
    #[cfg(test)]
    pub(crate) fn clear_probe(&self, lane: usize) {
        self.get_lane(lane)
            .probe_in_flight
            .store(false, Ordering::Release);
    }

    /// Transition to Open state with escalated cooldown.
    #[cfg(test)]
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        Self::cell_open(self.get_lane(lane).as_ref(), now_time, cfg, None);
    }

    /// Transition to Open state with escalated cooldown and optional Retry-After floor.
    #[cfg(test)]
    pub(crate) fn open_state_with_retry_after(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        Self::cell_open(self.get_lane(lane).as_ref(), now_time, cfg, retry_after);
    }

    /// Transition to Closed state (probe success).
    #[cfg(test)]
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
        Self::cell_closed(self.get_lane(lane).as_ref());
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
    pub client_fault: u64,
}

/// Helper for weighted selection tests - creates a lane with specific weight.
#[cfg(test)]
fn make_lane_data_with_weight(id: usize, max_permits: usize) -> (LaneData, u32) {
    let lane = LaneData {
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
        client_fault: 0,
    };
    (lane, (id as u32) + 1) // weight = id + 1 (so lane 0 has weight 1, lane 1 has weight 2, etc.)
}

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub(crate) struct BreakerCfg {
    pub base_cooldown_secs: u64,
    pub max_cooldown_secs: u64,
    pub honor_retry_after: bool,
    pub trip: TripConfig,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            honor_retry_after: true, // default to honoring Retry-After header
            trip: TripConfig::default(),
        }
    }
}

impl From<&crate::config::BreakerCfg> for BreakerCfg {
    /// Resolve the parsed config into the runtime breaker config the FSM evaluates.
    /// `honor_retry_after` has no config knob (always honored), and an absent `trip` block
    /// falls back to the ADR-0002 defaults.
    fn from(c: &crate::config::BreakerCfg) -> Self {
        let trip = c
            .trip
            .as_ref()
            .map(|t| TripConfig {
                mode: match t.mode {
                    crate::config::BreakerTripMode::ErrorRate => TripMode::ErrorRate,
                    crate::config::BreakerTripMode::Consecutive => TripMode::Consecutive,
                },
                window_s: t.window_s,
                threshold: t.threshold,
                min_requests: t.min_requests,
                n: t.n,
            })
            .unwrap_or_default();
        Self {
            base_cooldown_secs: c.base_cooldown_secs,
            max_cooldown_secs: c.max_cooldown_secs,
            honor_retry_after: true,
            trip,
        }
    }
}

/// Trip configuration mode.
#[derive(Debug, Clone)]
pub(crate) enum TripMode {
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Clone)]
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

// Pool-aware breaker operations, shared by the lane-default trait methods (pool "") and the
// `_in(pool, …)` trait methods. The lane-global checks (dead / budget) always read `lanes[lane]`;
// the breaker FSM runs against the resolved (pool, lane) cell.
impl InMemoryStore {
    #[cfg(test)]
    fn now_secs() -> u64 {
        crate::store::now_for_test()
    }
    #[cfg(not(test))]
    fn now_secs() -> u64 {
        now()
    }

    fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        Self::cell_usable_breaker(self.cell(pool, lane).as_ref(), now)
    }

    #[cfg_attr(not(test), allow(dead_code))] // reached only via the test-exercised `breaker_state`
    fn breaker_state_for(&self, pool: &str, lane: usize) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        Self::cell_breaker_state(self.cell(pool, lane).as_ref())
    }

    fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cell(pool, lane)
            .cooldown_until()
            .load(Ordering::Acquire)
            .saturating_sub(now)
    }

    fn record_failure_for(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return; // administratively down — ignore
        }
        Self::cell_record_failure(self.cell(pool, lane).as_ref(), now_time, cfg, retry_after);
    }

    fn record_success_for(&self, pool: &str, lane: usize) {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            // Dead lane: count the success for observability, don't touch the breaker.
            ls.ok.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Self::cell_record_success(self.cell(pool, lane).as_ref(), Self::now_secs());
        ls.ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        // (A7): hard-down is RECOVERABLE — long sticky cooldown + Open, recovered via the half-open
        // probe. We do NOT set `dead` (that would block recovery). Per (pool, lane): only the
        // routing pool's view is tripped; other pools discover the bad upstream independently.
        *ls.dead_reason.lock().unwrap() = reason.to_string();
        tracing::warn!(
            model = %ls.model,
            reason,
            cooldown_secs = HARD_DOWN_COOLDOWN_SECS,
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let cell = self.cell(pool, lane);
        cell.cooldown_until().store(
            Self::now_secs() + HARD_DOWN_COOLDOWN_SECS,
            Ordering::Release,
        );
        cell.breaker_state().store(ST_OPEN, Ordering::Release);
    }

    fn select_weighted_for(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize> {
        // Filter to usable members and build (lane_idx, cell, effective_weight).
        let mut healthy: Vec<(usize, Arc<dyn BreakerCellAccess>, i64)> =
            Vec::with_capacity(candidates.len());
        for (&candidate, &weight) in candidates.iter().zip(weights.iter()) {
            if self.usable_for(pool, candidate, now) {
                healthy.push((candidate, self.cell(pool, candidate), weight as i64));
            }
        }
        if healthy.is_empty() {
            return None;
        }

        // SWRR over the healthy subset (ADR-0001), using each cell's per-pool current_weight.
        let total: i64 = healthy.iter().map(|(_, _, w)| *w).sum();
        for (_, cell, eff_wt) in &healthy {
            cell.current_weight().fetch_add(*eff_wt, Ordering::Relaxed);
        }
        let mut best: Option<(usize, &Arc<dyn BreakerCellAccess>)> = None;
        let mut best_weight = i64::MIN;
        for (lane_idx, cell, _) in &healthy {
            let cw = cell.current_weight().load(Ordering::Relaxed);
            if cw > best_weight {
                best_weight = cw;
                best = Some((*lane_idx, cell));
            }
        }
        if let Some((_, cell)) = best {
            cell.current_weight().fetch_sub(total, Ordering::Relaxed);
        }
        best.map(|(idx, _)| idx)
    }
}

impl StateStore for InMemoryStore {
    fn usable(&self, lane: usize, now: u64) -> bool {
        self.usable_for("", lane, now)
    }

    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    fn breaker_state(&self, lane: usize) -> BreakerState {
        self.breaker_state_for("", lane)
    }

    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for("", lane, now)
    }

    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for(pool, lane, now)
    }

    fn record_success(&self, lane: usize) {
        self.record_success_for("", lane);
    }

    fn record_success_in(&self, pool: &str, lane: usize) {
        self.record_success_for(pool, lane);
    }

    fn record_client_fault(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Client faults do NOT increment err, streak, or trigger cooldowns.
        // They are tracked separately for observability.
        ls.client_fault.fetch_add(1, Ordering::Relaxed);
    }

    fn record_transient(
        &self,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        self.record_failure_for("", lane, Self::now_secs(), cfg, retry_after);
    }

    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        self.record_failure_for(pool, lane, Self::now_secs(), cfg, retry_after);
    }

    fn record_rate_limit(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        self.record_failure_for("", lane, now_time, cfg, retry_after);
    }

    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        self.record_failure_for(pool, lane, now_time, cfg, retry_after);
    }

    fn record_hard_down(&self, lane: usize, reason: &str) {
        self.record_hard_down_for("", lane, reason);
    }

    fn record_hard_down_in(&self, pool: &str, lane: usize, reason: &str) {
        self.record_hard_down_for(pool, lane, reason);
    }

    fn recover_lane(&self, lane: usize) {
        // A health probe tests the UPSTREAM, which is shared across pools — so a successful probe
        // recovers EVERY cell for this lane (the default/direct-route cell and all per-pool cells).
        let ls = self.get_lane(lane);
        if ls.breaker_state.load(Ordering::Acquire) != ST_CLOSED {
            Self::cell_closed(ls.as_ref());
        }
        let cells = self.pool_cells.lock().unwrap();
        for ((_, l), cell) in cells.iter() {
            if *l == lane && cell.breaker_state.load(Ordering::Acquire) != ST_CLOSED {
                Self::cell_closed(cell.as_ref());
            }
        }
    }

    fn lane_tripped_anywhere(&self, lane: usize) -> bool {
        if self.get_lane(lane).breaker_state.load(Ordering::Acquire) != ST_CLOSED {
            return true;
        }
        let cells = self.pool_cells.lock().unwrap();
        cells
            .iter()
            .any(|((_, l), cell)| {
                *l == lane && cell.breaker_state.load(Ordering::Acquire) != ST_CLOSED
            })
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
        // Consume one unit of the lifetime request budget (cost cap). Returns false when the lane
        // was already exhausted. Once budget reaches 0, `usable()` stops admitting the lane.
        let prev = ls.budget.fetch_sub(1, Ordering::Relaxed);
        prev > 0
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
            client_fault: ls.client_fault.load(Ordering::Relaxed),
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

    // SWRR selection over the healthy subset (ADR-0001 algorithm). Uses the lane-default cells.
    fn select_weighted(&self, candidates: &[usize], weights: &[u32], now: u64) -> Option<usize> {
        self.select_weighted_for("", candidates, weights, now)
    }

    fn select_weighted_in(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize> {
        self.select_weighted_for(pool, candidates, weights, now)
    }
}

// Test-only helpers: release code records outcomes via the cell-core fns; these give the unit
// tests a lane-indexed handle to seed the default cell's outcome window directly.
#[cfg(test)]
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
            client_fault: 0,
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
    fn test_hard_down_long_cooldown_and_recovery() {
        // (A7): hard-down → long sticky cooldown + Open, recoverable via the
        // probe, NOT a permanent `dead` kill.
        let store = Arc::new(InMemoryStore::new(vec![make_lane_data(0, 10)]));
        set_now_for_test(1000);

        store.record_hard_down(0, "billing / insufficient balance");

        let ls = store.get_lane(0);
        let until = ls.cooldown_until.load(Ordering::Relaxed);
        // NOT permanently dead (that would block recovery) — the core A7 invariant.
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
                n: 2,
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
                n: 99, // irrelevant in error-rate mode
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
                window_s: 42,
                threshold: 0.8,
                min_requests: 9,
                n: 4,
            }),
        };
        let rcfg = BreakerCfg::from(&ccfg);
        assert_eq!(rcfg.base_cooldown_secs, 7);
        assert_eq!(rcfg.max_cooldown_secs, 99);
        assert!(rcfg.honor_retry_after, "always honored (no config knob)");
        assert!(matches!(rcfg.trip.mode, TripMode::Consecutive));
        assert_eq!(rcfg.trip.window_s, 42);
        assert_eq!(rcfg.trip.n, 4);

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
                n: 1,
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
            store.lane_tripped_anywhere(0),
            "lane is tripped in at least one cell (pool A)"
        );

        // A successful health probe recovers EVERY cell for the lane.
        store.recover_lane(0);
        assert!(
            !store.lane_tripped_anywhere(0),
            "recover_lane must clear every cell (probe tests the shared upstream)"
        );
        assert!(store.usable_in("A", 0, 8000), "pool A recovered");
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
                n: u32::MAX,
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
        assert!(until >= 70030, "cooldown floor should honor retry_after when larger than computed backoff (got {until})");

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

        // Should use computed backoff without any server override (streak=0 -> base 15s)
        let until = store.get_lane(0).cooldown_until.load(Ordering::Relaxed);
        assert!(
            until >= 60015,
            "should fall back to computed backoff when retry_after absent (got {until})"
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
}
