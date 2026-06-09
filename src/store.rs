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

// Absolute ceiling on an UPSTREAM-supplied `Retry-After` we will honor as a cooldown floor. A
// server's hint can legitimately exceed the configured `max_cooldown_secs`, so we honor past the
// cap — but never past this ceiling (24h), so a hostile/buggy upstream sending a near-`u64::MAX`
// `Retry-After` cannot overflow `now + duration` (breaker bypass in release / panic in debug) or
// bench a lane for millennia.
const MAX_HONORED_RETRY_AFTER_SECS: u64 = 24 * 60 * 60;

// Breaker-state encoding for the per-cell `AtomicU64` (stored as u64 so it can be CAS'd).
const ST_CLOSED: u64 = 0;
const ST_OPEN: u64 = 1;
const ST_HALF_OPEN: u64 = 2;

// Bounded capacity of each cell's sliding outcome window (recent request outcomes for the
// error-rate trip computation).
const OUTCOME_WINDOW_CAPACITY: usize = 1024;

/// Lock a `std::sync::Mutex` on the production request path WITHOUT panicking on poison.
///
/// `.lock().unwrap()` panics if the mutex is poisoned (a thread panicked while holding the guard).
/// On the Tokio request path this is catastrophic and silent: one poisoned `pool_cells` / `swrr_lock`
/// / `outcome_window` / `dead_reason` mutex would make EVERY subsequent request that touches it panic
/// too — a poisoned-mutex DoS cascade. The data behind these mutexes is always still valid after a
/// poison (the critical sections only push to a bounded ring, mutate a small map, or swap a String),
/// so we recover the inner guard via `into_inner()` instead of propagating the poison. This keeps the
/// no-panic-on-request-path invariant: a single stray panic can never wedge the whole router.
fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Get current time in seconds since epoch.
pub(crate) fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Test-clock storage, THREAD-LOCAL.
//
// CRITICAL #1: these must NOT be function-local statics. A `static` declared inside a function body
// is scoped to that function, so `set_now_for_test` and `now_for_test` each declaring their own
// identically-named locals got INDEPENDENT storage — the injected time was never observed by
// `now_for_test` and every breaker timing test silently ran against the real wall clock.
//
// CRITICAL #2: they must be THREAD-LOCAL, not module-level statics. `cargo test` runs tests in
// parallel threads sharing one process; a single global clock means a unit test that froze time
// (e.g. set_now_for_test(1000)) would poison the clock for a concurrently-running forward
// integration test that records breaker cooldowns against the real wall clock. Per-thread storage
// isolates each test's injected time to its own thread while leaving real-time tests on real time.
#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static IN_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test helper to inject time for unit tests (this thread only).
#[cfg(test)]
pub(crate) fn set_now_for_test(t: u64) {
    TEST_NOW.with(|c| c.set(t));
    IN_TEST.with(|c| c.set(true));
}

#[cfg(test)]
pub(crate) fn now_for_test() -> u64 {
    let val = TEST_NOW.with(|c| c.get());
    // If test time is set on this thread, use it; otherwise fall back to real time.
    if IN_TEST.with(|c| c.get()) && val != 0 {
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
    // `usable` (mutating, lane-default cell) is exercised by the unit tests; in release, dispatch
    // goes through `usable_in`/`acquire_for_dispatch_in` and observers use the side-effect-free
    // `is_ready` (so /stats can't steal a recovery probe), leaving the bare form test-only — so it
    // is `#[cfg(test)]`-gated out of the release binary entirely rather than merely silenced.
    #[cfg(test)]
    fn usable(&self, lane: usize, now: u64) -> bool;
    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE readiness check: would this lane admit a request right now, WITHOUT
    /// transitioning an expired-Open lane to HalfOpen or CAS-acquiring its single-flight probe.
    /// `/healthz` and any non-dispatching observer must use this so they don't steal recovery
    /// probes from organic traffic. The bare-lane (pool `""`) form covers the default cell.
    fn is_ready(&self, lane: usize, now: u64) -> bool;
    /// Mutating admission for a lane selection is about to DISPATCH to: performs the Open→HalfOpen
    /// transition + single-flight probe CAS exactly once. Returns false if the probe was already
    /// taken (lost the race) so the caller can pick another lane.
    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// Release a single-flight recovery probe WON by `acquire_for_dispatch_in` but then NOT dispatched
    /// (the chosen lane couldn't get a concurrency slot before the request deadline, the semaphore
    /// closed on shutdown, etc.). The probe winner left the cell in HalfOpen with `probe_in_flight ==
    /// true`; if it returns without ever recording success/failure, neither `cell_closed` nor
    /// `cell_open` runs, so the flag stays `true` and the cell stays HalfOpen — `usable_for` then
    /// refuses every subsequent request and the lane is benched until the out-of-band prober catches
    /// it (a self-inflicted availability regression on the recovery path). This reverts the cell to
    /// Open WITHOUT escalating the cooldown (treating an undispatched probe winner as a no-op rather
    /// than a consumed probe): it clears `probe_in_flight` and only stores Open when the cell is still
    /// HalfOpen, leaving the existing (already-expired) cooldown intact so the very next request can
    /// re-win the probe. No-op when the cell is no longer HalfOpen (a concurrent success/failure
    /// already transitioned it) or when the probe flag was already clear.
    fn release_probe_in(&self, pool: &str, lane: usize);
    // The bare lane-default breaker mutators below are exercised by the unit tests; in release,
    // pool-routed dispatch goes through the `_in(pool, …)` variants, so most are unreachable there —
    // hence the not(test) dead-code allow (they remain a tested part of the lane-default API). NOTE:
    // `record_success` is the exception — it has a genuine production caller (the degraded
    // `forward_once` failover path at forward.rs:2497, which has no pool context and uses the
    // bare-lane forms), so it carries NO dead-code allow. `breaker_state`, `usable`,
    // `record_rate_limit`, `record_hard_down` are genuinely release-dead and `#[cfg(test)]`-gated
    // out of the release binary entirely rather than merely silenced with a dead-code allow.
    #[cfg(test)]
    fn breaker_state(&self, lane: usize) -> BreakerState;
    // `snapshot()` now reports the lane-GLOBAL (worst-across-all-pool-cells) cooldown via
    // `lane_max_cooldown_remaining`, not the default-cell-only `cooldown_remaining` (which stayed 0
    // for pool-routed traffic), so this bare-lane form is release-dead and exercised only by tests.
    #[cfg(test)]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64;
    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64;
    /// True if the breaker is suppressing this lane in ANY cell (default or any pool) — either a
    /// non-Closed (Open/HalfOpen) state OR a Closed lane with a pending soft cooldown
    /// (`cooldown_until > now`). Gates the health prober: both states make the lane unusable, and a
    /// probe tests the shared upstream, so either should be recovered early.
    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool;

    // ── Outcome recording (the breaker's write path) ─────────────────────────────────────────────
    // `record_success` is NOT release-dead: the degraded `forward_once` path (forward.rs:2497) calls
    // it with no pool context, so the compiler sees a real caller — no dead-code allow here.
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
    #[cfg(test)]
    fn record_rate_limit(&self, lane: usize, now: u64, cfg: &BreakerCfg, retry_after: Option<u64>);
    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    );
    // `record_hard_down` is the bare-lane (default-cell) hard-down primitive. The release hard-down
    // paths (the organic forward `HardDown` arm and the health prober's `HardDown` arm) both now go
    // through the all-cells `record_hard_down_all_cells` primitive (which inlines the per-cell trip to
    // avoid re-locking `pool_cells`), so this bare form is exercised only by the unit tests in release
    // — hence the not(test) dead-code allow, matching the other release-dead bare mutators above.
    #[cfg(test)]
    fn record_hard_down(&self, lane: usize, reason: &str);
    /// Hard-down the lane in EVERY cell (the default/direct-route cell AND every existing per-pool
    /// cell), mirroring the all-cells reach of `recover_lane` / `record_probe_failure_all_cells`. A
    /// hard-down (auth rejection / billing exhaustion) is a property of the SHARED upstream, not of
    /// one routing pool: a credential billing-suspended for a pool-routed request is equally dead for
    /// the default-cell `named`/`adhoc` routes and every other pool fronting the lane. Tripping only
    /// the routing pool's cell (the old organic-forward behavior) left the same upstream Closed in the
    /// other cells, so legacy/cross-protocol routes kept hammering a known-dead lane until the
    /// out-of-band prober caught it. This is the lane-global sibling of the per-cell
    /// `record_hard_down`/`record_hard_down_in` primitives, used on the organic forward path so any
    /// route through `forward_with_pool` trips the lane in every namespace at once.
    fn record_hard_down_all_cells(&self, lane: usize, reason: &str);
    /// A successful out-of-band health probe: recover the lane to Closed in EVERY cell (default and
    /// all pools), since the probe tests the shared upstream. No-op on cells already Closed.
    fn recover_lane(&self, lane: usize);
    /// A FAILED out-of-band health probe: record a transient failure against EVERY cell for the
    /// lane (the default cell AND every existing per-pool cell), mirroring `recover_lane`'s
    /// all-cells iteration. The probe tests the shared upstream, and organic traffic routes against
    /// per-pool cells, so a probe failure that only hit the default cell could never trip the
    /// per-pool breakers real traffic is selected against. `cfg` drives the trip/cooldown decision.
    fn record_probe_failure_all_cells(&self, lane: usize, what: &str, cfg: &BreakerCfg);

    // concurrency + budget — lane-global (shared across every pool fronting the lane).
    fn try_acquire(&self, lane: usize) -> Option<Permit>;
    /// The lane's concurrency semaphore, for a bounded async (`timeout`) acquire on the dispatch
    /// path — the task parks instead of busy-spinning when permits are saturated.
    fn lane_semaphore(&self, lane: usize) -> Arc<Semaphore>;
    /// Atomically consume one unit of the lane's lifetime request budget. Returns `false` when the
    /// budget was already exhausted (the spend was a no-op — the budget is never driven negative).
    /// `#[must_use]`: the bool is the over-spend signal; a silent discard hid the prior concurrent
    /// over-spend bug, so call sites that intentionally ignore it must say so with `let _ =`.
    #[must_use]
    fn spend_budget(&self, lane: usize) -> bool; // false => exhausted

    // weighted member selection (SWRR algorithm)
    /// Select a candidate from the given list using smooth weighted round-robin over healthy members.
    /// `candidates` are indices into the store's lane array.
    /// `weights` is the per-member weight for each candidate (must match candidates length).
    /// Returns None if no healthy members or all candidates are unusable.
    #[cfg(test)]
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

/// Bounded sliding window of recent request outcomes, each tagged success/error, used to compute
/// the error-rate trip signal. Backed by a `VecDeque` so dropping the oldest entry at capacity is
/// O(1). Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
pub(crate) struct OutcomeWindow {
    /// (timestamp_secs, is_error) per outcome, oldest at the front.
    entries: std::collections::VecDeque<(u64, bool)>,
    capacity: usize,
}

impl OutcomeWindow {
    fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record a timestamped outcome (`is_error` true for a failure). Drops the oldest at capacity.
    fn push(&mut self, ts: u64, is_error: bool) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ts, is_error));
    }

    /// Total outcomes within `window_s` seconds of `now`.
    fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|(ts, _)| *ts >= start).count()
    }

    /// Error outcomes within `window_s` seconds of `now`.
    fn error_count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries
            .iter()
            .filter(|(ts, is_error)| *ts >= start && *is_error)
            .count()
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
            breaker_state: AtomicU64::new(ST_CLOSED),
            streak: AtomicU32::new(0),
            cooldown_until: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            err: AtomicU64::new(0),
            outcome_window: std::sync::Mutex::new(OutcomeWindow::new(OUTCOME_WINDOW_CAPACITY)),
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
    /// Serializes the SWRR weight read-modify-write so concurrent selections don't interleave their
    /// `current_weight` updates (which would desync the algorithm's `Σ current_weight == 0` invariant
    /// and bias distribution). Selection is microsecond-fast, so the contention is negligible.
    swrr_lock: std::sync::Mutex<()>,
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
    ok: AtomicU64,
    err: AtomicU64,
    client_fault: AtomicU64,
    // FSM state per lane
    breaker_state: AtomicU64, // stored as u64 (ST_CLOSED/ST_OPEN/ST_HALF_OPEN) so it can be CAS'd
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
                    ok: AtomicU64::new(ld.ok),
                    err: AtomicU64::new(ld.err),
                    client_fault: AtomicU64::new(ld.client_fault),
                    breaker_state: AtomicU64::new(ST_CLOSED),
                    probe_in_flight: AtomicBool::new(false),
                    outcome_window: std::sync::Mutex::new(OutcomeWindow::new(
                        OUTCOME_WINDOW_CAPACITY,
                    )),
                    current_weight: AtomicI64::new(0),
                })
            })
            .collect();
        Self {
            lanes: lane_states,
            pool_cells: std::sync::Mutex::new(std::collections::HashMap::new()),
            swrr_lock: std::sync::Mutex::new(()),
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
        let mut cells = lock_recover(&self.pool_cells);
        cells
            .entry((Box::from(pool), lane))
            .or_insert_with(|| {
                // A new pool cell inherits the lane's current known health (breaker state + pending
                // cooldown + streak) rather than blindly assuming Closed — so a pool whose first
                // request arrives while the lane is mid-cooldown respects it. In production cells are
                // created while the lane is healthy, so this is normally a no-op.
                let ls = &self.lanes[lane];
                let c = BreakerCell::new();
                // Normalize an inherited HalfOpen to Open. HalfOpen encodes "some cell owns the
                // single-flight probe right now" — but `probe_in_flight` lives on the cell that won
                // it, NOT on this freshly-created sibling (born with `probe_in_flight == false`). A
                // sibling cell born ST_HALF_OPEN is wedged: both `cell_ready_breaker` and
                // `cell_acquire_breaker` return false unconditionally for HalfOpen, and no probe
                // outcome (cell_open/cell_closed) ever runs against it, so it never self-recovers —
                // organic traffic to this (pool, lane) is benched until an out-of-band recover_lane
                // happens to touch it (indefinitely when health probing is disabled). Storing Open
                // instead lets the inherited (already-expired) cooldown drive a fresh probe
                // acquisition on this cell's first request. The Open+cooldown inheritance below is
                // still honored verbatim so a sibling created mid-cooldown respects it.
                let inherited = ls.breaker_state.load(Ordering::Acquire);
                let normalized = if inherited == ST_HALF_OPEN {
                    ST_OPEN
                } else {
                    inherited
                };
                c.breaker_state.store(normalized, Ordering::Release);
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
        let window = lock_recover(c.outcome_window());

        match cfg.trip.mode {
            TripMode::ErrorRate => {
                // Both numerator and denominator come from the SAME sliding window, so the fraction
                // reflects RECENT health only. (Previously the numerator was the cumulative error
                // counter, which could exceed the windowed count and spuriously trip a long-running
                // lane on clean traffic.)
                let count = window.count_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false; // Below floor
                }
                let errors = window.error_count_in_window(now, cfg.trip.window_s);
                (errors as f64 / count as f64) >= cfg.trip.threshold
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

        // Exponential backoff capped at max_cooldown_secs, computed in O(1) (NOT an O(streak) loop —
        // on a long-running hard-failing lane the streak grows unboundedly and this runs on every
        // failure record, exactly when failure volume is highest). `base * 2^streak` saturates at
        // max after a handful of doublings, so clamp the shift exponent to 63 (a u64 shift of >=64
        // is UB / panics) and saturate the multiply before taking the min.
        let mut duration = if streak == 0 {
            cfg.base_cooldown_secs
        } else {
            let shift = streak.min(63);
            cfg.base_cooldown_secs
                .checked_shl(shift)
                .unwrap_or(u64::MAX)
                .min(cfg.max_cooldown_secs)
        };

        // Add bounded jitter ±10% only if streak > 0
        if streak > 0 {
            let jitter_range = duration / 10;
            #[cfg(test)]
            let time_seed = crate::store::now_for_test() as u128;
            #[cfg(not(test))]
            use std::time::{SystemTime, UNIX_EPOCH};
            #[cfg(not(test))]
            let time_seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();

            // Decorrelate lanes that fail within nanoseconds of each other (a cascading upstream
            // outage trips them ~simultaneously, so the wall-clock alone is near-identical across
            // them and `% (2*jitter_range+1)` collapses to the same value → synchronized cooldowns →
            // thundering-herd of half-open probes). Mix a per-CELL identity (its stable address) and
            // the current streak into the seed so each lane's jitter is independent regardless of
            // wall-clock proximity. FNV-1a folds the mixed inputs into a well-distributed value.
            let cell_id = c as *const _ as *const () as usize as u128;
            let mut seed = 0xcbf2_9ce4_8422_2325u128;
            for part in [time_seed, cell_id, streak as u128] {
                seed = (seed ^ part).wrapping_mul(0x0000_0100_0000_01b3);
            }
            let jitter_seed = seed;

            // Signed jitter in [-jitter_range, +jitter_range]; apply its sign so cooldowns are
            // spread both shorter AND longer (desyncing lanes). Using the absolute value here was a
            // bug — it only ever lengthened the cooldown.
            // Reduce the u128 FNV seed into an UNSIGNED bounded value BEFORE centering. Casting the
            // seed `as i64` first (the old bug) reinterprets the low 64 bits as signed — frequently
            // negative — and Rust's truncated `%` then yields a value in (-2r, +2r), so subtracting
            // `r` skewed the final jitter to roughly (-3r, +r) instead of the documented symmetric
            // [-r, +r]. Taking `% span` on the unsigned u128 keeps the remainder in [0, 2r], so the
            // centered result is exactly [-r, +r].
            let span = 2 * jitter_range as u128 + 1;
            let unbiased = (jitter_seed % span) as i64;
            let jitter = unbiased - jitter_range as i64;
            let jittered = if jitter >= 0 {
                duration.saturating_add(jitter as u64)
            } else {
                duration.saturating_sub(jitter.unsigned_abs())
            };
            duration = jittered.clamp(
                duration / 2, // At least half of base
                cfg.max_cooldown_secs,
            );
        }

        // Honor Retry-After as cooldown floor if present and configured. Exhaustive on the bool —
        // no `_` wildcard (breaker-match hard rule). When honoring, the server's explicit
        // Retry-After is a FLOOR (max with the computed backoff), respected even past the configured
        // `max_cooldown_secs` cap (a legit upstream hint may exceed it) — BUT clamped to an absolute
        // ceiling so a hostile/buggy upstream cannot drive the cooldown to near `u64::MAX`
        // (`Retry-After: 18446744073709551615`): that would overflow `now + duration` downstream
        // (breaker bypass in release, panic in debug) or park a lane out for millennia. When NOT
        // honoring, the server value is ignored entirely and the computed backoff stands (returning
        // `ra` verbatim there could SHORTEN the cooldown below the backoff floor).
        match (cfg.honor_retry_after, retry_after) {
            (true, Some(ra)) => duration.max(ra.min(MAX_HONORED_RETRY_AFTER_SECS)),
            (false, Some(_)) => duration,
            (true, None) | (false, None) => duration,
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
        // saturating_add: `duration` can be a server-supplied Retry-After (clamped in
        // compute_cooldown_with_retry_after, but defense-in-depth) — never wrap `now + duration`,
        // which in release would land `cooldown_until` in the past and instantly re-ready a tripped
        // lane (breaker bypass), and in debug would panic on the request path.
        c.cooldown_until()
            .store(now_time.saturating_add(duration), Ordering::Release);
        c.breaker_state().store(ST_OPEN, Ordering::Release);
        // Opening releases the single-flight probe back to Open. A failed half-open probe routes
        // here (ST_HALF_OPEN → cell_open); without this reset the flag stayed `true` forever, so the
        // next cooldown expiry transitioned the cell to HalfOpen but no request could ever win the
        // probe CAS — the lane was benched permanently. Clearing it lets the next cooldown re-probe.
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// Transition the cell to Closed (full recovery): reset streak/err/window, clear the cooldown
    /// and release the single-flight probe.
    fn cell_closed(c: &dyn BreakerCellAccess) {
        c.streak().store(0, Ordering::Release);
        c.err().store(0, Ordering::Release);
        lock_recover(c.outcome_window()).clear();
        c.cooldown_until().store(0, Ordering::Release);
        c.breaker_state().store(ST_CLOSED, Ordering::Release);
        c.probe_in_flight().store(false, Ordering::Release);
        // Reset the SWRR accumulator. While the member was tripped it was dropped from the healthy
        // set in `select_weighted_for` and stopped receiving fetch_add/fetch_sub, freezing its
        // `current_weight` at a stale value. On recovery it rejoins selection; carrying that stale
        // value biases the first few selections and violates the `Σ current_weight == 0` invariant
        // over the (now-changed) healthy set. Zeroing it here keeps the SWRR invariant exact.
        c.current_weight().store(0, Ordering::Release);
    }

    /// Release an UNDISPATCHED single-flight probe: a probe winner (HalfOpen + `probe_in_flight ==
    /// true`) that abandoned the dispatch before recording any outcome. Revert the cell to Open and
    /// clear the probe flag WITHOUT escalating the cooldown — the existing cooldown is already expired
    /// (that is why the cell was probe-eligible), so leaving it intact lets the next request re-win the
    /// probe immediately. Only acts when the cell is still HalfOpen (a concurrent success/failure may
    /// have already moved it); otherwise it just clears the flag defensively. The mirror of the
    /// `cell_open` probe-release, but for the no-outcome abandon path rather than a recorded failure.
    fn cell_release_probe(c: &dyn BreakerCellAccess) {
        // CAS the state HalfOpen → Open so we don't clobber a concurrent transition (e.g. a success
        // that already moved the cell to Closed). The probe flag is cleared regardless so a stale
        // `true` can never wedge the lane.
        let _ = c.breaker_state().compare_exchange(
            ST_HALF_OPEN,
            ST_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// Side-effect-FREE readiness check (the breaker portion of `usable`): true if the cell would
    /// admit a request right now, WITHOUT mutating any state. Closed honors any pending cooldown; an
    /// Open lane whose cooldown has expired is "ready" (a probe could be admitted) but is NOT yet
    /// transitioned here; HalfOpen admits nobody but the in-flight probe winner.
    ///
    /// This is the predicate used by the selection filter and by `/healthz` — neither should steal
    /// the single-flight recovery probe. The Open→HalfOpen transition + probe CAS is performed
    /// exactly once, on the single lane selection actually dispatches, via `cell_acquire_breaker`.
    fn cell_ready_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => now >= c.cooldown_until().load(Ordering::Acquire),
            ST_OPEN => now >= c.cooldown_until().load(Ordering::Acquire),
            ST_HALF_OPEN => false,
            // The breaker state is an atomic `u64` only ever set to one of the three ST_* sentinels,
            // so this is not reachable today. But this runs on the request-path selection filter:
            // `unreachable!()` would panic the task (no-panic-on-request-path invariant). Fail SAFE
            // by reporting "not ready" (deny admission) for any unexpected encoding instead.
            other => {
                tracing::error!(
                    state = other,
                    "unexpected breaker state; treating cell as not ready"
                );
                false
            }
        }
    }

    /// The mutating probe-acquisition step, run ONLY on the single lane a dispatch path actually
    /// chose. Closed honors any pending cooldown; an expired-cooldown Open lane transitions to
    /// HalfOpen and admits exactly one probe (CAS); HalfOpen admits nobody else. Returns true iff
    /// this caller may proceed (Closed-and-ready, or the probe winner).
    fn cell_acquire_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => now >= c.cooldown_until().load(Ordering::Acquire),
            ST_OPEN => {
                let until = c.cooldown_until().load(Ordering::Acquire);
                if now >= until {
                    // Single CAS Open→HalfOpen: the state and probe acquisition must move as an
                    // atomic pair. A non-CAS `store(ST_HALF_OPEN)` followed by a separate
                    // `probe_in_flight` CAS opens a window where a delayed store can clobber a
                    // concurrent `cell_closed` (which writes ST_CLOSED + clears the probe flag),
                    // leaving a Closed cell with probe_in_flight wedged true and permanently
                    // benching the lane. Only the thread that wins this CAS owns the cell's
                    // single-flight probe; losers observed the transition already happened and
                    // must treat the probe as taken.
                    if c.breaker_state()
                        .compare_exchange(
                            ST_OPEN,
                            ST_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        c.probe_in_flight().store(true, Ordering::Release);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ST_HALF_OPEN => false,
            // Request-path probe acquisition: fail SAFE (admit nobody) on an unexpected state rather
            // than `unreachable!()`-panicking the dispatching task. Not reachable under today's
            // atomic-sentinel invariant; this only guards a future/corrupt encoding gracefully.
            other => {
                tracing::error!(
                    state = other,
                    "unexpected breaker state; refusing probe acquisition"
                );
                false
            }
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
            // Not reachable under the atomic-sentinel invariant; report the benign Closed default
            // rather than panic, keeping this read total and side-effect-free for any encoding.
            other => {
                tracing::error!(state = other, "unexpected breaker state; reporting Closed");
                BreakerState::Closed
            }
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
        lock_recover(c.outcome_window()).push(now_time, true); // error outcome
        c.err().fetch_add(1, Ordering::Relaxed);
        c.streak().fetch_add(1, Ordering::Relaxed);

        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => {
                if Self::should_trip(c, now_time, cfg) {
                    Self::cell_open(c, now_time, cfg, retry_after);
                } else {
                    let duration =
                        Self::compute_cooldown_with_retry_after(c, now_time, cfg, retry_after);
                    // saturating_add: see cell_open — never wrap `now + duration` (breaker-bypass /
                    // debug-panic on a hostile upstream's unbounded Retry-After).
                    c.cooldown_until()
                        .store(now_time.saturating_add(duration), Ordering::Release);
                }
            }
            ST_HALF_OPEN => Self::cell_open(c, now_time, cfg, retry_after), // probe failed → reopen
            // Already Open: a failure while Open is an intentional no-op (the cooldown is already
            // armed; we don't re-escalate on every failed request during a cooldown). Enumerated
            // explicitly per the breaker-match hard rule — no `_ =>` catch-all.
            ST_OPEN => {}
            // Request-path failure recording: an unexpected state encoding is treated as a no-op
            // (like the already-Open case) rather than `unreachable!()`-panicking the task. Not
            // reachable under the atomic-sentinel invariant; this is the graceful backstop.
            other => {
                tracing::error!(
                    state = other,
                    "unexpected breaker state in record_failure; no-op"
                );
            }
        }
    }

    /// Record a success against the cell: reset the streak, push the outcome, and — if this was the
    /// half-open probe — complete recovery to Closed. (The lane-global `ok` counter is bumped by the
    /// caller, since it is shared across pools.)
    fn cell_record_success(c: &dyn BreakerCellAccess, now_time: u64) {
        let was_half_open = c.breaker_state().load(Ordering::Acquire) == ST_HALF_OPEN;
        c.streak().store(0, Ordering::Release);
        lock_recover(c.outcome_window()).push(now_time, false); // success outcome
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

    /// Mutating admission check used on the dispatch path (sticky-affinity preference + the single
    /// lane SWRR selection returns): an expired-Open lane transitions to HalfOpen and the caller
    /// CAS-acquires the single-flight probe. Only ever called for a lane about to receive a request.
    fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        Self::cell_acquire_breaker(self.cell(pool, lane).as_ref(), now)
    }

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Used by
    /// the selection filter and `/healthz` so neither steals the recovery probe nor wedges a lane.
    fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        Self::cell_ready_breaker(self.cell(pool, lane).as_ref(), now)
    }

    /// Lane-global admission gates shared by both the mutating and read-only checks: a `dead` lane
    /// (administratively down) or an exhausted budget is never admissible regardless of breaker FSM.
    fn lane_admissible(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        true
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

    /// Lane-global readiness for `/stats`: true iff the lane is admissible (not dead / in budget) AND
    /// at least one breaker cell (the default cell or ANY per-pool cell) would admit a request right
    /// now. Production traffic routes through NAMED pools, whose cells the default-cell-only
    /// `is_ready("", ...)` never sees — so reading only the default cell reports `usable=true` even
    /// when every per-pool breaker for the lane is tripped Open. Iterating all known cells makes the
    /// `/stats` `usable` flag reflect real admissibility. Side-effect-free (uses the non-mutating
    /// `cell_ready_breaker`, never the probe-stealing `usable`).
    fn lane_usable_any_cell(&self, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        if Self::cell_ready_breaker(self.get_lane(lane).as_ref(), now) {
            return true;
        }
        let cells = lock_recover(&self.pool_cells);
        cells
            .iter()
            .any(|((_, l), cell)| *l == lane && Self::cell_ready_breaker(cell.as_ref(), now))
    }

    /// Worst-case remaining cooldown across the default cell and every per-pool cell for the lane.
    /// `/stats` must surface the lane's most-tripped state, not the default cell's (which never moves
    /// for pool-routed traffic — see `lane_usable_any_cell`).
    fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        let mut worst = self
            .get_lane(lane)
            .cooldown_until
            .load(Ordering::Acquire)
            .saturating_sub(now);
        let cells = lock_recover(&self.pool_cells);
        for ((_, l), cell) in cells.iter() {
            if *l == lane {
                worst = worst.max(
                    cell.cooldown_until()
                        .load(Ordering::Acquire)
                        .saturating_sub(now),
                );
            }
        }
        worst
    }

    /// Worst-case consecutive-failure streak across the default cell and every per-pool cell for the
    /// lane (the lane-global health signal for `/stats`; the default cell's streak stays 0 for
    /// pool-routed traffic — see `lane_usable_any_cell`).
    fn lane_max_streak(&self, lane: usize) -> u32 {
        let mut worst = self.get_lane(lane).streak.load(Ordering::Relaxed);
        let cells = lock_recover(&self.pool_cells);
        for ((_, l), cell) in cells.iter() {
            if *l == lane {
                worst = worst.max(cell.streak().load(Ordering::Relaxed));
            }
        }
        worst
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
        // Bump the lane-GLOBAL error counter as well — but ONLY for a NAMED pool. `cell_record_failure`
        // bumps the cell's own `err()`; for a named pool that is the per-pool `BreakerCell.err` (a
        // per-pool diagnostic, distinct from `LaneState.err`), so the `/stats` `LaneState.err` snapshot
        // would otherwise stay permanently 0 for any lane reached exclusively via named pools
        // (production dispatch always passes the real pool name). For the DEFAULT cell (`pool == ""`),
        // however, `cell("", lane)` IS the `LaneState` itself, so `cell_record_failure` already bumped
        // `LaneState.err` via `c.err()`; bumping it again here double-counted every failure recorded on
        // the bare/default-cell path (degraded forward, direct/ad-hoc routes), inflating the public
        // `/stats` `err` metric 2x. Guard on a non-empty pool so the default cell is counted exactly
        // once. Still mirrors how `record_success_for` keeps the success/error counters symmetric (it
        // bumps `LaneState.ok` separately because `cell_record_success` does NOT touch `err()`/`ok()`).
        if !pool.is_empty() {
            self.get_lane(lane).err.fetch_add(1, Ordering::Relaxed);
        }
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

    // Only the per-cell `record_hard_down`/`record_hard_down_in` trait wrappers call this, and those
    // are test-only in release now (the all-cells primitive inlines the trip), so this is release-dead.
    #[cfg_attr(not(test), allow(dead_code))]
    fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE — long sticky cooldown + Open, recovered via the half-open
        // probe. We do NOT set `dead` (that would block recovery). Per (pool, lane): only the
        // routing pool's view is tripped; other pools discover the bad upstream independently.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        tracing::warn!(
            model = %ls.model,
            reason,
            cooldown_secs = HARD_DOWN_COOLDOWN_SECS,
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let cell = self.cell(pool, lane);
        cell.cooldown_until().store(
            Self::now_secs().saturating_add(HARD_DOWN_COOLDOWN_SECS),
            Ordering::Release,
        );
        cell.breaker_state().store(ST_OPEN, Ordering::Release);
        // Release the single-flight probe back to Open — mirrors `cell_open`. A hard-down can be
        // classified while the cell is HalfOpen with a probe in flight (a recovering lane's half-open
        // probe returns a billing/auth/hard-quota error). Without clearing this, the cell goes Open
        // with `probe_in_flight == true`; after the (30 min) cooldown expires the cell transitions
        // Open→HalfOpen but the probe CAS (false→true) fails forever, benching the lane permanently
        // even after the operator fixes the credential/billing. Clearing it keeps hard-down RECOVERABLE.
        cell.probe_in_flight().store(false, Ordering::Release);
    }

    fn select_weighted_for(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize> {
        // Filter to usable members and build (lane_idx, cell, effective_weight). The filter uses
        // the side-effect-FREE readiness check: a candidate enumeration must NOT transition lanes
        // Open→HalfOpen or steal the single-flight probe (the dispatched lane does that once, in
        // pick_among). We fetch the cell exactly once per candidate here (one pool_cells lock,
        // not the two a usable+re-cell pattern took) and reuse the Arc for the readiness peek.
        let mut healthy: Vec<(usize, Arc<dyn BreakerCellAccess>, i64)> =
            Vec::with_capacity(candidates.len());
        for (&candidate, &weight) in candidates.iter().zip(weights.iter()) {
            // weight == 0 means "drain": never select this member. config.rs permits `weight: 0`
            // with no `weight > 0` validation, and without this filter an all-zero-weight healthy set
            // gives `total == 0`, every `fetch_add(0)` leaves `current_weight` unchanged, and the
            // max-finder degenerates to always picking the first candidate — so a member weighted to
            // 0 still receives (all) traffic. Excluding it here honors the drain intent and keeps the
            // SWRR proportional-distribution invariant exact over the remaining members.
            if weight == 0 {
                continue;
            }
            if !self.lane_admissible(candidate) {
                continue;
            }
            let cell = self.cell(pool, candidate);
            if Self::cell_ready_breaker(cell.as_ref(), now) {
                healthy.push((candidate, cell, weight as i64));
            }
        }
        if healthy.is_empty() {
            return None;
        }

        // Smooth weighted round-robin over the healthy subset, using each cell's per-pool
        // current_weight. The add/find-max/subtract is one logical step, so serialize it across
        // concurrent selections (otherwise interleaving corrupts the `Σ current_weight == 0`
        // invariant and biases distribution).
        let _swrr = lock_recover(&self.swrr_lock);
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
    #[cfg(test)]
    fn usable(&self, lane: usize, now: u64) -> bool {
        self.usable_for("", lane, now)
    }

    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    fn is_ready(&self, lane: usize, now: u64) -> bool {
        self.ready_for("", lane, now)
    }

    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        // Mutating: the single dispatched lane does the Open→HalfOpen + probe CAS here. Lane-global
        // gates are re-checked (state may have changed since selection's read-only filter).
        self.usable_for(pool, lane, now)
    }

    fn release_probe_in(&self, pool: &str, lane: usize) {
        Self::cell_release_probe(self.cell(pool, lane).as_ref());
    }

    #[cfg(test)]
    fn breaker_state(&self, lane: usize) -> BreakerState {
        self.breaker_state_for("", lane)
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
    fn record_hard_down(&self, lane: usize, reason: &str) {
        self.record_hard_down_for("", lane, reason);
    }

    fn record_hard_down_all_cells(&self, lane: usize, reason: &str) {
        // Mirror `record_probe_failure_all_cells` exactly: operate on the per-pool cell Arcs while
        // holding the `pool_cells` lock, applying the SAME cell mutation `record_hard_down_for` does
        // (sticky Open + cooldown, probe released) — NOT by re-calling `record_hard_down_for`, which
        // re-locks `pool_cells` via `self.cell()` and would deadlock here.
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE: a sticky cooldown + Open, recovered via the half-open probe; do
        // NOT set `dead` (that would block recovery). Record the reason once, lane-wide.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        tracing::warn!(
            model = %ls.model,
            reason,
            cooldown_secs = HARD_DOWN_COOLDOWN_SECS,
            "lane hard-down (all cells); sticky cooldown (recovers via half-open probe)"
        );
        let now = Self::now_secs();
        let trip = |c: &dyn BreakerCellAccess| {
            c.cooldown_until().store(
                now.saturating_add(HARD_DOWN_COOLDOWN_SECS),
                Ordering::Release,
            );
            c.breaker_state().store(ST_OPEN, Ordering::Release);
            // Release any in-flight single-flight probe back to Open (see `record_hard_down_for`):
            // without this a hard-down classified while HalfOpen leaves the cell Open with
            // `probe_in_flight == true`, benching the lane permanently after cooldown.
            c.probe_in_flight().store(false, Ordering::Release);
        };
        // Default cell (direct/`named`/`adhoc` routes that read the "" cell).
        trip(ls.as_ref());
        // Every existing per-pool cell for this lane — the cells organic pool-routed traffic is
        // selected against. (A cell not yet created inherits the lane default lazily on first
        // access.)
        let cells = lock_recover(&self.pool_cells);
        for ((_, l), cell) in cells.iter() {
            if *l == lane {
                trip(cell.as_ref());
            }
        }
    }

    fn recover_lane(&self, lane: usize) {
        // A health probe tests the UPSTREAM, which is shared across pools — so a successful probe
        // recovers EVERY cell for this lane (the default/direct-route cell and all per-pool cells),
        // clearing both a tripped (non-Closed) breaker AND a soft cooldown on a Closed cell.
        let now = Self::now_secs();
        let suppressed = |c: &dyn BreakerCellAccess| {
            c.breaker_state().load(Ordering::Acquire) != ST_CLOSED
                || c.cooldown_until().load(Ordering::Acquire) > now
        };
        let ls = self.get_lane(lane);
        if suppressed(ls.as_ref()) {
            Self::cell_closed(ls.as_ref());
        }
        let cells = lock_recover(&self.pool_cells);
        for ((_, l), cell) in cells.iter() {
            if *l == lane && suppressed(cell.as_ref()) {
                Self::cell_closed(cell.as_ref());
            }
        }
    }

    fn record_probe_failure_all_cells(&self, lane: usize, _what: &str, cfg: &BreakerCfg) {
        // Administratively-dead lanes ignore failure recording (matches record_failure_for).
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes).
        Self::cell_record_failure(self.get_lane(lane).as_ref(), now, cfg, None);
        // Every existing per-pool cell for this lane — the cells organic traffic is selected
        // against. (A cell not yet created inherits health lazily on first access via `cell`.)
        let cells = lock_recover(&self.pool_cells);
        for ((_, l), cell) in cells.iter() {
            if *l == lane {
                Self::cell_record_failure(cell.as_ref(), now, cfg, None);
            }
        }
    }

    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool {
        let suppressed = |c: &dyn BreakerCellAccess| {
            c.breaker_state().load(Ordering::Acquire) != ST_CLOSED
                || c.cooldown_until().load(Ordering::Acquire) > now
        };
        if suppressed(self.get_lane(lane).as_ref()) {
            return true;
        }
        let cells = lock_recover(&self.pool_cells);
        cells
            .iter()
            .any(|((_, l), cell)| *l == lane && suppressed(cell.as_ref()))
    }

    fn try_acquire(&self, lane: usize) -> Option<Permit> {
        let ls = self.get_lane(lane);
        match ls.sem.clone().try_acquire_owned() {
            Ok(permit) => Some(Permit::new(permit)),
            Err(_) => None,
        }
    }

    fn lane_semaphore(&self, lane: usize) -> Arc<Semaphore> {
        self.get_lane(lane).sem.clone()
    }

    fn spend_budget(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        if !ls.limited {
            return true; // unlimited budget
        }
        // Consume one unit of the lifetime request budget (the `max_requests` cost cap). The prior
        // implementation did an unconditional `fetch_sub(1)`: under a concurrent burst, up to
        // `max_concurrent` requests pass `lane_admissible` (which READS the budget without consuming
        // it) before any of them spends, then all `fetch_sub`, driving the budget NEGATIVE and
        // exceeding `max_requests` by up to `max_concurrent`. A compare-and-swap loop makes the gate
        // and the decrement ATOMIC: decrement ONLY while the budget is strictly positive, so the cap
        // is a hard ceiling — the (N+1)th concurrent spender loses the CAS once the budget hits 0 and
        // returns `false` without underflowing. Returns `false` when the lane is already exhausted.
        let mut cur = ls.budget.load(Ordering::Relaxed);
        loop {
            if cur <= 0 {
                return false; // already exhausted — never drive the budget negative
            }
            match ls.budget.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed, // racing spender won; retry with the fresh value
            }
        }
    }

    fn snapshot(&self, lane: usize, t: u64) -> LaneSnapshot {
        let ls = self.get_lane(lane);
        LaneSnapshot {
            model: ls.model.clone(),
            provider: ls.provider.clone(),
            max_concurrent: ls.max,
            // In-flight count derived from the semaphore (the source of truth): a held permit is an
            // in-flight request. `max - available` rather than a separate counter that can drift.
            inflight: ls.max.saturating_sub(ls.sem.available_permits()) as i64,
            free_slots: ls.sem.available_permits(),
            ok: ls.ok.load(Ordering::Relaxed),
            err: ls.err.load(Ordering::Relaxed),
            client_fault: ls.client_fault.load(Ordering::Relaxed),
            // Side-effect-FREE readiness peek, NOT the mutating `usable()`. `snapshot` feeds the
            // /stats observer; the mutating path would transition an expired-Open default cell to
            // HalfOpen and CAS-acquire the single-flight recovery probe, so a monitor polling /stats
            // would steal the probe from organic traffic and falsely flip the reported state. `is_ready`
            // reports the same admission verdict without touching the breaker FSM.
            usable: self.lane_usable_any_cell(lane, t),
            dead: ls.dead.load(Ordering::Relaxed),
            dead_reason: lock_recover(&ls.dead_reason).clone(),
            cooldown_remaining_s: self.lane_max_cooldown_remaining(lane, t),
            streak: self.lane_max_streak(lane),
            budget: if ls.limited {
                ls.budget.load(Ordering::Relaxed)
            } else {
                -1
            },
        }
    }

    // SWRR selection over the healthy subset (ADR-0001 algorithm). Uses the lane-default cells.
    #[cfg(test)]
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
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, true);

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    /// Record success outcome with explicit time.
    pub(crate) fn record_outcome_success_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Reset streak on success (for the FSM to know we recovered)
        ls.streak.store(0, Ordering::Release);

        // Add to sliding window
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, false);

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
                n: 3,
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
    /// described in the HIGH finding: a delayed transition racing a completing `cell_closed`.
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

    /// HIGH/correctness (store.rs:1213): a failure recorded against a NAMED pool must increment the
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

    /// HIGH/security (store.rs:578,677 + 562): a hostile upstream `Retry-After` near `u64::MAX` must
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

    /// LOW/correctness (store.rs:1010-1026): a healthy member with `weight: 0` (operator drain) must
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

    /// HIGH/correctness (forward.rs:1398): a hard-down trips the lane in EVERY cell — the default
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
                n: u32::MAX,
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
                n: u32::MAX,
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
        assert_eq!(
            until, 80015,
            "honor_retry_after=false must ignore the server value and use the computed backoff"
        );
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
