// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

// Lower bound a hard-down sticky cooldown is asserted to exceed, in tests.
#[cfg(test)]
const COOLDOWN_TRANSIENT_SECS: u64 = 10;
// A hard-down fault (bad key / billing / hard quota) gets a long sticky cooldown and recovers via
// the half-open probe — NOT a permanent `dead` kill. A human likely has to fix the key, so fast
// re-probes are pointless; default 30 min. Now operator-tunable via `limits.hard_down_cooldown_secs`
// (threaded onto `InMemoryStore`); this const is the DEFAULT (== the config default) and is retained
// only as the expected value in tests that exercise the default-configured store.
#[cfg(test)]
const HARD_DOWN_COOLDOWN_SECS: u64 = crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS;

// Absolute ceiling on an UPSTREAM-supplied `Retry-After` we will honor as a cooldown floor. A
// server's hint can legitimately exceed the configured `max_cooldown_secs`, so we honor past the
// cap — but never past this ceiling (default 24h), so a hostile/buggy upstream sending a near-
// `u64::MAX` `Retry-After` cannot overflow `now + duration` (breaker bypass in release / panic in
// debug) or bench a lane for millennia. Now operator-tunable via `limits.max_honored_retry_after_secs`
// (threaded onto `InMemoryStore`); this const is the DEFAULT, retained only for default-config tests.
#[cfg(test)]
const MAX_HONORED_RETRY_AFTER_SECS: u64 = crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS;

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
/// On the Tokio request path this is catastrophic and silent: one poisoned SWRR shard /
/// `outcome_window` / `dead_reason` mutex (or the `pool_cells` RwLock) would make EVERY subsequent
/// request that touches it panic
/// too — a poisoned-mutex DoS cascade. The data behind these mutexes is always still valid after a
/// poison (the critical sections only push to a bounded ring, mutate a small map, or swap a String),
/// so we recover the inner guard via `into_inner()` instead of propagating the poison. This keeps the
/// no-panic-on-request-path invariant: a single stray panic can never wedge the whole router.
fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Poison-recovering shared READ acquire for an `RwLock` on the request path — the `RwLock`
/// analogue of [`lock_recover`]. A reader panic cannot leave inconsistent data behind the
/// `pool_cells` lock (readers only iterate), so recover the guard instead of cascading the poison.
fn read_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}

/// Poison-recovering exclusive WRITE acquire for an `RwLock` — used only on the rare lazy
/// cell-insert path. Same no-panic-on-request-path rationale as [`lock_recover`].
fn write_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
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
fn set_now_for_test(t: u64) {
    TEST_NOW.with(|c| c.set(t));
    IN_TEST.with(|c| c.set(true));
}

#[cfg(test)]
fn now_for_test() -> u64 {
    // "Unset" is signalled SOLELY by the `IN_TEST` flag (set true by `set_now_for_test`), NOT by the
    // stored value. The old guard (`val != 0`) conflated a legitimately-injected instant of 0 with
    // "never set" and silently fell back to the wall clock — so `set_now_for_test(0)` (epoch / a
    // deliberately-pinned zero instant) was unmockable and any cooldown math anchored at 0 ran
    // against real time, a latent flake. With the flag as the sole gate, 0 is a legal mock instant.
    if IN_TEST.with(|c| c.get()) {
        TEST_NOW.with(|c| c.get())
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

/// RAII concurrency permit: an owned semaphore permit, held solely to keep the lane's concurrency
/// slot reserved for this request's lifetime. The slot is returned to the semaphore when the permit
/// is dropped. `OwnedSemaphorePermit` is already `Send + 'static` and itself `#[must_use]`, so it is
/// moved into the `FirstByteBody` stream directly with no wrapper.
pub(crate) type Permit = tokio::sync::OwnedSemaphorePermit;

/// Snapshot of lane stats for /stats endpoint.
#[derive(Debug, Clone)]
pub(crate) struct LaneSnapshot {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) max_concurrent: usize,
    pub(crate) inflight: i64,
    pub(crate) free_slots: usize,
    pub(crate) ok: u64,
    pub(crate) err: u64,
    pub(crate) client_fault: u64,
    pub(crate) usable: bool,
    pub(crate) dead: bool,
    pub(crate) dead_reason: String,
    pub(crate) cooldown_remaining_s: u64,
    pub(crate) streak: u32,
    pub(crate) budget: i64,
}

/// StateStore trait - the seam for lane state access.
/// Operations, NOT field access. `lane: usize` identifies a member.
/// One lane's PORTABLE health state, keyed by its STABLE IDENTITY (model + provider) instead of
/// its array position (D1). This is the carrier that lets learned reliability state survive the
/// two events that invalidate positional indexing: a config APPLY that changes the lane set (the
/// new store is built with the surviving lanes' snapshots restored), and — via serde, for the D3
/// persistence follow-up — a RESTART. Ephemeral state is deliberately NOT carried: semaphores /
/// in-flight counts (empty by definition in a fresh store), the single-flight probe flag (reset —
/// an in-flight probe records into the OLD store snapshot it was dispatched under), SWRR fairness
/// counters (positional by nature; reset is harmless), and the rolling outcome windows (strictly
/// time-windowed — they refill within seconds and carrying them would import stale samples).
// Bin-target consumer is the config-apply core (next slice); tests exercise it now.
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct LaneHealthSnapshot {
    pub(crate) model: String,
    pub(crate) provider: String,
    /// Remaining lifetime request budget (`-1` = unlimited).
    pub(crate) budget: i64,
    /// Default-cell breaker: FSM state, cooldown deadline (unix secs), consecutive-error streak.
    pub(crate) breaker_state: u64,
    pub(crate) cooldown_until: u64,
    pub(crate) streak: u32,
    /// Lane-global hard-down latch + reason.
    pub(crate) dead: bool,
    pub(crate) dead_reason: String,
    /// Lifetime counters (feed /stats continuity).
    pub(crate) ok: u64,
    pub(crate) err: u64,
    pub(crate) client_fault: u64,
    /// Latency EWMA (raw f64 bits; 0 = no sample).
    pub(crate) latency_ewma_bits: u64,
    /// Per-(pool) breaker cells for this lane.
    pub(crate) cells: Vec<PoolCellHealthSnapshot>,
}

/// One per-pool breaker cell's portable state (the FSM triple; windows/probe/SWRR stay ephemeral).
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PoolCellHealthSnapshot {
    pub(crate) pool: String,
    pub(crate) breaker_state: u64,
    pub(crate) cooldown_until: u64,
    pub(crate) streak: u32,
    pub(crate) err: u64,
}

pub(crate) trait StateStore: Send + Sync + 'static {
    // ── Health queries ─────────────────────────────────────────────────────────────────────────
    // The bare `lane` methods operate on the lane-default cell (direct/ad-hoc routes, `/stats`);
    // the `_in(pool, …)` variants operate on the per-(pool, lane) breaker cell so a lane shared
    // across pools carries independent Open/Closed status per pool. Lane-global checks (dead /
    // budget) are identical across both — only the breaker FSM is isolated.
    // `usable` (mutating, lane-default cell) is exercised by the unit tests; in release, dispatch
    // goes through `usable_in`/`acquire_for_dispatch_in` and non-dispatching observers use the
    // side-effect-free all-cells `is_ready_any_cell` (so /healthz and /stats can't steal a recovery
    // probe), leaving the bare form test-only — so it is `#[cfg(test)]`-gated out of the release
    // binary entirely rather than merely silenced.
    #[cfg(test)]
    fn usable(&self, lane: usize, now: u64) -> bool;
    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE readiness check: would this lane admit a request right now, WITHOUT
    /// transitioning an expired-Open lane to HalfOpen or CAS-acquiring its single-flight probe. The
    /// bare-lane (pool `""`) form covers ONLY the default cell — `/healthz` now uses the all-cells
    /// `is_ready_any_cell` instead (production routes through NAMED pools whose cells trip
    /// independently), leaving this default-cell-only form exercised by the unit tests, so it is
    /// `#[cfg(test)]`-gated out of the release binary entirely.
    #[cfg(test)]
    fn is_ready(&self, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE readiness across ANY cell: true iff the lane is admissible (not dead / in
    /// budget) AND the default cell OR ANY per-pool cell would admit a request right now. `/healthz`
    /// must use this, not the default-cell-only `is_ready`: production traffic routes through NAMED
    /// pools whose cells trip independently, so a lane whose every per-pool cell is Open is NOT
    /// serviceable even though its default `""` cell (which pool-routed traffic never touches) reads
    /// ready — and `/healthz` would otherwise return 200 while every pool lane is circuit-broken.
    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE, POOL-AWARE readiness: would this lane admit a request right now in THIS
    /// pool's breaker cell, WITHOUT the Open→HalfOpen transition or single-flight probe CAS that
    /// `usable_in` performs. This is the EXACT predicate `select_weighted_in` uses to filter its
    /// healthy candidate set (lane-admissible + `cell_ready_breaker`), exposed for the routing-policy
    /// ordered walk so it filters the policy's ranked order by health identically to SWRR — the walk
    /// only ORDERS; the unchanged `acquire_for_dispatch_in` (called once on the chosen lane) still
    /// owns the HalfOpen probe race. Using `usable_in` here instead would steal recovery probes for
    /// every ranked lane the walk merely peeks at.
    // ROUTING-POLICY SIGNAL ACCESSORS: read per-request by `forward::decide_policy_order` (and
    // `pick_among` for `ready_in`) to build the `Candidate` projection the resolved policy ranks on.
    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// Available (free) concurrency permits on a lane's semaphore right now — a routing-policy signal
    /// (`least_busy`). Read-only snapshot; racy by nature (permits change between read and dispatch),
    /// which is fine for a ranking hint.
    fn available_permits(&self, lane: usize) -> usize;
    /// Per-lane lifetime request budget remaining (`None` = unlimited / unmetered). A routing-policy
    /// signal (`usage`) read cheaply from the store. Read-only.
    fn lane_budget_remaining(&self, lane: usize) -> Option<i64>;
    /// Rolling EWMA of observed end-to-end latency for this lane, in milliseconds — a routing-policy
    /// signal (`fastest`). `None` until the lane has served at least one request. Read-only, lock-free.
    fn lane_latency_ms(&self, lane: usize) -> Option<f64>;
    /// Fold one observed end-to-end latency SAMPLE (milliseconds) into this lane's rolling EWMA. Called
    /// after a request completes (off the selection hot path). Lock-free, bounded, allocation-free; a
    /// non-finite or non-positive sample is ignored so a bad measurement can never poison the signal.
    /// `pool` is accepted for symmetry with the other `_in` recorders, but latency is lane-global, so
    /// the EWMA is shared across every pool fronting the lane.
    fn record_latency_in(&self, pool: &str, lane: usize, latency_ms: f64);
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
    // ALL dispatch (including the degraded `forward_once` fallback/least-bad path) now routes through
    // the `_in(pool, …)` variants against the ROUTING POOL cell — recording on the default `""` cell
    // left the pool cell wedged HalfOpen forever (H1) — so the bare forms are release-dead. NOTE:
    // `is_ready`, `breaker_state`, `usable`, `record_success`, `record_rate_limit`, `record_hard_down`
    // are all `#[cfg(test)]`-gated out of the release binary entirely rather than merely silenced with
    // a dead-code allow.
    #[cfg(test)]
    fn breaker_state(&self, lane: usize) -> BreakerState;
    /// Per-(pool, lane) breaker FSM state — test-only, so regressions can assert the POOL cell (not
    /// just the default `""` cell) transitions correctly on the degraded forward path (H1).
    #[cfg(test)]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState;
    /// Force a (pool, lane) breaker cell into Open with the given `cooldown_until` — test-only. Set
    /// `cooldown_until` in the PAST for an expired-Open cell, which `acquire_for_dispatch_in`
    /// transitions to HalfOpen (the single-flight recovery probe) on the next dispatch — the exact
    /// state the degraded-forward H1 regression requires on the ROUTING POOL cell.
    #[cfg(test)]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64);
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
    // `record_success` is now release-dead: the degraded `forward_once` path records against the
    // ROUTING POOL cell via `record_success_in` (H1), so this bare default-cell form is test-only and
    // `#[cfg(test)]`-gated out of the release binary.
    #[cfg(test)]
    fn record_success(&self, lane: usize);
    fn record_success_in(&self, pool: &str, lane: usize);
    /// A SUCCESSFUL (2xx) out-of-band health probe: push a success outcome into the sliding
    /// error-rate window of EVERY cell for the lane (the default/direct-route cell AND every existing
    /// per-pool cell), mirroring the all-cells iteration of `record_probe_failure_all_cells`. The
    /// failed-probe path feeds a failure into each cell's window, so without a matching success record
    /// a lane whose probes sometimes fail and sometimes succeed would present a window of ONLY
    /// failures and the error-rate breaker would read 100% error and trip a mostly-healthy lane (the
    /// LOW #23 success half of symmetric probe accounting).
    ///
    /// Crucially the lane-global `LaneState.ok` stat is bumped EXACTLY ONCE per probe — once per
    /// SUCCESSFUL PROBE, not once per cell. Recording per cell via `record_success_in` instead bumped
    /// `LaneState.ok` (N+1) times for a lane in N pools (the default cell plus one per pool), inflating
    /// the public `/stats` `ok` metric. This is the exact mirror of how `record_probe_failure_all_cells`
    /// bumps `LaneState.err` exactly once (only the default cell's `cell_record_failure` touches
    /// `LaneState.err`; the per-pool cells bump their own separate `BreakerCell.err`). Here the
    /// per-cell `cell_record_success` touches no `ok`/`err` counter at all, so the single lane-global
    /// `ok` bump is applied explicitly, once.
    ///
    /// If a per-cell success push wins a HalfOpen→Closed CAS (possible when this push races a peer that
    /// re-armed the cell after the caller's `recover_lane`), the implementation MUST reset that cell's
    /// SWRR accumulator — `cell_record_success` zeroes `current_weight` under the transition lock and the
    /// matching `reset_swrr_for` re-seeds it under the pool shard lock, holding `Σ current_weight == 0`.
    /// Gating the reset on the recovered-bool mirrors `record_success_for`/`recover_lane` (LOW #19).
    fn record_probe_success_all_cells(&self, lane: usize);
    fn record_client_fault(&self, lane: usize);
    /// Record a transient upstream failure. `cfg` is the routing pool's resolved breaker config,
    /// which drives the trip decision (error-rate vs consecutive thresholds) and cooldown backoff.
    /// Returns `true` iff this failure drove a Closed→Open trip on the (pool, lane) cell, so the
    /// caller emits `BREAKER_TRIPS_TOTAL` once per logical trip (#29).
    #[cfg(test)]
    fn record_transient(
        &self,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    #[cfg(test)]
    fn record_rate_limit(
        &self,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
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
    /// Trips every cell for `lane` hard-down. Returns `true` iff this was a genuine fresh trip of the
    /// default cell (it was `ST_CLOSED` before) — so callers can gate `BREAKER_TRIPS_TOTAL` on a
    /// LOGICAL Closed→Open trip and not re-count a persistently-dead lane on every recovery-probe.
    fn record_hard_down_all_cells(&self, lane: usize, reason: &str) -> bool;
    /// A successful out-of-band health probe: recover the lane to Closed in EVERY cell (default and
    /// all pools), since the probe tests the shared upstream. No-op on cells already Closed.
    fn recover_lane(&self, lane: usize);
    /// A FAILED out-of-band health probe: record a transient failure against EVERY cell for the
    /// lane (the default cell AND every existing per-pool cell), mirroring `recover_lane`'s
    /// all-cells iteration. The probe tests the shared upstream, and organic traffic routes against
    /// per-pool cells, so a probe failure that only hit the default cell could never trip the
    /// per-pool breakers real traffic is selected against.
    ///
    /// `resolve_cfg` resolves the breaker config to apply to a given cell BY POOL NAME: it is called
    /// with `""` for the default cell and with each per-pool cell's pool name, so a probe failure
    /// trips/cools each cell against THAT pool's own configured thresholds and backoff (#24/#25) —
    /// not a one-size `BreakerCfg::default()` that ignored per-pool trip thresholds and cooldowns.
    /// The resolver falls back to the ADR-0002 default for any pool without its own config.
    /// `retry_after` (server-requested cooldown floor, e.g. a 429 `Retry-After`) is honored when the
    /// resolved cfg's `honor_retry_after` is set, exactly as on the organic failure path.
    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
    );

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

    /// Return one previously-spent unit to the lane's lifetime request budget. Used to COMPENSATE a
    /// `spend_budget` that was charged optimistically on the 2xx response HEADERS when the response
    /// body then failed to transfer intact — no usable response was delivered, so the spend must be
    /// reversed or every post-headers transport failure permanently drains the lane's `max_requests`
    /// budget and stealthily removes capacity. A no-op for an unlimited lane. Never raises the budget
    /// above the configured `max_requests` ceiling (a refund is only ever the inverse of a spend).
    fn refund_budget(&self, lane: usize);

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

    /// Export every lane's PORTABLE health state, keyed by stable identity (D1) — the input to a
    /// state-carrying store rebuild (config apply) and to the persistence snapshotter (D3).
    #[allow(dead_code)] // bin-target consumer is the config-apply core (next slice)
    fn export_health(&self) -> Vec<LaneHealthSnapshot>;
}

/// Bounded sliding window of recent request outcomes, each tagged success/error, used to compute
/// the error-rate trip signal. Backed by a `VecDeque` so dropping the oldest entry at capacity is
/// O(1). Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
struct OutcomeWindow {
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
struct BreakerCell {
    breaker_state: AtomicU64, // 0=Closed, 1=Open, 2=HalfOpen
    streak: AtomicU32,
    cooldown_until: AtomicU64,
    probe_in_flight: AtomicBool,
    err: AtomicU64,
    outcome_window: std::sync::Mutex<OutcomeWindow>,
    current_weight: AtomicI64, // SWRR state (per pool — selection runs over a pool's set)
    // Serializes every state+cooldown TRANSITION on this cell. `breaker_state` and `cooldown_until`
    // are two separate atomics, so a transition that touches BOTH (open: Open+long cooldown; closed:
    // Closed+clear cooldown; the Open→HalfOpen probe acquire) is not atomic across the pair on its
    // own. Two such transitions racing (e.g. a half-open probe SUCCESS recovering the cell to Closed
    // while a concurrent hard-down trips it Open with a 30-min sticky cooldown) could interleave their
    // individual stores into an INCONSISTENT pair — a hard-down lane left Open with a cleared/short
    // cooldown (sticky cooldown silently dropped → the dead lane keeps receiving traffic), or Closed
    // with a stale cooldown. Holding this lock across each transition's read-modify-write makes the
    // (state, cooldown) pair move as a unit with a single linearization point, so racing transitions
    // serialize and the last writer's consistent pair always wins. The hot read path
    // (`cell_ready_breaker`/`cell_acquire_breaker` selection) does NOT take this lock — it stays
    // lock-free; only the (comparatively rare) transitions serialize against each other.
    transition_lock: std::sync::Mutex<()>,
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
            transition_lock: std::sync::Mutex::new(()),
        }
    }
}

/// Read access to the breaker atomics, so the FSM logic can be written once and run against either
/// a `LaneState` (the default cell) or a per-pool `BreakerCell` without duplication.
trait BreakerCellAccess {
    fn breaker_state(&self) -> &AtomicU64;
    fn streak(&self) -> &AtomicU32;
    fn cooldown_until(&self) -> &AtomicU64;
    fn probe_in_flight(&self) -> &AtomicBool;
    fn err(&self) -> &AtomicU64;
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow>;
    fn current_weight(&self) -> &AtomicI64;
    /// Serializes state+cooldown transitions on this cell (see `BreakerCell::transition_lock`).
    fn transition_lock(&self) -> &std::sync::Mutex<()>;
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
    fn transition_lock(&self) -> &std::sync::Mutex<()> {
        &self.transition_lock
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
    fn transition_lock(&self) -> &std::sync::Mutex<()> {
        &self.transition_lock
    }
}

/// Per-lane breaker cells, keyed by lane index for an O(1) lane lookup. Each lane maps to its small
/// set of per-pool cells (`(pool name, cell)`), so a (pool, lane) point lookup is an O(1) hash probe
/// plus a scan bounded by the number of POOLS ON THAT LANE (typically tiny) — never the full
/// cross-product of pools×lanes — and the per-lane aggregation/recovery sweeps touch only the
/// relevant lane's cells instead of scanning every cell in the deployment. No per-call key allocation
/// on the hot path (the lane index is `Copy`; the pool name is compared by `&str`).
type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<BreakerCell>)>>;

/// FNV-1a over a pool name → SWRR shard index. Pure (no `self`) so it can be unit-tested and reused
/// by the per-pool shard memo without duplicating the constants. Distribution, not cryptographic
/// strength, is all that matters: it only picks which lock shard a pool's selections serialize on.
/// `SWRR_SHARDS` is a power of two, so the reduction is a cheap mask.
fn swrr_shard_index(pool: &str) -> usize {
    (fnv1a_u64(pool) as usize) & (SWRR_SHARDS - 1)
}

/// FNV-1a 64-bit offset-basis and prime (the canonical constants). Module-level so both the string
/// hash (`fnv1a_u64`) and the cooldown-jitter seed mixer (which folds 128-bit inputs with the same
/// FNV step) share one named definition instead of repeating the bare magic literals.
const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Deterministic FNV-1a 64-bit hash of a string's bytes. Stable across processes/restarts (unlike
/// the std `DefaultHasher`, whose seed is randomized), so callers that need a process-independent
/// hash (SWRR shard selection, session affinity) get identical results everywhere. Distribution,
/// not cryptographic strength, is all that matters.
pub(crate) fn fnv1a_u64(s: &str) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

/// Number of SWRR lock shards. The SWRR weight read-modify-write only needs to be serialized
/// PER POOL (the `Σ current_weight == 0` invariant is pool-local — two disjoint pools share no
/// `current_weight` cells), so a single global lock needlessly serialized every pool's selection.
/// A fixed shard array keyed by the pool-name hash lets disjoint pools select in parallel; only
/// pools that hash to the same shard contend (rare with this many shards), and the shard array
/// itself needs no allocation or new dependency. A power of two so the modulo is a cheap mask.
const SWRR_SHARDS: usize = 64;

/// Wraps the per-lane atomics/semaphores with per-(pool, lane) FSM breaker logic, populated lazily.
pub(crate) struct InMemoryStore {
    lanes: Vec<Arc<LaneState>>,
    /// Per-(pool, lane) breaker cells, created lazily on first access. The lane-global fields
    /// (sem/budget/dead/ok) always live on `lanes[lane]`; only the breaker FSM is isolated per pool.
    ///
    /// An `RwLock` (not a plain `Mutex`): the overwhelmingly common access is a READ of an
    /// already-created cell on the hot dispatch path (`cell()` / the `/stats` aggregators), and many
    /// such reads can proceed concurrently under a shared lock. Only the rare lazy first-touch insert
    /// of a new (pool, lane) cell takes the exclusive write lock. The previous `Mutex` forced an
    /// exclusive acquisition for every read, serializing the selection path.
    pool_cells: std::sync::RwLock<PoolCellMap>,
    /// Sharded SWRR locks (see `SWRR_SHARDS`). A selection serializes only against other selections
    /// whose pool hashes to the same shard, so concurrent selections for disjoint pools run in
    /// parallel. Boxed slice so the struct stays movable without a const-generic array literal.
    swrr_shards: Box<[std::sync::Mutex<()>]>,
    /// Operator-configured hard-down sticky cooldown (seconds). Replaces the historical
    /// `HARD_DOWN_COOLDOWN_SECS` const at every hard-down trip; defaults to 1800 when the operator
    /// omits `limits.hard_down_cooldown_secs`.
    hard_down_cooldown_secs: u64,
    /// Operator-configured ceiling (seconds) on a honored upstream `Retry-After`. Replaces the
    /// historical `MAX_HONORED_RETRY_AFTER_SECS` const in `compute_cooldown_with_retry_after`;
    /// defaults to 86_400 (24h). Bounds a hostile/buggy `Retry-After` so it cannot park a lane for
    /// millennia or overflow the cooldown arithmetic.
    max_honored_retry_after_secs: u64,
    /// Memoized pool-name → shard-index map. `swrr_shard` ran FNV-1a over the pool NAME on EVERY
    /// selection (the hot dispatch path); the index is a pure function of the (small, stable) set of
    /// pool names, so cache it on first touch and reuse thereafter. An append-only `Vec` scanned by
    /// byte-compare (the same idiom as `cell()`) — NOT a `HashMap`, whose SipHash lookup would cost
    /// more than the FNV it replaces. The cached value is identical to recomputing `swrr_shard_index`,
    /// so selection semantics are unchanged. `RwLock`: the common case is a shared-read hit; only a
    /// genuine first-touch miss takes the exclusive write lock to insert.
    pool_shards: std::sync::RwLock<Vec<(Box<str>, usize)>>,
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
    // Serializes state+cooldown transitions on the default cell — see `BreakerCell::transition_lock`.
    transition_lock: std::sync::Mutex<()>,
    // Rolling EWMA of observed end-to-end request latency for this lane, in MILLISECONDS, stored as
    // the raw bits of an `f64` (`f64::to_bits`) so it can be read/updated lock-free with a single
    // atomic — mirroring the lock-free atomic style the rest of this struct uses for cheap per-lane
    // signals. A sentinel of `0` bits (== `+0.0`) means "no sample yet" (a real end-to-end latency is
    // always strictly positive), which the routing-policy projection maps to `latency_ms: None`. This
    // is a lane-GLOBAL signal (latency is a property of the shared upstream, not of any one pool's
    // breaker cell), so it lives on `LaneState`, not on `BreakerCell`. Read by the `fastest` policy
    // via `lane_latency_ms`; updated after each request completes via `record_latency_in`.
    latency_ewma_bits: AtomicU64,
}

/// Smoothing factor (α) for the per-lane latency EWMA: `ewma = α·sample + (1-α)·ewma`. A smaller α
/// gives a longer memory (steadier signal, slower to react); 0.2 weights the most recent ~5 requests
/// most heavily, which is responsive enough to notice a degrading upstream without thrashing the
/// `fastest` ranking on a single slow outlier. Cheap, bounded, allocation-free.
const LATENCY_EWMA_ALPHA: f64 = 0.2;

impl InMemoryStore {
    /// Read a (pool, lane) cell's cumulative error counter — for concurrency/isolation tests.
    #[cfg(test)]
    fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).err().load(Ordering::Relaxed)
    }

    /// Construct with the historical hardcoded operational limits. Used by tests and any caller that
    /// does not thread operator config; production goes through [`new_with_limits`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(lanes: Vec<LaneData>) -> Self {
        Self::new_with_limits(
            lanes,
            crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
            crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        )
    }

    /// Construct with operator-configured hard-down cooldown + honored-`Retry-After` ceiling
    /// (`limits.hard_down_cooldown_secs` / `limits.max_honored_retry_after_secs`). Each defaults to
    /// its historical const at the config layer, so `new` and this share one source of truth.
    pub(crate) fn new_with_limits(
        lanes: Vec<LaneData>,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
    ) -> Self {
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
                    transition_lock: std::sync::Mutex::new(()),
                    // `0` bits == "no latency sample yet" (see `latency_ewma_bits`).
                    latency_ewma_bits: AtomicU64::new(0),
                })
            })
            .collect();
        Self {
            lanes: lane_states,
            pool_cells: std::sync::RwLock::new(std::collections::HashMap::new()),
            hard_down_cooldown_secs,
            max_honored_retry_after_secs,
            swrr_shards: (0..SWRR_SHARDS)
                .map(|_| std::sync::Mutex::new(()))
                .collect(),
            pool_shards: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Construct with PRIOR HEALTH STATE restored by stable lane identity (D1): each lane whose
    /// (model, provider) appears in `restored` starts with that snapshot's breaker/cooldown/streak/
    /// hard-down/latency/counters instead of fresh state — the carry-over that makes a lane-set
    /// config APPLY (and, via the persistence layer, a restart) preserve learned reliability.
    /// Matching is by IDENTITY, never position, so added/removed/reordered lanes are immune to the
    /// index-shift misattribution this design exists to prevent. Unmatched snapshots are dropped
    /// (their lane no longer exists); unmatched lanes start fresh (they are new). `LaneData`
    /// baseline fields (budget/cooldown/streak/dead/counters) are OVERRIDDEN by a matching
    /// snapshot — the snapshot IS the live truth the previous store held; per-pool cells are
    /// re-created eagerly so a restored Open cell blocks dispatch from the first request.
    // Bin-target consumer is the config-apply core (next slice); the carry-over tests use it now.
    #[allow(dead_code)]
    pub(crate) fn new_with_limits_restored(
        lanes: Vec<LaneData>,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
        restored: &[LaneHealthSnapshot],
    ) -> Self {
        let store =
            Self::new_with_limits(lanes, hard_down_cooldown_secs, max_honored_retry_after_secs);
        for (idx, lane) in store.lanes.iter().enumerate() {
            let Some(snap) = restored
                .iter()
                .find(|s| s.model == lane.model && s.provider == lane.provider)
            else {
                continue;
            };
            lane.budget.store(snap.budget, Ordering::Relaxed);
            lane.breaker_state
                .store(snap.breaker_state, Ordering::Relaxed);
            lane.cooldown_until
                .store(snap.cooldown_until, Ordering::Relaxed);
            lane.streak.store(snap.streak, Ordering::Relaxed);
            lane.dead.store(snap.dead, Ordering::Relaxed);
            *lane.dead_reason.lock().unwrap_or_else(|e| e.into_inner()) = snap.dead_reason.clone();
            lane.ok.store(snap.ok, Ordering::Relaxed);
            lane.err.store(snap.err, Ordering::Relaxed);
            lane.client_fault
                .store(snap.client_fault, Ordering::Relaxed);
            lane.latency_ewma_bits
                .store(snap.latency_ewma_bits, Ordering::Relaxed);
            // Recreate the per-pool breaker cells eagerly with their restored FSM state.
            let mut map = store.pool_cells.write().unwrap_or_else(|e| e.into_inner());
            let cells = map.entry(idx).or_default();
            for cs in &snap.cells {
                let cell = Arc::new(BreakerCell::new());
                cell.breaker_state
                    .store(cs.breaker_state, Ordering::Relaxed);
                cell.cooldown_until
                    .store(cs.cooldown_until, Ordering::Relaxed);
                cell.streak.store(cs.streak, Ordering::Relaxed);
                cell.err.store(cs.err, Ordering::Relaxed);
                cells.push((cs.pool.clone().into_boxed_str(), cell));
            }
        }
        store
    }

    fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }

    /// Select the SWRR shard lock for a pool. The shard is keyed by the pool-name hash so all
    /// selections for a given pool serialize against each other (preserving the pool-local
    /// `Σ current_weight == 0` invariant), while selections for pools hashing to other shards run in
    /// parallel. `SWRR_SHARDS` is a power of two, so the index is a cheap mask.
    fn swrr_shard(&self, pool: &str) -> &std::sync::Mutex<()> {
        // Fast path: the pool's shard index was computed once on its first selection and memoized,
        // so subsequent selections reuse it WITHOUT re-running FNV-1a over the name on every call.
        // Shared read lock — concurrent selections for already-seen pools don't block each other.
        {
            let cache = read_recover(&self.pool_shards);
            if let Some((_, idx)) = cache.iter().find(|(p, _)| p.as_ref() == pool) {
                return &self.swrr_shards[*idx];
            }
        }
        // First-touch miss: compute and insert under the exclusive write lock. Re-check first — a
        // racing selection for the same pool may have inserted between the read miss and this acquire.
        let idx = swrr_shard_index(pool);
        let mut cache = write_recover(&self.pool_shards);
        if !cache.iter().any(|(p, _)| p.as_ref() == pool) {
            cache.push((Box::from(pool), idx));
        }
        // The cached value equals `idx` regardless of which writer won, so index by the just-computed
        // value (identical shard selection to the old direct-FNV path).
        &self.swrr_shards[idx]
    }

    /// Resolve the breaker cell for a (pool, lane). An empty pool name selects the lane-global
    /// default cell (the `LaneState` itself) — used by direct/ad-hoc routes. A named pool gets a
    /// dedicated `BreakerCell`, created Closed on first access.
    fn cell(&self, pool: &str, lane: usize) -> Arc<dyn BreakerCellAccess> {
        if pool.is_empty() {
            return self.lanes[lane].clone();
        }
        // Fast path: the cell almost always already exists (it is created once, on the pool's first
        // request, then read on every subsequent dispatch). Take a SHARED read lock and look it up
        // WITHOUT allocating a `Box<str>` key — concurrent readers don't block each other, and the
        // hot path does zero heap allocation. Only a genuine first-touch miss falls through to the
        // exclusive write lock below.
        {
            let cells = read_recover(&self.pool_cells);
            // O(1) lane lookup, then a scan bounded by #pools-on-this-lane (typically tiny) with no
            // owned-key allocation — never the full pools×lanes cross-product.
            if let Some(per_lane) = cells.get(&lane) {
                if let Some((_, c)) = per_lane.iter().find(|(p, _)| p.as_ref() == pool) {
                    return c.clone();
                }
            }
        }
        let mut cells = write_recover(&self.pool_cells);
        let per_lane = cells.entry(lane).or_default();
        // Re-check under the write lock: a racing writer may have inserted this (pool, lane) between
        // the read-lock miss above and acquiring the write lock.
        if let Some((_, c)) = per_lane.iter().find(|(p, _)| p.as_ref() == pool) {
            return c.clone();
        }
        // A new pool cell inherits the lane's current known health (breaker state + pending cooldown
        // + streak) rather than blindly assuming Closed — so a pool whose first request arrives while
        // the lane is mid-cooldown respects it. In production cells are created while the lane is
        // healthy, so this is normally a no-op.
        let ls = &self.lanes[lane];
        let c = BreakerCell::new();
        // Normalize an inherited HalfOpen to Open. HalfOpen encodes "some cell owns the single-flight
        // probe right now" — but `probe_in_flight` lives on the cell that won it, NOT on this freshly-
        // created sibling (born with `probe_in_flight == false`). A sibling cell born ST_HALF_OPEN is
        // wedged: both `cell_ready_breaker` and `cell_acquire_breaker` return false unconditionally
        // for HalfOpen, and no probe outcome (cell_open/cell_closed) ever runs against it, so it never
        // self-recovers — organic traffic to this (pool, lane) is benched until an out-of-band
        // recover_lane happens to touch it (indefinitely when health probing is disabled). Storing
        // Open instead lets the inherited (already-expired) cooldown drive a fresh probe acquisition
        // on this cell's first request. The Open+cooldown inheritance below is still honored verbatim
        // so a sibling created mid-cooldown respects it.
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
        let c = Arc::new(c);
        per_lane.push((Box::from(pool), c.clone()));
        c
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
            TripMode::Consecutive => c.streak().load(Ordering::Relaxed) >= cfg.trip.consecutive_n,
        }
    }

    /// Compute escalating cooldown duration with optional Retry-After floor.
    /// If retry_after is Some and honor_retry_after is true, the cooldown is max(computed_backoff, retry_after).
    /// The server's explicit Retry-After is always respected even if it exceeds max_cooldown_secs.
    // NOTE: the honored-`Retry-After` CEILING is threaded in as a parameter (rather than read from
    // `&self`) because this and the `cell_*` helpers below are STATIC (`c: &dyn BreakerCellAccess`,
    // not `&self`) so they can run under the per-cell transition lock without re-borrowing the store.
    // Every caller is an `&self` method that passes `self.max_honored_retry_after_secs`.
    fn compute_cooldown_with_retry_after(
        c: &dyn BreakerCellAccess,
        _now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
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

        // Add bounded jitter ±10% on EVERY trip, including the `streak == 0` base path. Gating jitter
        // on `streak > 0` left the first-trip / sub-threshold cooldown (the `streak == 0` base,
        // reachable from the sub-threshold cooldown arm and direct `cell_open` callers) un-jittered, so
        // a fleet of lanes tripping together on the same base got the IDENTICAL cooldown → synchronized
        // half-open probes (thundering herd). Hoisting the computation here desyncs the base too; for
        // `streak == 0`, `duration == base_cooldown_secs` and the same `jitter_range = (duration/10)
        // .max(1)` and `[duration/2, max]` clamp apply.
        {
            // Floor the band at >=1s. On tight cooldowns (`duration < 10`) the ±10% range
            // `duration / 10` truncates to 0 → `span == 1` → jitter always 0 → EVERY lane that trips
            // on a small `base_cooldown_secs` gets the identical cooldown, defeating the
            // anti-thundering-herd desync exactly when the herd is densest (many lanes, short retry
            // loop). A 1s band restores a real spread for small bases; for `duration >= 10` this is a
            // no-op (`duration / 10 >= 1`), so larger cooldowns keep the documented ±10%.
            let jitter_range = (duration / 10).max(1);
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
            let mut seed = FNV1A_OFFSET_BASIS as u128;
            for part in [time_seed, cell_id, streak as u128] {
                seed = (seed ^ part).wrapping_mul(FNV1A_PRIME as u128);
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
            (true, Some(ra)) => duration.max(ra.min(max_honored_retry_after_secs)),
            (false, Some(_)) => duration,
            (true, None) | (false, None) => duration,
        }
    }

    /// Transition the cell to Open with an escalated cooldown (streak is owned by the record path,
    /// only read here). Acquires the per-cell transition lock so the Open state + cooldown move as a
    /// consistent pair against any racing transition; see `cell_open_locked`. Release code reaches
    /// the trip via `cell_open_locked` (already holding the lock), so only the test helpers call this
    /// lock-acquiring wrapper — hence release-dead.
    #[cfg_attr(not(test), allow(dead_code))]
    fn cell_open(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let _tx = lock_recover(c.transition_lock());
        Self::cell_open_locked(c, now_time, cfg, retry_after, max_honored_retry_after_secs);
    }

    /// `cell_open` body, assuming the caller already holds `c.transition_lock()`. Used by the record
    /// paths that take the lock once and may then call `cell_open` under it (re-taking the std Mutex
    /// would deadlock), so they call this instead.
    fn cell_open_locked(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let duration = Self::compute_cooldown_with_retry_after(
            c,
            now_time,
            cfg,
            retry_after,
            max_honored_retry_after_secs,
        );
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

    /// Transition the cell to Closed (full recovery): reset streak/window, clear the cooldown
    /// and release the single-flight probe. Acquires the per-cell transition lock so the Closed state
    /// and cleared cooldown move as a consistent pair against any racing transition (see
    /// `cell_closed_locked`).
    ///
    /// NOTE: this does NOT reset the cell's SWRR `current_weight`. That reset must run under the
    /// per-pool SWRR shard lock (which serializes selection and owns the `Σ current_weight == 0`
    /// invariant), and only the CALLER knows the pool the cell belongs to. Callers perform the reset
    /// via `reset_swrr_for(pool, cell)` AFTER this returns (the transition lock is released by then,
    /// so the shard lock is taken un-nested — no lock-order inversion against selection, which takes
    /// the shard lock with no transition lock held).
    ///
    /// Test-only: the production recovery path (`recover_lane`) now closes cells through
    /// `cell_closed_if_recoverable` (which re-validates suppression under the lock — LOW #16); the only
    /// remaining caller of this unconditional close is the `closed_state` test handle.
    #[cfg(test)]
    fn cell_closed(c: &dyn BreakerCellAccess) {
        let _tx = lock_recover(c.transition_lock());
        Self::cell_closed_locked(c);
    }

    /// Recovery close for `recover_lane`: close a cell whose suppression the probe is entitled to
    /// clear, re-validating UNDER the transition lock that no concurrent transition has re-armed the
    /// cell since the probe snapshotted it. Returns true iff the cell was actually closed.
    ///
    /// `observed_cooldown` is the `cooldown_until` value the lock-free pre-filter read for this cell.
    /// A successful 2xx probe is authoritative for the upstream state it OBSERVED, so it may clear the
    /// trip/cooldown it saw — but it must NOT clobber a STRICTER suppression a peer armed in the
    /// meantime. The race the finding (#16) calls out: between the pre-filter read and the close, a
    /// concurrent `record_hard_down_all_cells` / `cell_record_failure` parks the cell Open with a
    /// FRESH sticky cooldown (`now_hd + HARD_DOWN_COOLDOWN_SECS`, strictly later than anything the
    /// probe saw). An unconditional close would drop that just-armed cooldown and recover a lane the
    /// hard-down meant to keep suppressed.
    ///
    /// Discipline (mirrors `cell_record_success`'s CAS-under-lock): take the transition lock once —
    /// the SAME lock every trip/close uses, so this serializes against them — then re-read the
    /// cooldown. If it now extends BEYOND what the probe observed (`> observed_cooldown`), a peer
    /// re-armed a stricter suppression after the snapshot; leave the cell untouched. Otherwise (cell
    /// still non-Closed, OR a cooldown no later than observed) the probe's clearance still applies and
    /// we close. A future cooldown the probe ITSELF saw (`<= observed_cooldown`) is still cleared —
    /// that is the legitimate recovery of a tripped lane.
    fn cell_closed_if_recoverable(
        c: &dyn BreakerCellAccess,
        now: u64,
        observed_cooldown: u64,
    ) -> bool {
        let _tx = lock_recover(c.transition_lock());
        // A peer armed a stricter cooldown than the probe observed → its suppression is newer than the
        // probe's clearance; do not clobber it.
        if c.cooldown_until().load(Ordering::Acquire) > observed_cooldown {
            return false;
        }
        // Still suppressed (tripped breaker OR a cooldown still in the FUTURE relative to the caller's
        // `now` snapshot) → the probe clears it. An already-expired (past) nonzero `cooldown_until` on
        // a Closed cell is NOT a suppression — recovery already lapsed — so `> now`, not `> 0`, avoids
        // a spurious close + SWRR reset on an already-recovered lane.
        let suppressed = c.breaker_state().load(Ordering::Acquire) != ST_CLOSED
            || c.cooldown_until().load(Ordering::Acquire) > now;
        if suppressed {
            Self::cell_closed_locked(c);
        }
        suppressed
    }

    /// `cell_closed` body, assuming the caller already holds `c.transition_lock()`. Does NOT touch
    /// `current_weight` — see `cell_closed` and `reset_swrr_for` for why the SWRR reset is the
    /// caller's job (it must hold the per-pool shard lock).
    fn cell_closed_locked(c: &dyn BreakerCellAccess) {
        c.streak().store(0, Ordering::Release);
        // Do NOT zero `c.err()` here. For the default cell `c.err()` IS the PUBLIC `/stats`
        // lifetime `LaneState.err` counter, which must stay monotonic (like `LaneState.ok`).
        // The breaker FSM never reads `err()` — `should_trip` keys off `outcome_window` + `streak`
        // — so this zeroing was dead for recovery health yet corrupted the stats counter, making
        // `LaneState.err` non-monotonic on every default-cell recovery (LOW #12). Recovery health
        // is fully reset by the `streak`/`outcome_window`/`cooldown`/`state` stores below.
        lock_recover(c.outcome_window()).clear();
        c.cooldown_until().store(0, Ordering::Release);
        c.breaker_state().store(ST_CLOSED, Ordering::Release);
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// Reset a recovered cell's SWRR accumulator to 0, UNDER the pool's SWRR shard lock.
    ///
    /// While the member was tripped it was dropped from the healthy set in `select_weighted_for` and
    /// stopped receiving fetch_add/fetch_sub, freezing its `current_weight` at a stale value. On
    /// recovery it rejoins selection; carrying that stale value biases the first few selections and
    /// violates the `Σ current_weight == 0` invariant over the (now-changed) healthy set.
    ///
    /// This MUST hold `swrr_shard(pool)` while zeroing: selection (`select_weighted_for`) does the
    /// add/find-max/subtract that maintains the invariant under that same shard lock, so a bare
    /// `store(0)` from a concurrent recovery — not serialized against selection — could land between
    /// selection's `fetch_add` and its compensating `fetch_sub(total)`, breaking `Σ == 0`. Taking the
    /// shard lock here serializes the reset against any in-flight selection for the pool. The lock is
    /// taken WITHOUT any transition lock held (callers invoke this after the cell-close transition has
    /// returned), matching selection's lock discipline and avoiding lock-order inversion.
    fn reset_swrr_for(&self, pool: &str, c: &dyn BreakerCellAccess) {
        let _swrr = lock_recover(self.swrr_shard(pool));
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
        // Serialize against other transitions: this leaves the existing (expired) cooldown intact and
        // only reverts the state HalfOpen → Open, but it must not interleave with a concurrent
        // open/close/trip that is mid-way through its own (state, cooldown) pair.
        let _tx = lock_recover(c.transition_lock());
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
        // Fast lock-free pre-check: only an Open cell whose cooldown has expired needs the mutating
        // Open→HalfOpen probe-acquisition (which must serialize against trips/closes). Closed and
        // HalfOpen, and a not-yet-expired Open, are decided by a plain consistent read with no lock —
        // keeping the common dispatch case lock-free. We re-confirm the state under the lock below.
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => now >= c.cooldown_until().load(Ordering::Acquire),
            ST_OPEN => {
                let until = c.cooldown_until().load(Ordering::Acquire);
                if now >= until {
                    // The Open→HalfOpen probe acquisition reads BOTH state and cooldown and must move
                    // as an atomic pair against a concurrent trip/close (which writes both). Take the
                    // transition lock so a hard-down parking the cell Open with a fresh sticky
                    // cooldown can't interleave with this acquisition and let a probe slip through on
                    // a just-parked lane. Re-read under the lock: a peer transition may have changed
                    // the state or re-armed the cooldown since the lock-free check above.
                    let _tx = lock_recover(c.transition_lock());
                    if c.breaker_state().load(Ordering::Acquire) != ST_OPEN
                        || now < c.cooldown_until().load(Ordering::Acquire)
                    {
                        return false;
                    }
                    // Single CAS Open→HalfOpen under the lock: the state and probe acquisition move as
                    // an atomic pair. A non-CAS `store(ST_HALF_OPEN)` followed by a separate
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
    ///
    /// RETURNS `true` IFF this failure drove a logical Closed→Open trip (a threshold breach that
    /// transitioned the cell from Closed to Open). A HalfOpen→Open reopen (a failed recovery probe)
    /// is NOT counted as a fresh trip — the lane was already tripped and is merely re-arming its
    /// cooldown — nor is an already-Open no-op. The caller emits `BREAKER_TRIPS_TOTAL` once per
    /// `true`, so the counter reflects logical trips, not per-cell or per-cooldown-bump events.
    fn cell_record_failure(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) -> bool {
        lock_recover(c.outcome_window()).push(now_time, true); // error outcome
        c.err().fetch_add(1, Ordering::Relaxed);

        // The state-dependent transition reads BOTH state and cooldown and writes the (state,
        // cooldown) pair, so serialize it under the transition lock (re-reading the state under the
        // lock) — a concurrent close/trip must not interleave its pair with this one. The order-
        // insensitive `err()` bump and outcome_window push above are independent of the streak and
        // need no lock. `should_trip` (which also locks the outcome_window) and the inner
        // `cell_open_locked` run UNDER this lock; we call the `_locked` open variant so we never
        // re-take this std Mutex (which would deadlock).
        let _tx = lock_recover(c.transition_lock());
        // Bump the consecutive-failure streak UNDER the transition lock (was previously an
        // unconditional fetch_add outside it). `should_trip` (Consecutive mode) and
        // `compute_cooldown_with_retry_after` both read the streak under THIS lock; bumping it
        // outside let concurrent failures over-count the streak before the trip/cooldown read,
        // inflating the first-trip escalation/cooldown level. Serializing the bump with the
        // should_trip/compute_cooldown read makes the escalation level reflect the serialized
        // consecutive-failure count.
        //
        // The bump is NOT unconditional: it runs ONLY in the ST_CLOSED and ST_HALF_OPEN arms — the two
        // that READ/ACT on the streak (Closed's `should_trip`/`compute_cooldown`, HalfOpen's reopen
        // escalation). The ST_OPEN arm is a true no-op on the streak: an out-of-band probe failure
        // against an already-Open cell must NOT advance the consecutive count, or a later HalfOpen
        // re-trip computes an over-long cooldown (pinned at max) off an inflated streak.
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => {
                // Bump BEFORE `should_trip` — Consecutive mode reads the streak.
                c.streak().fetch_add(1, Ordering::Relaxed);
                if Self::should_trip(c, now_time, cfg) {
                    Self::cell_open_locked(
                        c,
                        now_time,
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    // A genuine Closed→Open trip — the only path that should mint a BREAKER_TRIPS_TOTAL.
                    true
                } else {
                    let duration = Self::compute_cooldown_with_retry_after(
                        c,
                        now_time,
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    // saturating_add: see cell_open — never wrap `now + duration` (breaker-bypass /
                    // debug-panic on a hostile upstream's unbounded Retry-After).
                    c.cooldown_until()
                        .store(now_time.saturating_add(duration), Ordering::Release);
                    false
                }
            }
            // probe failed → reopen: the lane was already tripped (Open) and won the half-open probe;
            // reopening it re-arms the cooldown but is NOT a fresh Closed→Open trip, so do NOT count it.
            ST_HALF_OPEN => {
                // The probe lane reopened: bump the streak so the reopen escalates off the real
                // consecutive count (`cell_open_locked` → `compute_cooldown_with_retry_after` reads it).
                c.streak().fetch_add(1, Ordering::Relaxed);
                Self::cell_open_locked(c, now_time, cfg, retry_after, max_honored_retry_after_secs);
                false
            }
            // Already Open: a failure while Open is an intentional no-op (the cooldown is already
            // armed; we don't re-escalate on every failed request during a cooldown). Enumerated
            // explicitly per the breaker-match hard rule — no `_ =>` catch-all.
            ST_OPEN => false,
            // Request-path failure recording: an unexpected state encoding is treated as a no-op
            // (like the already-Open case) rather than `unreachable!()`-panicking the task. Not
            // reachable under the atomic-sentinel invariant; this is the graceful backstop.
            other => {
                tracing::error!(
                    state = other,
                    "unexpected breaker state in record_failure; no-op"
                );
                false
            }
        }
    }

    /// Record a success against the cell: reset the streak (unless the cell is Open — see below),
    /// push the outcome, and — if this was the half-open probe — complete recovery to Closed. (The
    /// lane-global `ok` counter is bumped by the caller, since it is shared across pools.)
    ///
    /// Returns `true` iff this call won the HalfOpen→Closed recovery CAS (i.e. it actually closed the
    /// cell). The caller uses that to perform the SWRR `current_weight` reset under the pool's shard
    /// lock (`reset_swrr_for`) — the reset is NOT done here because this runs under the per-cell
    /// transition lock and the SWRR reset must run under the per-pool SWRR shard lock instead.
    fn cell_record_success(c: &dyn BreakerCellAccess, now_time: u64) -> bool {
        // Serialize the whole state-dependent transition (the streak-reset gate reads the state, and
        // the HalfOpen→Closed recovery writes the (state, cooldown) pair) under the transition lock,
        // so a concurrent hard-down trip (Open + sticky cooldown) can't interleave its pair with this
        // recovery — the exact race this lock closes. `cell_closed` is reached via `cell_closed_locked`
        // below so we never re-take this std Mutex (deadlock). The outcome_window push is a leaf lock
        // taken under this one (consistent ordering, no other path takes them in the reverse order).
        let _tx = lock_recover(c.transition_lock());
        // Reset the consecutive-failure streak on a success — but NOT while the cell is Open. A bare
        // `record_success(lane)` can land on an Open cell via the degraded-forward path
        // (forward.rs `record_success` on a lane whose cell is still Open): the HalfOpen→Closed CAS
        // below then fails (Open ≠ HalfOpen) so no recovery occurs, yet an unconditional reset would
        // already have wiped the streak. In Consecutive mode the streak drives the escalating
        // backoff cooldown (`compute_cooldown_with_retry_after`); zeroing it on a still-Open cell
        // resets that escalation, letting a persistently-failing upstream be re-probed more
        // aggressively than designed. So only reset when the cell is NOT Open — the Closed happy path
        // resets here, and the HalfOpen→Closed recovery resets again via `cell_closed` below (which
        // also zeroes the streak), keeping the recovered cell's memory clean.
        if c.breaker_state().load(Ordering::Acquire) != ST_OPEN {
            c.streak().store(0, Ordering::Release);
        }
        lock_recover(c.outcome_window()).push(now_time, false); // success outcome
                                                                // CAS HalfOpen → Closed rather than a plain load-then-act. A non-atomic
                                                                // `load(HalfOpen) … store(Closed)` opens a TOCTOU window: a concurrent
                                                                // `record_hard_down_all_cells` / `record_probe_failure_all_cells` can move the cell
                                                                // HalfOpen → Open (re-arming the sticky cooldown) between the read and the write, and the
                                                                // unconditional `cell_closed` store would then silently recover a lane the hard-down just
                                                                // parked — bypassing the cooldown and dropping the hard-down entirely. Only the thread that
                                                                // wins this CAS owns the HalfOpen → Closed recovery; if the cell is no longer HalfOpen
                                                                // (already Open, or already Closed by a peer), we record the success outcome but leave the
                                                                // state transition to whoever owns it. Mirrors the CAS pattern in `cell_acquire_breaker`
                                                                // (Open → HalfOpen) and `cell_release_probe` (HalfOpen → Open).
        if c.breaker_state()
            .compare_exchange(ST_HALF_OPEN, ST_CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Self::cell_closed_locked(c);
            return true;
        }
        false
    }

    // ── Thin lane-default wrappers ─────────────────────────────────────────────────────────────
    // These drive the breaker FSM by lane index against the default cell. Release code goes through
    // the cell-core fns directly (cell_open / cell_closed / cell_usable_breaker), so these exist
    // only to give the unit tests a concrete, lane-indexed handle — hence `#[cfg(test)]`.

    /// Attempt to acquire the single probe in HalfOpen state. True if this request wins the probe.
    #[cfg(test)]
    fn try_acquire_probe(&self, lane: usize) -> bool {
        self.get_lane(lane)
            .probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Clear the probe flag (called after probe completes).
    #[cfg(test)]
    fn clear_probe(&self, lane: usize) {
        self.get_lane(lane)
            .probe_in_flight
            .store(false, Ordering::Release);
    }

    /// Transition to Open state with escalated cooldown.
    #[cfg(test)]
    fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        Self::cell_open(
            self.get_lane(lane).as_ref(),
            now_time,
            cfg,
            None,
            self.max_honored_retry_after_secs,
        );
    }

    /// Transition to Open state with escalated cooldown and optional Retry-After floor.
    #[cfg(test)]
    fn open_state_with_retry_after(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        Self::cell_open(
            self.get_lane(lane).as_ref(),
            now_time,
            cfg,
            retry_after,
            self.max_honored_retry_after_secs,
        );
    }

    /// Transition to Closed state (probe success). Mirrors the production recovery path: close the
    /// cell, then reset its SWRR accumulator under the (default-pool) shard lock.
    #[cfg(test)]
    fn closed_state(&self, lane: usize, _now_time: u64) {
        let cell = self.get_lane(lane);
        Self::cell_closed(cell.as_ref());
        self.reset_swrr_for("", cell.as_ref());
    }
}

#[derive(Clone)]
pub(crate) struct LaneData {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) limited: bool,
    pub(crate) budget: i64,
    pub(crate) cooldown_until: u64,
    pub(crate) streak: u32,
    pub(crate) dead: bool,
    pub(crate) dead_reason: String,
    pub(crate) ok: u64,
    pub(crate) err: u64,
    pub(crate) client_fault: u64,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of `self.model` (the config key).
    pub(crate) upstream_model: Option<String>,
    /// Model-level per-attempt time-to-headers cap (ms); flows ModelCfg → LaneData → Lane.
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator-declared reasoning-capability flag (see `ModelCfg::reasoning`).
    pub(crate) reasoning: bool,
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
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: false,
    };
    (lane, (id as u32) + 1) // weight = id + 1 (so lane 0 has weight 1, lane 1 has weight 2, etc.)
}

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub(crate) struct BreakerCfg {
    pub(crate) base_cooldown_secs: u64,
    pub(crate) max_cooldown_secs: u64,
    pub(crate) honor_retry_after: bool,
    pub(crate) trip: TripConfig,
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
                window_s: t.window_secs,
                threshold: t.threshold,
                min_requests: t.min_requests,
                consecutive_n: t.consecutive_n,
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
    pub(crate) mode: TripMode,
    pub(crate) window_s: u64,
    pub(crate) threshold: f64,
    pub(crate) min_requests: usize,
    pub(crate) consecutive_n: u32, // For consecutive mode
}

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3, // 3 consecutive errors
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

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Shared
    /// body for both `is_ready` (test-gated) and `ready_in` (the non-test `StateStore` trait method,
    /// production-wired via `forward::decide_policy_order`/`pick_among`), so it is production-live.
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

    /// Lane-global readiness for `/healthz` and `/stats`: true iff the lane is admissible (not dead /
    /// in budget) AND at least one breaker cell that production ACTUALLY routes through would admit a
    /// request right now. Production traffic routes through NAMED pools, whose per-pool cells trip
    /// independently; the lane-default (pool `""`) cell is the `LaneState` itself, which starts
    /// `ST_CLOSED`/`cooldown=0` and is written ONLY by direct/ad-hoc routes — pool-routed traffic
    /// never touches it. So when a lane has per-pool cells, the default cell is (almost) always
    /// "ready" and must NOT short-circuit the verdict: a lane whose every per-pool cell is tripped
    /// Open is NOT serviceable for pool traffic even though its untouched default cell reads ready.
    /// Therefore: if the lane HAS per-pool cells, readiness is purely whether ANY per-pool cell would
    /// admit (the default cell is ignored — it does not reflect pool routing). Only a lane with NO
    /// per-pool cells (direct/ad-hoc-only) falls back to the default cell. Side-effect-free (uses the
    /// non-mutating `cell_ready_breaker`, never the probe-stealing `usable`).
    fn lane_usable_any_cell(&self, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        let cells = read_recover(&self.pool_cells);
        match cells.get(&lane) {
            // Lane belongs to one or more pools: readiness reflects ONLY the per-pool cells that
            // pool-routed traffic actually dispatches through. Do NOT short-circuit on the
            // always-Closed default cell.
            Some(per_lane) if !per_lane.is_empty() => per_lane
                .iter()
                .any(|(_, cell)| Self::cell_ready_breaker(cell.as_ref(), now)),
            // Direct/ad-hoc-only lane (no per-pool cells): the default cell IS the routed cell.
            _ => Self::cell_ready_breaker(self.get_lane(lane).as_ref(), now),
        }
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
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            worst = worst.max(
                cell.cooldown_until()
                    .load(Ordering::Acquire)
                    .saturating_sub(now),
            );
        }
        worst
    }

    /// Worst-case consecutive-failure streak across the default cell and every per-pool cell for the
    /// lane (the lane-global health signal for `/stats`; the default cell's streak stays 0 for
    /// pool-routed traffic — see `lane_usable_any_cell`).
    fn lane_max_streak(&self, lane: usize) -> u32 {
        let mut worst = self.get_lane(lane).streak.load(Ordering::Relaxed);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            worst = worst.max(cell.streak().load(Ordering::Relaxed));
        }
        worst
    }

    /// Returns `true` iff this failure drove a Closed→Open trip on the (pool, lane) cell — threaded
    /// out so the forward.rs call site can emit `BREAKER_TRIPS_TOTAL` exactly once per logical trip.
    fn record_failure_for(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return false; // administratively down — ignore
        }
        let tripped = Self::cell_record_failure(
            self.cell(pool, lane).as_ref(),
            now_time,
            cfg,
            retry_after,
            self.max_honored_retry_after_secs,
        );
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
        tripped
    }

    fn record_success_for(&self, pool: &str, lane: usize) {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            // Dead lane: count the success for observability, don't touch the breaker.
            ls.ok.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let cell = self.cell(pool, lane);
        let recovered = Self::cell_record_success(cell.as_ref(), Self::now_secs());
        // The HalfOpen→Closed recovery re-admits this cell to selection; zero its stale SWRR
        // accumulator under the pool's shard lock (NOT inside the transition-locked close above) so
        // the reset serializes against any concurrent selection for this pool and keeps the pool's
        // `Σ current_weight == 0` invariant exact. The transition lock is already released here, so
        // the shard lock is taken un-nested.
        if recovered {
            self.reset_swrr_for(pool, cell.as_ref());
        }
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
            cooldown_secs = self.hard_down_cooldown_secs,
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let cell = self.cell(pool, lane);
        // Take the cell's transition lock so this trip's (Open + sticky cooldown) pair lands
        // atomically with respect to a racing recovery (`cell_closed`) or probe acquisition — without
        // it the separate `cooldown_until`/`breaker_state` stores could interleave with a concurrent
        // success-recovery and leave the cell Open with a cleared/short cooldown (sticky cooldown
        // dropped) or Closed with the stale sticky cooldown.
        let _tx = lock_recover(cell.transition_lock());
        cell.cooldown_until().store(
            Self::now_secs().saturating_add(self.hard_down_cooldown_secs),
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
        // concurrent selections FOR THIS POOL (otherwise interleaving corrupts the
        // `Σ current_weight == 0` invariant and biases distribution). The invariant is pool-local —
        // disjoint pools share no `current_weight` cells — so a per-pool (sharded) lock suffices and
        // lets selections for different pools proceed in parallel (see `swrr_shard`).
        let _swrr = lock_recover(self.swrr_shard(pool));
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

    #[cfg(test)]
    fn is_ready(&self, lane: usize, now: u64) -> bool {
        self.ready_for("", lane, now)
    }

    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool {
        self.lane_usable_any_cell(lane, now)
    }

    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        // Read-only, pool-aware health peek — the EXACT predicate `select_weighted_in` uses to filter
        // its healthy candidate set (lane-admissible + non-mutating `cell_ready_breaker`), exposed for
        // the routing-policy ordered walk. Never the probe-stealing `usable`.
        self.ready_for(pool, lane, now)
    }

    fn available_permits(&self, lane: usize) -> usize {
        // Read-only snapshot of free concurrency permits — racy by nature (a ranking hint).
        self.get_lane(lane).sem.available_permits()
    }

    fn lane_budget_remaining(&self, lane: usize) -> Option<i64> {
        let ls = self.get_lane(lane);
        if ls.limited {
            Some(ls.budget.load(Ordering::Relaxed))
        } else {
            None // unlimited / unmetered
        }
    }

    fn lane_latency_ms(&self, lane: usize) -> Option<f64> {
        // `0` bits is the "no sample yet" sentinel (a real latency EWMA is strictly positive).
        let bits = self
            .get_lane(lane)
            .latency_ewma_bits
            .load(Ordering::Relaxed);
        if bits == 0 {
            None
        } else {
            Some(f64::from_bits(bits))
        }
    }

    fn record_latency_in(&self, _pool: &str, lane: usize, latency_ms: f64) {
        // Ignore a non-finite or non-positive sample — it would poison the EWMA (and `<= 0` collides
        // with the "no sample" sentinel). A real end-to-end latency is always strictly positive.
        if !latency_ms.is_finite() || latency_ms <= 0.0 {
            return;
        }
        let atomic = &self.get_lane(lane).latency_ewma_bits;
        // Lock-free read-modify-write CAS loop, the same idiom `spend_budget` uses. Contention here is
        // negligible (one update per completed request, off the selection path), so a CAS retry is far
        // cheaper than a lock and keeps the no-new-locks-on-the-hot-path requirement.
        let mut cur = atomic.load(Ordering::Relaxed);
        loop {
            let next = if cur == 0 {
                // First sample seeds the EWMA directly.
                latency_ms
            } else {
                let prev = f64::from_bits(cur);
                LATENCY_EWMA_ALPHA * latency_ms + (1.0 - LATENCY_EWMA_ALPHA) * prev
            };
            // Guard against a degenerate update landing on the sentinel (e.g. underflow to +0.0),
            // which would silently reset the lane to "no sample". Keep the previous value instead.
            let next_bits = next.to_bits();
            if next_bits == 0 {
                return;
            }
            match atomic.compare_exchange_weak(cur, next_bits, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => cur = observed, // a concurrent update won; retry on the fresh value
            }
        }
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
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState {
        self.breaker_state_for(pool, lane)
    }

    #[cfg(test)]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64) {
        let cell = self.cell(pool, lane);
        let _tx = lock_recover(cell.transition_lock());
        cell.cooldown_until()
            .store(cooldown_until, Ordering::Release);
        cell.breaker_state().store(ST_OPEN, Ordering::Release);
        cell.probe_in_flight().store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for("", lane, now)
    }

    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for(pool, lane, now)
    }

    #[cfg(test)]
    fn record_success(&self, lane: usize) {
        self.record_success_for("", lane);
    }

    fn record_success_in(&self, pool: &str, lane: usize) {
        self.record_success_for(pool, lane);
    }

    fn record_probe_success_all_cells(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Administratively-dead lane: count the success for observability (matching
        // `record_success_for`'s dead-lane branch) but do not touch the breaker. Bump `ok` exactly
        // once and return, mirroring `record_probe_failure_all_cells`'s dead-lane early-out.
        if ls.dead.load(Ordering::Relaxed) {
            ls.ok.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes) — IS the `LaneState`. `cell_record_success` pushes the
        // success outcome and runs the HalfOpen→Closed CAS. It does NOT touch `ok`/`err`, so it never
        // double-counts the lane-global stat. The CAS is *usually* a no-op here because the 2xx caller
        // runs `recover_lane` first — but only when `lane_needs_probe` is true, and even then a peer
        // (organic request, hard-down) can move a cell back to HalfOpen between that recovery and this
        // push. If this push then wins the HalfOpen→Closed CAS, `cell_closed_locked` zeroed the cell's
        // SWRR `current_weight` under the transition lock, so the matching `reset_swrr_for` MUST run to
        // hold the pool's `Σ current_weight == 0` invariant — gate it on the recovered-bool exactly
        // like `record_success_for` and `recover_lane` do. Dropping the bool here was
        // the LOW #19 defect.
        if Self::cell_record_success(ls.as_ref(), now) {
            // Default cell belongs to the no-pool ("") set; reset runs after the transition lock is
            // released (it is a leaf within `cell_record_success`), so the shard lock is un-nested.
            self.reset_swrr_for("", ls.as_ref());
        }
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // so the probe success dilutes the SAME per-pool error-rate windows the failed-probe path
        // trips against. Mirrors `record_probe_failure_all_cells`'s `pool_cells` iteration exactly
        // (existing cells only — a cell not yet created inherits health lazily on first access).
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            // Same SWRR gate per cell: a real HalfOpen→Closed close here re-admits the cell to
            // selection with a zeroed accumulator, so reset it under THIS pool's shard lock (keyed by
            // the pool name), serializing against that pool's selections — mirrors `recover_lane`.
            if Self::cell_record_success(cell.as_ref(), now) {
                self.reset_swrr_for(pool_name, cell.as_ref());
            }
        }
        // Bump the lane-GLOBAL `ok` counter EXACTLY ONCE per probe (not once per cell). This is the
        // R24 fix: the prior per-cell `record_success_in` loop bumped `LaneState.ok` (N+1) times for a
        // lane in N pools. Mirrors `record_probe_failure_all_cells`, which bumps `LaneState.err` once.
        ls.ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_client_fault(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Client faults do NOT increment err, streak, or trigger cooldowns.
        // They are tracked separately for observability.
        ls.client_fault.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn record_transient(
        &self,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for("", lane, Self::now_secs(), cfg, retry_after)
    }

    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for(pool, lane, Self::now_secs(), cfg, retry_after)
    }

    #[cfg(test)]
    fn record_rate_limit(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for("", lane, now_time, cfg, retry_after)
    }

    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for(pool, lane, now_time, cfg, retry_after)
    }

    #[cfg(test)]
    fn record_hard_down(&self, lane: usize, reason: &str) {
        self.record_hard_down_for("", lane, reason);
    }

    fn record_hard_down_all_cells(&self, lane: usize, reason: &str) -> bool {
        // Mirror `record_probe_failure_all_cells` exactly: operate on the per-pool cell Arcs while
        // holding the `pool_cells` lock, applying the SAME cell mutation `record_hard_down_for` does
        // (sticky Open + cooldown, probe released) — NOT by re-calling `record_hard_down_for`, which
        // re-locks `pool_cells` via `self.cell()` and would deadlock here.
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE: a sticky cooldown + Open, recovered via the half-open probe; do
        // NOT set `dead` (that would block recovery). Record the reason once, lane-wide.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        let hard_down_cooldown_secs = self.hard_down_cooldown_secs;
        tracing::warn!(
            model = %ls.model,
            reason,
            cooldown_secs = hard_down_cooldown_secs,
            "lane hard-down (all cells); sticky cooldown (recovers via half-open probe)"
        );
        let now = Self::now_secs();
        let trip = |c: &dyn BreakerCellAccess| {
            // Per-cell transition lock so the (Open + sticky cooldown) pair lands atomically against a
            // racing recovery/probe-acquire on the SAME cell (the torn-write race). Each cell has its
            // own lock and we take them one at a time (never nested), so iterating all cells here
            // cannot deadlock; the `pool_cells` READ lock held by the caller is a different,
            // strictly-outer lock (transition fns never reach back to `pool_cells`).
            let _tx = lock_recover(c.transition_lock());
            c.cooldown_until().store(
                now.saturating_add(hard_down_cooldown_secs),
                Ordering::Release,
            );
            c.breaker_state().store(ST_OPEN, Ordering::Release);
            // Release any in-flight single-flight probe back to Open (see `record_hard_down_for`):
            // without this a hard-down classified while HalfOpen leaves the cell Open with
            // `probe_in_flight == true`, benching the lane permanently after cooldown.
            c.probe_in_flight().store(false, Ordering::Release);
        };
        // Was the default cell a genuine fresh trip (Closed → Open)? Capture BEFORE tripping so the
        // caller can gate BREAKER_TRIPS_TOTAL on a logical trip, not a HalfOpen/Open re-classification
        // that recurs on every recovery-probe cycle of a persistently-dead lane. Best-effort metric: a
        // rare concurrent trip may miscount by one — far better than the prior unconditional per-probe
        // over-count.
        let default_was_closed = ls.as_ref().breaker_state().load(Ordering::Acquire) == ST_CLOSED;
        // Default cell (direct/`named`/`adhoc` routes that read the "" cell).
        trip(ls.as_ref());
        // Every existing per-pool cell for this lane — the cells organic pool-routed traffic is
        // selected against. (A cell not yet created inherits the lane default lazily on first
        // access.)
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            trip(cell.as_ref());
        }
        default_was_closed
    }

    fn recover_lane(&self, lane: usize) {
        // A health probe tests the UPSTREAM, which is shared across pools — so a successful probe
        // recovers EVERY cell for this lane (the default/direct-route cell and all per-pool cells),
        // clearing both a tripped (non-Closed) breaker AND a soft cooldown on a Closed cell.
        let now = Self::now_secs();
        // Lock-free pre-filter: skip cells that are plainly Closed-and-cooled so we don't take the
        // transition lock (and, on close, the SWRR shard lock) for the common already-healthy case.
        // It returns the cooldown value it OBSERVED (`Some(observed)`) so the under-lock close can
        // re-validate against it. This pre-read is ONLY a fast path AND the snapshot — the
        // authoritative decision happens under the transition lock in `cell_closed_if_recoverable`,
        // which closes the TOCTOU (#16): a concurrent hard-down can park a cell Open with a fresh
        // sticky cooldown between this read and the close, and an unconditional close would clobber
        // that just-armed cooldown.
        let observe = |c: &dyn BreakerCellAccess| -> Option<u64> {
            let cooldown = c.cooldown_until().load(Ordering::Acquire);
            let suppressed =
                c.breaker_state().load(Ordering::Acquire) != ST_CLOSED || cooldown > now;
            suppressed.then_some(cooldown)
        };
        // Close a cell only if it both passed the pre-filter and survives the under-lock re-validation
        // against the cooldown the pre-filter observed. Returns whether the close actually happened so
        // the caller can gate the SWRR reset on a real close — a cell a peer re-armed mid-race is left
        // suppressed and must NOT have its accumulator zeroed.
        let close = |c: &dyn BreakerCellAccess| -> bool {
            match observe(c) {
                Some(observed) => Self::cell_closed_if_recoverable(c, now, observed),
                None => false,
            }
        };
        let ls = self.get_lane(lane);
        // The default cell belongs to the no-pool ("") set. The SWRR reset runs after the close
        // returns (transition lock released), so the shard lock is taken un-nested — see
        // `reset_swrr_for`.
        if close(ls.as_ref()) {
            self.reset_swrr_for("", ls.as_ref());
        }
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            if close(cell.as_ref()) {
                // Each per-pool cell's SWRR reset runs under ITS pool's shard lock (the map key is
                // the pool name), serializing against that pool's selections.
                self.reset_swrr_for(pool_name, cell.as_ref());
            }
        }
    }

    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        _what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
    ) {
        // Administratively-dead lanes ignore failure recording (matches record_failure_for).
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes) — resolved against the `""` (no-pool) config. The
        // returned trip bool is intentionally discarded: the out-of-band prober does not emit
        // `BREAKER_TRIPS_TOTAL` (that counter is reserved for the organic request path). `retry_after`
        // (the probe's server-requested cooldown floor) is forwarded so a 429/Retry-After probe honors
        // the upstream's backoff; `cell_record_failure` applies it only when `honor_retry_after` is set.
        let default_cfg = resolve_cfg("");
        let max_honored_retry_after_secs = self.max_honored_retry_after_secs;
        let _ = Self::cell_record_failure(
            self.get_lane(lane).as_ref(),
            now,
            &default_cfg,
            retry_after,
            max_honored_retry_after_secs,
        );
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // each evaluated against ITS OWN pool's resolved breaker config (trip thresholds + cooldown
        // backoff), not a one-size default. (A cell not yet created inherits health lazily on first
        // access via `cell`.)
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            let cfg = resolve_cfg(pool_name);
            let _ = Self::cell_record_failure(
                cell.as_ref(),
                now,
                &cfg,
                retry_after,
                max_honored_retry_after_secs,
            );
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
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .any(|(_, cell)| suppressed(cell.as_ref()))
    }

    fn try_acquire(&self, lane: usize) -> Option<Permit> {
        let ls = self.get_lane(lane);
        ls.sem.clone().try_acquire_owned().ok()
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

    fn refund_budget(&self, lane: usize) {
        let ls = self.get_lane(lane);
        if !ls.limited {
            return; // unlimited budget — nothing was spent
        }
        // Inverse of a single `spend_budget`: return the one unit charged on the 2xx headers when the
        // body then failed to transfer. This is ALWAYS paired with a prior successful spend on the
        // same request, so a plain increment can never push the budget above its configured ceiling.
        ls.budget.fetch_add(1, Ordering::Relaxed);
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

    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(idx, ls)| LaneHealthSnapshot {
                model: ls.model.clone(),
                provider: ls.provider.clone(),
                budget: if ls.limited {
                    ls.budget.load(Ordering::Relaxed)
                } else {
                    -1
                },
                breaker_state: ls.breaker_state.load(Ordering::Relaxed),
                cooldown_until: ls.cooldown_until.load(Ordering::Relaxed),
                streak: ls.streak.load(Ordering::Relaxed),
                dead: ls.dead.load(Ordering::Relaxed),
                dead_reason: lock_recover(&ls.dead_reason).clone(),
                ok: ls.ok.load(Ordering::Relaxed),
                err: ls.err.load(Ordering::Relaxed),
                client_fault: ls.client_fault.load(Ordering::Relaxed),
                latency_ewma_bits: ls.latency_ewma_bits.load(Ordering::Relaxed),
                cells: {
                    let map = self.pool_cells.read().unwrap_or_else(|e| e.into_inner());
                    map.get(&idx)
                        .map(|cells| {
                            cells
                                .iter()
                                .map(|(pool, cell)| PoolCellHealthSnapshot {
                                    pool: pool.to_string(),
                                    breaker_state: cell.breaker_state.load(Ordering::Relaxed),
                                    cooldown_until: cell.cooldown_until.load(Ordering::Relaxed),
                                    streak: cell.streak.load(Ordering::Relaxed),
                                    err: cell.err.load(Ordering::Relaxed),
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                },
            })
            .collect()
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
    fn record_outcome_error_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Add to sliding window
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, true);

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    /// Record success outcome with explicit time.
    fn record_outcome_success_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Reset streak on success (for the FSM to know we recovered)
        ls.streak.store(0, Ordering::Release);

        // Add to sliding window
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, false);

        ls.ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Drive the recovery-close gate (`cell_closed_if_recoverable`) directly against a named cell with
    /// an EXPLICIT `observed_cooldown`. This lets a regression test reproduce the #16 TOCTOU
    /// deterministically: pass the (smaller) cooldown a probe would have observed, after a concurrent
    /// hard-down has already re-armed the live cell to a stricter cooldown — exactly the interleaving
    /// where the old unconditional close clobbered the hard-down. Returns whether the cell was closed.
    fn recover_close_if_recoverable(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        observed: u64,
    ) -> bool {
        Self::cell_closed_if_recoverable(self.cell(pool, lane).as_ref(), now, observed)
    }

    /// Read a cell's raw `cooldown_until` (no `now` subtraction), for race-regression assertions.
    fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane)
            .cooldown_until()
            .load(Ordering::Acquire)
    }

    /// Park a named cell HalfOpen with the single-flight probe acquired and a STALE SWRR accumulator —
    /// the precondition under which a recorded success drives a HalfOpen→Closed recovery whose reset
    /// the caller is responsible for. Test-only setup for the LOW #19 regression.
    fn arm_half_open_stale_swrr(&self, pool: &str, lane: usize, cooldown: u64, stale_weight: i64) {
        let c = self.cell(pool, lane);
        c.current_weight().store(stale_weight, Ordering::Relaxed);
        c.cooldown_until().store(cooldown, Ordering::Relaxed);
        c.breaker_state().store(ST_HALF_OPEN, Ordering::Relaxed);
        c.probe_in_flight().store(true, Ordering::Relaxed);
    }

    /// Read a cell's raw SWRR `current_weight`, for the LOW #19 invariant assertion.
    fn cell_current_weight(&self, pool: &str, lane: usize) -> i64 {
        self.cell(pool, lane)
            .current_weight()
            .load(Ordering::Relaxed)
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
            upstream_model: None,
            attempt_timeout_ms: None,
            reasoning: false,
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
}
