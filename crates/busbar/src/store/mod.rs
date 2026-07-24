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

/// Normalize a breaker state being RESTORED from a snapshot (or inherited by a sibling cell):
/// `ST_HALF_OPEN` becomes `ST_OPEN`. A restored HalfOpen cell has `probe_in_flight == false` (the
/// snapshot never carries it, and the restore path never sets it), and both `cell_ready_breaker` and
/// `cell_acquire_breaker` reject HalfOpen unconditionally — so the cell WEDGES: no dispatch can acquire
/// it and no probe outcome (`cell_open`/`cell_closed`) ever runs against it, benching that (pool, lane)
/// until an out-of-band `recover_lane` touches it (indefinitely when health probing is disabled).
/// Restoring `ST_OPEN` instead lets the restored (already-expired) cooldown drive a fresh probe
/// acquisition on the cell's first request. (found: audit c1r6 — restore lacked the sibling-create
/// path's existing normalization.)
fn restored_breaker_state(state: u64) -> u64 {
    if state == ST_HALF_OPEN {
        ST_OPEN
    } else {
        state
    }
}

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

/// RAII concurrency permit, held for the request's lifetime and released on drop.
///
/// A lane with `max_concurrent` SET holds a real slot on its semaphore (`Bounded`) — the cap is
/// enforced exactly, at any configured value. A lane with `max_concurrent` OMITTED is unbounded:
/// there is nothing to enforce, so nothing is counted — `Unbounded` touches no shared state at
/// all. (The old realization acquired a permit from a `MAX_PERMITS` semaphore even for unbounded
/// lanes: two shared-atomic writes per request on a cache line every worker fights over, paying
/// full contention for a limit that could never bind.)
#[must_use]
pub(crate) enum Permit {
    // The permit is never READ — it exists to be HELD (its Drop returns the slot).
    Bounded(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit),
    Unbounded,
}

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
    /// Monotonic Closed→Open trip count + the most recent trip's epoch (0 = never) — the
    /// poll-safe "did a trip happen since I last looked" signal (audit #5).
    pub(crate) trips: u64,
    pub(crate) last_trip_at: u64,
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
    /// Monotonic Closed→Open trip count + last-trip epoch (0 = never) — learned reliability, so it
    /// carries across apply/restart like ok/err. `serde(default)` reads pre-1.3 persisted snapshots.
    #[serde(default)]
    pub(crate) trips: u64,
    #[serde(default)]
    pub(crate) last_trip_at: u64,
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
    // ROUTING-POLICY SIGNAL ACCESSORS: read per-request by `proxy::decide_policy_order` (and
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
    /// Read a (pool, lane) cell's current single-flight probe epoch (owner token). A probe winner
    /// captures this immediately after `acquire_for_dispatch_in` succeeds and later passes it to
    /// `release_probe_owned_in` so a STALLED, late release cannot revert a newer probe (P2 #4).
    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64;
    /// OWNER-CHECKED variant of `release_probe_in`: reverts the undispatched probe ONLY when the cell's
    /// probe epoch still equals `owned_epoch`. Used by the `ProbeGuard` drop path (the one release site
    /// that can outlive its acquisition across an await, so the one that can be stale). A strict no-op
    /// when the epoch has moved on - the probe we won was already consumed or superseded.
    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64);
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
    fn export_health(&self) -> Vec<LaneHealthSnapshot>;

    /// Restore health state IN PLACE by stable identity (D3 boot restore — runs before the first
    /// request is served). Lanes without a matching snapshot are untouched; snapshots without a
    /// matching lane are dropped.
    fn restore_health(&self, restored: &[LaneHealthSnapshot]);
}

mod in_memory;
pub(crate) use in_memory::*;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
