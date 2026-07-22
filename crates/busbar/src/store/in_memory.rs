use super::*;

/// Bounded sliding window of recent request outcomes, each tagged success/error, used to compute
/// the error-rate trip signal. Backed by a `VecDeque` so dropping the oldest entry at capacity is
/// O(1). Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
pub(crate) struct OutcomeWindow {
    /// (timestamp_secs, is_error) per outcome, oldest at the front.
    pub(crate) entries: std::collections::VecDeque<(u64, bool)>,
    pub(crate) capacity: usize,
}

impl OutcomeWindow {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record a timestamped outcome (`is_error` true for a failure). Drops the oldest at capacity.
    pub(crate) fn push(&mut self, ts: u64, is_error: bool) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ts, is_error));
    }

    /// Total outcomes within `window_s` seconds of `now`.
    pub(crate) fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|(ts, _)| *ts >= start).count()
    }

    /// Error outcomes within `window_s` seconds of `now`.
    pub(crate) fn error_count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries
            .iter()
            .filter(|(ts, is_error)| *ts >= start && *is_error)
            .count()
    }

    /// Clear all entries.
    pub(crate) fn clear(&mut self) {
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
    // MONOTONIC single-flight probe generation, bumped each time a probe is WON (Open→HalfOpen CAS in
    // `cell_acquire_breaker`). It is the probe's OWNER TOKEN: the winner captures the post-bump value
    // and passes it back to `cell_release_probe`, which reverts the cell ONLY if the epoch still
    // matches. Without it, a stalled undispatched-probe release (a `ProbeGuard` dropped LATE, after the
    // cell already recorded an outcome AND a NEW probe was won) would CAS the fresh winner's HalfOpen
    // back to Open and clear its `probe_in_flight`, so a third caller could win a DUPLICATE concurrent
    // probe on a lane already being probed. Benign (an extra recovery probe, no correctness loss) but
    // real; the epoch check makes release a strict no-op for any but the current probe owner.
    pub(crate) probe_epoch: AtomicU64,
    pub(crate) err: AtomicU64,
    pub(crate) outcome_window: std::sync::Mutex<OutcomeWindow>,
    pub(crate) current_weight: AtomicI64, // SWRR state (per pool — selection runs over a pool's set)
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
    pub(crate) transition_lock: std::sync::Mutex<()>,
}

impl InMemoryStore {
    /// The identity-keyed restore shared by the state-carrying constructor (config apply) and the
    /// in-place boot restore (D3): apply each matching snapshot's lane-global fields and recreate
    /// its per-pool breaker cells eagerly (a restored Open cell blocks dispatch from request one).
    pub(crate) fn restore_health_impl(&self, restored: &[LaneHealthSnapshot]) {
        for (idx, lane) in self.lanes.iter().enumerate() {
            let Some(snap) = restored
                .iter()
                .find(|s| s.model == lane.model && s.provider == lane.provider)
            else {
                continue;
            };
            // Carry over the remaining request budget ONLY when BOTH the snapshot and the new lane
            // are limited, and never above the NEW cap. `export_health` writes the sentinel -1 for
            // an unlimited lane; if the new config just ADDED `max_requests` to a lane that was
            // unlimited at snapshot time, storing that -1 over the freshly-set cap would make
            // `lane_admissible` (`limited && budget <= 0`) reject every dispatch with NO
            // self-recovery path (the budget only rises on a successful dispatch, which is itself
            // gated on admissibility). And if the operator LOWERED `max_requests`, the prior
            // (larger) remaining budget must be clamped to the freshly-set cap the constructor
            // already stored — otherwise the lane over-serves by up to (old_remaining - new_cap),
            // silently blowing past the operator's newly-lowered hard ceiling. `min` with the
            // current atomic (which holds the new cap at this point) handles same-cap and
            // cap-increase carry-over unchanged while capping a reduction.
            if lane.limited && snap.budget >= 0 {
                let new_cap = lane.budget.load(Ordering::Relaxed);
                lane.budget
                    .store(snap.budget.min(new_cap), Ordering::Relaxed);
            }
            lane.breaker_state.store(
                restored_breaker_state(snap.breaker_state),
                Ordering::Relaxed,
            );
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
            lane.trips.store(snap.trips, Ordering::Relaxed);
            lane.last_trip_at
                .store(snap.last_trip_at, Ordering::Relaxed);
            let mut map = self.pool_cells.write().unwrap_or_else(|e| e.into_inner());
            let cells = map.entry(idx).or_default();
            for cs in &snap.cells {
                // In-place restore may find the cell already lazily created — restore INTO it.
                if let Some((_, cell)) = cells.iter().find(|(p, _)| p.as_ref() == cs.pool) {
                    cell.breaker_state
                        .store(restored_breaker_state(cs.breaker_state), Ordering::Relaxed);
                    cell.cooldown_until
                        .store(cs.cooldown_until, Ordering::Relaxed);
                    cell.streak.store(cs.streak, Ordering::Relaxed);
                    cell.err.store(cs.err, Ordering::Relaxed);
                } else {
                    let cell = Arc::new(BreakerCell::new());
                    cell.breaker_state
                        .store(restored_breaker_state(cs.breaker_state), Ordering::Relaxed);
                    cell.cooldown_until
                        .store(cs.cooldown_until, Ordering::Relaxed);
                    cell.streak.store(cs.streak, Ordering::Relaxed);
                    cell.err.store(cs.err, Ordering::Relaxed);
                    cells.push((cs.pool.clone().into_boxed_str(), cell));
                }
            }
        }
    }
}

impl BreakerCell {
    pub(crate) fn new() -> Self {
        Self {
            breaker_state: AtomicU64::new(ST_CLOSED),
            streak: AtomicU32::new(0),
            cooldown_until: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            probe_epoch: AtomicU64::new(0),
            err: AtomicU64::new(0),
            outcome_window: std::sync::Mutex::new(OutcomeWindow::new(OUTCOME_WINDOW_CAPACITY)),
            current_weight: AtomicI64::new(0),
            transition_lock: std::sync::Mutex::new(()),
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
    /// Monotonic single-flight probe owner token (see `BreakerCell::probe_epoch`).
    fn probe_epoch(&self) -> &AtomicU64;
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
    fn probe_epoch(&self) -> &AtomicU64 {
        &self.probe_epoch
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
    fn probe_epoch(&self) -> &AtomicU64 {
        &self.probe_epoch
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
pub(crate) type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<BreakerCell>)>>;

/// FNV-1a over a pool name → SWRR shard index. Pure (no `self`) so it can be unit-tested and reused
/// by the per-pool shard memo without duplicating the constants. Distribution, not cryptographic
/// strength, is all that matters: it only picks which lock shard a pool's selections serialize on.
/// `SWRR_SHARDS` is a power of two, so the reduction is a cheap mask.
pub(crate) fn swrr_shard_index(pool: &str) -> usize {
    (fnv1a_u64(pool) as usize) & (SWRR_SHARDS - 1)
}

/// FNV-1a 64-bit offset-basis and prime (the canonical constants). Module-level so both the string
/// hash (`fnv1a_u64`) and the cooldown-jitter seed mixer (which folds 128-bit inputs with the same
/// FNV step) share one named definition instead of repeating the bare magic literals.
pub(crate) const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

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
pub(crate) const SWRR_SHARDS: usize = 64;

/// Wraps the per-lane atomics/semaphores with per-(pool, lane) FSM breaker logic, populated lazily.
pub(crate) struct InMemoryStore {
    pub(crate) lanes: Vec<Arc<LaneState>>,
    /// Per-(pool, lane) breaker cells, created lazily on first access. The lane-global fields
    /// (sem/budget/dead/ok) always live on `lanes[lane]`; only the breaker FSM is isolated per pool.
    ///
    /// An `RwLock` (not a plain `Mutex`): the overwhelmingly common access is a READ of an
    /// already-created cell on the hot dispatch path (`cell()` / the `/stats` aggregators), and many
    /// such reads can proceed concurrently under a shared lock. Only the rare lazy first-touch insert
    /// of a new (pool, lane) cell takes the exclusive write lock. The previous `Mutex` forced an
    /// exclusive acquisition for every read, serializing the selection path.
    pub(crate) pool_cells: std::sync::RwLock<PoolCellMap>,
    /// Sharded SWRR locks (see `SWRR_SHARDS`). A selection serializes only against other selections
    /// whose pool hashes to the same shard, so concurrent selections for disjoint pools run in
    /// parallel. Boxed slice so the struct stays movable without a const-generic array literal.
    pub(crate) swrr_shards: Box<[std::sync::Mutex<()>]>,
    /// Operator-configured hard-down sticky cooldown (seconds). Replaces the historical
    /// `HARD_DOWN_COOLDOWN_SECS` const at every hard-down trip; defaults to 1800 when the operator
    /// omits `limits.hard_down_cooldown_secs`.
    pub(crate) hard_down_cooldown_secs: u64,
    /// Operator-configured ceiling (seconds) on a honored upstream `Retry-After`. Replaces the
    /// historical `MAX_HONORED_RETRY_AFTER_SECS` const in `compute_cooldown_with_retry_after`;
    /// defaults to 86_400 (24h). Bounds a hostile/buggy `Retry-After` so it cannot park a lane for
    /// millennia or overflow the cooldown arithmetic.
    pub(crate) max_honored_retry_after_secs: u64,
    /// Memoized pool-name → shard-index map. `swrr_shard` ran FNV-1a over the pool NAME on EVERY
    /// selection (the hot dispatch path); the index is a pure function of the (small, stable) set of
    /// pool names, so cache it on first touch and reuse thereafter. An append-only `Vec` scanned by
    /// byte-compare (the same idiom as `cell()`) — NOT a `HashMap`, whose SipHash lookup would cost
    /// more than the FNV it replaces. The cached value is identical to recomputing `swrr_shard_index`,
    /// so selection semantics are unchanged. `RwLock`: the common case is a shared-read hit; only a
    /// genuine first-touch miss takes the exclusive write lock to insert.
    pub(crate) pool_shards: std::sync::RwLock<Vec<(Box<str>, usize)>>,
}

// Field ORDER is perf-deliberate (hot-path cache locality): the per-request atomics are grouped
// into one cluster so a dispatch decision (dead check → SWRR weight → breaker CAS → outcome
// counter) touches 1-2 cache lines instead of hopping over the Strings and Mutex blocks that used
// to interleave them. Boot-time read-only fields lead; Mutex-guarded cold state trails. Pure
// layout change — every constructor uses named fields, so semantics are untouched.
pub(crate) struct LaneState {
    // ── read-only after boot ──
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) limited: bool,
    // ── hot per-request atomics (keep contiguous) ──
    pub(crate) dead: AtomicBool,
    // FSM state per lane
    pub(crate) breaker_state: AtomicU64, // stored as u64 (ST_CLOSED/ST_OPEN/ST_HALF_OPEN) so it can be CAS'd
    pub(crate) probe_in_flight: AtomicBool,
    // Single-flight probe owner token - see `BreakerCell::probe_epoch`.
    pub(crate) probe_epoch: AtomicU64,
    // SWRR state per lane
    pub(crate) current_weight: AtomicI64,
    pub(crate) cooldown_until: AtomicU64,
    pub(crate) budget: AtomicI64,
    pub(crate) streak: AtomicU32,
    pub(crate) ok: AtomicU64,
    pub(crate) err: AtomicU64,
    pub(crate) client_fault: AtomicU64,
    // Rolling EWMA of observed end-to-end request latency for this lane, in MILLISECONDS, stored as
    // the raw bits of an `f64` (`f64::to_bits`) so it can be read/updated lock-free with a single
    // atomic — mirroring the lock-free atomic style the rest of this struct uses for cheap per-lane
    // signals. A sentinel of `0` bits (== `+0.0`) means "no sample yet" (a real end-to-end latency is
    // always strictly positive), which the routing-policy projection maps to `latency_ms: None`. This
    // is a lane-GLOBAL signal (latency is a property of the shared upstream, not of any one pool's
    // breaker cell), so it lives on `LaneState`, not on `BreakerCell`. Read by the `fastest` policy
    // via `lane_latency_ms`; updated after each request completes via `record_latency_in`.
    pub(crate) latency_ewma_bits: AtomicU64,
    // MONOTONIC count of genuine Closed→Open breaker trips on this lane (any cell) + the epoch of
    // the most recent one (0 = never). Breaker open→close is transient — a poll-only consumer can
    // miss the whole episode between two polls; a monotonic count + last-trip timestamp let it
    // detect "a trip happened since I last looked" without catching the live edge (3rd-party audit
    // #5). Lane-global (like ok/err): a trip in ANY pool cell counts. Carried across config apply /
    // restart with the rest of the learned health.
    pub(crate) trips: AtomicU64,
    pub(crate) last_trip_at: AtomicU64,
    // ── cold, Mutex-guarded state (rare paths: trips, window maintenance, transitions) ──
    pub(crate) dead_reason: std::sync::Mutex<String>,
    pub(crate) outcome_window: std::sync::Mutex<OutcomeWindow>,
    // Serializes state+cooldown transitions on the default cell — see `BreakerCell::transition_lock`.
    pub(crate) transition_lock: std::sync::Mutex<()>,
}

/// Smoothing factor (α) for the per-lane latency EWMA: `ewma = α·sample + (1-α)·ewma`. A smaller α
/// gives a longer memory (steadier signal, slower to react); 0.2 weights the most recent ~5 requests
/// most heavily, which is responsive enough to notice a degrading upstream without thrashing the
/// `fastest` ranking on a single slow outlier. Cheap, bounded, allocation-free.
pub(crate) const LATENCY_EWMA_ALPHA: f64 = 0.2;

impl InMemoryStore {
    /// Read a (pool, lane) cell's cumulative error counter — for concurrency/isolation tests.
    #[cfg(test)]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
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
                    probe_epoch: AtomicU64::new(0),
                    outcome_window: std::sync::Mutex::new(OutcomeWindow::new(
                        OUTCOME_WINDOW_CAPACITY,
                    )),
                    current_weight: AtomicI64::new(0),
                    transition_lock: std::sync::Mutex::new(()),
                    // `0` bits == "no latency sample yet" (see `latency_ewma_bits`).
                    latency_ewma_bits: AtomicU64::new(0),
                    trips: AtomicU64::new(0),
                    last_trip_at: AtomicU64::new(0),
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
        store.restore_health_impl(restored);
        store
    }

    pub(crate) fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }

    /// Select the SWRR shard lock for a pool. The shard is keyed by the pool-name hash so all
    /// selections for a given pool serialize against each other (preserving the pool-local
    /// `Σ current_weight == 0` invariant), while selections for pools hashing to other shards run in
    /// parallel. `SWRR_SHARDS` is a power of two, so the index is a cheap mask.
    pub(crate) fn swrr_shard(&self, pool: &str) -> &std::sync::Mutex<()> {
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
    pub(crate) fn cell(&self, pool: &str, lane: usize) -> Arc<dyn BreakerCellAccess> {
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
    pub(crate) fn should_trip(c: &dyn BreakerCellAccess, now: u64, cfg: &BreakerCfg) -> bool {
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
    pub(crate) fn compute_cooldown_with_retry_after(
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
            // `base * 2^streak`, saturating. NOTE: `checked_shl` only guards the shift COUNT (>= 64),
            // NOT value overflow — `10u64.checked_shl(63)` is `Some(0)` (the high bits shift out), so
            // an even `base_cooldown_secs` at `streak >= 63` WRAPPED TO 0, giving a zero cooldown
            // (tripped cell re-admits instantly) exactly when the lane is failing hardest. Compute in
            // u128 (base < 2^64, shift <= 63 → product < 2^127, no overflow) then saturate to u64.
            // (found: audit c2r3.)
            let shift = streak.min(63);
            let shifted = (cfg.base_cooldown_secs as u128) << shift;
            u64::try_from(shifted)
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
                // At least half of base, but NEVER below 1s. For `base_cooldown_secs = 1` (the
                // minimum config_validate permits) the integer floor `1/2` truncates to 0, and a
                // −1 jitter draw (~1/3 of trips) then produced a ZERO cooldown — the tripped cell
                // re-admits instantly (`now >= cooldown_until`), the exact zero-backoff outcome the
                // validator rejects a static `base_cooldown_secs = 0` to prevent. (found: audit c2r1.)
                (duration / 2).max(1),
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
    pub(crate) fn cell_open(
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
    pub(crate) fn cell_open_locked(
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
    pub(crate) fn cell_closed(c: &dyn BreakerCellAccess) {
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
    pub(crate) fn cell_closed_if_recoverable(
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
    pub(crate) fn cell_closed_locked(c: &dyn BreakerCellAccess) {
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
    pub(crate) fn reset_swrr_for(&self, pool: &str, c: &dyn BreakerCellAccess) {
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
    pub(crate) fn cell_release_probe(c: &dyn BreakerCellAccess) {
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

    /// OWNER-CHECKED probe release: the same revert as [`cell_release_probe`], but a strict NO-OP
    /// unless `owned_epoch` still equals the cell's current `probe_epoch`. This closes the stalled-
    /// release duplication (P2 finding #4): a `ProbeGuard` can outlive its acquisition across the
    /// permit-wait await, so it may drop LATE - after the cell already recorded an outcome (advancing
    /// past the probe) and a NEW probe was won (bumping the epoch). The un-owned `cell_release_probe`
    /// would then CAS the FRESH winner's HalfOpen back to Open and clear its `probe_in_flight`, letting
    /// a third caller win a duplicate concurrent probe on an already-probing lane. Checking the epoch
    /// under the transition lock - the epoch is bumped under the same lock in `cell_acquire_breaker` -
    /// makes a late release affect only the probe it actually won, and nothing once that probe is gone.
    pub(crate) fn cell_release_probe_owned(c: &dyn BreakerCellAccess, owned_epoch: u64) {
        let _tx = lock_recover(c.transition_lock());
        // Not (still) the owner: the probe we won has already been consumed/superseded. Do nothing -
        // reverting here would clobber whatever transition or newer probe now holds the cell.
        if c.probe_epoch().load(Ordering::Acquire) != owned_epoch {
            return;
        }
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
    pub(crate) fn cell_ready_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
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
    pub(crate) fn cell_acquire_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
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
                        // Won the single-flight probe: bump the owner-token epoch BEFORE publishing the
                        // in-flight flag. The winner will read `probe_epoch` (synchronously, before any
                        // await - the cell is HalfOpen so no peer can win a new probe in between) and
                        // pass it to `cell_release_probe_owned`, which reverts ONLY on an epoch match.
                        // Bumping under the transition lock keeps it paired with the state store.
                        c.probe_epoch().fetch_add(1, Ordering::AcqRel);
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
    pub(crate) fn cell_breaker_state(c: &dyn BreakerCellAccess) -> BreakerState {
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
    pub(crate) fn cell_record_failure(
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
    pub(crate) fn cell_record_success(c: &dyn BreakerCellAccess, now_time: u64) -> bool {
        // Serialize the whole state-dependent transition (the streak-reset gate reads the state, and
        // the HalfOpen→Closed recovery writes the (state, cooldown) pair) under the transition lock,
        // so a concurrent hard-down trip (Open + sticky cooldown) can't interleave its pair with this
        // recovery — the exact race this lock closes. `cell_closed` is reached via `cell_closed_locked`
        // below so we never re-take this std Mutex (deadlock). The outcome_window push is a leaf lock
        // taken under this one (consistent ordering, no other path takes them in the reverse order).
        let _tx = lock_recover(c.transition_lock());
        // Reset the consecutive-failure streak on a success — but NOT while the cell is Open. A bare
        // `record_success(lane)` can land on an Open cell via the degraded-forward path
        // (proxy engine `record_success` on a lane whose cell is still Open): the HalfOpen→Closed CAS
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
    pub(crate) fn open_state_with_retry_after(
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
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
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
    /// Operator-declared prompt-caching capability flag (see `ModelCfg::prompt_caching`).
    pub(crate) prompt_caching: bool,
}

/// Helper for weighted selection tests - creates a lane with specific weight.
#[cfg(test)]
pub(crate) fn make_lane_data_with_weight(id: usize, max_permits: usize) -> (LaneData, u32) {
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
        prompt_caching: false,
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
    pub(crate) fn now_secs() -> u64 {
        crate::store::now_for_test()
    }
    #[cfg(not(test))]
    pub(crate) fn now_secs() -> u64 {
        now()
    }

    /// Mutating admission check used on the dispatch path (sticky-affinity preference + the single
    /// lane SWRR selection returns): an expired-Open lane transitions to HalfOpen and the caller
    /// CAS-acquires the single-flight probe. Only ever called for a lane about to receive a request.
    pub(crate) fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        Self::cell_acquire_breaker(self.cell(pool, lane).as_ref(), now)
    }

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Shared
    /// body for both `is_ready` (test-gated) and `ready_in` (the non-test `StateStore` trait method,
    /// production-wired via `proxy::decide_policy_order`/`pick_among`), so it is production-live.
    pub(crate) fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        Self::cell_ready_breaker(self.cell(pool, lane).as_ref(), now)
    }

    /// Lane-global admission gates shared by both the mutating and read-only checks: a `dead` lane
    /// (administratively down) or an exhausted budget is never admissible regardless of breaker FSM.
    pub(crate) fn lane_admissible(&self, lane: usize) -> bool {
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
    pub(crate) fn breaker_state_for(&self, pool: &str, lane: usize) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        Self::cell_breaker_state(self.cell(pool, lane).as_ref())
    }

    pub(crate) fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
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
    pub(crate) fn lane_usable_any_cell(&self, lane: usize, now: u64) -> bool {
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
    pub(crate) fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
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
    pub(crate) fn lane_max_streak(&self, lane: usize) -> u32 {
        let mut worst = self.get_lane(lane).streak.load(Ordering::Relaxed);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            worst = worst.max(cell.streak().load(Ordering::Relaxed));
        }
        worst
    }

    /// Returns `true` iff this failure drove a Closed→Open trip on the (pool, lane) cell — threaded
    /// out so the proxy engine call site can emit `BREAKER_TRIPS_TOTAL` exactly once per logical trip.
    pub(crate) fn record_failure_for(
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
        // Genuine Closed→Open trip: bump the lane's MONOTONIC trip counter + stamp the epoch, at
        // the same seam that mints BREAKER_TRIPS_TOTAL — one logical trip, counted once (audit #5).
        if tripped {
            let ls = self.get_lane(lane);
            ls.trips.fetch_add(1, Ordering::Relaxed);
            ls.last_trip_at.store(now_time, Ordering::Relaxed);
        }
        tripped
    }

    pub(crate) fn record_success_for(&self, pool: &str, lane: usize) {
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
    pub(crate) fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
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

    pub(crate) fn select_weighted_for(
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

    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).probe_epoch().load(Ordering::Acquire)
    }

    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64) {
        Self::cell_release_probe_owned(self.cell(pool, lane).as_ref(), owned_epoch);
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
            trips: ls.trips.load(Ordering::Relaxed),
            last_trip_at: ls.last_trip_at.load(Ordering::Relaxed),
        }
    }

    fn restore_health(&self, restored: &[LaneHealthSnapshot]) {
        self.restore_health_impl(restored);
    }

    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(idx, ls)| {
                // Read (breaker_state, cooldown_until) as a CONSISTENT PAIR under a SINGLE hold of the
                // transition lock. They are two separate atomics that a trip/close/probe writes
                // together; a lock-free pair of loads can straddle a concurrent transition and observe
                // an INCONSISTENT pair (e.g. Open with a cleared/short cooldown), which this snapshot
                // then PERSISTS - on restore a hard-down lane would be revived as receiving traffic.
                // Holding the same lock the write path holds, for BOTH loads at once, makes the pair
                // move as a unit (P2 finding #5). Released immediately; the remaining fields are
                // independent counters with no cross-field invariant.
                let (breaker_state, cooldown_until) = {
                    let _tx = lock_recover(&ls.transition_lock);
                    (
                        ls.breaker_state.load(Ordering::Relaxed),
                        ls.cooldown_until.load(Ordering::Relaxed),
                    )
                };
                LaneHealthSnapshot {
                    model: ls.model.clone(),
                    provider: ls.provider.clone(),
                    budget: if ls.limited {
                        ls.budget.load(Ordering::Relaxed)
                    } else {
                        -1
                    },
                    breaker_state,
                    cooldown_until,
                    streak: ls.streak.load(Ordering::Relaxed),
                    dead: ls.dead.load(Ordering::Relaxed),
                    dead_reason: lock_recover(&ls.dead_reason).clone(),
                    ok: ls.ok.load(Ordering::Relaxed),
                    err: ls.err.load(Ordering::Relaxed),
                    client_fault: ls.client_fault.load(Ordering::Relaxed),
                    latency_ewma_bits: ls.latency_ewma_bits.load(Ordering::Relaxed),
                    trips: ls.trips.load(Ordering::Relaxed),
                    last_trip_at: ls.last_trip_at.load(Ordering::Relaxed),
                    cells: {
                        let map = self.pool_cells.read().unwrap_or_else(|e| e.into_inner());
                        map.get(&idx)
                            .map(|cells| {
                                cells
                                    .iter()
                                    .map(|(pool, cell)| {
                                        // Same consistent-pair read as the default cell above - the
                                        // per-pool cell's (state, cooldown) is written together under its
                                        // own transition lock, so snapshot both under one hold (P2 #5).
                                        let (breaker_state, cooldown_until) = {
                                            let _tx = lock_recover(&cell.transition_lock);
                                            (
                                                cell.breaker_state.load(Ordering::Relaxed),
                                                cell.cooldown_until.load(Ordering::Relaxed),
                                            )
                                        };
                                        PoolCellHealthSnapshot {
                                            pool: pool.to_string(),
                                            breaker_state,
                                            cooldown_until,
                                            streak: cell.streak.load(Ordering::Relaxed),
                                            err: cell.err.load(Ordering::Relaxed),
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    },
                }
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

    /// Drive the recovery-close gate (`cell_closed_if_recoverable`) directly against a named cell with
    /// an EXPLICIT `observed_cooldown`. This lets a regression test reproduce the #16 TOCTOU
    /// deterministically: pass the (smaller) cooldown a probe would have observed, after a concurrent
    /// hard-down has already re-armed the live cell to a stricter cooldown — exactly the interleaving
    /// where the old unconditional close clobbered the hard-down. Returns whether the cell was closed.
    pub(crate) fn recover_close_if_recoverable(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        observed: u64,
    ) -> bool {
        Self::cell_closed_if_recoverable(self.cell(pool, lane).as_ref(), now, observed)
    }

    /// Read a cell's raw `cooldown_until` (no `now` subtraction), for race-regression assertions.
    pub(crate) fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane)
            .cooldown_until()
            .load(Ordering::Acquire)
    }

    /// Park a named cell HalfOpen with the single-flight probe acquired and a STALE SWRR accumulator —
    /// the precondition under which a recorded success drives a HalfOpen→Closed recovery whose reset
    /// the caller is responsible for. Test-only setup for the LOW #19 regression.
    pub(crate) fn arm_half_open_stale_swrr(
        &self,
        pool: &str,
        lane: usize,
        cooldown: u64,
        stale_weight: i64,
    ) {
        let c = self.cell(pool, lane);
        c.current_weight().store(stale_weight, Ordering::Relaxed);
        c.cooldown_until().store(cooldown, Ordering::Relaxed);
        c.breaker_state().store(ST_HALF_OPEN, Ordering::Relaxed);
        c.probe_in_flight().store(true, Ordering::Relaxed);
    }

    /// Read a cell's raw SWRR `current_weight`, for the LOW #19 invariant assertion.
    pub(crate) fn cell_current_weight(&self, pool: &str, lane: usize) -> i64 {
        self.cell(pool, lane)
            .current_weight()
            .load(Ordering::Relaxed)
    }
}
