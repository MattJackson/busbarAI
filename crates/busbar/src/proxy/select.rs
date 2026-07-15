use super::*;

/// A compliance restrict captured on the PRIMARY pool that must persist across every failover hop —
/// including a `fallback_pool` spill to an independent pool. `tags_any` is the eligible tag set,
/// `on_empty` decides what happens when a hop's candidates carry none of them (fail-closed reject vs
/// advisory weighted-escape), and `name` is the gate name for logs/metrics.
#[derive(Debug, Clone)]
pub(crate) struct RestrictConstraint {
    pub(crate) tags_any: Vec<String>,
    pub(crate) on_empty: crate::config::PolicyOnError,
    pub(crate) name: &'static str,
}

/// Context for request lifecycle: deadline, accumulated exclusions, and visited pools.
#[derive(Debug, Clone)]
pub(crate) struct RequestCtx {
    /// Computed once at start; each hop checks remaining time against this.
    deadline: u64,
    /// Accumulated excluded lane indices across hops (already tried).
    pub(crate) excluded: std::collections::HashSet<usize>,
    /// Visited pool names for loop prevention in fallback chains (e.g., A→B→A).
    visited_pools: std::collections::HashSet<String>,
    /// Compliance restricts in force for this request (captured at the primary pool's gate
    /// reconcile). Re-applied on every downstream hop so a `Restrict` gate's "only these lanes,
    /// ever" guarantee holds across a `fallback_pool` spill — see [`RequestCtx::enforce_restricts`].
    pub(crate) active_restricts: Vec<RestrictConstraint>,
}

impl RequestCtx {
    pub(crate) fn new(deadline_secs: u64) -> Self {
        let start = now();
        Self {
            deadline: start.saturating_add(deadline_secs),
            excluded: std::collections::HashSet::new(),
            visited_pools: std::collections::HashSet::new(),
            active_restricts: Vec::new(),
        }
    }

    /// Re-apply the captured compliance restricts against a DOWNSTREAM pool's candidate set, keyed by
    /// THAT pool's own member tags (lane `idx` are global; `pool_runtime.members` is idx-keyed). The
    /// primary-pool gate reconcile shrinks `cands` in place, which keeps the restriction across
    /// in-pool failover — but a `fallback_pool` hop rebuilds candidates from an INDEPENDENT pool's
    /// full membership, so without re-applying here a compliance (e.g. BAA-only) restrict would be
    /// silently dropped at the pool boundary. Mirrors Reconcile-2 exactly: a `Weighted` on_empty is an
    /// advisory escape (skip this restrict on this hop); the fail-closed default returns `Err(name)`
    /// so the caller REJECTS rather than spilling to an ineligible lane. (found: audit c1r13.)
    pub(crate) fn enforce_restricts(
        &self,
        app: &App,
        pool_name: &str,
        cands: Vec<WeightedLane>,
    ) -> Result<Vec<WeightedLane>, &'static str> {
        let mut cands = cands;
        for r in &self.active_restricts {
            let members = app.pool_runtime.get(pool_name).map(|rt| &rt.members);
            let restricted: Vec<WeightedLane> = cands
                .iter()
                .filter(|wl| {
                    members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                        meta.tags.iter().any(|t| r.tags_any.iter().any(|w| w == t))
                    })
                })
                .cloned()
                .collect();
            if restricted.is_empty() {
                if matches!(r.on_empty, crate::config::PolicyOnError::Weighted) {
                    continue; // advisory escape — skip this restrict on this hop
                }
                return Err(r.name); // fail closed — no eligible lane satisfies a required restrict
            }
            cands = restricted;
        }
        Ok(cands)
    }

    /// Check if deadline has been exceeded.
    pub(crate) fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }

    /// Remaining time until deadline in seconds.
    pub(crate) fn remaining(&self, now: u64) -> u64 {
        self.deadline.saturating_sub(now)
    }

    /// Add a lane to the exclusion set (mark as already tried).
    pub(crate) fn exclude(&mut self, idx: usize) {
        self.excluded.insert(idx);
    }

    /// Fill `out` with candidates minus exclusions (clears `out` first).
    pub(crate) fn fill_candidates<'a>(
        &self,
        cands: &'a [WeightedLane],
        out: &mut Vec<&'a WeightedLane>,
    ) {
        out.clear();
        out.extend(cands.iter().filter(|wl| !self.excluded.contains(&wl.idx)));
    }

    /// Mark a pool as visited for loop prevention.
    pub(crate) fn mark_pool_visited(&mut self, pool_name: &str) {
        self.visited_pools.insert(pool_name.to_string());
    }

    /// Check if a pool has already been visited (loop detection).
    pub(crate) fn is_pool_visited(&self, pool_name: &str) -> bool {
        self.visited_pools.contains(pool_name)
    }
}

/// RAII release for a WON-but-UNDISPATCHED single-flight recovery probe.
///
/// Once `acquire_for_dispatch_in` wins the probe the cell is HalfOpen + `probe_in_flight == true`; the
/// flag is normally cleared only when a request records an outcome. Every path between winning the
/// probe and actually dispatching a request must release it, INCLUDING the implicit path where the
/// `pick_among` future is DROPPED (client disconnect) while parked at the `timeout(sem.acquire_owned())`
/// await — no early-return runs on drop, so without this guard the cell stays HalfOpen+probe_in_flight
/// and the lane is benched until the slow out-of-band prober resets it (the HIGH this fixes).
///
/// `Drop` calls the idempotent `release_probe_in` (CAS HalfOpen→Open + clear flag) while `armed`. The
/// two paths that hand a LIVE permit to a dispatched request DISARM the guard first, because the
/// dispatched request now owns the probe and releases it via its recorded outcome.
pub(crate) struct ProbeGuard<'a> {
    pub(crate) store: &'a dyn crate::store::StateStore,
    pub(crate) pool: &'a str,
    pub(crate) lane: usize,
    pub(crate) armed: bool,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.release_probe_in(self.pool, self.lane);
        }
    }
}

/// Pick a lane from `cands` using session affinity (if any) then weighted selection (SWRR) over
/// the healthy subset, returning the chosen lane index and its acquired concurrency permit.
/// `cands` is a `&[WeightedLane]` slice where each lane carries its configured weight.
/// `request_ctx` provides accumulated exclusions to avoid retrying failed lanes.
/// `affinity_key` enables sticky routing as a preference (not a hard constraint).
pub(crate) async fn pick_among(
    app: &Arc<App>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    affinity_key: Option<&str>,
    pool_name: &str,
    // The routing policy's ranked preference for this request, resolved ONCE before the failover loop
    // (see the ROUTING-POLICY SEAM in `forward_with_pool`). `None` is the ZERO-COST default: pure
    // SWRR, byte-identical to pre-feature behavior. `Some(order)` makes selection walk the ranked
    // lanes through the unchanged breaker filter instead of the blind SWRR pick (see SELECTION below).
    policy_order: Option<&[usize]>,
) -> Option<(usize, Permit)> {
    let t = now();

    // Session affinity preference - try sticky lane first if usable (in this pool's breaker view).
    // Uses a stable hash (NOT DefaultHasher, whose seed is randomized per process) so a session
    // pins to the same lane across restarts.
    if let Some(k) = affinity_key {
        if !cands.is_empty() {
            let pos = (stable_hash(k) as usize) % cands.len();
            let sticky = cands[pos].idx;

            // DRAIN (`weight: 0`): an operator weights a member to 0 to bleed it off before
            // decommission. SWRR (`select_weighted_for`) and the routing-policy preferred walk both
            // already exclude a 0-weight candidate; this sticky fast-path must too, else a session
            // whose hash lands on a drained-but-breaker-healthy member keeps pinning to it on the
            // NORMAL path — silently defeating drain. `usable_in`/`lane_admissible` only consult
            // dead/budget/breaker, never weight, so gate on the candidate's weight here.
            if cands[pos].weight != 0
                && !request_ctx.excluded.contains(&sticky)
                && app.store.usable_in(pool_name, sticky, t)
            {
                // CLASS GUARD (single-flight recovery probe), sticky fast path: `usable_in` →
                // `cell_acquire_breaker` transitions an expired-Open lane to HalfOpen and CAS-wins
                // the single-flight `probe_in_flight` flag as a SIDE EFFECT. If we then fail to get a
                // concurrency permit, NO request is dispatched on this lane, so neither
                // `record_success` (→ cell_closed) nor a failure (→ cell_open) ever runs to clear the
                // probe. Falling through to the SWRR loop without releasing it would leave the lane
                // wedged HalfOpen + probe_in_flight, benching it until the slow out-of-band prober
                // resets it — the SAME leak the main loop guards below. So: keep the probe only on the
                // dispatch (try_acquire success); release it on every other exit before falling through.
                if let Some(p) = app.store.try_acquire(sticky) {
                    return Some((sticky, p));
                } else {
                    app.store.release_probe_in(pool_name, sticky);
                }
            }
        }
    }

    // Filter out already-tried lanes (accumulated exclusions across hops). A locally-tracked
    // exclusion set lets us skip a lane we selected but couldn't probe-acquire (HalfOpen race),
    // without mutating the caller's RequestCtx for what is a within-pick retry.
    let mut local_excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // Hoisted out of the retry loop and pre-sized to the candidate count: the loop body re-runs on
    // every within-pick retry hop (HalfOpen-probe race), so reusing these buffers (`.clear()` +
    // re-`.extend()` each iteration) avoids both per-iteration allocation AND growth reallocation.
    // The filter can only DROP entries, so `cands.len()` is an upper bound (capacity, not fill);
    // selection semantics are unchanged. `filtered_cands` borrows `cands`, which outlives the loop.
    let mut filtered_cands: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    let mut candidates: Vec<usize> = Vec::with_capacity(cands.len());
    let mut weights: Vec<u32> = Vec::with_capacity(cands.len());

    loop {
        // Deadline guard: never spin or re-select past the request deadline.
        if request_ctx.expired(now()) {
            return None;
        }

        request_ctx.fill_candidates(cands, &mut filtered_cands);
        filtered_cands.retain(|wl| !local_excluded.contains(&wl.idx));
        if filtered_cands.is_empty() {
            return None;
        }

        // Extract lane indices and weights for select_weighted call
        candidates.clear();
        candidates.extend(filtered_cands.iter().map(|wl| wl.idx));
        weights.clear();
        weights.extend(filtered_cands.iter().map(|wl| wl.weight));

        // SELECTION. Two paths, and ONLY two:
        //
        //  • `policy_order == None` (the ZERO-COST DEFAULT, `route: weighted` / absent): byte-identical
        //    to pre-feature behavior — a single `select_weighted_in` call, the unchanged inline SWRR.
        //
        //  • `policy_order == Some(order)` (a routing policy returned `Prefer`): an ORDERED WALK.
        //    Honor EXACTLY the same health filter SWRR honors — `select_weighted_in` admits a candidate
        //    iff it is lane-admissible (not dead / in budget) AND its per-pool breaker cell is ready
        //    (the side-effect-FREE `ready_in`, the SAME predicate SWRR's filter uses). So: pick the
        //    FIRST lane in the policy's ranked `order` that is (a) still in this hop's candidate set
        //    (`candidates` is already exclusions- and local_excluded-filtered) and (b) `ready_in`. A
        //    preferred lane that is tripped / dead / excluded / at-capacity-by-breaker fails this check
        //    and we walk to the next. If NO ranked lane qualifies — every preferred lane is
        //    unhealthy/excluded, OR the policy ranked only a subset and those are exhausted — we fall
        //    THROUGH to `select_weighted_in` over the same candidate set, which both (i) preserves the
        //    contract's "an omitted/unranked candidate is lowest-priority but still REACHABLE, never
        //    stranded" guarantee, and (ii) keeps `Abstain` ⇒ today's SWRR exact (Abstain resolves to
        //    `policy_order == None`, so it never reaches this arm at all).
        //
        // The walk only ORDERS. It does NOT touch the breaker/probe/failover machinery: `ready_in` is
        // a read-only peek (no Open→HalfOpen transition, no single-flight probe CAS), and the SOLE
        // mutating admission — `acquire_for_dispatch_in` below — still runs EXACTLY ONCE on the chosen
        // lane, identically to the SWRR path. A preferred lane that then loses the HalfOpen probe race
        // is `local_excluded` + re-walked just like an SWRR pick, so it falls to the next preferred
        // lane (or to SWRR) with no change to breaker, failover, or translation behavior.
        let picked_lane_idx = match policy_order {
            Some(order) => {
                let now_t = now();
                // First ranked lane that is in this hop's candidate set, NOT drained, AND breaker-ready.
                //
                // C2 (weight:0 drain): SWRR's `select_weighted_in` skips `weight == 0` members (the
                // operator drain signal — see store.rs). The side-effect-free `ready_in` does NOT
                // check weight, so without this filter the ordered walk could rank a DRAINED lane #1
                // and dispatch to it, violating operator drain intent. Mirror SWRR here: a candidate
                // weighted to 0 is excluded from the preferred walk. It still falls through to
                // `select_weighted_in` below if no ranked lane qualifies — which itself re-skips
                // weight-0 — so a fully-drained candidate set strands nothing it shouldn't.
                let preferred = order.iter().copied().find(|idx| {
                    candidates
                        .iter()
                        .position(|c| c == idx)
                        .is_some_and(|pos| weights[pos] != 0)
                        && app.store.ready_in(pool_name, *idx, now_t)
                });
                match preferred {
                    Some(idx) => idx,
                    // No ranked lane qualifies: fall through to SWRR over the same candidates so an
                    // unranked-but-healthy lane is still reachable (never stranded by the policy).
                    None => {
                        match app
                            .store
                            .select_weighted_in(pool_name, &candidates, &weights, now_t)
                        {
                            Some(i) => i,
                            None => return None,
                        }
                    }
                }
            }
            // Zero-cost default: today's exact inline SWRR, one predictable branch.
            None => match app
                .store
                .select_weighted_in(pool_name, &candidates, &weights, now())
            {
                Some(i) => i,
                None => return None,
            },
        };

        // The dispatched lane does the breaker probe acquisition exactly once here (Open→HalfOpen
        // CAS). If it lost the single-flight probe race, drop it locally and re-select another lane.
        if !app
            .store
            .acquire_for_dispatch_in(pool_name, picked_lane_idx, now())
        {
            local_excluded.insert(picked_lane_idx);
            continue;
        }

        // CLASS GUARD (single-flight recovery probe): from here on we have WON the probe
        // (`acquire_for_dispatch_in` returned true, leaving the cell HalfOpen + `probe_in_flight ==
        // true`). The probe is normally released only when an outcome is recorded (`record_success`
        // → cell_closed, or a failure → cell_open). EVERY abandon of the probe below — explicit early
        // return OR an IMPLICIT future-drop while parked on the permit await — must release it, else
        // the flag stays `true`, the cell stays HalfOpen, and `usable_for` benches the lane until the
        // slow out-of-band prober resets it (the HIGH this fixes). `ProbeGuard` enforces that on Drop;
        // the only paths that legitimately keep the probe are the two that actually DISPATCH a request
        // (the immediate `try_acquire` hit and the `Ok(Ok(permit))` permit-wait success), which DISARM
        // the guard before returning the live permit — the dispatched request then owns the probe and
        // releases it via its recorded outcome.
        let mut probe_guard = ProbeGuard {
            store: app.store.as_ref(),
            pool: pool_name,
            lane: picked_lane_idx,
            armed: true,
        };

        // Try to acquire the concurrency permit immediately.
        if let Some(p) = app.store.try_acquire(picked_lane_idx) {
            // Live permit → dispatched request owns the probe; disarm so Drop is a no-op.
            probe_guard.armed = false;
            return Some((picked_lane_idx, p));
        }

        // Permits saturated: park (not busy-spin) until a slot frees OR the deadline passes. A
        // bounded `timeout` acquire yields the task efficiently and guarantees we never block past
        // the request deadline (unbounded spinning here was a head-of-line-blocking DoS surface).
        let remaining = request_ctx.remaining(now());
        if remaining == 0 {
            // Deadline already passed before we could even park — `probe_guard` drops here and
            // releases the won-but-undispatched probe so the lane stays re-probeable.
            return None;
        }
        let sem = app.store.lane_semaphore(picked_lane_idx);
        // If this future is DROPPED while parked on the await below (client disconnect), `probe_guard`
        // drops with it and releases the probe — the leak A1 fixes.
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(remaining),
            sem.acquire_owned(),
        )
        .await
        {
            // Got a permit before the deadline — a genuine dispatch; disarm the guard (the request
            // itself will record the success/failure that releases the probe).
            Ok(Ok(permit)) => {
                probe_guard.armed = false;
                return Some((picked_lane_idx, permit));
            }
            // Semaphore closed (shutdown) — no request dispatched; `probe_guard` drops and releases.
            Ok(Err(_)) => return None,
            // Deadline hit while waiting for a permit — no request dispatched; `probe_guard` drops and
            // releases so the recovered lane isn't permanently benched, then give up so the caller can
            // 503/failover.
            Err(_) => return None,
        }
    }
}

/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream). Both
/// must engage the streaming body path rather than being buffered.
pub(crate) fn is_streaming_content_type(ct: &str) -> bool {
    // Read the cached streaming-CT set instead of re-sweeping the registry per request: a CT is
    // "streaming" iff it is the streaming `Content-Type` of SOME registered protocol's writer (SSE
    // protocols → `text/event-stream`; Bedrock → `application/vnd.amazon.eventstream`). The cache
    // (`proto::streaming_content_types`) reads those MIMEs from the writer vtable, so naming no
    // protocol/MIME literal here keeps the agnostic core clean. The detected set is unchanged:
    // `text/event-stream` + `application/vnd.amazon.eventstream`.
    crate::proto::streaming_content_types()
        .iter()
        .any(|p| ct.starts_with(p))
}

/// The streaming `Content-Type` the INGRESS client expects, by ingress protocol. On a cross-protocol
/// reframe the streamed body is re-encoded into the client's framing, so the response header must
/// describe the CLIENT's wire format — copying the upstream CT verbatim would mislabel the body
/// (e.g. a Bedrock-egress `application/vnd.amazon.eventstream` reaching an SSE client, or vice
/// versa). Returns `None` for an unrecognized protocol name so the caller keeps the upstream CT
/// rather than guessing.
///
/// Dispatches through `ProtocolWriter::streaming_content_type` (SSE protocols → `text/event-stream`;
/// Bedrock → `application/vnd.amazon.eventstream`) so this function carries no `"bedrock"` branch —
/// the CT is a property of the writer vtable, not the name string.
pub(crate) fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    crate::proto::protocol_for(ingress).map(|p| p.writer().streaming_content_type())
}
