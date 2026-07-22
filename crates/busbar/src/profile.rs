// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fine-grained, ENV-GUARDED hot-path stage profiler — a permanent latency-regression tool.
//!
//! Answers the question "where does the per-request in-process time go — one fat stage or a thousand
//! small cuts?" at line/stage granularity, without perturbing the release hot path: every hook is a
//! single relaxed atomic-bool load ([`enabled`]) that is `false` (and branch-predicted away) unless
//! `BUSBAR_PROFILE` is set in the environment. Same opt-in pattern as `BUSBAR_CAPTURE_METRICS`.
//!
//! Usage on the hot path:
//! ```ignore
//! let _t = crate::profile::start(crate::profile::Stage::LanePick);
//! // ... work ...
//! drop(_t); // records elapsed nanos into the LanePick bucket (no-op when disabled)
//! ```
//! or the explicit form [`record`] when a scope guard doesn't fit (across `?`/early-return arms).
//!
//! At the end of a profiling run the driver (the `capture_latency_metrics` test) calls [`dump`],
//! which prints one `BUSBAR_PROFILE stage=<name> n=<count> mean=<us> p50=<us> p99=<us>` line per
//! stage that recorded at least one sample. Buckets accumulate across the whole run.
//!
//! Zero cost when unset: `enabled()` reads one `AtomicBool` initialized ONCE from the env; a disabled
//! `start`/`record` does nothing and allocates nothing. The buckets themselves are only ever touched
//! on the enabled path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// The hot-path stages attributed by the profiler. Ordering here is the report order. Keep this in
/// sync with the `start`/`record` call sites; a stage with no call site simply reports zero samples.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// `auth_middleware` pre-handler work: carrier token extract + chain/cache verdict + extension
    /// inserts (the span ends BEFORE `next.run`, so downstream time is not attributed here).
    MwAuth,
    /// Body already-parsed handling + candidate op-support filter + wants_stream/affinity derivation
    /// (the pre-dispatch bookkeeping in `forward_with_pool_parsed_inner` before the failover loop).
    Prepare,
    /// `pick_among`: session-affinity fast path + SWRR weighted selection + breaker probe + permit.
    LanePick,
    /// Per-hop request shaping: `translate_request_cross_protocol` (same-proto pristine short-circuit
    /// or cross-protocol IR translate + serialize).
    TranslateReq,
    /// Egress auth headers (bearer / SigV4) + URL/path build + `reqwest::RequestBuilder` construction.
    ClientBuild,
    /// Sub-stage of ClientBuild: `sign_and_wire_path_parts` + `lane_auth_headers` (auth String allocs
    /// + `HeaderValue::from_str`).
    CbAuth,
    /// Sub-stage of ClientBuild: `convert_headers` (HeaderMap rebuild) + the reqwest builder chain
    /// (`post(format!(url))`, `.headers()`, `.header()×3`, `.body()`).
    CbReqwest,
    /// `req.send().await` — the upstream round-trip to response headers (the mock upstream here).
    UpstreamSend,
    /// Post-2xx breaker/latency/budget bookkeeping (record_success/record_latency/spend_budget).
    RecordSuccess,
    /// Response body streaming setup: `FirstByteBody::new` + `into_body` + response builder + headers.
    RespBuild,
    /// Sub-stage of RespBuild: header/CT/relay-id capture + SSE detection + translate resolution
    /// (everything before `FirstByteBody::new`).
    RbPre,
    /// Sub-stage of RespBuild: `FirstByteBody::new` + `into_body` + the axum `Response::builder`
    /// chain + `maybe_attach_*` header calls + `.body()`.
    RbBody,
    /// The ingress `finish` boundary: metrics record + request-log gate + refund check.
    Finish,
}

impl Stage {
    /// Stable report name (also the `BUSBAR_PROFILE stage=` value). Used only by [`dump`] (the
    /// reporting half), which today runs from the `capture_latency_metrics` profiling driver.
    #[cfg_attr(not(test), allow(dead_code))]
    fn name(self) -> &'static str {
        match self {
            Stage::MwAuth => "mw_auth",
            Stage::Prepare => "prepare",
            Stage::LanePick => "lane_pick",
            Stage::TranslateReq => "translate_req",
            Stage::ClientBuild => "client_build",
            Stage::CbAuth => "  cb_auth",
            Stage::CbReqwest => "  cb_reqwest",
            Stage::UpstreamSend => "upstream_send",
            Stage::RecordSuccess => "record_success",
            Stage::RespBuild => "resp_build",
            Stage::RbPre => "  rb_pre",
            Stage::RbBody => "  rb_body",
            Stage::Finish => "finish",
        }
    }

    /// Dense bucket index, for the fixed-size bucket array.
    fn idx(self) -> usize {
        self as usize
    }
}

/// Number of `Stage` variants (the bucket-array length). Must equal the number of enum arms above.
const STAGE_COUNT: usize = 13;

/// Per-stage sample CAP. Buckets are bounded so a long-lived enabled binary cannot grow them without
/// limit (and re-sort an ever-larger `Vec` under the global `Mutex` on every [`dump`]). Once a bucket
/// is full, further samples are admitted by RESERVOIR sampling (see [`Bucket::record`]) so the retained
/// set stays a uniform sample of ALL observations — p50/p99 remain representative rather than being
/// biased toward the first N. 4096 u32s per stage is ~16 KiB/stage, ~208 KiB across all stages: plenty
/// for stable percentiles, trivially bounded memory. This is a dev-only tool; the cap is a safety net.
const BUCKET_CAP: usize = 4096;

/// One-shot env read: profiling is ON iff `BUSBAR_PROFILE` is present (any value) in the environment.
/// Read exactly once and cached in an `AtomicBool` so the hot-path check is a single relaxed load.
fn enabled_cell() -> &'static AtomicBool {
    static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
    ENABLED.get_or_init(|| AtomicBool::new(std::env::var_os("BUSBAR_PROFILE").is_some()))
}

/// True when stage profiling is enabled (a single relaxed atomic load on the hot path). `false`
/// unless `BUSBAR_PROFILE` was set in the environment at first check.
#[inline]
pub(crate) fn enabled() -> bool {
    enabled_cell().load(Ordering::Relaxed)
}

/// One stage's bounded sample store: up to [`BUCKET_CAP`] retained nanosecond durations plus a count
/// of ALL observations ever offered (`seen`). A `u32` holds up to ~4.29 s, far beyond any per-stage
/// in-process span. Bounding the retained `Vec` keeps memory and the per-[`dump`] sort cost fixed no
/// matter how long the (enabled) binary runs; `seen` drives the reservoir admission below.
#[derive(Default)]
struct Bucket {
    samples: Vec<u32>,
    /// Total number of samples ever offered to this bucket (NOT the retained length). Reported by
    /// [`dump`] as `n=` so the report still reflects the true observation count, and used as the
    /// running index for Algorithm-R reservoir replacement once the bucket is full.
    seen: u64,
}

impl Bucket {
    /// Admit one sample under a fixed [`BUCKET_CAP`] via Algorithm-R reservoir sampling: while below
    /// the cap, append; once full, replace a uniformly random existing slot with probability
    /// `cap / seen`. This keeps `samples` a uniform random subset of all observations, so p50/p99 stay
    /// representative rather than frozen to the first `cap` samples. No allocation once the cap is hit.
    fn record(&mut self, n: u32) {
        self.seen += 1;
        if self.samples.len() < BUCKET_CAP {
            self.samples.push(n);
            return;
        }
        // Full: replace slot j (0..seen) with prob cap/seen — i.e. keep only when j < cap.
        let j = next_rand() % self.seen;
        if let Some(slot) = usize::try_from(j)
            .ok()
            .and_then(|j| self.samples.get_mut(j))
        {
            *slot = n;
        }
    }
}

/// Cheap process-local xorshift64* PRNG for reservoir admission. Deterministic seed is fine: the goal
/// is a uniform sample, not cryptographic randomness, and this path is dev-only and single-purpose.
/// Behind the global bucket `Mutex` (record is the only caller), so the non-atomic state is safe.
fn next_rand() -> u64 {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    let mut s = STATE
        .get_or_init(|| Mutex::new(0x9E37_79B9_7F4A_7C15))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Per-stage sample store. Behind a single `Mutex` — the profiler is a single-threaded measurement
/// tool (the capture test drives one request at a time), so contention is nil; the lock is only ever
/// taken on the enabled path. Buckets are bounded (see [`BUCKET_CAP`]) so a long-running enabled
/// binary cannot grow them without limit.
fn buckets() -> &'static Mutex<Vec<Bucket>> {
    static BUCKETS: OnceLock<Mutex<Vec<Bucket>>> = OnceLock::new();
    BUCKETS.get_or_init(|| Mutex::new((0..STAGE_COUNT).map(|_| Bucket::default()).collect()))
}

/// Record `nanos` into `stage`'s bucket. No-op when profiling is disabled.
#[inline]
pub(crate) fn record(stage: Stage, nanos: u64) {
    if !enabled() {
        return;
    }
    let n = u32::try_from(nanos).unwrap_or(u32::MAX);
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());
    b[stage.idx()].record(n);
}

/// A running stage timer: records its elapsed time into `stage` when dropped. Cheap to construct even
/// when disabled (it still takes an `Instant`, but that path is never hit in a release build with the
/// env unset because the call sites gate construction on [`enabled`] — see the macro-free call
/// convention in the hot path). Prefer explicit [`record`] where a scope guard would span a `?`.
pub(crate) struct Timer {
    stage: Stage,
    start: Instant,
}

impl Timer {
    #[inline]
    fn new(stage: Stage) -> Self {
        Self {
            stage,
            start: Instant::now(),
        }
    }
}

impl Drop for Timer {
    #[inline]
    fn drop(&mut self) {
        record(self.stage, self.start.elapsed().as_nanos() as u64);
    }
}

/// Start a scoped [`Timer`] for `stage` — returns `Some(Timer)` only when profiling is enabled, so a
/// disabled run does not even take the `Instant`. Bind it to a `let _t = ...;` and let the scope end
/// (or `drop(_t)`) record the span.
#[inline]
pub(crate) fn start(stage: Stage) -> Option<Timer> {
    if enabled() {
        Some(Timer::new(stage))
    } else {
        None
    }
}

/// Print one `BUSBAR_PROFILE` line per stage that recorded samples, with count, mean, p50 and p99 in
/// microseconds. Called by the profiling driver at the end of a run. No-op (and clears nothing) when
/// disabled. Percentiles use nearest-rank on the sorted per-stage samples.
///
/// The reporting half of the profiler — invoked today from the `capture_latency_metrics` driver
/// (a `#[cfg(test)]` entry point); allowed dead in a non-test build so the tool stays permanently
/// available without a warning.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn dump() {
    if !enabled() {
        return;
    }
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());
    // Iterate in enum order for a stable, readable report.
    let stages = [
        Stage::MwAuth,
        Stage::Prepare,
        Stage::LanePick,
        Stage::TranslateReq,
        Stage::ClientBuild,
        Stage::CbAuth,
        Stage::CbReqwest,
        Stage::UpstreamSend,
        Stage::RecordSuccess,
        Stage::RespBuild,
        Stage::RbPre,
        Stage::RbBody,
        Stage::Finish,
    ];
    for stage in stages {
        let bucket = &mut b[stage.idx()];
        let samples = &mut bucket.samples;
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        // `retained` drives the percentile math; `seen` is the TRUE observation count reported as `n=`
        // (they diverge once the bucket saturates and reservoir sampling kicks in).
        let retained = samples.len();
        let seen = bucket.seen;
        let sum: u64 = samples.iter().map(|&x| x as u64).sum();
        let mean_us = (sum as f64 / retained as f64) / 1000.0;
        let pct = |p: f64| -> f64 {
            let i = (((retained - 1) as f64) * p).round() as usize;
            samples[i] as f64 / 1000.0
        };
        eprintln!(
            "BUSBAR_PROFILE stage={} n={} mean={:.3} p50={:.3} p99={:.3}",
            stage.name(),
            seen,
            mean_us,
            pct(0.50),
            pct(0.99),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_is_bounded_and_tracks_true_count() {
        // Offer far more samples than the cap; the retained set must never exceed BUCKET_CAP, but the
        // `seen` count must reflect EVERY observation (so the report's `n=` stays truthful).
        let mut b = Bucket::default();
        let offered = BUCKET_CAP * 4 + 123;
        for i in 0..offered {
            b.record(i as u32);
        }
        assert_eq!(
            b.samples.len(),
            BUCKET_CAP,
            "retained samples must be capped at BUCKET_CAP, not grow unbounded"
        );
        assert_eq!(
            b.seen, offered as u64,
            "seen must count all offered samples, not just the retained ones"
        );
    }

    #[test]
    fn bucket_under_cap_keeps_everything() {
        // Below the cap it behaves exactly like the old unbounded Vec: every sample retained, in order.
        let mut b = Bucket::default();
        for i in 0..10u32 {
            b.record(i);
        }
        assert_eq!(b.samples.len(), 10);
        assert_eq!(b.seen, 10);
        assert_eq!(b.samples, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn reservoir_stays_representative_of_the_range() {
        // Reservoir sampling keeps a uniform subset, so the retained min/max should still span most of
        // the offered range (a first-N cap would freeze the max near BUCKET_CAP). Feed a large ramp and
        // check the retained max lands in the upper reaches — a smoke test that late samples are admitted.
        let mut b = Bucket::default();
        let offered = BUCKET_CAP * 10;
        for i in 0..offered {
            b.record(i as u32);
        }
        let max = *b.samples.iter().max().unwrap();
        assert!(
            max as usize > offered / 2,
            "reservoir must admit late/high samples (max {max} should exceed half of {offered}); a \
             first-N cap would freeze the retained max near BUCKET_CAP"
        );
    }
}
