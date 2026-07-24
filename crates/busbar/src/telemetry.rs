// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TELEMETRY BANK — per-thread metric cells for the request hot path, one scrape-time
//! aggregator.
//!
//! ## Why this layer exists
//!
//! The request hot path used to update ~26 Prometheus metric sites through the `metrics` facade
//! macros. Every one of those is a shared atomic in the global recorder's registry: at high RPS on
//! many cores the increments ping-pong the metric cache lines between cores, and that contention
//! measurably caps throughput (part of a measured −36% collapse from concurrency 64→1024). The fix
//! is ONE proper layer, not N ad-hoc thread-local hacks:
//!
//! * **Per-thread bank** — each thread that emits owns a private block of pre-registered slots. A
//!   hot-path write is a plain add into the thread's OWN cell: the cells are `AtomicU64` with
//!   `Relaxed` ordering, but only the OWNING thread ever writes them (owner-writes-only), so in
//!   steady state the cache line stays exclusive to its core. The atomic type exists purely so the
//!   aggregator can READ other threads' cells safely during a concurrent scrape.
//! * **Slot registration once per config generation** — label combinations are bounded (pools and
//!   models come from config; outcomes/protocols/dispositions are fixed vocabularies), so slots are
//!   interned ONCE when an `App` snapshot is built ([`AppSlots::build`]) and the hot path holds a
//!   plain slot index. It never allocates and never builds a `metrics::Key`/label map. Re-applying a
//!   config re-interns the same label sets to the SAME slots, so counts accumulate monotonically
//!   across generations.
//! * **One aggregator** — [`flush_to_recorder`] runs at scrape time (called from
//!   `metrics::render()`): it sums every thread's cells per slot and pushes the DELTA since the last
//!   flush into the process-global `metrics-exporter-prometheus` recorder. The exposition is
//!   rendered by the SAME recorder as before, so metric names, labels, HELP/TYPE lines, and
//!   formatting are byte-identical to the pre-bank output. Histogram slots buffer raw samples
//!   per thread and drain them into the recorder at flush, so the summary/quantile rendering is
//!   unchanged too (samples are just delivered at scrape time instead of request time).
//!
//! ## THE RULE — observation only
//!
//! If ENFORCEMENT depends on a count, it does NOT go through the bank. Budget cells, `max_concurrent`
//! permits, rate windows, breaker failure counters — anything a decision reads — counts inline where
//! the decision is made. The bank's cells are eventually-consistent by design (a thread's adds are
//! only globally visible at the next scrape), which is exactly right for OBSERVATION and exactly
//! wrong for enforcement. Adding a new observability counter tomorrow = registering a slot here; a
//! new enforcement counter never touches this module.
//!
//! ## What stays on the plain `metrics` macros
//!
//! Cold-path and boot-path metrics keep the macro emission (migrating them is churn without
//! benefit — they fire far off the steady-state request path or with runtime-resolved label
//! vocabularies the config-time registration can't enumerate):
//! * route-policy selection/rejection counters (`policy` can be an operator-defined hook name
//!   resolved at hook-fire time; rejections additionally carry a dynamic clamped `status`),
//! * webhook / tap backpressure drop counters (global anomaly signals),
//! * the billing-truncation counter (anomaly path),
//! * every scrape-time gauge in `metrics.rs` (they are already scrape-driven).
//!
//! [`AppSlots`] lookups fall back to the identical macro emission whenever a label value is not in
//! the current generation's registered set (e.g. a custom ingress protocol, or unit tests driving a
//! bare `App`), so output is preserved in every case — the bank is a fast path, never a gate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::state::{App, Lane, WeightedLane};

// ── Capacity ─────────────────────────────────────────────────────────────────────────────────────
//
// Slots are process-lifetime (the intern table is append-only; identical label sets re-registered by
// a later config generation reuse their slot). Per-thread storage is CHUNKED and lazily allocated:
// a thread only materializes the 8 KiB counter chunk / sample-buffer chunk that one of its slots
// actually lands in, so a mostly-idle thread costs almost nothing. The caps below are far beyond any
// real deployment (a pool contributes ~40 counter slots + ~6 histogram slots); if the table ever
// fills — e.g. a pathological test suite churning thousands of distinct pool names — registration
// degrades gracefully: it returns an INVALID slot and the emit helpers fall back to the macros.
const COUNTER_CHUNK: usize = 1024;
const COUNTER_CHUNKS: usize = 64; // 65,536 counter slots
const HIST_CHUNK: usize = 256;
const HIST_CHUNKS: usize = 32; // 8,192 histogram slots
/// A per-thread histogram buffer that grows past this many samples between scrapes drains straight
/// into the recorder (the old contended path) rather than growing without bound — correctness is
/// preserved and the cost is amortized 1/N. Only reachable when scrapes stop while traffic doesn't.
const HIST_DRAIN_THRESHOLD: usize = 65_536;

/// Joins label values into the intern key — a control byte that cannot occur in a metric name,
/// label key, or any of the (operator-bounded) label values, so the join is unambiguous.
const KEY_SEP: char = '\u{1f}';

// ── Fixed label vocabularies (indices into the per-family slot arrays) ──────────────────────────

/// `outcome` values on `busbar_requests_total`, exactly as `ingress::finish_inner` classifies them.
pub(crate) const OUTCOMES: [&str; 4] = ["ok", "exhausted", "client_error", "error"];
/// `disposition` values on `busbar_upstream_failures_total` (see `proxy::DISPOSITION_*`).
pub(crate) const DISPOSITIONS: [&str; 4] = [
    crate::proxy::DISPOSITION_TRANSIENT,
    crate::proxy::DISPOSITION_ATTEMPT_TIMEOUT,
    crate::proxy::DISPOSITION_HARD_DOWN,
    crate::proxy::DISPOSITION_CONTEXT_LENGTH,
];
/// `reason` values on `busbar_failovers_total`: the dispositions plus the transport error classes
/// the pre-response failure arm records (`proxy::ERR_NET_CONNECT` / `ERR_NET_TIMEOUT`).
pub(crate) const REASONS: [&str; 6] = [
    crate::proxy::DISPOSITION_TRANSIENT,
    crate::proxy::DISPOSITION_ATTEMPT_TIMEOUT,
    crate::proxy::DISPOSITION_HARD_DOWN,
    crate::proxy::DISPOSITION_CONTEXT_LENGTH,
    crate::proxy::ERR_NET_CONNECT,
    crate::proxy::ERR_NET_TIMEOUT,
];

// ── Slot handles ─────────────────────────────────────────────────────────────────────────────────

/// A registered counter cell. `Copy` — the hot path holds and passes these by value. An INVALID
/// slot (registration hit the capacity cap) drops adds; the emit helpers check [`is_valid`] first
/// and fall back to the macro path so no observation is lost.
///
/// [`is_valid`]: CounterSlot::is_valid
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CounterSlot(u32);

/// A registered histogram slot (a per-thread raw-sample buffer, drained at scrape). Same validity
/// contract as [`CounterSlot`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct HistogramSlot(u32);

impl CounterSlot {
    pub(crate) const INVALID: CounterSlot = CounterSlot(u32::MAX);

    pub(crate) fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }

    /// Owner-writes-only add into THIS thread's cell. Relaxed load+store (not `fetch_add`) is
    /// sufficient and cheapest: the owning thread is the only writer, the atomic type only makes the
    /// aggregator's concurrent reads defined. No-op for INVALID slots and during TLS teardown.
    pub(crate) fn add(self, n: u64) {
        if !self.is_valid() {
            return;
        }
        let idx = self.0 as usize;
        // `try_with`: an emission from a destructor after the thread's bank was torn down is
        // dropped rather than panicking — the bank is observation-only (THE RULE), so a lost
        // observation on thread death is acceptable where a panic is not.
        let _ = BANK.try_with(|bank| {
            let chunk = bank.counters[idx / COUNTER_CHUNK].get_or_init(new_counter_chunk);
            let cell = &chunk[idx % COUNTER_CHUNK];
            cell.store(
                cell.load(Ordering::Relaxed).wrapping_add(n),
                Ordering::Relaxed,
            );
        });
    }

    pub(crate) fn incr(self) {
        self.add(1);
    }
}

impl HistogramSlot {
    pub(crate) const INVALID: HistogramSlot = HistogramSlot(u32::MAX);

    pub(crate) fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }

    /// Buffer one observation in THIS thread's sample vector. The mutex is uncontended in steady
    /// state (the aggregator takes it only during a scrape drain, and no other thread ever touches
    /// it), so the lock is a single uncontended CAS on a cache line this core owns.
    pub(crate) fn record(self, value: f64) {
        if !self.is_valid() {
            return;
        }
        let idx = self.0 as usize;
        let _ = BANK.try_with(|bank| {
            let chunk = bank.hists[idx / HIST_CHUNK].get_or_init(new_hist_chunk);
            let mut buf = chunk[idx % HIST_CHUNK]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            buf.push(value);
            if buf.len() >= HIST_DRAIN_THRESHOLD {
                // Scrapes have stopped but traffic hasn't: drain through the recorder inline
                // (bounded memory beats bank locality when nobody is scraping).
                let samples = std::mem::take(&mut *buf);
                drop(buf);
                drain_hist_overflow(self.0, samples);
            }
        });
    }
}

// ── Per-thread bank ──────────────────────────────────────────────────────────────────────────────

/// One lazily-allocated block of per-thread histogram sample buffers (see `ThreadBank::hists`).
type HistChunk = Box<[Mutex<Vec<f64>>]>;

struct ThreadBank {
    counters: [OnceLock<Box<[AtomicU64]>>; COUNTER_CHUNKS],
    hists: [OnceLock<HistChunk>; HIST_CHUNKS],
}

fn new_counter_chunk() -> Box<[AtomicU64]> {
    (0..COUNTER_CHUNK).map(|_| AtomicU64::new(0)).collect()
}

fn new_hist_chunk() -> HistChunk {
    (0..HIST_CHUNK).map(|_| Mutex::new(Vec::new())).collect()
}

impl ThreadBank {
    fn new() -> Self {
        ThreadBank {
            counters: std::array::from_fn(|_| OnceLock::new()),
            hists: std::array::from_fn(|_| OnceLock::new()),
        }
    }
}

thread_local! {
    /// This thread's bank. Created on first emission; the registry keeps a second `Arc` so the
    /// aggregator can keep summing a dead thread's final totals (counters are cumulative — dropping
    /// a dead thread's cells would make the exposed totals REGRESS, which Prometheus rejects).
    static BANK: Arc<ThreadBank> = {
        let bank = Arc::new(ThreadBank::new());
        registry()
            .threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(bank.clone());
        bank
    };
}

// ── Global registry (intern table + thread list + aggregator state) ─────────────────────────────

struct SlotDesc<H> {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    /// The recorder handle, minted LAZILY at first flush — never before the recorder is installed
    /// (a handle minted against the pre-install no-op recorder would be bound to it forever).
    handle: OnceLock<H>,
    /// Counters only: the total already pushed into the recorder. Guarded by `flush_lock` (single
    /// writer); atomic so the cold-path reader needs no lock.
    flushed: AtomicU64,
}

struct SlotTable<H> {
    index: Mutex<HashMap<String, u32>>,
    descs: RwLock<Vec<Arc<SlotDesc<H>>>>,
}

impl<H> SlotTable<H> {
    fn new() -> Self {
        SlotTable {
            index: Mutex::new(HashMap::new()),
            descs: RwLock::new(Vec::new()),
        }
    }

    /// Intern `(name, labels)` → slot id. Identical label sets always resolve to the SAME slot, so
    /// re-registration across config generations accumulates into the same cells. Returns `None`
    /// at the capacity cap (`max`), after which callers degrade to the macro path.
    fn intern(
        &self,
        name: &'static str,
        labels: &[(&'static str, &str)],
        max: usize,
    ) -> Option<u32> {
        let mut key = String::with_capacity(name.len() + labels.len() * 16);
        key.push_str(name);
        for (k, v) in labels {
            key.push(KEY_SEP);
            key.push_str(k);
            key.push(KEY_SEP);
            key.push_str(v);
        }
        let mut index = self.index.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(&id) = index.get(key.as_str()) {
            return Some(id);
        }
        let mut descs = self.descs.write().unwrap_or_else(|p| p.into_inner());
        if descs.len() >= max {
            // Warn once per table, not per registration — the fallback path is correct, just slower.
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    metric = name,
                    cap = max,
                    "telemetry bank slot table full; further label sets fall back to the metrics macros"
                );
            }
            return None;
        }
        let id = descs.len() as u32;
        descs.push(Arc::new(SlotDesc {
            name,
            labels: labels.iter().map(|(k, v)| (*k, (*v).to_string())).collect(),
            handle: OnceLock::new(),
            flushed: AtomicU64::new(0),
        }));
        index.insert(key, id);
        Some(id)
    }
}

struct Registry {
    counters: SlotTable<metrics::Counter>,
    hists: SlotTable<metrics::Histogram>,
    threads: Mutex<Vec<Arc<ThreadBank>>>,
    /// Serializes flushes so the read-sum / delta-increment / store-flushed sequence is atomic per
    /// slot (two concurrent scrapes must not double-count a delta).
    flush_lock: Mutex<()>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        counters: SlotTable::new(),
        hists: SlotTable::new(),
        threads: Mutex::new(Vec::new()),
        flush_lock: Mutex::new(()),
    })
}

/// Register (or re-resolve) a counter slot for a bounded label set. Registration-time only — the
/// hot path holds the returned slot. Label VALUES must come from operator-bounded vocabularies
/// (the same cardinality contract as `metrics.rs`).
pub(crate) fn counter_slot(name: &'static str, labels: &[(&'static str, &str)]) -> CounterSlot {
    match registry()
        .counters
        .intern(name, labels, COUNTER_CHUNK * COUNTER_CHUNKS)
    {
        Some(id) => CounterSlot(id),
        None => CounterSlot::INVALID,
    }
}

/// Register (or re-resolve) a histogram slot. Same contract as [`counter_slot`].
pub(crate) fn histogram_slot(name: &'static str, labels: &[(&'static str, &str)]) -> HistogramSlot {
    match registry()
        .hists
        .intern(name, labels, HIST_CHUNK * HIST_CHUNKS)
    {
        Some(id) => HistogramSlot(id),
        None => HistogramSlot::INVALID,
    }
}

// ── Aggregator ───────────────────────────────────────────────────────────────────────────────────

/// Metric metadata for handles minted outside the `metrics` macros (the macros bake an equivalent
/// static). Target/module only affect recorder-side filtering, which the Prometheus exporter
/// ignores, so one shared value serves every slot.
static METADATA: metrics::Metadata<'static> =
    metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!()));

fn mint_counter(desc: &SlotDesc<metrics::Counter>) -> metrics::Counter {
    let labels: Vec<metrics::Label> = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()))
        .collect();
    let key = metrics::Key::from_parts(desc.name, labels);
    metrics::with_recorder(|r| r.register_counter(&key, &METADATA))
}

fn mint_histogram(desc: &SlotDesc<metrics::Histogram>) -> metrics::Histogram {
    let labels: Vec<metrics::Label> = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()))
        .collect();
    let key = metrics::Key::from_parts(desc.name, labels);
    metrics::with_recorder(|r| r.register_histogram(&key, &METADATA))
}

/// Overflow drain for a histogram buffer that outgrew [`HIST_DRAIN_THRESHOLD`]: push the samples
/// through the recorder handle directly. Pre-install the recorder is a no-op sink (matching the
/// macro behavior in the same situation), so the samples are dropped rather than hoarded.
fn drain_hist_overflow(slot: u32, samples: Vec<f64>) {
    if !crate::metrics::recorder_installed() {
        return;
    }
    let desc = {
        let descs = registry()
            .hists
            .descs
            .read()
            .unwrap_or_else(|p| p.into_inner());
        match descs.get(slot as usize) {
            Some(d) => d.clone(),
            None => return,
        }
    };
    let handle = desc.handle.get_or_init(|| mint_histogram(&desc));
    for s in samples {
        handle.record(s);
    }
}

/// THE aggregator: sum every thread's cells per slot and push the delta since the last flush into
/// the process-global Prometheus recorder. Called from `metrics::render()` so every scrape (and
/// every test that reads the exposition) observes up-to-date bank totals. Deltas (not absolutes)
/// so banked series compose additively with anything the macro fallback paths emitted on the same
/// series. No-op until the recorder is installed — a handle minted before install would bind to
/// the no-op recorder forever (same contract as the handle cache in `metrics.rs`).
pub(crate) fn flush_to_recorder() {
    if !crate::metrics::recorder_installed() {
        return;
    }
    let reg = registry();
    let _guard = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());
    let threads: Vec<Arc<ThreadBank>> = reg
        .threads
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();

    // Counters: sum → delta → increment. A slot whose lifetime total is still zero is SKIPPED
    // (no handle minted), so registering slots does not surface zero-valued series that the macro
    // world would not have shown until first increment — /metrics output stays identical.
    let counter_descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in counter_descs.iter().enumerate() {
        let (chunk_i, off) = (i / COUNTER_CHUNK, i % COUNTER_CHUNK);
        let mut sum: u64 = 0;
        for bank in &threads {
            if let Some(chunk) = bank.counters[chunk_i].get() {
                sum = sum.wrapping_add(chunk[off].load(Ordering::Relaxed));
            }
        }
        let prev = desc.flushed.load(Ordering::Relaxed);
        if sum > prev {
            let handle = desc.handle.get_or_init(|| mint_counter(desc));
            handle.increment(sum - prev);
            desc.flushed.store(sum, Ordering::Relaxed);
        }
    }
    drop(counter_descs);

    // Histograms: drain each thread's sample buffer into the recorder. The recorder's own
    // summary/histogram machinery then renders exactly what per-request `record()` calls would
    // have produced — samples are merely delivered at scrape time instead of request time.
    let hist_descs = reg.hists.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in hist_descs.iter().enumerate() {
        let (chunk_i, off) = (i / HIST_CHUNK, i % HIST_CHUNK);
        for bank in &threads {
            let Some(chunk) = bank.hists[chunk_i].get() else {
                continue;
            };
            let samples = {
                let mut buf = chunk[off].lock().unwrap_or_else(|p| p.into_inner());
                if buf.is_empty() {
                    continue;
                }
                std::mem::take(&mut *buf)
            };
            let handle = desc.handle.get_or_init(|| mint_histogram(desc));
            for s in samples {
                handle.record(s);
            }
        }
    }
}

// ── Per-App slot tables (registered once per config generation) ─────────────────────────────────

/// The banked slots for one request family: `busbar_requests_total` (per outcome) and
/// `busbar_request_duration_seconds`, for a fixed `(ingress_protocol, pool)` pair.
#[derive(Clone, Copy)]
struct RequestFamily {
    requests: [CounterSlot; OUTCOMES.len()],
    duration: HistogramSlot,
}

/// The banked slots for one `(pool label, lane)` pair on the upstream walk:
/// attempts, per-disposition failures, and breaker trips.
#[derive(Clone, Copy)]
struct LaneFamily {
    attempts: CounterSlot,
    failures: [CounterSlot; DISPOSITIONS.len()],
    trips: CounterSlot,
}

/// All hot-path metric slots for ONE `App` snapshot, resolved at config load (`App` construction)
/// so the request path never interns, allocates, or touches the recorder registry. Lookups are
/// read-only probes into maps owned by the (immutable) `App` — no shared-cache-line writes.
///
/// Every lookup method returns the slots for values in THIS generation's bounded label space; a
/// miss (custom protocol, label from a different generation, bare test `App`) falls back to the
/// exact macro emission the site used before the bank, so `/metrics` output is preserved always.
pub(crate) struct AppSlots {
    /// pool label (ingress convention: pools ∪ models ∪ "unresolved") → per-protocol request
    /// families, indexed by position in `proto::KNOWN_PROTOCOLS`.
    request: HashMap<Box<str>, Box<[RequestFamily]>>,
    /// engine pool label (pools ∪ models, matching `proxy::metric_pool_label`) → lane idx → family.
    lane: HashMap<Box<str>, HashMap<usize, LaneFamily>>,
    /// engine pool label → failover-reason slots, indexed by position in [`REASONS`].
    failover: HashMap<Box<str>, [CounterSlot; REASONS.len()]>,
}

impl AppSlots {
    /// Register every hot-path slot for one config generation. Label spaces registered here are
    /// exactly the bounded sets the emission sites can produce: configured pool names, configured
    /// lane MODEL strings, the `"unresolved"` sentinel, and the fixed vocabularies above.
    pub(crate) fn build(
        lanes: &[Lane],
        pools: &HashMap<String, Vec<WeightedLane>>,
        by_model: &HashMap<String, usize>,
    ) -> AppSlots {
        use crate::metrics::{
            BREAKER_TRIPS_TOTAL, FAILOVERS_TOTAL, REQUESTS_TOTAL, REQUEST_DURATION_SECONDS,
            UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL,
        };

        // Ingress pool labels: configured pools, model-routed labels, and the pre-routing sentinel.
        let mut ingress_labels: Vec<&str> = pools.keys().map(String::as_str).collect();
        ingress_labels.extend(by_model.keys().map(String::as_str));
        ingress_labels.push(crate::proxy::POOL_LABEL_UNRESOLVED);
        ingress_labels.sort_unstable();
        ingress_labels.dedup();

        let mut request = HashMap::with_capacity(ingress_labels.len());
        for pool in &ingress_labels {
            let families: Box<[RequestFamily]> = crate::proto::KNOWN_PROTOCOLS
                .iter()
                .map(|proto| RequestFamily {
                    requests: std::array::from_fn(|oi| {
                        counter_slot(
                            REQUESTS_TOTAL,
                            &[
                                ("ingress_protocol", proto),
                                ("pool", pool),
                                ("outcome", OUTCOMES[oi]),
                            ],
                        )
                    }),
                    duration: histogram_slot(
                        REQUEST_DURATION_SECONDS,
                        &[("ingress_protocol", proto), ("pool", pool)],
                    ),
                })
                .collect();
            request.insert(Box::from(*pool), families);
        }

        // Engine labels: named pools walk their members; model-routed traffic is labeled by the
        // lane's model string (`metric_pool_label` resolves the empty cell key to the model).
        let mut lane_map: HashMap<Box<str>, HashMap<usize, LaneFamily>> = HashMap::new();
        let mut engine_labels: Vec<(&str, Vec<usize>)> = Vec::new();
        for (pool, members) in pools {
            engine_labels.push((pool.as_str(), members.iter().map(|wl| wl.idx).collect()));
        }
        for (model, &idx) in by_model {
            engine_labels.push((model.as_str(), vec![idx]));
        }

        let mut failover = HashMap::with_capacity(engine_labels.len());
        for (pool, member_idxs) in &engine_labels {
            let mut per_lane = HashMap::with_capacity(member_idxs.len());
            for &idx in member_idxs {
                let Some(lane) = lanes.get(idx) else { continue };
                let lane_label = lane.model.as_str();
                per_lane.insert(
                    idx,
                    LaneFamily {
                        attempts: counter_slot(
                            UPSTREAM_ATTEMPTS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                        failures: std::array::from_fn(|di| {
                            counter_slot(
                                UPSTREAM_FAILURES_TOTAL,
                                &[
                                    ("pool", pool),
                                    ("lane", lane_label),
                                    ("disposition", DISPOSITIONS[di]),
                                ],
                            )
                        }),
                        trips: counter_slot(
                            BREAKER_TRIPS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                    },
                );
            }
            lane_map
                .entry(Box::from(*pool))
                .or_default()
                .extend(per_lane);
            failover.entry(Box::from(*pool)).or_insert_with(|| {
                std::array::from_fn(|ri| {
                    counter_slot(FAILOVERS_TOTAL, &[("pool", pool), ("reason", REASONS[ri])])
                })
            });
        }

        AppSlots {
            request,
            lane: lane_map,
            failover,
        }
    }

    fn request_family(&self, ingress_protocol: &str, pool: &str) -> Option<&RequestFamily> {
        let proto_idx = crate::proto::KNOWN_PROTOCOLS
            .iter()
            .position(|p| *p == ingress_protocol)?;
        self.request.get(pool).map(|fams| &fams[proto_idx])
    }

    fn lane_family(&self, pool_label: &str, lane_idx: usize) -> Option<&LaneFamily> {
        self.lane.get(pool_label)?.get(&lane_idx)
    }
}

// ── Hot-path emit helpers (bank fast path, macro fallback) ──────────────────────────────────────

/// `busbar_requests_total` + `busbar_request_duration_seconds` for one finished request. Bank fast
/// path when `(ingress_protocol, pool)` is in this generation's registered set; otherwise the
/// pre-existing cached-handle helpers in `metrics.rs` (byte-identical series either way).
pub(crate) fn request_finished(
    app: &App,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
    seconds: f64,
) {
    let fam = app.tslots.request_family(ingress_protocol, pool);
    let outcome_idx = OUTCOMES.iter().position(|o| *o == outcome);
    match (fam, outcome_idx) {
        (Some(fam), Some(oi)) if fam.requests[oi].is_valid() => fam.requests[oi].incr(),
        _ => crate::metrics::incr_requests_total(ingress_protocol, pool, outcome),
    }
    match fam {
        Some(fam) if fam.duration.is_valid() => fam.duration.record(seconds),
        _ => crate::metrics::record_request_duration(ingress_protocol, pool, seconds),
    }
}

/// `busbar_upstream_attempts_total` for one dispatch attempt on `(pool label, lane)`.
pub(crate) fn upstream_attempt(app: &App, pool_label: &str, lane_idx: usize) {
    match app.tslots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.attempts.is_valid() => fam.attempts.incr(),
        _ => metrics::counter!(
            crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
            "pool" => pool_label.to_owned(),
            "lane" => app.lanes[lane_idx].model.clone()
        )
        .increment(1),
    }
}

/// `busbar_upstream_failures_total` for one classified failure on `(pool label, lane)`.
pub(crate) fn upstream_failure(
    app: &App,
    pool_label: &str,
    lane_idx: usize,
    disposition: &'static str,
) {
    let fam = app.tslots.lane_family(pool_label, lane_idx);
    let di = DISPOSITIONS.iter().position(|d| *d == disposition);
    match (fam, di) {
        (Some(fam), Some(di)) if fam.failures[di].is_valid() => fam.failures[di].incr(),
        _ => metrics::counter!(
            crate::metrics::UPSTREAM_FAILURES_TOTAL,
            "pool" => pool_label.to_owned(),
            "lane" => app.lanes[lane_idx].model.clone(),
            "disposition" => disposition
        )
        .increment(1),
    }
}

/// `busbar_breaker_trips_total` for one logical Closed→Open trip on `(pool label, lane)`.
pub(crate) fn breaker_trip(app: &App, pool_label: &str, lane_idx: usize) {
    match app.tslots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.trips.is_valid() => fam.trips.incr(),
        _ => metrics::counter!(
            crate::metrics::BREAKER_TRIPS_TOTAL,
            "pool" => pool_label.to_owned(),
            "lane" => app.lanes[lane_idx].model.clone()
        )
        .increment(1),
    }
}

/// `busbar_failovers_total` for one failover event on `pool label`, by reason.
pub(crate) fn failover(app: &App, pool_label: &str, reason: &'static str) {
    let slots = app.tslots.failover.get(pool_label);
    let ri = REASONS.iter().position(|r| *r == reason);
    match (slots, ri) {
        (Some(slots), Some(ri)) if slots[ri].is_valid() => slots[ri].incr(),
        _ => metrics::counter!(
            crate::metrics::FAILOVERS_TOTAL,
            "pool" => pool_label.to_owned(),
            "reason" => reason
        )
        .increment(1),
    }
}

/// `busbar_translations_total` for one cross-protocol hop. Both names come from the fixed protocol
/// vocabulary, so the slots are config-independent: one process-lifetime table over
/// `KNOWN_PROTOCOLS × KNOWN_PROTOCOLS` (from ≠ to), resolved by a short linear scan (≤30 static-str
/// compares — no hash, no allocation). Unknown (plugin) protocol names fall back to the macro.
pub(crate) fn translation(from: &str, to: &str) {
    static SLOTS: OnceLock<Vec<(&'static str, &'static str, CounterSlot)>> = OnceLock::new();
    let table = SLOTS.get_or_init(|| {
        let mut v = Vec::new();
        for f in crate::proto::KNOWN_PROTOCOLS {
            for t in crate::proto::KNOWN_PROTOCOLS {
                if f != t {
                    v.push((
                        *f,
                        *t,
                        counter_slot(
                            crate::metrics::TRANSLATIONS_TOTAL,
                            &[("from", f), ("to", t)],
                        ),
                    ));
                }
            }
        }
        v
    });
    match table
        .iter()
        .find(|(f, t, slot)| *f == from && *t == to && slot.is_valid())
    {
        Some((_, _, slot)) => slot.incr(),
        None => metrics::counter!(
            crate::metrics::TRANSLATIONS_TOTAL,
            "from" => from.to_string(),
            "to" => to.to_string()
        )
        .increment(1),
    }
}

#[cfg(test)]
#[path = "tests/telemetry_tests.rs"]
mod tests;
