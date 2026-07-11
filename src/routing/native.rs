// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Busbar-native routing policies — small, sync sorts over the live signals projected into
//! `Candidate`. Each native is the proof-of-completeness for its input signal (the scope-lock
//! conformance rule): if a native can't be written, the contract's in-data is incomplete.
//!
//! All natives are SYNC and never touch async or I/O; the async-trait wrapper is free for them. The
//! default `weighted` native exists only as the explicit `route: native, policy.name: weighted`
//! form — it returns `Abstain`, converging with the zero-cost default SWRR path.
//!
//! The native bodies + `native_policy` registry are live: `resolve_policy` looks a non-weighted name
//! up here at config load, and `forward::decide_policy_order` invokes the resolved policy per request.

use super::{
    Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
};
use std::time::Duration;

// ── Policy-name constants ─────────────────────────────────────────────────────────────────────────
// Single source of truth for the five native policy wire names. Referenced from:
//   • the `name()` impls below (what feeds `x-busbar-route-policy`),
//   • the `native_policy` registry match arms below,
//   • `config.rs` (deserialization / shorthand desugar),
//   • `routing/mod.rs` (zero-cost-path guard).
pub(crate) const POLICY_NAME_WEIGHTED: &str = "weighted";
pub(crate) const POLICY_NAME_CHEAPEST: &str = "cheapest";
pub(crate) const POLICY_NAME_FASTEST: &str = "fastest";
pub(crate) const POLICY_NAME_LEAST_BUSY: &str = "least_busy";
pub(crate) const POLICY_NAME_USAGE: &str = "usage";
pub(crate) const POLICY_NAME_SMART: &str = "smart";

/// `weighted` — the explicit form of the default. Always `Abstain`, so selection falls through to
/// the unchanged inline SWRR. Lets operators write `route: native, policy.name: weighted` and get
/// byte-identical behavior to the default, proving the seam without changing the hot path.
struct WeightedPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for WeightedPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }

    fn name(&self) -> &'static str {
        POLICY_NAME_WEIGHTED
    }
}

/// Rank candidates by a total-order key, ascending (smallest key first). Candidates whose key is
/// `None` are demoted to the end (lowest preference) but still ranked among themselves by `idx` for
/// determinism — never dropped, so a member with missing signal data is reachable, not stranded.
/// Returns `Abstain` if EVERY candidate lacks the signal (no opinion → default SWRR).
fn rank_ascending_by<K: PartialOrd + Copy>(
    candidates: &[Candidate<'_>],
    key: impl Fn(&Candidate<'_>) -> Option<K>,
) -> RoutingDecision {
    let mut keyed: Vec<(usize, Option<K>)> = candidates.iter().map(|c| (c.idx, key(c))).collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return RoutingDecision::Abstain;
    }
    // Sort: Some(k) before None; among Some, ascending by k; ties (and None/None) by idx for a
    // deterministic, stable order. `partial_cmp` can't yield None here because keys are finite
    // numbers in practice, but fall back to Equal to stay total and panic-free.
    keyed.sort_by(|(ia, ka), (ib, kb)| match (ka, kb) {
        (Some(a), Some(b)) => a
            .partial_cmp(b)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    RoutingDecision::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// Rank descending (largest key first) — the same shape as `rank_ascending_by` but preferring the
/// LARGEST signal (e.g. most free concurrency, most budget remaining).
fn rank_descending_by<K: PartialOrd + Copy>(
    candidates: &[Candidate<'_>],
    key: impl Fn(&Candidate<'_>) -> Option<K>,
) -> RoutingDecision {
    let mut keyed: Vec<(usize, Option<K>)> = candidates.iter().map(|c| (c.idx, key(c))).collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return RoutingDecision::Abstain;
    }
    keyed.sort_by(|(ia, ka), (ib, kb)| match (ka, kb) {
        (Some(a), Some(b)) => b
            .partial_cmp(a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    RoutingDecision::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// `cheapest` — prefer the lowest operator-declared `cost_per_mtok`. Members with no declared cost
/// are demoted (but reachable). Proof-of-completeness for the `cost` signal.
struct CheapestPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for CheapestPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_ascending_by(candidates, |c| c.cost_per_mtok))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_CHEAPEST
    }
}

/// `fastest` — prefer the lowest measured rolling-EWMA latency. Members with no latency sample yet
/// are demoted (reachable). Proof-of-completeness for the `latency` signal.
struct FastestPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for FastestPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_ascending_by(candidates, |c| c.latency_ms))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_FASTEST
    }
}

/// `least_busy` — prefer the lane with the most available concurrency permits (the most headroom).
/// Always has data (available_concurrency is always known), so never Abstains. Proof-of-completeness
/// for the `concurrency` signal.
struct LeastBusyPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for LeastBusyPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_descending_by(candidates, |c| {
            Some(c.available_concurrency)
        }))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_LEAST_BUSY
    }
}

/// `usage` — prefer the candidate with the most rate-limit HEADROOM: the largest fraction of the
/// request's governance rate budget (the tighter of the caller key's RPM / TPM limit) still available
/// this window, so traffic steers away from a candidate about to hit a provider 429. Ranks DESCENDING
/// by `Candidate.rate_headroom` (most headroom first); candidates with no headroom signal (`None`) are
/// demoted to last but stay reachable. Abstains when EVERY candidate lacks the signal (no rate limit
/// in play → fall through to the default SWRR). Proof-of-completeness for the `rate_headroom` signal.
struct UsagePolicy;

#[async_trait::async_trait]
impl RoutingPolicy for UsagePolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_descending_by(candidates, |c| c.rate_headroom))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_USAGE
    }
}

/// `smart` — task-aware MULTI-signal ranking, the native counterpart to a routing hook. It classifies
/// the request into a task bucket from SHAPE signals only (tools, size, interactivity — never prompt
/// content), then scores every candidate over the live `cost` / `latency` / `available_concurrency`
/// signals with per-bucket weights, adds a boost for the operator-declared quality `tier`, and scales
/// a lane down as it nears its rate-limit cap (`rate_headroom`). No sidecar, no script: a compiled,
/// sub-microsecond, in-process decision. Never Abstains — `available_concurrency` is always present,
/// so there is always something to rank on (a pool with no cost/latency/tier data degrades to
/// concurrency-weighted, which is a sane default rather than a coin flip).
struct SmartPolicy;

/// The task buckets `smart` classifies into, each with its own weighting of the live signals.
#[derive(Clone, Copy)]
enum Bucket {
    QuickAnswer,
    Code,
    LongForm,
    Bulk,
}

impl Bucket {
    /// Shape-only classification (no prompt content is ever available to a policy by default).
    fn classify(req: &RoutingRequest<'_>) -> Bucket {
        if req.has_tools {
            Bucket::Code // tool / agent traffic wants the capable tier
        } else if req.max_tokens.unwrap_or(0) >= 4096 || req.total_chars > 24_000 {
            Bucket::LongForm // ~4 chars/token: 24k chars is roughly 6k tokens
        } else if !req.stream && req.message_count <= 1 {
            Bucket::Bulk // single-shot, non-interactive: optimize cost
        } else {
            Bucket::QuickAnswer // interactive default: optimize latency
        }
    }

    /// Per-bucket `(cost, latency, concurrency)` weights + the quality tiers to boost.
    fn weights(self) -> (f64, f64, f64, &'static [&'static str]) {
        match self {
            Bucket::QuickAnswer => (0.30, 0.50, 0.20, &["small", "overflow"]),
            Bucket::Code => (0.10, 0.20, 0.20, &["large", "primary"]),
            Bucket::LongForm => (0.20, 0.10, 0.20, &["large", "primary"]),
            Bucket::Bulk => (0.60, 0.10, 0.30, &["small", "overflow"]),
        }
    }
}

/// Boost added to a candidate whose operator-declared `tier` is in the bucket's preferred set — the
/// operator's quality judgment, encoded as data, enforced here.
const SMART_TIER_BOOST: f64 = 0.5;

/// The `smart` ranking: classify, then score every candidate and rank descending (best first),
/// tie-broken by `idx` for determinism. Missing per-candidate signals score neutral (0.5) so a cold
/// lane is neither punished nor favored. Sub-microsecond; runs inline on the async worker.
fn smart_rank(req: &RoutingRequest<'_>, candidates: &[Candidate<'_>]) -> RoutingDecision {
    if candidates.is_empty() {
        return RoutingDecision::Abstain;
    }
    let (w_cost, w_lat, w_conc, tiers) = Bucket::classify(req).weights();
    // Normalization ceilings across the candidate set (0 → the signal does not differentiate).
    let max_cost = candidates
        .iter()
        .filter_map(|c| c.cost_per_mtok)
        .fold(0.0_f64, f64::max);
    let max_lat = candidates
        .iter()
        .filter_map(|c| c.latency_ms)
        .fold(0.0_f64, f64::max);
    let max_conc = candidates
        .iter()
        .map(|c| c.available_concurrency)
        .max()
        .unwrap_or(0);
    let score = |c: &Candidate<'_>| -> f64 {
        // Lower cost / latency is better → 1 - normalized; higher free concurrency is better.
        let cost_s = c.cost_per_mtok.map_or(0.5, |x| {
            if max_cost > 0.0 {
                1.0 - x / max_cost
            } else {
                0.5
            }
        });
        let lat_s = c.latency_ms.map_or(0.5, |x| {
            if max_lat > 0.0 {
                1.0 - x / max_lat
            } else {
                0.5
            }
        });
        let conc_s = if max_conc > 0 {
            c.available_concurrency as f64 / max_conc as f64
        } else {
            0.5
        };
        let mut s = w_cost * cost_s + w_lat * lat_s + w_conc * conc_s;
        if c.tier.is_some_and(|t| tiers.contains(&t)) {
            s += SMART_TIER_BOOST;
        }
        // Back a lane off as its rate-limit headroom shrinks, so traffic steers away from a 429.
        if let Some(h) = c.rate_headroom {
            s *= 0.5 + 0.5 * h;
        }
        s
    };
    let mut scored: Vec<(usize, f64)> = candidates.iter().map(|c| (c.idx, score(c))).collect();
    // Descending by score; ties (and NaN-safe fallback) by idx ascending for a deterministic order.
    scored.sort_by(|(ia, sa), (ib, sb)| {
        sb.partial_cmp(sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib))
    });
    RoutingDecision::Prefer(scored.into_iter().map(|(idx, _)| idx).collect())
}

#[async_trait::async_trait]
impl RoutingPolicy for SmartPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(smart_rank(req, candidates))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_SMART
    }
}

/// Resolve a native policy name to a boxed policy. `None` for an unknown name (rejected at startup
/// validation). `weighted` returns the Abstaining default native.
pub(crate) fn native_policy(name: &str) -> Option<std::sync::Arc<dyn RoutingPolicy>> {
    use std::sync::Arc;
    match name {
        POLICY_NAME_WEIGHTED => Some(Arc::new(WeightedPolicy)),
        POLICY_NAME_CHEAPEST => Some(Arc::new(CheapestPolicy)),
        POLICY_NAME_FASTEST => Some(Arc::new(FastestPolicy)),
        POLICY_NAME_LEAST_BUSY => Some(Arc::new(LeastBusyPolicy)),
        POLICY_NAME_USAGE => Some(Arc::new(UsagePolicy)),
        POLICY_NAME_SMART => Some(Arc::new(SmartPolicy)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(
        idx: usize,
        cost: Option<f64>,
        lat: Option<f64>,
        conc: usize,
        budget: Option<i64>,
    ) -> Candidate<'static> {
        // Most native tests don't exercise the `usage` signal; default `rate_headroom` to `None`.
        // The `usage` tests build candidates with `cand_rate` to set it explicitly.
        cand_rate(idx, cost, lat, conc, budget, None)
    }

    fn cand_rate(
        idx: usize,
        cost: Option<f64>,
        lat: Option<f64>,
        conc: usize,
        budget: Option<i64>,
        rate: Option<f64>,
    ) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: cost,
            tags: &[],
            latency_ms: lat,
            available_concurrency: conc,
            budget_remaining: budget,
            rate_headroom: rate,
        }
    }

    fn req() -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 1,
            tool_count: 0,
            has_tools: false,
            total_chars: 10,
            system_chars: 0,
            max_tokens: None,
            stream: false,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: None,
        }
    }

    #[tokio::test]
    async fn weighted_native_abstains() {
        let d = WeightedPolicy
            .decide(
                &req(),
                &[cand(0, None, None, 1, None)],
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    #[tokio::test]
    async fn cheapest_orders_by_cost_demoting_unknown() {
        let cands = [
            cand(0, Some(15.0), None, 1, None),
            cand(1, Some(3.0), None, 1, None),
            cand(2, None, None, 1, None), // no cost -> demoted to last
        ];
        let d = CheapestPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0, 2]));
    }

    #[tokio::test]
    async fn cheapest_all_unknown_abstains() {
        let cands = [cand(0, None, None, 1, None), cand(1, None, None, 1, None)];
        let d = CheapestPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    #[tokio::test]
    async fn fastest_orders_by_latency() {
        let cands = [
            cand(0, None, Some(120.0), 1, None),
            cand(1, None, Some(40.0), 1, None),
            cand(2, None, Some(80.0), 1, None),
        ];
        let d = FastestPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 2, 0]));
    }

    #[tokio::test]
    async fn least_busy_prefers_most_headroom() {
        let cands = [
            cand(0, None, None, 2, None),
            cand(1, None, None, 9, None),
            cand(2, None, None, 5, None),
        ];
        let d = LeastBusyPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 2, 0]));
    }

    /// `usage` ranks DESCENDING by `rate_headroom` (most rate-limit headroom first), demoting a
    /// candidate with no headroom signal (`None`) to last but keeping it reachable.
    #[tokio::test]
    async fn usage_orders_by_rate_headroom_demoting_unknown() {
        let cands = [
            cand_rate(0, None, None, 1, None, Some(0.10)), // nearly at the cap
            cand_rate(1, None, None, 1, None, Some(0.90)), // most headroom
            cand_rate(2, None, None, 1, None, None),       // no signal -> demoted to last
            cand_rate(3, None, None, 1, None, Some(0.50)),
        ];
        let d = UsagePolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 3, 0, 2]));
    }

    /// `usage` Abstains when EVERY candidate lacks the rate-headroom signal (no rate limit in play),
    /// so selection falls through to the default SWRR.
    #[tokio::test]
    async fn usage_all_unknown_abstains() {
        let cands = [
            cand_rate(0, None, None, 1, Some(100), None),
            cand_rate(1, None, None, 1, None, None),
            cand_rate(2, None, None, 1, Some(5000), None),
        ];
        let d = UsagePolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    #[test]
    fn native_registry_known_and_unknown() {
        assert!(native_policy("weighted").is_some());
        assert!(native_policy("cheapest").is_some());
        assert!(native_policy("fastest").is_some());
        assert!(native_policy("least_busy").is_some());
        assert!(native_policy("usage").is_some());
        assert!(native_policy("smart").is_some());
        assert!(native_policy("nonexistent").is_none());
    }

    /// Build a candidate with an explicit `tier` (the quality signal `smart` boosts).
    fn cand_tier(
        idx: usize,
        cost: Option<f64>,
        lat: Option<f64>,
        conc: usize,
        tier: &'static str,
    ) -> Candidate<'static> {
        let mut c = cand(idx, cost, lat, conc, None);
        c.tier = Some(tier);
        c
    }

    fn req_shape(
        has_tools: bool,
        max_tokens: Option<u32>,
        stream: bool,
        msgs: usize,
    ) -> RoutingRequest<'static> {
        RoutingRequest {
            has_tools,
            max_tokens,
            stream,
            message_count: msgs,
            ..req()
        }
    }

    /// `smart` in the CODE bucket (has_tools) boosts the preferred tier: the capable `large`-tier lane
    /// wins over a cheaper/faster `small`-tier one because the tier boost dominates the code weights.
    #[tokio::test]
    async fn smart_code_bucket_boosts_capable_tier() {
        let cands = [
            cand_tier(0, Some(3.0), Some(900.0), 8, "large"),
            cand_tier(1, Some(0.15), Some(300.0), 10, "small"),
        ];
        let d = SmartPolicy
            .decide(
                &req_shape(true, Some(512), true, 3),
                &cands,
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(
            d,
            RoutingDecision::Prefer(vec![0, 1]),
            "code bucket prefers the large tier"
        );
    }

    /// `smart` in the BULK bucket (single-shot, non-stream) weights COST heavily: the cheap lane wins.
    #[tokio::test]
    async fn smart_bulk_bucket_prefers_cheap() {
        let cands = [
            cand_tier(0, Some(3.0), Some(300.0), 8, "large"),
            cand_tier(1, Some(0.15), Some(900.0), 8, "small"),
        ];
        let d = SmartPolicy
            .decide(
                &req_shape(false, None, false, 1),
                &cands,
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(
            d,
            RoutingDecision::Prefer(vec![1, 0]),
            "bulk bucket prefers the cheap lane"
        );
    }

    /// `smart` never Abstains on a non-empty pool (concurrency is always present) but DOES Abstain on
    /// an empty pool, and its decision is deterministic (ties broken by idx).
    #[tokio::test]
    async fn smart_abstains_only_on_empty_pool() {
        let empty: [Candidate<'_>; 0] = [];
        let d = SmartPolicy
            .decide(&req(), &empty, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
        // Two identical candidates: a valid ranking, tie-broken by idx (never a panic on equal f64).
        let cands = [cand(0, None, None, 5, None), cand(1, None, None, 5, None)];
        let d = SmartPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0, 1]));
    }

    /// The registry round-trips each known name to a policy whose `name()` matches (not merely
    /// `is_some()`) — the resolved transport's name is what feeds the `x-busbar-route-policy` header.
    #[test]
    fn native_registry_names_round_trip() {
        for name in [
            "weighted",
            "cheapest",
            "fastest",
            "least_busy",
            "usage",
            "smart",
        ] {
            let p = native_policy(name).expect("known name must resolve");
            assert_eq!(
                p.name(),
                name,
                "resolved native policy name must round-trip"
            );
        }
    }

    // ── edge cases: empty pool / single candidate / all-saturated / all-unknown ──────────────────

    /// An empty candidate pool yields `Abstain` for every native (no candidates → no opinion → SWRR).
    #[tokio::test]
    async fn all_natives_abstain_on_empty_pool() {
        let empty: [Candidate<'_>; 0] = [];
        for name in [
            "weighted",
            "cheapest",
            "fastest",
            "least_busy",
            "usage",
            "smart",
        ] {
            let p = native_policy(name).unwrap();
            let d = p
                .decide(&req(), &empty, &ctx(), Duration::from_millis(10))
                .await
                .unwrap();
            assert_eq!(
                d,
                RoutingDecision::Abstain,
                "{name} must Abstain on an empty candidate pool"
            );
        }
    }

    /// A single candidate carrying the relevant signal ranks to a one-element `Prefer` for the
    /// signal-bearing natives; the always-present `least_busy` likewise prefers it.
    #[tokio::test]
    async fn single_candidate_prefers_it() {
        // cheapest: one candidate with a cost.
        let d = CheapestPolicy
            .decide(
                &req(),
                &[cand(0, Some(5.0), None, 1, None)],
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));
        // fastest: one candidate with a latency sample.
        let d = FastestPolicy
            .decide(
                &req(),
                &[cand(0, None, Some(30.0), 1, None)],
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));
        // least_busy: always has data.
        let d = LeastBusyPolicy
            .decide(
                &req(),
                &[cand(0, None, None, 3, None)],
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));
        // usage: one candidate with rate headroom.
        let d = UsagePolicy
            .decide(
                &req(),
                &[cand_rate(0, None, None, 1, None, Some(0.5))],
                &ctx(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));
    }

    /// `least_busy` with EVERY candidate saturated (`available_concurrency == 0`) does NOT Abstain —
    /// the concurrency signal is always present, so it ranks all lanes (all-zero → ordered by `idx`).
    /// The ordered walk + breaker machinery downstream is what skips a truly-unusable lane; the native
    /// only ORDERS and must never strand a lane by dropping it.
    #[tokio::test]
    async fn least_busy_all_saturated_ranks_by_idx() {
        let cands = [
            cand(0, None, None, 0, None),
            cand(1, None, None, 0, None),
            cand(2, None, None, 0, None),
        ];
        let d = LeastBusyPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0, 1, 2]));
    }

    /// `usage` with EVERY candidate at the cap (`rate_headroom == Some(0.0)`) still ranks (the signal
    /// is present on all), tie-breaking by `idx` — it does NOT Abstain (Abstain is only for all-`None`).
    #[tokio::test]
    async fn usage_all_at_cap_ranks_by_idx() {
        let cands = [
            cand_rate(0, None, None, 1, None, Some(0.0)),
            cand_rate(1, None, None, 1, None, Some(0.0)),
        ];
        let d = UsagePolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0, 1]));
    }

    /// `cheapest` with EVERY candidate at weight-0 / no declared cost Abstains (no cost signal at all
    /// → fall through to SWRR). Weight is irrelevant to `cheapest`; it ranks on cost.
    #[tokio::test]
    async fn cheapest_all_weight_zero_no_cost_abstains() {
        let mut a = cand(0, None, None, 1, None);
        a.weight = 0;
        let mut b = cand(1, None, None, 1, None);
        b.weight = 0;
        let d = CheapestPolicy
            .decide(&req(), &[a, b], &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// `fastest` with EVERY candidate lacking a latency sample Abstains (mirrors `cheapest_all_unknown`).
    #[tokio::test]
    async fn fastest_all_unknown_latency_abstains() {
        let cands = [cand(0, None, None, 1, None), cand(1, None, None, 1, None)];
        let d = FastestPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// `fastest` demotes a candidate with no latency sample to last (reachable, not dropped), exactly
    /// as `cheapest` demotes a no-cost candidate. Mirrors `cheapest_orders_by_cost_demoting_unknown`.
    #[tokio::test]
    async fn fastest_orders_by_latency_demoting_unknown() {
        let cands = [
            cand(0, None, Some(120.0), 1, None),
            cand(1, None, None, 1, None), // no latency sample -> demoted to last
            cand(2, None, Some(40.0), 1, None),
        ];
        let d = FastestPolicy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![2, 0, 1]));
    }
}
