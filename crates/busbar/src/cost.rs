// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The COST + LIMIT MODEL: rate-card resolution, ledger-to-spend derivation, and the resolved
//! `groups:` limit topology the generic limit engine (governance) enforces. This is the ONE module
//! the engine calls for anything cost- or limit-shaped; the `Store` trait (in `busbar-api`) stays
//! the persistence seam and carries ONLY tokens.
//!
//! Principles (the 1.5.0 redesign):
//! - TOKENS ARE THE LEDGER; dollars are ALWAYS derived, never stored as truth. Every spend figure
//!   is computed here at read time as `ledger x current rate card`, so correcting a rate is a
//!   config edit + reload - past and future derived figures instantly become right. (Honest limit:
//!   repricing cannot un-make PAST admit/reject decisions taken under a wrong rate.)
//! - NO CURRENCY in the core. Rates are ABSTRACT cost units (micro-units per token in config,
//!   integer NANO-units per token internally); `_cents` fields are abstract minor units. Currency
//!   is a display concern owned entirely by the consumer.
//! - ALL-OR-NOTHING pricing: `rate_card` absent => every model prices at 0 (only the flat
//!   per-request fee counts); present => authoritative + complete (validated at boot).
//! - INTEGER MATH ONLY on the hot path: config floats convert ONCE here to nano-units per token;
//!   derivation is a few u128 multiply-adds over the models a bucket actually used.
//! - GROUPS are the ONE limit tree (S3): a group's generic limits (requests / tokens / budget per
//!   window, plus the instantaneous `concurrent` gauge) resolve here into per-(group, window)
//!   ENFORCEMENT BUCKETS; keys are pure auth and contribute no caps of their own.
//!
//! A `CostModel` is resolved from config at boot / config-apply and lives on `App` (rebuilt on
//! apply), while the `GovState` token ledger survives the apply - which is exactly what makes
//! reprice-on-reload work.

use std::collections::HashMap;

use busbar_api::TierTokens;

use crate::config::groups::LimitMetric;

/// Nano-units (1e-9 abstract cost unit) per cent (1e-2 unit): the divisor that lands a derived
/// nano-unit total in whole cents.
const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units per micro-unit, for the hook seam's `spend_micros` projection.
const NANOS_PER_MICRO: u128 = 1_000;

/// The prefix namespacing GROUP bucket ids in the store, so a group named like a key id can never
/// collide with a real key's bucket. Key buckets use the bare key id. A group's per-window buckets
/// are `group:<name>@<window>` - one ledger row per (group, window granularity), so a group with
/// limits in several windows never double-counts a flush into one row. A POOL-SCOPED bucket
/// (limits carrying `pool: <name>`) appends `#<pool>`: `group:<name>@<window>#<pool>` - its own
/// ledger row, accounting only the traffic dispatched through that pool.
pub(crate) const GROUP_BUCKET_PREFIX: &str = "group:";

/// One model's per-token rates in integer NANO-units per token (config micro-units x 1000, rounded
/// once at resolve). All hot-path math is integer over these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RateNanos {
    pub(crate) input: u64,
    pub(crate) output: u64,
    pub(crate) cache_read: u64,
    pub(crate) cache_write: u64,
}

impl RateNanos {
    pub(crate) fn from_cfg(r: &crate::config::RateEntryCfg) -> Self {
        // Config values are validated finite + >= 0; the clamp here is defense-in-depth so a NaN
        // or negative that slipped past validation becomes 0, never a huge/garbage integer rate.
        fn nanos(utok: f64) -> u64 {
            let v = (utok * 1000.0).round();
            if v.is_finite() && v > 0.0 {
                v as u64
            } else {
                0
            }
        }
        Self {
            input: nanos(r.input_utok),
            output: nanos(r.output_utok),
            cache_read: nanos(r.cache_read_utok),
            cache_write: nanos(r.cache_write_utok),
        }
    }

    /// The nano-unit cost of one tier-token split at this rate: four multiply-adds in u128 (a u64
    /// token count times a u64 nano rate cannot overflow u128).
    #[inline]
    pub(crate) fn cost_nanos(&self, t: &TierTokens) -> u128 {
        (t.input as u128) * (self.input as u128)
            + (t.output as u128) * (self.output as u128)
            + (t.cache_read as u128) * (self.cache_read as u128)
            + (t.cache_write as u128) * (self.cache_write as u128)
    }
}

/// One (group, window, pool?) ENFORCEMENT BUCKET, resolved from the group's windowed limits:
/// every limit of the group that shares this window AND pool scope enforces against this one
/// ledger cell. The three windowed metrics are independent caps on the same cell's counters
/// (requests / total tokens / derived spend).
#[derive(Debug, Clone)]
pub(crate) struct GroupBucket {
    /// The store/ledger bucket id: `group:<name>@<window>`, or `group:<name>@<window>#<pool>`
    /// for a pool-scoped bucket.
    pub(crate) bucket_id: String,
    /// The window word (`minute` | `hour` | `day` | `month` | `total`) - the `budget_window`
    /// period sentinel AND the metrics/error vocabulary.
    pub(crate) window: &'static str,
    /// Request-count cap per window (`{ requests: N, per: <window> }`), if any.
    pub(crate) requests_cap: Option<u64>,
    /// Total-token cap per window (`{ tokens: N, per: <window> }`), if any. Best-effort like the
    /// old TPM: tokens land post-response, so the cap blocks the NEXT request once crossed.
    pub(crate) tokens_cap: Option<u64>,
    /// Spend cap per window (`{ budget: N, per: <window> }`) in abstract cents, if any. Derived at
    /// check time from the cell's token ledger x the current rate card (+ the flat per-request
    /// fee x requests).
    pub(crate) budget_cap: Option<i64>,
    /// `Some(pool)` = this bucket accounts ONLY traffic dispatched through that pool (limits
    /// carrying `pool: <name>`); `None` = group-wide (every request through the group).
    pub(crate) pool: Option<String>,
    /// Where BUDGET-exhausted traffic goes instead of a rejection (`on_exhaust: downgrade,
    /// downgrade_to: <pool>` on the governing budget limit). `None` = block (the default). When
    /// several budget limits merge into this bucket, the MOST RESTRICTIVE (minimum) cap's
    /// behavior governs - it is the one that actually blocks.
    pub(crate) downgrade_to: Option<String>,
}

/// One resolved group: its enabled flag, in-flight cap, per-window enforcement buckets, and parent
/// (by index, so the chain walk is index-chasing with zero hashing).
#[derive(Debug, Clone)]
pub(crate) struct GroupRuntime {
    pub(crate) name: String,
    /// `false` FREEZES the group: every request charging through it (its own keys AND every
    /// descendant's) is rejected while history is kept (C10).
    pub(crate) enabled: bool,
    /// The instantaneous in-flight cap (`{ concurrent: N }` - no window), if any.
    pub(crate) concurrent_cap: Option<u64>,
    /// The group's windowed enforcement buckets, one per distinct window its limits use (config
    /// order of first use). Empty for a group with only a `concurrent` limit (or none).
    pub(crate) buckets: Vec<GroupBucket>,
    pub(crate) parent: Option<usize>,
}

/// One bucket of a resolved enforcement chain (borrowed views into the key / the `CostModel`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainBucket<'a> {
    /// The store/ledger bucket id (the key id, or `group:<name>@<window>[#<pool>]`).
    pub(crate) bucket_id: &'a str,
    /// The operator-facing group name for diagnostics; `None` for the key's own bucket.
    pub(crate) group_name: Option<&'a str>,
    /// The bucket's window word - the `budget_window` period sentinel (`total` for the key's own
    /// attribution bucket). `'static`: both sources (the group buckets and the key's `total`) are
    /// compile-time sentinels.
    pub(crate) window: &'static str,
    pub(crate) requests_cap: Option<u64>,
    pub(crate) tokens_cap: Option<u64>,
    pub(crate) budget_cap: Option<i64>,
    /// `Some(pool)` = the bucket is pool-scoped: it checks/charges/accrues ONLY when the request
    /// was dispatched through that pool. `None` = applies to every request through the group.
    pub(crate) pool: Option<&'a str>,
    /// The budget limit's `downgrade_to` pool, when it declared `on_exhaust: downgrade`.
    pub(crate) downgrade_to: Option<&'a str>,
}

impl ChainBucket<'_> {
    /// Whether this bucket participates in a request dispatched through `pool` - group-wide
    /// buckets always do; a pool-scoped bucket only for its own pool. Every enforcement walk
    /// (admit / charge / refund / accrue / headroom) keys off this ONE predicate so the paths
    /// can never disagree on what was charged vs what is refunded.
    pub(crate) fn applies_to_pool(&self, pool: &str) -> bool {
        self.pool.is_none_or(|p| p == pool)
    }
}

/// A resolved enforcement chain: the key's attribution bucket plus every ancestor group's
/// per-window buckets, innermost group first. Sized by the chain actually walked (the tree is
/// unbounded by policy; a chain can never exceed the number of groups — cycles are a validate
/// error and the walk clamps there defensively). Also carries the GROUP INDICES walked (for the
/// `enabled` freeze check and the `concurrent` gauges, which are per group, not per window
/// bucket).
pub(crate) struct Chain<'a> {
    buckets: Vec<ChainBucket<'a>>,
    groups: Vec<usize>,
}

impl<'a> Chain<'a> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &ChainBucket<'a>> {
        self.buckets.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }

    /// The `CostModel::groups()` indices of the chain's groups, innermost first.
    pub(crate) fn group_indices(&self) -> &[usize] {
        &self.groups
    }
}

/// The resolved cost model: the effective integer rate table + the group limit topology + the
/// flat per-request fee. Immutable once resolved; rebuilt with the config on apply/reload.
pub(crate) struct CostModel {
    /// `None` = `rate_card` absent = token pricing 0 for every model. `Some` = the AUTHORITATIVE
    /// effective table, straight from the top-level `rate_card:` (S5: the ONLY cost source).
    rates: Option<HashMap<String, RateNanos>>,
    groups: Vec<GroupRuntime>,
    group_idx: HashMap<String, usize>,
    price_per_request_cents: i64,
}

impl CostModel {
    /// Resolve from config. Assumes `config_validate` has already passed (completeness, acyclic
    /// groups, valid limit shapes); this is a pure projection and is defensive, never panicking,
    /// on anything validation should have caught.
    pub(crate) fn resolve_parts(
        rate_card: Option<&std::collections::BTreeMap<String, crate::config::RateEntryCfg>>,
        per_request_fee: i64,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        // S5: rate_card is the ONLY cost source - the 1.4.x pool-member tiered-override loop is
        // GONE (cost lives on no pool member; routing derives its scalar from the card).
        let rates = rate_card.map(|card| {
            card.iter()
                .map(|(model, r)| (model.clone(), RateNanos::from_cfg(r)))
                .collect::<HashMap<String, RateNanos>>()
        });
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            rates,
            groups,
            group_idx,
            price_per_request_cents: per_request_fee.max(0),
        }
    }

    /// Rebuild the model with a NEW groups map, reusing the resolved rate card + flat fee unchanged.
    /// The Admin-API group-mutation seam (`build_with_group` / `build_without_group`): a runtime
    /// group change must reproject enforcement buckets WITHOUT re-parsing the rate card (which the
    /// mutation never touched). Pure — assumes the caller already re-ran `validate_groups`.
    pub(crate) fn with_groups(
        &self,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            rates: self.rates.clone(),
            groups,
            group_idx,
            price_per_request_cents: self.price_per_request_cents,
        }
    }

    /// Project a `GroupCfg` map into the runtime enforcement form: sorted `GroupRuntime` vec + a
    /// name→index map (parents resolved to indices). Shared verbatim by `resolve_parts` (boot/apply)
    /// and `with_groups` (runtime group mutation) so the two paths can never drift.
    fn project_groups(
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> (Vec<GroupRuntime>, HashMap<String, usize>) {
        let mut group_names: Vec<&String> = groups_cfg.keys().collect();
        group_names.sort();
        let group_idx: HashMap<String, usize> = group_names
            .iter()
            .enumerate()
            .map(|(i, n)| ((*n).clone(), i))
            .collect();
        let groups: Vec<GroupRuntime> = group_names
            .iter()
            .map(|name| {
                let g = &groups_cfg[name.as_str()];
                // Project the group's generic limits into per-(window, pool) enforcement buckets.
                // A bucket materialises on first use (config order); a metric repeated for the
                // same window + pool scope keeps the MOST RESTRICTIVE (minimum) amount - AND
                // semantics inside one group, same as across the chain. A pool-qualified limit
                // gets its OWN bucket (its own ledger row), so `budget: 5000 pool: frontier` and
                // `budget: 5000 pool: value` account independently.
                let mut buckets: Vec<GroupBucket> = Vec::new();
                let mut concurrent_cap: Option<u64> = None;
                for l in &g.limits {
                    match (l.metric, l.per) {
                        (LimitMetric::Concurrent, _) => {
                            concurrent_cap =
                                Some(concurrent_cap.map_or(l.amount, |c: u64| c.min(l.amount)));
                        }
                        (metric, Some(window)) => {
                            let w = window.as_str();
                            let bucket = match buckets
                                .iter_mut()
                                .find(|b| b.window == w && b.pool.as_deref() == l.pool.as_deref())
                            {
                                Some(b) => b,
                                None => {
                                    let bucket_id = match &l.pool {
                                        Some(p) => {
                                            format!("{GROUP_BUCKET_PREFIX}{name}@{w}#{p}")
                                        }
                                        None => format!("{GROUP_BUCKET_PREFIX}{name}@{w}"),
                                    };
                                    buckets.push(GroupBucket {
                                        bucket_id,
                                        window: w,
                                        requests_cap: None,
                                        tokens_cap: None,
                                        budget_cap: None,
                                        pool: l.pool.clone(),
                                        downgrade_to: None,
                                    });
                                    buckets.last_mut().expect("just pushed")
                                }
                            };
                            let min_u = |cur: Option<u64>| {
                                Some(cur.map_or(l.amount, |c: u64| c.min(l.amount)))
                            };
                            match metric {
                                LimitMetric::Requests => {
                                    bucket.requests_cap = min_u(bucket.requests_cap)
                                }
                                LimitMetric::Tokens => bucket.tokens_cap = min_u(bucket.tokens_cap),
                                LimitMetric::Budget => {
                                    let amount = i64::try_from(l.amount).unwrap_or(i64::MAX);
                                    // The MOST RESTRICTIVE budget's exhaustion behavior governs:
                                    // it is the cap that actually blocks, so its downgrade (or
                                    // its absence = block) is what fires.
                                    if bucket.budget_cap.is_none_or(|c| amount < c) {
                                        bucket.downgrade_to = l.downgrade_to.clone();
                                    }
                                    bucket.budget_cap = Some(
                                        bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)),
                                    );
                                }
                                LimitMetric::Concurrent => unreachable!("matched above"),
                            }
                        }
                        // A windowed metric with no `per` cannot deserialize (LimitCfg enforces the
                        // shape at parse); defensively skip rather than panic.
                        (_, None) => {}
                    }
                }
                GroupRuntime {
                    name: (*name).clone(),
                    enabled: g.enabled,
                    concurrent_cap,
                    buckets,
                    // A missing parent is a validate error; defensively resolve to None here so a
                    // bad config that somehow booted degrades to a shorter chain, never a panic.
                    parent: g.parent.as_deref().and_then(|p| group_idx.get(p).copied()),
                }
            })
            .collect();
        (groups, group_idx)
    }

    /// A minimal model for tests / governance-off paths: no card, no groups, the given flat fee.
    #[cfg(test)]
    pub(crate) fn flat(price_per_request_cents: i64) -> Self {
        Self {
            rates: None,
            groups: Vec::new(),
            group_idx: HashMap::new(),
            price_per_request_cents: price_per_request_cents.max(0),
        }
    }

    /// Resolve a CONFIGURED model name to its rate-card key. 1.5.0: the rate card is keyed by the
    /// CONFIG model name itself (two providers serving one upstream model are two `models:`
    /// entries with two card entries), so this is the identity - kept as the one seam every
    /// consumer resolves through, so a future re-aliasing lands in one place.
    pub(crate) fn resolve_model_alias<'a>(&'a self, model: &'a str) -> &'a str {
        model
    }

    /// Whether a rate card is configured (token pricing active).
    pub(crate) fn pricing_enabled(&self) -> bool {
        self.rates.is_some()
    }

    pub(crate) fn price_per_request_cents(&self) -> i64 {
        self.price_per_request_cents
    }

    pub(crate) fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    pub(crate) fn group_named(&self, name: &str) -> Option<&GroupRuntime> {
        self.group_idx.get(name).map(|&i| &self.groups[i])
    }

    /// The effective rate for `model` (post-`upstream_model` resolution). Semantics of the three
    /// outcomes:
    /// - card absent: `Some(zero)` - every model prices at 0.
    /// - card present, model priced: `Some(rate)`.
    /// - card present, model UNKNOWN: `None` - fail-closed; the admission path rejects an
    ///   unpriced passthrough model, and the derive paths price it at 0 with a warn (it can only
    ///   arise from ledger rows written before a config change).
    #[inline]
    pub(crate) fn rate_for(&self, model: &str) -> Option<RateNanos> {
        match &self.rates {
            None => Some(RateNanos::default()),
            Some(table) => table.get(model).copied(),
        }
    }

    /// Whether a request for `model` must be REJECTED because the rate card is present but has no
    /// entry (an arbitrary passthrough model string not in any configured lane). Fail-closed and
    /// consistent with the completeness rule: you either price nothing or price everything.
    #[inline]
    pub(crate) fn model_unpriced(&self, model: &str) -> bool {
        match &self.rates {
            None => false,
            Some(table) => !table.contains_key(model),
        }
    }

    /// DERIVE the spend (in cents, abstract minor units) of a ledger view: a few multiply-adds
    /// over the models the bucket actually used, plus - when `include_request_fee` - the flat
    /// per-request fee times the BILLABLE request count (`fee_requests`: admitted minus refunded,
    /// so the fee bills 2xx only). Every enforcement/read path passes `true` (each bucket counts
    /// its own billable requests, so its fee component is its own); the flag exists for callers
    /// that want a tokens-only projection. Pure recompute from tokens x current rates: no spend is
    /// ever cached or stored.
    ///
    /// A model with no rate (card present, entry missing - only possible for ledger rows written
    /// under a previous config) derives at 0; the mismatch is the operator's rate-card edit
    /// taking effect retroactively, which is the designed behavior.
    pub(crate) fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m TierTokens)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        let mut nanos: u128 = 0;
        for (model, tokens) in models {
            if let Some(rate) = self.rate_for(model) {
                nanos = nanos.saturating_add(rate.cost_nanos(tokens));
            }
        }
        // SATURATE into i64 (never `as`-cast): an adversarially large ledger (u64-scale token
        // counts x a large configured rate) can push the cent total past i64::MAX, and a wrapping
        // cast would land NEGATIVE - which `.max(0)` below then floors to 0, i.e. an over-the-top
        // ledger would derive as FREE and bypass every budget cap. Pin at i64::MAX instead (an
        // astronomically over-cap spend that blocks, fail-closed).
        let mut cents = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
        if include_request_fee {
            let fee = self
                .price_per_request_cents
                .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
            cents = cents.saturating_add(fee);
        }
        cents.max(0)
    }

    /// As [`Self::derive_spend_cents`] but in MICRO-units, for the hook seam / admin projections.
    pub(crate) fn derive_spend_micros<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m TierTokens)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        let mut nanos: u128 = 0;
        for (model, tokens) in models {
            if let Some(rate) = self.rate_for(model) {
                nanos = nanos.saturating_add(rate.cost_nanos(tokens));
            }
        }
        let micros = i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX);
        if include_request_fee {
            // 1 cent = 10_000 micro-units.
            let fee_micros = self
                .price_per_request_cents
                .saturating_mul(10_000)
                .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
            micros.saturating_add(fee_micros)
        } else {
            micros
        }
    }

    /// Resolve the ENFORCEMENT CHAIN for a key: [key's attribution bucket] -> key.group's window
    /// buckets -> parent's -> ... root, innermost first. Borrows the key + this model's group
    /// table; allocates only the chain vectors themselves.
    ///
    /// `Err(missing)` when the key names a `group` that does not exist in config - the
    /// FAIL-CLOSED outcome (mint validates the group; boot re-checks; this arm covers a shared
    /// durable store whose keys reference a group another node's config no longer has).
    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_api::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let mut buckets: Vec<ChainBucket<'a>> = Vec::with_capacity(8);
        buckets.push(ChainBucket {
            bucket_id: &key.id,
            group_name: None,
            window: crate::governance::WINDOW_TOTAL,
            requests_cap: None,
            tokens_cap: None,
            budget_cap: None,
            pool: None,
            downgrade_to: None,
        });
        let mut groups: Vec<usize> = Vec::new();
        let mut next = match key.group.as_deref() {
            None => None,
            Some(name) => match self.group_idx.get(name) {
                Some(&i) => Some(i),
                None => return Err(name),
            },
        };
        while let Some(i) = next {
            if groups.len() >= self.groups.len() {
                // A distinct-node walk cannot exceed the group count without revisiting one, i.e.
                // a cycle. Cycles are a validate error; clamp defensively (never loop).
                break;
            }
            let g = &self.groups[i];
            groups.push(i);
            for b in &g.buckets {
                buckets.push(ChainBucket {
                    bucket_id: &b.bucket_id,
                    group_name: Some(&g.name),
                    window: b.window,
                    requests_cap: b.requests_cap,
                    tokens_cap: b.tokens_cap,
                    budget_cap: b.budget_cap,
                    pool: b.pool.as_deref(),
                    downgrade_to: b.downgrade_to.as_deref(),
                });
            }
            next = g.parent;
        }
        Ok(Chain { buckets, groups })
    }
}

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod tests;
