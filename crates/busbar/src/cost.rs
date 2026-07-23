// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The COST MODEL: rate-card resolution + ledger-to-spend derivation + budget-group chain
//! resolution. This is the ONE module the engine calls for anything cost-shaped; the `Store` trait
//! (in `busbar-api`) stays the persistence seam and carries ONLY tokens.
//!
//! Principles (the 1.5.0 cost-model spec):
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
//!
//! A `CostModel` is resolved from config at boot / config-apply and lives on `App` (rebuilt on
//! apply), while the `GovState` token ledger survives the apply - which is exactly what makes
//! reprice-on-reload work.

use std::collections::HashMap;

use busbar_api::TierTokens;

/// Maximum budget-group chain depth (a key's own bucket not counted). Validated at boot; the
/// runtime walk also clamps here so a corrupt store/config can never loop.
pub(crate) const MAX_GROUP_DEPTH: usize = 8;

/// Maximum enforcement-chain length: the key's own bucket + `MAX_GROUP_DEPTH` group buckets.
pub(crate) const MAX_CHAIN: usize = 1 + MAX_GROUP_DEPTH;

/// Nano-units (1e-9 abstract cost unit) per cent (1e-2 unit): the divisor that lands a derived
/// nano-unit total in whole cents.
const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units per micro-unit, for the hook seam's `spend_micros` projection.
const NANOS_PER_MICRO: u128 = 1_000;

/// The prefix namespacing budget-GROUP bucket ids in the store, so a group named like a key id can
/// never collide with a real key's bucket. Key buckets use the bare key id.
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

/// One resolved budget group: its bucket identity, cap, window, and parent (by index, so the chain
/// walk is index-chasing with zero hashing).
#[derive(Debug, Clone)]
pub(crate) struct GroupRuntime {
    pub(crate) name: String,
    /// The store bucket id (`group:<name>`).
    pub(crate) bucket_id: String,
    pub(crate) max_budget_cents: i64,
    pub(crate) budget_period: String,
    pub(crate) parent: Option<usize>,
}

/// One bucket of a resolved enforcement chain (borrowed views into the key / the `CostModel`; the
/// chain walk allocates nothing).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainBucket<'a> {
    /// The store/ledger bucket id (key id, or `group:<name>`).
    pub(crate) bucket_id: &'a str,
    /// The operator-facing name for diagnostics: the group name, or `None` for the key's own
    /// bucket.
    pub(crate) group_name: Option<&'a str>,
    pub(crate) max_budget_cents: Option<i64>,
    pub(crate) budget_period: &'a str,
    /// True for the key's own (innermost) bucket - the only bucket the flat per-request fee
    /// counts against.
    pub(crate) is_key: bool,
}

/// A resolved enforcement chain: the key bucket plus every ancestor group, innermost first.
/// Fixed-capacity (no heap) - depth is validated <= [`MAX_GROUP_DEPTH`].
pub(crate) struct Chain<'a> {
    buckets: [Option<ChainBucket<'a>>; MAX_CHAIN],
    len: usize,
}

impl<'a> Chain<'a> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &ChainBucket<'a>> {
        self.buckets[..self.len].iter().filter_map(|b| b.as_ref())
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// The resolved cost model: the effective integer rate table + the budget-group topology + the
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
    /// groups, valid periods); this is a pure projection and is defensive, never panicking, on
    /// anything validation should have caught.
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
                // P1 projection: the group's BUDGET limit (the first, when present) drives the
                // existing budget-chain machinery; a group with no budget limit is uncapped on
                // the spend axis (i64::MAX, "total"). The generic limit engine (requests /
                // tokens / concurrent + per-window budget stacking) lands in P4 on this same
                // topology.
                let budget = g.limits.iter().find_map(|l| {
                    (l.metric == crate::config::groups::LimitMetric::Budget)
                        .then_some((l.amount, l.per))
                });
                let (max_budget_cents, budget_period) = match budget {
                    Some((amount, per)) => {
                        let period = match per {
                            Some(crate::config::groups::LimitWindow::Day) => "daily",
                            Some(crate::config::groups::LimitWindow::Month) => "monthly",
                            Some(crate::config::groups::LimitWindow::Minute) => "minute",
                            Some(crate::config::groups::LimitWindow::Hour) => "hour",
                            Some(crate::config::groups::LimitWindow::Total) | None => "total",
                        };
                        (i64::try_from(amount).unwrap_or(i64::MAX), period)
                    }
                    None => (i64::MAX, "total"),
                };
                GroupRuntime {
                    name: (*name).clone(),
                    bucket_id: format!("{GROUP_BUCKET_PREFIX}{name}"),
                    max_budget_cents,
                    budget_period: budget_period.to_string(),
                    // A missing parent is a validate error; defensively resolve to None here so a
                    // bad config that somehow booted degrades to a shorter chain, never a panic.
                    parent: g.parent.as_deref().and_then(|p| group_idx.get(p).copied()),
                }
            })
            .collect();
        Self {
            rates,
            groups,
            group_idx,
            price_per_request_cents: per_request_fee.max(0),
        }
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

    /// The effective rate for `model` (post-`upstream_model` resolution, pool-member override
    /// already merged). Semantics of the three outcomes:
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
    /// over the models the bucket actually used, plus - for the key's own bucket - the flat
    /// per-request fee times the request count. Pure recompute from tokens x current rates: no
    /// spend is ever cached or stored.
    ///
    /// A model with no rate (card present, entry missing - only possible for ledger rows written
    /// under a previous config) derives at 0; the mismatch is the operator's rate-card edit
    /// taking effect retroactively, which is the designed behavior.
    pub(crate) fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m TierTokens)>,
        requests: u64,
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
                .saturating_mul(i64::try_from(requests).unwrap_or(i64::MAX));
            cents = cents.saturating_add(fee);
        }
        cents.max(0)
    }

    /// As [`Self::derive_spend_cents`] but in MICRO-units, for the hook seam / admin projections.
    pub(crate) fn derive_spend_micros<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m TierTokens)>,
        requests: u64,
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
                .saturating_mul(i64::try_from(requests).unwrap_or(i64::MAX));
            micros.saturating_add(fee_micros)
        } else {
            micros
        }
    }

    /// Resolve the ENFORCEMENT CHAIN for a key: [key's own bucket] -> key.budget_group -> parent
    /// -> ... root, innermost first. Zero-allocation (borrows the key + this model's group table).
    ///
    /// `Err(missing)` when the key names a `budget_group` that does not exist in config - the
    /// FAIL-CLOSED outcome (mint validates the group; boot re-checks; this arm covers a shared
    /// durable store whose keys reference a group another node's config no longer has).
    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_api::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let mut buckets: [Option<ChainBucket<'a>>; MAX_CHAIN] = Default::default();
        buckets[0] = Some(ChainBucket {
            bucket_id: &key.id,
            group_name: None,
            max_budget_cents: key.max_budget_cents,
            budget_period: &key.budget_period,
            is_key: true,
        });
        let mut len = 1;
        let mut next = match key.budget_group.as_deref() {
            None => None,
            Some(name) => match self.group_idx.get(name) {
                Some(&i) => Some(i),
                None => return Err(name),
            },
        };
        while let Some(i) = next {
            if len >= MAX_CHAIN {
                // Validation caps depth at MAX_GROUP_DEPTH; clamp defensively (never loop).
                break;
            }
            let g = &self.groups[i];
            buckets[len] = Some(ChainBucket {
                bucket_id: &g.bucket_id,
                group_name: Some(&g.name),
                max_budget_cents: Some(g.max_budget_cents),
                budget_period: &g.budget_period,
                is_key: false,
            });
            len += 1;
            next = g.parent;
        }
        Ok(Chain { buckets, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
    use crate::config::RateEntryCfg;
    use busbar_api::VirtualKey;
    use std::collections::BTreeMap;

    fn card(entries: &[(&str, f64, f64)]) -> BTreeMap<String, RateEntryCfg> {
        entries
            .iter()
            .map(|(m, i, o)| {
                (
                    m.to_string(),
                    RateEntryCfg {
                        input_utok: *i,
                        output_utok: *o,
                        cache_read_utok: 0.0,
                        cache_write_utok: 0.0,
                    },
                )
            })
            .collect()
    }

    fn resolve_card_fee(
        rate_card: Option<&BTreeMap<String, RateEntryCfg>>,
        per_request_fee: i64,
    ) -> CostModel {
        CostModel::resolve_parts(rate_card, per_request_fee, &BTreeMap::new())
    }

    /// A group whose only limit is a budget cap (the P1 projection the chain machinery enforces).
    fn budget_group(budget: u64, per: LimitWindow, parent: Option<&str>) -> GroupCfg {
        GroupCfg {
            parent: parent.map(str::to_string),
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: budget,
                per: Some(per),
            }],
        }
    }

    fn key(budget: Option<i64>, group: Option<&str>) -> VirtualKey {
        VirtualKey {
            id: "vk_1".into(),
            key_hash: "h".into(),
            name: "k".into(),
            allowed_pools: vec![],
            max_budget_cents: budget,
            budget_period: "total".into(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: group.map(String::from),
            labels: BTreeMap::new(),
        }
    }

    fn toks(input: u64, output: u64) -> TierTokens {
        TierTokens {
            input,
            output,
            cache_read: 0,
            cache_write: 0,
        }
    }

    /// ABSENT rate card => token pricing is 0 for every model; only the flat per-request fee
    /// counts. This is the all-or-nothing OFF arm.
    #[test]
    fn absent_rate_card_prices_tokens_at_zero() {
        let cm = resolve_card_fee(None, 3);
        assert!(!cm.pricing_enabled());
        assert!(!cm.model_unpriced("anything"), "no card = nothing to miss");
        let t = toks(1_000_000, 1_000_000);
        let spend = cm.derive_spend_cents([("anything", &t)].into_iter(), 5, true);
        assert_eq!(spend, 15, "tokens derive to 0; 5 requests x 3c fee remain");
    }

    /// PRESENT rate card: derivation is integer nano-unit math over the tier split. gpt-5 at
    /// 2.5 utok input / 10 utok output: 1M input + 1M output tokens = 2.5 + 10 units = 1250 cents.
    #[test]
    fn present_rate_card_derives_integer_spend() {
        let c = card(&[("gpt-5", 2.5, 10.0)]);
        let cm = resolve_card_fee(Some(&c), 0);
        assert!(cm.pricing_enabled());
        let t = toks(1_000_000, 1_000_000);
        let spend = cm.derive_spend_cents([("gpt-5", &t)].into_iter(), 0, false);
        assert_eq!(spend, 1250);
        // Micro projection: 12.5 units = 12_500_000 micro-units.
        let micros = cm.derive_spend_micros([("gpt-5", &t)].into_iter(), 0, false);
        assert_eq!(micros, 12_500_000);
    }

    /// Sub-micro precision survives the nano scale: 3.125 utok/token x 8 tokens = 25 micro-units
    /// exactly (no truncation at the micro boundary).
    #[test]
    fn nano_scale_keeps_sub_micro_precision() {
        let c = BTreeMap::from([(
            "m".to_string(),
            RateEntryCfg {
                input_utok: 3.125,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
            },
        )]);
        let cm = resolve_card_fee(Some(&c), 0);
        let t = toks(8, 0);
        assert_eq!(
            cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
            25
        );
    }

    /// Runtime model NOT in a present card => `model_unpriced` (the admission path rejects); the
    /// derive paths price it at 0 (ledger rows from a previous config).
    #[test]
    fn unknown_model_with_card_is_unpriced_and_derives_zero() {
        let c = card(&[("gpt-5", 1.0, 1.0)]);
        let cm = resolve_card_fee(Some(&c), 0);
        assert!(cm.model_unpriced("mystery-model"));
        assert!(!cm.model_unpriced("gpt-5"));
        let t = toks(1_000_000, 0);
        assert_eq!(
            cm.derive_spend_cents([("mystery-model", &t)].into_iter(), 0, false),
            0
        );
    }

    /// REPRICE-ON-READ: the ledger (tokens) is fixed; deriving under a corrected rate card yields
    /// the corrected spend - no stored dollar to migrate.
    #[test]
    fn reprice_on_read_recomputes_derived_spend() {
        let t = toks(1_000_000, 0);
        let wrong = resolve_card_fee(Some(&card(&[("m", 10.0, 0.0)])), 0);
        let fixed = resolve_card_fee(Some(&card(&[("m", 5.0, 0.0)])), 0);
        assert_eq!(
            wrong.derive_spend_cents([("m", &t)].into_iter(), 0, false),
            1000
        );
        assert_eq!(
            fixed.derive_spend_cents([("m", &t)].into_iter(), 0, false),
            500,
            "same tokens, corrected rate: derived spend halves on next read"
        );
    }

    /// REGRESSION (audit cost-1.5.0 #2): a cent total past i64::MAX SATURATES at i64::MAX
    /// (fail-closed: an astronomical ledger blocks). The pre-fix `as i64` cast wrapped - a large
    /// (u64-scale tokens x large configured rate) ledger could land NEGATIVE, be floored to 0 by
    /// `.max(0)`, and derive as FREE, bypassing every budget cap.
    #[test]
    fn derive_spend_cents_saturates_never_wraps_free() {
        // 1e15 micro-units/token -> 1e18 nano-units/token; x u64::MAX tokens ~= 1.8e37 nanos
        // -> ~1.8e30 cents, far past i64::MAX.
        let cm = resolve_card_fee(Some(&card(&[("m", 1e15, 0.0)])), 0);
        let t = toks(u64::MAX, 0);
        assert_eq!(
            cm.derive_spend_cents([("m", &t)].into_iter(), 0, false),
            i64::MAX,
            "an over-i64 cent total must pin at i64::MAX (blocks), never wrap toward 0 (free)"
        );
        // The micro projection already saturated correctly; pin it too.
        assert_eq!(
            cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
            i64::MAX
        );
    }

    /// S5: rate_card is the ONLY cost source - pool members carry no cost, and the routing
    /// scalar (`cheapest` / hook Candidate.cost_per_mtok) derives from a model's card entry as
    /// the blended (input + output) / 2 in units/mtok.
    #[test]
    fn rate_card_is_sole_cost_source_and_drives_routing_scalar() {
        let c = card(&[("gpt-5", 2.5, 10.0)]);
        let cm = resolve_card_fee(Some(&c), 0);
        let r = cm.rate_for("gpt-5").unwrap();
        assert_eq!(
            (r.input, r.output),
            (2_500, 10_000),
            "nano-unit rates come straight from the card"
        );
        // The routing scalar projection: (2.5 + 10.0) / 2 = 6.25 units/mtok.
        let scalar = crate::config::rate_entry_per_mtok(&c["gpt-5"]);
        assert!((scalar - 6.25).abs() < f64::EPSILON);
        // A pool member no longer parses a cost field at all (fail-closed on the removed key).
        let err = serde_yaml::from_str::<crate::config::PoolCfg>(
            "members:\n  - model: gpt-5\n    cost_per_mtok: 4\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cost_per_mtok"),
            "the removed member cost key must fail loudly: {err}"
        );
    }

    /// Chain resolution: key bucket first (fee applies there only), then the group chain to the
    /// root; each bucket carries its OWN period. A key with no group is a 1-bucket chain.
    #[test]
    fn chain_resolves_key_then_group_ancestry() {
        let groups = BTreeMap::from([
            (
                "acme".to_string(),
                budget_group(10_000_000, LimitWindow::Month, None),
            ),
            (
                "growth".to_string(),
                budget_group(2_000_000, LimitWindow::Month, Some("acme")),
            ),
            (
                "bob".to_string(),
                budget_group(500_000, LimitWindow::Day, Some("growth")),
            ),
        ]);
        let cm = CostModel::resolve_parts(None, 0, &groups);
        let k = key(Some(100_000), Some("bob"));
        let chain = cm.chain_for(&k).expect("resolves");
        let got: Vec<(String, Option<i64>, String, bool)> = chain
            .iter()
            .map(|b| {
                (
                    b.bucket_id.to_string(),
                    b.max_budget_cents,
                    b.budget_period.to_string(),
                    b.is_key,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("vk_1".to_string(), Some(100_000), "total".to_string(), true),
                (
                    "group:bob".to_string(),
                    Some(500_000),
                    "daily".to_string(),
                    false
                ),
                (
                    "group:growth".to_string(),
                    Some(2_000_000),
                    "monthly".to_string(),
                    false
                ),
                (
                    "group:acme".to_string(),
                    Some(10_000_000),
                    "monthly".to_string(),
                    false
                ),
            ]
        );

        // No group: exactly the key bucket.
        let solo = key(None, None);
        let chain = cm.chain_for(&solo).expect("resolves");
        assert_eq!(chain.len(), 1);
        assert!(chain.iter().next().unwrap().is_key);
    }

    /// A key naming a MISSING group fails closed: chain resolution surfaces the offender.
    #[test]
    fn chain_with_missing_group_fails_closed_naming_it() {
        let cm = CostModel::resolve_parts(None, 0, &BTreeMap::new());
        let k = key(None, Some("ghost"));
        match cm.chain_for(&k) {
            Err(missing) => assert_eq!(missing, "ghost"),
            Ok(_) => panic!("a missing group must fail chain resolution"),
        }
    }
}
