// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the cost + limit model: rate-card derivation (tokens are the ledger, dollars derive)
//! and the resolved `groups:` limit topology (per-(group, window) enforcement buckets, the chain
//! walk, C6 key encoding).

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

fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
    }
}

fn group(parent: Option<&str>, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled: true,
        limits,
        ..Default::default()
    }
}

pub(crate) fn key(group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: "vk_1".into(),
        key_hash: "h".into(),
        name: "k".into(),
        allowed_pools: None,
        enabled: true,
        created_at: 0,
        group: group.map(String::from),
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

/// GROUP RESOLUTION: each distinct window a group's limits use becomes ONE enforcement bucket
/// (`group:<name>@<window>`) carrying that window's caps; `concurrent` resolves to the group's
/// instantaneous gauge cap, never a bucket.
#[test]
fn group_limits_resolve_to_per_window_buckets() {
    let groups = BTreeMap::from([(
        "bob".to_string(),
        group(
            None,
            vec![
                limit(LimitMetric::Requests, 10, Some(LimitWindow::Minute)),
                limit(LimitMetric::Tokens, 500, Some(LimitWindow::Minute)),
                limit(LimitMetric::Requests, 1000, Some(LimitWindow::Day)),
                limit(LimitMetric::Budget, 200, Some(LimitWindow::Month)),
                limit(LimitMetric::Concurrent, 5, None),
            ],
        ),
    )]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let g = cm.group_named("bob").expect("resolved");
    assert!(g.enabled);
    assert_eq!(g.concurrent_cap, Some(5));
    assert_eq!(g.buckets.len(), 3, "minute, day, month");
    let minute = g.buckets.iter().find(|b| b.window == "minute").unwrap();
    assert_eq!(minute.bucket_id, "group:bob@minute");
    assert_eq!(minute.requests_cap, Some(10));
    assert_eq!(minute.tokens_cap, Some(500));
    assert_eq!(minute.budget_cap, None);
    let day = g.buckets.iter().find(|b| b.window == "day").unwrap();
    assert_eq!(day.requests_cap, Some(1000));
    let month = g.buckets.iter().find(|b| b.window == "month").unwrap();
    assert_eq!(month.budget_cap, Some(200));
}

/// A metric repeated for the same window keeps the MOST RESTRICTIVE amount (AND semantics inside
/// one group, same as across the chain).
#[test]
fn duplicate_metric_same_window_keeps_the_minimum() {
    let groups = BTreeMap::from([(
        "g".to_string(),
        group(
            None,
            vec![
                limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute)),
                limit(LimitMetric::Requests, 7, Some(LimitWindow::Minute)),
                limit(LimitMetric::Concurrent, 9, None),
                limit(LimitMetric::Concurrent, 3, None),
            ],
        ),
    )]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let g = cm.group_named("g").unwrap();
    assert_eq!(g.buckets[0].requests_cap, Some(7));
    assert_eq!(g.concurrent_cap, Some(3));
}

/// Chain resolution: key attribution bucket first (uncapped, `total`), then EVERY window bucket of
/// each ancestor group, innermost group first; `group_indices` exposes the walked groups for the
/// enabled/concurrent checks. A key with no group is a 1-bucket chain (authed + unlimited).
#[test]
fn chain_resolves_key_then_group_window_buckets() {
    let groups = BTreeMap::from([
        (
            "acme".to_string(),
            group(
                None,
                vec![limit(LimitMetric::Budget, 10_000, Some(LimitWindow::Month))],
            ),
        ),
        (
            "growth".to_string(),
            group(
                Some("acme"),
                vec![
                    limit(LimitMetric::Requests, 50, Some(LimitWindow::Minute)),
                    limit(LimitMetric::Budget, 2_000, Some(LimitWindow::Month)),
                ],
            ),
        ),
    ]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let k = key(Some("growth"));
    let chain = cm.chain_for(&k).expect("resolves");
    let got: Vec<(String, &str, Option<u64>, Option<i64>)> = chain
        .iter()
        .map(|b| {
            (
                b.bucket_id.to_string(),
                b.window,
                b.requests_cap,
                b.budget_cap,
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("vk_1".to_string(), "total", None, None),
            ("group:growth@minute".to_string(), "minute", Some(50), None),
            ("group:growth@month".to_string(), "month", None, Some(2_000)),
            ("group:acme@month".to_string(), "month", None, Some(10_000)),
        ]
    );
    // The walked group indices resolve to growth (innermost) then acme.
    let names: Vec<&str> = chain
        .group_indices()
        .iter()
        .map(|&i| cm.groups()[i].name.as_str())
        .collect();
    assert_eq!(names, vec!["growth", "acme"]);

    // No group: exactly the key's uncapped attribution bucket.
    let solo = key(None);
    let chain = cm.chain_for(&solo).expect("resolves");
    assert_eq!(chain.len(), 1);
    let b = chain.iter().next().unwrap();
    assert!(b.group_name.is_none());
    assert_eq!(b.window, "total");
    assert_eq!(
        (b.requests_cap, b.tokens_cap, b.budget_cap),
        (None, None, None)
    );
    assert!(chain.group_indices().is_empty());
}

/// A key naming a MISSING group fails closed: chain resolution surfaces the offender.
#[test]
fn chain_with_missing_group_fails_closed_naming_it() {
    let cm = CostModel::resolve_parts(None, 0, &BTreeMap::new());
    let k = key(Some("ghost"));
    match cm.chain_for(&k) {
        Err(missing) => assert_eq!(missing, "ghost"),
        Ok(_) => panic!("a missing group must fail chain resolution"),
    }
}
