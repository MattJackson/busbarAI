// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the P4 GENERIC LIMIT ENGINE: `GovState::try_admit` over the resolved group chain.
//! Every metric (requests / tokens / budget / concurrent), each in its own window; the chain AND
//! across levels; the `enabled: false` freeze; the key-with-no-group unlimited posture; the RAII
//! in-flight grant; refunds; hydrate/accrual across the per-(group, window) buckets.

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use std::collections::BTreeMap;

fn gov() -> GovState {
    GovState::new(Arc::new(MemoryStore::new()), None).expect("memory store constructs")
}

fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
        pool: None,
    }
}

fn group_cfg(parent: Option<&str>, enabled: bool, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled,
        limits,
        ..Default::default()
    }
}

fn model(groups: &[(&str, GroupCfg)]) -> CostModel {
    let map: BTreeMap<String, GroupCfg> = groups
        .iter()
        .map(|(n, g)| (n.to_string(), g.clone()))
        .collect();
    CostModel::resolve_parts(None, 0, &map)
}

fn model_with_card(groups: &[(&str, GroupCfg)], fee: i64, card: &[(&str, f64, f64)]) -> CostModel {
    let map: BTreeMap<String, GroupCfg> = groups
        .iter()
        .map(|(n, g)| (n.to_string(), g.clone()))
        .collect();
    let card: BTreeMap<String, crate::config::RateEntryCfg> = card
        .iter()
        .map(|(m, i, o)| {
            (
                m.to_string(),
                crate::config::RateEntryCfg {
                    input_utok: *i,
                    output_utok: *o,
                    cache_read_utok: 0.0,
                    cache_write_utok: 0.0,
                },
            )
        })
        .collect();
    CostModel::resolve_parts((!card.is_empty()).then_some(&card), fee, &map)
}

fn key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        key_hash: format!("h:{id}"),
        name: id.to_string(),
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

/// The exact blocking bucket must be NAMED: group + metric + window (+ retry for rolling windows).
#[track_caller]
fn assert_blocked(
    err: LimitBlocked,
    group: &str,
    metric: &str,
    window: Option<&str>,
    has_retry: bool,
) {
    match err {
        LimitBlocked::Limit {
            group: g,
            metric: m,
            window: w,
            pool: _,
            retry_after,
        } => {
            assert_eq!(g, group, "blocking group");
            assert_eq!(m, metric, "blocking metric");
            assert_eq!(w, window, "blocking window");
            assert_eq!(retry_after.is_some(), has_retry, "retry-after presence");
        }
        other => panic!("expected a Limit rejection, got {other:?}"),
    }
}

/// `requests` per MINUTE: N admissions charge and pass; N+1 in the same window is rejected naming
/// (group, requests, minute) with a Retry-After to the minute roll; the NEXT window admits again.
#[test]
fn requests_per_minute_enforced_and_window_rolls() {
    let g = gov();
    let cm = model(&[(
        "bob",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 3, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_r", Some("bob"));
    let now = 1_700_000_000; // mid-minute
    for _ in 0..3 {
        g.try_admit(&cm, &k, "", now).expect("under the cap");
    }
    let err = g.try_admit(&cm, &k, "", now).unwrap_err();
    assert_blocked(err, "bob", "requests", Some("minute"), true);
    // The next minute window is fresh.
    g.try_admit(&cm, &k, "", now + 60)
        .expect("new window admits");
}

/// Every windowed granularity resolves and enforces independently: an HOUR cap and a DAY cap on
/// one group live in separate buckets and the tighter one blocks first.
#[test]
fn hour_and_day_windows_enforce_independently() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 2, Some(LimitWindow::Hour)),
                limit(LimitMetric::Requests, 3, Some(LimitWindow::Day)),
            ],
        ),
    )]);
    let k = key("vk_hd", Some("g"));
    let day0 = 1_700_006_400 / super::SECS_PER_DAY * super::SECS_PER_DAY; // a UTC midnight
    g.try_admit(&cm, &k, "", day0).expect("1st");
    g.try_admit(&cm, &k, "", day0).expect("2nd");
    // Hour cap (2) trips first.
    assert_blocked(
        g.try_admit(&cm, &k, "", day0).unwrap_err(),
        "g",
        "requests",
        Some("hour"),
        true,
    );
    // Next hour: the hour bucket is fresh but the DAY bucket already holds 2; one more is the
    // day's 3rd and passes, the next blocks on the day cap.
    let next_hour = day0 + 3600;
    g.try_admit(&cm, &k, "", next_hour).expect("day's 3rd");
    assert_blocked(
        g.try_admit(&cm, &k, "", next_hour).unwrap_err(),
        "g",
        "requests",
        Some("day"),
        true,
    );
}

/// `total` never rolls: the rejection carries NO Retry-After.
#[test]
fn total_window_blocks_without_retry_after() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Total))],
        ),
    )]);
    let k = key("vk_t", Some("g"));
    g.try_admit(&cm, &k, "", 100).expect("first");
    assert_blocked(
        g.try_admit(&cm, &k, "", 100_000_000).unwrap_err(),
        "g",
        "requests",
        Some("total"),
        false,
    );
}

/// `tokens` per window is BEST-EFFORT post-paid: admission passes until the LEDGERED total crosses
/// the cap, then the next request is rejected naming (group, tokens, window).
#[test]
fn tokens_cap_blocks_after_ledger_crosses() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Tokens, 100, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_tok", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now)
        .expect("no tokens ledgered yet");
    g.record_usage(&cm, &k, "", "m", &toks(60, 39), now); // 99 < 100
    g.try_admit(&cm, &k, "", now).expect("still under");
    g.record_usage(&cm, &k, "", "m", &toks(1, 0), now); // exactly 100 = at the cap
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens",
        Some("minute"),
        true,
    );
    // A fresh window forgets the tokens.
    g.try_admit(&cm, &k, "", now + 60).expect("fresh window");
}

/// `budget` per window derives spend from the token ledger x the rate card PLUS the flat fee x
/// requests, and blocks at/over the cap. Repricing applies on the next check (tokens are truth).
#[test]
fn budget_cap_derives_from_ledger_and_rate_card() {
    let g = gov();
    // 10 utok/token input; cap 100 cents per month. 100_000 input tokens = 1_000_000 utok
    // = 100 cents = AT the cap.
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 100, Some(LimitWindow::Month))],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_b", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("nothing spent");
    g.record_usage(&cm, &k, "", "m", &toks(99_000, 0), now); // 99 cents
    g.try_admit(&cm, &k, "", now).expect("under the cap");
    g.record_usage(&cm, &k, "", "m", &toks(1_000, 0), now); // 100 cents = at the cap
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("month"),
        true,
    );
}

/// The flat per-request fee is part of a group bucket's derived spend: with fee=10 and a 25-cent
/// budget, the 3rd admission's prospective spend (2 charged x 10 + 10 = 30) exceeds the cap.
#[test]
fn per_request_fee_counts_into_group_budget() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 25, Some(LimitWindow::Day))],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_fee", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("fee 10 <= 25");
    g.try_admit(&cm, &k, "", now).expect("fee 20 <= 25");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("day"),
        true,
    );
    // A refund (non-2xx) returns the fee, re-opening the cap (the fee bills 2xx only).
    g.refund_request(&cm, &k, "", now);
    g.try_admit(&cm, &k, "", now)
        .expect("refund re-opened the cap");
}

/// REGRESSION (found by the test agent): a REFUND must return the fee (2xx-only billing) WITHOUT
/// returning the request-LIMIT slot. Otherwise a caller escapes the `requests` cap by hammering
/// failing requests: each refunds its own slot and the cap only ever counts successes.
#[test]
fn refund_returns_the_fee_but_never_the_requests_limit_slot() {
    let g = gov();
    // One group with BOTH a requests cap (2/day) and a budget cap fed by a fee.
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Requests, 2, Some(LimitWindow::Day)),
                    limit(LimitMetric::Budget, 1_000, Some(LimitWindow::Day)),
                ],
            ),
        )],
        10, // fee 10 cents/request
        &[],
    );
    let k = key("vk_split", Some("g"));
    let now = 1_700_000_000;
    // Two admissions, both REFUNDED (simulating two non-2xx outcomes).
    g.try_admit(&cm, &k, "", now).expect("1st admits");
    g.refund_request(&cm, &k, "", now);
    g.try_admit(&cm, &k, "", now).expect("2nd admits");
    g.refund_request(&cm, &k, "", now);
    // The requests LIMIT saw 2 admissions and was NOT refunded: the 3rd is rejected on the
    // requests cap even though both prior requests "failed".
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "requests",
        Some("day"),
        true,
    );
    // The FEE, meanwhile, was refunded: derived spend on the budget bucket is 0 (both fees
    // returned), so the budget cap is untouched by the two failures.
    let u = g
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .unwrap();
    assert_eq!(u.requests, 2, "admission count is never refunded");
    assert_eq!(
        u.spend_cents, 0,
        "both fees were refunded (2xx-only billing)"
    );
}

/// `concurrent` is an INSTANTANEOUS in-flight gauge: holds live on the returned grant and release
/// on drop; a full gauge rejects naming (group, concurrent) with no window and no Retry-After.
#[test]
fn concurrent_gauge_holds_and_releases() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Concurrent, 2, None)]),
    )]);
    let k = key("vk_c", Some("g"));
    let now = 1_700_000_000;
    let g1 = g.try_admit(&cm, &k, "", now).expect("1st in flight");
    let g2 = g.try_admit(&cm, &k, "", now).expect("2nd in flight");
    assert_eq!(g1.held(), 1);
    assert_eq!(g.concurrent_in_flight("g"), 2);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "concurrent",
        None,
        false,
    );
    drop(g1);
    assert_eq!(g.concurrent_in_flight("g"), 1);
    let _g3 = g.try_admit(&cm, &k, "", now).expect("slot freed");
    drop(g2);
    drop(_g3);
    assert_eq!(g.concurrent_in_flight("g"), 0, "all holds released");
}

/// A rejected admission must NOT leak a concurrent hold: an inner gauge taken before an outer
/// (parent) limit blocks is rolled back with the rejection.
#[test]
fn rejected_admission_releases_concurrent_holds() {
    let g = gov();
    let cm = model(&[
        (
            "parent",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Minute))],
            ),
        ),
        (
            "child",
            group_cfg(
                Some("parent"),
                true,
                vec![limit(LimitMetric::Concurrent, 10, None)],
            ),
        ),
    ]);
    let k = key("vk_leak", Some("child"));
    let now = 1_700_000_000;
    let held = g.try_admit(&cm, &k, "", now).expect("first admits");
    // Second: the child's gauge increments, then the parent's requests cap blocks - the gauge
    // must be released with the rejection.
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "parent",
        "requests",
        Some("minute"),
        true,
    );
    drop(held);
    assert_eq!(
        g.concurrent_in_flight("child"),
        0,
        "no hold leaked by the rejected admission"
    );
}

/// CHAIN AND across levels: the parent's cap blocks the child's keys even when the child's own
/// caps have headroom, and NOTHING is charged on a blocked admission (all-or-nothing).
#[test]
fn chain_and_parent_blocks_child_and_charges_nothing() {
    let g = gov();
    let cm = model(&[
        (
            "acme",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
            ),
        ),
        (
            "growth",
            group_cfg(
                Some("acme"),
                true,
                vec![limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute))],
            ),
        ),
    ]);
    let k = key("vk_child", Some("growth"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("1st");
    g.try_admit(&cm, &k, "", now).expect("2nd");
    // Parent cap (2) blocks despite the child's 100-cap headroom.
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "acme",
        "requests",
        Some("minute"),
        true,
    );
    // ALL-OR-NOTHING: the child's minute bucket holds exactly the 2 admitted charges (the
    // rejected attempt charged nothing anywhere).
    let child = g
        .derived_bucket_usage(&cm, "group:growth@minute", "minute", true, now)
        .unwrap();
    assert_eq!(child.requests, 2);
}

/// PHASE 1 runtime-mutation bridge (task #100): a per-user leaf ADDED at runtime via
/// `CostModel::with_groups` — the exact rebuild `build_with_group` performs on a `POST /groups` —
/// enforces exactly like a boot-resolved tree. The team ceiling ANDs ABOVE the leaf, so a generous
/// personal budget can never let the user spend past the team cap (the over-allocation SAFETY
/// property). Proves "self-issue a key / raise a budget at runtime" yields live, chain-correct
/// enforcement — the machinery the whole self-service story rests on.
#[test]
fn runtime_added_user_leaf_is_capped_by_the_team_ceiling() {
    let g = gov();
    // Boot-time tree: only the team ceiling exists (2 requests/min).
    let base = model(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
        ),
    )]);
    // Runtime add of `user:bob` under team with a DELIBERATELY LOOSER personal cap (5/min) — the map
    // build_with_group hands to with_groups after a self-mint / budget raise.
    let mut map: BTreeMap<String, GroupCfg> = BTreeMap::new();
    map.insert(
        "team".into(),
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
        ),
    );
    map.insert(
        "user:bob".into(),
        group_cfg(
            Some("team"),
            true,
            vec![limit(LimitMetric::Requests, 5, Some(LimitWindow::Minute))],
        ),
    );
    let cm = base.with_groups(&map);
    let k = key("vk_bob", Some("user:bob"));
    let now = 1_700_000_000;
    // Two admissions fit under the team ceiling; the third is blocked by TEAM, not bob's 5-cap —
    // the personal budget cannot exceed the shared team pool no matter how generously it's set.
    g.try_admit(&cm, &k, "", now).expect("1st");
    g.try_admit(&cm, &k, "", now).expect("2nd");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "team",
        "requests",
        Some("minute"),
        true,
    );
}

/// `enabled: false` FREEZES a group: every request through it (directly or via a descendant) is
/// rejected as Disabled, before anything is charged; history is kept.
#[test]
fn disabled_group_freezes_the_chain() {
    let g = gov();
    let build = |parent_enabled: bool| {
        model(&[
            (
                "parent",
                group_cfg(
                    None,
                    parent_enabled,
                    vec![limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute))],
                ),
            ),
            ("child", group_cfg(Some("parent"), true, vec![])),
        ])
    };
    let k = key("vk_frozen", Some("child"));
    let now = 1_700_000_000;
    // Accrue history under the enabled config first.
    let cm = build(true);
    g.try_admit(&cm, &k, "", now).expect("enabled admits");
    // Freeze the ANCESTOR: the child's keys are rejected too (freeze walks the chain).
    let frozen = build(false);
    match g.try_admit(&frozen, &k, "", now).unwrap_err() {
        LimitBlocked::Disabled(name) => assert_eq!(name, "parent"),
        other => panic!("expected Disabled, got {other:?}"),
    }
    // History kept: the parent's minute bucket still holds the pre-freeze charge.
    let hist = g
        .derived_bucket_usage(&frozen, "group:parent@minute", "minute", true, now)
        .unwrap();
    assert_eq!(hist.requests, 1, "freezing keeps history");
    // Unfreeze: admission resumes.
    g.try_admit(&build(true), &k, "", now)
        .expect("unfrozen admits");
}

/// A key with NO group is authed + UNLIMITED: every admission passes and only its own attribution
/// bucket is charged.
#[test]
fn key_with_no_group_is_unlimited() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_free", None);
    let now = 1_700_000_000;
    for _ in 0..100 {
        g.try_admit(&cm, &k, "", now).expect("no group = no caps");
    }
    let usage = g.usage_for(&cm, "vk_free", now).unwrap();
    // usage_for reads the store; the key was never persisted, so read the bucket directly.
    assert!(usage.is_none());
    let bucket = g
        .derived_bucket_usage(&cm, "vk_free", super::WINDOW_TOTAL, true, now)
        .unwrap();
    assert_eq!(bucket.requests, 100);
    // The configured (unrelated) group's buckets saw nothing.
    let other = g
        .derived_bucket_usage(&cm, "group:g@minute", "minute", true, now)
        .unwrap();
    assert_eq!(other.requests, 0);
}

/// A key bound to a group MISSING from this node's config fails CLOSED at admission.
#[test]
fn missing_group_fails_closed() {
    let g = gov();
    let cm = model(&[]);
    let k = key("vk_ghost", Some("ghost"));
    match g.try_admit(&cm, &k, "", 1_700_000_000).unwrap_err() {
        LimitBlocked::MissingGroup(name) => assert_eq!(name, "ghost"),
        other => panic!("expected MissingGroup, got {other:?}"),
    }
}

/// Accrual lands the SAME response's tokens on EVERY chain bucket (each window counts all
/// traffic), and hydrate restores each per-(group, window) bucket for its own current window.
#[test]
fn accrual_and_hydrate_cover_every_chain_bucket() {
    let store = Arc::new(MemoryStore::new());
    let g = GovState::new(store.clone(), None).unwrap();
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Budget, 1_000, Some(LimitWindow::Day)),
                    limit(LimitMetric::Budget, 10_000, Some(LimitWindow::Month)),
                ],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_acc", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("admits");
    g.record_usage(&cm, &k, "", "m", &toks(500, 0), now);
    for bucket in ["vk_acc", "group:g@day", "group:g@month"] {
        let window = if bucket == "vk_acc" {
            super::WINDOW_TOTAL
        } else if bucket.ends_with("@day") {
            super::WINDOW_DAY
        } else {
            super::WINDOW_MONTH
        };
        let u = g
            .derived_bucket_usage(&cm, bucket, window, true, now)
            .unwrap();
        assert_eq!(u.tokens, 500, "bucket {bucket} accrued the tokens");
    }
    // Flush to the store, then a FRESH GovState hydrates every bucket back.
    assert!(g.flush_budgets() >= 1);
    let g2 = GovState::new(store, None).unwrap();
    g2.hydrate_budgets(&cm, now).unwrap();
    let day = g2
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .unwrap();
    assert_eq!(day.tokens, 500, "hydrate restored the day bucket");
    let month = g2
        .derived_bucket_usage(&cm, "group:g@month", "month", true, now)
        .unwrap();
    assert_eq!(month.tokens, 500, "hydrate restored the month bucket");
}

/// Headroom derives from the CHAIN's requests/tokens limits: the tightest fraction wins; a chain
/// with no such limits reports None.
#[test]
fn rate_headroom_reads_the_chain() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 4, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_head", Some("g"));
    let now = 1_700_000_000;
    assert_eq!(
        g.rate_headroom(&cm, &k, None, now),
        Some(1.0),
        "untouched = full"
    );
    g.try_admit(&cm, &k, "", now).unwrap();
    g.try_admit(&cm, &k, "", now).unwrap();
    let h = g.rate_headroom(&cm, &k, None, now).unwrap();
    assert!((h - 0.5).abs() < 1e-9, "2 of 4 used = 0.5, got {h}");
    // No group = no limits = nothing to be near.
    assert_eq!(g.rate_headroom(&cm, &key("vk_none", None), None, now), None);
}

// ── pool-scoped limits (§6b: per-(group, pool) accounting) ───────────────────────────────────────

fn pooled(metric: LimitMetric, amount: u64, per: LimitWindow, pool: &str) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per: Some(per),
        pool: Some(pool.to_string()),
    }
}

/// The pool-split budget: `{ budget: 25, per: day, pool: frontier }` + the same for `value` on ONE
/// group account INDEPENDENTLY - exhausting the frontier budget blocks only frontier traffic (the
/// rejection names the pool), value traffic still admits against its own untouched bucket, and a
/// pool with no qualified limit is capped by neither.
#[test]
fn pool_scoped_budgets_account_independently() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    pooled(LimitMetric::Budget, 25, LimitWindow::Day, "frontier"),
                    pooled(LimitMetric::Budget, 25, LimitWindow::Day, "value"),
                ],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_ps", Some("team"));
    let now = 1_700_000_000;
    // fee=10: two frontier admissions spend 20; the 3rd would reach 30 > 25.
    g.try_admit(&cm, &k, "frontier", now).expect("frontier 1st");
    g.try_admit(&cm, &k, "frontier", now).expect("frontier 2nd");
    match g.try_admit(&cm, &k, "frontier", now).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("day"),
            pool: Some(pool),
            retry_after: Some(_),
        } => {
            assert_eq!(group, "team");
            assert_eq!(pool, "frontier", "the rejection names the exhausted pool");
        }
        other => panic!("expected the frontier budget to block, got {other:?}"),
    }
    // The value pool's own bucket is untouched: the dev's traffic downgrades, it is not locked out.
    g.try_admit(&cm, &k, "value", now).expect("value 1st");
    g.try_admit(&cm, &k, "value", now).expect("value 2nd");
    assert_blocked(
        g.try_admit(&cm, &k, "value", now).unwrap_err(),
        "team",
        "budget",
        Some("day"),
        true,
    );
    // A pool neither limit names is capped by neither bucket.
    g.try_admit(&cm, &k, "other", now)
        .expect("unqualified pool is not pool-capped");
}

/// A group-wide limit still ANDs across every pool: pool-scoped budgets carve the spend, the
/// group-wide `requests` ceiling counts ALL traffic regardless of pool.
#[test]
fn group_wide_limit_ands_with_pool_scoped() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Requests, 3, Some(LimitWindow::Day)),
                    pooled(LimitMetric::Budget, 100, LimitWindow::Day, "frontier"),
                ],
            ),
        )],
        1,
        &[],
    );
    let k = key("vk_gw", Some("team"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "frontier", now).expect("1st");
    g.try_admit(&cm, &k, "value", now)
        .expect("2nd (different pool, same requests ceiling)");
    g.try_admit(&cm, &k, "frontier", now).expect("3rd");
    assert_blocked(
        g.try_admit(&cm, &k, "value", now).unwrap_err(),
        "team",
        "requests",
        Some("day"),
        true,
    );
}

/// Accrual mirrors admission: tokens ledgered under pool A land ONLY in A's pool bucket, so they
/// exhaust A's budget without touching B's; and the REFUND of a pool-A admission erodes only the
/// buckets that admission charged.
#[test]
fn pool_scoped_accrual_and_refund_mirror_the_charge() {
    let g = gov();
    // 10 utok/token: 100_000 input tokens = 100 cents = AT a 100-cent cap. No flat fee.
    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    pooled(LimitMetric::Budget, 100, LimitWindow::Month, "frontier"),
                    pooled(LimitMetric::Budget, 100, LimitWindow::Month, "value"),
                ],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_pa", Some("team"));
    let now = 1_700_000_000;
    // Tokens served through the value pool fill ONLY value's bucket.
    g.record_usage(&cm, &k, "value", "m", &toks(100_000, 0), now);
    g.try_admit(&cm, &k, "frontier", now)
        .expect("frontier bucket is untouched by value-pool tokens");
    match g.try_admit(&cm, &k, "value", now).unwrap_err() {
        LimitBlocked::Limit {
            pool: Some(pool), ..
        } => assert_eq!(pool, "value"),
        other => panic!("expected value's budget to block, got {other:?}"),
    }
    // Refund mirror: a frontier admission's refund re-opens frontier, never value.
    let g2 = gov();
    let cm2 = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![pooled(
                    LimitMetric::Budget,
                    25,
                    LimitWindow::Day,
                    "frontier",
                )],
            ),
        )],
        10,
        &[],
    );
    g2.try_admit(&cm2, &k, "frontier", now).expect("1st");
    g2.try_admit(&cm2, &k, "frontier", now).expect("2nd");
    assert!(g2.try_admit(&cm2, &k, "frontier", now).is_err(), "at cap");
    g2.refund_request(&cm2, &k, "frontier", now);
    g2.try_admit(&cm2, &k, "frontier", now)
        .expect("the refunded fee re-opened frontier's bucket");
}
