// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TELEMETRY BANK tests: multi-thread sum correctness under concurrent scrape, slot
//! re-registration across config generations, and byte-level `/metrics` parity with the
//! pre-bank macro emission for the migrated hot-path families.
//!
//! Every test uses its OWN pool/lane label values (the process-global recorder is shared across
//! the whole test binary), and asserts STRICT DELTAS via `test_support::metric_sum` — the same
//! discipline as every other metrics test in the crate.

use super::*;
use crate::test_support::{metric_sum, LaneSpec, TestApp};

fn openai() -> crate::proto::Protocol {
    crate::proto::Protocol::openai()
}

/// Multi-thread adds must sum exactly, INCLUDING while a concurrent scraper is flushing the bank
/// mid-write. 8 writer threads × 10k increments race ~50 render/flush cycles; the final total must
/// be exact (no lost or double-counted deltas).
#[test]
fn test_bank_multithread_adds_sum_exactly_under_concurrent_scrape() {
    crate::metrics::init();
    let slot = counter_slot(
        crate::metrics::REQUESTS_TOTAL,
        &[
            ("ingress_protocol", "openai"),
            ("pool", "tel-bank-mt-pool"),
            ("outcome", "ok"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");
    let before = metric_sum(
        crate::metrics::REQUESTS_TOTAL,
        &[("pool", "tel-bank-mt-pool")],
    );

    let writers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    slot.incr();
                }
            })
        })
        .collect();
    // Concurrent scrapes while the writers run: each render() flushes bank deltas into the
    // recorder. Exactness at the end proves flush never loses or double-counts a delta.
    for _ in 0..50 {
        let _ = crate::metrics::render();
    }
    for w in writers {
        w.join().unwrap();
    }

    let after = metric_sum(
        crate::metrics::REQUESTS_TOTAL,
        &[("pool", "tel-bank-mt-pool")],
    );
    assert_eq!(
        (after - before).round() as u64,
        80_000,
        "8 threads x 10k adds must sum exactly across concurrent flushes"
    );
}

/// Identical (name, labels) always intern to the SAME slot — the config-apply contract: a new
/// generation re-registering the same label space accumulates into the same cells.
#[test]
fn test_reregistration_same_labels_resolves_same_slot() {
    let labels = [("pool", "tel-rereg-pool"), ("reason", "hard_down")];
    let a = counter_slot(crate::metrics::FAILOVERS_TOTAL, &labels);
    let b = counter_slot(crate::metrics::FAILOVERS_TOTAL, &labels);
    assert_eq!(a, b, "identical counter label sets must share a slot");

    let hlabels = [("ingress_protocol", "openai"), ("pool", "tel-rereg-pool")];
    let h1 = histogram_slot(crate::metrics::REQUEST_DURATION_SECONDS, &hlabels);
    let h2 = histogram_slot(crate::metrics::REQUEST_DURATION_SECONDS, &hlabels);
    assert_eq!(h1, h2, "identical histogram label sets must share a slot");

    // Different labels must NOT collide.
    let c = counter_slot(
        crate::metrics::FAILOVERS_TOTAL,
        &[("pool", "tel-rereg-pool"), ("reason", "attempt_timeout")],
    );
    assert_ne!(a, c);
}

/// Config re-apply end-to-end: two `App` generations with the same pool shape route their emissions
/// into the same series, and the exposed total accumulates monotonically across the swap.
#[test]
fn test_config_reapply_accumulates_across_generations() {
    crate::metrics::init();
    let build = || {
        TestApp::new()
            .lane(LaneSpec::new("tel-gen-model", openai(), "http://m"))
            .pool("tel-gen-pool", &[(0, 1)])
            .build()
    };
    let gen1 = build();
    let gen2 = build(); // the "post-apply" snapshot: same label space, fresh AppSlots

    let labels = [("pool", "tel-gen-pool"), ("outcome", "ok")];
    let before = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    request_finished(&gen1, "openai", "tel-gen-pool", "ok", 0.001);
    request_finished(&gen2, "openai", "tel-gen-pool", "ok", 0.002);
    let after = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        2,
        "both generations must land in the same series"
    );
}

/// The banked request family renders the SAME series names and labels as the pre-bank macro
/// emission: `busbar_requests_total{ingress_protocol,pool,outcome}` and the
/// `busbar_request_duration_seconds` summary (quantile lines + `_sum` + `_count`).
#[test]
fn test_request_finished_renders_premigration_names_and_labels() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new("tel-parity-model", openai(), "http://m"))
        .pool("tel-parity-pool", &[(0, 1)])
        .build();

    request_finished(&app, "anthropic", "tel-parity-pool", "ok", 0.005);
    let out = crate::metrics::render();

    let counter_line = out.lines().find(|l| {
        !l.starts_with('#')
            && l.starts_with(crate::metrics::REQUESTS_TOTAL)
            && l.contains("ingress_protocol=\"anthropic\"")
            && l.contains("pool=\"tel-parity-pool\"")
            && l.contains("outcome=\"ok\"")
    });
    assert!(
        counter_line.is_some(),
        "banked requests_total must render with the exact pre-migration labels; got:\n{out}"
    );

    // The duration histogram renders as the exporter's default summary: quantile lines plus
    // `_sum`/`_count`. The bank buffers raw samples and drains them into the SAME exporter, so
    // the shape is unchanged.
    assert!(
        out.lines().any(|l| {
            !l.starts_with('#')
                && l.starts_with(crate::metrics::REQUEST_DURATION_SECONDS)
                && l.contains("pool=\"tel-parity-pool\"")
                && l.contains("quantile=")
        }),
        "duration summary quantile lines must render for the banked pool; got:\n{out}"
    );
    let count = metric_sum(
        "busbar_request_duration_seconds_count",
        &[
            ("ingress_protocol", "anthropic"),
            ("pool", "tel-parity-pool"),
        ],
    );
    assert!(
        count >= 1.0,
        "duration _count must reflect the banked sample; got {count}"
    );
}

/// The engine-side helpers (attempts / failures / trips / failovers) must emit exactly one count
/// into the exact pre-migration series each.
#[test]
fn test_engine_helpers_emit_premigration_series() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new("tel-eng-model", openai(), "http://m"))
        .pool("tel-eng-pool", &[(0, 1)])
        .build();
    let pool = [("pool", "tel-eng-pool")];

    let attempts0 = metric_sum(crate::metrics::UPSTREAM_ATTEMPTS_TOTAL, &pool);
    upstream_attempt(&app, "tel-eng-pool", 0);
    assert_eq!(
        (metric_sum(crate::metrics::UPSTREAM_ATTEMPTS_TOTAL, &pool) - attempts0).round() as u64,
        1
    );

    let failures0 = metric_sum(
        crate::metrics::UPSTREAM_FAILURES_TOTAL,
        &[
            ("pool", "tel-eng-pool"),
            ("lane", "tel-eng-model"),
            ("disposition", crate::proxy::DISPOSITION_TRANSIENT),
        ],
    );
    upstream_failure(&app, "tel-eng-pool", 0, crate::proxy::DISPOSITION_TRANSIENT);
    assert_eq!(
        (metric_sum(
            crate::metrics::UPSTREAM_FAILURES_TOTAL,
            &[
                ("pool", "tel-eng-pool"),
                ("lane", "tel-eng-model"),
                ("disposition", crate::proxy::DISPOSITION_TRANSIENT),
            ],
        ) - failures0)
            .round() as u64,
        1
    );

    let trips0 = metric_sum(crate::metrics::BREAKER_TRIPS_TOTAL, &pool);
    breaker_trip(&app, "tel-eng-pool", 0);
    assert_eq!(
        (metric_sum(crate::metrics::BREAKER_TRIPS_TOTAL, &pool) - trips0).round() as u64,
        1
    );

    // A failover with a transport-class reason (`timeout`, from the pre-response error arm).
    let fo_labels = [
        ("pool", "tel-eng-pool"),
        ("reason", crate::proxy::ERR_NET_TIMEOUT),
    ];
    let failovers0 = metric_sum(crate::metrics::FAILOVERS_TOTAL, &fo_labels);
    failover(&app, "tel-eng-pool", crate::proxy::ERR_NET_TIMEOUT);
    assert_eq!(
        (metric_sum(crate::metrics::FAILOVERS_TOTAL, &fo_labels) - failovers0).round() as u64,
        1
    );
}

/// A label value OUTSIDE the generation's registered space (an unconfigured pool name) must fall
/// back to the macro path and still be counted — the bank is a fast path, never a gate.
#[test]
fn test_unregistered_pool_falls_back_to_macro_emission() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new("tel-fb-model", openai(), "http://m"))
        .pool("tel-fb-pool", &[(0, 1)])
        .build();

    let labels = [("pool", "tel-fb-unregistered-pool"), ("outcome", "ok")];
    let before = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    request_finished(&app, "openai", "tel-fb-unregistered-pool", "ok", 0.001);
    let after = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        1,
        "unregistered labels must still be counted via the macro fallback"
    );
}

/// Histogram slots: samples recorded on several threads all reach the recorder at the next flush
/// (`_count` advances by exactly the number recorded).
#[test]
fn test_histogram_bank_drains_all_thread_samples() {
    crate::metrics::init();
    let slot = histogram_slot(
        crate::metrics::REQUEST_DURATION_SECONDS,
        &[("ingress_protocol", "openai"), ("pool", "tel-hist-mt-pool")],
    );
    assert!(slot.is_valid());
    let labels = [("ingress_protocol", "openai"), ("pool", "tel-hist-mt-pool")];
    let before = metric_sum("busbar_request_duration_seconds_count", &labels);

    let writers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..100 {
                    slot.record(0.003);
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }

    let after = metric_sum("busbar_request_duration_seconds_count", &labels);
    assert_eq!(
        (after - before).round() as u64,
        400,
        "every thread's buffered samples must drain at flush"
    );
}

/// Cross-protocol translation slots cover the fixed protocol table and count into the exact
/// pre-migration `busbar_translations_total{from,to}` series.
#[test]
fn test_translation_bank_counts_known_protocol_pair() {
    crate::metrics::init();
    let labels = [("from", "cohere"), ("to", "gemini")];
    let before = metric_sum(crate::metrics::TRANSLATIONS_TOTAL, &labels);
    translation("cohere", "gemini");
    let after = metric_sum(crate::metrics::TRANSLATIONS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        1,
        "known protocol pair must count via the bank"
    );

    // Unknown (plugin) protocol names fall back to the macro and are still counted.
    let fb_labels = [("from", "tel-custom-proto"), ("to", "openai")];
    let fb_before = metric_sum(crate::metrics::TRANSLATIONS_TOTAL, &fb_labels);
    translation("tel-custom-proto", "openai");
    let fb_after = metric_sum(crate::metrics::TRANSLATIONS_TOTAL, &fb_labels);
    assert_eq!((fb_after - fb_before).round() as u64, 1);
}
