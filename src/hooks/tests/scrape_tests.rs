//! Tests for the hook-metrics Prometheus renderer. Drive `render_text` directly (the pure half) so
//! the exposition format is asserted without a live hook or socket.

use super::*;
use std::collections::BTreeMap;

fn metric(name: &str, kind: &str, value: f64) -> HookMetric {
    HookMetric {
        name: name.to_string(),
        kind: kind.to_string(),
        value,
        labels: None,
        quantiles: None,
        estimated: None,
        ci_low: None,
        ci_high: None,
        help: None,
        label: None,
        unit: None,
        viz: None,
        max: None,
    }
}

fn labels(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

/// A counter renders with the verbatim name, an auto `hook` label, TYPE line, and the value.
#[test]
fn counter_renders_with_hook_label_and_verbatim_name() {
    let m = HookMetric {
        help: Some("tokens the hook saved".into()),
        labels: labels(&[("pool", "chat")]),
        ..metric("tokens_saved_total", "counter", 42.0)
    };
    let text = render_text(&[("headroom".to_string(), vec![m])]);
    assert!(text.contains("# TYPE tokens_saved_total counter"), "{text}");
    assert!(
        text.contains("# HELP tokens_saved_total tokens the hook saved"),
        "{text}"
    );
    // verbatim name + hook label FIRST + the hook's own label, exact value.
    assert!(
        text.contains("tokens_saved_total{hook=\"headroom\",pool=\"chat\"} 42\n"),
        "{text}"
    );
}

/// A histogram (quantiles) renders as a Prometheus SUMMARY: one line per quantile + `_count`.
#[test]
fn histogram_renders_as_summary() {
    let mut qs = BTreeMap::new();
    qs.insert("0.5".to_string(), 18.0);
    qs.insert("0.95".to_string(), 54.0);
    qs.insert("0.99".to_string(), 91.0);
    let m = HookMetric {
        quantiles: Some(qs),
        labels: labels(&[("pool", "chat")]),
        ..metric("compress_latency_us", "histogram", 1000.0)
    };
    let text = render_text(&[("headroom".to_string(), vec![m])]);
    assert!(
        text.contains("# TYPE compress_latency_us summary"),
        "{text}"
    );
    assert!(
        text.contains("compress_latency_us{hook=\"headroom\",pool=\"chat\",quantile=\"0.5\"} 18\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "compress_latency_us{hook=\"headroom\",pool=\"chat\",quantile=\"0.99\"} 91\n"
        ),
        "{text}"
    );
    // observation count from `value`
    assert!(
        text.contains("compress_latency_us_count{hook=\"headroom\",pool=\"chat\"} 1000\n"),
        "{text}"
    );
}

/// A hook cannot impersonate a first-party series: `busbar_`-prefixed names are dropped.
#[test]
fn busbar_prefix_is_reserved() {
    let text = render_text(&[(
        "evil".to_string(),
        vec![
            metric("busbar_engine_requests_total", "counter", 9.0),
            metric("legit_total", "counter", 1.0),
        ],
    )]);
    assert!(
        !text.contains("busbar_engine_requests_total"),
        "reserved name must be dropped: {text}"
    );
    assert!(text.contains("legit_total{hook=\"evil\"} 1\n"), "{text}");
}

/// Two hooks emitting the SAME metric name share one HELP/TYPE header and are separated only by the
/// `hook` label — the dimensional model that lets a dashboard query the bare name across hooks or
/// filter to one.
#[test]
fn two_hooks_same_name_share_header_split_by_label() {
    let a = (
        "hook_a".to_string(),
        vec![metric("proxy_compression_ratio_by_strategy", "gauge", 0.4)],
    );
    let b = (
        "hook_b".to_string(),
        vec![metric("proxy_compression_ratio_by_strategy", "gauge", 0.6)],
    );
    let text = render_text(&[a, b]);
    // exactly one TYPE line for the shared name
    assert_eq!(
        text.matches("# TYPE proxy_compression_ratio_by_strategy")
            .count(),
        1,
        "one TYPE header per name: {text}"
    );
    assert!(
        text.contains("proxy_compression_ratio_by_strategy{hook=\"hook_a\"} 0.4\n"),
        "{text}"
    );
    assert!(
        text.contains("proxy_compression_ratio_by_strategy{hook=\"hook_b\"} 0.6\n"),
        "{text}"
    );
}

/// A same-name entry of a DIFFERENT type is dropped (Prometheus forbids mixing types per name), so
/// the exposition stays valid rather than breaking the whole scrape.
#[test]
fn type_conflict_for_shared_name_is_dropped() {
    let a = ("a".to_string(), vec![metric("shared", "counter", 1.0)]);
    let b = ("b".to_string(), vec![metric("shared", "gauge", 2.0)]);
    let text = render_text(&[a, b]);
    assert_eq!(
        text.matches("# TYPE shared").count(),
        1,
        "one type only: {text}"
    );
    assert!(text.contains("# TYPE shared counter"), "first wins: {text}");
    // the gauge entry (b) is dropped; only the counter (a) renders
    assert!(text.contains("shared{hook=\"a\"} 1\n"), "{text}");
    assert!(
        !text.contains("hook=\"b\""),
        "conflicting-type entry dropped: {text}"
    );
}

/// Label values are Prometheus-escaped (quote / backslash / newline) so a value can't break the line.
#[test]
fn label_values_are_escaped() {
    let m = HookMetric {
        labels: labels(&[("k", "a\"b\\c")]),
        ..metric("x_total", "counter", 1.0)
    };
    let text = render_text(&[("h".to_string(), vec![m])]);
    assert!(text.contains(r#"k="a\"b\\c""#), "{text}");
}
