use super::*;

/// Charge a non-streaming response's token usage to the virtual key's budget, sourced from the IR
/// (Change A). The streaming path bills from `translate.usage()` inside `FirstByteBody`; buffered
/// (non-streaming) cross-protocol responses already decode the egress body egress→IR→ingress, so the
/// terminal `IrUsage` is available WITHOUT a separate byte-scan — bill straight from `ir.usage`.
///
/// Billed tokens = the normalized billable total (A2): `uncached_input + cache_read +
/// cache_creation + output` (see [`crate::ir::IrUsage::billable_tokens`]). Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so this sum is correct
/// provider-agnostically. This matches the streaming billing arm.
/// OPERATION-BLIND usage recording: project the response IR's neutral `Billing` and record token
/// meters through the existing sink (identical numbers for chat — the Billing round-trip preserves
/// the additive-cache convention). Non-token meters (duration/characters/images/flat) are carried in
/// the client-visible body today and priced by the 1.3 engine; nothing to record here yet.
pub(crate) fn record_resp_usage(
    ir: &crate::ir::variant::IrResp,
    usage_sink: &Option<UsageSink>,
    lane: Option<(&str, &str)>,
) {
    if let Some(crate::billing::Billing::Tokens(t)) = ir.usage() {
        let usage = crate::ir::IrUsage {
            input_tokens: t.input,
            output_tokens: t.output,
            cache_creation_input_tokens: t.cache_creation,
            cache_read_input_tokens: t.cache_read,
        };
        record_ir_usage(&usage, usage_sink, lane);
    } else if let Some(sink) = usage_sink {
        // A delivered response with NO token usage (a flat-fee op, e.g. moderations) still METERS as
        // one request against the serving model — FinOps consumers count requests per model even
        // when nothing token-bills.
        if let Some((model, provider)) = lane {
            sink.gov
                .record_metering(&sink.key.id, model, provider, None, sink.charged_at);
        }
    }
}

/// `lane` is the SERVING lane's `(model, provider)` — the per-model metering attribution. `None`
/// (an unknown/unresolvable lane) still bills the budget but records no metering row.
pub(crate) fn record_ir_usage(
    usage: &crate::ir::IrUsage,
    usage_sink: &Option<UsageSink>,
    lane: Option<(&str, &str)>,
) {
    if let Some(sink) = usage_sink {
        // `billable_tokens` saturates internally — operands are UPSTREAM-CONTROLLED token counts, so
        // an unchecked `+` could panic on overflow in debug / wrap in release (#18). Saturates to
        // `u64::MAX`, matching the streaming path and the saturating `record_tokens` downstream.
        let tokens = usage.billable_tokens();
        if tokens > 0 {
            // Same window as the flat per-request fee (`sink.charged_at`, header-arrival epoch), so
            // the buffered-path token fee and the per-request fee never split across windows (#29).
            sink.gov.record_tokens(
                &sink.key.id,
                &sink.key.budget_period,
                sink.charged_at,
                tokens,
            );
        }
        // Metering (raw per-model consumption series) records the SPLIT — even a zero-token
        // delivered response counts its request. Same pinned epoch as the budget charges (#29).
        if let Some((model, provider)) = lane {
            sink.gov
                .record_metering(&sink.key.id, model, provider, Some(usage), sink.charged_at);
        }
    }
}

/// The bounded `pool` LABEL for an UPSTREAM/breaker metric (LOW #25).
///
/// The breaker-CELL key (`pool_name`) is `""` for the lane-default cell shared by every
/// direct/ad-hoc (single-model) route — that empty string is the correct CELL key and must NOT be
/// repointed (the cell identity drives breaker state, /stats, /healthz). But emitting it verbatim
/// as the `pool` metric LABEL mislabels all model-routed upstream traffic under an empty-string
/// series, whereas `REQUESTS_TOTAL` (via `ingress::pool_label`) labels the SAME request stream with
/// the MODEL name. That split makes upstream metrics impossible to correlate with the request
/// counter for non-pool traffic. Resolve the metric label to the routed lane's model name when the
/// cell key is empty, leaving named-pool traffic labeled by its pool name. This decouples the metric
/// label from the cell key WITHOUT touching the cell key itself.
pub(crate) fn metric_pool_label<'a>(app: &'a Arc<App>, pool_name: &'a str, i: usize) -> &'a str {
    if pool_name.is_empty() {
        app.lanes[i].model.as_str()
    } else {
        pool_name
    }
}

/// Emit `BREAKER_TRIPS_TOTAL` once for a logical Closed→Open trip on a (pool, lane) cell. Called from
/// the organic forward path's failure-record sites whenever `record_transient_in`/`record_rate_limit_in`
/// reports a fresh trip, mirroring the HardDown arm so threshold-based trips are counted too (#29). The
/// `pool` label is the bounded, operator-controlled canonical pool name, or the routed model name for
/// the default (`""`) cell (LOW #25; see `metric_pool_label`) so it correlates with REQUESTS_TOTAL.
pub(crate) fn emit_breaker_trip(app: &Arc<App>, pool_name: &str, i: usize) {
    crate::telemetry::breaker_trip(app, metric_pool_label(app, pool_name, i), i);
    tracing::warn!(pool = %pool_name, lane = %app.lanes[i].model, "lane breaker tripped (Closed→Open)");
}

/// The effective per-attempt time-to-response-headers cap for pool member `i`: the pool-member
/// override wins over the model-level default (`None` = uncapped). This is the layering the
/// feature promises — the SAME model can be `attempt_timeout_ms: 10000` in a batch pool and
/// `50` in a latency-critical pool, with the model-level value as the fallback for pools (and
/// the default `""` cell) that don't override it.
pub(crate) fn effective_attempt_timeout_ms(
    cands: &[crate::state::WeightedLane],
    i: usize,
    lane_default: Option<u64>,
) -> Option<u64> {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.attempt_timeout_ms)
        .or(lane_default)
}

/// The effective per-lane reasoning capability for pool member `i`: the pool-member override wins
/// over the model-level flag (same layering as `effective_attempt_timeout_ms`), default false —
/// a lane never receives thinking params unless some level of config claimed the capability.
pub(crate) fn effective_reasoning(
    cands: &[crate::state::WeightedLane],
    i: usize,
    lane_default: bool,
) -> bool {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.reasoning)
        .unwrap_or(lane_default)
}

/// Floor an `attempt_timeout_ms` cap by the request's remaining wall-clock budget (whole seconds),
/// so a per-attempt cap can never grant MORE time than the request has left — mirroring how the
/// reqwest transport timeout is budget-clamped. `.max(1)` keeps the cap non-zero on a nearly
/// exhausted budget (a zero-duration timeout would fail the attempt before it is even tried).
pub(crate) fn attempt_cap(ms: u64, remaining_secs: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms.min(remaining_secs.saturating_mul(1000).max(1)))
}
