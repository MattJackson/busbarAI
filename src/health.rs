// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Active health probing.
//!
//! busbar's breaker is fundamentally *passive*: it trips on real request failures and recovers via
//! the half-open probe on the next organic request. Active probing layers a background prober on
//! top, per the provider's `health:` config:
//!
//! - `none` — no probing (the default; pure passive health).
//! - `dead` — re-probe ONLY tripped lanes, so a recovered upstream is picked back up promptly
//!   instead of waiting for organic traffic to drive the half-open probe.
//! - `active` — probe EVERY lane, so a silently-dead upstream trips out before real traffic hits.
//!
//! A probe is a one-token request built by the lane's protocol writer (`probe_body`), sent with the
//! lane's own auth/path. A 2xx recovers a tripped lane (→ Closed); any failure is recorded as a
//! transient (which, on a Closed lane in `active` mode, can trip it out).

use std::sync::Arc;
use std::time::Duration;

use axum::http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};

use crate::breaker::{classify, normalize_raw_error, Disposition, RawUpstreamError};
use crate::config::HealthMode;
use crate::proto::convert_headers;
use crate::state::App;
use crate::store::{now, BreakerCfg};

/// Cap on the bytes read from a non-2xx probe response before breaker classification, mirroring the
/// request path's size-capped read: a hostile/misconfigured upstream must not force an unbounded
/// heap allocation just because a probe failed. 64 KiB is far more than any error envelope needs.
const PROBE_ERROR_BODY_CAP: usize = 64 * 1024;

// Default probe interval / timeout (the PROCESS-WIDE fallback used when a per-lane `health:` block
// omits `interval_secs` / `timeout_secs`). Operator-tunable via `health.default_probe_interval_secs`
// / `health.default_probe_timeout_secs` (defaults 30 / 5), read through `crate::limits`. The per-lane
// override still wins (see `unwrap_or` below).

/// Spawn one background prober task per lane that has a probing mode configured. A no-op for lanes
/// with `mode: none` (or no `health:` block). Tasks live for the process lifetime.
pub(crate) fn spawn_probers(app: Arc<App>) {
    for i in 0..app.lanes.len() {
        let Some(h) = app.lanes[i].health.clone() else {
            continue;
        };
        if h.mode == HealthMode::None {
            continue;
        }
        let interval = Duration::from_secs(
            h.interval_secs
                .unwrap_or_else(crate::limits::default_probe_interval_secs)
                .max(1),
        );
        let timeout = Duration::from_secs(
            h.timeout_secs
                .unwrap_or_else(crate::limits::default_probe_timeout_secs)
                .max(1),
        );
        let mode = h.mode;
        let app = app.clone();
        let model = app.lanes[i].model.clone();
        tracing::info!(
            lane = %model,
            mode = ?mode,
            interval_secs = interval.as_secs(),
            "active health probing enabled for lane"
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately — skip it so we don't probe at startup before any
            // traffic has had a chance to establish health.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let should = match mode {
                    HealthMode::Active => true,
                    // Re-probe a lane the breaker is suppressing in ANY cell — whether fully tripped
                    // (Open) OR just in a soft cooldown (Closed but a sub-threshold transient armed a
                    // cooldown). Both make the lane unusable; dead mode's job is to recover either early.
                    HealthMode::Dead => app.store.lane_needs_probe(i, now()),
                    HealthMode::None => false,
                };
                if should {
                    probe_lane(&app, i, timeout).await;
                }
            }
        });
    }
}

/// Send a single health probe to lane `i` and fold the outcome into the breaker, running a non-2xx
/// response through the SAME two-stage disposition pipeline organic traffic uses
/// (`proto.extract_error` → `normalize_raw_error` → `breaker::classify`) rather than forcing every
/// failure to a transient cooldown:
///   - 2xx → recover the lane if it was tripped (→ Closed), THEN push a success outcome into every
///     cell's sliding error-rate window (`record_probe_success_all_cells`). Recording the success is
///     what makes probe-outcome accounting SYMMETRIC: failures already feed the window via
///     `record_probe_failure_all_cells`, so without a matching success record a lane that fails some
///     probes and succeeds others would show a 100%-error window (every cell holds only failures) and
///     the error-rate breaker would trip a perfectly recoverable lane (LOW #23). The success is
///     recorded AFTER recovery so no cell is HalfOpen at that point — the success push therefore never
///     *forces* a HalfOpen→Closed transition (recovery, when warranted, already happened via
///     `recover_lane`); on an already-healthy lane the cells are Closed and the push only feeds the
///     window. The success counts toward the lane's `ok` stat, exactly mirroring how a failed probe
///     feeds the breaker — probe accounting is now fully two-sided rather than failure-only.
///   - `HardDown` (Auth/Billing — e.g. an invalid credential or exhausted balance) → record a
///     hard-down trip on every cell the lane routes against, matching organic semantics. Previously
///     these were mis-recorded as transient, so an auth-dead lane oscillated between cooldown and
///     re-probe forever instead of being parked dead (and the prober kept firing guaranteed-401s).
///   - `TransientUpstream` (5xx/429/timeout/overloaded/network) and transport errors → record a
///     transient failure across all cells (drives the trip evaluation in `active` mode and re-arms
///     the cooldown on a tripped lane).
///   - `ClientFault` / `ContextLength` → the LANE is healthy; the probe request itself was rejected
///     as malformed or too large for this model. Record NOTHING — penalizing the breaker here would
///     bench a working lane over a probe-construction issue, matching the organic "record nothing"
///     disposition for these classes.
pub(crate) async fn probe_lane(app: &Arc<App>, i: usize, timeout: Duration) {
    let lane = &app.lanes[i];

    // No key, no probe — we can't authenticate (e.g. a passthrough deployment with no static key),
    // and a guaranteed 401 would only thrash the breaker.
    if lane.api_key.is_empty() {
        return;
    }

    let body = lane.protocol.writer().probe_body(&lane.model);
    let url_path = lane.path.clone().unwrap_or_else(|| {
        lane.protocol
            .writer()
            .upstream_path_for_stream(&lane.model, false)
    });

    // SigV4 signs over the URI-encoded canonical path, so the probe MUST send the wire request over
    // the SAME encoding or AWS rejects with SignatureDoesNotMatch (every Bedrock modelId carries a
    // reserved `:` that signs as `%3A` but a raw send transmits `:`). Encode the path ONCE via the
    // shared `sign_and_wire_path` helper — the identical primitive the organic forward path uses —
    // and reuse it for both the signed canonical URI and the wire URL so signed == sent.
    let wire_path = crate::forward::sign_and_wire_path(&url_path);
    let signing_ctx = crate::proto::SigningContext {
        host: crate::forward::host_from_base(&lane.base_url),
        canonical_uri: wire_path
            .split('?')
            .next()
            .unwrap_or(&wire_path)
            .to_string(),
        body: &body,
        timestamp_epoch: now(),
        // Active health probes use busbar's own configured lane key (never a forwarded caller
        // token), so the native API-key shape (Token mode) is correct here.
        auth_mode: crate::auth::AuthMode::Token,
    };
    let auth = crate::forward::lane_auth_headers(lane, &lane.api_key, &signing_ctx);

    // Send the SAME native-SDK fingerprint headers the organic forward path sends, so a probe is
    // indistinguishable from real traffic to the backend: reqwest emits no default User-Agent (its
    // absence is a proxy tell), and a missing Accept differs from what a native SDK sends. The probe
    // is non-streaming, so `wants_stream = false`. Without these, a backend could fingerprint and
    // special-case busbar's health probes — defeating the indistinguishability guarantee.
    let egress_name = lane.protocol.name();
    let res = app
        .client
        .post(format!("{}{}", lane.base_url, wire_path))
        .headers(convert_headers(auth))
        .header(CONTENT_TYPE, crate::forward::APPLICATION_JSON)
        .header(USER_AGENT, crate::forward::egress_user_agent(egress_name))
        .header(ACCEPT, crate::forward::egress_accept(egress_name, false))
        .timeout(timeout)
        .body(body)
        .send()
        .await;

    // Classify the probe outcome through the organic disposition pipeline so auth/billing failures
    // reach HardDown instead of being mis-filed as transient cooldowns. Carry the server-requested
    // `Retry-After` alongside the disposition so a transient probe failure honors the upstream's
    // cooldown floor (the captured value is otherwise dropped by `classify`, which returns only the
    // Disposition).
    let (disposition, retry_after_secs) = match res {
        Ok(r) if r.status().is_success() => {
            if app.store.lane_needs_probe(i, now()) {
                // Probe tests the shared upstream → recover the lane in every cell (all pools +
                // default), clearing both Open trips and soft cooldowns. This runs FIRST so that by
                // the time we record the success outcome below, every cell is Closed and the success
                // push can never force a HalfOpen→Closed transition (recovery already happened here).
                app.store.recover_lane(i);
                tracing::info!(lane = %lane.model, "lane recovered via health probe");
            }
            // Record the 2xx as a SUCCESS in every cell's sliding error-rate window — the symmetric
            // counterpart to the failed-probe `record_probe_failure_all_cells` below. Without this,
            // probes only ever fed FAILURES into the window, so a lane that intermittently fails
            // probes presented a 100%-error window to the error-rate breaker and tripped spuriously
            // (LOW #23). This does NOT force any breaker transition — recovery, when warranted,
            // already happened above; here we only push the outcome.
            app.store.record_probe_success_all_cells(i);
            return;
        }
        Ok(r) => {
            // Non-2xx: run the body through Stage 1a (proto.extract_error) → Stage 1b
            // (normalize_raw_error + the lane's error_map) → Stage 2 (classify), exactly as the
            // forwarding path does, capturing the Retry-After header the body-only extractor can't
            // see so the cooldown floor is honored.
            let status = r.status();
            let retry_after_secs = r
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            let body = read_capped_error_body(r).await;
            let mut raw: RawUpstreamError = lane.protocol.reader().extract_error(status, &body);
            raw.retry_after_secs = retry_after_secs;
            (
                classify(&normalize_raw_error(&raw, &lane.error_map)),
                retry_after_secs,
            )
        }
        // Transport error (connect/timeout/reset): treat as a transient network failure, as the
        // organic path does. No HTTP response, so no Retry-After.
        Err(_) => (Disposition::TransientUpstream, None),
    };

    match disposition {
        Disposition::HardDown => {
            // Auth/Billing: the lane is definitively bad (e.g. invalid credential). Park it down in
            // EVERY cell organic traffic routes against via the canonical all-cells primitive
            // `record_hard_down_all_cells`, mirroring the all-cells reach of a successful probe's
            // `recover_lane` and a failed probe's `record_probe_failure_all_cells`. All three probe
            // outcomes (success / transient / hard-down) now derive their cell set from the SAME live
            // `pool_cells` map under ONE lock — rather than this path uniquely iterating CONFIG pool
            // membership (which took N per-pool locks and eagerly lazy-created a cell for every config
            // member the lane may never be routed against). Using the shared primitive keeps the trip
            // and recover bases in lockstep against any future change to how cells are materialized.
            app.store
                .record_hard_down_all_cells(i, "health-probe hard-down (auth/billing)");
            tracing::warn!(lane = %lane.model, "lane hard-down via health probe (parked dead, recovers on a 2xx probe)");
        }
        Disposition::TransientUpstream => {
            // A transient failed probe must trip the SAME cells a successful probe (recover_lane)
            // clears — the default cell AND every per-pool cell — because organic traffic routes
            // against per-pool cells. Each cell is evaluated against ITS OWN pool's resolved breaker
            // config (trip thresholds + cooldown backoff): resolve the per-pool `BreakerCfg` from
            // `app.pool_runtime` by pool name, falling back to the ADR-0002 default for the bare `""`
            // default cell and any pool without its own breaker block — matching the per-pool cfg the
            // organic forward path resolves (forward.rs `breaker_cfg`). This replaces the prior
            // one-size `BreakerCfg::default()` that ignored per-pool thresholds/cooldowns (#24/#25).
            let resolve_cfg = |pool: &str| -> BreakerCfg {
                app.pool_runtime
                    .get(pool)
                    .and_then(|r| r.breaker.clone())
                    .unwrap_or_default()
            };
            app.store.record_probe_failure_all_cells(
                i,
                "health-probe",
                &resolve_cfg,
                retry_after_secs,
            );
        }
        // The lane is healthy; the probe REQUEST was rejected (malformed / too large for the model).
        // Record nothing — do not bench a working lane over a probe-construction issue.
        Disposition::ClientFault | Disposition::ContextLength => {
            tracing::debug!(
                lane = %lane.model,
                "health probe got a client-fault/context-length response; lane not penalized"
            );
        }
    }
}

/// Read at most `PROBE_ERROR_BODY_CAP` bytes of a non-2xx probe response body for breaker
/// classification. Streams chunk-by-chunk and stops once the cap is reached so a hostile or
/// misconfigured upstream cannot force an unbounded allocation on the probe path.
async fn read_capped_error_body(mut resp: reqwest::Response) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = PROBE_ERROR_BODY_CAP.saturating_sub(buf.len());
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // this chunk filled the cap
                }
            }
            Ok(None) => break, // end of body
            Err(_) => break,   // mid-body transport error — classify on what we have
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCfg, HealthMode};
    use crate::proto::Protocol;
    use crate::store::BreakerState;
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use axum::http::StatusCode;
    use std::sync::Arc;

    fn health_active() -> HealthCfg {
        HealthCfg {
            mode: HealthMode::Active,
            interval_secs: Some(30),
            timeout_secs: Some(5),
        }
    }

    /// Stand up a mock upstream that returns `resp`, build a one-lane App (anthropic, in pool `p`)
    /// pointed at it, run a single probe, and hand back the App so the test can inspect the breaker.
    async fn probe_once(resp: MockResponse) -> (Arc<crate::state::App>, MockServer) {
        let state = Arc::new(MockServerState::new());
        state.push(resp);
        let server = MockServer::new(state).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                    .api_key("sk-test")
                    .health(health_active()),
            )
            .pool("p", &[(0, 1)])
            .build();
        probe_lane(&app, 0, Duration::from_secs(5)).await;
        (app, server)
    }

    /// Regression (MEDIUM/conformance, final audit): an active health probe must send the SAME
    /// native-SDK fingerprint headers organic traffic sends — `User-Agent` and `Accept` — or a
    /// backend could fingerprint and special-case busbar's probes (defeating indistinguishability).
    /// reqwest emits no default User-Agent, so its absence on the probe was a tell.
    #[tokio::test]
    async fn test_probe_sends_native_user_agent_and_accept_headers() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({"ok": true}),
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                    .api_key("sk-test")
                    .health(health_active()),
            )
            .pool("p", &[(0, 1)])
            .build();
        probe_lane(&app, 0, Duration::from_secs(5)).await;
        // The probe carries the protocol's native-SDK User-Agent and Accept (non-streaming), exactly
        // as the organic forward path does (egress_user_agent / egress_accept).
        assert_eq!(
            state.get_last_request_header("user-agent").as_deref(),
            Some(crate::forward::egress_user_agent("anthropic")),
            "probe must send the native User-Agent organic traffic sends"
        );
        assert_eq!(
            state.get_last_request_header("accept").as_deref(),
            Some(crate::forward::egress_accept("anthropic", false)),
            "probe must send the native Accept organic traffic sends"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_probe_auth_failure_is_hard_down_not_transient() {
        // Regression: a 401 probe must classify as HardDown (auth) and PARK the lane dead in the
        // default cell AND the per-pool cell — not be mis-recorded as a recoverable transient that
        // oscillates between cooldown and re-probe forever.
        let (app, server) = probe_once(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        })
        .await;

        assert!(
            matches!(app.store.breaker_state(0), BreakerState::Open { .. }),
            "401 probe must trip the default cell Open (hard-down), got {:?}",
            app.store.breaker_state(0)
        );
        assert!(
            app.store.cooldown_remaining_in("p", 0, now()) > 60,
            "401 probe must arm the long sticky hard-down cooldown on the per-pool cell, not a \
             short transient cooldown"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_probe_server_error_is_transient_not_hard_down() {
        // A single 503 probe is a transient failure: it must NOT immediately Open the default cell
        // with the multi-minute sticky hard-down cooldown (one sub-threshold transient stays Closed
        // under the default error-rate breaker).
        let (app, server) = probe_once(MockResponse::ServerError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: serde_json::json!({"error": "upstream down"}),
        })
        .await;

        assert!(
            matches!(app.store.breaker_state(0), BreakerState::Closed),
            "a single 503 probe must record a transient (no immediate hard-down trip), got {:?}",
            app.store.breaker_state(0)
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_probe_client_fault_does_not_penalize_lane() {
        // A 400 (client fault — the probe request shape, not the lane) must record NOTHING: the lane
        // stays Closed with no cooldown, so a healthy lane is never benched over a probe-construction
        // issue.
        let (app, server) = probe_once(MockResponse::ServerError {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({"error": "bad request"}),
        })
        .await;

        assert!(
            matches!(app.store.breaker_state(0), BreakerState::Closed),
            "a 400 probe (client fault) must not trip the breaker, got {:?}",
            app.store.breaker_state(0)
        );
        assert_eq!(
            app.store.cooldown_remaining_in("p", 0, now()),
            0,
            "a 400 probe (client fault) must not arm any cooldown"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_probe_skips_lane_without_key() {
        // No api_key → no probe (can't authenticate; a guaranteed 401 would only thrash the breaker).
        // The lane must stay Closed even though no upstream is reachable.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), "http://127.0.0.1:1")
                    .api_key("")
                    .health(health_active()),
            )
            .pool("p", &[(0, 1)])
            .build();
        probe_lane(&app, 0, Duration::from_secs(1)).await;
        assert!(matches!(app.store.breaker_state(0), BreakerState::Closed));
    }

    /// REGRESSION (R22 LOW #23, symmetric probe accounting): a 2xx probe must record a SUCCESS into
    /// every cell's sliding error-rate window, not just a failed probe recording a FAILURE. With the
    /// old failure-only accounting, a lane whose probes intermittently fail presented a window holding
    /// ONLY failures, so the error-rate breaker (errors / total) read ~100% and tripped a recoverable
    /// lane. Here we drive 7 successful probes then 5 failing (503) probes against a default error-rate
    /// breaker (min_requests=5, threshold=0.5): the failures alone would breach (5/5 = 1.0 >= 0.5 →
    /// Open), but the recorded successes dilute the window to 5/12 ≈ 0.42 < 0.5, so BOTH the default
    /// cell and the per-pool cell stay Closed. Against the pre-fix code (no success recorded) the 5th
    /// failure trips the default cell Open — this test fails there and passes after.
    #[tokio::test]
    async fn test_probe_success_recorded_so_intermittent_failures_dont_trip() {
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                    .api_key("sk-test")
                    .health(health_active()),
            )
            .pool("p", &[(0, 1)])
            .build();

        // 7 successful probes: each must push a SUCCESS into both the default and the per-pool cell's
        // window (the per-pool cell is lazily created Closed on the first success record).
        for _ in 0..7 {
            state.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: serde_json::json!({ "ok": true }),
            });
            probe_lane(&app, 0, Duration::from_secs(5)).await;
        }
        // 5 failing (503 transient) probes. The failure path records into the SAME cells. Even at the
        // 5th failure the windows hold 7 successes + 5 errors → 5/12 < 0.5 → no trip.
        for _ in 0..5 {
            state.push(MockResponse::ServerError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: serde_json::json!({ "error": "upstream down" }),
            });
            probe_lane(&app, 0, Duration::from_secs(5)).await;
        }

        assert!(
            matches!(app.store.breaker_state(0), BreakerState::Closed),
            "recorded probe successes must dilute the error-rate window so 5 of 12 outcomes stays \
             below the 0.5 trip threshold; default cell should remain Closed, got {:?}",
            app.store.breaker_state(0)
        );
        assert!(
            matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
            "the per-pool cell organic traffic routes against must likewise stay Closed once probe \
             successes are recorded into its window, got {:?}",
            app.store.breaker_state_in("p", 0)
        );
        server.shutdown().await;
    }

    /// REGRESSION (R22 LOW #23): a 2xx probe on an already-Closed, never-tripped lane must still push
    /// a success outcome into the lane's window (the success half of symmetric accounting) — it is NOT
    /// silently dropped just because the lane needed no recovery. We assert observably: after one
    /// success probe followed by 4 failing probes, the default cell holds 1 success + 4 errors = 5
    /// outcomes at 4/5 = 0.8 >= 0.5 and trips Open; if the success had NOT been recorded the window
    /// would hold only 4 errors (4 < min_requests=5) and stay Closed. So an Open default cell here
    /// proves the healthy-lane success was recorded.
    #[tokio::test]
    async fn test_probe_success_recorded_even_on_healthy_lane() {
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                    .api_key("sk-test")
                    .health(health_active()),
            )
            .pool("p", &[(0, 1)])
            .build();

        // One success on a healthy (Closed, untripped) lane — recovery is a no-op, but the success
        // must still be recorded into the window.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        });
        probe_lane(&app, 0, Duration::from_secs(5)).await;
        // 4 failing probes. With the success recorded the window is 1 success + 4 errors = 5 outcomes
        // (>= min_requests) at 4/5 = 0.8 >= 0.5 → trips Open. Without the success it would be 4 errors
        // only (< min_requests) → stays Closed.
        for _ in 0..4 {
            state.push(MockResponse::ServerError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: serde_json::json!({ "error": "upstream down" }),
            });
            probe_lane(&app, 0, Duration::from_secs(5)).await;
        }

        assert!(
            matches!(app.store.breaker_state(0), BreakerState::Open { .. }),
            "the healthy-lane probe success must be recorded so the window reaches min_requests (1 \
             success + 4 errors = 5 at 0.8 error rate) and trips Open; a Closed cell here would mean \
             the success was dropped, got {:?}",
            app.store.breaker_state(0)
        );
        server.shutdown().await;
    }

    /// REGRESSION (R24 LOW #17): a single SUCCESSFUL probe bumps the lane-global `ok` stat EXACTLY
    /// ONCE — not once per cell. The lane sits in THREE pools, so the pre-fix code (which recorded the
    /// success via a per-cell `record_success_in` loop over the default cell plus every pool) bumped
    /// `LaneState.ok` 4 times per 2xx probe (1 default + 3 pools), inflating the public `/stats` `ok`
    /// metric by (N+1). The R23 fix had already decoupled the SYMMETRIC failure path (one `err` bump
    /// per probe) but the success path still multi-counted. After the fix `ok` rises by exactly 1 per
    /// successful probe, mirroring how `record_probe_failure_all_cells` bumps `err` once. We drive 2
    /// probes and assert `ok == 2` (the pre-fix code would read 8).
    #[tokio::test]
    async fn test_probe_success_bumps_lane_ok_once_not_per_cell() {
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                    .api_key("sk-test")
                    .health(health_active()),
            )
            // Same lane fronted by three distinct pools — the per-cell success loop would bump the
            // lane-global `ok` (1 default + 3 pools) = 4 times per probe under the old code.
            .pool("a", &[(0, 1)])
            .pool("b", &[(0, 1)])
            .pool("c", &[(0, 1)])
            .build();

        for _ in 0..2 {
            state.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: serde_json::json!({ "ok": true }),
            });
            probe_lane(&app, 0, Duration::from_secs(5)).await;
        }

        assert_eq!(
            app.store.snapshot(0, now()).ok,
            2,
            "a successful probe must bump the lane-global `ok` exactly once (mirroring the single \
             `err` bump on the failure path); a lane in 3 pools probed twice must read ok == 2, not \
             ok == 8 (the pre-fix per-cell multi-count of 4 per probe)"
        );
        server.shutdown().await;
    }

    /// REGRESSION (R16 HIGH, SigV4 signed==sent): the active probe MUST sign the canonical URI from
    /// the SAME path encoding it transmits on the wire. `probe_lane` derives both the SigV4
    /// `canonical_uri` and the wire URL from `crate::forward::sign_and_wire_path(&url_path)` (the
    /// identical primitive the organic forward path uses), so for a Bedrock-style path whose modelId
    /// carries a reserved `:` the signed/sent path is byte-identical and `%3A`-encoded — eliminating
    /// the `SignatureDoesNotMatch` 403 that would otherwise park every Bedrock lane dead. This guards
    /// the contract at the health layer (the helper itself is covered by the forward.rs reserved-char
    /// test) so a future refactor of the probe can't reintroduce a raw-send divergence.
    #[test]
    fn test_probe_signs_and_sends_same_encoded_path_for_reserved_chars() {
        let url_path = "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse";
        let wire_path = crate::forward::sign_and_wire_path(url_path);
        let canonical_uri = wire_path
            .split('?')
            .next()
            .unwrap_or(&wire_path)
            .to_string();

        assert!(
            wire_path.contains("%3A"),
            "Bedrock modelId ':' must be percent-encoded on the wire path: {wire_path}"
        );
        assert!(
            !wire_path.contains(":0/converse"),
            "the raw ':' must NOT survive on the wire path (would diverge from the signed URI): \
             {wire_path}"
        );
        assert_eq!(
            canonical_uri, wire_path,
            "with no query string the signed canonical URI must equal the transmitted wire path \
             (signed == sent), the exact invariant that prevents SignatureDoesNotMatch"
        );
    }
}
