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

use axum::http::header::CONTENT_TYPE;

use crate::config::HealthMode;
use crate::proto::convert_headers;
use crate::state::App;
use crate::store::{now, BreakerCfg};

/// Default seconds between probes when a `health:` block omits `interval_secs`.
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
/// Default per-probe request timeout when a `health:` block omits `timeout_secs`.
const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 5;

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
                .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
                .max(1),
        );
        let timeout =
            Duration::from_secs(h.timeout_secs.unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS).max(1));
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

/// Send a single health probe to lane `i` and fold the outcome into the breaker:
///   - 2xx → recover the lane if it was tripped (→ Closed). A healthy lane is left untouched (no
///     synthetic success is counted, so probes don't pollute the `ok` stats).
///   - anything else / transport error → record a transient failure (drives the trip evaluation in
///     `active` mode and re-arms the cooldown on a tripped lane).
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

    let signing_ctx = crate::proto::SigningContext {
        host: crate::forward::host_from_base(&lane.base_url),
        canonical_uri: crate::sigv4::uri_encode_path(
            url_path.split('?').next().unwrap_or(&url_path),
        ),
        body: &body,
        timestamp_epoch: now(),
    };
    let auth = crate::forward::lane_auth_headers(lane, &lane.api_key, &signing_ctx);

    let res = app
        .client
        .post(format!("{}{}", lane.base_url, url_path))
        .headers(convert_headers(auth))
        .header(CONTENT_TYPE, "application/json")
        .timeout(timeout)
        .body(body)
        .send()
        .await;

    let healthy = matches!(&res, Ok(r) if r.status().is_success());
    if healthy {
        if app.store.lane_needs_probe(i, now()) {
            // Probe tests the shared upstream → recover the lane in every cell (all pools + default),
            // clearing both Open trips and soft cooldowns.
            app.store.recover_lane(i);
            tracing::info!(lane = %lane.model, "lane recovered via health probe");
        }
    } else {
        // A failed probe must trip the SAME cells a successful probe (recover_lane) clears — the
        // default cell AND every per-pool cell — because organic traffic routes against per-pool
        // cells. Recording only the default cell (the previous behavior) meant `active` probing
        // could never trip the per-pool breakers real traffic is selected against, so a silently
        // dead upstream stayed Closed for named pools. (The single default BreakerCfg is used for
        // all cells; per-pool trip-threshold nuance is a known limitation of the out-of-band prober.)
        app.store
            .record_probe_failure_all_cells(i, "health-probe", &BreakerCfg::default());
    }
}
