// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::forward::forward_with_pool;
use crate::state::{App, WeightedLane};

/// G-2 (0.12): enforce a virtual key's allowed-pools list against the resolved target pool. No-op
/// when governance is off (`gov.key` is None) or the key allows all pools. Returns a 403 response
/// to short-circuit when the key may not use this pool.
fn pool_authorized(gov: &crate::governance::GovCtx, pool: &str) -> Option<Response> {
    if let Some(key) = &gov.key {
        if !crate::governance::pool_allowed(key, pool) {
            return Some(
                (
                    StatusCode::FORBIDDEN,
                    format!(
                        "virtual key '{}' is not allowed to use pool '{pool}'",
                        key.id
                    ),
                )
                    .into_response(),
            );
        }
    }
    None
}

/// G-3 (0.12): reject (402) before forwarding when the resolved virtual key is already over its
/// budget for the current window. No-op when governance is off or the key has no budget cap.
fn budget_check(app: &Arc<App>, gov: &crate::governance::GovCtx) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        if g.is_over_budget(key, crate::store::now()) {
            return Some(
                (
                    StatusCode::PAYMENT_REQUIRED,
                    format!("virtual key '{}' has exceeded its budget", key.id),
                )
                    .into_response(),
            );
        }
    }
    None
}

/// G-4 (0.12): reject (429 + Retry-After) before forwarding when the resolved virtual key is over
/// its RPM/TPM for the current window. No-op when governance is off or the key has no rate cap.
fn rate_check(app: &Arc<App>, gov: &crate::governance::GovCtx) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        if let Err(retry) = g.check_rate(key, crate::store::now()) {
            return Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(axum::http::header::RETRY_AFTER, retry.to_string())],
                    format!("rate limit exceeded for virtual key '{}'", key.id),
                )
                    .into_response(),
            );
        }
    }
    None
}

/// B-602/G-3: the ingress boundary — emit per-request observability metrics (one client request =
/// one call here, unlike the re-entrant forward_with_pool) AND charge the request to the virtual
/// key's budget. Outcome is derived from the final status; duration is wall-clock.
fn finish(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    resp: Response,
) -> Response {
    let outcome = match resp.status().as_u16() {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    };
    metrics::counter!(
        crate::metrics::REQUESTS_TOTAL,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    )
    .increment(1);
    let elapsed = started.elapsed();
    metrics::histogram!(
        crate::metrics::REQUEST_DURATION_SECONDS,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    )
    .record(elapsed.as_secs_f64());

    // B-604: best-effort request-log webhook (no-op unless configured).
    crate::observability::fire_request_log(crate::observability::build_request_log(
        crate::store::now(),
        ingress_protocol,
        pool,
        outcome,
        elapsed.as_millis() as u64,
    ));

    // G-3: charge the request to the virtual key's budget. Token-based cost is a future refinement
    // (tokens=0 here); the flat per-request price is what accrues today.
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        g.record_request(key, crate::store::now(), 0);
    }
    resp
}

// POST /v1/chat/completions — OpenAI-style ingress: model from body, same-protocol passthrough.
// Cross-protocol translation (openai ingress → non-openai lane) is B-503 and NOT implemented here;
// if the body's model resolves to a non-openai lane, this would send an OpenAI body upstream (wrong).
#[tracing::instrument(name = "openai_ingress", skip_all)]
pub(crate) async fn openai_ingress(
    State(app): State<Arc<App>>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };

    let model = match v.get("model").and_then(|m| m.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "router: missing 'model' in request body".to_string(),
            )
                .into_response()
        }
    };

    // G-2: enforce the virtual key's allowed-pools against the requested model/pool.
    if let Some(resp) = pool_authorized(&gov, &model) {
        return resp;
    }
    // G-3: reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(&app, &gov) {
        return resp;
    }
    // G-4: reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(&app, &gov) {
        return resp;
    }

    let _affinity_key: Option<&str> = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    if let Some(cands) = app.pools.get(&model) {
        let resp = forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            None,
            &model,
            _affinity_key,
            "openai",
        )
        .await;
        return finish(&app, &gov, "openai", &model, started, resp);
    }

    if let Some(&i) = app.by_model.get(&model) {
        let resp = crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            None,
        )
        .await;
        return finish(&app, &gov, "openai", &model, started, resp);
    }

    (
        StatusCode::NOT_FOUND,
        format!("router: unknown model '{model}'"),
    )
        .into_response()
}

// POST /<name>/v1/messages   — name resolves to a pool (round-robin) or a single model
#[tracing::instrument(name = "named", skip_all, fields(pool = %name))]
pub(crate) async fn named(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // NOTE: Caller token extraction from request extensions requires handler signature change.
    // For now, caller_token is None - passthrough mode will use lane's api_key as fallback.
    let _caller_token = None;

    // G-2: enforce the virtual key's allowed-pools against the named pool/model.
    if let Some(resp) = pool_authorized(&gov, &name) {
        return resp;
    }
    // G-3: reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(&app, &gov) {
        return resp;
    }
    // G-4: reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(&app, &gov) {
        return resp;
    }

    let started = Instant::now();
    let affinity_key = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    if let Some(cands) = app.pools.get(&name) {
        // Convert WeightedLane vec to match forward signature (already same type now)
        let resp = forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            _caller_token,
            &name,
            affinity_key,
            "anthropic",
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, resp);
    }
    if let Some(&i) = app.by_model.get(&name) {
        // Use forward for model-based routing (no pool name context needed)
        let resp = crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            _caller_token,
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, resp);
    }

    (
        StatusCode::NOT_FOUND,
        format!("router: '{name}' is not a known model or pool"),
    )
        .into_response()
}

// POST /<provider>/<model>/v1/messages — ad-hoc direct
#[tracing::instrument(name = "adhoc", skip_all, fields(provider = %provider, model = %model))]
pub(crate) async fn adhoc(
    State(app): State<Arc<App>>,
    Path((provider, model)): Path<(String, String)>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    body: Bytes,
) -> Response {
    let _caller_token = None;
    let started = Instant::now();

    // G-2: enforce the virtual key's allowed-pools against the ad-hoc model target.
    if let Some(resp) = pool_authorized(&gov, &model) {
        return resp;
    }
    // G-3: reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(&app, &gov) {
        return resp;
    }
    // G-4: reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(&app, &gov) {
        return resp;
    }

    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => {
            // Single lane with weight=1 (default for ad-hoc routing) - use forward, not forward_with_pool
            let resp = crate::forward::forward(
                app.clone(),
                vec![WeightedLane { idx: i, weight: 1 }],
                body,
                _caller_token,
            )
            .await;
            finish(&app, &gov, "anthropic", &model, started, resp)
        }
        Some(&i) => (
            StatusCode::BAD_REQUEST,
            format!(
                "router: model '{}' is on provider '{}', not '{}'",
                model, app.lanes[i].provider, provider
            ),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!("router: unknown model '{model}'"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal governance-off App for exercising `finish` in isolation.
    fn minimal_app() -> Arc<App> {
        use std::sync::atomic::AtomicUsize;
        Arc::new(App {
            lanes: vec![],
            store: Arc::new(crate::store::InMemoryStore::new(vec![])),
            by_model: std::collections::HashMap::new(),
            pools: std::collections::HashMap::new(),
            rr: AtomicUsize::new(0),
            client: reqwest::Client::new(),
            auth: Arc::new(crate::auth::AuthMiddleware::new(
                &crate::config::AuthCfg::default_none(),
            )),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            governance: None,
        })
    }

    #[test]
    fn test_finish_emits_request_metrics() {
        crate::metrics::init();
        let resp = (StatusCode::OK, "ok").into_response();
        let out = finish(
            &minimal_app(),
            &crate::governance::GovCtx::default(),
            "openai",
            "mypool",
            Instant::now(),
            resp,
        );
        // finish must pass the response through unchanged.
        assert_eq!(out.status(), StatusCode::OK);

        let scrape = crate::metrics::render();
        assert!(
            scrape.contains(crate::metrics::REQUESTS_TOTAL),
            "finish should emit requests_total; got:\n{scrape}"
        );
        assert!(
            scrape.contains("outcome=\"ok\""),
            "a 2xx response maps to outcome=ok; got:\n{scrape}"
        );
        assert!(
            scrape.contains(crate::metrics::REQUEST_DURATION_SECONDS),
            "finish should emit the request-duration histogram; got:\n{scrape}"
        );
    }

    #[test]
    fn test_finish_outcome_mapping_503_is_exhausted() {
        crate::metrics::init();
        let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
        let _ = finish(
            &minimal_app(),
            &crate::governance::GovCtx::default(),
            "anthropic",
            "p2",
            Instant::now(),
            resp,
        );
        assert!(
            crate::metrics::render().contains("outcome=\"exhausted\""),
            "503 maps to outcome=exhausted"
        );
    }
}
