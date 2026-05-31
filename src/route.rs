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

/// B-602: emit the per-request observability metrics at the ingress boundary (one client request =
/// one call here, unlike the re-entrant forward_with_pool). Outcome is derived from the final
/// status; duration is wall-clock for the whole proxied request.
fn finish(ingress_protocol: &str, pool: &str, started: Instant, resp: Response) -> Response {
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
    resp
}

// POST /v1/chat/completions — OpenAI-style ingress: model from body, same-protocol passthrough.
// Cross-protocol translation (openai ingress → non-openai lane) is B-503 and NOT implemented here;
// if the body's model resolves to a non-openai lane, this would send an OpenAI body upstream (wrong).
#[tracing::instrument(name = "openai_ingress", skip_all)]
pub(crate) async fn openai_ingress(
    State(app): State<Arc<App>>,
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
        return finish("openai", &model, started, resp);
    }

    if let Some(&i) = app.by_model.get(&model) {
        let resp = crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            None,
        )
        .await;
        return finish("openai", &model, started, resp);
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // NOTE: Caller token extraction from request extensions requires handler signature change.
    // For now, caller_token is None - passthrough mode will use lane's api_key as fallback.
    let _caller_token = None;

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
        return finish("anthropic", &name, started, resp);
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
        return finish("anthropic", &name, started, resp);
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
    body: Bytes,
) -> Response {
    let _caller_token = None;
    let started = Instant::now();

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
            finish("anthropic", &model, started, resp)
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

    #[test]
    fn test_finish_emits_request_metrics() {
        crate::metrics::init();
        let resp = (StatusCode::OK, "ok").into_response();
        let out = finish("openai", "mypool", Instant::now(), resp);
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
        let _ = finish("anthropic", "p2", Instant::now(), resp);
        assert!(
            crate::metrics::render().contains("outcome=\"exhausted\""),
            "503 maps to outcome=exhausted"
        );
    }
}
