// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::forward::forward_with_pool;
use crate::state::{App, WeightedLane};

// POST /v1/chat/completions — OpenAI-style ingress: model from body, same-protocol passthrough.
// Cross-protocol translation (openai ingress → non-openai lane) is B-503 and NOT implemented here;
// if the body's model resolves to a non-openai lane, this would send an OpenAI body upstream (wrong).
pub(crate) async fn openai_ingress(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
        return forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            None,
            &model,
            _affinity_key,
        )
        .await;
    }

    if let Some(&i) = app.by_model.get(&model) {
        return crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            None,
        )
        .await;
    }

    (
        StatusCode::NOT_FOUND,
        format!("router: unknown model '{model}'"),
    )
        .into_response()
}

// POST /<name>/v1/messages   — name resolves to a pool (round-robin) or a single model
pub(crate) async fn named(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // NOTE: Caller token extraction from request extensions requires handler signature change.
    // For now, caller_token is None - passthrough mode will use lane's api_key as fallback.
    let _caller_token = None;

    let affinity_key = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    if let Some(cands) = app.pools.get(&name) {
        // Convert WeightedLane vec to match forward signature (already same type now)
        return forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            _caller_token,
            &name,
            affinity_key,
        )
        .await;
    }
    if let Some(&i) = app.by_model.get(&name) {
        // Use forward for model-based routing (no pool name context needed)
        return crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            _caller_token,
        )
        .await;
    }

    (
        StatusCode::NOT_FOUND,
        format!("router: '{name}' is not a known model or pool"),
    )
        .into_response()
}

// POST /<provider>/<model>/v1/messages — ad-hoc direct
pub(crate) async fn adhoc(
    State(app): State<Arc<App>>,
    Path((provider, model)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let _caller_token = None;

    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => {
            // Single lane with weight=1 (default for ad-hoc routing) - use forward, not forward_with_pool
            crate::forward::forward(
                app.clone(),
                vec![WeightedLane { idx: i, weight: 1 }],
                body,
                _caller_token,
            )
            .await
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
