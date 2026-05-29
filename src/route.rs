// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::forward::forward;
use crate::state::App;

// POST /<name>/v1/messages   — name resolves to a pool (round-robin) or a single model
pub async fn named(State(app): State<Arc<App>>, Path(name): Path<String>, body: Bytes) -> Response {
    if let Some(cands) = app.pools.get(&name) {
        return forward(app.clone(), cands.clone(), body).await;
    }
    if let Some(&i) = app.by_model.get(&name) {
        return forward(app.clone(), vec![i], body).await;
    }
    (
        StatusCode::NOT_FOUND,
        format!("router: '{name}' is not a known model or pool"),
    )
        .into_response()
}

// POST /<provider>/<model>/v1/messages — ad-hoc direct
pub async fn adhoc(
    State(app): State<Arc<App>>,
    Path((provider, model)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => forward(app.clone(), vec![i], body).await,
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
