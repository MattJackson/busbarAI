// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Virtual-key management API. Admin CRUD over `/admin/keys`, guarded by the
//! configured admin token (enforced in `auth_middleware`, not here). Mutations refresh the
//! `GovState` cache. Responses never include a key's `key_hash`; the plaintext secret is returned
//! exactly once, on creation.

use std::sync::Arc;

use axum::extract::{Json, Path, State};
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::governance::{NewKeySpec, VirtualKey};
use crate::state::App;

#[derive(Deserialize)]
pub(crate) struct CreateKeyReq {
    name: String,
    #[serde(default)]
    allowed_pools: Vec<String>,
    #[serde(default)]
    max_budget_cents: Option<i64>,
    #[serde(default)]
    budget_period: Option<String>,
    #[serde(default)]
    rpm_limit: Option<u32>,
    #[serde(default)]
    tpm_limit: Option<u32>,
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Key metadata for API responses — deliberately omits `key_hash`.
fn key_meta(k: &VirtualKey) -> Value {
    json!({
        "id": k.id,
        "name": k.name,
        "allowed_pools": k.allowed_pools,
        "max_budget_cents": k.max_budget_cents,
        "budget_period": k.budget_period,
        "rpm_limit": k.rpm_limit,
        "tpm_limit": k.tpm_limit,
        "enabled": k.enabled,
        "created_at": k.created_at,
    })
}

fn disabled() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({"error": "governance/admin API is not enabled"}),
    )
}

/// POST /admin/keys — mint a virtual key. Returns the plaintext secret ONCE.
pub(crate) async fn create_key(
    State(app): State<Arc<App>>,
    Json(req): Json<CreateKeyReq>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    let spec = NewKeySpec {
        name: req.name,
        allowed_pools: req.allowed_pools,
        max_budget_cents: req.max_budget_cents,
        budget_period: req.budget_period.unwrap_or_else(|| "total".to_string()),
        rpm_limit: req.rpm_limit,
        tpm_limit: req.tpm_limit,
    };
    match gov.create_key(spec, crate::store::now()) {
        Ok((key, secret)) => {
            let mut body = key_meta(&key);
            body["secret"] = json!(secret); // shown exactly once
            json_response(StatusCode::CREATED, body)
        }
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": e.to_string()}),
        ),
    }
}

/// GET /admin/keys — list key metadata (no secrets/hashes).
pub(crate) async fn list_keys(State(app): State<Arc<App>>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    match gov.all_keys() {
        Ok(keys) => json_response(
            StatusCode::OK,
            json!({ "keys": keys.iter().map(key_meta).collect::<Vec<_>>() }),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": e.to_string()}),
        ),
    }
}

/// GET /admin/keys/:id/usage — current-window usage counters.
pub(crate) async fn key_usage(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    match gov.usage_for(&id, crate::store::now()) {
        Ok(Some(u)) => json_response(
            StatusCode::OK,
            json!({"id": id, "spend_cents": u.spend_cents, "tokens": u.tokens, "requests": u.requests}),
        ),
        Ok(None) => json_response(StatusCode::NOT_FOUND, json!({"error": "key not found"})),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": e.to_string()}),
        ),
    }
}

/// DELETE /admin/keys/:id — revoke a key.
pub(crate) async fn delete_key(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    match gov.delete_key(&id) {
        Ok(()) => json_response(StatusCode::OK, json!({"deleted": id})),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": e.to_string()}),
        ),
    }
}
