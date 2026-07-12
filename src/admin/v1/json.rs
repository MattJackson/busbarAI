// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON-REST adapter for Admin API **v1** — mounts `/admin/v1/*`.
//!
//! The version-specific WIRE layer for the JSON transport: it declares the v1 routes, owns the v1 JSON
//! envelope helpers, and maps each route to a shared `AdminService` call. It holds NO operation logic
//! — logic lives in `super::service`, the frozen types in `super::contract`. A GraphQL adapter for v1
//! is a sibling `super::graphql` over the SAME service. Releasing v2 copies the whole `v1/` directory
//! to `v2/`, changes only what differs, and mounts `/admin/v2/*` alongside; v1 keeps answering.

use std::sync::Arc;

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{extract::Path, extract::Query, Extension, Router};
use serde::Serialize;
use serde_json::json;

use super::contract::AdminError;
use super::service::AdminService;
use crate::admin::transport::AdminTransport;
use crate::state::App;

/// The JSON-REST adapter for v1: the `/admin/v1/*` resource API with the stable
/// `{"error":{"code","message"}}` envelope (design-admin-api-v1 §0.3). Zero-sized — every request
/// reads the shared service out of the router's extension layer.
pub(crate) struct JsonV1;

impl AdminTransport for JsonV1 {
    fn name(&self) -> &'static str {
        "json/v1"
    }

    fn router(&self, service: Arc<AdminService>) -> Router<Arc<App>> {
        // The service is shared across every route via an extension layer. Routes stay declarative;
        // each handler pulls `Arc<AdminService>` and maps the typed result onto the JSON wire.
        Router::new()
            .route("/admin/v1/info", get(info))
            .route("/admin/v1/pools", get(list_pools))
            .route("/admin/v1/models", get(list_models))
            .route("/admin/v1/providers", get(list_providers))
            .route("/admin/v1/hooks", get(list_hooks))
            .route("/admin/v1/hooks/{name}", get(get_hook))
            .route("/admin/v1/plugins", get(list_plugins))
            .route("/admin/v1/auth", get(get_auth))
            .route("/admin/v1/config", get(get_config))
            .route("/admin/v1/config/validate", post(validate_config))
            .layer(Extension(service))
    }
}

// ── JSON wire helpers (v1) ───────────────────────────────────────────────────────────────────────

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract` view
/// (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view appears
/// automatically (additive-only holds by construction).
fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::forward::APPLICATION_JSON)],
        serde_json::to_string(view).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

/// Project an `AdminError` onto the stable v1 JSON error envelope
/// `{"error":{"code":<stable>,"message":<human>}}` with the error's HTTP status. Tooling branches on
/// `code`; `message` is human-only.
fn err_json(e: &AdminError) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, crate::forward::APPLICATION_JSON)],
        json!({"error": {"code": e.code(), "message": e.message()}}).to_string(),
    )
        .into_response()
}

/// Map a service `Result<View, AdminError>` onto the JSON wire: `ok_json` on success (given status),
/// `err_json` on error. The single seam every v1 json handler funnels through.
fn respond<T: Serialize>(status: StatusCode, result: Result<T, AdminError>) -> Response {
    match result {
        Ok(view) => ok_json(status, &view),
        Err(e) => err_json(&e),
    }
}

// ── route handlers (thin: call the service, project onto the wire) ───────────────────────────────

/// `GET /admin/v1/info` — version, compiled-in plugin proof, uptime, topology.
async fn info(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.info().await)
}

/// `GET /admin/v1/pools` — pool topology read.
async fn list_pools(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.list_pools().await)
}

/// `GET /admin/v1/models` — model lanes + providers.
async fn list_models(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.list_models().await)
}

/// `GET /admin/v1/providers` — distinct providers + lane counts.
async fn list_providers(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.list_providers().await)
}

/// `GET /admin/v1/hooks` — the hook registry read.
async fn list_hooks(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.list_hooks().await)
}

/// `GET /admin/v1/hooks/{name}` — one hook definition (404 if unregistered).
async fn get_hook(
    Extension(service): Extension<Arc<AdminService>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service.get_hook(&name).await)
}

/// `GET /admin/v1/plugins?type=auth|hooks` — the plugin catalog for one type. A missing/unknown
/// `type` is an `invalid_request` (the two types are distinct engine contracts).
async fn list_plugins(
    Extension(service): Extension<Arc<AdminService>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service.list_plugins(ptype).await)
}

/// `GET /admin/v1/auth` — the ingress auth chain + upstream-credential mode (no secrets).
async fn get_auth(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.get_auth().await)
}

/// `GET /admin/v1/config` — the effective running config snapshot (redacted; no secrets).
async fn get_config(Extension(service): Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.get_config().await)
}

/// The `POST /admin/v1/config/validate` request body: a full proposed config — the `config.yaml`
/// deploy block + the `providers.yaml` definitions — mirroring the two files busbar loads at boot.
#[derive(serde::Deserialize)]
struct ValidateConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape), keyed by provider name. Optional: a config
    /// that references no providers.yaml entries validates against an empty def set (and reports the
    /// dangling references as errors).
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /admin/v1/config/validate` — dry-run validate a proposed config. A malformed body is an
/// `invalid_request`; a well-formed body always returns 200 with the `{ok, errors}` verdict.
async fn validate_config(
    Extension(service): Extension<Arc<AdminService>>,
    body: axum::body::Bytes,
) -> Response {
    let req: ValidateConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    respond(
        StatusCode::OK,
        service.validate_config(req.config, req.providers).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error envelope projection is `{"error":{"code","message"}}` with the error's status — the
    /// shape v1 tooling parses.
    #[test]
    fn err_json_uses_stable_envelope() {
        let resp = err_json(&AdminError::NotFound("hook".into()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
