// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Admin API v1 TRANSPORT adapters — the "driving adapters" over the shared service.
//!
//! `AdminTransport` is the port every wire format plugs into: given the shared `AdminService`, an
//! adapter builds whatever it needs to expose the frozen operations. The JSON-REST adapter
//! (`JsonRest`) is the first and only transport today; a GraphQL, gRPC, **MCP** (drive busbar as MCP
//! tools), or CLI adapter is a NEW `AdminTransport` impl calling the SAME `AdminService` methods and
//! reusing the SAME `contract` views/errors — no operation logic is ever duplicated per transport.
//!
//! An adapter's ONLY jobs are (1) translate its wire request into a service call and (2) project the
//! typed `Result<View, AdminError>` back onto its wire (status + envelope for REST; a tool-result for
//! MCP; a typed field for GraphQL). All logic, scope, atomicity, and audit live in the service.

use std::sync::Arc;

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use serde_json::json;

use super::contract::AdminError;
use super::service::AdminService;
use crate::state::App;

/// The port a wire format implements to expose the admin surface. All state is the shared service;
/// an adapter is otherwise a zero-sized strategy. `name()` labels the transport for logs/negotiation;
/// `router()` returns the mount this transport contributes, backed by that service.
pub(crate) trait AdminTransport {
    /// The stable wire name of this transport (`"json-rest"`, `"graphql"`, `"mcp"`, …).
    fn name(&self) -> &'static str;

    /// Build the router exposing this transport's endpoints, all backed by the shared service.
    fn router(&self, service: Arc<AdminService>) -> Router<Arc<App>>;
}

/// The JSON-REST adapter: the classic `/admin/v1/*` resource API with the stable
/// `{"error":{"code","message"}}` envelope (design-admin-api-v1 §0.3). Zero-sized — every request
/// reads the shared service out of router state.
pub(crate) struct JsonRest;

impl AdminTransport for JsonRest {
    fn name(&self) -> &'static str {
        "json-rest"
    }

    fn router(&self, service: Arc<AdminService>) -> Router<Arc<App>> {
        // The service is shared across every route via an extension layer. Routes stay declarative;
        // each handler pulls `Arc<AdminService>` and maps the typed result onto the JSON wire.
        Router::new()
            .route("/admin/v1/info", get(info))
            .layer(axum::Extension(service))
    }
}

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract`
/// view (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view
/// appears automatically (additive-only holds by construction).
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
/// `err_json` on error. The single seam every REST handler funnels through.
fn respond<T: Serialize>(status: StatusCode, result: Result<T, AdminError>) -> Response {
    match result {
        Ok(view) => ok_json(status, &view),
        Err(e) => err_json(&e),
    }
}

/// `GET /admin/v1/info` — thin adapter: call the service, project the typed result onto JSON.
async fn info(axum::Extension(service): axum::Extension<Arc<AdminService>>) -> Response {
    respond(StatusCode::OK, service.info().await)
}

/// Mount the admin v1 surface onto `router` using the given transport over the shared `App`. Called
/// from `main` once the `App` is built. Keeping this a free function (not inline in `main`) means
/// swapping/adding a transport is a one-line change at the call site.
pub(crate) fn mount<T: AdminTransport>(
    router: Router<Arc<App>>,
    transport: &T,
    app: Arc<App>,
) -> Router<Arc<App>> {
    let service = Arc::new(AdminService::new(app));
    tracing::info!(
        transport = transport.name(),
        "admin API v1 transport mounted"
    );
    router.merge(transport.router(service))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stable error taxonomy is locked: each variant's `code` + HTTP status is the frozen wire
    /// contract tooling branches on. A change here is a breaking change to v1 and must fail this test.
    #[test]
    fn admin_error_codes_and_statuses_are_frozen() {
        let cases = [
            (AdminError::NotFound("key".into()), "not_found", 404u16),
            (
                AdminError::Forbidden {
                    needed: super::super::contract::Scope::Full,
                },
                "forbidden",
                403,
            ),
            (AdminError::Validation("bad".into()), "invalid_request", 400),
            (AdminError::Conflict("stale".into()), "conflict", 409),
            (AdminError::Internal, "internal", 500),
        ];
        for (e, code, status) in cases {
            assert_eq!(e.code(), code, "frozen error code changed");
            assert_eq!(e.http_status(), status, "frozen error status changed");
        }
    }

    /// The error envelope projection is `{"error":{"code","message"}}` — the shape tooling parses.
    #[test]
    fn err_json_uses_stable_envelope() {
        let resp = err_json(&AdminError::NotFound("hook".into()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
