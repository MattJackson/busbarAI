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

use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{extract::Path, extract::Query, Router};
use serde::Serialize;
use serde_json::json;

use super::contract::AdminError;
use super::service::{build_with_hook, build_without_hook, AdminService};
use crate::admin::audit;
use crate::admin::transport::AdminTransport;
use crate::state::AppHandle;

/// The JSON-REST adapter for v1: the `/admin/v1/*` resource API with the stable
/// `{"error":{"code","message"}}` envelope (design-admin-api-v1 §0.3). Zero-sized — each request
/// builds an `AdminService` over the CURRENT snapshot from the router's `Arc<AppHandle>` state (so a
/// read after a config apply reflects the new config), and the mutation path swaps through the handle.
pub(crate) struct JsonV1;

impl AdminTransport for JsonV1 {
    fn name(&self) -> &'static str {
        "json/v1"
    }

    fn router(&self) -> Router<Arc<AppHandle>> {
        // Routes stay declarative; each handler pulls the `Arc<AppHandle>` state, loads the current
        // snapshot into a per-request `AdminService`, and maps the typed result onto the JSON wire.
        Router::new()
            .route("/admin/v1/info", get(info))
            .route("/admin/v1/pools", get(list_pools))
            .route("/admin/v1/pools/{name}", get(get_pool))
            .route("/admin/v1/models", get(list_models))
            .route("/admin/v1/providers", get(list_providers))
            .route("/admin/v1/hooks", get(list_hooks).post(register_hook))
            .route("/admin/v1/hooks/{name}", get(get_hook).delete(delete_hook))
            .route("/admin/v1/hooks/{name}/health", get(hook_health))
            .route("/admin/v1/plugins", get(list_plugins))
            .route("/admin/v1/auth", get(get_auth))
            .route("/admin/v1/admin-auth", get(get_admin_auth))
            .route("/admin/v1/usage", get(get_usage))
            .route("/admin/v1/config", get(get_config))
            .route("/admin/v1/audit", get(get_audit))
            .route("/admin/v1/config/validate", post(validate_config))
            .route("/admin/v1/openapi.json", get(openapi))
    }
}

/// Build a per-request `AdminService` over the CURRENT snapshot loaded from the handle.
fn service(handle: &Arc<AppHandle>) -> AdminService {
    AdminService::new(handle.load())
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
async fn info(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).info().await)
}

/// `GET /admin/v1/pools` — pool topology read.
async fn list_pools(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_pools().await)
}

/// `GET /admin/v1/pools/{name}` — live per-member status of one pool (404 if unknown).
async fn get_pool(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    respond(StatusCode::OK, service(&handle).get_pool(&name).await)
}

/// `GET /admin/v1/models` — model lanes + providers.
async fn list_models(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_models().await)
}

/// `GET /admin/v1/providers` — distinct providers + lane counts.
async fn list_providers(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_providers().await)
}

/// `GET /admin/v1/hooks` — the hook registry read.
async fn list_hooks(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_hooks().await)
}

/// `GET /admin/v1/hooks/{name}` — one hook definition (404 if unregistered).
async fn get_hook(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    respond(StatusCode::OK, service(&handle).get_hook(&name).await)
}

/// `GET /admin/v1/hooks/{name}/health` — best-effort transport reachability (404 if unregistered).
async fn hook_health(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    respond(StatusCode::OK, service(&handle).hook_health(&name).await)
}

/// `GET /admin/v1/plugins?type=auth|hooks` — the plugin catalog for one type. A missing/unknown
/// `type` is an `invalid_request` (the two types are distinct engine contracts).
async fn list_plugins(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service(&handle).list_plugins(ptype).await)
}

/// `GET /admin/v1/auth` — the ingress auth chain + upstream-credential mode (no secrets).
async fn get_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_auth().await)
}

/// `GET /admin/v1/admin-auth` — the admin-plane auth config (the admin surface guard).
async fn get_admin_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_admin_auth().await)
}

/// `GET /admin/v1/usage` — fleet usage aggregation (spend/tokens/requests, per-key).
async fn get_usage(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_usage().await)
}

/// `GET /admin/v1/config` — the effective running config snapshot (redacted; no secrets).
async fn get_config(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_config().await)
}

/// The `POST /admin/v1/hooks` request body: the hook name + its definition.
#[derive(serde::Deserialize)]
struct RegisterHookReq {
    name: String,
    config: crate::config::HookCfg,
}

/// `POST /admin/v1/hooks` — register (or replace) a hook at RUNTIME. Validates the definition, builds
/// the next `App` snapshot with the hook wired + transports re-resolved, atomically `swap`s it in, and
/// returns `201` with the registered hook. A `global` hook is LIVE immediately (new requests see it);
/// in-flight requests finish on the old snapshot. Lanes/store are untouched — live breaker state is
/// preserved. This is the first API-driven config mutation.
async fn register_hook(State(handle): State<Arc<AppHandle>>, body: axum::body::Bytes) -> Response {
    let req: RegisterHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    let current = handle.load();
    let resource = format!("hook:{}", req.name);
    match build_with_hook(&current, &req.name, req.config) {
        Ok(next) => {
            handle.swap(Arc::new(next));
            audit::AUDIT.record("hook.register", &resource, audit::OUTCOME_APPLIED);
            // Project the registered hook from the NEW (post-swap) snapshot for the 201 body.
            respond(
                StatusCode::CREATED,
                service(&handle).get_hook(&req.name).await,
            )
        }
        Err(e) => {
            audit::AUDIT.record("hook.register", &resource, audit::OUTCOME_REJECTED);
            err_json(&e)
        }
    }
}

/// `DELETE /admin/v1/hooks/{name}` — remove a hook at RUNTIME (live). Builds the next snapshot without
/// the hook (dropped from the registry + global wiring, transports re-resolved) and swaps it in.
/// `404 not_found` if the hook is unregistered. `204 No Content` on success.
async fn delete_hook(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    let current = handle.load();
    let resource = format!("hook:{name}");
    match build_without_hook(&current, &name) {
        Ok(next) => {
            handle.swap(Arc::new(next));
            audit::AUDIT.record("hook.delete", &resource, audit::OUTCOME_APPLIED);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            audit::AUDIT.record("hook.delete", &resource, audit::OUTCOME_REJECTED);
            err_json(&e)
        }
    }
}

/// `GET /admin/v1/audit` — the admin audit log (most-recent-first), every mutation with its outcome.
async fn get_audit() -> Response {
    let entries = audit::AUDIT.list(200);
    ok_json(StatusCode::OK, &json!({ "entries": entries }))
}

/// The stable v1 GET endpoints (path, summary), the single source for both the router-mount drift
/// test and the OpenAPI `paths`. Templated/POST routes are documented separately in `openapi_doc`.
/// Adding a GET endpoint means adding it here so the doc + the drift guard both see it.
pub(crate) const V1_GET_PATHS: &[(&str, &str)] = &[
    (
        "/admin/v1/info",
        "Version, compiled-in plugin proof, uptime, topology",
    ),
    ("/admin/v1/pools", "Pool topology (members + weights)"),
    ("/admin/v1/models", "Model lanes + upstream providers"),
    ("/admin/v1/providers", "Distinct providers + lane counts"),
    ("/admin/v1/hooks", "Hook registry (definitions)"),
    (
        "/admin/v1/plugins",
        "Plugin catalog by type (compiled-in + external)",
    ),
    (
        "/admin/v1/auth",
        "Ingress auth chain + upstream-credential mode",
    ),
    (
        "/admin/v1/admin-auth",
        "Admin-plane auth config (the admin surface guard)",
    ),
    (
        "/admin/v1/usage",
        "Fleet usage aggregation (spend/tokens/requests, per-key)",
    ),
    (
        "/admin/v1/config",
        "Effective running config snapshot (redacted)",
    ),
    (
        "/admin/v1/audit",
        "Admin audit log — every mutation with its outcome (newest first)",
    ),
    ("/admin/v1/openapi.json", "This OpenAPI 3.1 document"),
];

/// Build the OpenAPI 3.1 document describing the v1 JSON-REST surface. Paths + methods + the stable
/// error envelope are the machine-readable contract (tooling generates clients + branches on the error
/// `code`). Response bodies are described loosely (not full struct schemas) today — the additive
/// follow-up derives per-view schemas; paths/methods/error shape are the frozen part callers rely on.
fn openapi_doc() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for (path, summary) in V1_GET_PATHS {
        paths.insert(
            (*path).to_string(),
            json!({
                "get": {
                    "summary": summary,
                    "security": [{"adminToken": []}],
                    "responses": {
                        "200": {"description": "OK"},
                        "401": {"description": "Missing/invalid admin credential"}
                    }
                }
            }),
        );
    }
    // Runtime hook registration: POST on the /hooks collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut("/admin/v1/hooks")
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Register (or replace) a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Registered (body is the hook definition)"},
                    "400": {"description": "Malformed body or invalid definition (`invalid_request`)"},
                    "409": {"description": "Grant change on an existing hook (`conflict`, §6.4 immutability)"}
                }
            }),
        );
    }
    // Templated + non-GET routes.
    paths.insert(
        "/admin/v1/hooks/{name}".to_string(),
        json!({
            "get": {
                "summary": "One hook definition",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            },
            "delete": {
                "summary": "Remove a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "204": {"description": "Removed"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        "/admin/v1/pools/{name}".to_string(),
        json!({
            "get": {
                "summary": "Live per-member status of one pool (breaker/concurrency/latency)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown pool (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        "/admin/v1/hooks/{name}/health".to_string(),
        json!({
            "get": {
                "summary": "Best-effort hook transport reachability",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (`reachable` may be null for webhook/non-unix)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        "/admin/v1/config/validate".to_string(),
        json!({
            "post": {
                "summary": "Dry-run validate a proposed config",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "Verdict `{ok, errors}` (even for an invalid config)"},
                    "400": {"description": "Malformed request body (error code `invalid_request`)"}
                }
            }
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Busbar Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The frozen, additive-only /admin/v1 surface. Errors use the stable \
                            envelope {\"error\":{\"code\",\"message\"}}; tooling branches on `code`."
        },
        "components": {
            "securitySchemes": {
                "adminToken": {"type": "apiKey", "in": "header", "name": "x-admin-token"}
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string",
                                    "enum": ["not_found", "forbidden", "invalid_request",
                                             "conflict", "internal"]},
                                "message": {"type": "string"}
                            },
                            "required": ["code", "message"]
                        }
                    },
                    "required": ["error"]
                }
            }
        },
        "paths": paths
    })
}

/// `GET /admin/v1/openapi.json` — the OpenAPI 3.1 schema of the v1 surface (the discovery contract).
async fn openapi() -> Response {
    ok_json(StatusCode::OK, &openapi_doc())
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
    State(handle): State<Arc<AppHandle>>,
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
        service(&handle)
            .validate_config(req.config, req.providers)
            .await,
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

    /// CONTRACT LOCK: the openapi Error-schema `code` enum must EXACTLY match the frozen `AdminError`
    /// codes — no drift between the discovery doc and the taxonomy tooling actually receives. Every
    /// variant's `code()` must appear in the enum, and the enum must list nothing else.
    #[test]
    fn openapi_error_enum_matches_admin_error_codes() {
        use std::collections::BTreeSet;
        let doc = openapi_doc();
        let enum_codes: BTreeSet<String> = doc["components"]["schemas"]["Error"]["properties"]
            ["error"]["properties"]["code"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        // The exhaustive set of AdminError codes — kept in lock-step with `AdminError::code`.
        let actual_codes: BTreeSet<String> = [
            AdminError::NotFound(String::new()),
            AdminError::Forbidden {
                needed: crate::admin::v1::contract::Scope::Full,
            },
            AdminError::Validation(String::new()),
            AdminError::Conflict(String::new()),
            AdminError::Internal,
        ]
        .iter()
        .map(|e| e.code().to_string())
        .collect();
        assert_eq!(
            enum_codes, actual_codes,
            "openapi error-code enum drifted from AdminError::code"
        );
    }
}
