// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON-REST adapter for Admin API **v1** — mounts `/api/v1/admin/*`.
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
use axum::routing::{get, patch, post};
use axum::{extract::Path, extract::Query, Router};
use serde::Serialize;
use serde_json::json;

use super::contract::{AdminError, PATH_ADMIN_AUTH, PATH_CONFIG_VALIDATE, PATH_GROUPS, PATH_HOOKS};
use super::service::{
    build_with_group, build_with_hook, build_with_registry, build_without_group,
    build_without_hook, AdminService,
};
use crate::admin::audit;
use crate::admin::transport::AdminTransport;
use crate::state::AppHandle;

/// The JSON-REST adapter for v1: the `/api/v1/admin/*` resource API with the stable
/// `{"error":{"code","message"}}` envelope (design-admin-api-v1 §0.3). Zero-sized — each request
/// builds an `AdminService` over the CURRENT snapshot from the router's `Arc<AppHandle>` state (so a
/// read after a config apply reflects the new config), and the mutation path swaps through the handle.
pub(crate) struct JsonV1;

impl AdminTransport for JsonV1 {
    fn name(&self) -> &'static str {
        "json/v1"
    }

    fn version(&self) -> &'static str {
        "v1"
    }

    fn area(&self) -> &'static str {
        "admin"
    }

    fn router(&self) -> Router<Arc<AppHandle>> {
        // Routes are RELATIVE — `admin::transport::mount` nests this router under the computed
        // `/api/<version>/<area>` prefix (the algorithmic mount grammar), so no path here can drift
        // from `contract::ADMIN_PREFIX`. Each handler pulls the `Arc<AppHandle>` state, loads the
        // current snapshot into a per-request `AdminService`, and maps the typed result onto the
        // JSON wire.
        Router::new()
            .route("/info", get(info))
            .route("/pools", get(list_pools))
            .route("/pools/{name}", get(get_pool))
            .route("/models", get(list_models))
            .route("/providers", get(list_providers))
            .route(PATH_HOOKS, get(list_hooks).post(register_hook))
            .route(
                "/hooks/{name}",
                get(get_hook).put(put_hook).delete(delete_hook),
            )
            .route("/hooks/{name}/health", get(hook_health))
            .route("/hooks/{name}/settings", patch(patch_hook_settings))
            .route("/hooks/{name}/schema", get(hook_schema))
            .route("/hooks/{name}/status", get(hook_status))
            // Groups — the `groups:` limit-tree CRUD (Phase 1, task #100): runtime-mutable groups
            // → per-user budgets. Reads are read-only scope; mutations are full scope.
            .route(PATH_GROUPS, get(list_groups).post(register_group))
            .route(
                "/groups/{name}",
                get(get_group)
                    .put(put_group)
                    .patch(patch_group)
                    .delete(delete_group),
            )
            .route("/groups/{name}/usage", get(get_group_usage))
            // Per-section overlay RESET (D3): DISCARD a section's overlay mutations and revert it to
            // base config.yaml. Full scope (the mutation fallthrough). section ∈ {groups, hooks}.
            .route(
                "/overlay/{section}",
                axum::routing::delete(reset_overlay_section),
            )
            .route("/plugins", get(list_plugins).post(install_plugin))
            .route("/plugins/reload", post(reload_plugins))
            .route("/plugins/{file}", axum::routing::delete(remove_plugin))
            .route("/auth", get(get_auth))
            .route(PATH_ADMIN_AUTH, get(get_admin_auth).put(put_auth))
            .route("/usage", get(get_usage))
            .route("/config", get(get_config))
            .route("/audit", get(get_audit))
            .route(PATH_CONFIG_VALIDATE, post(validate_config))
            .route("/config/versions", get(list_config_versions))
            .route("/config/versions/{v}", get(get_config_version))
            .route("/config/diff", get(config_diff))
            .route("/config/rollback", post(rollback_config))
            .route("/config/reload", post(reload_config))
            .route("/auth/cache/flush", post(flush_credential_cache))
            .route("/config/apply", post(apply_config))
            .route("/openapi.json", get(openapi))
            // Virtual-key management — the keys resource of the SAME v1 admin surface. Handlers
            // live in `crate::admin` while they migrate into the layered service; mounting them
            // here (not in main.rs) keeps the whole admin surface one router under one prefix.
            .route(
                "/keys",
                post(crate::admin::create_key).get(crate::admin::list_keys),
            )
            .route(
                "/keys/{id}",
                get(crate::admin::get_key)
                    .delete(crate::admin::delete_key)
                    .patch(crate::admin::update_key),
            )
            .route("/keys/{id}/usage", get(crate::admin::key_usage))
            .route("/keys/{id}/rotate", post(crate::admin::rotate_key))
            // 1.5.0 signed-token keys: revoke a key (denylist, keep the binding) and rotate the
            // busbar key-signing key (revoke-all).
            .route("/keys/{id}/revoke", post(crate::admin::revoke_key))
            .route(
                "/signing-key/rotate",
                post(crate::admin::rotate_signing_key),
            )
            // EVERY response on this surface speaks the frozen envelope — including an unmatched
            // path (404 `not_found`) and a matched path with the wrong method (405
            // `method_not_allowed`). Without these, axum's nest semantics leak an empty-body 405
            // from the inner MethodRouter and fall unmatched paths through to the data plane's
            // vendor-native shaping (re-audit HIGH-1).
            .fallback(|| async { err_json(&AdminError::NotFound("resource".into())) })
            .method_not_allowed_fallback(|| async { err_json(&AdminError::MethodNotAllowed) })
    }
}

/// Build a per-request `AdminService` over the CURRENT snapshot loaded from the handle.
fn service(handle: &Arc<AppHandle>) -> AdminService {
    AdminService::new(handle.load())
}

/// Absolute admin path from a RELATIVE one — `contract::ADMIN_PREFIX` + `rel`. The OpenAPI doc keys
/// (which document the WIRE, so they must be absolute) are all built through this, so no absolute
/// path is ever hand-written here and none can drift from the mount grammar.
// Only `openapi_doc()` (feature `openapi-schema`) calls this; the function is compiled solely under
// that feature, so `ap` is dead in every build without it — allow it there.
#[cfg_attr(not(feature = "openapi-schema"), allow(dead_code))]
fn ap(rel: &str) -> String {
    format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX)
}

/// §6.3 BODY-DERIVED AUTHORIZATION REFINEMENT for hook registration. The route matrix admits a
/// `hooks-register` principal to POST/PUT `/api/v1/admin/hooks*`, but that scope is "define a hook,
/// don't wire it into a security-critical path". A non-`Full` caller therefore may NOT register a
/// hook that (a) sees or rewrites caller content/identity (`prompt`/`user` above `no`) or (b) sets
/// inline `global: true` — attaching to every request is chain WIRING, which is full-only. `Full`
/// (operator token, mapped-full, or the open dev posture) is unrestricted. Returns the 403 to
/// surface, or `None` to allow.
fn hooks_register_escalation(
    scope: crate::auth::AdminScope,
    cfg: &crate::config::HookCfg,
) -> Option<AdminError> {
    use crate::admin::v1::contract::Scope;
    if scope.0 == Some(Scope::Full) {
        return None;
    }
    if cfg.global
        || cfg.prompt != crate::config::PromptAccess::No
        || cfg.user != crate::config::UserAccess::No
    {
        return Some(AdminError::Forbidden {
            needed: Scope::Full,
        });
    }
    None
}

/// Serializes config-plane MUTATIONS (hook register/replace/delete, config apply/reload/rollback,
/// settings, auth chain) so each `read current → build next → swap → record` runs atomically with
/// respect to the others. READS stay lock-free (`handle.load()`), and mutations are rare
/// admin-only operations, so this never touches request-serving latency. Without it, two
/// concurrent mutations both read version N, both build N+1, and one swap is silently lost while
/// the version log gains two divergent N+1 entries; and a settings PATCH could have another
/// mutation slip in during its (up to 5s) configure-ack await. The lock is held only across the
/// SYNC build+swap+record — never across a network await (the settings push happens BEFORE the
/// lock, then the version is re-validated under it).
static CONFIG_MUTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ── JSON wire helpers (v1) ───────────────────────────────────────────────────────────────────────

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract` view
/// (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view appears
/// automatically (additive-only holds by construction).
fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        serde_json::to_string(view).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

/// Project an `AdminError` onto the stable v1 JSON error envelope
/// `{"error":{"code":<stable>,"message":<human>}}` with the error's HTTP status. Tooling branches on
/// `code`; `message` is human-only.
pub(crate) fn err_json(e: &AdminError) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
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

/// Decode the opaque `?cursor=` into a start offset (0 when absent). A malformed/foreign cursor is a
/// 400 `invalid_request` — never a silent skip — so every cursor-paginated handler rejects it the same.
// The Err variant is an axum `Response` (the ready-to-return 400) — intentionally, so callers just
// `return` it; that makes the Result "large", which is fine for a per-request handler helper.
#[allow(clippy::result_large_err)]
fn cursor_offset(q: &std::collections::HashMap<String, String>) -> Result<usize, Response> {
    match q.get("cursor") {
        None => Ok(0),
        Some(c) => crate::admin::v1::contract::decode_offset_cursor(c).ok_or_else(|| {
            err_json(&AdminError::Validation(
                "invalid or foreign pagination cursor".into(),
            ))
        }),
    }
}

/// Given a slice fetched with `limit + 1` starting at `start`, trim it IN PLACE to `limit` and return
/// the next opaque cursor iff the probe row existed (i.e. a further page remains). The one seam that
/// gives keys/audit/versions an identical `{items, next_cursor}` continuation.
fn page_cursor<T>(items: &mut Vec<T>, start: usize, limit: usize) -> Option<String> {
    if items.len() > limit {
        items.truncate(limit);
        Some(crate::admin::v1::contract::encode_offset_cursor(
            start.saturating_add(limit),
        ))
    } else {
        None
    }
}

/// Parse the optional `If-Match` header into the caller's expected config version (H3: ONE
/// optimistic-concurrency mechanism across the whole surface — the RFC-7232 header, exactly as the
/// keys resource already speaks it; there is no body-level `expected_version` twin). Grammar: the
/// config-plane ETag is the config version quoted (`"42"`); a bare `42` is accepted leniently and
/// `*` (RFC: "any current representation") matches unconditionally, i.e. no guard. Anything else is
/// a 400 `invalid_request` — a malformed guard must never silently pass as "no guard".
// The Err variant is the ready-to-return 400 `Response` — intentional (callers just `return` it);
// a "large" Result is fine for a per-request handler helper.
#[allow(clippy::result_large_err)]
fn if_match_version(headers: &axum::http::HeaderMap) -> Result<Option<u64>, Response> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    let bare = s.strip_prefix("W/").unwrap_or(s); // weak tags compare by value here
    let bare = bare.trim_matches('"');
    bare.parse::<u64>().map(Some).map_err(|_| {
        err_json(&AdminError::Validation(
            "malformed If-Match: expected the config-plane ETag (a quoted config version, e.g. \
             \"42\") or *"
                .into(),
        ))
    })
}

/// The stale-guard rejection every version-guarded mutation shares: the caller's `If-Match` version
/// vs the live one. `None` (absent / `*`) never rejects.
fn stale_if_match(expected: Option<u64>, current: u64) -> Option<AdminError> {
    match expected {
        // RETRYABLE: re-read the resource (fresh ETag) and retry — its own frozen code, split
        // from terminal `conflict` (external review R3).
        Some(v) if v != current => Some(AdminError::VersionConflict(format!(
            "If-Match version {v} is stale (current is {current})"
        ))),
        _ => None,
    }
}

/// Stamp the config-plane `ETag` (`"<config_version>"`) onto a response — the token `If-Match`
/// guards against. Emitted on the version-guarded reads AND on every successful mutation (whose new
/// version the caller chains into its next `If-Match`).
fn with_config_etag(mut resp: Response, version: u64) -> Response {
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
        resp.headers_mut().insert(axum::http::header::ETAG, v);
    }
    resp
}

// ── route handlers (thin: call the service, project onto the wire) ───────────────────────────────

mod handlers;
pub(crate) use handlers::*;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
