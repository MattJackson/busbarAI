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

use super::contract::AdminError;
use super::service::{build_with_hook, build_with_registry, build_without_hook, AdminService};
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
            .route("/hooks", get(list_hooks).post(register_hook))
            .route(
                "/hooks/{name}",
                get(get_hook).put(put_hook).delete(delete_hook),
            )
            .route("/hooks/{name}/health", get(hook_health))
            .route("/hooks/{name}/settings", patch(patch_hook_settings))
            .route("/hooks/{name}/schema", get(hook_schema))
            .route("/plugins", get(list_plugins))
            .route("/auth", get(get_auth))
            .route("/admin-auth", get(get_admin_auth).put(put_auth))
            .route("/usage", get(get_usage))
            .route("/config", get(get_config))
            .route("/audit", get(get_audit))
            .route("/config/validate", post(validate_config))
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
    }
}

/// Build a per-request `AdminService` over the CURRENT snapshot loaded from the handle.
fn service(handle: &Arc<AppHandle>) -> AdminService {
    AdminService::new(handle.load())
}

/// Absolute admin path from a RELATIVE one — `contract::ADMIN_PREFIX` + `rel`. The OpenAPI doc keys
/// (which document the WIRE, so they must be absolute) are all built through this, so no absolute
/// path is ever hand-written here and none can drift from the mount grammar.
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
        Some(v) if v != current => Some(AdminError::Conflict(format!(
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

/// `GET /api/v1/admin/info` — version, compiled-in plugin proof, uptime, topology.
async fn info(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).info().await)
}

/// `GET /api/v1/admin/pools` — pool topology read.
async fn list_pools(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_pools().await)
}

/// `GET /api/v1/admin/pools/{name}` — live per-member status of one pool (404 if unknown).
async fn get_pool(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    respond(StatusCode::OK, service(&handle).get_pool(&name).await)
}

/// `GET /api/v1/admin/models` — model lanes + providers.
async fn list_models(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_models().await)
}

/// `GET /api/v1/admin/providers` — distinct providers + lane counts.
async fn list_providers(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_providers().await)
}

/// `GET /api/v1/admin/hooks` — the hook registry read (+ config-plane `ETag` for `If-Match` chaining).
async fn list_hooks(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).list_hooks().await),
        version,
    )
}

/// `GET /api/v1/admin/hooks/{name}` — one hook definition (404 if unregistered; + config-plane `ETag`).
async fn get_hook(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_hook(&name).await),
        version,
    )
}

/// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability (404 if unregistered).
async fn hook_health(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    respond(StatusCode::OK, service(&handle).hook_health(&name).await)
}

/// `GET /api/v1/admin/plugins?type=auth|hooks` — the plugin catalog for one type. A missing/unknown
/// `type` is an `invalid_request` (the two types are distinct engine contracts).
async fn list_plugins(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service(&handle).list_plugins(ptype).await)
}

/// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode (no secrets).
async fn get_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_auth().await)
}

/// `GET /api/v1/admin/admin-auth` — the admin-plane auth config (the admin surface guard;
/// + config-plane `ETag` so a `PUT /api/v1/admin/admin-auth` can chain `If-Match` off this read).
async fn get_admin_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_admin_auth().await),
        version,
    )
}

/// `GET /api/v1/admin/usage` — fleet usage aggregation (spend/tokens/requests, per-key).
async fn get_usage(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_usage().await)
}

/// `GET /api/v1/admin/config` — the effective running config snapshot (redacted; no secrets;
/// + config-plane `ETag` so apply/rollback callers chain `If-Match` off this read).
async fn get_config(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_config().await),
        version,
    )
}

/// The `POST /api/v1/admin/hooks` request body: the hook name + its definition. Optimistic concurrency
/// rides the `If-Match` header (H3) — never a body field.
#[derive(serde::Deserialize)]
struct RegisterHookReq {
    name: String,
    config: crate::config::HookCfg,
}

/// The `PUT /api/v1/admin/hooks/{name}` body: the replacement definition (the name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
struct PutHookReq {
    config: crate::config::HookCfg,
}

/// `POST /api/v1/admin/hooks` — register (or replace) a hook at RUNTIME. Validates the definition, builds
/// the next `App` snapshot with the hook wired + transports re-resolved, atomically `swap`s it in, and
/// returns `201` with the registered hook. A `global` hook is LIVE immediately (new requests see it);
/// in-flight requests finish on the old snapshot. Lanes/store are untouched — live breaker state is
/// preserved. This is the first API-driven config mutation.
async fn register_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RegisterHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // §6.3: a hooks-register principal may not register a content-seeing / global (wired) hook.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.register",
            &format!("hook:{}", req.name),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{}", req.name);
    // A base-config-defined hook may NOT be shadowed/redirected via the API — the same guard PUT
    // and PATCH enforce (put_hook / patch_hook_settings). Without it a narrow hooks-register token
    // could POST a same-shape definition over a base hook's name and silently redirect its
    // transport (e.g. point a base `pii-guard` gate at a hostile socket). Edit config.yaml for base
    // hooks. (found: audit c1r5 — register was the one mutation verb missing this check.)
    if current.base_hook_names.contains(&req.name) {
        audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)",
            req.name
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    match build_with_hook(&current, &req.name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_APPLIED, &actor);
            // Persist the new hook state to the overlay (best-effort; no-op when persistence disabled).
            // Clear any tombstone for this name — a re-register un-deletes it.
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.register {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&req.name),
            );
            // Project the registered hook from the NEW (post-swap) snapshot for the 201 body; the
            // new config-plane ETag rides along so the caller chains its next If-Match without a read.
            with_config_etag(
                respond(
                    StatusCode::CREATED,
                    service(&handle).get_hook(&req.name).await,
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/hooks/{name}` — REPLACE an existing hook definition at runtime (live, atomic
/// swap). `404 not_found` for an unregistered name (PUT replaces; POST creates). `409 conflict`
/// for a BASE-defined hook (operator file config is edited in the file, never silently shadowed
/// via the API) and for a grant change (`kind`/`prompt`/`user` are immutable — §6.4, enforced in
/// `build_with_hook`). Audited + versioned + overlay-persisted like every mutation.
async fn put_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // §6.3: a hooks-register principal may not replace a hook into a content-seeing / global form.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.replace",
            &format!("hook:{name}"),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{name}");
    if !current.hook_registry.contains_key(&name) {
        // Audit the 404 like every other reject in this handler (and like DELETE's 404) — otherwise
        // an attacker can probe which hook names exist via the response code with no audit trail.
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    }
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    match build_with_hook(&current, &name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.replace {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/hooks/{name}` — remove an API-registered hook at RUNTIME (live). Builds the next
/// snapshot without the hook (dropped from the registry + global wiring, transports re-resolved) and
/// swaps it in. `404 not_found` if the hook is unregistered; `409 conflict` if the hook is
/// base-config-defined (base hooks are file-owned and read-only via the API — the same posture as
/// PUT/PATCH; edit config.yaml to remove one). `204 No Content` on success.
async fn delete_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{name}");
    // Optimistic concurrency (H3): DELETE honors `If-Match` like every other config-plane mutation
    // (it previously had NO guard — the one mutation verb missing it).
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    // §6.3 escalation guard, keyed on the EXISTING hook's grants — a non-Full (hooks-register)
    // principal may not DELETE a content-seeing (`prompt`/`user`) or `global: true` gate. Such a
    // hook can only have been created by a Full admin (register/put block a narrow token from wiring
    // one), and DELETING it TEARS DOWN that admin's security gate — the same escalation register /
    // put / patch already forbid. Without this a hooks-register token could remove an operator's
    // global `pii-guard` gate and reach content by the back door. (found: audit c1r13; the sibling
    // c1r6 fix closed the PATCH path — DELETE was the remaining verb missing the guard.)
    if let Some(existing) = current.hook_registry.get(&name) {
        if let Some(e) = hooks_register_escalation(scope, existing) {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&e);
        }
    }
    // A base-config hook is read-only via the API (consistent with put_hook / patch_hook_settings).
    // Without this a narrow hooks-register token could DELETE an operator's base-defined security
    // gate (e.g. `pii-guard`) — an escalation beyond "register" — and the additive overlay can't
    // durably subtract a base hook anyway. Edit config.yaml. (found: audit c1r5.)
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    match build_without_hook(&current, &name) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // Tombstone this name so the deletion survives a restart even if the hook was base-defined.
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.delete {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                Some(&name),
                None,
            );
            // 204 still carries the NEW config-plane ETag — a scripted delete chain needs no re-read.
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/audit` — the admin audit log (most-recent-first), every mutation with its outcome.
/// Filters: `?action=hook.register`, `?resource=hook:x`. Paginated by the shared cursor envelope:
/// `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}` (next_cursor iff more).
async fn get_audit(Query(q): Query<std::collections::HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let action = q.get("action").map(String::as_str);
    let resource = q.get("resource").map(String::as_str);
    // Fetch one past the page to learn whether a further page exists, then trim to `limit`.
    let mut entries = audit::AUDIT.list_filtered(start, limit + 1, action, resource);
    let next_cursor = page_cursor(&mut entries, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": entries, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions` — version history metadata, newest first. Paginated by the shared
/// cursor envelope: `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}`.
async fn list_config_versions(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let mut versions = handle.load().versions.list(start, limit + 1);
    let next_cursor = page_cursor(&mut versions, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": versions, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions/{v}` — one retained version WITH its hook-surface snapshot.
async fn get_config_version(State(handle): State<Arc<AppHandle>>, Path(v): Path<u64>) -> Response {
    match handle.load().versions.get(v) {
        Some(cv) => ok_json(
            StatusCode::OK,
            &json!({
                "version": cv.version,
                "ts": cv.ts,
                "principal": cv.principal,
                "summary": cv.summary,
                "hooks": cv.hook_registry,
                "global_hooks": cv.global_hooks,
            }),
        ),
        None => err_json(&AdminError::NotFound(format!(
            "config version {v} (pruned or never recorded)"
        ))),
    }
}

/// `GET /api/v1/admin/config/diff?from=&to=` — structured hook-surface diff between two retained
/// versions: hook names added / removed / changed (definition differs), plus the global wiring of
/// each side when it changed.
async fn config_diff(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (Some(from), Some(to)) = (
        q.get("from").and_then(|s| s.parse::<u64>().ok()),
        q.get("to").and_then(|s| s.parse::<u64>().ok()),
    ) else {
        return err_json(&AdminError::Validation(
            "`from` and `to` query params (version numbers) are required".into(),
        ));
    };
    let app = handle.load();
    let (Some(a), Some(b)) = (app.versions.get(from), app.versions.get(to)) else {
        return err_json(&AdminError::NotFound(format!(
            "config version {from} and/or {to} (pruned or never recorded)"
        )));
    };
    let mut added: Vec<&String> = b
        .hook_registry
        .keys()
        .filter(|k| !a.hook_registry.contains_key(*k))
        .collect();
    let mut removed: Vec<&String> = a
        .hook_registry
        .keys()
        .filter(|k| !b.hook_registry.contains_key(*k))
        .collect();
    // "Changed" = present in both with a differing definition. HookCfg has no PartialEq (transport
    // objects don't); compare the serialized form — the definition IS its config shape.
    let mut changed: Vec<&String> = a
        .hook_registry
        .iter()
        .filter(|(k, va)| {
            b.hook_registry
                .get(*k)
                .is_some_and(|vb| serde_json::to_value(va).ok() != serde_json::to_value(vb).ok())
        })
        .map(|(k, _)| k)
        .collect();
    added.sort();
    removed.sort();
    changed.sort();
    let mut body = json!({
        "from": from,
        "to": to,
        "hooks": { "added": added, "removed": removed, "changed": changed },
    });
    if a.global_hooks != b.global_hooks {
        body["global_hooks"] = json!({ "from": a.global_hooks, "to": b.global_hooks });
    }
    ok_json(StatusCode::OK, &body)
}

/// The `POST /api/v1/admin/config/rollback` request body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
struct RollbackReq {
    /// The retained version to restore.
    version: u64,
}

/// `POST /api/v1/admin/config/rollback` — restore a retained version's hook surface. The target is
/// RE-VALIDATED against current reality before the swap (a rollback that no longer resolves is
/// rejected, never blindly applied); the result is a NEW version (history is append-only — rolling
/// back never rewrites it), audited and overlay-persisted.
async fn rollback_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RollbackReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed rollback body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("config:v{}", req.version);
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by(
            "config.rollback",
            &resource,
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let Some(target) = current.versions.get(req.version) else {
        audit::AUDIT.record_by(
            "config.rollback",
            &resource,
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&AdminError::NotFound(format!(
            "config version {} (pruned or never recorded)",
            req.version
        )));
    };
    match build_with_registry(&current, target.hook_registry, target.global_hooks) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("config.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("config.rollback to v{}", req.version),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            // Best-effort overlay persistence of the restored surface (no-op when disabled).
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                None,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "restored_version": req.version,
                        "new_version": cur.config_version,
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.rollback",
                &resource,
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/admin-auth` — replace the ADMIN auth chain (`admin_auth:`) at runtime. Pairs with
/// `GET /api/v1/admin/admin-auth`, which reports the same `admin_auth` chain (read-after-write coherent).
/// Body:
/// `{"admin_auth": ["module", ...]}`. Guarded three ways:
/// - every name must be a compiled-in admin module (a typo can never silently drop auth);
/// - optimistic concurrency via `If-Match` (409 `conflict` when stale);
/// - **the D4 DRY-RUN GUARD**: the CALLING request's own credentials are re-evaluated against the
///   CANDIDATE chain, and unless they would still hold FULL scope under it the change is rejected
///   with 409 — you cannot lock yourself out with this endpoint. (A chain broken some other way
///   is fix-config + restart: sub-second, health persists.)
///
/// Applied live and atomically (config-version bump, audited); like `config/apply`, the change is
/// live until the next reload/restart returns to disk truth — persist by updating config.yaml.
async fn put_auth(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PutAuthBody {
        admin_auth: Vec<String>,
    }
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutAuthBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return err_json(&AdminError::Validation(format!("invalid body: {e}"))),
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        // Audit the rejected attempt (§6.7: every mutation attempt leaves a trail — uniform with
        // every other stale-If-Match rejection in this file, and with put_auth's own
        // dry-run-guard rejection below).
        audit::AUDIT.record_by(
            "auth.admin_chain_put",
            "auth:admin_auth",
            audit::OUTCOME_REJECTED,
            principal.actor_id(),
        );
        return err_json(&e);
    }
    // Known-module validation (mirrors the boot rule): `admin-tokens` is the built-in; the
    // test-only stand-in exists in test builds only. An unknown name can never silently drop auth.
    for name in &req.admin_auth {
        let known = name == "admin-tokens" || (cfg!(test) && name == "test-scope-module");
        if !known {
            return err_json(&AdminError::Validation(format!(
                "admin_auth names unknown module '{name}'; the built-in admin module is \
                 `admin-tokens` (external admin modules are registered at compile time)"
            )));
        }
    }
    if req.admin_auth.is_empty() {
        tracing::warn!(
            "PUT /api/v1/admin/admin-auth applied an EMPTY admin_auth chain — the admin API is now the \
             open (anonymous, full-authority) dev posture"
        );
    }
    // Candidate app with the new chain.
    let mut next = (*current).clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.admin_chain = req.admin_auth.clone();
    // D4 DRY-RUN GUARD: this very request's carriers, evaluated under the CANDIDATE chain.
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::auth::AuthMiddleware::extract_bearer_token);
    let header_tok = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let survives = matches!(
        crate::auth::dry_run_admin_scope(&next, bearer.as_deref(), header_tok.as_deref()),
        Some(crate::admin::v1::contract::Scope::Full)
    );
    if !survives {
        audit::AUDIT.record_by(
            "auth.admin_chain_put",
            "auth:admin_auth",
            audit::OUTCOME_REJECTED,
            principal.actor_id(),
        );
        return err_json(&AdminError::Conflict(
            "the new admin_auth chain would not grant THIS caller full scope — refusing to lock \
             you out. Authenticate with a credential the new chain accepts (at full scope) and \
             retry, or change the chain in config.yaml and restart"
                .into(),
        ));
    }
    let installed = Arc::new(next);
    handle.swap(installed.clone());
    audit::AUDIT.record_by(
        "auth.admin_chain_put",
        "auth:admin_auth",
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    let cur = handle.load();
    installed.versions.record(
        installed.config_version,
        principal.actor_id(),
        "auth.admin_chain_put",
        &installed.hook_registry,
        &installed.global_hooks,
    );
    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "applied": true,
                "admin_auth": req.admin_auth,
                "config_version": cur.config_version,
                "note": "live until the next config reload/restart returns to disk truth; persist by updating config.yaml"
            }),
        ),
        cur.config_version,
    )
}

/// `POST /api/v1/admin/auth/cache/flush` — INSTANT REVOCATION of the credential cache's
/// cached-allow window (design-hooks-v2 §2.5). Body `{"module": "<name>"}` flushes one module's
/// partition; no/empty body flushes everything. The deny path never needed this (`Reject` is
/// never cached); this closes the Identify window when a directory changes NOW.
async fn flush_credential_cache(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let app = handle.load();
    let module: Option<String> = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(v) => match v.get("module") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(m)) => Some(m.clone()),
                Some(_) => {
                    return err_json(&AdminError::Validation(
                        "`module` must be a string (the auth module whose partition to flush)"
                            .into(),
                    ))
                }
            },
            Err(_) => return err_json(&AdminError::Validation("body must be JSON".into())),
        }
    };
    let flushed = match module.as_deref() {
        Some(m) => app.credential_cache.flush_module(m),
        None => app.credential_cache.flush_all(),
    };
    audit::AUDIT.record_by(
        "auth.cache_flush",
        module.as_deref().unwrap_or("*"),
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    ok_json(StatusCode::OK, &json!({ "flushed": flushed }))
}

/// `POST /api/v1/admin/config/reload` — re-run the BOOT disk-load pipeline (config.yaml +
/// providers.yaml + env interpolation from the boot-time environment + overlay merge), validate,
/// build a complete new `App` reusing process-lifetime state (client pool, governance DB, version
/// history, rate windows) with every surviving lane's health RESTORED BY STABLE IDENTITY, and
/// atomically swap it in. A NORMAL admin call under the NORMAL admin auth chain — no second
/// credential path exists (D3). Invalid disk config = `invalid_request`, nothing changes. The
/// GitOps primitive: push config, call reload, no restart, no health amnesia.
async fn reload_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return err_json(&AdminError::Validation(
            "this busbar was started without config files (ephemeral mode); reload has no disk \
             truth to read"
                .into(),
        ));
    };
    let outcome =
        crate::load_config_from_disk(&config_path, &providers_path, false).and_then(|loaded| {
            let cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
                .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
            crate::build_app_from_config(
                cfg,
                loaded.deploy.governance.clone(),
                loaded.overlay_path,
                loaded.base_hook_names,
                (Some(config_path), Some(providers_path)),
                Some(&current),
            )
        });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.reload (from disk)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({ "reloaded": true, "config_version": cur.config_version }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&AdminError::Validation(e))
        }
    }
}

/// The `POST /api/v1/admin/config/apply` body: a full proposed config (validate's exact shape).
/// Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
struct ApplyConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape). Optional — empty validates/fails loudly
    /// on dangling references.
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /api/v1/admin/config/apply` — apply a FULL config carried in the request body, atomically:
/// resolve + validate (an invalid config is a 400 that changes nothing), build a complete new
/// `App` reusing process-lifetime state, carry every surviving lane's health BY STABLE IDENTITY
/// (D1), swap. The body-carried twin of `config/reload` (disk) — Terraform/CI push the config they
/// hold instead of writing files. NOTE: an applied config is LIVE but not written to disk — the
/// next reload/restart returns to disk truth (+overlay); the response says so.
async fn apply_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: ApplyConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by(
            "config.apply",
            "config:body",
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let base_hook_names: std::collections::HashSet<String> =
        req.config.hooks.keys().cloned().collect();
    let outcome = crate::config::resolve(&req.config, &req.providers)
        .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))
        .and_then(|cfg| {
            crate::build_app_from_config(
                cfg,
                req.config.governance.clone(),
                current.overlay_path.clone(),
                base_hook_names,
                (current.config_path.clone(), current.providers_path.clone()),
                Some(&current),
            )
        });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.apply (request body)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": cur.config_version,
                        "note": "live until the next reload/restart returns to disk truth; persist \
                                 by updating config.yaml",
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&AdminError::Validation(e))
        }
    }
}

/// The `PATCH /api/v1/admin/hooks/{name}/settings` body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
struct PatchSettingsReq {
    settings: serde_json::Map<String, serde_json::Value>,
}

/// `PATCH /api/v1/admin/hooks/{name}/settings` — push an opaque settings map to the RUNNING hook and
/// COMMIT ON ACK (D2): busbar sends the `configure` message over the hook's transport, waits for
/// the versioned ack (5s deadline), and only then swaps in the registry update (grants untouched —
/// immutability holds by construction) + persists + audits + versions. A nack/timeout/error
/// commits NOTHING (`invalid_request` names the reason). Base-defined hooks are 409 (edit the
/// file). Socket hooks ALSO receive the committed settings as the configure preamble on every
/// future (re)connection, so a restarted hook never runs blind.
async fn patch_hook_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PatchSettingsReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed settings body: {e}"
            )))
        }
    };
    // BOUND the settings map. It is persisted verbatim into the state file AND re-sent to the hook
    // as the configure preamble on EVERY (re)connection, so an unbounded map amplifies both the
    // snapshot size and per-reconnect wire traffic. Cap the serialized size and the key count as
    // defense-in-depth (admin-gated, but a compromised hooks-register token should not be able to
    // bloat the durable state / reconnect path). The caps are far past any real hook's settings.
    if let Err(e) = crate::admin::v1::service::validate_hook_settings_size(&req.settings) {
        return err_json(&e);
    }
    let current = handle.load();
    let resource = format!("hook:{name}");
    let Some(existing) = current.hook_registry.get(&name) else {
        // Audit the 404 like the other rejects here (and DELETE) — a missing audit row on the
        // unknown-name path lets a narrow token probe which hooks exist by response code alone.
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    };
    // §6.3 escalation guard, keyed on the EXISTING hook's grants (PATCH changes settings, not
    // grants). A non-Full (hooks-register) principal may not push settings to a content-seeing
    // (`prompt`/`user`) or `global: true` hook — the same ceiling register_hook/put_hook enforce.
    // Without it a narrow token could retune a `prompt: rw` global gate it can neither create nor
    // replace, reaching a content-seeing hook by the back door. (found: audit c1r6.)
    if let Some(e) = hooks_register_escalation(scope, existing) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    let mut updated = existing.clone();
    updated.settings = req.settings;
    let pre_push_version = current.config_version;
    let settings_version = pre_push_version.wrapping_add(1);
    // PUSH first, COMMIT on ack — a hook that never acked never sees committed state it doesn't
    // hold (§6.5: no partial config ever goes live). The client is captured here; the load() that
    // feeds the actual swap is re-taken AFTER the await, under the mutation lock.
    let client = current.client.clone();
    if let Err(e) = crate::routing::push_configure(&updated, &name, settings_version, &client).await
    {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(format!(
            "hook did not acknowledge the settings push: {e}"
        )));
    }
    // COMMIT under the mutation lock, guarding the configure-ack await window: if any config-plane
    // mutation landed while we were awaiting the ack, `current` is stale and swapping on it would
    // clobber that change (and reuse its version number). Re-validate the version under the lock;
    // a change means "config moved during your push" → 409, retry (the ack was for a now-stale
    // snapshot). Version unchanged ⇒ `current` is still the live snapshot, so the build is sound.
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if current.config_version != pre_push_version {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(
            "config changed during the settings push; retry".to_string(),
        ));
    }
    match build_with_hook(&current, &name, updated) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.settings {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/hooks/{name}/schema` — proxy the hook's self-described settings JSON Schema
/// (the `describe` wire message). `{"schema": null}` when the hook/transport doesn't answer.
async fn hook_schema(State(handle): State<Arc<AppHandle>>, Path(name): Path<String>) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    };
    let schema = crate::routing::fetch_schema(hook, &current.client).await;
    ok_json(StatusCode::OK, &json!({ "name": name, "schema": schema }))
}

/// The stable v1 GET endpoints (RELATIVE path, summary), the single source for both the
/// router-mount drift test and the OpenAPI `paths`. Paths are relative to `contract::ADMIN_PREFIX`
/// (no absolute path is hand-written anywhere — the `ap` helper derives them). Templated/POST
/// routes are documented separately in `openapi_doc`. Adding a GET endpoint means adding it here so
/// the doc + the drift guard both see it.
pub(crate) const V1_GET_PATHS: &[(&str, &str)] = &[
    (
        "/info",
        "Version, compiled-in plugin proof, uptime, topology",
    ),
    ("/pools", "Pool topology (members + weights)"),
    ("/models", "Model lanes + upstream providers"),
    ("/providers", "Distinct providers + lane counts"),
    ("/hooks", "Hook registry (definitions)"),
    (
        "/plugins",
        "Plugin catalog by type (compiled-in + external)",
    ),
    (
        "/auth",
        "Ingress auth chain + upstream-credential mode",
    ),
    (
        "/admin-auth",
        "Admin-plane auth config (the admin surface guard)",
    ),
    (
        "/usage",
        "Fleet usage aggregation (spend/tokens/requests, per-key)",
    ),
    (
        "/config",
        "Effective running config snapshot (redacted)",
    ),
    (
        "/audit",
        "Admin audit log — every mutation with its outcome (newest first). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    (
        "/config/versions",
        "Config version history (newest first; id/ts/principal/summary). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    ("/openapi.json", "This OpenAPI 3.1 document"),
];

/// Build the OpenAPI 3.1 document describing the v1 JSON-REST surface. Paths + methods + the stable
/// error envelope are the machine-readable contract (tooling generates clients + branches on the error
/// `code`). Response bodies are described loosely (not full struct schemas) today — the additive
/// follow-up derives per-view schemas; paths/methods/error shape are the frozen part callers rely on.
fn openapi_doc() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for (path, summary) in V1_GET_PATHS {
        paths.insert(
            ap(path),
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
    if let Some(obj) = paths.get_mut(&ap("/hooks")).and_then(|p| p.as_object_mut()) {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Register (or replace) a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Registered (body is the hook definition)"},
                    "400": {"description": "Malformed body or invalid definition (`invalid_request`)"},
                    "403": {"description": "hooks-register principal may not register a content-seeing (`prompt`/`user`) or `global: true` hook (`forbidden`, §6.3)"},
                    "409": {"description": "Base-defined hook (edit config.yaml), grant change on an existing hook, or stale `If-Match` (`conflict`, §6.4)"}
                }
            }),
        );
    }
    // Templated + non-GET routes.
    paths.insert(
        ap("/hooks/{name}"),
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
            "put": {
                "summary": "Replace an overlay hook definition — live immediately (grants immutable)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced hook"},
                    "400": {"description": "Invalid definition (error code `invalid_request`)"},
                    "403": {"description": "A `hooks-register` principal may not replace a hook into a content-seeing (`prompt`/`user`) or `global` form (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook, grant change, or stale `If-Match` (error code `conflict`)"}
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
                    "403": {"description": "A `hooks-register` principal may not delete a content-seeing (`prompt`/`user`) or `global` hook (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook — read-only via the API; edit config.yaml (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/pools/{name}"),
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
        ap("/hooks/{name}/health"),
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
        ap("/config/diff"),
        json!({
            "get": {
                "summary": "Structured hook-surface diff between two retained versions",
                "security": [{"adminToken": []}],
                "parameters": [
                    {"name": "from", "in": "query", "required": true, "schema": {"type": "integer"}},
                    {"name": "to", "in": "query", "required": true, "schema": {"type": "integer"}}
                ],
                "responses": {
                    "200": {"description": "The diff (hooks added/removed/changed + global-wiring delta)"},
                    "400": {"description": "Missing/non-numeric `from` or `to` (error code `invalid_request`)"},
                    "404": {"description": "Either version pruned or never recorded (error code `not_found`)"},
                    "401": {"description": "Missing/invalid admin credential"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/versions/{v}"),
        json!({
            "get": {
                "summary": "One retained config version, with its hook-surface snapshot",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "v", "in": "path", "required": true,
                    "schema": {"type": "integer"}
                }],
                "responses": {
                    "200": {"description": "The version (metadata + hooks + global_hooks)"},
                    "404": {"description": "Pruned or never recorded (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/settings"),
        json!({
            "patch": {
                "summary": "Push an opaque settings map to the running hook; COMMIT ON ACK",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "Acked + committed (the updated hook)"},
                    "400": {"description": "Hook did not acknowledge (error code `invalid_request`); nothing committed"},
                    "403": {"description": "A `hooks-register` principal may not push settings to a content-seeing (`prompt`/`user`) or `global` hook (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook or stale `If-Match` (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/schema"),
        json!({
            "get": {
                "summary": "The hook's self-described settings JSON Schema (describe proxy)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "`{name, schema}` (`schema` null when the hook doesn't answer describe)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/apply"),
        json!({
            "post": {
                "summary": "Apply a full config from the request body, atomically (live until next reload/restart; health preserved by lane identity)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied, config_version, note}`"},
                    "400": {"description": "Invalid config (error code `invalid_request`); nothing changed"},
                    "409": {"description": "stale `If-Match` (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/reload"),
        json!({
            "post": {
                "summary": "Re-read config.yaml/providers.yaml from disk and apply atomically (health state preserved by lane identity)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{reloaded, config_version}`"},
                    "400": {"description": "Disk config invalid or no config files (error code `invalid_request`); nothing changed"}
                }
            }
        }),
    );
    if let Some(auth_path) = paths.get_mut(&ap("/admin-auth")) {
        auth_path["put"] = json!({
            "summary": "Replace the admin_auth chain at runtime — dry-run guarded (the calling credentials must hold full scope under the NEW chain, else 409). Live until the next reload/restart",
            "security": [{"adminToken": []}],
            "responses": {
                "200": {"description": "`{applied, admin_auth, config_version, note}`"},
                "400": {"description": "Unknown module / malformed body (error code `invalid_request`)"},
                "409": {"description": "Stale `If-Match`, or the new chain would lock the caller out (error code `conflict`)"}
            }
        });
    }
    paths.insert(
        ap("/auth/cache/flush"),
        json!({
            "post": {
                "summary": "Flush the credential cache — one module's partition (`{module}`) or everything (empty body). Instant revocation of the cached-allow window",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{flushed}` — entries dropped"},
                    "400": {"description": "Malformed body (error code `invalid_request`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/rollback"),
        json!({
            "post": {
                "summary": "Restore a retained version's hook surface (re-validated; a NEW version)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{restored_version, new_version}`"},
                    "404": {"description": "Target version not retained (error code `not_found`)"},
                    "409": {"description": "stale `If-Match` (error code `conflict`)"},
                    "400": {"description": "Snapshot fails re-validation (error code `invalid_request`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/validate"),
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

    // Virtual-key management (mounted in main.rs, not the v1 router, but part of the frozen v1
    // surface — must be discoverable). The secret is shown ONCE at create/rotate and never read back.
    paths.insert(
        ap("/keys"),
        json!({
            "get": {
                "summary": "List virtual keys (metadata only; never secrets). Filters: ?enabled=, ?prefix=. Paginate: ?limit=, ?cursor= (opaque)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{items, next_cursor}` — the cursor page envelope (next_cursor null at end)"},
                    "400": {"description": "Malformed/foreign pagination cursor (error code `invalid_request`)"},
                    "401": {"description": "Missing/invalid admin credential"}
                }
            },
            "post": {
                "summary": "Mint a virtual key. The secret is returned EXACTLY once. Honors an `Idempotency-Key` header (per-principal ~10min replay)",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Created (body includes the once-shown secret)"},
                    "400": {"description": "Malformed body / invalid budget or rate (error code `invalid_request`)"},
                    "409": {"description": "An Idempotency-Key request is already in flight (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}"),
        json!({
            "get": {
                "summary": "One key's metadata + `ETag` (never the secret/hash)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Key metadata (+ `ETag` header)"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            },
            "patch": {
                "summary": "Update budget / rate / enabled. Optional `If-Match` for optimistic concurrency",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Updated metadata"},
                    "400": {"description": "Invalid budget/rate (error code `invalid_request`)"},
                    "404": {"description": "Unknown key (error code `not_found`)"},
                    "409": {"description": "Stale `If-Match` ETag (error code `conflict`)"}
                }
            },
            "delete": {
                "summary": "Revoke a key — it stops resolving immediately",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "204": {"description": "Revoked — No Content"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/usage"),
        json!({
            "get": {
                "summary": "Current-window usage for one key (spend / tokens / requests)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Usage counters"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/rotate"),
        json!({
            "post": {
                "summary": "Mint a fresh secret in place (same id, budgets, usage). The new secret is shown once; the old stops resolving",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Rotated (body includes the once-shown new secret)"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            }
        }),
    );

    // Stamp EVERY path+method with its required admin scope (`x-busbar-required-scope`) from the
    // SAME `required_scope` matrix the middleware enforces — the machine-readable authorization
    // matrix (§6.3), drift-proof by construction because both readers share one function. The
    // matrix keys on the literal path shape; templated segments (`{name}`) sit inside the same
    // prefix the matcher tests, so the annotation is exact for every route documented here.
    for (path, methods) in paths.iter_mut() {
        if let Some(obj) = methods.as_object_mut() {
            for (method, op) in obj.iter_mut() {
                let m = match method.as_str() {
                    "get" => axum::http::Method::GET,
                    "post" => axum::http::Method::POST,
                    "put" => axum::http::Method::PUT,
                    "patch" => axum::http::Method::PATCH,
                    "delete" => axum::http::Method::DELETE,
                    _ => continue,
                };
                if let Some(op) = op.as_object_mut() {
                    op.insert(
                        "x-busbar-required-scope".to_string(),
                        json!(crate::admin::v1::contract::required_scope(&m, path).as_str()),
                    );
                }
            }
        }
    }

    // Stamp the `If-Match` header parameter onto every version-guarded mutation (H3: the ONE
    // optimistic-concurrency mechanism across the surface). Driven by an explicit op list — NOT
    // "every mutation" — because the unguarded ops (validate: stateless dry-run; reload: returns to
    // disk truth unconditionally; cache/flush, key create/rotate: no versioned resource) must not
    // advertise a guard they don't enforce. Keys PATCH/DELETE guard on the KEY's own ETag; the
    // config-plane ops guard on the config-version ETag their reads emit.
    const IF_MATCH_GUARDED: &[(&str, &str)] = &[
        ("/hooks", "post"),
        ("/hooks/{name}", "put"),
        ("/hooks/{name}", "delete"),
        ("/hooks/{name}/settings", "patch"),
        ("/admin-auth", "put"),
        ("/config/apply", "post"),
        ("/config/rollback", "post"),
        ("/keys/{id}", "patch"),
        ("/keys/{id}", "delete"),
    ];
    for (path, method) in IF_MATCH_GUARDED {
        if let Some(op) = paths
            .get_mut(&ap(path))
            .and_then(|p| p.get_mut(*method))
            .and_then(|op| op.as_object_mut())
        {
            let param = json!({
                "name": "If-Match", "in": "header", "required": false,
                "schema": {"type": "string"},
                "description": "Optimistic concurrency: the resource's ETag from a prior read \
                                (or the ETag returned by the previous mutation). Stale = 409 \
                                `conflict`, nothing changes; absent or `*` = unconditional."
            });
            match op.get_mut("parameters").and_then(|p| p.as_array_mut()) {
                Some(params) => params.push(param),
                None => {
                    op.insert("parameters".to_string(), json!([param]));
                }
            }
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Busbar Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The frozen, additive-only /api/v1/admin surface. Errors use the stable \
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
                                             "conflict", "rate_limited", "internal"]},
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

/// `GET /api/v1/admin/openapi.json` — the OpenAPI 3.1 schema of the v1 surface (the discovery contract).
async fn openapi() -> Response {
    ok_json(StatusCode::OK, &openapi_doc())
}

/// The `POST /api/v1/admin/config/validate` request body: a full proposed config — the `config.yaml`
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

/// `POST /api/v1/admin/config/validate` — dry-run validate a proposed config. A malformed body is an
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

    /// Collect an axum Response into (status, content-type, parsed JSON body) for the wire-helper
    /// micro-tests below.
    async fn parts(resp: Response) -> (StatusCode, String, serde_json::Value) {
        let status = resp.status();
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).expect("body is JSON");
        (status, ct, body)
    }

    /// The error envelope projection is `{"error":{"code","message"}}` with the error's status — the
    /// shape v1 tooling parses — served as application/json.
    #[tokio::test]
    async fn err_json_uses_stable_envelope() {
        let (status, ct, body) = parts(err_json(&AdminError::NotFound("hook".into()))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(ct, crate::forward::APPLICATION_JSON);
        assert_eq!(body["error"]["code"], "not_found");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "message is human text, never empty"
        );
        assert_eq!(
            body["error"].as_object().unwrap().len(),
            2,
            "the envelope is exactly code+message (additive changes go OUTSIDE error)"
        );
    }

    /// `ok_json` serializes the view verbatim with the GIVEN status and application/json.
    #[tokio::test]
    async fn ok_json_serializes_view_with_given_status() {
        #[derive(Serialize)]
        struct View {
            name: &'static str,
            n: u32,
        }
        let (status, ct, body) =
            parts(ok_json(StatusCode::CREATED, &View { name: "x", n: 7 })).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(ct, crate::forward::APPLICATION_JSON);
        assert_eq!(body, json!({"name": "x", "n": 7}));
    }

    /// `respond` — the single seam every v1 handler funnels through — maps Ok to the given status
    /// and Err to the error's own status + envelope (the Ok-status never leaks onto an error).
    #[tokio::test]
    async fn respond_maps_ok_and_err() {
        let ok: Result<serde_json::Value, AdminError> = Ok(json!({"ok": true}));
        let (status, _, body) = parts(respond(StatusCode::OK, ok)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);

        let err: Result<serde_json::Value, AdminError> = Err(AdminError::RateLimited);
        let (status, _, body) = parts(respond(StatusCode::OK, err)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    /// Structural lock on the discovery doc: OpenAPI 3.1, an info.version that matches the crate,
    /// and every path under the ONE contract prefix (whose literal value is pinned by the golden
    /// test in contract.rs) — the doc never mixes prefixes.
    #[test]
    fn openapi_doc_is_31_and_v1_prefixed() {
        let doc = openapi_doc();
        assert!(
            doc["openapi"].as_str().unwrap().starts_with("3.1"),
            "discovery doc is OpenAPI 3.1"
        );
        assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
        let prefix = format!("{}/", crate::admin::v1::contract::ADMIN_PREFIX);
        for path in doc["paths"].as_object().unwrap().keys() {
            assert!(
                path.starts_with(&prefix),
                "{path} escaped the frozen {prefix} prefix"
            );
        }
    }

    /// CONTRACT LOCK: every openapi path+method is annotated with `x-busbar-required-scope`, and
    /// the annotation matches the enforced `required_scope` matrix exactly (one source of truth —
    /// this test guards against a future hand-written path entry forgetting or contradicting it).
    #[test]
    fn openapi_paths_annotate_required_scope() {
        let doc = openapi_doc();
        let paths = doc["paths"].as_object().expect("paths object");
        assert!(!paths.is_empty());
        for (path, methods) in paths {
            for (method, op) in methods.as_object().expect("methods") {
                let m = match method.as_str() {
                    "get" => axum::http::Method::GET,
                    "post" => axum::http::Method::POST,
                    "put" => axum::http::Method::PUT,
                    "patch" => axum::http::Method::PATCH,
                    "delete" => axum::http::Method::DELETE,
                    // Path-item `x-*` specification extensions (e.g. `x-busbar-error-envelope`) are
                    // valid OpenAPI and are not operations — they carry no scope annotation.
                    ext if ext.starts_with("x-") => continue,
                    other => panic!("unexpected method {other} on {path}"),
                };
                let annotated = op["x-busbar-required-scope"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} missing scope annotation"));
                let enforced = crate::admin::v1::contract::required_scope(&m, path).as_str();
                assert_eq!(annotated, enforced, "{method} {path} annotation drifted");
            }
        }
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
            AdminError::RateLimited,
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

    /// REGRESSION (audit c1r12): the §6.3 escalation 403 fires on PUT `/hooks/{name}` and PATCH
    /// `/hooks/{name}/settings` (a `hooks-register` principal touching a content-seeing / global
    /// hook), exactly as it does on POST `/hooks` — so all three must DOCUMENT the 403.
    #[test]
    fn openapi_hook_escalation_endpoints_document_403() {
        let doc = openapi_doc();
        let cases = [
            ("/api/v1/admin/hooks", "post"),
            ("/api/v1/admin/hooks/{name}", "put"),
            ("/api/v1/admin/hooks/{name}", "delete"),
            ("/api/v1/admin/hooks/{name}/settings", "patch"),
        ];
        for (path, method) in cases {
            assert!(
                doc["paths"][path][method]["responses"]["403"].is_object(),
                "{method} {path} can 403 on §6.3 escalation but its openapi omits it"
            );
        }
    }
}
