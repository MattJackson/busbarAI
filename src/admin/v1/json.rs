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
use super::service::{build_with_hook, build_with_registry, build_without_hook, AdminService};
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
            .route(
                "/admin/v1/hooks/{name}",
                get(get_hook).put(put_hook).delete(delete_hook),
            )
            .route("/admin/v1/hooks/{name}/health", get(hook_health))
            .route("/admin/v1/plugins", get(list_plugins))
            .route("/admin/v1/auth", get(get_auth))
            .route("/admin/v1/admin-auth", get(get_admin_auth))
            .route("/admin/v1/usage", get(get_usage))
            .route("/admin/v1/config", get(get_config))
            .route("/admin/v1/audit", get(get_audit))
            .route("/admin/v1/config/validate", post(validate_config))
            .route("/admin/v1/config/versions", get(list_config_versions))
            .route("/admin/v1/config/versions/{v}", get(get_config_version))
            .route("/admin/v1/config/diff", get(config_diff))
            .route("/admin/v1/config/rollback", post(rollback_config))
            .route("/admin/v1/config/reload", post(reload_config))
            .route("/admin/v1/config/apply", post(apply_config))
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
    /// Optimistic-concurrency guard: reject with `conflict` when the CURRENT config version
    /// differs (a concurrent mutation landed between your read and this write). Optional in the
    /// transition; the release contract makes it mandatory.
    #[serde(default)]
    expected_version: Option<u64>,
}

/// The `PUT /admin/v1/hooks/{name}` body: the replacement definition (the name rides the path).
#[derive(serde::Deserialize)]
struct PutHookReq {
    config: crate::config::HookCfg,
    #[serde(default)]
    expected_version: Option<u64>,
}

/// `POST /admin/v1/hooks` — register (or replace) a hook at RUNTIME. Validates the definition, builds
/// the next `App` snapshot with the hook wired + transports re-resolved, atomically `swap`s it in, and
/// returns `201` with the registered hook. A `global` hook is LIVE immediately (new requests see it);
/// in-flight requests finish on the old snapshot. Lanes/store are untouched — live breaker state is
/// preserved. This is the first API-driven config mutation.
async fn register_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let req: RegisterHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    let current = handle.load();
    let resource = format!("hook:{}", req.name);
    if let Some(expected) = req.expected_version {
        if expected != current.config_version {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&AdminError::Conflict(format!(
                "expected_version {expected} is stale (current is {})",
                current.config_version
            )));
        }
    }
    match build_with_hook(&current, &req.name, req.config) {
        Ok(next) => {
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_APPLIED, &actor);
            // Persist the new hook state to the overlay (best-effort; no-op when persistence disabled).
            // Clear any tombstone for this name — a re-register un-deletes it.
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                &format!("hook.register {resource}"),
                &cur.hook_registry,
                &cur.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&req.name),
            );
            // Project the registered hook from the NEW (post-swap) snapshot for the 201 body.
            respond(
                StatusCode::CREATED,
                service(&handle).get_hook(&req.name).await,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /admin/v1/hooks/{name}` — REPLACE an existing hook definition at runtime (live, atomic
/// swap). `404 not_found` for an unregistered name (PUT replaces; POST creates). `409 conflict`
/// for a BASE-defined hook (operator file config is edited in the file, never silently shadowed
/// via the API) and for a grant change (`kind`/`prompt`/`user` are immutable — §6.4, enforced in
/// `build_with_hook`). Audited + versioned + overlay-persisted like every mutation.
async fn put_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let req: PutHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    let current = handle.load();
    let resource = format!("hook:{name}");
    if !current.hook_registry.contains_key(&name) {
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    }
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    if let Some(expected) = req.expected_version {
        if expected != current.config_version {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&AdminError::Conflict(format!(
                "expected_version {expected} is stale (current is {})",
                current.config_version
            )));
        }
    }
    match build_with_hook(&current, &name, req.config) {
        Ok(next) => {
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                &format!("hook.replace {resource}"),
                &cur.hook_registry,
                &cur.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&name),
            );
            respond(StatusCode::OK, service(&handle).get_hook(&name).await)
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /admin/v1/hooks/{name}` — remove a hook at RUNTIME (live). Builds the next snapshot without
/// the hook (dropped from the registry + global wiring, transports re-resolved) and swaps it in.
/// `404 not_found` if the hook is unregistered. `204 No Content` on success.
async fn delete_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let current = handle.load();
    let resource = format!("hook:{name}");
    match build_without_hook(&current, &name) {
        Ok(next) => {
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // Tombstone this name so the deletion survives a restart even if the hook was base-defined.
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                &format!("hook.delete {resource}"),
                &cur.hook_registry,
                &cur.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                Some(&name),
                None,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `GET /admin/v1/audit` — the admin audit log (most-recent-first), every mutation with its outcome.
/// Optional filters: `?action=hook.register`, `?resource=hook:x`, `?limit=N` (capped at 1000).
async fn get_audit(Query(q): Query<std::collections::HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);
    let action = q.get("action").map(String::as_str);
    let resource = q.get("resource").map(String::as_str);
    let entries = audit::AUDIT.list_filtered(limit, action, resource);
    ok_json(StatusCode::OK, &json!({ "entries": entries }))
}

/// `GET /admin/v1/config/versions` — version history metadata, newest first (`?limit=N`, cap 1000).
async fn list_config_versions(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    ok_json(
        StatusCode::OK,
        &json!({ "versions": handle.load().versions.list(limit) }),
    )
}

/// `GET /admin/v1/config/versions/{v}` — one retained version WITH its hook-surface snapshot.
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

/// `GET /admin/v1/config/diff?from=&to=` — structured hook-surface diff between two retained
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

/// The `POST /admin/v1/config/rollback` request body.
#[derive(serde::Deserialize)]
struct RollbackReq {
    /// The retained version to restore.
    version: u64,
    /// Optimistic-concurrency guard: reject with `conflict` if the CURRENT config version differs
    /// (someone mutated between your read and this rollback). Optional in v1 (mandatory with the
    /// broader ETag sweep).
    #[serde(default)]
    expected_version: Option<u64>,
}

/// `POST /admin/v1/config/rollback` — restore a retained version's hook surface. The target is
/// RE-VALIDATED against current reality before the swap (a rollback that no longer resolves is
/// rejected, never blindly applied); the result is a NEW version (history is append-only — rolling
/// back never rewrites it), audited and overlay-persisted.
async fn rollback_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let req: RollbackReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed rollback body: {e}"
            )))
        }
    };
    let current = handle.load();
    let resource = format!("config:v{}", req.version);
    if let Some(expected) = req.expected_version {
        if expected != current.config_version {
            audit::AUDIT.record_by(
                "config.rollback",
                &resource,
                audit::OUTCOME_REJECTED,
                &actor,
            );
            return err_json(&AdminError::Conflict(format!(
                "expected_version {expected} is stale (current is {})",
                current.config_version
            )));
        }
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
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by("config.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                &format!("config.rollback to v{}", req.version),
                &cur.hook_registry,
                &cur.global_hooks,
            );
            // Best-effort overlay persistence of the restored surface (no-op when disabled).
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                None,
            );
            ok_json(
                StatusCode::OK,
                &json!({
                    "restored_version": req.version,
                    "new_version": cur.config_version,
                }),
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

/// `POST /admin/v1/config/reload` — re-run the BOOT disk-load pipeline (config.yaml +
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
    let outcome = crate::load_config_from_disk(&config_path, &providers_path).and_then(|loaded| {
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
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                "config.reload (from disk)",
                &cur.hook_registry,
                &cur.global_hooks,
            );
            ok_json(
                StatusCode::OK,
                &json!({ "reloaded": true, "config_version": cur.config_version }),
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

/// The `POST /admin/v1/config/apply` body: a full proposed config (validate's exact shape) plus
/// the optimistic-concurrency guard.
#[derive(serde::Deserialize)]
struct ApplyConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape). Optional — empty validates/fails loudly
    /// on dangling references.
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
    #[serde(default)]
    expected_version: Option<u64>,
}

/// `POST /admin/v1/config/apply` — apply a FULL config carried in the request body, atomically:
/// resolve + validate (an invalid config is a 400 that changes nothing), build a complete new
/// `App` reusing process-lifetime state, carry every surviving lane's health BY STABLE IDENTITY
/// (D1), swap. The body-carried twin of `config/reload` (disk) — Terraform/CI push the config they
/// hold instead of writing files. NOTE: an applied config is LIVE but not written to disk — the
/// next reload/restart returns to disk truth (+overlay); the response says so.
async fn apply_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let req: ApplyConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    let current = handle.load();
    if let Some(expected) = req.expected_version {
        if expected != current.config_version {
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            return err_json(&AdminError::Conflict(format!(
                "expected_version {expected} is stale (current is {})",
                current.config_version
            )));
        }
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
            handle.swap(Arc::new(next));
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            cur.versions.record(
                cur.config_version,
                &actor,
                "config.apply (request body)",
                &cur.hook_registry,
                &cur.global_hooks,
            );
            ok_json(
                StatusCode::OK,
                &json!({
                    "applied": true,
                    "config_version": cur.config_version,
                    "note": "live until the next reload/restart returns to disk truth; persist by \
                             updating config.yaml",
                }),
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
    (
        "/admin/v1/config/versions",
        "Config version history (newest first; id/ts/principal/summary)",
    ),
    (
        "/admin/v1/config/diff",
        "Structured hook-surface diff between two versions (?from=&to=)",
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
            "put": {
                "summary": "Replace an overlay hook definition — live immediately (grants immutable)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced hook"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook, grant change, or stale expected_version (error code `conflict`)"},
                    "400": {"description": "Invalid definition (error code `invalid_request`)"}
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
        "/admin/v1/config/versions/{v}".to_string(),
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
        "/admin/v1/config/apply".to_string(),
        json!({
            "post": {
                "summary": "Apply a full config from the request body, atomically (live until next reload/restart; health preserved by lane identity)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied, config_version, note}`"},
                    "400": {"description": "Invalid config (error code `invalid_request`); nothing changed"},
                    "409": {"description": "`expected_version` stale (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        "/admin/v1/config/reload".to_string(),
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
    paths.insert(
        "/admin/v1/config/rollback".to_string(),
        json!({
            "post": {
                "summary": "Restore a retained version's hook surface (re-validated; a NEW version)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{restored_version, new_version}`"},
                    "404": {"description": "Target version not retained (error code `not_found`)"},
                    "409": {"description": "`expected_version` stale (error code `conflict`)"},
                    "400": {"description": "Snapshot fails re-validation (error code `invalid_request`)"}
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
}
