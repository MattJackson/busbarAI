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

/// The budget periods `governance::budget_window` actually enforces. An unrecognized value (a typo
/// like `"weekly"` / `"monthlly"`) is NOT a window `budget_window` knows: it silently degrades to the
/// all-time `"total"` window with a `tracing::warn!`, so a key created with a typo'd period returns
/// 201 yet enforces an all-time cap — its stored metadata says one thing while governance does
/// another. Validate at the ingress (key creation) so an operator gets a 400 with the allowed set
/// instead of a silently-misenforcing key. Kept in lock-step with the arms of
/// `governance::budget_window`.
const VALID_BUDGET_PERIODS: &[&str] = &["total", "daily", "monthly"];

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// 500 for an internal store/DB failure. The detailed error (which may embed raw SQL fragments,
/// column/table names, or file paths from rusqlite) is logged server-side via `tracing::error!`;
/// the HTTP body carries only a generic message so internal storage details are never disclosed to
/// the client (even an authenticated admin). `op` names the operation for log correlation.
fn internal_error(op: &str, e: &crate::governance::StoreError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store operation failed");
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "internal error"}),
    )
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

/// 500 for a `spawn_blocking` task that failed to run to completion (cancelled or panicked). The
/// blocking store closures here don't panic in normal operation, but a `JoinError` must NOT
/// propagate as an `unwrap()` on the request path — map it to a generic 500 (details logged).
fn join_error(op: &str, e: &tokio::task::JoinError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store task failed to join");
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "internal error"}),
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
    // Default to the all-time `"total"` window when omitted; otherwise the value MUST be one
    // `governance::budget_window` enforces. Reject an unrecognized period with 400 rather than
    // letting it persist and silently degrade to `"total"` at evaluation time (a key whose stored
    // metadata disagrees with the cap it actually enforces).
    let budget_period = req.budget_period.unwrap_or_else(|| "total".to_string());
    if !VALID_BUDGET_PERIODS.contains(&budget_period.as_str()) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": format!(
                    "invalid budget_period '{budget_period}': must be one of {VALID_BUDGET_PERIODS:?}"
                )
            }),
        );
    }
    let spec = NewKeySpec {
        name: req.name,
        allowed_pools: req.allowed_pools,
        max_budget_cents: req.max_budget_cents,
        budget_period,
        rpm_limit: req.rpm_limit,
        tpm_limit: req.tpm_limit,
    };
    // Offload the blocking rusqlite write off the Tokio worker thread (matches the request-path
    // discipline in governance::is_over_budget_async / offload_store_write).
    let gov = gov.clone();
    let now = crate::store::now();
    let res = tokio::task::spawn_blocking(move || gov.create_key(spec, now)).await;
    match res {
        Ok(Ok((key, secret))) => {
            let mut body = key_meta(&key);
            body["secret"] = json!(secret); // shown exactly once
            json_response(StatusCode::CREATED, body)
        }
        Ok(Err(e)) => internal_error("create_key", &e),
        Err(e) => join_error("create_key", &e),
    }
}

/// GET /admin/keys — list key metadata (no secrets/hashes).
pub(crate) async fn list_keys(State(app): State<Arc<App>>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    let gov = gov.clone();
    let res = tokio::task::spawn_blocking(move || gov.all_keys()).await;
    match res {
        Ok(Ok(keys)) => json_response(
            StatusCode::OK,
            json!({ "keys": keys.iter().map(key_meta).collect::<Vec<_>>() }),
        ),
        Ok(Err(e)) => internal_error("list_keys", &e),
        Err(e) => join_error("list_keys", &e),
    }
}

/// GET /admin/keys/:id/usage — current-window usage counters.
pub(crate) async fn key_usage(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    let now = crate::store::now();
    let gov2 = gov.clone();
    let id2 = id.clone();
    let res = tokio::task::spawn_blocking(move || gov2.usage_for(&id2, now)).await;
    match res {
        Ok(Ok(Some(u))) => json_response(
            StatusCode::OK,
            json!({"id": id, "spend_cents": u.spend_cents, "tokens": u.tokens, "requests": u.requests}),
        ),
        Ok(Ok(None)) => json_response(StatusCode::NOT_FOUND, json!({"error": "key not found"})),
        Ok(Err(e)) => internal_error("key_usage", &e),
        Err(e) => join_error("key_usage", &e),
    }
}

/// DELETE /admin/keys/:id — revoke a key. Returns 404 when no key with `id` exists (REST/OpenAPI
/// contract), so a typo'd or already-deleted id is distinguishable from an actual revocation rather
/// than masquerading as a spurious 200.
pub(crate) async fn delete_key(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    // Existence check before delete: `usage_for` resolves the key by id and returns Ok(None) when it
    // does not exist (the store's `delete_key` silently no-ops a zero-row delete, so we cannot rely
    // on it to signal not-found). Use the public GovState API rather than reaching into the store.
    //
    // Both store calls (the lookup and the delete) run on ONE `spawn_blocking` task so neither
    // blocks a Tokio worker thread, matching the request-path discipline. Running them on the same
    // task also keeps the lookup→delete pair tighter than two separately-scheduled awaits would.
    // NOTE: this does not make the check-then-act atomic — `GovState`/store expose no rows-affected
    // signal, so two concurrent DELETEs of the same id can still both observe `Some` and both return
    // 200 (the underlying `delete_key` no-ops the second SQL delete). Eliminating that residual
    // TOCTOU requires the store's `delete_key` to report `changes()` and map zero rows to 404, which
    // lives in the store layer (not this fix unit's owned files). See the obs unit's skipped note.
    let now = crate::store::now();
    let gov = gov.clone();
    let id_for_task = id.clone();
    let res = tokio::task::spawn_blocking(move || match gov.usage_for(&id_for_task, now) {
        Ok(None) => Ok(None),
        Ok(Some(_)) => gov.delete_key(&id_for_task).map(Some),
        Err(e) => Err(e),
    })
    .await;
    match res {
        Ok(Ok(Some(()))) => json_response(StatusCode::OK, json!({"deleted": id})),
        Ok(Ok(None)) => json_response(StatusCode::NOT_FOUND, json!({"error": "key not found"})),
        Ok(Err(e)) => internal_error("delete_key", &e),
        Err(e) => join_error("delete_key", &e),
    }
}

#[cfg(test)]
mod tests {
    use crate::governance::{GovState, NewKeySpec, SqliteStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    /// Build a router whose App has governance enabled with a known admin token, returning the
    /// listen address + the live server handle.
    async fn serve_with_gov(
        gov: Arc<GovState>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, handle)
    }

    #[tokio::test]
    async fn test_create_list_usage_roundtrip_through_spawn_blocking() {
        // Exercises the create_key / list_keys / key_usage handlers end-to-end after they were moved
        // onto spawn_blocking: a slow rusqlite call must not block a Tokio worker, and the offloaded
        // handlers must still return the same responses (no secret/hash leak; usage resolves).
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();

        // create
        let created = client
            .post(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k1"}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);
        let body: serde_json::Value = created.json().await.unwrap();
        let id = body["id"].as_str().unwrap().to_string();
        assert!(body["secret"].is_string(), "secret returned once on create");
        assert!(body["key_hash"].is_null(), "key_hash must never be exposed");

        // list
        let listed = client
            .get(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status().as_u16(), 200);
        let lb: serde_json::Value = listed.json().await.unwrap();
        assert_eq!(lb["keys"].as_array().unwrap().len(), 1);
        assert!(
            lb["keys"][0]["secret"].is_null(),
            "list must not leak secrets"
        );

        // usage
        let usage = client
            .get(format!("http://{addr}/admin/keys/{id}/usage"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(usage.status().as_u16(), 200);
        let ub: serde_json::Value = usage.json().await.unwrap();
        assert_eq!(ub["id"], id);
        handle.abort();
    }

    #[tokio::test]
    async fn test_create_key_rejects_unknown_budget_period() {
        // Regression (MEDIUM/correctness): an unrecognized budget_period (a typo) must be rejected
        // with 400, NOT accepted at 201 and silently enforced as the all-time `"total"` window. A
        // valid period (and the default when omitted) must still create the key.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

        // Typo'd period → 400, no key minted.
        for bad in ["weekly", "monthlly", "", "TOTAL"] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", "budget_period": bad}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "budget_period '{bad}' must be rejected with 400"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("budget_period"),
                "400 body must name budget_period: {body}"
            );
        }

        // Each valid period (and the omitted-default) creates the key with that exact period.
        for good in ["total", "daily", "monthly"] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", "budget_period": good}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                201,
                "valid budget_period '{good}' must create the key"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body["budget_period"], good,
                "stored period must match request"
            );
        }

        // Omitted budget_period defaults to "total".
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "omitted period must default");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["budget_period"], "total",
            "omitted period defaults to total"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_delete_existing_key_returns_200() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();

        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let resp = client
            .delete(format!("http://{addr}/admin/keys/{}", key.id))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "existing key deletes with 200");
        handle.abort();
    }

    #[tokio::test]
    async fn test_delete_missing_key_returns_404() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());

        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let resp = client
            .delete(format!("http://{addr}/admin/keys/vk_does_not_exist"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "deleting a non-existent key must 404, not a spurious 200"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "key not found");
        handle.abort();
    }

    #[tokio::test]
    async fn test_delete_key_is_not_idempotent_200() {
        // After a successful delete, a second delete of the same id must 404 (proves the 200 was a
        // real revocation, not a no-op masquerading as success).
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys/{}", key.id);
        let first = client
            .delete(&url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status().as_u16(), 200);
        let second = client
            .delete(&url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(second.status().as_u16(), 404, "second delete must 404");
        handle.abort();
    }
}
