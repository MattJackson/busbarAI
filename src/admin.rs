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
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

/// Deserialize a field as a "double option" so the three JSON intents stay distinguishable:
///   - field ABSENT: the `#[serde(default)]` on the field supplies the OUTER `None`.
///   - field present `null`: this fn is invoked and yields `Some(None)` (an explicit clear).
///   - field present value: this fn is invoked and yields `Some(Some(v))` (an explicit set).
///
/// Serde calls a field's deserializer ONLY when the key is present, so the absent case never reaches
/// here (it is covered by the field default). This is the standard `double_option` pattern; it lets
/// PATCH express "clear this cap back to unlimited" (`null`) distinctly from "leave it unchanged"
/// (omit), which a single `Option<T>` cannot represent.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

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
    // Reject a negative budget at the ingress. `max_budget_cents` is a signed `i64` (the store column
    // is signed and the field is optional/unset = unlimited), so serde does NOT reject a negative the
    // way it auto-rejects the unsigned `rpm_limit`/`tpm_limit: u32` fields below. A negative cap is
    // not "unlimited"; governance evaluates `spend_cents >= max_budget_cents`, so `max_budget_cents:
    // -1` makes a brand-new key (spend 0) read as over budget from its first request — a silent,
    // unrecoverable DoS that still echoes 201 + the bogus value. A typo like `-100` for a $1 cap is
    // the realistic source. Bound it to `>= 0` (0 = a hard "no spend allowed" cap, still a coherent
    // semantic) and 400 otherwise. The `rpm_limit`/`tpm_limit` siblings are unsigned, so a negative
    // for them is already a 400 at deserialization — no parallel range check is reachable here.
    if let Some(budget) = req.max_budget_cents {
        if budget < 0 {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "max_budget_cents must be >= 0"}),
            );
        }
    }
    // Reject a zero rate limit. `rpm_limit`/`tpm_limit` are unsigned, so serde already rejects a
    // negative at deserialization, but `0` parses fine and is NOT "unlimited" — omitting the field
    // (None) is the unlimited semantic. Governance evaluates `requests >= rpm` / `tokens >= tpm` on a
    // window that starts at 0, so `rpm_limit: 0` (0 >= 0) or `tpm_limit: 0` (0 >= 0) makes the key
    // reject every request from creation: a permanently-unusable key minted with a 201 and no
    // diagnostic. A literal `0` is almost always a typo for "no limit" (which is None/omitted). 400
    // both so the operator gets a coherent error instead of a dead key. Any positive value, and an
    // omitted field (unlimited), still create the key.
    if req.rpm_limit == Some(0) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "rpm_limit must be >= 1 (omit the field for unlimited)"}),
        );
    }
    if req.tpm_limit == Some(0) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "tpm_limit must be >= 1 (omit the field for unlimited)"}),
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

/// Partial update to an existing key. Every field is optional; only the present ones change. The
/// secret, name, allowed-pools, and budget period are immutable here (rotate/recreate for those).
///
/// The three cap fields are THREE-STATE via serde double-option (`Option<Option<T>>`):
///   - absent (`#[serde(default)]` -> outer `None`): leave the stored cap unchanged.
///   - JSON `null` (`Some(None)`): CLEAR the cap back to unlimited.
///   - a value (`Some(Some(v))`): SET the cap to that value.
///
/// A single `Option<T>` could not tell absent from present-null, so a cap could never be cleared
/// once set. `enabled` is a plain `Option<bool>` (a bool has no "unlimited"/clear state).
#[derive(Deserialize)]
pub(crate) struct UpdateKeyReq {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    rpm_limit: Option<Option<u32>>,
    #[serde(default, deserialize_with = "double_option")]
    tpm_limit: Option<Option<u32>>,
    #[serde(default, deserialize_with = "double_option")]
    max_budget_cents: Option<Option<i64>>,
}

/// PATCH /admin/keys/:id — enable/disable a key or adjust its rate/budget caps. The `enabled` field
/// is the primary use (disabling a key WITHOUT destroying its usage history, which `DELETE` would).
/// Admin-gated by the auth middleware (every `/admin/*` path requires the admin token). Validation
/// is kept at create-parity: a negative budget or a zero rate cap is a 400, exactly as `create_key`
/// rejects them — otherwise PATCH would be a back door around those guards. 404 if the key is absent.
pub(crate) async fn update_key(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateKeyReq>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    // Create-parity validation (see create_key for the rationale on each): a negative budget is a
    // silent over-budget DoS; a zero rate cap is a permanently-unusable key. Reject both here so PATCH
    // cannot install a value create() forbids.
    //
    // THREE-STATE: validation applies ONLY to a present *value* (`Some(Some(v))` = set). A present
    // `null` (`Some(Some(_))` vs `Some(None)`) means "clear to unlimited" and is always allowed — it
    // can never produce a dead/over-budget key, so it must NOT be rejected by the create-parity
    // guards. Absent (`None`) leaves the field unchanged and likewise needs no check.
    if let Some(Some(budget)) = req.max_budget_cents {
        if budget < 0 {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "max_budget_cents must be >= 0 (use null to clear to unlimited)"}),
            );
        }
    }
    if req.rpm_limit == Some(Some(0)) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "rpm_limit must be >= 1 (omit to leave unchanged, null to clear to unlimited)"}),
        );
    }
    if req.tpm_limit == Some(Some(0)) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "tpm_limit must be >= 1 (omit to leave unchanged, null to clear to unlimited)"}),
        );
    }
    let gov = gov.clone();
    let (enabled, rpm, tpm, budget) = (
        req.enabled,
        req.rpm_limit,
        req.tpm_limit,
        req.max_budget_cents,
    );
    let res =
        tokio::task::spawn_blocking(move || gov.update_key(&id, enabled, rpm, tpm, budget)).await;
    match res {
        Ok(Ok(Some(key))) => json_response(StatusCode::OK, key_meta(&key)),
        Ok(Ok(None)) => json_response(StatusCode::NOT_FOUND, json!({"error": "key not found"})),
        Ok(Err(e)) => internal_error("update_key", &e),
        Err(e) => join_error("update_key", &e),
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
    //
    // TOCTOU: `GovState`/store expose no rows-affected signal, so a *bare* check-then-act would let
    // two concurrent DELETEs of the same id both observe `Some` and both return 200 (the second SQL
    // delete no-ops) — a misleading audit trail implying two revocations of one row. The store-layer
    // `changes()` fix is out of this unit's owned files, so we close the race here instead: serialize
    // every delete's lookup→delete critical section behind a process-wide async mutex. `delete_key`
    // is the only operation that flips a key from existing to absent, so serializing deletes against
    // each other is sufficient — the loser of a race now observes `Ok(None)` and correctly returns
    // 404. Deletes are admin-only and rare, so a single global lock has no meaningful cost.
    static DELETE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _delete_guard = DELETE_GATE.lock().await;
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
    async fn test_create_key_rejects_negative_max_budget_cents() {
        // Regression (HIGH/correctness): a negative `max_budget_cents` is a signed-i64 value serde
        // does NOT auto-reject (unlike the unsigned rpm/tpm limits). A negative cap makes governance
        // read a brand-new key (spend 0) as over budget from request one — a silent DoS. It must be
        // rejected with 400 and no key minted; `0` (a hard no-spend cap) and a positive value, and an
        // omitted field (unlimited), must all still create the key.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

        for bad in [-1_i64, -100, i64::MIN] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", "max_budget_cents": bad}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "negative max_budget_cents {bad} must be rejected with 400"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("max_budget_cents"),
                "400 body must name max_budget_cents: {body}"
            );
        }

        // Zero (hard no-spend cap) and a positive value both create the key with that exact cap.
        for good in [0_i64, 1, 100_000] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", "max_budget_cents": good}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                201,
                "non-negative max_budget_cents {good} must create the key"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body["max_budget_cents"], good,
                "stored cap must match request"
            );
        }

        // Omitted field → unlimited (null), still 201.
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            201,
            "omitted budget must create key"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["max_budget_cents"].is_null(),
            "omitted budget is unlimited (null)"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_patch_key_enables_disables_and_validates_at_create_parity() {
        // #28: PATCH /admin/keys/:id can disable a key (without DELETE destroying its history) and
        // adjust caps; it is admin-gated and rejects the same invalid values create() does.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let base = format!("http://{addr}/admin/keys");

        // Create a key to operate on.
        let created: serde_json::Value = client
            .post(&base)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        let key_url = format!("{base}/{id}");

        // Admin gate: PATCH without the admin token is rejected by the middleware (not 200).
        let no_tok = client
            .patch(&key_url)
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap();
        assert_ne!(no_tok.status().as_u16(), 200, "PATCH must be admin-gated");

        // Disable the key → 200, enabled=false.
        let disabled = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap();
        assert_eq!(disabled.status().as_u16(), 200);
        let body: serde_json::Value = disabled.json().await.unwrap();
        assert_eq!(body["enabled"], false, "key is disabled: {body}");

        // Create-parity validation: negative budget and zero rate caps are 400 via PATCH too.
        for bad in [
            serde_json::json!({"max_budget_cents": -1}),
            serde_json::json!({"rpm_limit": 0}),
            serde_json::json!({"tpm_limit": 0}),
        ] {
            let r = client
                .patch(&key_url)
                .header("x-admin-token", "admintok")
                .json(&bad)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 400, "PATCH must reject {bad} with 400");
        }

        // PATCH a non-existent key → 404.
        let missing = client
            .patch(format!("{base}/vk_nope"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);

        handle.abort();
    }

    #[tokio::test]
    async fn test_create_key_rejects_zero_rate_limits() {
        // Regression (LOW/bug): `rpm_limit`/`tpm_limit` are unsigned, so serde rejects a negative but
        // accepts `0`. A zero limit is NOT "unlimited" (that is the omitted/None case): governance
        // checks `requests >= rpm` / `tokens >= tpm` against a window starting at 0, so `0` makes the
        // key reject every request from creation — a permanently-dead key minted with 201 and no
        // diagnostic. Both fields must 400; a positive value, and omission (unlimited), must create it.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

        for field in ["rpm_limit", "tpm_limit"] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", field: 0}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "{field}: 0 must be rejected with 400"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert!(
                body["error"].as_str().unwrap_or("").contains(field),
                "400 body must name {field}: {body}"
            );
        }

        // A positive limit on either field still creates the key.
        for field in ["rpm_limit", "tpm_limit"] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", field: 5}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                201,
                "{field}: 5 must create the key"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body[field], 5, "stored {field} must match request");
        }

        // Omitted limits → unlimited (null), still 201.
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            201,
            "omitted limits must create key"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["rpm_limit"].is_null() && body["tpm_limit"].is_null(),
            "omitted limits are unlimited (null): {body}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_patch_key_clears_caps_to_unlimited_via_null() {
        // LOW #16/#19 (three-state): PATCH must distinguish absent (leave unchanged), JSON null
        // (clear to unlimited), and a value (set). A single Option<T> conflated absent with null, so a
        // cap could never be cleared once set. Verify the full matrix end-to-end through the handler.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let base = format!("http://{addr}/admin/keys");

        // Create a key that HAS all three caps set.
        let created: serde_json::Value = client
            .post(&base)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({
                "name": "k",
                "rpm_limit": 10,
                "tpm_limit": 2000,
                "max_budget_cents": 5000
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["rpm_limit"], 10);
        assert_eq!(created["tpm_limit"], 2000);
        assert_eq!(created["max_budget_cents"], 5000);
        let key_url = format!("{base}/{id}");

        // Present null CLEARS each cap to unlimited (null in the response).
        let cleared: serde_json::Value = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({
                "rpm_limit": null,
                "tpm_limit": null,
                "max_budget_cents": null
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            cleared["rpm_limit"].is_null(),
            "rpm cleared to unlimited: {cleared}"
        );
        assert!(cleared["tpm_limit"].is_null(), "tpm cleared to unlimited");
        assert!(
            cleared["max_budget_cents"].is_null(),
            "budget cleared to unlimited"
        );

        // Re-set them with values.
        let reset: serde_json::Value = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({
                "rpm_limit": 7,
                "tpm_limit": 99,
                "max_budget_cents": 123
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reset["rpm_limit"], 7);
        assert_eq!(reset["tpm_limit"], 99);
        assert_eq!(reset["max_budget_cents"], 123);

        // Absent fields LEAVE the caps unchanged (only `enabled` present here).
        let unchanged: serde_json::Value = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(unchanged["enabled"], false);
        assert_eq!(unchanged["rpm_limit"], 7, "absent leaves rpm unchanged");
        assert_eq!(unchanged["tpm_limit"], 99, "absent leaves tpm unchanged");
        assert_eq!(
            unchanged["max_budget_cents"], 123,
            "absent leaves budget unchanged"
        );

        // Clearing to unlimited (null) must NOT trip the create-parity guards (those reject a present
        // 0/negative VALUE, not a clear). null on rpm/tpm/budget all return 200.
        let cleared2 = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"rpm_limit": null, "max_budget_cents": null}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            cleared2.status().as_u16(),
            200,
            "null (clear) must not be rejected by the create-parity guards"
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

    #[tokio::test]
    async fn test_concurrent_delete_returns_exactly_one_200() {
        // Regression (MEDIUM/correctness, TOCTOU): two concurrent DELETEs of the SAME id must not
        // both observe the key and both return 200 (which would imply two revocations of one row in
        // an audit trail). The delete handler serializes its lookup→delete critical section, so the
        // winner returns 200 and every loser returns 404. Fire a burst and assert exactly one 200.
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
        let url = format!("http://{addr}/admin/keys/{}", key.id);

        // Launch several DELETEs concurrently against the single freshly-created key.
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let url = url.clone();
            tasks.push(tokio::spawn(async move {
                let client = reqwest::Client::new();
                client
                    .delete(&url)
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            }));
        }
        let mut ok = 0;
        let mut not_found = 0;
        for t in tasks {
            match t.await.unwrap() {
                200 => ok += 1,
                404 => not_found += 1,
                other => panic!("unexpected status {other} from concurrent delete"),
            }
        }
        assert_eq!(
            ok, 1,
            "exactly one concurrent delete must report a 200 revocation"
        );
        assert_eq!(
            not_found, 7,
            "every losing concurrent delete must report 404"
        );
        handle.abort();
    }
}
