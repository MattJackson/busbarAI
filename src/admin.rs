// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Virtual-key management API. Admin CRUD over `/admin/keys`, guarded by the
//! configured admin token (enforced in `auth_middleware`, not here). Mutations refresh the
//! `GovState` cache. Responses never include a key's `key_hash`; the plaintext secret is returned
//! exactly once, on creation.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
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

/// Process-wide gate serializing the existence-sensitive critical sections of the key store.
///
/// `delete_key` is the only operation that flips a key from existing to absent, but its check-then-act
/// (`usage_for` lookup → `delete_key`) and `update_key`'s check-then-act (the store's `get_key` →
/// `put_key` UPSERT) BOTH read existence and then write, with no rows-affected signal from the store
/// to make either atomic. Two hazards follow, and BOTH are closed by serializing every such section
/// behind this one async mutex:
///   - Two concurrent DELETEs of one id would otherwise both observe `Some` and both return 200 (the
///     second SQL delete no-ops) — a misleading audit trail of two revocations of one row.
///   - A PATCH interleaved with a DELETE would otherwise RESURRECT the revoked key: the PATCH reads
///     the row (exists), the DELETE removes it, then the PATCH's `put_key` UPSERT re-inserts it. Under
///     this gate the PATCH's lookup→put runs to completion before any DELETE (so the row is gone
///     afterward), or after it (so the PATCH's `get_key` returns `None` → 404 and never re-puts).
///
/// The proper store-layer fix is an UPDATE-ONLY `put`/`update` (`UPDATE … WHERE id=?` that affects 0
/// rows when absent, never an upsert) used by `update_key`, which would need no lock at all — but that
/// method lives in `governance.rs`, outside this unit's owned files. This gate is the admin-side guard
/// that closes the resurrection race with the surface we own. Both ops are admin-only and rare, so a
/// single global lock has no meaningful cost.
///
/// CANCELLATION SAFETY: this is a `std::sync::Mutex`, NOT a `tokio::sync::Mutex`, and the guard
/// is acquired INSIDE each operation's `spawn_blocking` closure — bound to the SYNCHRONOUS store
/// mutation, not to the async handler future. An earlier design held an async guard across the
/// cancellable outer `.await`; if the client dropped the request, the guard was dropped while the
/// already-scheduled (and thus uncancellable) `spawn_blocking` closure kept running its lookup→write,
/// re-opening the very resurrection / double-revoke races this gate closes. Acquiring the lock inside
/// the blocking closure means the gate is held for the entire lookup→write regardless of any
/// outer-future drop: `spawn_blocking`, once scheduled, runs to completion. A `std::sync::Mutex` is
/// used precisely because the lock is taken on a blocking thread with no async runtime in scope.
/// A poisoned lock (a panic in another holder while the gate was held) is recovered with
/// `into_inner()` — the guarded data is `()`, so there is no inconsistent state to fear, and refusing
/// to serialize would be worse than proceeding.
static EXISTENCE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Deserialize)]
struct CreateKeyReq {
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
    /// When true, ALSO issue an AWS-style access-key-id + secret access key (the MinIO/S3-compatible
    /// model) so a Bedrock-SDK client can authenticate to this key via inbound SigV4. Both the
    /// `aws_access_key_id` and the `aws_secret_access_key` are returned ONCE here at creation; the
    /// SECRET is never exposed again by any read API (mirroring the bearer `secret`). Defaults to false.
    #[serde(default)]
    issue_aws_credential: bool,
}

/// The budget periods `governance::budget_window` actually enforces. An unrecognized value (a typo
/// like `"weekly"` / `"monthlly"`) is NOT a window `budget_window` knows: it silently degrades to the
/// all-time `"total"` window with a `tracing::warn!`, so a key created with a typo'd period returns
/// 201 yet enforces an all-time cap — its stored metadata says one thing while governance does
/// another. Validate at the ingress (key creation) so an operator gets a 400 with the allowed set
/// instead of a silently-misenforcing key. Kept in lock-step with the arms of
/// `governance::budget_window`.
const VALID_BUDGET_PERIODS: &[&str] = &["total", "daily", "monthly"];

/// Error-type taxonomy strings used by the admin API and by `main.rs` (which references them via
/// `crate::admin::ERR_TYPE_*`). `forward.rs` defines parallel `KIND_NOT_FOUND`/`KIND_INVALID_REQUEST`
/// consts with the same string values independently, rather than importing from here.
pub(crate) const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
pub(crate) const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
const ERR_TYPE_INTERNAL: &str = "internal_error";

/// Maximum byte lengths for admin-API path / body fields (defense-in-depth DB/log-bloat guards).
/// A real minted key id is `vk_` + 16 hex chars (19 chars); 64 is generous headroom.
/// 256 chars for a key name is far past any reasonable label.
const MAX_KEY_NAME_LEN: usize = 256;
const MAX_KEY_ID_LEN: usize = 64;

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::forward::APPLICATION_JSON)],
        body.to_string(),
    )
        .into_response()
}

/// Admin error envelope — the SAME vendor object shape the proxy emits
/// (`{"error":{"message":...,"type":...}}`, see `forward::ingress_error`), so a client parses admin
/// and proxy errors with one code path instead of a flat `{"error":"<string>"}` special case. The
/// `type` taxonomy mirrors `forward::cross_protocol_error_kind`: `invalid_request_error` for 4xx
/// client errors, `not_found_error` for 404, `internal_error` for 5xx. `message` carries only
/// caller-safe text — store/DB details are logged server-side (see `internal_error`/`join_error`)
/// and never reach this body.
fn error_response(status: StatusCode, error_type: &str, message: impl Into<String>) -> Response {
    json_response(
        status,
        json!({"error": {"message": message.into(), "type": error_type}}),
    )
}

/// 500 for an internal store/DB failure. The detailed error (which may embed raw SQL fragments,
/// column/table names, or file paths from rusqlite) is logged server-side via `tracing::error!`;
/// the HTTP body carries only a generic message so internal storage details are never disclosed to
/// the client (even an authenticated admin). `op` names the operation for log correlation.
fn internal_error(op: &str, e: &crate::governance::StoreError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store operation failed");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        ERR_TYPE_INTERNAL,
        "internal error",
    )
}

// ── Admin API (the FROZEN surface — /admin/v1/*) ─────────────────────────────────────────────────
//
// Built engine + swappable layers (Matthew 7/11), VERSION-FIRST: each API version (`v1`, later `v2`)
// is a self-contained unit under its own directory holding that version's CONTRACT (typed views +
// stable error codes), its SERVICE (typed operations over the shared engine), and its TRANSPORT wire
// adapters (`json`, later `graphql`). The transport PORT (`AdminTransport` in `transport`) is shared
// across versions and transports. Releasing v2 is a LAYER copy of `v1/`, not a rewrite; v1 never
// breaks. The legacy `/admin/keys` handlers below stay as a deprecated alias with their `{type}`
// envelope while keys migrate into the versioned service.
pub(crate) mod transport;
pub(crate) mod v1;

pub(crate) use v1::json::JsonV1;
pub(crate) use v1::service::mark_start;

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
    error_response(
        StatusCode::NOT_FOUND,
        ERR_TYPE_NOT_FOUND,
        "governance/admin API is not enabled",
    )
}

/// Bound a path `id` (the virtual-key id from `/admin/keys/{id}`). Admin-gated, but an unbounded id
/// flows into a store lookup / log lines — cap it as defense-in-depth (DB/log-bloat guard). A real
/// minted id is `vk_` + 16 hex chars (19 chars), so [`MAX_KEY_ID_LEN`] is generous headroom. Returns
/// a 400 response when too long, `None` when acceptable.
fn reject_overlong_id(id: &str) -> Option<Response> {
    if id.len() > MAX_KEY_ID_LEN {
        Some(error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "id must be <= 64 characters",
        ))
    } else {
        None
    }
}

/// 500 for a `spawn_blocking` task that failed to run to completion (cancelled or panicked). The
/// blocking store closures here don't panic in normal operation, but a `JoinError` must NOT
/// propagate as an `unwrap()` on the request path — map it to a generic 500 (details logged).
fn join_error(op: &str, e: &tokio::task::JoinError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store task failed to join");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        ERR_TYPE_INTERNAL,
        "internal error",
    )
}

/// POST /admin/keys — mint a virtual key. Returns the plaintext secret ONCE.
pub(crate) async fn create_key(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    // Parse the body via the depth-guarded `crate::json` seam, NOT axum's stock `Json<T>` extractor,
    // whose `JsonRejection` body echoes the raw serde `Display` — a fragment of the offending input.
    // This body carries SECRETS (an AWS secret_access_key, the bearer being minted), so any parse
    // failure maps to a GENERIC 400, logging only the byte length via `parse_err_log` (never the raw
    // error, never an input fragment).
    let req: CreateKeyReq = match crate::json::parse(&body) {
        Ok(req) => req,
        Err(_) => {
            tracing::warn!("create_key: {}", crate::json::parse_err_log(body.len()));
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_TYPE_INVALID_REQUEST,
                "invalid JSON",
            );
        }
    };
    // Bound the key name. It is admin-gated, but an unbounded `name` persists verbatim into the
    // store (DB-bloat / log-line-bloat vector) — cap it as defense-in-depth. MAX_KEY_NAME_LEN chars
    // is far past any reasonable label.
    if req.name.len() > MAX_KEY_NAME_LEN {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "name must be <= 256 characters",
        );
    }
    // Default to the all-time `"total"` window when omitted; otherwise the value MUST be one
    // `governance::budget_window` enforces. Reject an unrecognized period with 400 rather than
    // letting it persist and silently degrade to `"total"` at evaluation time (a key whose stored
    // metadata disagrees with the cap it actually enforces).
    let budget_period = req
        .budget_period
        .unwrap_or_else(|| VALID_BUDGET_PERIODS[0].to_string());
    if !VALID_BUDGET_PERIODS.contains(&budget_period.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            // Do NOT echo the caller-supplied value back in the error body (matches every other 400).
            format!("invalid budget_period: must be one of {VALID_BUDGET_PERIODS:?}"),
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
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_TYPE_INVALID_REQUEST,
                "max_budget_cents must be >= 0",
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
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "rpm_limit must be >= 1 (omit the field for unlimited)",
        );
    }
    if req.tpm_limit == Some(0) {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "tpm_limit must be >= 1 (omit the field for unlimited)",
        );
    }
    // NON-FATAL ingress diagnostic for `allowed_pools`. Unlike the rejections above, an
    // allowed-pools entry that names no currently-configured pool is NOT a 400: minting a key whose
    // pool will be configured later is a legitimate, supported workflow (key first, pool wired
    // afterward), so the store accepts any string. But an entry that matches no configured pool is
    // far more often a typo (`"smrt"` for `"smart"`) than a deliberate forward reference, and a
    // typo'd allow-entry silently scopes the key to a pool it can never reach. Surface it at the
    // ingress with a `tracing::warn!` (matching the module's validate-at-ingress convention) so the
    // typo is visible in logs, while still creating the key — the forward-reference case stays
    // unbroken. `app.pools` is the authoritative set of configured pool names (see `state::App`).
    for pool in &req.allowed_pools {
        if !app.pools.contains_key(pool) {
            tracing::warn!(
                pool = %pool,
                key_name = %req.name,
                "create_key: allowed_pools entry names no configured pool (possible typo; \
                 key still created — configure the pool later to activate this entry)"
            );
        }
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
    // discipline in governance::charge_within_budget_async / offload_store_write).
    let gov = gov.clone();
    let now = crate::store::now();
    let issue_aws = req.issue_aws_credential;
    // When AWS credentials are requested, mint via `create_key_with_aws` (issues the AccessKeyId +
    // secret access key alongside the bearer secret). Otherwise the unchanged bearer-only mint.
    if issue_aws {
        let res = tokio::task::spawn_blocking(move || gov.create_key_with_aws(spec, now)).await;
        match res {
            Ok(Ok((key, secret, access_key_id, secret_access_key))) => {
                let mut body = key_meta(&key);
                body["secret"] = json!(secret); // bearer secret, shown exactly once
                                                // The AccessKeyId is NOT secret (it travels in plaintext in the SigV4 header), but it
                                                // is returned here at creation. The AWS SECRET access key is shown ONCE here only —
                                                // never returned by any read API, mirroring the bearer `secret`.
                body["aws_access_key_id"] = json!(access_key_id);
                body["aws_secret_access_key"] = json!(secret_access_key);
                json_response(StatusCode::CREATED, body)
            }
            Ok(Err(e)) => internal_error("create_key", &e),
            Err(e) => join_error("create_key", &e),
        }
    } else {
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
struct UpdateKeyReq {
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
    body: Bytes,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    // Parse via the depth-guarded `crate::json` seam, not axum's `Json<T>` (whose rejection body
    // echoes the raw serde error / an input fragment). Any failure maps to a GENERIC 400, logging
    // only the byte length via `parse_err_log` — no raw error, no input fragment.
    let req: UpdateKeyReq = match crate::json::parse(&body) {
        Ok(req) => req,
        Err(_) => {
            tracing::warn!("update_key: {}", crate::json::parse_err_log(body.len()));
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_TYPE_INVALID_REQUEST,
                "invalid JSON",
            );
        }
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
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_TYPE_INVALID_REQUEST,
                "max_budget_cents must be >= 0 (use null to clear to unlimited)",
            );
        }
    }
    if req.rpm_limit == Some(Some(0)) {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "rpm_limit must be >= 1 (omit to leave unchanged, null to clear to unlimited)",
        );
    }
    if req.tpm_limit == Some(Some(0)) {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "tpm_limit must be >= 1 (omit to leave unchanged, null to clear to unlimited)",
        );
    }
    let gov = gov.clone();
    let (enabled, rpm, tpm, budget) = (
        req.enabled,
        req.rpm_limit,
        req.tpm_limit,
        req.max_budget_cents,
    );
    // RESURRECTION RACE: `update_key` is a check-then-act (`get_key` → `put_key`, and `put_key`
    // UPSERTs on the PRIMARY KEY, so it INSERTs a missing row rather than no-opping). A PATCH that
    // reads an extant key, then has a concurrent DELETE remove the row before its `put_key` runs,
    // would re-create the just-revoked key. Hold the same existence gate `delete_key` uses across this
    // whole lookup→put section so PATCH and DELETE cannot interleave: the PATCH either completes
    // before the DELETE (row removed afterward) or sees `None` after it (404, no re-put). See
    // `EXISTENCE_GATE`.
    //
    // CANCELLATION SAFETY: the gate is locked INSIDE the `spawn_blocking` closure so its
    // lifetime is bound to the synchronous `gov.update_key` mutation, not to this cancellable async
    // handler. If the client drops the request, the already-scheduled closure still runs to completion
    // holding the gate — so a dropped outer future can never release the gate while the lookup→write
    // is still in flight (which would re-open the resurrection / double-revoke races).
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        gov.update_key(&id, enabled, rpm, tpm, budget)
    })
    .await;
    match res {
        Ok(Ok(Some(key))) => json_response(StatusCode::OK, key_meta(&key)),
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found"),
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
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    let now = crate::store::now();
    let gov2 = gov.clone();
    let id2 = id.clone();
    let res = tokio::task::spawn_blocking(move || gov2.usage_for(&id2, now)).await;
    match res {
        Ok(Ok(Some(u))) => json_response(
            StatusCode::OK,
            json!({"id": id, "spend_cents": u.spend_cents, "tokens": u.tokens, "requests": u.requests}),
        ),
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found"),
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
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
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
    // every delete's lookup→delete critical section behind the process-wide `EXISTENCE_GATE`. The same
    // gate also serializes `update_key`'s lookup→put, so a PATCH cannot resurrect a key this DELETE
    // removes (see `EXISTENCE_GATE`). The loser of a delete race observes `Ok(None)` and correctly
    // returns 404. Deletes are admin-only and rare, so a single global lock has no meaningful cost.
    //
    // CANCELLATION SAFETY: the gate is locked INSIDE the `spawn_blocking` closure, so the whole
    // lookup→delete runs under the lock on the blocking thread. `spawn_blocking` is uncancellable once
    // scheduled, so even if the client drops this request the critical section completes while still
    // holding the gate — the gate can never be released mid-sequence by an outer-future drop.
    let now = crate::store::now();
    let gov = gov.clone();
    let id_for_task = id.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        match gov.usage_for(&id_for_task, now) {
            Ok(None) => Ok(None),
            Ok(Some(_)) => gov.delete_key(&id_for_task).map(Some),
            Err(e) => Err(e),
        }
    })
    .await;
    match res {
        Ok(Ok(Some(()))) => json_response(StatusCode::OK, json!({"deleted": id})),
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found"),
        Ok(Err(e)) => internal_error("delete_key", &e),
        Err(e) => join_error("delete_key", &e),
    }
}

#[cfg(test)]
mod tests {
    use crate::governance::{GovState, NewKeySpec, SqliteStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    /// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
    /// assert a particular `tracing::warn!` fired (mirrors the established pattern in config.rs /
    /// config_validate.rs / eventstream.rs).
    #[derive(Clone, Default)]
    struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            // Capture the rendered message AND every other field (e.g. the structured `pool` /
            // `key_name` on create_key's diagnostic) so a test can assert on a field value, not just
            // the static message text. Fields are flattened into one `key=value` string per event.
            #[derive(Default)]
            struct Vis {
                message: String,
                fields: String,
            }
            impl Vis {
                fn record(&mut self, field: &tracing::field::Field, rendered: String) {
                    if field.name() == "message" {
                        self.message = rendered;
                    } else {
                        if !self.fields.is_empty() {
                            self.fields.push(' ');
                        }
                        self.fields
                            .push_str(&format!("{}={}", field.name(), rendered));
                    }
                }
            }
            impl tracing::field::Visit for Vis {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.record(field, format!("{value:?}"));
                }
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.record(field, value.to_string());
                }
            }
            let mut vis = Vis::default();
            event.record(&mut vis);
            if let Ok(mut msgs) = self.0.lock() {
                msgs.push(format!("{} {}", vis.message, vis.fields));
            }
        }
    }

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

    /// `GET /admin/v1/info` flows end-to-end through the ports-and-adapters stack (JSON-REST
    /// transport → service → contract view): admin-token guarded, returns the version, the
    /// compiled-in plugin proof (with the default build's `tokens`/`ranking` present + the always-on
    /// `weighted_floor`), and the topology counts. Proves the transport is mounted and the frozen
    /// v1 surface answers.
    #[tokio::test]
    async fn test_admin_v1_info_reports_version_features_and_topology() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();

        // Wrong token → 401 (the v1 surface is admin-guarded like the rest of /admin).
        let unauth = client
            .get(format!("http://{addr}/admin/v1/info"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            unauth.status().as_u16(),
            401,
            "v1/info must be admin-guarded"
        );

        let resp = client
            .get(format!("http://{addr}/admin/v1/info"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "info must report the build version"
        );
        // The `weighted_floor` is ALWAYS true (non-removable). `tokens`/`ranking` are present iff their
        // feature is compiled in — so the compliance-by-compilation proof holds under
        // `--no-default-features` too (the lists are empty there).
        assert_eq!(body["build"]["weighted_floor"], serde_json::json!(true));
        let auth_modules = body["build"]["auth_modules"].as_array().unwrap();
        assert_eq!(
            auth_modules.iter().any(|m| m == "tokens"),
            cfg!(feature = "auth-tokens"),
            "auth_modules must contain `tokens` iff the auth-tokens feature is compiled in: {auth_modules:?}"
        );
        let hook_plugins = body["build"]["hook_plugins"].as_array().unwrap();
        assert_eq!(
            hook_plugins.iter().any(|m| m == "ranking"),
            cfg!(feature = "hooks-ranking"),
            "hook_plugins must contain `ranking` iff the hooks-ranking feature is compiled in: {hook_plugins:?}"
        );
        // Topology keys are present and numeric (exact counts depend on the TestApp fixture).
        assert!(body["topology"]["pools"].is_number());
        assert!(body["topology"]["models"].is_number());
        assert!(body["topology"]["providers"].is_number());

        handle.abort();
    }

    /// The topology read surface (`/admin/v1/pools`, `/models`, `/providers`) flows through the
    /// service and projects the pool/model/provider views. Built on a two-lane, two-provider fixture
    /// so the provider aggregation + pool membership are observable.
    #[tokio::test]
    async fn test_admin_v1_topology_reads_pools_models_providers() {
        use crate::test_support::LaneSpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());

        let app = TestApp::new()
            .governance(gov)
            .lane(
                LaneSpec::new(
                    "model-a",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1/",
                )
                .provider("prov-x"),
            )
            .lane(
                LaneSpec::new(
                    "model-b",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1/",
                )
                .provider("prov-y"),
            )
            .pool("mypool", &[(0, 3), (1, 1)])
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let get = |path: String| {
            let url = format!("http://{addr}{path}");
            let client = client.clone();
            async move {
                client
                    .get(url)
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };

        let pools = get("/admin/v1/pools".into()).await;
        let items = pools["items"].as_array().unwrap();
        let mypool = items
            .iter()
            .find(|p| p["name"] == "mypool")
            .expect("mypool present");
        let members = mypool["members"].as_array().unwrap();
        assert_eq!(members.len(), 2, "pool has two members");
        let weight_a = members.iter().find(|m| m["model"] == "model-a").unwrap()["weight"].as_u64();
        assert_eq!(weight_a, Some(3), "model-a weight projected");

        let models = get("/admin/v1/models".into()).await;
        let m_items = models["items"].as_array().unwrap();
        assert!(m_items
            .iter()
            .any(|m| m["model"] == "model-a" && m["provider"] == "prov-x"));
        assert!(m_items
            .iter()
            .any(|m| m["model"] == "model-b" && m["provider"] == "prov-y"));

        let providers = get("/admin/v1/providers".into()).await;
        let p_items = providers["items"].as_array().unwrap();
        let px = p_items.iter().find(|p| p["provider"] == "prov-x").unwrap();
        assert_eq!(px["model_count"].as_u64(), Some(1));
        assert!(p_items.iter().any(|p| p["provider"] == "prov-y"));

        handle.abort();
    }

    /// `GET /admin/v1/pools/{name}` projects each member's LIVE status (usable/cooldown/concurrency/
    /// inflight/tallies) from the store; 404s an unknown pool.
    #[tokio::test]
    async fn test_admin_v1_pool_detail_live_status() {
        use crate::test_support::LaneSpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new()
            .governance(gov)
            .lane(
                LaneSpec::new(
                    "m1",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1/",
                )
                .provider("p"),
            )
            .pool("mypool", &[(0, 5)])
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let ok: serde_json::Value = client
            .get(format!("http://{addr}/admin/v1/pools/mypool"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(ok["name"], "mypool");
        let members = ok["members"].as_array().unwrap();
        assert_eq!(members.len(), 1);
        let m = &members[0];
        assert_eq!(m["model"], "m1");
        assert_eq!(m["weight"], 5);
        // Live-status fields present + typed. A fresh lane is usable with no cooldown.
        assert_eq!(m["usable"], true);
        assert_eq!(m["cooldown_remaining_s"], 0);
        assert!(m["available_concurrency"].is_number());
        assert!(m["inflight"].is_number());
        assert!(m["ok"].is_number());
        assert!(m["dead"].is_boolean());

        // Unknown pool → 404 not_found.
        let missing = client
            .get(format!("http://{addr}/admin/v1/pools/nope"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);
        assert_eq!(
            missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "not_found"
        );

        handle.abort();
    }

    /// The hooks read surface (`GET /admin/v1/hooks`, `GET /admin/v1/hooks/{name}`) projects the
    /// registry definitions (kind/transport/grants/global), 404s an unknown name, and never leaks a
    /// secret. Built on a fixture with one global gate.
    #[tokio::test]
    async fn test_admin_v1_hooks_read_surface() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());

        let gate = crate::config::HookCfg {
            kind: crate::config::HookKind::Gate,
            socket: None,
            webhook: Some("http://127.0.0.1:9990/".to_string()),
            timeout_ms: 25,
            on_error: crate::config::PolicyOnError::Reject,
            prompt: crate::config::PromptAccess::Rw,
            user: crate::config::UserAccess::Ro,
            priority: 7,
            at: None,
            on_empty: None,
            global: false,
        };
        let app = TestApp::new()
            .governance(gov)
            .hook("compress", gate)
            .global_hook("compress")
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // List: the one hook, projected.
        let list = client
            .get(format!("http://{addr}/admin/v1/hooks"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        let items = list["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let h = &items[0];
        assert_eq!(h["name"], "compress");
        assert_eq!(h["kind"], "gate");
        assert_eq!(h["prompt"], "rw");
        assert_eq!(h["user"], "ro");
        assert_eq!(h["priority"], 7);
        assert_eq!(h["on_error"], "reject");
        assert_eq!(h["transport"]["kind"], "webhook");
        assert_eq!(h["transport"]["target"], "http://127.0.0.1:9990/");
        assert_eq!(
            h["global"], true,
            "named in global_hooks → reported as globally wired"
        );

        // Get one by name.
        let one = client
            .get(format!("http://{addr}/admin/v1/hooks/compress"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(one.status().as_u16(), 200);

        // Unknown name → 404 with the stable v1 `not_found` code.
        let missing = client
            .get(format!("http://{addr}/admin/v1/hooks/nope"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);
        let body: serde_json::Value = missing.json().await.unwrap();
        assert_eq!(body["error"]["code"], "not_found");

        handle.abort();
    }

    /// `GET /admin/v1/hooks/{name}/health` best-effort probes a hook's transport: 404 for an unknown
    /// name; a webhook hook reports `reachable: null` (probed on demand); a socket hook pointing at a
    /// nonexistent path reports `reachable: false`. Never fires the hook.
    #[tokio::test]
    async fn test_admin_v1_hook_health_best_effort() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mk = |socket: Option<&str>, webhook: Option<&str>| crate::config::HookCfg {
            kind: crate::config::HookKind::Gate,
            socket: socket.map(str::to_string),
            webhook: webhook.map(str::to_string),
            timeout_ms: 5,
            on_error: crate::config::PolicyOnError::default(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            on_empty: None,
            global: false,
        };
        let app = TestApp::new()
            .governance(gov)
            .hook("web", mk(None, Some("http://127.0.0.1:9980/")))
            .hook("sock", mk(Some("/nonexistent/busbar-hook.sock"), None))
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let get = |name: &str| {
            let url = format!("http://{addr}/admin/v1/hooks/{name}/health");
            let client = client.clone();
            async move {
                client
                    .get(url)
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap()
            }
        };

        // Unknown → 404 not_found.
        let missing = get("nope").await;
        assert_eq!(missing.status().as_u16(), 404);
        assert_eq!(
            missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "not_found"
        );

        // Webhook → reachable null (not probed here).
        let web: serde_json::Value = get("web").await.json().await.unwrap();
        assert_eq!(web["name"], "web");
        assert_eq!(web["transport"]["kind"], "webhook");
        assert!(web["reachable"].is_null(), "webhook is not probed here");

        // Socket to a nonexistent path → reachable false (best-effort connect failed).
        let sock: serde_json::Value = get("sock").await.json().await.unwrap();
        assert_eq!(sock["transport"]["kind"], "socket");
        // On unix the connect fails → Some(false); on non-unix sockets aren't probed → null. Accept both.
        assert!(
            sock["reachable"] == serde_json::json!(false) || sock["reachable"].is_null(),
            "socket to a dead path is unreachable (unix) or unprobed (non-unix): {}",
            sock["reachable"]
        );

        handle.abort();
    }

    /// The plugin catalog (`GET /admin/v1/plugins?type=`) lists compiled-in plugins per type (the
    /// same feature-gated source as `info`) plus external hooks from the registry, and rejects an
    /// unknown/absent type with the stable `invalid_request` code.
    #[tokio::test]
    async fn test_admin_v1_plugins_catalog_by_type() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let gate = crate::config::HookCfg {
            kind: crate::config::HookKind::Gate,
            socket: Some("/run/busbar/h.sock".to_string()),
            webhook: None,
            timeout_ms: 5,
            on_error: crate::config::PolicyOnError::default(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            on_empty: None,
            global: false,
        };
        let app = TestApp::new().governance(gov).hook("myhook", gate).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let get = |q: &str| {
            let url = format!("http://{addr}/admin/v1/plugins?type={q}");
            let client = client.clone();
            async move {
                client
                    .get(url)
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap()
            }
        };

        // auth: the compiled-in tokens module — present iff the auth-tokens feature is compiled in.
        let auth: serde_json::Value = get("auth").await.json().await.unwrap();
        let a_items = auth["items"].as_array().unwrap();
        let tokens = a_items.iter().find(|p| p["name"] == "tokens");
        assert_eq!(
            tokens.is_some(),
            cfg!(feature = "auth-tokens"),
            "tokens listed iff compiled in"
        );
        if let Some(tokens) = tokens {
            assert_eq!(tokens["loader"], "compiled-in");
            assert_eq!(tokens["type"], "auth");
        }

        // hooks: the weighted floor is ALWAYS compiled-in; ranking iff the feature is on; plus the
        // external myhook.
        let hooks: serde_json::Value = get("hooks").await.json().await.unwrap();
        let h_items = hooks["items"].as_array().unwrap();
        assert!(h_items
            .iter()
            .any(|p| p["name"] == "weighted" && p["loader"] == "compiled-in"));
        assert_eq!(
            h_items.iter().any(|p| p["name"] == "ranking"),
            cfg!(feature = "hooks-ranking"),
            "ranking listed iff compiled in"
        );
        let ext = h_items
            .iter()
            .find(|p| p["name"] == "myhook")
            .expect("external hook listed");
        assert_eq!(ext["loader"], "external");
        assert_eq!(ext["active"], true);
        assert_eq!(ext["target"], "/run/busbar/h.sock");

        // Unknown type → 400 invalid_request.
        let bad = get("nope").await;
        assert_eq!(bad.status().as_u16(), 400);
        let body: serde_json::Value = bad.json().await.unwrap();
        assert_eq!(body["error"]["code"], "invalid_request");

        handle.abort();
    }

    /// `GET /admin/v1/auth` reports the ingress chain + upstream-credential mode, never a secret. A
    /// governance-only fixture (no explicit auth chain) is the open front door.
    #[tokio::test]
    async fn test_admin_v1_auth_read() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let body: serde_json::Value = client
            .get(format!("http://{addr}/admin/v1/auth"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(body["chain"].is_array());
        assert_eq!(body["open"], true, "no explicit chain → open front door");
        assert_eq!(body["upstream_credentials"], "own");
        // Sanity: no secret-looking field leaked.
        assert!(body.get("client_tokens").is_none());

        handle.abort();
    }

    /// `POST /admin/v1/config/validate` dry-runs a proposed config: a malformed body is a 400
    /// `invalid_request`; a well-formed body describing an INVALID config (here a provider reference
    /// absent from the defs) returns 200 with `ok:false` and the resolution errors — never mutating.
    #[tokio::test]
    async fn test_admin_v1_config_validate_dry_run() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/v1/config/validate");

        // Malformed body → 400 invalid_request (the REQUEST is broken, not the config).
        let bad = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body("{\"config\": \"not-an-object\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status().as_u16(), 400);
        let body: serde_json::Value = bad.json().await.unwrap();
        assert_eq!(body["error"]["code"], "invalid_request");

        // Well-formed body, invalid config: deploy references provider "openai" but the defs are empty
        // → resolve fails with a dangling-provider error → 200 ok:false.
        let proposed = serde_json::json!({
            "config": {
                "providers": { "openai": { "api_key_env": "OPENAI_KEY" } },
                "models": {}
            },
            "providers": {}
        });
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(proposed.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["ok"], false, "config with a dangling provider is invalid");
        let errors = v["errors"].as_array().unwrap();
        assert!(!errors.is_empty(), "invalid config must report errors");
        assert!(
            errors
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("openai")),
            "the dangling provider is named in an error: {errors:?}"
        );

        handle.abort();
    }

    /// `GET /admin/v1/config` composes the effective-config snapshot (auth + pools/models/providers +
    /// hooks + global_hooks) from the redacted reads. Asserts the shape and that no secret-bearing
    /// field (client tokens, provider keys) appears anywhere in the serialized body.
    #[tokio::test]
    async fn test_admin_v1_config_effective_snapshot_no_secrets() {
        use crate::test_support::LaneSpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let gate = crate::config::HookCfg {
            kind: crate::config::HookKind::Gate,
            socket: None,
            webhook: Some("http://127.0.0.1:9970/".to_string()),
            timeout_ms: 5,
            on_error: crate::config::PolicyOnError::default(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            on_empty: None,
            global: false,
        };
        let app = TestApp::new()
            .governance(gov)
            .lane(
                LaneSpec::new(
                    "m",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1/",
                )
                .provider("prov"),
            )
            .pool("p", &[(0, 1)])
            .hook("g", gate)
            .global_hook("g")
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let resp = client
            .get(format!("http://{addr}/admin/v1/config"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        // Composed sections present.
        assert!(body["auth"]["chain"].is_array());
        assert!(body["pools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "p"));
        assert!(body["models"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["model"] == "m"));
        assert!(body["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["provider"] == "prov"));
        assert!(body["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == "g"));
        assert!(body["global_hooks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "g"));
        // No secret-bearing key names anywhere in the snapshot.
        for needle in ["admintok", "client_tokens", "api_key", "secret"] {
            assert!(
                !text.contains(needle),
                "effective config must not leak `{needle}`: {text}"
            );
        }

        handle.abort();
    }

    /// `GET /admin/v1/openapi.json` returns a valid OpenAPI 3.1 doc, and — the DRIFT GUARD — every GET
    /// path it documents (from V1_GET_PATHS) actually resolves on the live router (never a phantom
    /// endpoint in the discovery contract). Also asserts the stable error `code` enum is present.
    #[tokio::test]
    async fn test_admin_v1_openapi_paths_all_resolve() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let doc: serde_json::Value = client
            .get(format!("http://{addr}/admin/v1/openapi.json"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(doc["info"]["title"], "Busbar Admin API");
        // The stable error code enum is documented.
        let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]
            ["code"]["enum"]
            .as_array()
            .unwrap();
        assert!(codes.iter().any(|c| c == "not_found"));

        // DRIFT GUARD: every documented GET path is both listed in the doc AND actually mounted.
        for (path, _) in crate::admin::v1::json::V1_GET_PATHS {
            assert!(
                doc["paths"][path]["get"].is_object(),
                "documented path {path} missing from openapi doc"
            );
            let status = client
                .get(format!("http://{addr}{path}"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status();
            assert_ne!(
                status.as_u16(),
                404,
                "openapi documents {path} but the router does not mount it (phantom endpoint)"
            );
        }

        handle.abort();
    }

    /// SECURITY CONTRACT: every documented `/admin/v1` GET endpoint rejects a MISSING token and a
    /// WRONG token with 401 — the whole surface is admin-guarded, no read leaks without the credential.
    /// Iterates the same V1_GET_PATHS the openapi doc + drift guard use, so a newly-added endpoint is
    /// automatically covered.
    #[tokio::test]
    async fn test_admin_v1_all_reads_require_admin_token() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        for (path, _) in crate::admin::v1::json::V1_GET_PATHS {
            // No token → 401.
            let none = client
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                none.status().as_u16(),
                401,
                "{path} must reject a request with NO admin token"
            );
            // Wrong token → 401.
            let wrong = client
                .get(format!("http://{addr}{path}"))
                .header("x-admin-token", "not-the-token")
                .send()
                .await
                .unwrap();
            assert_eq!(
                wrong.status().as_u16(),
                401,
                "{path} must reject a request with the WRONG admin token"
            );
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_create_key_with_aws_credential_returns_secret_once_and_hides_on_reads() {
        // Minting with `issue_aws_credential: true` returns the AccessKeyId AND the secret access key
        // ONCE at creation; neither the AWS secret nor the key_hash is ever returned by a later read.
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();

        let created = client
            .post(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "bedrock-key", "issue_aws_credential": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);
        let body: serde_json::Value = created.json().await.unwrap();
        let akid = body["aws_access_key_id"].as_str().unwrap().to_string();
        let aws_secret = body["aws_secret_access_key"].as_str().unwrap().to_string();
        assert!(akid.starts_with("AKIA"), "akid shape: {akid}");
        assert_eq!(aws_secret.len(), 40, "aws secret is 40 chars");
        assert!(
            body["secret"].is_string(),
            "bearer secret returned once too"
        );

        // A plain mint (no flag) carries NO AWS fields.
        let plain: serde_json::Value = client
            .post(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "plain"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            plain["aws_secret_access_key"].is_null() && plain["aws_access_key_id"].is_null(),
            "a bearer-only key must not carry AWS fields: {plain}"
        );

        // The list endpoint must NEVER expose the AWS secret (nor key_hash).
        let listed: serde_json::Value = client
            .get(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let listed_str = listed.to_string();
        assert!(
            !listed_str.contains(&aws_secret),
            "the AWS secret access key must NEVER appear in a read response: {listed_str}"
        );
        for k in listed["keys"].as_array().unwrap() {
            assert!(
                k["aws_secret_access_key"].is_null(),
                "list must not leak the AWS secret"
            );
            assert!(k["key_hash"].is_null(), "list must not leak key_hash");
        }

        handle.abort();
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
                body["error"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("budget_period"),
                "400 body must name budget_period: {body}"
            );
            assert_eq!(
                body["error"]["type"],
                "invalid_request_error", // golden wire-contract literal (kept bare on purpose)
                "400 error type must be invalid_request_error: {body}"
            );
        }

        // Each valid period (and the omitted-default) creates the key with that exact period.
        for &good in super::VALID_BUDGET_PERIODS {
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
            body["budget_period"],
            "total", // golden wire-contract literal (kept bare on purpose)
            "omitted period defaults to total"
        );

        handle.abort();
    }

    /// MED (no-raw-parse-error / secret-leak): a malformed admin create/update body must produce a
    /// GENERIC 400 whose body contains NEITHER serde error prose NOR any fragment of the offending
    /// input. The create-key body carries SECRETS (an AWS secret_access_key, the bearer being minted),
    /// so axum's stock `Json<T>` rejection — which echoes the raw serde `Display` — must NOT be used.
    #[tokio::test]
    async fn test_admin_malformed_body_returns_generic_400_no_input_fragment() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();

        // A SECRET-bearing fragment that must NEVER be echoed back in the error body.
        let secret_fragment = "SUPER_SECRET_AWS_KEY_abc123";
        let malformed = format!(r#"{{"name": "k", "secret_access_key": "{secret_fragment}" "#);

        for path in ["/admin/keys", "/admin/keys/some-id"] {
            let req = if path == "/admin/keys" {
                client.post(format!("http://{addr}{path}"))
            } else {
                client.patch(format!("http://{addr}{path}"))
            };
            let resp = req
                .header("x-admin-token", "admintok")
                .header("content-type", crate::forward::APPLICATION_JSON)
                .body(malformed.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "malformed body on {path} must be 400"
            );
            let text = resp.text().await.unwrap();
            assert!(
                !text.contains(secret_fragment),
                "the 400 body on {path} must NOT echo any input fragment; got {text}"
            );
            // The generic envelope only — no serde prose (e.g. "expected", "column", "EOF").
            assert!(
                !text.contains("expected")
                    && !text.contains("column")
                    && !text.contains("EOF")
                    && !text.contains("line"),
                "the 400 body on {path} must NOT contain serde error text; got {text}"
            );
            let body: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                body["error"]["message"], "invalid JSON",
                "the 400 body on {path} must be the generic envelope; got {text}"
            );
            assert_eq!(
                body["error"]["type"],
                "invalid_request_error", // golden wire-contract literal (kept bare on purpose)
                "the 400 error type must be invalid_request_error; got {text}"
            );
        }

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
                body["error"]["message"]
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
                body["error"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains(field),
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

    #[test]
    fn test_create_key_warns_on_unconfigured_allowed_pool() {
        // Regression (LOW #13, completeness): create_key accepted `allowed_pools` with NO ingress
        // diagnostic, unlike its sibling validations. An entry naming no configured pool must NOT be
        // a 400 (minting a key before its pool exists is a supported forward-reference workflow), but
        // it MUST surface a NON-FATAL `tracing::warn!` so a typo (`"smrt"` for `"smart"`) is visible.
        // Against the old code (no warn) the unknown-pool assertion FAILS; it passes once the
        // diagnostic is emitted. We also assert the key is still created (201) and that a configured
        // pool produces NO warning (no false positive on the legitimate path).
        //
        // The diagnostic fires synchronously in the handler BEFORE the `spawn_blocking().await`, so a
        // thread-local subscriber (`with_default`) on a current-thread runtime captures it — we call
        // the handler directly rather than through the HTTP server (whose task would run on a
        // different thread, out of the subscriber's reach).
        use tracing_subscriber::layer::SubscriberExt as _;

        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        // App has exactly one configured pool, "smart" (lane 0). "smrt" is the typo'd sibling.
        let app = TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:0",
            ))
            .pool("smart", &[(0, 1)])
            .governance(gov)
            .build();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());

        let (unknown_status, known_status) = tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                // Request 1: references "smart" (configured, OK) AND "smrt" (typo, no such pool).
                let body1 = axum::body::Bytes::from(
                    serde_json::json!({
                        "name": "k-typo",
                        "allowed_pools": ["smart", "smrt"]
                    })
                    .to_string(),
                );
                let r1 = super::create_key(axum::extract::State(app.clone()), body1).await;
                let s1 = r1.status().as_u16();

                // Request 2: references ONLY the configured pool — no warning expected.
                let body2 = axum::body::Bytes::from(
                    serde_json::json!({
                        "name": "k-ok",
                        "allowed_pools": ["smart"]
                    })
                    .to_string(),
                );
                let r2 = super::create_key(axum::extract::State(app), body2).await;
                let s2 = r2.status().as_u16();
                (s1, s2)
            })
        });

        // Both keys are still created — the diagnostic is non-fatal (forward-reference preserved).
        assert_eq!(
            unknown_status, 201,
            "an unconfigured allowed_pool must NOT 400 — the key is still minted"
        );
        assert_eq!(
            known_status, 201,
            "a configured allowed_pool creates the key"
        );

        let msgs = cap.0.lock().unwrap();
        // Exactly one warning, naming the typo'd pool — "smart" (configured) must NOT warn.
        let pool_warns: Vec<&String> = msgs
            .iter()
            .filter(|m| m.contains("allowed_pools entry names no configured pool"))
            .collect();
        assert_eq!(
            pool_warns.len(),
            1,
            "exactly one allowed_pools diagnostic expected (only the typo'd entry): {msgs:?}"
        );
        assert!(
            pool_warns[0].contains("smrt"),
            "the warning must name the typo'd pool 'smrt': {:?}",
            pool_warns[0]
        );
        assert!(
            !pool_warns[0].contains("smart\""),
            "the configured pool 'smart' must NOT be reported as unconfigured: {:?}",
            pool_warns[0]
        );
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
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
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
        assert_eq!(body["error"]["message"], "key not found");
        assert_eq!(body["error"]["type"], "not_found_error"); // golden wire-contract literal (kept bare on purpose)
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
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
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
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
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

    #[tokio::test]
    async fn test_patch_after_delete_404s_and_does_not_recreate_key() {
        // Regression (MEDIUM #7, SECURITY): a PATCH must never RESURRECT a key a DELETE removed. The
        // store's `update_key` is a check-then-act (`get_key` → `put_key`, where `put_key` UPSERTs and
        // so re-INSERTs a missing row). Serializing `update_key`'s lookup→put behind the same gate as
        // DELETE closes the window. This sequential case (DELETE fully precedes PATCH) proves the base
        // contract: PATCH on a deleted key 404s and leaves it deleted (a later GET/usage stays 404).
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        let (addr, handle) = serve_with_gov(gov).await;
        let client = reqwest::Client::new();
        let key_url = format!("http://{addr}/admin/keys/{}", key.id);

        // Revoke the key.
        let del = client
            .delete(&key_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(del.status().as_u16(), 200, "the key is revoked");

        // PATCH the now-deleted key → 404, and it must NOT recreate the row.
        let patched = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            patched.status().as_u16(),
            404,
            "PATCH on a deleted key must 404, not resurrect it"
        );

        // The key must still be gone: usage 404s and the list is empty.
        let usage = client
            .get(format!("{key_url}/usage"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            usage.status().as_u16(),
            404,
            "the revoked key must remain absent after the PATCH"
        );
        let listed: serde_json::Value = client
            .get(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            listed["keys"].as_array().unwrap().len(),
            0,
            "PATCH must not have re-inserted the deleted key: {listed}"
        );
        handle.abort();
    }

    /// A `Store` decorator that can pause inside `put_key` to force the exact PATCH/DELETE
    /// interleaving the resurrection race needs — something a black-box HTTP burst cannot do
    /// deterministically (the window between `update_key`'s `get_key` and `put_key` is microscopic).
    /// All methods delegate to an inner `SqliteStore`; only `put_key` is instrumented, and only once
    /// armed (so the create-time `put_key` during setup is unaffected).
    ///
    /// When armed, the FIRST subsequent `put_key` (the PATCH's) signals `entered` and then BLOCKS on
    /// `release` until the test lets it proceed. This pins the PATCH between its existence check and
    /// its write, so the test can run a DELETE in that gap and observe whether the gate prevents the
    /// PATCH from re-inserting (resurrecting) the just-revoked row.
    struct BarrierStore {
        inner: SqliteStore,
        armed: std::sync::atomic::AtomicBool,
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl crate::governance::Store for BarrierStore {
        fn put_key(
            &self,
            key: &crate::governance::VirtualKey,
        ) -> crate::governance::StoreResult<()> {
            // Disarm atomically so only the first put after arming pauses (and never the setup put).
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                let _ = self.entered.send(());
                // Block this blocking-pool thread until the test releases us, AFTER it has run a DELETE.
                let _ = self.release.lock().unwrap().recv();
            }
            self.inner.put_key(key)
        }
        fn get_key(
            &self,
            id: &str,
        ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn get_key_by_hash(
            &self,
            key_hash: &str,
        ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
            self.inner.get_key_by_hash(key_hash)
        }
        fn list_keys(&self) -> crate::governance::StoreResult<Vec<crate::governance::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn add_usage(
            &self,
            key_id: &str,
            window_start: u64,
            spend_cents: i64,
            tokens: u64,
            count_request: bool,
        ) -> crate::governance::StoreResult<()> {
            self.inner
                .add_usage(key_id, window_start, spend_cents, tokens, count_request)
        }
        fn get_usage(
            &self,
            key_id: &str,
            window_start: u64,
        ) -> crate::governance::StoreResult<crate::governance::Usage> {
            self.inner.get_usage(key_id, window_start)
        }
        fn charge_within_budget(
            &self,
            key_id: &str,
            window_start: u64,
            cost_cents: i64,
            max_cents: Option<i64>,
        ) -> crate::governance::StoreResult<bool> {
            self.inner
                .charge_within_budget(key_id, window_start, cost_cents, max_cents)
        }
        fn refund_request(
            &self,
            key_id: &str,
            window_start: u64,
            cost_cents: i64,
        ) -> crate::governance::StoreResult<()> {
            self.inner.refund_request(key_id, window_start, cost_cents)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_patch_interleaved_with_delete_never_resurrects_key() {
        // Regression (MEDIUM #7, SECURITY — the precise interleaving the gate exists to stop): a PATCH
        // that has already read an extant key, then is overtaken by a DELETE that revokes it, must NOT
        // have its `put_key` re-INSERT (resurrect) the row. We force the interleaving deterministically
        // with `BarrierStore`: the PATCH's `put_key` pauses between the existence check and the write
        // while the DELETE runs.
        //
        // Old code (PATCH not under the gate): the DELETE proceeds while the PATCH is paused, removes
        // the row, returns 200; then the PATCH's UPSERT re-inserts it -> key PRESENT -> this test's
        // final "key absent" assertion FAILS.
        //
        // Fixed code (PATCH holds the same `EXISTENCE_GATE` across lookup→put): the DELETE blocks on
        // the gate until the PATCH releases it, so it runs strictly AFTER the PATCH's put -> the row is
        // removed last -> key ABSENT -> this test PASSES.
        crate::metrics::init();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let store = Arc::new(BarrierStore {
            inner: SqliteStore::open_in_memory().unwrap(),
            armed: std::sync::atomic::AtomicBool::new(false),
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let gov =
            Arc::new(GovState::new(store.clone(), 0, 0, Some("admintok".to_string())).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        let (addr, handle) = serve_with_gov(gov).await;
        let key_url = format!("http://{addr}/admin/keys/{}", key.id);

        // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
        store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

        // PATCH in the background — it will read the key, then block inside put_key.
        let patch_url = key_url.clone();
        let patch_task = tokio::spawn(async move {
            reqwest::Client::new()
                .patch(&patch_url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"enabled": false}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });

        // Wait until the PATCH is parked inside put_key (between its check and its write).
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .unwrap()
            .expect("PATCH must reach the instrumented put_key");

        // DELETE in the background. Old code: it completes now. Fixed code: it blocks on EXISTENCE_GATE.
        let delete_url = key_url.clone();
        let delete_task = tokio::spawn(async move {
            reqwest::Client::new()
                .delete(&delete_url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });

        // Give the DELETE a moment to either complete (old) or wedge on the gate (fixed), then release
        // the paused PATCH so both can finish.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        release_tx.send(()).unwrap();
        let _ = patch_task.await.unwrap();
        let _ = delete_task.await.unwrap();

        // DECISIVE: regardless of the order the two requests reported, the revoked key must be GONE.
        // A resurrecting PATCH (old code) leaves it PRESENT here.
        let listed: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{addr}/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            listed["keys"].as_array().unwrap().len(),
            0,
            "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
        );
        handle.abort();
    }

    #[test]
    fn test_existence_gate_is_std_sync_mutex_lockable_without_runtime() {
        // Regression (MEDIUM #6, R26 — CONTINUES the R25 existence-race fix): the gate MUST be a
        // `std::sync::Mutex<()>`, not a `tokio::sync::Mutex<()>`. The fix binds the gate's lifetime to
        // the SYNCHRONOUS store mutation by locking it INSIDE the `spawn_blocking` closure (which has no
        // async runtime in scope); a `tokio::sync::Mutex` cannot be locked there — its `.lock()` returns
        // a future. This test locks the gate from a PLAIN (non-async) thread with no Tokio runtime
        // present: that only compiles/runs for a `std::sync::Mutex`. Against the old `tokio::sync::Mutex`
        // this call would not typecheck as a blocking lock (and `into_inner` on poison is std-only), so
        // the gate-type regression is pinned. We assert the guarded unit value round-trips.
        let guard = super::EXISTENCE_GATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The guarded data is the unit type; dereferencing proves we hold a std MutexGuard<()>.
        let () = *guard;
        drop(guard);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
        // Regression (MEDIUM #6, R26 — request-cancellation voids the existence gate): the R25 fix held
        // the gate across the cancellable outer `.await`. If the client dropped the request, the async
        // guard dropped — but the already-scheduled (uncancellable) `spawn_blocking` closure kept
        // running its lookup→write with the gate NO LONGER held, re-opening the resurrection /
        // double-revoke races. The R26 fix locks the gate INSIDE the blocking closure, so the gate is
        // held for the entire lookup→write regardless of any outer-future drop.
        //
        // We force the exact condition with `BarrierStore`: a PATCH parks inside `put_key` (between its
        // existence check and its write). We then DROP (cancel) the PATCH's driving future while it is
        // parked, and fire a DELETE. The DELETE must NOT be able to complete while the PATCH's blocking
        // mutation is still in flight:
        //   - Old code (async guard owned by the dropped PATCH future): cancelling releases the gate, so
        //     the DELETE acquires it and COMPLETES within the window -> this test's "DELETE still
        //     pending" assertion FAILS.
        //   - Fixed code (gate locked inside the still-running blocking closure): the DELETE blocks on
        //     the gate until the PATCH's `put_key` finishes -> the DELETE is STILL PENDING in the
        //     window -> this test PASSES. Releasing the barrier then lets both drain.
        crate::metrics::init();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let store = Arc::new(BarrierStore {
            inner: SqliteStore::open_in_memory().unwrap(),
            armed: std::sync::atomic::AtomicBool::new(false),
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let gov =
            Arc::new(GovState::new(store.clone(), 0, 0, Some("admintok".to_string())).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        let (addr, handle) = serve_with_gov(gov).await;
        let key_url = format!("http://{addr}/admin/keys/{}", key.id);

        // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
        store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

        // PATCH in the background — it will read the key, acquire the gate inside the blocking closure,
        // then block inside put_key. We keep the JoinHandle so we can ABORT (cancel) it.
        let patch_url = key_url.clone();
        let patch_task = tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .patch(&patch_url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"enabled": false}))
                .send()
                .await;
        });

        // Wait until the PATCH is parked inside put_key (gate held by the blocking closure).
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .unwrap()
            .expect("PATCH must reach the instrumented put_key");

        // CANCEL the PATCH: abort its driving future. The Tokio JoinHandle abort drops the async task;
        // in the old design this dropped the async existence guard. The blocking closure keeps running.
        patch_task.abort();
        let _ = patch_task.await; // joins the cancellation

        // Fire a DELETE. Old code: gate is free -> DELETE completes quickly. Fixed code: gate is still
        // held by the parked blocking closure -> DELETE blocks.
        let delete_url = key_url.clone();
        let delete_task = tokio::spawn(async move {
            reqwest::Client::new()
                .delete(&delete_url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });

        // Give the DELETE time to either complete (old) or wedge on the gate (fixed).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !delete_task.is_finished(),
            "a cancelled PATCH must keep the EXISTENCE_GATE held for its full blocking mutation; the \
             DELETE must remain blocked on the gate (old async-guard code releases it on cancel)"
        );

        // Release the parked PATCH put_key so the gate frees and the DELETE can finish — proves no
        // deadlock and lets the task drain cleanly.
        release_tx.send(()).unwrap();
        let del_status = delete_task.await.unwrap();
        // The PATCH's put_key resurrected/updated the row (it ran to completion despite cancellation),
        // so the DELETE that follows under the gate observes it and revokes it: 200. (The point of this
        // test is the BLOCKING, not the final status — but it must be a coherent 200, not a 404.)
        assert_eq!(
            del_status, 200,
            "the DELETE runs after the gate frees and revokes the (now-present) key"
        );
        handle.abort();
    }
}
