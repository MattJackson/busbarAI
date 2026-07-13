// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Virtual-key management API. Admin CRUD over `/admin/keys`, guarded by the
//! configured admin token (enforced in `auth_middleware`, not here). Mutations refresh the
//! `GovState` cache. Responses never include a key's `key_hash`; the plaintext secret is returned
//! exactly once, on creation.

use axum::body::Bytes;
use axum::extract::Path;
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
/// `crate::admin::ERR_TYPE_*`). The two values shared with the forward/OpenAI-family vocabulary
/// alias their canonical home in `proto::openai_family` so the banks cannot drift.
pub(crate) const ERR_TYPE_NOT_FOUND: &str = crate::proto::openai_family::ERR_TYPE_NOT_FOUND;
pub(crate) const ERR_TYPE_INVALID_REQUEST: &str =
    crate::proto::openai_family::ERR_TYPE_INVALID_REQUEST;
const ERR_TYPE_INTERNAL: &str = "internal_error";
const ERR_TYPE_CONFLICT: &str = "conflict_error";
/// RETRYABLE optimistic-concurrency staleness — maps to the frozen `version_conflict` code
/// (re-read + retry), split from terminal `conflict` (external review R3).
const ERR_TYPE_VERSION_CONFLICT: &str = "version_conflict_error";

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

/// Admin error envelope — the FROZEN v1 shape `{"error":{"code":...,"message":...}}` with the
/// canonical `code` enum (`not_found`/`invalid_request`/`conflict`/`internal`/…), IDENTICAL to every
/// other `/api/v1/admin` resource (see `admin::v1::contract::AdminError::code`). These legacy key
/// handlers previously spoke a DIFFERENT envelope (`{message,type}` with `*_error` values); that
/// split forced a client/Terraform provider to branch on `error.code` for config/hooks/auth but on
/// `error.type` for keys, with different values. Since `/api/v1/admin` freezes at 1.3, keys must speak
/// the one contract (audit: admin contract H1). `message` carries only caller-safe text — store/DB
/// details are logged server-side (see `internal_error`) and never reach this body.
fn error_response(status: StatusCode, error_type: &str, message: impl Into<String>) -> Response {
    // Map the legacy `*_error` type onto the frozen v1 `code` enum, byte-for-byte matching
    // `AdminError::code()` so keys and non-keys emit the SAME code for the same condition.
    let code = match error_type {
        ERR_TYPE_NOT_FOUND => "not_found",
        ERR_TYPE_INVALID_REQUEST => "invalid_request",
        ERR_TYPE_CONFLICT => "conflict",
        ERR_TYPE_VERSION_CONFLICT => "version_conflict",
        ERR_TYPE_INTERNAL => "internal",
        // Every caller passes one of the four above; fall back safely to the generic 4xx/5xx code
        // rather than leaking an unmapped token onto the frozen wire.
        _ if status.is_server_error() => "internal",
        _ => "invalid_request",
    };
    json_response(
        status,
        json!({"error": {"code": code, "message": message.into()}}),
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

// ── Admin API (the FROZEN surface — /api/v1/admin/*) ─────────────────────────────────────────────────
//
// Built engine + swappable layers (Matthew 7/11), VERSION-FIRST: each API version (`v1`, later `v2`)
// is a self-contained unit under its own directory holding that version's CONTRACT (typed views +
// stable error codes), its SERVICE (typed operations over the shared engine), and its TRANSPORT wire
// adapters (`json`, later `graphql`). The transport PORT (`AdminTransport` in `transport`) is shared
// across versions and transports. Releasing v2 is a LAYER copy of `v1/`, not a rewrite; v1 never
// breaks. The keys handlers below are mounted ONLY at the canonical `/api/v1/admin/keys*` routes
// (via the JsonV1 router — the pre-release `/admin/keys` alias is gone), and speak the ONE frozen
// v1 contract: the `{error:{code,message}}` envelope with the stable code enum (contract H1). Keys
// are a first-class v1 resource served by these handlers until they migrate into the versioned
// service module.
pub(crate) mod audit;
pub(crate) mod rate;
pub(crate) mod transport;
pub(crate) mod v1;
pub(crate) mod versions;

pub(crate) use v1::json::JsonV1;
pub(crate) use v1::service::mark_start;

/// Key metadata for API responses — deliberately omits `key_hash`.
/// A key record's ETag: a short digest of its mutable metadata. Changes whenever any PATCHable
/// field changes, so `If-Match` detects a concurrent modification (409, no lost update).
fn key_etag(k: &VirtualKey) -> String {
    let meta = key_meta(k);
    crate::sigv4::sha256_hex(meta.to_string().as_bytes())[..16].to_string()
}

/// Parse the optional `If-Match` header for a KEY mutation (PATCH/DELETE `/keys/{id}`): the key's
/// own ETag from a prior GET (16 lowercase hex chars — see `key_etag`), quotes/weak-prefix
/// stripped. `*` (RFC 7232: "any current representation") matches any existing key, i.e. no guard —
/// `Ok(None)`. Anything that cannot be a key ETag is a 400 `invalid_request` — the SAME terminal
/// the config-plane parser gives a malformed guard, never a retriable-looking 409 that a client
/// with a header bug would re-read and retry forever (re-audit M4). Shared by PATCH and DELETE so
/// the two verbs can never diverge on grammar.
#[allow(clippy::result_large_err)] // Err = the ready-to-return 400 Response (callers just return it)
fn parse_key_if_match(headers: &axum::http::HeaderMap) -> Result<Option<String>, Response> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    let bare = s.strip_prefix("W/").unwrap_or(s).trim_matches('"');
    if bare.len() == 16 && bare.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(Some(bare.to_string()))
    } else {
        Err(error_response(
            StatusCode::BAD_REQUEST,
            ERR_TYPE_INVALID_REQUEST,
            "malformed If-Match: expected the key's ETag (16 hex chars, quoted) or *",
        ))
    }
}

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

/// Governance-off semantics (re-audit HIGH-2): ONE rule across the keys surface, chosen so no
/// status is ambiguous —
/// - collection READS (`GET /keys`) answer 200 with an EMPTY page (`disabled_empty_list`): with
///   governance off the keyspace is truthfully empty, and a 404 on a collection reads as a
///   mount/path error to every REST client;
/// - single-resource READS keep 404 `not_found` (also truthful — no such key exists);
/// - WRITES (create/patch/delete/rotate) answer 409 `conflict` (`disabled_write`): the request
///   conflicts with the server's configured state, with an actionable message. Previously every
///   handler returned 404 — making `not_found` mean two different things forever.
fn disabled_write() -> Response {
    error_response(
        StatusCode::CONFLICT,
        ERR_TYPE_CONFLICT,
        "governance is not enabled on this server; enable `governance:` in config.yaml to manage \
         virtual keys",
    )
}

/// `GET /keys` with governance off: the truthful empty page in the standard cursor envelope.
fn disabled_empty_list() -> Response {
    json_response(
        StatusCode::OK,
        json!({ "items": [], "next_cursor": serde_json::Value::Null }),
    )
}

/// Single-resource read with governance off: no key can exist, so `not_found` is truthful.
fn disabled_read() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        ERR_TYPE_NOT_FOUND,
        "key not found (governance is not enabled on this server)",
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

/// The request header carrying a client-chosen idempotency token on the two replayable admin
/// mutations (key mint + key rotate).
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// Replay window (seconds, ~10 min) for the idempotency cache; stale entries are swept on use.
const IDEMPOTENCY_TTL_SECS: u64 = 600;

/// An in-flight idempotency RESERVATION. `create_key` inserts a `Null`-body sentinel under the
/// cache lock the instant it decides to mint (atomic with the "already cached?" check), so a
/// concurrent retry with the same `Idempotency-Key` sees the reservation and is rejected instead
/// of double-minting. This guard clears that sentinel on drop UNLESS the mint committed — so a
/// request that fails after reserving frees the key for a legitimate retry, while a successful
/// mint (which replaced the sentinel with its real 201 body and disarmed the guard) keeps it.
struct IdemReservation {
    #[allow(clippy::type_complexity)]
    cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), (u64, serde_json::Value)>>,
    >,
    key: (String, String),
    committed: bool,
}

impl Drop for IdemReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        // Only remove if it is STILL the pending sentinel — never clobber a real committed body
        // (a success path that already replaced it).
        if matches!(c.get(&self.key), Some((_, v)) if v.is_null()) {
            c.remove(&self.key);
        }
    }
}

/// POST /admin/keys — mint a virtual key. Returns the plaintext secret ONCE.
pub(crate) async fn create_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    // IDEMPOTENT MINT (optional `Idempotency-Key`): a retried POST with the same key inside the
    // ~10min window returns the FIRST response verbatim (including the once-shown secret — the
    // standard idempotency contract: a retry is the same request, not a second mint) instead of
    // double-creating. Bounded: stale entries are swept on every use.
    let idem_key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    // The idempotency key is scoped to the PRINCIPAL: (actor, header). A different admin's identical
    // Idempotency-Key value must never replay this principal's response (which carries a secret).
    let idem_ckey: Option<(String, String)> = idem_key.as_ref().map(|k| (actor.clone(), k.clone()));
    if let Some(ref ck) = idem_ckey {
        let now = crate::store::now();
        let mut cache = app
            .idempotency_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (t, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match cache.get(ck) {
            // A COMPLETED prior mint (the real 201 object): replay it verbatim.
            Some((_, cached)) if !cached.is_null() => {
                return json_response(StatusCode::CREATED, cached.clone());
            }
            // An IN-FLIGHT reservation (Null sentinel): a concurrent request with the same key is
            // still minting. Reject rather than double-mint (the TOCTOU a separate check+insert
            // allowed); the client's retry succeeds once the first completes or the reservation
            // expires.
            Some(_) => {
                return error_response(
                    StatusCode::CONFLICT,
                    ERR_TYPE_CONFLICT,
                    "a request with this Idempotency-Key is already in flight",
                );
            }
            // First time: RESERVE under this SAME lock hold, so a concurrent request observes the
            // reservation instead of an empty slot.
            None => {
                cache.insert(ck.clone(), (now, serde_json::Value::Null));
            }
        }
    }
    // Clears the reservation if we return before committing (parse / validation / mint failure);
    // disarmed on success, where the real body replaces the sentinel.
    let mut idem_reservation = idem_ckey.as_ref().map(|ck| IdemReservation {
        cache: app.idempotency_cache.clone(),
        key: ck.clone(),
        committed: false,
    });
    let Some(gov) = &app.governance else {
        return disabled_write();
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
                audit::AUDIT.record_by(
                    "key.create",
                    &format!("key:{}", key.id),
                    audit::OUTCOME_APPLIED,
                    &actor,
                );
                let mut body = key_meta(&key);
                body["secret"] = json!(secret); // bearer secret, shown exactly once
                                                // The AccessKeyId is NOT secret (it travels in plaintext in the SigV4 header), but it
                                                // is returned here at creation. The AWS SECRET access key is shown ONCE here only —
                                                // never returned by any read API, mirroring the bearer `secret`.
                body["aws_access_key_id"] = json!(access_key_id);
                body["aws_secret_access_key"] = json!(secret_access_key);
                if let Some(ref ck) = idem_ckey {
                    app.idempotency_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(ck.clone(), (crate::store::now(), body.clone()));
                }
                // Mint committed and the sentinel replaced by the real body — disarm the guard so
                // it does not remove the now-cached response.
                if let Some(g) = idem_reservation.as_mut() {
                    g.committed = true;
                }
                json_response(StatusCode::CREATED, body)
            }
            Ok(Err(e)) => internal_error("create_key", &e),
            Err(e) => join_error("create_key", &e),
        }
    } else {
        let res = tokio::task::spawn_blocking(move || gov.create_key(spec, now)).await;
        match res {
            Ok(Ok((key, secret))) => {
                audit::AUDIT.record_by(
                    "key.create",
                    &format!("key:{}", key.id),
                    audit::OUTCOME_APPLIED,
                    &actor,
                );
                let mut body = key_meta(&key);
                body["secret"] = json!(secret); // shown exactly once
                if let Some(ref ck) = idem_ckey {
                    app.idempotency_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(ck.clone(), (crate::store::now(), body.clone()));
                }
                // Mint committed and the sentinel replaced by the real body — disarm the guard so
                // it does not remove the now-cached response.
                if let Some(g) = idem_reservation.as_mut() {
                    g.committed = true;
                }
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
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    // OPTIMISTIC CONCURRENCY (optional `If-Match`): the caller's ETag is compared against the
    // CURRENT record — a stale tag is a 409, never a lost update. The compare must be ATOMIC with
    // the write, so it is deferred INTO the gated write closure below (a separate pre-read here
    // would leave a window in which a concurrent PATCH mutates the row between the check and this
    // write, defeating the guard). Absent header = the transitional unguarded path.
    let if_match = match parse_key_if_match(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
    // The If-Match compare and the write run TOGETHER under the existence gate, so the record the
    // ETag was checked against is the same record that gets updated — no concurrent PATCH can slip
    // between them and defeat the guard (the lost-update the separate pre-read allowed).
    enum UpdateOutcome {
        Updated(Box<crate::governance::VirtualKey>),
        NotFound,
        EtagStale,
    }
    let resource = format!("key:{id}");
    let res =
        tokio::task::spawn_blocking(move || -> crate::governance::StoreResult<UpdateOutcome> {
            let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tag) = &if_match {
                match gov.all_keys()?.into_iter().find(|k| k.id == id) {
                    Some(k) if key_etag(&k) != *tag => return Ok(UpdateOutcome::EtagStale),
                    None => return Ok(UpdateOutcome::NotFound),
                    Some(_) => {}
                }
            }
            Ok(match gov.update_key(&id, enabled, rpm, tpm, budget)? {
                Some(key) => UpdateOutcome::Updated(Box::new(key)),
                None => UpdateOutcome::NotFound,
            })
        })
        .await;
    match res {
        Ok(Ok(UpdateOutcome::Updated(key))) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_APPLIED, &actor);
            json_response(StatusCode::OK, key_meta(&key))
        }
        Ok(Ok(UpdateOutcome::EtagStale)) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            error_response(
                StatusCode::CONFLICT,
                ERR_TYPE_VERSION_CONFLICT,
                "If-Match ETag is stale: the key changed since you read it (re-read and retry)",
            )
        }
        Ok(Ok(UpdateOutcome::NotFound)) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found")
        }
        Ok(Err(e)) => internal_error("update_key", &e),
        Err(e) => join_error("update_key", &e),
    }
}

/// GET /admin/keys — list key metadata (no secrets/hashes). Optional filters (design-admin-api-v1
/// §2.1): `?enabled=true|false` (by enabled state), `?prefix=vk_ab` (by key-id prefix).
pub(crate) async fn list_keys(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Strict query parsing FIRST (re-audit L6): a malformed filter/cursor is a loud 400 on every
    // server — governance-off must not fork the validation behavior (200-empty only for a VALID
    // query).
    // An unparseable filter value is a loud 400, never a silently-dropped filter (which would
    // return MORE keys than the caller asked for).
    let enabled = match q.get("enabled") {
        None => None,
        Some(v) => match v.parse::<bool>() {
            Ok(b) => Some(b),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ERR_TYPE_INVALID_REQUEST,
                    "invalid `enabled` filter: expected true|false",
                )
            }
        },
    };
    let prefix = q.get("prefix").cloned();
    // PAGINATION (design-admin-api-v1 §0.4): the ONE cursor envelope shared by every admin list —
    // `?limit=` bounds the page, `?cursor=` (opaque) resumes after the prior one, and the response is
    // `{items, next_cursor}` (next_cursor present iff more rows remain). No `total`, no `?offset=` —
    // one pagination grammar across keys/audit/versions/topology.
    // Default 200 / hard cap 1000 — the SAME limit policy as the audit/versions lists (one
    // pagination grammar, one limit policy; an unbounded default response is exactly what
    // pagination exists to prevent — re-audit M9).
    let limit = match q.get("limit") {
        None => 200,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n.min(1000),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ERR_TYPE_INVALID_REQUEST,
                    "invalid `limit`: expected an integer (max 1000)",
                )
            }
        },
    };
    let start = match q.get("cursor") {
        Some(c) => match crate::admin::v1::contract::decode_offset_cursor(c) {
            Some(n) => n,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ERR_TYPE_INVALID_REQUEST,
                    "invalid or foreign pagination cursor",
                )
            }
        },
        None => 0,
    };
    let Some(gov) = &app.governance else {
        return disabled_empty_list();
    };
    let gov = gov.clone();
    let res = tokio::task::spawn_blocking(move || gov.all_keys()).await;
    match res {
        Ok(Ok(keys)) => {
            let mut filtered: Vec<_> = keys
                .iter()
                .filter(|k| enabled.is_none_or(|e| k.enabled == e))
                .filter(|k| prefix.as_deref().is_none_or(|p| k.id.starts_with(p)))
                .collect();
            // Deterministic page boundaries: sort by id (the store's iteration order is not a
            // pagination contract).
            filtered.sort_by(|a, b| a.id.cmp(&b.id));
            let total = filtered.len();
            let page: Vec<_> = filtered
                .into_iter()
                .skip(start)
                .take(limit)
                .map(key_meta)
                .collect();
            // More rows past this page → hand back the next opaque cursor; else None (end of list).
            let end = start.saturating_add(page.len());
            let next_cursor =
                (end < total).then(|| crate::admin::v1::contract::encode_offset_cursor(end));
            json_response(
                StatusCode::OK,
                json!({ "items": page, "next_cursor": next_cursor }),
            )
        }
        Ok(Err(e)) => internal_error("list_keys", &e),
        Err(e) => join_error("list_keys", &e),
    }
}

/// POST /api/v1/admin/keys/{id}/rotate — mint a FRESH bearer secret for an existing key, in place: the
/// id (and with it budgets, rate windows, usage, audit attribution) is unchanged; the old secret
/// stops resolving immediately; the new secret is returned exactly once, exactly like mint. 404
/// for an unknown id. An attached AWS SigV4 credential is not touched (separate lifecycle).
pub(crate) async fn rotate_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    // IDEMPOTENT ROTATE (optional `Idempotency-Key`, re-audit M10): rotate is the one other
    // destructive, secret-bearing POST — a network-level retry without this mints TWICE and the
    // first (lost) response's secret is silently dead. Same mechanics as create's idempotent mint
    // (principal-scoped cache + in-flight reservation), with the cache key additionally scoped by
    // operation + key id so a create and a rotate sharing a header value can never replay each
    // other's response.
    let idem_ckey: Option<(String, String)> = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|k| (actor.clone(), format!("rotate:{id}:{k}")));
    if let Some(ref ck) = idem_ckey {
        let now = crate::store::now();
        let mut cache = app
            .idempotency_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (t, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match cache.get(ck) {
            Some((_, cached)) if !cached.is_null() => {
                return json_response(StatusCode::OK, cached.clone());
            }
            Some(_) => {
                return error_response(
                    StatusCode::CONFLICT,
                    ERR_TYPE_CONFLICT,
                    "a request with this Idempotency-Key is already in flight",
                );
            }
            None => {
                cache.insert(ck.clone(), (now, serde_json::Value::Null));
            }
        }
    }
    let mut idem_reservation = idem_ckey.as_ref().map(|ck| IdemReservation {
        cache: app.idempotency_cache.clone(),
        key: ck.clone(),
        committed: false,
    });
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    let gov = gov.clone();
    let gid = id.clone();
    // rotate is a check-then-act (get_key → mint → put_key over the UPSERT primitive), so it must
    // hold EXISTENCE_GATE for the same reason update_key/delete_key do: without it a concurrent
    // delete that lands between rotate's read and write is clobbered by rotate's put — RESURRECTING
    // a revoked key with a fresh secret. Gate acquired INSIDE the closure for cancellation safety
    // (a scheduled spawn_blocking runs to completion even if the handler future is dropped).
    // (found: audit c1r6 — rotate was the one key-mutator missing the gate.)
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        gov.rotate_key(&gid)
    })
    .await;
    let resource = format!("key:{id}");
    match res {
        Ok(Ok(Some((key, secret)))) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_APPLIED, &actor);
            let mut body = key_meta(&key);
            body["secret"] = json!(secret); // shown exactly once, exactly like mint
                                            // COMMIT the idempotency slot with the real response (replaces the reservation) and
                                            // disarm the drop-guard — a retry inside the window replays THIS body verbatim.
            if let Some(ref ck) = idem_ckey {
                let mut cache = app
                    .idempotency_cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                cache.insert(ck.clone(), (crate::store::now(), body.clone()));
                if let Some(r) = idem_reservation.as_mut() {
                    r.committed = true;
                }
            }
            json_response(StatusCode::OK, body)
        }
        Ok(Ok(None)) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_REJECTED, &actor);
            error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found")
        }
        Ok(Err(e)) => internal_error("rotate_key", &e),
        Err(e) => join_error("rotate_key", &e),
    }
}

/// GET /admin/keys/:id — one key's metadata (id/name/pools/budgets/limits/enabled; never the
/// secret or key_hash). 404 when no key with `id` exists. Fills the single-key read gap in the key
/// surface (design-admin-api-v1 §2.1); it stays on the legacy `{type}` envelope + `key_meta` shape so
/// it is consistent with the sibling key routes (the full `{code}`-envelope migration is a follow-up).
pub(crate) async fn get_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    let gov = gov.clone();
    let id2 = id.clone();
    // The synchronous store read runs on the blocking pool (the SQLite backend is sync). Read via
    // `all_keys` + find (the same accessor the list handler uses) — admin scale, no hot path.
    let res = tokio::task::spawn_blocking(move || {
        gov.all_keys()
            .map(|keys| keys.into_iter().find(|k| k.id == id2))
    })
    .await;
    match res {
        Ok(Ok(Some(k))) => {
            let etag = key_etag(&k);
            // ETag lives ONLY in the HTTP `ETag` header (RFC 7232), not duplicated into the JSON
            // body — one authoritative surface, matching how config/hooks/auth expose their
            // concurrency token. (contract H4.)
            let meta = key_meta(&k);
            let mut resp = json_response(StatusCode::OK, meta);
            if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
                resp.headers_mut().insert(axum::http::header::ETAG, v);
            }
            resp
        }
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found"),
        Ok(Err(e)) => internal_error("get_key", &e),
        Err(e) => join_error("get_key", &e),
    }
}

/// GET /api/v1/admin/keys/{id}/usage — the key's BUDGET-window counters (the enforcement view:
/// spend/tokens/requests against its own budget window; the fleet FinOps series lives on `/usage`)
/// plus `rate_headroom`: the fraction `[0,1]` of the tightest configured RPM/TPM limit still
/// available in the current 60s window (`null` when the key has no rate caps) — a client can back
/// off BEFORE hitting a 429 instead of discovering the cap by tripping it (key-06).
pub(crate) async fn key_usage(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    let now = crate::store::now();
    let gov2 = gov.clone();
    let id2 = id.clone();
    // One blocking hop fetches BOTH the usage counters and the key record (the record feeds the
    // in-memory `rate_headroom` read, which needs the configured caps).
    let res = tokio::task::spawn_blocking(move || {
        let usage = gov2.usage_for(&id2, now)?;
        let key = gov2.all_keys()?.into_iter().find(|k| k.id == id2);
        Ok::<_, crate::governance::StoreError>(usage.map(|u| (u, key)))
    })
    .await;
    match res {
        Ok(Ok(Some((u, key)))) => {
            let headroom = key.as_ref().and_then(|k| gov.rate_headroom(k, now));
            // Label the numbers (re-audit L): WHICH budget window these counters cover
            // (`budget_period` + its start epoch) and when the read was taken — a consumer can
            // cache, align, and reset-detect without guessing.
            let (period, window_start) = key
                .as_ref()
                .map(|k| {
                    (
                        k.budget_period.clone(),
                        crate::governance::budget_window(&k.budget_period, now),
                    )
                })
                .map_or(
                    (serde_json::Value::Null, serde_json::Value::Null),
                    |(p, w)| (json!(p), json!(w)),
                );
            json_response(
                StatusCode::OK,
                json!({
                    "id": id,
                    "budget_period": period,
                    "window_start": window_start,
                    "as_of": now,
                    "spend_cents": u.spend_cents,
                    "tokens": u.tokens,
                    "requests": u.requests,
                    "rate_headroom": headroom,
                }),
            )
        }
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found"),
        Ok(Err(e)) => internal_error("key_usage", &e),
        Err(e) => join_error("key_usage", &e),
    }
}

/// DELETE /admin/keys/:id — revoke a key. Returns 404 when no key with `id` exists (REST/OpenAPI
/// contract), so a typo'd or already-deleted id is distinguishable from an actual revocation rather
/// than masquerading as a spurious 200.
pub(crate) async fn delete_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    // Optimistic concurrency (optional `If-Match`, H3 — every mutation verb on the surface honors
    // it): the caller's ETag is compared against the CURRENT record inside the gated critical
    // section below, so the delete only lands on the exact record state the caller last read.
    let if_match = match parse_key_if_match(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Existence check before delete: the key RECORD is looked up first and `None` means not-found
    // (the store's `delete_key` silently no-ops a zero-row delete, so we cannot rely on it to signal
    // not-found). Use the public GovState API rather than reaching into the store. The record (not a
    // bare existence bit) is needed anyway: the optional If-Match guard compares its ETag.
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
    /// The three delete outcomes the gated critical section distinguishes.
    enum DeleteOutcome {
        Deleted,
        NotFound,
        EtagStale,
    }
    let gov = gov.clone();
    let id_for_task = id.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        // The key RECORD (not just existence) is read under the gate: the If-Match compare must be
        // atomic with the delete, exactly like PATCH's compare-and-put.
        let key = gov.all_keys()?.into_iter().find(|k| k.id == id_for_task);
        match key {
            None => Ok(DeleteOutcome::NotFound),
            Some(k) => {
                if let Some(expected) = &if_match {
                    if key_etag(&k) != *expected {
                        return Ok(DeleteOutcome::EtagStale);
                    }
                }
                gov.delete_key(&id_for_task)
                    .map(|()| DeleteOutcome::Deleted)
            }
        }
    })
    .await;
    let resource = format!("key:{id}");
    match res {
        Ok(Ok(DeleteOutcome::Deleted)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // 204 No Content — the SAME success shape as `DELETE /api/v1/admin/hooks/{name}` (was a
            // bespoke `200 {"deleted": id}` found nowhere else on the surface). (contract H4.)
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(DeleteOutcome::NotFound)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            error_response(StatusCode::NOT_FOUND, ERR_TYPE_NOT_FOUND, "key not found")
        }
        Ok(Ok(DeleteOutcome::EtagStale)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            error_response(
                StatusCode::CONFLICT,
                ERR_TYPE_VERSION_CONFLICT,
                "If-Match ETag is stale: the key changed since you read it (re-read and retry)",
            )
        }
        Ok(Err(e)) => internal_error("delete_key", &e),
        Err(e) => join_error("delete_key", &e),
    }
}

// The admin-surface e2e tests authenticate through the `admin-tokens` module; a
// `--no-default-features` binary compiles it OUT, which DISABLES the admin API wholesale (the
// admin_auth chain all-Passes ⇒ denied) — so this module only applies when the module exists.
#[cfg(all(test, feature = "auth-admin-tokens"))]
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

    /// `GET /api/v1/admin/info` flows end-to-end through the ports-and-adapters stack (JSON-REST
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
            .get(format!("http://{addr}/api/v1/admin/info"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            unauth.status().as_u16(),
            401,
            "v1/info must be admin-guarded"
        );

        let resp = client
            .get(format!("http://{addr}/api/v1/admin/info"))
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
        // No overlay configured in this fixture → persistence off.
        assert_eq!(body["config_persistence"], false);

        handle.abort();
    }

    /// The topology read surface (`/api/v1/admin/pools`, `/models`, `/providers`) flows through the
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

        let pools = get("/api/v1/admin/pools".into()).await;
        let items = pools["items"].as_array().unwrap();
        let mypool = items
            .iter()
            .find(|p| p["name"] == "mypool")
            .expect("mypool present");
        let members = mypool["members"].as_array().unwrap();
        assert_eq!(members.len(), 2, "pool has two members");
        let weight_a = members.iter().find(|m| m["model"] == "model-a").unwrap()["weight"].as_u64();
        assert_eq!(weight_a, Some(3), "model-a weight projected");

        let models = get("/api/v1/admin/models".into()).await;
        let m_items = models["items"].as_array().unwrap();
        assert!(m_items
            .iter()
            .any(|m| m["model"] == "model-a" && m["provider"] == "prov-x"));
        assert!(m_items
            .iter()
            .any(|m| m["model"] == "model-b" && m["provider"] == "prov-y"));

        let providers = get("/api/v1/admin/providers".into()).await;
        let p_items = providers["items"].as_array().unwrap();
        let px = p_items.iter().find(|p| p["provider"] == "prov-x").unwrap();
        assert_eq!(px["model_count"].as_u64(), Some(1));
        assert!(p_items.iter().any(|p| p["provider"] == "prov-y"));

        handle.abort();
    }

    /// `GET /api/v1/admin/pools/{name}` projects each member's LIVE status (usable/cooldown/concurrency/
    /// inflight/tallies) from the store; 404s an unknown pool.
    /// Re-audit HIGH-1: EVERY response under the native-API root speaks the frozen envelope —
    /// including unmatched paths (404 `not_found`) and wrong methods (405 `method_not_allowed`),
    /// which previously fell through to the data plane's vendor-native shaping (`error.type`).
    #[tokio::test]
    async fn test_api_root_unmatched_paths_speak_the_admin_envelope() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Unmatched path INSIDE the admin nest + an /api path outside any surface: both 404 in the
        // admin envelope (`code`, never a vendor `type`).
        for path in ["/api/v1/admin/nonexistent", "/api/junk"] {
            let r = client
                .get(format!("http://{addr}{path}"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 404, "{path}");
            let body: serde_json::Value = r.json().await.unwrap();
            assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
            assert!(
                body["error"]["type"].is_null(),
                "{path}: never the vendor envelope: {body}"
            );
        }

        // Wrong method on a real endpoint: 405 in the envelope with the frozen code.
        let r = client
            .delete(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 405);
        assert_eq!(
            r.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "method_not_allowed"
        );
        handle.abort();
    }

    /// Re-audit HIGH-2: governance-off semantics are UNAMBIGUOUS — collection reads answer the
    /// truthful empty page, single reads a truthful 404, and writes a 409 `conflict` with an
    /// actionable message (previously everything was 404, making `not_found` mean two things).
    #[tokio::test]
    async fn test_keys_surface_governance_disabled_semantics() {
        crate::metrics::init();
        let mut app = TestApp::new().build(); // NO governance
        {
            // Open admin posture (explicit empty chain) — this test probes HANDLER semantics, not
            // auth; with governance off there is no admin token for the default chain to accept.
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.admin_chain = Vec::new();
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Collection read: 200 empty page in the standard envelope.
        let r = client
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "collection GET is 200-empty");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 0);
        assert!(body["next_cursor"].is_null());

        // Single-resource read: truthful 404.
        let r = client
            .get(format!("http://{addr}/api/v1/admin/keys/vk_x"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404);

        // Write: 409 conflict with the actionable message.
        let r = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            409,
            "writes conflict with server state"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "conflict");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("governance"),
            "actionable message: {body}"
        );
        handle.abort();
    }

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
            .get(format!("http://{addr}/api/v1/admin/pools/mypool"))
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
        assert_eq!(m["cooldown_remaining_seconds"], 0);
        assert!(m["available_concurrency"].is_number());
        assert!(m["inflight"].is_number());
        assert!(m["ok"].is_number());
        assert!(m["dead"].is_boolean());
        // Trip observability (audit #5): a MONOTONIC trip counter + last-trip epoch, so a poller
        // detects transient breaker episodes it can never catch live. Fresh lane: 0 / null.
        assert_eq!(m["trip_count"], 0);
        assert!(m["last_trip_at"].is_null());

        // ?detail=true on the COLLECTION returns the same row shape for every pool in ONE call
        // (audit #7 — no more M+1 dashboard fan-out).
        let detailed: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/pools?detail=true"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let items = detailed["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "mypool");
        assert_eq!(
            items[0]["members"][0]["usable"], true,
            "detail rows carry the live status inline: {detailed}"
        );
        assert_eq!(items[0]["members"][0]["trip_count"], 0);

        // Unknown pool → 404 not_found.
        let missing = client
            .get(format!("http://{addr}/api/v1/admin/pools/nope"))
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

    /// `GET /api/v1/admin/admin-auth` reports the admin-plane guard: with governance + an admin token it
    /// is `configured: true` with the `admin-token` module. Never a secret.
    #[tokio::test]
    async fn test_admin_v1_admin_auth_read() {
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
            .get(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["configured"], true);
        // modules reports the live admin_auth chain verbatim (the SAME resource PUT admin-auth writes)
        assert!(body["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "admin-tokens"));

        handle.abort();
    }

    /// `GET /api/v1/admin/keys/{id}` returns one key's metadata (never the secret/hash); 404 for an
    /// unknown id. Fills the single-key read gap on the legacy key surface.
    #[tokio::test]
    async fn test_admin_v1_get_single_key() {
        use crate::governance::NewKeySpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (minted, minted_secret) = gov
            .create_key(
                NewKeySpec {
                    name: "svc".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                crate::store::now(),
            )
            .unwrap();
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Found → 200 with metadata, no secret/hash.
        let resp = client
            .get(format!("http://{addr}/api/v1/admin/keys/{}", minted.id))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["id"], minted.id);
        assert_eq!(body["name"], "svc");
        assert!(body.get("key_hash").is_none(), "never expose the hash");
        assert!(
            !text.contains(&minted_secret),
            "never expose the secret on a read"
        );

        // Unknown id → 404.
        let missing = client
            .get(format!("http://{addr}/api/v1/admin/keys/vk_doesnotexist"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);

        handle.abort();
    }

    /// `GET /api/v1/admin/usage` is the METERING read: the current UTC-day bucket aggregated per
    /// (model, provider) and per key, each row carrying the raw token SPLIT plus busbar's DERIVED
    /// `spend_micros` (from the configured global prices), under a `window`/`as_of`/`currency`
    /// header. Never leaks the secret (id/name only).
    #[tokio::test]
    async fn test_admin_v1_usage_meters_by_model_and_key() {
        use crate::governance::NewKeySpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        // Prices: 1¢/request + 50¢/1k tokens — the derivation inputs the assertions replay.
        let gov = Arc::new(GovState::new(store, 1, 50, Some("admintok".to_string())).unwrap());
        let now = crate::store::now();
        let (minted, minted_secret) = gov
            .create_key(
                NewKeySpec {
                    name: "team-a".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                now,
            )
            .unwrap();
        // Two responses metered against one model (split preserved), one against another model.
        let usage = crate::ir::IrUsage {
            input_tokens: 700,
            output_tokens: 200,
            cache_read_input_tokens: Some(100),
            cache_creation_input_tokens: None,
        };
        // On a runtime `record_metering` offloads (fire-and-forget) — run the setup writes on a
        // plain thread (no tokio context → the write happens inline) and join, so the GET below
        // deterministically sees them.
        {
            let gov = gov.clone();
            let key_id = minted.id.clone();
            std::thread::spawn(move || {
                gov.record_metering(&key_id, "gpt-x", "openai", Some(&usage), now);
                gov.record_metering(&key_id, "gpt-x", "openai", Some(&usage), now);
                gov.record_metering(&key_id, "claude-z", "anthropic", None, now);
            })
            .join()
            .unwrap();
        }
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let body: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/usage"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // Window/freshness/currency header (the audit's #2/#3 findings).
        assert_eq!(body["currency"], "USD");
        assert!(body["as_of"].as_u64().unwrap() >= now);
        let (start, end) = (
            body["window"]["start"].as_u64().unwrap(),
            body["window"]["end"].as_u64().unwrap(),
        );
        assert_eq!(end - start, 86_400, "one UTC-day metering bucket");
        assert!((start..end).contains(&now));

        // Totals: raw split + derived spend. 3 requests; billable = 2×(700+200+100) = 2000 tokens.
        // spend = 3 req × 1¢ + 2000 tokens × 50¢/1k = 3¢ + 100¢ = 103¢ = 1_030_000 micro-USD.
        assert_eq!(body["total"]["requests"], 3);
        assert_eq!(body["total"]["tokens_input"], 1400);
        assert_eq!(body["total"]["tokens_output"], 400);
        assert_eq!(body["total"]["tokens_cache_read"], 200);
        assert_eq!(body["total"]["tokens_cache_creation"], 0);
        assert_eq!(body["total"]["spend_micros"], 1_030_000);

        // Per-model attribution (the FinOps unit): each row carries the same split shape.
        let by_model = body["by_model"].as_array().unwrap();
        assert_eq!(by_model.len(), 2, "{by_model:?}");
        let x = by_model.iter().find(|m| m["model"] == "gpt-x").unwrap();
        assert_eq!(x["provider"], "openai");
        assert_eq!(x["requests"], 2);
        assert_eq!(x["tokens_input"], 1400);
        // 2 req × 1¢ + 2000 × 50¢/1k = 102¢
        assert_eq!(x["spend_micros"], 1_020_000);
        let z = by_model.iter().find(|m| m["model"] == "claude-z").unwrap();
        assert_eq!(
            z["requests"], 1,
            "a flat (zero-token) response still counts"
        );
        assert_eq!(z["spend_micros"], 10_000, "1 req × 1¢ = 10_000 micro-USD");

        // Per-key attribution names the key; the secret never appears anywhere in the body.
        let by_key = body["by_key"].as_array().unwrap();
        assert_eq!(by_key.len(), 1);
        assert_eq!(by_key[0]["id"], minted.id);
        assert_eq!(by_key[0]["name"], "team-a");
        assert_eq!(by_key[0]["requests"], 3);
        let text = body.to_string();
        assert!(
            !text.contains(&minted_secret),
            "usage must not leak the key secret"
        );

        handle.abort();
    }

    /// END-TO-END config apply: `POST /api/v1/admin/hooks` registers a hook at runtime (201), and a
    /// subsequent `GET /api/v1/admin/hooks` SEES it — proving the AppHandle swap took effect AND the
    /// per-request service reads the CURRENT snapshot. Invalid definitions reject with invalid_request.
    /// D2 e2e (unix): PATCH settings pushes `configure` to the running hook and commits ON ACK
    /// (the registry shows the new settings); a NACKing hook commits nothing; GET schema proxies
    /// the hook's describe reply.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
        crate::metrics::init();
        // A fake hook binary: acks configure (echoing the pushed version), answers describe.
        let dir = std::env::temp_dir().join(format!("busbar-d2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("hook.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let ack_mode = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hook_ack = ack_mode.clone();
        let hook_task = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let ack = hook_ack.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                        let reply = if let Some(c) = v.get("configure") {
                            if ack.load(std::sync::atomic::Ordering::Relaxed) {
                                serde_json::json!({"ack": {"settings_version": c["settings_version"]}})
                            } else {
                                serde_json::json!({"error": "refused"})
                            }
                        } else if v.get("describe").is_some() {
                            serde_json::json!({"schema": {"type": "object", "properties": {"ratio": {"type": "number"}}}})
                        } else {
                            serde_json::json!({})
                        };
                        if w.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let serve = tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| {
            req.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };

        // Register the hook (overlay), then PATCH its settings — ack mode on: commits.
        let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
            .body(
                serde_json::json!({
                    "name": "cfg-hook",
                    "config": {"kind": "gate", "socket": sock.to_str().unwrap()}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);
        let patched = admin(client.patch(format!(
            "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
        )))
        .body(serde_json::json!({"settings": {"ratio": 0.4}}).to_string())
        .send()
        .await
        .unwrap();
        assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);
        let got: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            got["settings"]["ratio"], 0.4,
            "committed settings visible: {got}"
        );

        // NACK mode: the push is refused — nothing commits.
        ack_mode.store(false, std::sync::atomic::Ordering::Relaxed);
        let refused = admin(client.patch(format!(
            "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
        )))
        .body(serde_json::json!({"settings": {"ratio": 0.9}}).to_string())
        .send()
        .await
        .unwrap();
        assert_eq!(refused.status().as_u16(), 400, "nack = not committed");
        let still: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            still["settings"]["ratio"], 0.4,
            "old settings intact: {still}"
        );

        // Schema proxy (ack mode back on — the committed settings ride the configure preamble on
        // the fresh describe connection, and a nacking hook refuses connections by design).
        ack_mode.store(true, std::sync::atomic::Ordering::Relaxed);
        let schema: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook/schema")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        // The describe reply is the {schema, dashboard?} envelope; the engine EXTRACTS the schema
        // member, so the endpoint serves a SINGLE nest (the old double-wrap was audit W-H3).
        assert_eq!(
            schema["schema"]["properties"]["ratio"]["type"], "number",
            "describe schema extracted, single nest: {schema}"
        );

        serve.abort();
        hook_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `POST /api/v1/admin/config/apply`: a body-carried full config swaps in atomically — the new
    /// topology is live, the surviving identity keeps its tripped health, and a stale
    /// If-Match is a 409 that changes nothing.
    #[tokio::test]
    async fn test_admin_v1_config_apply_body_swaps_and_carries_health() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .governance(gov)
            .build();
        Arc::get_mut(&mut app)
            .expect("sole owner")
            .store
            .record_hard_down(0, "tripped before apply");
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| {
            req.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };

        let body = serde_json::json!({
            "providers": {
                "test-provider": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1/", "api_key_env": "BUSBAR_TEST_APPLY_NO_KEY"}
            },
            "config": {
                "listen": "127.0.0.1:0",
                "providers": {"test-provider": {"api_key_env": "BUSBAR_TEST_APPLY_NO_KEY"}},
                "models": {
                    "m0": {"provider": "test-provider", "max_concurrent": 4},
                    "m-applied": {"provider": "test-provider", "max_concurrent": 4}
                },
                "pools": {"apply-pool": {"members": [{"target": "m0"}, {"target": "m-applied"}]}}
            }
        });
        let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);

        let pool: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/pools/apply-pool")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let members = pool["members"].as_array().unwrap();
        let m0 = members.iter().find(|m| m["model"] == "m0").unwrap();
        let ma = members.iter().find(|m| m["model"] == "m-applied").unwrap();
        assert_eq!(m0["usable"], false, "carried trip: {m0}");
        assert_eq!(ma["usable"], true, "fresh lane: {ma}");

        // Stale If-Match: 409, nothing applied (H3: concurrency rides the header, never the body).
        let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
            .header("if-match", "\"0\"")
            .body(
                serde_json::json!({
                    "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status().as_u16(), 409);
        // A malformed If-Match is a 400 invalid_request, never a silent unguarded write.
        let malformed = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
            .header("if-match", "\"not-a-version\"")
            .body(
                serde_json::json!({
                    "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(malformed.status().as_u16(), 400);

        handle.abort();
    }

    /// `POST /api/v1/admin/config/reload`: re-reads disk truth and swaps it in atomically — the new
    /// topology is live, surviving lanes keep their learned health BY IDENTITY (a breaker tripped
    /// before the reload is still tripped after it), and an invalid disk config rejects with 400
    /// changing nothing.
    #[tokio::test]
    async fn test_admin_v1_config_reload_swaps_disk_truth_and_carries_health() {
        crate::metrics::init();
        let dir = std::env::temp_dir().join(format!("busbar-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let providers_path = dir.join("providers.yaml");
        let config_path = dir.join("config.yaml");
        std::fs::write(
            &providers_path,
            "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY
",
        )
        .unwrap();
        // Disk truth: the SAME identity as the running lane (m0 @ test-provider) plus a NEW model.
        std::fs::write(
            &config_path,
            "listen: 127.0.0.1:0
providers:
  test-provider:
    api_key_env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY
models:
  m0:
    provider: test-provider
    max_concurrent: 4
  m-new:
    provider: test-provider
    max_concurrent: 4
pools:
  reload-pool:
    members:
      - target: m0
      - target: m-new
",
        )
        .unwrap();

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .governance(gov)
            .build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.config_path = Some(config_path.clone());
            inner.providers_path = Some(providers_path.clone());
            // Trip m0's default-cell breaker hard so the carried state is unmistakable.
            inner.store.record_hard_down(0, "tripped before reload");
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

        // Reload: disk truth replaces the synthetic topology.
        let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);
        let models: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/models")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let names: Vec<&str> = models["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["model"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"m-new"),
            "the reloaded topology is live: {names:?}"
        );

        // The surviving identity (m0 @ test-provider) carried its tripped health state.
        let pool: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/pools/reload-pool")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let members = pool["members"].as_array().unwrap();
        let m0 = members
            .iter()
            .find(|m| m["model"] == "m0")
            .expect("m0 present");
        let m_new = members
            .iter()
            .find(|m| m["model"] == "m-new")
            .expect("m-new present");
        assert_eq!(
            m0["usable"], false,
            "m0's pre-reload trip must survive by identity: {m0}"
        );
        assert_eq!(
            m_new["usable"], true,
            "the new lane starts healthy: {m_new}"
        );

        // Invalid disk config: 400, nothing changes.
        std::fs::write(
            &config_path,
            "listen: 127.0.0.1:0
models:
  broken:
    provider: nope
    max_concurrent: 1
providers: {}
",
        )
        .unwrap();
        let before: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/info")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let bad = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status().as_u16(), 400, "invalid disk config rejects");
        let after: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/info")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            before["config_version"], after["config_version"],
            "a rejected reload changes nothing"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Per-principal mutation rate limits: the config class (apply/rollback) caps at 10/min per
    /// principal — the 11th attempt in the window is a 429 in the frozen envelope, and FAILED
    /// attempts count (these are all 404s — anti-enumeration).
    #[tokio::test]
    async fn test_admin_v1_mutation_rate_limit_config_class() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // 10 rollback attempts to a bogus version (all 404 — still spend budget), then the 11th
        // is limited. Tolerate landing exactly on a minute boundary (window refill mid-loop) by
        // accepting the 429 anywhere from attempt 11 to 22, but REQUIRE it eventually.
        let mut limited_at = None;
        for i in 1..=22 {
            let resp = client
                .post(format!("http://{addr}/api/v1/admin/config/rollback"))
                .header("x-admin-token", "admintok")
                .header("content-type", "application/json")
                .body(serde_json::json!({"version": 424242}).to_string())
                .send()
                .await
                .unwrap();
            match resp.status().as_u16() {
                404 => continue,
                429 => {
                    assert!(i >= 11, "the budget is 10/min; limited too early at {i}");
                    let body: serde_json::Value = resp.json().await.unwrap();
                    assert_eq!(body["error"]["code"], "rate_limited");
                    limited_at = Some(i);
                    break;
                }
                other => panic!("unexpected status {other} at attempt {i}"),
            }
        }
        assert!(
            limited_at.is_some(),
            "the limiter never fired in 22 attempts"
        );

        handle.abort();
    }

    /// The scope LADDER end-to-end with group-mapped NON-full principals (via the test-only
    /// external module): read-only reads but cannot mint (403, audited); hooks-register registers
    /// hooks but cannot mint keys; an unmapped group gets nothing at all (403 even on reads);
    /// the operator token stays full.
    #[tokio::test]
    async fn test_admin_v1_scope_ladder_e2e_with_group_mapped_principals() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new().governance(gov).build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
            inner.group_map.insert(
                "viewers".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("read-only".to_string()),
                    ..Default::default()
                },
            );
            inner.group_map.insert(
                "registrars".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("hooks-register".to_string()),
                    ..Default::default()
                },
            );
            // For the CAP proofs below: a group MAPPED full — the module ceiling must cut it
            // down — and a group mapped full that the allowlist doesn't authorize at all.
            inner.group_map.insert(
                "admins-capped".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("full".to_string()),
                    ..Default::default()
                },
            );
            inner.group_map.insert(
                "sneaky".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("full".to_string()),
                    ..Default::default()
                },
            );
            // §2.4 trust-boundary caps on the external module: it may only assert these groups
            // (`sneaky` is deliberately NOT pre-authorized), and nothing through it can exceed
            // hooks-register regardless of group_map.
            inner.auth_modules.insert(
                "test-scope-module".to_string(),
                crate::config::AuthModuleCfg {
                    allowed_groups: Some(vec![
                        "viewers".to_string(),
                        "registrars".to_string(),
                        "admins-capped".to_string(),
                        "strangers".to_string(),
                    ]),
                    max_admin_scope: Some("hooks-register".to_string()),
                },
            );
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let with = |tok: &'static str, req: reqwest::RequestBuilder| {
            req.header("x-admin-token", tok)
                .header("content-type", "application/json")
        };
        let hook_body = serde_json::json!({
            "name": "scoped-hook",
            "config": {"kind": "tap", "webhook": "http://127.0.0.1:9969/"}
        })
        .to_string();
        let key_body = serde_json::json!({"name": "k"}).to_string();

        // read-only: GET 200, mutations 403 with the frozen envelope.
        let r = with(
            "grp:viewers",
            client.get(format!("http://{addr}/api/v1/admin/info")),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 200, "read-only can read");
        let r = with(
            "grp:viewers",
            client.post(format!("http://{addr}/api/v1/admin/keys")),
        )
        .body(key_body.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 403, "read-only cannot mint");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "forbidden");
        let r = with(
            "grp:viewers",
            client.post(format!("http://{addr}/api/v1/admin/hooks")),
        )
        .body(hook_body.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 403, "read-only cannot register hooks");

        // hooks-register: hook lifecycle yes, keys no (the escalation guard).
        let r = with(
            "grp:registrars",
            client.post(format!("http://{addr}/api/v1/admin/hooks")),
        )
        .body(hook_body.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 201, "hooks-register registers hooks");
        let r = with(
            "grp:registrars",
            client.post(format!("http://{addr}/api/v1/admin/keys")),
        )
        .body(key_body.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 403, "hooks-register cannot mint keys");

        // Unmapped group: authenticated but zero grants — 403 even on reads.
        let r = with(
            "grp:strangers",
            client.get(format!("http://{addr}/api/v1/admin/info")),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 403, "unmapped groups grant nothing");

        // max_admin_scope CEILING: a group MAPPED full through the capped module lands at
        // hooks-register — it registers hooks but still cannot mint keys.
        let capped_hook = serde_json::json!({
            "name": "capped-hook",
            "config": {"kind": "tap", "webhook": "http://127.0.0.1:9969/"}
        })
        .to_string();
        let r = with(
            "grp:admins-capped",
            client.post(format!("http://{addr}/api/v1/admin/hooks")),
        )
        .body(capped_hook)
        .send()
        .await
        .unwrap();
        assert_eq!(
            r.status().as_u16(),
            201,
            "the ceiling still allows what it grants (hooks-register)"
        );
        let r = with(
            "grp:admins-capped",
            client.post(format!("http://{addr}/api/v1/admin/keys")),
        )
        .body(key_body.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(
            r.status().as_u16(),
            403,
            "group_map said full, the module ceiling says hooks-register — the ceiling wins"
        );

        // allowed_groups INTERSECTION: `sneaky` is mapped full in group_map but the module is not
        // authorized to assert it — the group is dropped BEFORE mapping, leaving zero grants.
        let r = with(
            "grp:sneaky",
            client.get(format!("http://{addr}/api/v1/admin/info")),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(
            r.status().as_u16(),
            403,
            "a group outside allowed_groups never reaches group_map"
        );

        // The operator token is still full (admin-tokens is exempt from module ceilings).
        let r = with(
            "admintok",
            client.post(format!("http://{addr}/api/v1/admin/keys")),
        )
        .body(key_body)
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 201, "operator token stays full");

        handle.abort();
    }

    /// §6.3 ESCALATION GUARD: a hooks-register principal may register a shape-only, non-global hook
    /// but NOT one wired into a security-critical path — a `prompt: rw`/`ro` content-seeing gate, a
    /// `user: ro` identity-seeing hook, or an inline `global: true` (chain wiring is full-only). The
    /// operator (full) may register all of them.
    #[tokio::test]
    async fn test_admin_v1_hooks_register_cannot_escalate_via_grants_or_global() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new().governance(gov).build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
            inner.group_map.insert(
                "registrars".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("hooks-register".to_string()),
                    ..Default::default()
                },
            );
            // The module ceiling defaults to read-only; lift it so registrars actually resolves to
            // hooks-register (admin-tokens stays full — it is ceiling-exempt).
            inner.auth_modules.insert(
                "test-scope-module".to_string(),
                crate::config::AuthModuleCfg {
                    allowed_groups: None,
                    max_admin_scope: Some("full".to_string()),
                },
            );
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let post = |tok: &'static str, cfg: serde_json::Value| {
            client
                .post(format!("http://{addr}/api/v1/admin/hooks"))
                .header("x-admin-token", tok)
                .header("content-type", "application/json")
                .body(serde_json::json!({"name": "h", "config": cfg}).to_string())
                .send()
        };
        let base = |extra: serde_json::Value| {
            let mut c = serde_json::json!({"kind": "gate", "webhook": "http://127.0.0.1:9969/"});
            for (k, v) in extra.as_object().unwrap() {
                c[k] = v.clone();
            }
            c
        };

        // hooks-register: each escalating form is 403 (forbidden), naming full.
        for (label, cfg) in [
            ("prompt: rw gate", base(serde_json::json!({"prompt": "rw"}))),
            ("prompt: ro gate", base(serde_json::json!({"prompt": "ro"}))),
            ("user: ro hook", base(serde_json::json!({"user": "ro"}))),
            ("global: true", base(serde_json::json!({"global": true}))),
        ] {
            let r = post("grp:registrars", cfg).await.unwrap();
            assert_eq!(
                r.status().as_u16(),
                403,
                "hooks-register must not register a {label}"
            );
            let body: serde_json::Value = r.json().await.unwrap();
            assert_eq!(body["error"]["code"], "forbidden", "{label}");
        }

        // hooks-register CAN register a shape-only, non-global hook.
        let r = post("grp:registrars", base(serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            201,
            "a shape-only, non-global hook is within hooks-register"
        );

        // The operator (full) can register a prompt: rw global gate (unique name — `h` is taken).
        let r = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "op-hook",
                    "config": base(serde_json::json!({"prompt": "rw", "global": true}))
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 201, "full scope registers anything");

        // REGRESSION (audit c1r6): a hooks-register token may not RETUNE (PATCH settings) a
        // content-seeing / global hook it can neither create nor replace — PATCH must enforce the
        // same §6.3 ceiling, keyed on the EXISTING hook's grants.
        let patch = client
            .patch(format!("http://{addr}/api/v1/admin/hooks/op-hook/settings"))
            .header("x-admin-token", "grp:registrars")
            .header("content-type", "application/json")
            .body(serde_json::json!({"settings": {"k": "v"}}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            patch.status().as_u16(),
            403,
            "hooks-register must not PATCH settings on a prompt:rw global hook"
        );
        assert_eq!(
            patch.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "forbidden"
        );

        // REGRESSION (audit c1r13): a hooks-register token may not DELETE a content-seeing / global
        // gate a full admin installed — tearing down that security gate is the same §6.3 escalation
        // register/put/patch forbid.
        let del = client
            .delete(format!("http://{addr}/api/v1/admin/hooks/op-hook"))
            .header("x-admin-token", "grp:registrars")
            .send()
            .await
            .unwrap();
        assert_eq!(
            del.status().as_u16(),
            403,
            "hooks-register must not DELETE a prompt:rw global hook"
        );
        assert_eq!(
            del.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "forbidden"
        );
        // And the operator's gate is still there — the rejected delete did not remove it.
        let still = client
            .get(format!("http://{addr}/api/v1/admin/hooks/op-hook"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            still.status().as_u16(),
            200,
            "the gate survives the rejected delete"
        );

        handle.abort();
    }

    /// The idempotency cache is SCOPED TO THE PRINCIPAL: a second admin presenting the same
    /// Idempotency-Key value must mint its OWN key, never replay the first principal's response
    /// (which carries a once-shown secret). Two full principals, same key value, distinct results.
    #[tokio::test]
    async fn test_admin_v1_idempotency_key_is_principal_scoped() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new().governance(gov).build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
            // A group mapped FULL so the second principal can also mint keys.
            inner.group_map.insert(
                "admins".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("full".to_string()),
                    ..Default::default()
                },
            );
            inner.auth_modules.insert(
                "test-scope-module".to_string(),
                crate::config::AuthModuleCfg {
                    allowed_groups: None,
                    max_admin_scope: Some("full".to_string()),
                },
            );
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let mint = |tok: &'static str| {
            client
                .post(format!("http://{addr}/api/v1/admin/keys"))
                .header("x-admin-token", tok)
                .header("content-type", "application/json")
                .header("idempotency-key", "shared-value")
                .body(serde_json::json!({"name": "k"}).to_string())
                .send()
        };

        // Principal A (operator) mints under the shared key.
        let a: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
        // Principal B (a different full principal) mints under the SAME key value.
        let b: serde_json::Value = mint("grp:admins").await.unwrap().json().await.unwrap();

        assert!(a["id"].is_string() && b["id"].is_string());
        assert_ne!(
            a["id"], b["id"],
            "a second principal's identical Idempotency-Key must mint a NEW key, not replay A's"
        );
        assert_ne!(
            a["secret"], b["secret"],
            "B must never receive A's once-shown secret via a cross-principal replay"
        );
        // And A replaying its OWN key still returns A's response (per-principal idempotency intact).
        let a2: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
        assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

        handle.abort();
    }

    /// The credential cache end-to-end (§2.5): an external-module identify is CACHED (the second
    /// request is served from the cache — observable via the flush count), `POST
    /// /api/v1/admin/auth/cache/flush` drops it (full scope; read-only principals get 403), and the
    /// built-in operator token is NEVER cached (flush finds nothing after operator calls).
    #[tokio::test]
    async fn test_admin_v1_credential_cache_and_flush_endpoint() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new().governance(gov).build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
            inner.group_map.insert(
                "viewers".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("read-only".to_string()),
                    ..Default::default()
                },
            );
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Two reads as a group-mapped principal: the module's Identify lands in the cache.
        for _ in 0..2 {
            let r = client
                .get(format!("http://{addr}/api/v1/admin/info"))
                .header("x-admin-token", "grp:viewers")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 200);
        }

        // A read-only principal cannot flush (full-scope mutation).
        let r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", "grp:viewers")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");

        // Operator flushes the module partition: exactly ONE entry (the cached viewers identify;
        // operator-token authentications are never cached).
        let r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"module": "test-scope-module"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        // TWO entries in the module's partition: the viewers Identify, plus the PASS the module
        // returned for the operator token (Pass IS cached, short-TTL — §2.5; only the built-in
        // admin-tokens module's own verdicts are exempt). The flushing request's own Pass was
        // inserted by its chain run before the handler flushed.
        assert_eq!(
            body["flushed"], 2,
            "the viewers Identify + the operator credential's cached Pass"
        );

        // Flush-all with an empty body: nothing left.
        let r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = r.json().await.unwrap();
        // Exactly ONE: this very request's chain run re-cached a Pass for the operator credential
        // under the external module before the handler flushed. Nothing else survived.
        assert_eq!(
            body["flushed"], 1,
            "only this request's own cached Pass remained"
        );

        // Malformed body: invalid_request.
        let r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body("{\"module\": 7}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400);

        handle.abort();
    }

    /// `PUT /api/v1/admin/admin-auth` end-to-end with the D4 dry-run guard: a chain that would lock the
    /// CALLER out is a 409 and nothing changes; a chain the caller survives applies atomically
    /// (the old credential stops working on the very next request, the surviving one carries on);
    /// unknown modules and a stale If-Match reject.
    #[tokio::test]
    async fn test_admin_v1_put_auth_dry_run_guard() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let mut app = TestApp::new().governance(gov).build();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            // Chain starts as BOTH modules (so both credentials work); group_map + an explicit
            // full ceiling make `grp:admins` a full principal through the external stand-in.
            inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
            inner.group_map.insert(
                "admins".to_string(),
                crate::config::GroupMapEntry {
                    admin_scope: Some("full".to_string()),
                    ..Default::default()
                },
            );
            inner.auth_modules.insert(
                "test-scope-module".to_string(),
                crate::config::AuthModuleCfg {
                    allowed_groups: None,
                    max_admin_scope: Some("full".to_string()),
                },
            );
        }
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let put = |tok: &'static str, body: serde_json::Value| {
            client
                .put(format!("http://{addr}/api/v1/admin/admin-auth"))
                .header("x-admin-token", tok)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
        };

        // Unknown module: 400, nothing changes.
        let r = put("admintok", serde_json::json!({"admin_auth": ["saml"]}))
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            400,
            "unknown module is invalid_request"
        );

        // Stale If-Match: 409 (H3: concurrency rides the header; a body-level twin no longer parses
        // — deny_unknown_fields makes a leftover `expected_version` field a loud 400, not a no-op).
        let r = client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("if-match", "\"999\"")
            .body(serde_json::json!({"admin_auth": ["admin-tokens"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 409, "stale If-Match conflicts");

        // THE D4 GUARD: the operator token would NOT survive a chain of only the external module
        // (its credential has no grp: shape — all-Pass denies). 409, and the operator still works.
        let r = put(
            "admintok",
            serde_json::json!({"admin_auth": ["test-scope-module"]}),
        )
        .await
        .unwrap();
        assert_eq!(
            r.status().as_u16(),
            409,
            "a chain that locks the caller out is refused"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "conflict");
        let r = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "nothing changed on the refusal");

        // The SAME change made by a caller who survives it (a full group-mapped principal through
        // the external module) applies…
        let r = put(
            "grp:admins",
            serde_json::json!({"admin_auth": ["test-scope-module"]}),
        )
        .await
        .unwrap();
        assert_eq!(
            r.status().as_u16(),
            200,
            "the surviving caller's change applies"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["applied"], true);

        // …after which the operator token no longer authenticates (it is not in the chain)…
        let r = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            401,
            "the dropped module's credential stops working immediately"
        );

        // …and the surviving credential carries on.
        let r = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "grp:admins")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);

        // READ-AFTER-WRITE (L3): GET /api/v1/admin/admin-auth reflects exactly what the PUT installed —
        // the write and read now name the SAME resource (previously PUT lived on /auth and GET
        // admin-auth reported a hard-coded module, so they could never agree).
        let body: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "grp:admins")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["configured"], true);
        assert_eq!(
            body["modules"],
            serde_json::json!(["test-scope-module"]),
            "GET admin-auth mirrors the PUT'd chain verbatim"
        );

        handle.abort();
    }

    /// Idempotent mint + optimistic concurrency: a retried POST with the same Idempotency-Key
    /// returns the FIRST response (same id + secret, no double-create); a PATCH with a stale
    /// If-Match is a 409 that changes nothing; a fresh If-Match succeeds.
    #[tokio::test]
    async fn test_admin_v1_key_idempotent_mint_and_if_match() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| {
            req.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };

        // Same Idempotency-Key twice → identical response, ONE key.
        let mint = |k: &'static str| {
            admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
                .header("idempotency-key", k)
                .body(serde_json::json!({"name": "idem"}).to_string())
                .send()
        };
        let a: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
        let b: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
        assert_eq!(a["id"], b["id"], "replay returns the same key");
        assert_eq!(
            a["secret"], b["secret"],
            "replay returns the FIRST response verbatim"
        );
        let listed: serde_json::Value = admin(client.get(format!(
            "http://{addr}/api/v1/admin/keys?prefix={}",
            a["id"].as_str().unwrap()
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(
            listed["items"].as_array().unwrap().len(),
            1,
            "no double-create: {listed}"
        );

        // If-Match: stale = 409 untouched; current etag = applied.
        let id = a["id"].as_str().unwrap();
        let got = admin(client.get(format!("http://{addr}/api/v1/admin/keys/{id}")))
            .send()
            .await
            .unwrap();
        // ETag is header-only now (H4) — strip the surrounding quotes to feed back as If-Match.
        let etag = got
            .headers()
            .get(axum::http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .trim_matches('"')
            .to_string();
        let stale = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
            .header("if-match", "\"deadbeefdeadbeef\"")
            .body(serde_json::json!({"rpm_limit": 5}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");
        let fresh = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
            .header("if-match", format!("\"{etag}\""))
            .body(serde_json::json!({"rpm_limit": 5}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");

        handle.abort();
    }

    /// The idempotency RESERVATION frees itself on a FAILED mint: a POST that reserves an
    /// Idempotency-Key then fails validation must NOT leave a stuck in-flight sentinel — a
    /// subsequent valid retry under the SAME key mints normally (not a spurious 409/replay).
    #[tokio::test]
    async fn test_admin_v1_idempotency_reservation_frees_on_failure() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let post = |body: &'static str| {
            client
                .post(format!("http://{addr}/api/v1/admin/keys"))
                .header("x-admin-token", "admintok")
                .header("content-type", "application/json")
                .header("idempotency-key", "reuse-key")
                .body(body)
                .send()
        };

        // Reserve the key, then fail validation (unknown budget_period).
        let bad = post(r#"{"name": "x", "budget_period": "fortnightly"}"#)
            .await
            .unwrap();
        assert_eq!(bad.status().as_u16(), 400, "invalid body is a 400");

        // The SAME key now mints normally — the reservation was cleared, not stuck in-flight.
        let good = post(r#"{"name": "x"}"#).await.unwrap();
        assert_eq!(
            good.status().as_u16(),
            201,
            "a valid retry under the same key mints (reservation freed on the prior failure)"
        );

        handle.abort();
    }

    /// Key ROTATION: the new secret works, the old stops resolving, the id + settings are
    /// unchanged; unknown ids 404. And keys pagination: limit/offset over the id-sorted set with a
    /// stable total.
    #[tokio::test]
    async fn test_admin_v1_key_rotate_and_pagination() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov.clone()).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| {
            req.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };

        // Mint three keys.
        let mut ids = Vec::new();
        for n in ["ka", "kb", "kc"] {
            let created: serde_json::Value =
                admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
                    .body(serde_json::json!({"name": n}).to_string())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
            ids.push((
                created["id"].as_str().unwrap().to_string(),
                created["secret"].as_str().unwrap().to_string(),
            ));
        }

        // Pagination (cursor envelope): page 1 with ?limit=2 yields 2 items + a next_cursor; feeding
        // that opaque cursor back yields the final item with next_cursor=null. Covers all three once.
        let p1: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/keys?limit=2")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(p1["items"].as_array().unwrap().len(), 2);
        let cursor = p1["next_cursor"]
            .as_str()
            .expect("more rows remain -> a next_cursor is present");
        let p2: serde_json::Value = admin(client.get(format!(
            "http://{addr}/api/v1/admin/keys?limit=2&cursor={cursor}"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(p2["items"].as_array().unwrap().len(), 1);
        assert!(
            p2["next_cursor"].is_null(),
            "last page has no next_cursor: {p2}"
        );
        let mut seen: Vec<String> = p1["items"]
            .as_array()
            .unwrap()
            .iter()
            .chain(p2["items"].as_array().unwrap())
            .map(|k| k["id"].as_str().unwrap().to_string())
            .collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3, "pages cover every key exactly once");

        // A malformed/foreign cursor is a 400 invalid_request (never a silent skip).
        let bad = admin(client.get(format!("http://{addr}/api/v1/admin/keys?cursor=notacursor")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            bad.status().as_u16(),
            400,
            "foreign cursor is invalid_request"
        );
        assert_eq!(
            bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );

        // Rotate the first key: same id, new secret; old secret dead, new secret resolves.
        let (id, old_secret) = ids[0].clone();
        let rotated: serde_json::Value =
            admin(client.post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(rotated["id"], id.as_str(), "id is stable across rotation");
        let new_secret = rotated["secret"].as_str().unwrap().to_string();
        assert_ne!(new_secret, old_secret);
        assert!(gov.lookup(&new_secret).is_some(), "new secret resolves");
        assert!(
            gov.lookup(&old_secret).is_none(),
            "old secret stops resolving immediately"
        );

        // Unknown id → 404.
        let missing = admin(client.post(format!("http://{addr}/api/v1/admin/keys/vk_nope/rotate")))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);

        handle.abort();
    }

    /// `PUT /api/v1/admin/hooks/{name}`: replaces an overlay hook live; 404 for an unknown name;
    /// 409 for a grant change (immutability) and for a stale If-Match.
    #[tokio::test]
    async fn test_admin_v1_put_hook_replaces_live_with_guards() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| {
            req.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };

        // PUT on an unknown name is 404 (PUT replaces; POST creates).
        let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
            .body(
                serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:1/"}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);

        // Create, then replace with a new transport target (same grants) — 200, live.
        let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
            .body(
                serde_json::json!({
                    "name": "rep",
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9971/"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);
        let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .body(
                serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:9972/"}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(replaced.status().as_u16(), 200);
        let got: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert!(
            got["transport"].to_string().contains("9972"),
            "the replacement is live: {got}"
        );

        // Grant change via PUT is a 409 (immutability holds on the replace path too).
        let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .body(serde_json::json!({"config": {"kind": "gate", "webhook": "http://127.0.0.1:9972/", "prompt": "rw"}}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

        // Stale If-Match is a 409 conflict (H3: concurrency rides the header).
        let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .header("if-match", "\"0\"")
            .body(
                serde_json::json!({
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9973/"},
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

        // The current ETag (from the GET above / the PUT response) applies cleanly: read it live.
        let live = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .send()
            .await
            .unwrap();
        let etag = live
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .expect("config-plane reads emit the ETag")
            .to_string();
        let fresh = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .header("if-match", etag)
            .body(
                serde_json::json!({
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9973/"},
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");
        assert!(
            fresh.headers().get(reqwest::header::ETAG).is_some(),
            "the mutation response carries the NEW ETag for chaining"
        );

        handle.abort();
    }

    /// The config version-history cycle: mutations record attributed versions; diff explains a
    /// change; rollback restores a prior hook surface LIVE as a NEW version; unknown targets 404
    /// and a stale If-Match conflicts.
    #[tokio::test]
    async fn test_admin_v1_config_versions_rollback_and_diff() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

        // v1: register a hook. v2: delete it. (Boot floor is v0.)
        let body = serde_json::json!({
            "name": "rbk",
            "config": {"kind": "tap", "webhook": "http://127.0.0.1:9979/"}
        });
        let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);
        let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/rbk")))
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status().as_u16(), 204);

        // The history lists boot + register + delete, newest first, attributed.
        let versions: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let list = versions["items"].as_array().unwrap();
        assert_eq!(list.len(), 3, "boot + register + delete: {versions}");
        assert_eq!(list[0]["version"], 2);
        assert!(list[0]["summary"]
            .as_str()
            .unwrap()
            .contains("hook.delete hook:rbk"));
        assert_eq!(list[0]["principal"], "admin");

        // Diff v1 -> v2: the hook was removed.
        let diff: serde_json::Value = admin(client.get(format!(
            "http://{addr}/api/v1/admin/config/diff?from=1&to=2"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(diff["hooks"]["removed"][0], "rbk", "{diff}");

        // Rollback to v1 restores the hook, LIVE, as a NEW version (append-only history).
        let rb = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
            .header("content-type", "application/json")
            .body(serde_json::json!({"version": 1}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(rb.status().as_u16(), 200);
        let rb_body: serde_json::Value = rb.json().await.unwrap();
        assert_eq!(rb_body["restored_version"], 1);
        assert_eq!(rb_body["config_version"], 3); // the post-rollback version, under the uniform name
        let restored = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rbk")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            restored.status().as_u16(),
            200,
            "the rolled-back hook is live again"
        );

        // Guard rails: unknown target = 404; stale If-Match = 409 (H3).
        let missing = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
            .header("content-type", "application/json")
            .body(serde_json::json!({"version": 999}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);
        let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
            .header("content-type", "application/json")
            .header("if-match", "\"0\"")
            .body(serde_json::json!({"version": 1}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status().as_u16(), 409);

        handle.abort();
    }

    #[tokio::test]
    async fn test_admin_v1_register_hook_takes_effect_live() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Before: no hooks.
        let before: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(before["items"].as_array().unwrap().len(), 0);

        // Register a global gate at runtime.
        let body = serde_json::json!({
            "name": "compress",
            "config": {
                "kind": "gate",
                "webhook": "http://127.0.0.1:9977/",
                "prompt": "rw",
                "global": true
            }
        });
        let created = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201, "hook registered");
        let created_body: serde_json::Value = created.json().await.unwrap();
        assert_eq!(created_body["name"], "compress");
        assert_eq!(created_body["kind"], "gate");
        assert_eq!(created_body["global"], true);

        // After: the hook is LIVE — a fresh read sees it (swap took effect + reads-current).
        let after: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let items = after["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "the registered hook is now in the live config"
        );
        assert_eq!(items[0]["name"], "compress");

        // The config version bumped from 0 → 1 on the apply (drift-detection primitive).
        let info: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            info["config_version"], 1,
            "one apply bumped the config version"
        );

        // GET one by name also sees it.
        let one = client
            .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(one.status().as_u16(), 200);

        // A RESERVED name (an on_error terminal / built-in) rejects on the register path too —
        // previously only boot validation checked this, so a runtime hook named `reject` could
        // shadow the terminal and make every consumer's on_error parse ambiguous (audit #8).
        for reserved in ["reject", "weighted", "nothing", "cheapest", "admin-tokens"] {
            let shadow = client
                .post(format!("http://{addr}/api/v1/admin/hooks"))
                .header("x-admin-token", "admintok")
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "name": reserved,
                        "config": {"kind": "gate", "webhook": "http://127.0.0.1:9977/"}
                    })
                    .to_string(),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(
                shadow.status().as_u16(),
                400,
                "hook name `{reserved}` is reserved and must reject"
            );
            assert_eq!(
                shadow.json::<serde_json::Value>().await.unwrap()["error"]["code"],
                "invalid_request"
            );
        }

        // Invalid definition (prompt:rw on a tap) → 400 invalid_request, no mutation.
        let bad = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "bad",
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9977/", "prompt": "rw"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status().as_u16(), 400);
        assert_eq!(
            bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );

        // Grant immutability over the wire (§6.4): re-registering "compress" (a prompt:rw gate) with a
        // DIFFERENT grant (prompt:ro) → 409 conflict, no mutation. Same grants would be idempotent.
        let escalate = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "compress",
                    "config": {"kind": "gate", "webhook": "http://127.0.0.1:9977/", "prompt": "ro"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            escalate.status().as_u16(),
            409,
            "grant change must conflict"
        );
        assert_eq!(
            escalate.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "conflict"
        );

        handle.abort();
    }

    /// `GET /api/v1/admin/audit` records admin mutations: registering a hook appears in the audit log as
    /// `hook.register` / `applied`, with the resource named. (The audit ring is process-global, so
    /// other concurrent tests may add entries — assert the specific action appears, not an exact count.)
    #[tokio::test]
    async fn test_admin_v1_audit_records_mutations() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // A uniquely-named hook so the audit assertion can't collide with a concurrent test.
        let name = "audit_probe_hook_x7";
        client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": name,
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9979/", "global": true}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();

        let audit: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/audit"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let entries = audit["items"].as_array().unwrap();
        let mine = entries
            .iter()
            .find(|e| e["resource"] == format!("hook:{name}"))
            .expect("the registration is recorded in the audit log");
        assert_eq!(mine["action"], "hook.register");
        assert_eq!(mine["outcome"], "applied");
        assert!(mine["seq"].is_number() && mine["ts"].is_number());

        // Filter by resource (§2.5): only this hook's entries come back.
        let filtered: serde_json::Value = client
            .get(format!(
                "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let f = filtered["items"].as_array().unwrap();
        assert!(!f.is_empty());
        assert!(
            f.iter().all(|e| e["resource"] == format!("hook:{name}")),
            "the resource filter returns only matching entries"
        );

        // Filter by a non-matching action → empty.
        let none: serde_json::Value = client
            .get(format!(
                "http://{addr}/api/v1/admin/audit?resource=hook:{name}&action=key.create"
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(none["items"].as_array().unwrap().len(), 0);

        handle.abort();
    }

    /// REGRESSION (audit c1r9): the UNKNOWN-NAME 404 on `PUT /hooks/{name}` and
    /// `PATCH /hooks/{name}/settings` must be AUDITED (like DELETE's 404) — an unaudited 404 lets a
    /// principal probe which hook names exist by response code alone, with no trail.
    #[tokio::test]
    async fn test_admin_v1_hook_mutation_404_is_audited() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Two uniquely-named, NEVER-registered hooks so the audit assertions can't collide.
        let put_name = "ghost_put_hook_q3";
        let patch_name = "ghost_patch_hook_q3";

        let put_resp = client
            .put(format!("http://{addr}/api/v1/admin/hooks/{put_name}"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:9978/"}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(put_resp.status(), 404, "PUT on an unknown hook is a 404");

        let patch_resp = client
            .patch(format!(
                "http://{addr}/api/v1/admin/hooks/{patch_name}/settings"
            ))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"settings": {"k": "v"}}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            patch_resp.status(),
            404,
            "PATCH on an unknown hook is a 404"
        );

        // Both 404s must appear in the audit log as REJECTED, resource-named.
        for (name, action) in [(put_name, "hook.replace"), (patch_name, "hook.settings")] {
            let filtered: serde_json::Value = client
                .get(format!(
                    "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
                ))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let entry = filtered["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["resource"] == format!("hook:{name}"))
                .unwrap_or_else(|| panic!("the {action} 404 must be recorded in the audit log"));
            assert_eq!(entry["action"], action);
            assert_eq!(
                entry["outcome"], "rejected",
                "the unknown-name 404 is a rejected mutation, audited"
            );
        }

        handle.abort();
    }

    /// `GET /api/v1/admin/keys` supports `?prefix=` and `?enabled=` filters (§2.1): a full-id prefix
    /// returns just that key; a non-matching prefix returns none; `?enabled=true` includes a fresh key.
    #[tokio::test]
    async fn test_admin_v1_list_keys_filters() {
        use crate::governance::NewKeySpec;
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let (minted, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "filter-probe".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                crate::store::now(),
            )
            .unwrap();
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let get = |query: String| {
            let url = format!("http://{addr}/api/v1/admin/keys{query}");
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

        // Prefix = the full id → exactly this key.
        let by_prefix = get(format!("?prefix={}", minted.id)).await;
        let keys = by_prefix["items"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["id"], minted.id);

        // Non-matching prefix → none.
        let none = get("?prefix=vk_does_not_exist".into()).await;
        assert_eq!(none["items"].as_array().unwrap().len(), 0);

        // enabled=true includes the fresh (enabled) key.
        let enabled = get("?enabled=true".into()).await;
        assert!(enabled["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["id"] == minted.id));

        handle.abort();
    }

    /// GOLDEN PATH: the whole config plane working together in one flow — register → live + version
    /// bump + audit + persist → delete → gone + version bump + audit. A coherent-flow regression anchor
    /// for the marquee feature (catches integration breaks the per-feature tests miss).
    #[tokio::test]
    async fn test_admin_v1_config_plane_golden_path() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("t".to_string())).unwrap());
        let overlay = std::env::temp_dir().join(format!(
            "busbar-golden-{}-{}.json",
            std::process::id(),
            crate::store::now()
        ));
        let _ = std::fs::remove_file(&overlay);
        let app = TestApp::new()
            .governance(gov)
            .overlay_path(overlay.clone())
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let c = reqwest::Client::new();
        let base = format!("http://{addr}");
        let get = |p: String| {
            let (c, url) = (c.clone(), format!("{base}{p}"));
            async move {
                c.get(url)
                    .header("x-admin-token", "t")
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };
        let name = "golden_gate";

        // Baseline: no hooks, version 0, persistence on.
        assert_eq!(
            get("/api/v1/admin/hooks".into()).await["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let info0 = get("/api/v1/admin/info".into()).await;
        assert_eq!(info0["config_version"], 0);
        assert_eq!(info0["config_persistence"], true);

        // Register.
        let created = c
            .post(format!("{base}/api/v1/admin/hooks"))
            .header("x-admin-token", "t")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({"name": name, "config":
                    {"kind": "gate", "webhook": "http://127.0.0.1:9982/", "global": true}})
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);

        // Live (read sees it), version bumped, persisted to disk.
        assert!(get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == name));
        assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 1);
        assert_eq!(get("/api/v1/admin/config".into()).await["version"], 1);
        assert!(crate::config::overlay::read(&overlay)
            .unwrap()
            .hooks
            .contains_key(name));
        // Audit records it.
        assert!(
            get(format!("/api/v1/admin/audit?resource=hook:{name}")).await["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "hook.register" && e["outcome"] == "applied")
        );

        // Delete.
        let deleted = c
            .delete(format!("{base}/api/v1/admin/hooks/{name}"))
            .header("x-admin-token", "t")
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status().as_u16(), 204);

        // Gone, version bumped again, persisted removal.
        assert_eq!(
            get("/api/v1/admin/hooks".into()).await["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 2);
        assert!(!crate::config::overlay::read(&overlay)
            .unwrap()
            .hooks
            .contains_key(name));

        let _ = std::fs::remove_file(&overlay);
        handle.abort();
    }

    /// Config-overlay PERSISTENCE: with an overlay path set, registering a hook over the API writes it
    /// to the overlay file, and merging that overlay onto a fresh base config (a "restart") restores
    /// the hook — so a runtime-registered hook survives a restart.
    #[tokio::test]
    async fn test_admin_v1_hook_register_persists_to_overlay() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let overlay = std::env::temp_dir().join(format!(
            "busbar-persist-test-{}-{}.json",
            std::process::id(),
            crate::store::now()
        ));
        let _ = std::fs::remove_file(&overlay);
        let app = TestApp::new()
            .governance(gov)
            .overlay_path(overlay.clone())
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Register a global gate — the handler persists it to the overlay file.
        let created = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "persisted_gate",
                    "config": {"kind": "gate", "webhook": "http://127.0.0.1:9981/", "global": true}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);

        // The overlay file now holds the hook.
        let doc = crate::config::overlay::read(&overlay).expect("overlay written");
        assert!(doc.hooks.contains_key("persisted_gate"));
        assert!(doc.global_hooks.iter().any(|g| g == "persisted_gate"));

        // "Restart": merge the overlay onto a fresh base config → the hook is restored.
        let mut fresh: crate::config::DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        crate::config::overlay::merge_into(&mut fresh, doc);
        assert!(
            fresh.hooks.contains_key("persisted_gate"),
            "the runtime-registered hook survives a restart via the overlay"
        );

        let _ = std::fs::remove_file(&overlay);
        handle.abort();
    }

    /// Key mutations are audited too (§6.7 — EVERY admin mutation): minting a key records
    /// `key.create` / `applied` with the new key's id.
    #[tokio::test]
    async fn test_admin_v1_audit_records_key_mutations() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // Mint a uniquely-named key.
        let minted: serde_json::Value = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"name": "audit_key_probe_z3"}).to_string())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = minted["id"].as_str().unwrap().to_string();

        let audit: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/audit"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let mine = audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["resource"] == format!("key:{id}"))
            .expect("the key creation is recorded in the audit log");
        assert_eq!(mine["action"], "key.create");
        assert_eq!(mine["outcome"], "applied");

        handle.abort();
    }

    /// REGRESSION (audit c1r5): base-config hooks are READ-ONLY across every mutation verb — a
    /// narrow hooks-register token must not be able to shadow/redirect (POST) or remove (DELETE) an
    /// operator's file-defined hook (e.g. a `pii-guard` gate). PUT/PATCH already guarded; this pins
    /// POST + DELETE to the same 409, matching the guard other verbs enforce.
    #[tokio::test]
    async fn test_admin_v1_base_hook_is_read_only_via_api() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let base: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
            "kind": "gate", "webhook": "http://127.0.0.1:9990/", "prompt": "no", "global": true
        }))
        .unwrap();
        let app = TestApp::new()
            .governance(gov)
            .base_hook("pii-guard", base)
            .build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // POST a same-shape definition over the base hook's name → 409 (no silent transport redirect).
        let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "pii-guard",
                    "config": {"kind": "gate", "webhook": "http://127.0.0.1:6666/", "prompt": "no", "global": true}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            shadow.status().as_u16(),
            409,
            "POST cannot shadow a base hook"
        );

        // DELETE the base hook → 409 (cannot remove an operator's base security gate via the API).
        let del = client
            .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            del.status().as_u16(),
            409,
            "DELETE cannot remove a base hook"
        );

        // It is still present and unchanged.
        let got: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            got["transport"].to_string().contains("9990"),
            "base hook untouched: {got}"
        );
    }

    /// `DELETE /api/v1/admin/hooks/{name}` removes a hook at runtime (live): register → delete (204) →
    /// GET /hooks/{name} 404. Deleting an unregistered hook is 404.
    #[tokio::test]
    async fn test_admin_v1_delete_hook_takes_effect_live() {
        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let tok = ("x-admin-token", "admintok");

        // Register a global tap.
        let created = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header(tok.0, tok.1)
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "logger",
                    "config": {"kind": "tap", "webhook": "http://127.0.0.1:9978/", "global": true}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201);

        // Delete an absent hook → 404.
        let absent = client
            .delete(format!("http://{addr}/api/v1/admin/hooks/nope"))
            .header(tok.0, tok.1)
            .send()
            .await
            .unwrap();
        assert_eq!(absent.status().as_u16(), 404);

        // Delete the registered hook → 204, and it's gone live.
        let deleted = client
            .delete(format!("http://{addr}/api/v1/admin/hooks/logger"))
            .header(tok.0, tok.1)
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status().as_u16(), 204);

        let after = client
            .get(format!("http://{addr}/api/v1/admin/hooks/logger"))
            .header(tok.0, tok.1)
            .send()
            .await
            .unwrap();
        assert_eq!(
            after.status().as_u16(),
            404,
            "the hook is gone from the live config"
        );

        handle.abort();
    }

    /// The hooks read surface (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`) projects the
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
            on_error: "reject".to_string(),
            prompt: crate::config::PromptAccess::Rw,
            user: crate::config::UserAccess::Ro,
            priority: 7,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global: false,
            default: false,
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
            .get(format!("http://{addr}/api/v1/admin/hooks"))
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
            .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(one.status().as_u16(), 200);

        // Unknown name → 404 with the stable v1 `not_found` code.
        let missing = client
            .get(format!("http://{addr}/api/v1/admin/hooks/nope"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);
        let body: serde_json::Value = missing.json().await.unwrap();
        assert_eq!(body["error"]["code"], "not_found");

        handle.abort();
    }

    /// `GET /api/v1/admin/hooks/{name}/health` best-effort probes a hook's transport: 404 for an unknown
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
            on_error: "weighted".to_string(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global: false,
            default: false,
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
            let url = format!("http://{addr}/api/v1/admin/hooks/{name}/health");
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

    /// The plugin catalog (`GET /api/v1/admin/plugins?type=`) lists compiled-in plugins per type (the
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
            on_error: "weighted".to_string(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global: false,
            default: false,
        };
        let app = TestApp::new().governance(gov).hook("myhook", gate).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        let get = |q: &str| {
            let url = format!("http://{addr}/api/v1/admin/plugins?type={q}");
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

    /// `GET /api/v1/admin/auth` reports the ingress chain + upstream-credential mode, never a secret. A
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
            .get(format!("http://{addr}/api/v1/admin/auth"))
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

    /// `POST /api/v1/admin/config/validate` dry-runs a proposed config: a malformed body is a 400
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
        let url = format!("http://{addr}/api/v1/admin/config/validate");

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

    /// `GET /api/v1/admin/config` composes the effective-config snapshot (auth + pools/models/providers +
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
            on_error: "weighted".to_string(),
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            priority: 0,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global: false,
            default: false,
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
            .get(format!("http://{addr}/api/v1/admin/config"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        // Composed sections present.
        assert_eq!(body["version"], 0, "fresh config is version 0");
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

    /// `GET /api/v1/admin/openapi.json` returns a valid OpenAPI 3.1 doc, and — the DRIFT GUARD — every GET
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
            .get(format!("http://{addr}/api/v1/admin/openapi.json"))
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

        // The runtime hook mutation methods are documented in the discovery contract.
        assert!(
            doc["paths"]["/api/v1/admin/hooks"]["post"].is_object(),
            "POST /api/v1/admin/hooks (register) must be in the openapi doc"
        );
        assert!(
            doc["paths"]["/api/v1/admin/hooks/{name}"]["delete"].is_object(),
            "DELETE /api/v1/admin/hooks/{{name}} (remove) must be in the openapi doc"
        );

        // DRIFT GUARD: every documented GET path is both listed in the doc AND actually mounted.
        // V1_GET_PATHS entries are RELATIVE; the wire path derives from the contract prefix (whose
        // literal value is pinned by its own golden test in contract.rs).
        for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
            let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
            assert!(
                doc["paths"][&path]["get"].is_object(),
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

    /// SECURITY CONTRACT: every documented `/api/v1/admin` GET endpoint rejects a MISSING token and a
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

        for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
            let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
            // No token → 401, in the FROZEN v1 envelope (code `unauthorized`) — the most frequent
            // error a tooling consumer hits must branch on the same code seam as every other
            // (3rd-party audit #9; previously a protocol-shaped body).
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
            let body: serde_json::Value = none.json().await.unwrap();
            assert_eq!(
                body["error"]["code"], "unauthorized",
                "{path}: the admin 401 speaks the v1 envelope: {body}"
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
            .post(format!("http://{addr}/api/v1/admin/keys"))
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
            .post(format!("http://{addr}/api/v1/admin/keys"))
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
            .get(format!("http://{addr}/api/v1/admin/keys"))
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
        for k in listed["items"].as_array().unwrap() {
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
            .post(format!("http://{addr}/api/v1/admin/keys"))
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
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status().as_u16(), 200);
        let lb: serde_json::Value = listed.json().await.unwrap();
        assert_eq!(lb["items"].as_array().unwrap().len(), 1);
        assert!(
            lb["items"][0]["secret"].is_null(),
            "list must not leak secrets"
        );

        // usage — an UNCAPPED key reports `rate_headroom: null` (nothing to be near).
        let usage = client
            .get(format!("http://{addr}/api/v1/admin/keys/{id}/usage"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(usage.status().as_u16(), 200);
        let ub: serde_json::Value = usage.json().await.unwrap();
        assert_eq!(ub["id"], id);
        assert!(
            ub["rate_headroom"].is_null(),
            "uncapped key has no headroom signal: {ub}"
        );

        // A rate-CAPPED key reports its headroom fraction (a fresh window = fully available, 1.0),
        // so a client can back off BEFORE tripping a 429 (key-06).
        let capped: serde_json::Value = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k-capped", "rpm_limit": 10}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let capped_id = capped["id"].as_str().unwrap();
        let ub: serde_json::Value = client
            .get(format!("http://{addr}/api/v1/admin/keys/{capped_id}/usage"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            ub["rate_headroom"], 1.0,
            "fresh capped key is fully available: {ub}"
        );
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
        let url = format!("http://{addr}/api/v1/admin/keys");

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
                body["error"]["code"],
                "invalid_request", // frozen v1 envelope: keys speak the SAME code enum (H1)
                "400 error code must be invalid_request: {body}"
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

        for path in ["/api/v1/admin/keys", "/api/v1/admin/keys/some-id"] {
            let req = if path == "/api/v1/admin/keys" {
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
                body["error"]["code"],
                "invalid_request", // frozen v1 envelope: keys speak the SAME code enum (H1)
                "the 400 error code must be invalid_request; got {text}"
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
        let url = format!("http://{addr}/api/v1/admin/keys");

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
        let base = format!("http://{addr}/api/v1/admin/keys");

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
        let url = format!("http://{addr}/api/v1/admin/keys");

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
        let base = format!("http://{addr}/api/v1/admin/keys");

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
                let r1 = super::create_key(
                    crate::state::CurrentApp(app.clone()),
                    axum::Extension(crate::auth::AuthPrincipal(None)),
                    axum::http::HeaderMap::new(),
                    body1,
                )
                .await;
                let s1 = r1.status().as_u16();

                // Request 2: references ONLY the configured pool — no warning expected.
                let body2 = axum::body::Bytes::from(
                    serde_json::json!({
                        "name": "k-ok",
                        "allowed_pools": ["smart"]
                    })
                    .to_string(),
                );
                let r2 = super::create_key(
                    crate::state::CurrentApp(app),
                    axum::Extension(crate::auth::AuthPrincipal(None)),
                    axum::http::HeaderMap::new(),
                    body2,
                )
                .await;
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
            .delete(format!("http://{addr}/api/v1/admin/keys/{}", key.id))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            204,
            "existing key deletes with 204 No Content (H4)"
        );
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
            .delete(format!("http://{addr}/api/v1/admin/keys/vk_does_not_exist"))
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
        assert_eq!(body["error"]["code"], "not_found"); // frozen v1 envelope: keys speak the SAME code enum (H1)
        handle.abort();
    }

    #[tokio::test]
    async fn test_delete_key_is_not_idempotent_204() {
        // After a successful delete, a second delete of the same id must 404 (proves the 204 was a
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
        let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
        let first = client
            .delete(&url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status().as_u16(), 204);
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
    async fn test_concurrent_delete_returns_exactly_one_204() {
        // Regression (MEDIUM/correctness, TOCTOU): two concurrent DELETEs of the SAME id must not
        // both observe the key and both return 204 (which would imply two revocations of one row in
        // an audit trail). The delete handler serializes its lookup→delete critical section, so the
        // winner returns 204 and every loser returns 404. Fire a burst and assert exactly one 204.
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
        let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

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
                204 => ok += 1,
                404 => not_found += 1,
                other => panic!("unexpected status {other} from concurrent delete"),
            }
        }
        assert_eq!(
            ok, 1,
            "exactly one concurrent delete must report a 204 revocation"
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
        let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

        // Revoke the key.
        let del = client
            .delete(&key_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(del.status().as_u16(), 204, "the key is revoked");

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
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            listed["items"].as_array().unwrap().len(),
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
        fn add_metering(
            &self,
            delta: &crate::governance::MeteringDelta,
        ) -> crate::governance::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
            self.inner.list_metering(bucket)
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
        let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

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
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            listed["items"].as_array().unwrap().len(),
            0,
            "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
        );
        handle.abort();
    }

    /// REGRESSION (audit c1r6, SECURITY): `rotate_key` is a check-then-act (get_key → mint →
    /// put_key over the UPSERT), so — exactly like update_key/delete_key — it must hold
    /// EXISTENCE_GATE across lookup→write. Without it a DELETE that revokes the key between rotate's
    /// read and its `put_key` is clobbered by the put, RESURRECTING the revoked key with a fresh
    /// (attacker-usable) secret. Same deterministic `BarrierStore` interleaving as the PATCH test.
    #[tokio::test]
    async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
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

        // Arm the barrier so rotate's put_key (the next put) pauses between its check and its write.
        store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

        let rotate_url = format!("http://{addr}/api/v1/admin/keys/{}/rotate", key.id);
        let rotate_task = tokio::spawn(async move {
            reqwest::Client::new()
                .post(&rotate_url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });

        // Wait until rotate is parked inside put_key.
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .unwrap()
            .expect("ROTATE must reach the instrumented put_key");

        let delete_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
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

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        release_tx.send(()).unwrap();
        let _ = rotate_task.await.unwrap();
        let _ = delete_task.await.unwrap();

        // DECISIVE: the revoked key must be GONE. A resurrecting rotate (ungated) leaves it PRESENT.
        let listed: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            listed["items"].as_array().unwrap().len(),
            0,
            "rotate must never resurrect a key a concurrent DELETE revoked: {listed}"
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
        let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

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
        // so the DELETE that follows under the gate observes it and revokes it: 204. (The point of this
        // test is the BLOCKING, not the final status — but it must be a coherent 204, not a 404.)
        assert_eq!(
            del_status, 204,
            "the DELETE runs after the gate frees and revokes the (now-present) key"
        );
        handle.abort();
    }
}
