// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Virtual-key management API. Admin CRUD over `/api/v1/admin/keys`, guarded by the
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
    /// The `governance.budget_groups` bucket this key charges into (in addition to its own inline
    /// budget above, which stays the innermost bucket). Validated to EXIST at mint - a key naming a
    /// missing group is a 400 naming the offender. Named `budget_group`, never bare `group` (that
    /// name belongs to the auth `group_map` concept with opposite union semantics).
    #[serde(default)]
    budget_group: Option<String>,
    /// Optional mint-time labels (e.g. `{"team": "growth"}`) echoed onto this key's metric series
    /// so external dashboards can aggregate by them; never interpreted by enforcement.
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
}

/// The budget periods `governance::budget_window` actually enforces. An unrecognized value (a typo
/// like `"weekly"` / `"monthlly"`) is NOT a window `budget_window` knows: it silently degrades to the
/// all-time `"total"` window with a `tracing::warn!`, so a key created with a typo'd period returns
/// 201 yet enforces an all-time cap — its stored metadata says one thing while governance does
/// another. Validate at the ingress (key creation) so an operator gets a 400 with the allowed set
/// instead of a silently-misenforcing key. Kept in lock-step with the arms of
/// `governance::budget_window`.
const VALID_BUDGET_PERIODS: &[&str] = &[
    crate::governance::BUDGET_PERIOD_TOTAL,
    crate::governance::BUDGET_PERIOD_DAILY,
    crate::governance::BUDGET_PERIOD_MONTHLY,
];

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

// M6/F2 (scrape break): mint-time `labels` are echoed VERBATIM as Prometheus label names on every
// key metric series (metrics.rs `base_labels`). An unvalidated map is a scrape-integrity hole:
//   - a label named `key`/`bucket`/`model`/`tier` (the RESERVED names busbar itself attaches)
//     duplicates a label on the series, which breaks the WHOLE /metrics exposition (a duplicate
//     label name is invalid Prometheus text -> every scrape fails, not just this key);
//   - a name that is not a valid Prometheus label name (`^[a-zA-Z_][a-zA-Z0-9_]*$`) is rejected by
//     the exposition encoder for the same all-or-nothing effect;
//   - an unbounded count / length bloats every scrape and the store row.
// So validate at the mint ingress (the one write path) and 400 anything unsafe.
/// Label names busbar itself attaches to key metric series - an operator label may not shadow them.
const RESERVED_METRIC_LABELS: &[&str] = &["key", "bucket", "model", "tier"];
const MAX_LABEL_COUNT: usize = 16;
const MAX_LABEL_NAME_LEN: usize = 64;
const MAX_LABEL_VALUE_LEN: usize = 256;

/// Validate the mint-time `labels` map. Returns `Err(message)` (a 400 body) for a reserved/invalid
/// name, an over-count map, or an over-long name/value. `Ok(())` when every label is scrape-safe.
fn validate_mint_labels(labels: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    if labels.len() > MAX_LABEL_COUNT {
        return Err(format!(
            "too many labels: {} (max {MAX_LABEL_COUNT})",
            labels.len()
        ));
    }
    for (name, value) in labels {
        if RESERVED_METRIC_LABELS.contains(&name.as_str()) {
            return Err(format!(
                "label name '{name}' is reserved (busbar attaches it to metric series); \
                 reserved names are {RESERVED_METRIC_LABELS:?}"
            ));
        }
        if name.len() > MAX_LABEL_NAME_LEN {
            return Err(format!(
                "label name is {} chars; must be <= {MAX_LABEL_NAME_LEN}",
                name.len()
            ));
        }
        if !is_valid_label_name(name) {
            return Err(format!(
                "label name '{name}' is not a valid Prometheus label name \
                 (must match ^[a-zA-Z_][a-zA-Z0-9_]*$)"
            ));
        }
        if value.len() > MAX_LABEL_VALUE_LEN {
            return Err(format!(
                "label '{name}' value is {} chars; must be <= {MAX_LABEL_VALUE_LEN}",
                value.len()
            ));
        }
    }
    Ok(())
}

/// A valid Prometheus label name: `^[a-zA-Z_][a-zA-Z0-9_]*$` (non-empty, ASCII-alnum + underscore,
/// never leading with a digit). Hand-rolled to avoid a regex dependency on the mint path.
fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false, // empty or bad first char
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
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
/// column/table names, or paths from the store backend) is logged server-side via `tracing::error!`;
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
// Built engine + swappable layers, VERSION-FIRST: each API version (`v1`, later `v2`)
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
        "budget_group": k.budget_group,
        "labels": k.labels,
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

/// Bound a path `id` (the virtual-key id from `/api/v1/admin/keys/{id}`). Admin-gated, but an unbounded id
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

/// POST /api/v1/admin/keys — mint a virtual key. Returns the plaintext secret ONCE.
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
    // M6/F2: labels are echoed verbatim as Prometheus label NAMES on this key's metric series; an
    // unsafe name (reserved, or not a valid label name) or an oversized map breaks the WHOLE scrape.
    // Reject at the mint ingress (see `validate_mint_labels`).
    if let Err(msg) = validate_mint_labels(&req.labels) {
        return error_response(StatusCode::BAD_REQUEST, ERR_TYPE_INVALID_REQUEST, msg);
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
    // MINT-TIME fail-closed check: a `budget_group` must exist in governance.budget_groups NOW - a
    // dangling binding would make every request on the new key fail closed at admission. 400 with
    // the offender named (mirrors the boot-side check over stored keys).
    if let Some(group) = req.budget_group.as_deref() {
        if app.cost.group_named(group).is_none() {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_TYPE_INVALID_REQUEST,
                format!(
                    "budget_group '{group}' does not exist in governance.budget_groups; \
                     configure it first (e.g. {group}: {{ max_budget_cents: 0, budget_period: monthly }})"
                ),
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
        budget_group: req.budget_group,
        labels: req.labels,
    };
    // Offload the blocking store write off the Tokio worker thread (matches the request-path
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

/// PATCH /api/v1/admin/keys/{id} — enable/disable a key or adjust its rate/budget caps. The `enabled` field
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

/// GET /api/v1/admin/keys — list key metadata (no secrets/hashes). Optional filters (design-admin-api-v1
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
        None => crate::admin::v1::contract::LIST_LIMIT_DEFAULT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n.min(crate::admin::v1::contract::LIST_LIMIT_MAX),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ERR_TYPE_INVALID_REQUEST,
                    format!(
                        "invalid `limit`: expected an integer (max {})",
                        crate::admin::v1::contract::LIST_LIMIT_MAX
                    ),
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

/// GET /api/v1/admin/keys/{id} — one key's metadata (id/name/pools/budgets/limits/enabled; never the
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
    let cost = app.cost.clone();
    let res = tokio::task::spawn_blocking(move || {
        // DERIVED at read time: spend_cents = ledger x CURRENT rate card (+ fee x requests) - a
        // rate-card correction changes this number on the very next read (tokens are the truth).
        let usage = gov2.usage_for(&cost, &id2, now)?;
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

/// DELETE /api/v1/admin/keys/{id} — revoke a key. Returns 404 when no key with `id` exists (REST/OpenAPI
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
#[path = "tests/tests.rs"]
mod tests;
