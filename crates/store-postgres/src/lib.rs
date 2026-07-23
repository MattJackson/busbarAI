// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store — the shared, multi-node `db`
//! plugin. Implements `busbar_api::Store` over a mutex-guarded synchronous `postgres` client,
//! depending only on the `busbar-api` contract (plus the `postgres` driver), never on the engine.
//!
//! It mirrors the SQLite backend's schema and semantics exactly (same tables, same UPSERT shapes,
//! same JSON encoding of `allowed_pools`) so `store: sqlite` and `store: postgres` are drop-in
//! interchangeable — the only differences are the SQL dialect (`$N` params, `EXCLUDED`, `GREATEST`,
//! `BIGINT`/`BOOLEAN`) and that Postgres is a shared server, which is the whole point: one database
//! behind a fleet of busbar nodes means virtual keys, budgets, and usage are shared across the
//! cluster instead of siloed per node.
//!
//! Like SQLite, it is a **single mutex-guarded connection** used off the request hot path (key CRUD
//! + the write-behind usage flush), so serializing access on one connection is correct and simple.
//!
//! ## Known limitations (documented honestly, not papered over)
//!
//! - **No TLS in this build (`NoTls`).** Run the connection over a trusted network segment, a local
//!   socket, or a TLS-terminating proxy (pgbouncer/stunnel). The Redis store, by contrast, speaks
//!   `rediss://` natively.
//! - **No automatic reconnect.** A persistently dropped connection surfaces as store errors on the
//!   (write-behind, retried-per-tick) flush path and on admin operations; the budget flusher
//!   re-marks unflushed deltas dirty and retries every tick, so accrued spend is not lost across a
//!   brief outage, but a permanently broken connection requires a process restart (let your
//!   supervisor handle it). The Redis store implements one-shot transparent reconnect.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use postgres::types::ToSql;
use postgres::{Client, NoTls, Row};
use std::sync::Mutex;

// postgres driver error -> the api's backend-agnostic `StoreError` (the contract crate stays
// storage-free, so the `From` impl that powers `?` cannot live there).
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, postgres::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
    }
}

/// True when a postgres error is SQLSTATE 42P01 (`undefined_table`) - the ONE case migrate() treats
/// as an unversioned (version 0) database. Every other error class (connection, timeout, permission)
/// is transient/fatal and must never be read as "fresh DB". See migrate()'s H1 note.
fn is_undefined_table(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE)
}

/// Extract the PASSWORD from a Postgres DSN (L2). Supports both the URL form
/// (`postgres://user:pass@host:5432/db`) and the libpq keyword form (`... password=secret ...`), so
/// a connect-error string can be scrubbed of the secret regardless of which shape the operator used.
fn dsn_password(dsn: &str) -> Option<String> {
    // URL form: `scheme://[user[:pass]@]host...`.
    if let Some(rest) = dsn.split("://").nth(1) {
        if let Some((userinfo, _)) = rest.rsplit_once('@') {
            if let Some((_, pass)) = userinfo.split_once(':') {
                if !pass.is_empty() {
                    return Some(pass.to_string());
                }
            }
        }
    }
    // libpq keyword form: whitespace-separated `key=value` pairs; find `password=...`.
    for tok in dsn.split_whitespace() {
        if let Some(v) = tok.strip_prefix("password=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Percent-DECODE a URL component (`%40` -> `@`). A malformed escape is left verbatim. So the scrub
/// redacts BOTH the raw and decoded forms of a URL-embedded password.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH raw and percent-decoded forms) with `<redacted>`.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    out
}

/// Store schema version, mirrored from the SQLite backend's `PRAGMA user_version` in a tiny
/// `busbar_schema` table. v2 = the 1.5.0 token-ledger cost model (see the SQLite backend's
/// `SCHEMA_VERSION` doc). 1.5.0 is unreleased, so a pre-v2 database is dropped and recreated - a
/// bump, never a migration.
const SCHEMA_VERSION: i64 = 2;

// Same tables/columns as the SQLite backend, in Postgres types: INTEGER -> BIGINT, the enabled flag
// as BOOLEAN. `CREATE TABLE IF NOT EXISTS` is idempotent, so migrate() is safe to run every open.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS busbar_schema (
    version BIGINT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS virtual_keys (
    id               TEXT PRIMARY KEY,
    key_hash         TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    allowed_pools    TEXT NOT NULL DEFAULT '',
    max_budget_cents BIGINT,
    budget_period    TEXT NOT NULL DEFAULT 'total',
    rpm_limit        BIGINT,
    tpm_limit        BIGINT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       BIGINT NOT NULL,
    budget_group     TEXT,
    labels           TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS aws_credentials (
    access_key_id     TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    secret_access_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aws_credentials_key_id ON aws_credentials (key_id);
-- The TOKEN LEDGER (v2): per-(bucket, window) request counts + per-(bucket, window, model) tier
-- token counts. `bucket_id` is a virtual key's id OR a budget-group bucket id. NO spend column:
-- dollars are derived at read time from `ledger x rate_card` in the engine.
CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    requests     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    bucket_id          TEXT NOT NULL,
    window_start       BIGINT NOT NULL,
    model              TEXT NOT NULL,
    tokens_input       BIGINT NOT NULL DEFAULT 0,
    tokens_output      BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read  BIGINT NOT NULL DEFAULT 0,
    tokens_cache_write BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model)
);
CREATE TABLE IF NOT EXISTS usage_metering (
    key_id                TEXT NOT NULL,
    bucket                BIGINT NOT NULL,
    model                 TEXT NOT NULL,
    provider              TEXT NOT NULL,
    tokens_input          BIGINT NOT NULL DEFAULT 0,
    tokens_output         BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read     BIGINT NOT NULL DEFAULT 0,
    tokens_cache_creation BIGINT NOT NULL DEFAULT 0,
    requests              BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider)
);
-- The admin AUDIT log's durable home (mirrors the SQLite backend). Append-only; `seq` is the engine's
-- monotonic sequence (PK). The engine owns the hash chain; the store persists each record verbatim
-- (upsert on `seq` so a replay is idempotent) and returns them oldest-first for boot restore.
CREATE TABLE IF NOT EXISTS audit_log (
    seq       BIGINT PRIMARY KEY,
    ts        BIGINT NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
";

/// Postgres `Store` backend (durable, shared across a cluster). A single mutex-guarded connection —
/// governance is off the request hot path, so serializing access is fine.
pub struct PostgresStore {
    client: Mutex<Client>,
}

/// Clamp a `u64` into `i64` for a BIGINT column (a value above `i64::MAX` pins to `i64::MAX`, never
/// wraps) — mirrors the SQLite backend.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed BIGINT back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` — mirrors the SQLite backend's DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Read a signed BIGINT rate-limit column back as a `u32`, SATURATING an out-of-range value to
/// `u32::MAX` (and clamping a negative to 0) instead of wrapping via `as u32` - mirrors the SQLite
/// backend's DI-2 posture so a direct-DB write can never silently narrow to a WRONG cap.
fn read_u32_cap(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl PostgresStore {
    /// Connect to Postgres with the given libpq connection string / URL (e.g.
    /// `postgres://user:pass@host:5432/dbname`) and ensure the schema. TLS is not wired in this
    /// build (`NoTls`); front the database with a TLS-terminating proxy or a local socket.
    pub fn connect(conn_str: &str) -> StoreResult<Self> {
        // L2: a connect error's string can embed the DSN (and thus the password). Scrub it before it
        // leaves the crate, matching the Redis backend. Handles both the URL form
        // (`postgres://user:pass@host/db`) and the libpq keyword form (`password=secret`), in raw and
        // percent-decoded shapes.
        let secret = dsn_password(conn_str);
        let client = Client::connect(conn_str, NoTls)
            .map_err(|e| StoreError(scrub(e.to_string(), secret.as_deref())))?;
        let store = Self {
            client: Mutex::new(client),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Poison-recovering lock of the client (mirrors the SQLite backend): the guard is reachable off
    /// the hot path, and continuing after a recovered guard is safe because the driver rolls back a
    /// panicked statement.
    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> StoreResult<()> {
        let mut client = self.lock();
        // SCHEMA-VERSION BUMP (v2, the 1.5.0 token-ledger cost model). A pre-v2 database - one that
        // still carries the legacy `usage_counters` table, or a `virtual_keys` without the v2
        // columns - is DROPPED and recreated (1.5.0 is unreleased: bump, not migrate). A fresh or
        // already-v2 database passes straight through the idempotent CREATEs.
        //
        // H1 (data-loss): the version read must never CONFLATE a transient read error with a fresh
        // DB. We ensure the version table exists FIRST, then read; a *transient* read failure
        // (connection blip, lock timeout, permission) PROPAGATES and fails boot rather than
        // defaulting to 0 and dropping every governance table on a healthy v2 DB. Only a genuine
        // "relation does not exist" (SQLSTATE 42P01) counts as an unversioned (version 0) database.
        client
            .batch_execute("CREATE TABLE IF NOT EXISTS busbar_schema (version BIGINT PRIMARY KEY)")
            .store()?;
        let version: i64 =
            match client.query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[]) {
                Ok(Some(r)) => r.get(0),
                // No rows -> an empty (freshly created) version table -> version 0.
                Ok(None) => 0,
                // A genuinely-absent table is the only non-fatal "unversioned" signal (version 0). Any
                // OTHER error (transient/connection/permission) MUST fail boot - never silently 0.
                Err(e) if is_undefined_table(&e) => 0,
                Err(e) => return Err(StoreError(e.to_string())),
            };
        // Wrap the legacy DROP + full CREATE + version-INSERT in ONE transaction so a crash between
        // the drop and the recreate cannot leave a half-initialised DB that a re-run re-drops (L3).
        let mut tx = client.transaction().store()?;
        if version < SCHEMA_VERSION {
            let legacy: bool = tx
                .query_one("SELECT to_regclass('usage_counters') IS NOT NULL OR to_regclass('virtual_keys') IS NOT NULL", &[])
                .store()?
                .get(0);
            if legacy {
                tx.batch_execute(
                    "DROP TABLE IF EXISTS virtual_keys;
                         DROP TABLE IF EXISTS aws_credentials;
                         DROP TABLE IF EXISTS usage_counters;
                         DROP TABLE IF EXISTS usage_windows;
                         DROP TABLE IF EXISTS usage_ledger;
                         DROP TABLE IF EXISTS usage_metering;
                         DROP TABLE IF EXISTS audit_log;",
                )
                .store()?;
            }
        }
        tx.batch_execute(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO busbar_schema (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
            &[&SCHEMA_VERSION],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }
}

// `labels` encoding - identical to the SQLite backend: a JSON object in the `labels TEXT` column.
fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}
fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

// `allowed_pools` encoding — identical to the SQLite backend: JSON array of strings (delimiter-safe),
// reading legacy bare comma-delimited values transparently.
fn pools_to_storage(pools: &[String]) -> String {
    serde_json::to_string(pools).unwrap_or_else(|_| "[]".to_string())
}
fn pools_from_storage(stored: &str) -> Vec<String> {
    let trimmed = stored.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Ok(pools) = serde_json::from_str::<Vec<String>>(trimmed) {
        return pools;
    }
    trimmed.split(',').map(String::from).collect()
}

/// Map a `virtual_keys` row (in the fixed SELECT column order) to a `VirtualKey`.
fn row_to_key(r: &Row) -> VirtualKey {
    VirtualKey {
        id: r.get(0),
        key_hash: r.get(1),
        name: r.get(2),
        allowed_pools: pools_from_storage(&r.get::<_, String>(3)),
        max_budget_cents: r.get(4),
        budget_period: r.get(5),
        // DI-2 (mirrors the SQLite backend): a direct-DB BIGINT above u32::MAX (or a negative)
        // would silently wrap to a WRONG rate-limit cap with `as u32`. Saturate instead - the admin
        // API bounds these on the write path; this closes the direct-DB hole.
        rpm_limit: r.get::<_, Option<i64>>(6).map(read_u32_cap),
        tpm_limit: r.get::<_, Option<i64>>(7).map(read_u32_cap),
        enabled: r.get(8),
        created_at: read_u64(r.get::<_, i64>(9)),
        budget_group: r.get(10),
        labels: labels_from_storage(&r.get::<_, String>(11)),
    }
}

const KEY_COLUMNS: &str =
    "id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels";

impl Store for PostgresStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let pools = pools_to_storage(&key.allowed_pools);
        let labels = labels_to_storage(&key.labels);
        let rpm = key.rpm_limit.map(|v| v as i64);
        let tpm = key.tpm_limit.map(|v| v as i64);
        let created = clamp(key.created_at);
        self.lock()
            .execute(
                "INSERT INTO virtual_keys
                    (id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                 ON CONFLICT (id) DO UPDATE SET
                    key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                    max_budget_cents=EXCLUDED.max_budget_cents, budget_period=EXCLUDED.budget_period,
                    rpm_limit=EXCLUDED.rpm_limit, tpm_limit=EXCLUDED.tpm_limit, enabled=EXCLUDED.enabled,
                    budget_group=EXCLUDED.budget_group, labels=EXCLUDED.labels",
                &[
                    &key.id, &key.key_hash, &key.name, &pools, &key.max_budget_cents,
                    &key.budget_period, &rpm, &tpm, &key.enabled, &created,
                    &key.budget_group, &labels,
                ],
            )
            .store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM virtual_keys WHERE id=$1");
        let row = self.lock().query_opt(&sql, &[&id]).store()?;
        Ok(row.map(|r| row_to_key(&r)))
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM virtual_keys ORDER BY created_at");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Atomic: the key row, its usage counters, and its AWS credentials go together or not at all,
        // so a revoked key can never leave an orphaned credential (an auth-bypass) or stale usage.
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute("DELETE FROM virtual_keys WHERE id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM usage_windows WHERE bucket_id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE bucket_id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM aws_credentials WHERE key_id=$1", &[&id])
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        // Read the requests row + every model row inside ONE transaction so a concurrent node's
        // `add_usage` can never yield a torn ledger.
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let requests: u64 = tx
            .query_opt(
                "SELECT requests FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
                &[&bucket_id, &ws],
            )
            .store()?
            .map(|r| read_u64(r.get::<_, i64>(0)))
            .unwrap_or(0);
        let rows = tx
            .query(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                 FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2 ORDER BY model",
                &[&bucket_id, &ws],
            )
            .store()?;
        tx.commit().store()?;
        Ok(UsageLedger {
            requests,
            models: rows
                .iter()
                .map(|r| ModelTokens {
                    model: r.get(0),
                    tokens: TierTokens {
                        input: read_u64(r.get::<_, i64>(1)),
                        output: read_u64(r.get::<_, i64>(2)),
                        cache_read: read_u64(r.get::<_, i64>(3)),
                        cache_write: read_u64(r.get::<_, i64>(4)),
                    },
                })
                .collect(),
        })
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): replace the whole (bucket, window) record -
        // the requests row AND every model row - in ONE transaction, so a re-flush is idempotent
        // and a reader never sees half a ledger.
        let ws = clamp(window_start);
        let rq = clamp(ledger.requests);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests)
             VALUES ($1,$2,$3)
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET requests = EXCLUDED.requests",
            &[&bucket_id, &ws, &rq],
        )
        .store()?;
        for m in &ledger.models {
            let (ti, to, tcr, tcw) = (
                clamp(m.tokens.input),
                clamp(m.tokens.output),
                clamp(m.tokens.cache_read),
                clamp(m.tokens.cache_write),
            );
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[&bucket_id, &ws, &m.model, &ti, &to, &tcr, &tcw],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE fleet-honest accumulate: the signed requests delta plus every per-model tier
        // delta land in ONE transaction, each counter floored at 0 (GREATEST). N nodes flushing
        // deltas sum to the true fleet total, where `put_usage`'s absolute overwrite is
        // last-writer-wins. No dollar delta crosses this wire.
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            // `$3::bigint` casts anchor the parameter type inside GREATEST (whose bare `0` would
            // otherwise make Postgres infer int4 and fail to serialize the i64 binding).
            "INSERT INTO usage_windows (bucket_id, window_start, requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = GREATEST(0, usage_windows.requests + $3::bigint)",
            &[&bucket_id, &ws, &delta.requests],
        )
        .store()?;
        for m in &delta.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES ($1,$2,$3,GREATEST(0,$4::bigint),GREATEST(0,$5::bigint),GREATEST(0,$6::bigint),GREATEST(0,$7::bigint))
                 ON CONFLICT (bucket_id, window_start, model) DO UPDATE SET
                    tokens_input       = GREATEST(0, usage_ledger.tokens_input + $4::bigint),
                    tokens_output      = GREATEST(0, usage_ledger.tokens_output + $5::bigint),
                    tokens_cache_read  = GREATEST(0, usage_ledger.tokens_cache_read + $6::bigint),
                    tokens_cache_write = GREATEST(0, usage_ledger.tokens_cache_write + $7::bigint)",
                &[
                    &bucket_id,
                    &ws,
                    &m.model,
                    &m.tokens.input,
                    &m.tokens.output,
                    &m.tokens.cache_read,
                    &m.tokens.cache_write,
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let (bucket, ti, to, tcr, tcc) = (
            clamp(d.bucket),
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_creation),
        );
        self.lock()
            .execute(
                "INSERT INTO usage_metering (key_id, bucket, model, provider,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1)
                 ON CONFLICT (key_id, bucket, model, provider) DO UPDATE SET
                     tokens_input          = usage_metering.tokens_input + EXCLUDED.tokens_input,
                     tokens_output         = usage_metering.tokens_output + EXCLUDED.tokens_output,
                     tokens_cache_read     = usage_metering.tokens_cache_read + EXCLUDED.tokens_cache_read,
                     tokens_cache_creation = usage_metering.tokens_cache_creation + EXCLUDED.tokens_cache_creation,
                     requests              = usage_metering.requests + 1",
                &[
                    &d.key_id, &bucket, &d.model, &d.provider, &ti, &to, &tcr, &tcc,
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let b = clamp(bucket);
        let rows = self
            .lock()
            .query(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests
                 FROM usage_metering WHERE bucket=$1",
                &[&b],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| MeteringRow {
                key_id: r.get(0),
                model: r.get(1),
                provider: r.get(2),
                tokens_input: read_u64(r.get::<_, i64>(3)),
                tokens_output: read_u64(r.get::<_, i64>(4)),
                tokens_cache_read: read_u64(r.get::<_, i64>(5)),
                tokens_cache_creation: read_u64(r.get::<_, i64>(6)),
                requests: read_u64(r.get::<_, i64>(7)),
            })
            .collect())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        self.lock()
            .execute(
                "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
                 VALUES ($1,$2,$3)
                 ON CONFLICT (access_key_id) DO UPDATE SET
                    key_id=EXCLUDED.key_id, secret_access_key=EXCLUDED.secret_access_key",
                &[&cred.access_key_id, &cred.key_id, &cred.secret_access_key],
            )
            .store()?;
        Ok(())
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // ATOMIC mint: the bearer key and its AWS credential commit together or not at all.
        let pools = pools_to_storage(&key.allowed_pools);
        let labels = labels_to_storage(&key.labels);
        let rpm = key.rpm_limit.map(|v| v as i64);
        let tpm = key.tpm_limit.map(|v| v as i64);
        let created = clamp(key.created_at);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "INSERT INTO virtual_keys
                (id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (id) DO UPDATE SET
                key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                max_budget_cents=EXCLUDED.max_budget_cents, budget_period=EXCLUDED.budget_period,
                rpm_limit=EXCLUDED.rpm_limit, tpm_limit=EXCLUDED.tpm_limit, enabled=EXCLUDED.enabled,
                budget_group=EXCLUDED.budget_group, labels=EXCLUDED.labels",
            &[
                &key.id, &key.key_hash, &key.name, &pools, &key.max_budget_cents,
                &key.budget_period, &rpm, &tpm, &key.enabled, &created,
                &key.budget_group, &labels,
            ],
        )
        .store()?;
        tx.execute(
            "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
             VALUES ($1,$2,$3)
             ON CONFLICT (access_key_id) DO UPDATE SET
                key_id=EXCLUDED.key_id, secret_access_key=EXCLUDED.secret_access_key",
            &[&cred.access_key_id, &cred.key_id, &cred.secret_access_key],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let rows = self
            .lock()
            .query(
                "SELECT access_key_id, key_id, secret_access_key FROM aws_credentials",
                &[],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| AwsCredential {
                access_key_id: r.get(0),
                key_id: r.get(1),
                secret_access_key: r.get(2),
            })
            .collect())
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // Upsert on the `seq` PK: append-only in practice, idempotent if the engine re-writes a record
        // for the same seq (never a UNIQUE violation).
        let (seq, ts) = (clamp(entry.seq), clamp(entry.ts));
        self.lock()
            .execute(
                "INSERT INTO audit_log
                    (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (seq) DO UPDATE SET
                    ts=EXCLUDED.ts, action=EXCLUDED.action, resource=EXCLUDED.resource,
                    outcome=EXCLUDED.outcome, principal=EXCLUDED.principal,
                    prev_hash=EXCLUDED.prev_hash, hash=EXCLUDED.hash",
                &[
                    &seq,
                    &ts,
                    &entry.action,
                    &entry.resource,
                    &entry.outcome,
                    &entry.principal,
                    &entry.prev_hash,
                    &entry.hash,
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let rows = self
            .lock()
            .query(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq",
                &[],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| AuditRecord {
                seq: read_u64(r.get::<_, i64>(0)),
                ts: read_u64(r.get::<_, i64>(1)),
                action: r.get(2),
                resource: r.get(3),
                outcome: r.get(4),
                principal: r.get(5),
                prev_hash: r.get(6),
                hash: r.get(7),
            })
            .collect())
    }
}

// A tiny compile-time assertion that the param binding types line up (keeps ToSql import used even
// when the integration test is skipped for lack of a live database).
const _: fn() = || {
    fn assert_tosql<T: ToSql>() {}
    assert_tosql::<i64>();
    assert_tosql::<Option<i64>>();
    assert_tosql::<bool>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// L2: a connect-error string must never leak the DSN password. `dsn_password` extracts it from
    /// both the URL and libpq keyword forms, and `scrub` redacts BOTH raw and percent-decoded forms.
    #[test]
    fn dsn_password_extraction_and_scrub() {
        // URL form.
        assert_eq!(
            dsn_password("postgres://user:s3cr3t@host:5432/db").as_deref(),
            Some("s3cr3t")
        );
        // URL form, percent-encoded password.
        assert_eq!(
            dsn_password("postgresql://u:p%40ss@host/db").as_deref(),
            Some("p%40ss")
        );
        // libpq keyword form.
        assert_eq!(
            dsn_password("host=db user=u password=kwsecret dbname=x").as_deref(),
            Some("kwsecret")
        );
        // No password.
        assert_eq!(dsn_password("postgres://host:5432/db"), None);
        assert_eq!(dsn_password("host=db user=u"), None);

        // A connect error embedding the DSN is scrubbed of the raw AND decoded password.
        let raw = dsn_password("postgresql://u:p%40ss@host/db").unwrap();
        let leak = "could not connect: postgresql://u:p%40ss@host/db (auth p@ss)".to_string();
        let s = scrub(leak, Some(&raw));
        assert!(
            !s.contains("p%40ss") && !s.contains("p@ss") && s.contains("<redacted>"),
            "both raw and decoded password forms must be scrubbed; got {s}"
        );
        assert_eq!(scrub("plain".into(), None), "plain");
        assert_eq!(percent_decode("p%40ss"), "p@ss");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
    }

    /// DI-2: a BIGINT rate-limit column above `u32::MAX` (or negative) must SATURATE to `u32::MAX`,
    /// not wrap to a wrong (lower) cap via `as u32`. Matches the SQLite backend's semantics exactly.
    #[test]
    fn read_u32_cap_saturates_out_of_range_bigint() {
        assert_eq!(read_u32_cap(60), 60, "in-range value passes through");
        assert_eq!(read_u32_cap(0), 0);
        assert_eq!(read_u32_cap(i64::from(u32::MAX)), u32::MAX, "the boundary");
        // Above u32::MAX would wrap to a WRONG lower cap with `as u32` (e.g. 0); saturate instead.
        assert_eq!(read_u32_cap(i64::from(u32::MAX) + 1), u32::MAX);
        assert_eq!(read_u32_cap(i64::MAX), u32::MAX);
        // A corrupt/direct-DB negative clamps to u32::MAX too (matches SQLite's unwrap_or(MAX)).
        assert_eq!(read_u32_cap(-1), u32::MAX);
    }

    /// End-to-end against a REAL Postgres, gated on `BUSBAR_TEST_POSTGRES_URL` (a docker
    /// `postgres:16` service in CI). Skips cleanly when unset LOCALLY so the default `cargo test`
    /// needs no database - but MUST NOT silently skip in CI: CI provisions the service and sets the
    /// URL (see .github/workflows/ci.yml), so when `CI` is set the missing URL is a HARD FAILURE
    /// rather than a silent skip. Otherwise a broken CI service block would let the only coverage of
    /// the delete_key cascade / credential cleanup vanish unnoticed (P1 #6).
    #[test]
    fn roundtrip_against_live_postgres() {
        let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
            Ok(url) => url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!(
                    "BUSBAR_TEST_POSTGRES_URL is unset under CI: the Postgres service container must \
                     provision it (see .github/workflows/ci.yml). Refusing to silently skip the only \
                     live-DB coverage in CI."
                );
            }
            Err(_) => {
                eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the Postgres store test");
                return;
            }
        };
        let store = PostgresStore::connect(&url).expect("connect");
        // Isolate from any prior run.
        let _ = store.delete_key("vk_pg");

        let key = VirtualKey {
            id: "vk_pg".into(),
            key_hash: "h".into(),
            name: "pg".into(),
            allowed_pools: vec!["prod,special".into()],
            max_budget_cents: Some(1234),
            budget_period: "total".into(),
            rpm_limit: Some(60),
            tpm_limit: None,
            enabled: true,
            created_at: 99,
            budget_group: Some("growth".into()),
            labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        };
        store.put_key(&key).unwrap();
        let got = store.get_key("vk_pg").unwrap().unwrap();
        assert_eq!(got.max_budget_cents, Some(1234));
        // The comma-bearing pool name survives (JSON encoding, not a bare comma split).
        assert_eq!(got.allowed_pools, vec!["prod,special".to_string()]);
        assert_eq!(got.rpm_limit, Some(60));
        assert_eq!(
            got.budget_group.as_deref(),
            Some("growth"),
            "budget_group survives the Postgres round-trip"
        );
        assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));

        // Absolute put_usage of a per-model token ledger, then read back.
        let base = UsageLedger {
            requests: 3,
            models: vec![ModelTokens {
                model: "gpt-5".into(),
                tokens: TierTokens {
                    input: 9,
                    output: 4,
                    cache_read: 2,
                    cache_write: 1,
                },
            }],
        };
        store.put_usage("vk_pg", 100, &base).unwrap();
        let u = store.get_usage("vk_pg", 100).unwrap();
        assert_eq!(u.requests, 3);
        assert_eq!(u.tokens_for("gpt-5").unwrap().input, 9);

        // ADDITIVE fleet flush primitive: add_usage accumulates per-model signed deltas on top
        // (and a negative delta refunds, floored at 0). A second model materializes its own row.
        let mk_delta = |requests: i64, model: &str, input: i64| busbar_api::UsageDelta {
            requests,
            models: vec![busbar_api::ModelTokensDelta {
                model: model.into(),
                tokens: busbar_api::TierTokensDelta {
                    input,
                    output: 1,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        };
        store
            .add_usage("vk_pg", 100, &mk_delta(2, "gpt-5", 1))
            .unwrap();
        let u = store.get_usage("vk_pg", 100).unwrap();
        assert_eq!(u.requests, 5, "add_usage accumulates the requests delta");
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!(
            (t.input, t.output),
            (10, 5),
            "add_usage accumulates per-model tier deltas"
        );
        store
            .add_usage("vk_pg", 100, &mk_delta(0, "haiku", 7))
            .unwrap();
        assert_eq!(
            store.get_usage("vk_pg", 100).unwrap().models.len(),
            2,
            "a second model materializes its own ledger row"
        );
        store
            .add_usage("vk_pg", 100, &mk_delta(-100, "gpt-5", -10_000))
            .unwrap();
        let u = store.get_usage("vk_pg", 100).unwrap();
        assert_eq!(
            (u.requests, u.tokens_for("gpt-5").unwrap().input),
            (0, 0),
            "an over-refund floors at 0, never negative"
        );

        // METERING: the billing-critical raw-consumption UPSERT. Two deltas for the SAME
        // (key, bucket, model, provider) must ACCUMULATE (ON CONFLICT DO UPDATE), not overwrite -
        // this is what a third party's cost reconstruction reads back. Use a private bucket so the
        // read-back is isolated from any other row in the table.
        let m_bucket = 20_260_722_u64;
        let delta = |ti, to, tcr, tcc| MeteringDelta {
            key_id: "vk_pg".into(),
            bucket: m_bucket,
            model: "gpt-x".into(),
            provider: "special".into(),
            tokens_input: ti,
            tokens_output: to,
            tokens_cache_read: tcr,
            tokens_cache_creation: tcc,
        };
        store.add_metering(&delta(10, 5, 2, 1)).unwrap();
        store.add_metering(&delta(30, 15, 4, 3)).unwrap();
        let rows: Vec<MeteringRow> = store
            .list_metering(m_bucket)
            .unwrap()
            .into_iter()
            .filter(|r| r.key_id == "vk_pg")
            .collect();
        assert_eq!(rows.len(), 1, "the two deltas UPSERT into ONE row");
        let r = &rows[0];
        assert_eq!(
            (
                r.model.as_str(),
                r.provider.as_str(),
                r.tokens_input,
                r.tokens_output,
                r.tokens_cache_read,
                r.tokens_cache_creation,
                r.requests,
            ),
            ("gpt-x", "special", 40, 20, 6, 4, 2),
            "the UPSERT accumulates every token class plus the request count"
        );
        // Cleanup so the test is re-runnable against a persistent CI database.
        store
            .lock()
            .execute(
                "DELETE FROM usage_metering WHERE key_id='vk_pg' AND bucket=$1",
                &[&(m_bucket as i64)],
            )
            .expect("metering cleanup");

        // AUDIT: the tamper-evidence chain must round-trip through the store verbatim, oldest-first
        // by seq (the store never interprets the hash chain - it is a dumb durable sink). Isolate on a
        // high seq band so a persistent CI table does not collide, and clean up afterward.
        let a_base = 900_000_000_u64;
        let mk = |seq: u64, prev: &str, hash: &str| AuditRecord {
            seq,
            ts: 1000 + seq,
            action: "plugin.install".into(),
            resource: format!("plugin:{seq}"),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: prev.into(),
            hash: hash.into(),
        };
        // Append OUT of seq order to prove the ORDER BY seq on read.
        store.append_audit(&mk(a_base + 2, "h1", "h2")).unwrap();
        store.append_audit(&mk(a_base + 1, "", "h1")).unwrap();
        store.append_audit(&mk(a_base + 3, "h2", "h3")).unwrap();
        let chain: Vec<AuditRecord> = store
            .list_audit()
            .unwrap()
            .into_iter()
            .filter(|a| a.seq >= a_base)
            .collect();
        assert_eq!(chain.len(), 3);
        assert_eq!(
            (chain[0].seq, chain[1].seq, chain[2].seq),
            (a_base + 1, a_base + 2, a_base + 3),
            "audit records return oldest-first by seq"
        );
        assert_eq!(chain[0].prev_hash, "", "chain head links to nothing");
        assert_eq!(chain[1].prev_hash, "h1");
        assert_eq!(
            (chain[2].prev_hash.as_str(), chain[2].hash.as_str()),
            ("h2", "h3"),
            "the prev_hash -> hash links survive the round-trip verbatim"
        );
        assert_eq!(chain[2].resource, format!("plugin:{}", a_base + 3));
        // A re-append of the same seq UPSERTs (idempotent replay), never a UNIQUE violation.
        store.append_audit(&mk(a_base + 2, "h1", "h2b")).unwrap();
        let replayed: Vec<AuditRecord> = store
            .list_audit()
            .unwrap()
            .into_iter()
            .filter(|a| a.seq >= a_base)
            .collect();
        assert_eq!(replayed.len(), 3, "re-append of an existing seq upserts");
        assert_eq!(
            replayed[1].hash, "h2b",
            "the replayed record overwrites the prior digest"
        );
        // Cleanup so the test is re-runnable against a persistent CI database.
        store
            .lock()
            .execute("DELETE FROM audit_log WHERE seq >= $1", &[&(a_base as i64)])
            .expect("audit cleanup");

        // Attach an AWS credential so delete_key's CASCADE (key + usage + credentials) can be
        // verified end to end - the credential-cleanup path P1 #6 flagged as untested.
        let cred = AwsCredential {
            access_key_id: "AKIA_PG_TEST".into(),
            key_id: "vk_pg".into(),
            secret_access_key: "s3cr3t".into(),
        };
        store.put_aws_credential(&cred).unwrap();
        assert!(
            store
                .list_aws_credentials()
                .unwrap()
                .iter()
                .any(|c| c.access_key_id == "AKIA_PG_TEST"),
            "the AWS credential must be present before delete_key"
        );

        store.delete_key("vk_pg").unwrap();
        // CASCADE: the key, its token ledger, AND its AWS credential are all gone.
        assert!(store.get_key("vk_pg").unwrap().is_none());
        assert_eq!(
            store.get_usage("vk_pg", 100).unwrap(),
            UsageLedger::default(),
            "delete_key must cascade to the token ledger"
        );
        assert!(
            !store
                .list_aws_credentials()
                .unwrap()
                .iter()
                .any(|c| c.access_key_id == "AKIA_PG_TEST"),
            "delete_key must cascade to the AWS credentials (credential cleanup, P1 #6)"
        );
    }

    /// H1 (data-loss regression): migrate() must NEVER conflate a transient version-read error with
    /// a fresh (unversioned) database. Only SQLSTATE 42P01 (`undefined_table`) counts as version 0;
    /// every OTHER error class (connection/timeout/permission/syntax) is fatal and must PROPAGATE so
    /// boot fails LOUDLY rather than defaulting to 0 and dropping every governance table on a healthy
    /// v2 DB. This test builds REAL driver errors from a live connection and asserts the classifier:
    /// a genuine missing-table error is version-0; any other error is NOT (so migrate returns Err).
    /// Gated on `BUSBAR_TEST_POSTGRES_URL` (skips locally, HARD-FAILS in CI - same policy as the
    /// round-trip test).
    #[test]
    fn migrate_version_read_error_is_not_treated_as_fresh_db() {
        let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
            Ok(url) => url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!(
                    "BUSBAR_TEST_POSTGRES_URL is unset under CI: refusing to silently skip the H1 \
                     data-loss regression (see .github/workflows/ci.yml)."
                );
            }
            Err(_) => {
                eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the H1 migrate regression");
                return;
            }
        };
        // Migrate first so `busbar_schema` exists - the undefined-COLUMN probe below then isolates
        // a non-42P01 error class (a missing table would itself be 42P01 and confuse the assertion).
        let store = PostgresStore::connect(&url).expect("connect+migrate");
        let mut client = Client::connect(&url, NoTls).expect("connect");

        // A genuine missing table (42P01) is the ONLY error migrate() may read as "version 0".
        let missing = client
            .query_opt("SELECT MAX(version) FROM busbar_no_such_table_zzz_h1", &[])
            .expect_err("querying a missing table must error");
        assert!(
            is_undefined_table(&missing),
            "a missing-table read must classify as undefined_table (version 0), got {:?}",
            missing.code()
        );

        // A DIFFERENT error class (undefined COLUMN, 42703) against the EXISTING busbar_schema table
        // must NOT be read as version 0 - migrate() propagates it and fails boot. This is the exact
        // class the old `.ok().flatten()...unwrap_or(0)` swallowed, then dropped every table.
        let other = client
            .query_opt("SELECT no_such_column_zzz_h1 FROM busbar_schema", &[])
            .expect_err("querying a missing column must error");
        assert_eq!(
            other.code(),
            Some(&postgres::error::SqlState::UNDEFINED_COLUMN),
            "sanity: the probe hits the missing-column class, not a missing-table"
        );
        assert!(
            !is_undefined_table(&other),
            "a non-missing-table error must NOT classify as version 0 (must fail boot), got {:?}",
            other.code()
        );

        // End to end: a healthy v2 DB carrying data survives a re-run of migrate() (connect() runs
        // it). Seed a key, reconnect (re-migrate), and assert the key is STILL there - the legacy
        // DROP path never fires on a correctly-read v2 version.
        let key = VirtualKey {
            id: "vk_h1".into(),
            key_hash: "h1_hash".into(),
            name: "h1".into(),
            allowed_pools: vec![],
            max_budget_cents: None,
            budget_period: "total".into(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 1,
            budget_group: None,
            labels: std::collections::BTreeMap::new(),
        };
        let _ = store.delete_key("vk_h1");
        store.put_key(&key).unwrap();
        drop(store);
        let store2 = PostgresStore::connect(&url).expect("re-connect+re-migrate");
        assert!(
            store2.get_key("vk_h1").unwrap().is_some(),
            "a healthy v2 DB must NOT be dropped by a migrate() re-run"
        );
        store2.delete_key("vk_h1").unwrap();
    }
}
