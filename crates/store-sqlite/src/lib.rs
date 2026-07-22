// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store — the default `db` plugin.
//! Implements `busbar_api::store::Store` over an embedded, mutex-guarded rusqlite `Connection`,
//! depending only on the `busbar-api` contract (plus rusqlite), never on the engine.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

// rusqlite error -> the api's backend-agnostic `StoreError` (the contract crate stays storage-free,
// so the `From` impl that powers `?` cannot live there). Replace `<rusqlite call>?` with `<call>.store()?`.
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, rusqlite::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
    }
}

/// Store schema version, kept in SQLite's `PRAGMA user_version`. v2 = the 1.5.0 cost-model schema:
/// the scalar `usage_counters` table (stored `spend_cents` - a derived dollar persisted as truth)
/// is REPLACED by the per-(bucket, window[, model]) token-ledger pair `usage_windows` +
/// `usage_ledger`, and `virtual_keys` grows `budget_group` + `labels`. 1.5.0 is UNRELEASED, so the
/// bump is destructive (drop + recreate), never a migration: a pre-v2 dev database is recreated
/// empty on open.
const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS virtual_keys (
    id               TEXT PRIMARY KEY,
    key_hash         TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    allowed_pools    TEXT NOT NULL DEFAULT '',
    max_budget_cents INTEGER,
    budget_period    TEXT NOT NULL DEFAULT 'total',
    rpm_limit        INTEGER,
    tpm_limit        INTEGER,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL,
    budget_group     TEXT,
    labels           TEXT NOT NULL DEFAULT '{}'
);
-- AWS-style credentials for inbound SigV4 verification (the MinIO/S3-compatible model), kept in a
-- SEPARATE table keyed by the virtual key's id rather than as columns on `virtual_keys`. This keeps
-- the `VirtualKey` row shape (and every existing construction of it elsewhere) unchanged while still
-- TYING the credential to the key: `access_key_id` is the plaintext lookup handle carried in the
-- SigV4 `Authorization` header, and `secret_access_key` is the symmetric signing secret (stored in
-- plaintext because HMAC verification needs the same value the client signs with). `access_key_id`
-- is the PRIMARY KEY (a given AccessKeyId resolves to exactly one key); `key_id` carries the FK
-- relationship to `virtual_keys.id`. Rows are removed when the owning key is deleted (see
-- `delete_key`), so a revoked key's AWS credential cannot outlive it.
CREATE TABLE IF NOT EXISTS aws_credentials (
    access_key_id     TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    secret_access_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aws_credentials_key_id ON aws_credentials (key_id);
-- The TOKEN LEDGER (v2): per-(bucket, window) request counts + per-(bucket, window, model) tier
-- token counts. `bucket_id` is a virtual key's id OR a budget-group bucket id - key buckets and
-- group buckets share the shape. NO spend column: dollars are derived at read time from
-- `ledger x rate_card` in the engine, so correcting a rate is a config edit, never a data fix.
CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    requests     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    bucket_id          TEXT NOT NULL,
    window_start       INTEGER NOT NULL,
    model              TEXT NOT NULL,
    tokens_input       INTEGER NOT NULL DEFAULT 0,
    tokens_output      INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read  INTEGER NOT NULL DEFAULT 0,
    tokens_cache_write INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model)
);
CREATE TABLE IF NOT EXISTS usage_metering (
    key_id                TEXT NOT NULL,
    bucket                INTEGER NOT NULL,
    model                 TEXT NOT NULL,
    provider              TEXT NOT NULL,
    tokens_input          INTEGER NOT NULL DEFAULT 0,
    tokens_output         INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read     INTEGER NOT NULL DEFAULT 0,
    tokens_cache_creation INTEGER NOT NULL DEFAULT 0,
    requests              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider)
);
-- The admin AUDIT log's durable home (design: the audit log persists through the configured store).
-- Append-only; `seq` is the engine's monotonic sequence (unique within a process lineage, continued
-- across restart) and the primary key. The engine computes the hash chain — the store persists each
-- record verbatim (INSERT OR REPLACE on `seq` so a replay of the same seq is idempotent) and returns
-- them oldest-first for the boot restore. No secret: action/resource/outcome/principal metadata only.
CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
";

/// Embedded SQLite `Store` backend (durable; opt-in via `governance.store: sqlite`). The single
/// `Connection` is mutex-guarded; the governance surface is low-frequency (key CRUD) or batched
/// (usage), so it is never on the request hot path.
pub struct SqliteStore {
    // A single mutex-guarded connection. Governance is off the request hot path (key CRUD, batched
    // usage, the write-behind flush), so serializing all access on one connection is fine.
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &str, busy_timeout_ms: i64) -> StoreResult<Self> {
        let conn = Connection::open(path).store()?;
        // Harden the on-disk DB against `SQLITE_BUSY` from a second connection or an external tool
        // (backup/inspection): WAL lets readers and a writer proceed concurrently, and a 5s busy
        // timeout makes a transient lock contention retry-then-succeed rather than fail instantly.
        // Skip both for an in-memory path: `:memory:` ignores WAL (no rollback journal file exists)
        // and has no second connection to contend with, so the pragmas are inapplicable there.
        if !path.starts_with(":memory:") && !path.contains("mode=memory") {
            // `journal_mode` returns the resulting mode as a row, so use `pragma_update`/query rather
            // than `execute` (which rejects a statement that yields rows). `busy_timeout` is a plain
            // setter and is safe via `execute_batch`.
            conn.pragma_update(None, "journal_mode", "WAL").store()?;
            conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
                .store()?;
        }
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory SQLite store, for unit tests.
    pub fn open_in_memory() -> StoreResult<Self> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory().store()?),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Acquire the SQLite connection mutex, recovering from a poisoned lock instead of panicking.
    /// Mirrors `rate_write`/`caches_read`: this lock is reachable from the request path (the atomic
    /// admission charge in `charge_within_budget_async` → `charge_within_budget_inner` runs inside
    /// `spawn_blocking`), and the project
    /// rule is no panic on the request path. A panic under the connection lock would otherwise poison
    /// it and cascade into a governance-wide outage on every subsequent CRUD/usage call. SQLite's own
    /// state stays consistent across a recovered guard (a panicked statement is rolled back by
    /// rusqlite's Drop), so continuing with `into_inner()` is safe.
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        Self::lock_conn_raw(&self.conn)
    }

    /// Poison-recovering lock of a raw `&Mutex<Connection>` — same rationale as [`Self::lock_conn`],
    /// but takes the mutex by reference so the shared `*_inner` SQL bodies can lock it without `&self`.
    fn lock_conn_raw(conn: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
        conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> StoreResult<()> {
        let conn = self.lock_conn();
        // SCHEMA-VERSION BUMP (v2, the 1.5.0 token-ledger cost model). 1.5.0 is unreleased, so a
        // pre-v2 database (user_version < 2 with any governance table already present) is DROPPED
        // and recreated - a bump, not a migration. A fresh database (no tables) simply creates the
        // v2 schema; a v2 database is untouched (idempotent CREATE IF NOT EXISTS).
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .store()?;
        if version < SCHEMA_VERSION {
            let has_legacy: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='usage_counters')
                       OR EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='virtual_keys')",
                    [],
                    |r| r.get(0),
                )
                .store()?;
            if has_legacy {
                conn.execute_batch(
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
        conn.execute_batch(SCHEMA).store()?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        Ok(())
    }

    // ── Shared SQL bodies for the accounting methods ─────────────────────────────────────────────
    // Each `*_inner` holds the EXACT SQL of its accounting method, locking the passed connection mutex
    // (poison-recovering). Takes no `&self`, so it is shared without borrowing the store.

    fn put_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): replace the whole (bucket, window) record -
        // the requests row AND every model row - in ONE transaction, so a re-flush of the same cell
        // is idempotent and a reader never sees half a ledger. Clamp u64 counts into i64 (a value
        // above i64::MAX pins, never wraps).
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=?1 AND window_start=?2",
            params![bucket_id, window_start as i64],
        )
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests)
             VALUES (?1,?2,?3)
             ON CONFLICT(bucket_id, window_start) DO UPDATE SET requests = excluded.requests",
            params![
                bucket_id,
                window_start as i64,
                i64::try_from(ledger.requests).unwrap_or(i64::MAX)
            ],
        )
        .store()?;
        for m in &ledger.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    bucket_id,
                    window_start as i64,
                    m.model,
                    i64::try_from(m.tokens.input).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.output).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_read).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_write).unwrap_or(i64::MAX),
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> StoreResult<()> {
        // ADDITIVE fleet-honest accumulate: the signed requests delta plus every per-model tier
        // delta land in ONE transaction (atomic across the two tables), each counter floored at 0
        // so a refund can never drive a durable counter negative.
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests)
             VALUES (?1,?2,MAX(0,?3))
             ON CONFLICT(bucket_id, window_start) DO UPDATE SET
                requests = MAX(0, requests + ?3)",
            params![bucket_id, window_start as i64, delta.requests],
        )
        .store()?;
        for m in &delta.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,MAX(0,?4),MAX(0,?5),MAX(0,?6),MAX(0,?7))
                 ON CONFLICT(bucket_id, window_start, model) DO UPDATE SET
                    tokens_input       = MAX(0, tokens_input + ?4),
                    tokens_output      = MAX(0, tokens_output + ?5),
                    tokens_cache_read  = MAX(0, tokens_cache_read + ?6),
                    tokens_cache_write = MAX(0, tokens_cache_write + ?7)",
                params![
                    bucket_id,
                    window_start as i64,
                    m.model,
                    m.tokens.input,
                    m.tokens.output,
                    m.tokens.cache_read,
                    m.tokens.cache_write,
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering_inner(conn: &Mutex<Connection>, d: &MeteringDelta) -> StoreResult<()> {
        let conn = Self::lock_conn_raw(conn);
        conn.execute(
            "INSERT INTO usage_metering (key_id, bucket, model, provider,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1)
             ON CONFLICT(key_id, bucket, model, provider) DO UPDATE SET
                 tokens_input          = tokens_input + excluded.tokens_input,
                 tokens_output         = tokens_output + excluded.tokens_output,
                 tokens_cache_read     = tokens_cache_read + excluded.tokens_cache_read,
                 tokens_cache_creation = tokens_cache_creation + excluded.tokens_cache_creation,
                 requests              = requests + 1",
            params![
                d.key_id,
                d.bucket as i64,
                d.model,
                d.provider,
                i64::try_from(d.tokens_input).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_output).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_cache_read).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_cache_creation).unwrap_or(i64::MAX),
            ],
        )
        .store()?;
        Ok(())
    }

    fn list_metering_inner(conn: &Mutex<Connection>, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let conn = Self::lock_conn_raw(conn);
        let mut stmt = conn
            .prepare(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests
             FROM usage_metering WHERE bucket = ?1",
            )
            .store()?;
        let rows = stmt
            .query_map(params![bucket as i64], |r| {
                // DI-3 posture (matches get_usage): clamp a corrupt negative stored counter to 0
                // instead of wrapping a negative i64 to a huge u64 via `as`.
                let u = |v: i64| v.max(0) as u64;
                Ok(MeteringRow {
                    key_id: r.get(0)?,
                    model: r.get(1)?,
                    provider: r.get(2)?,
                    tokens_input: u(r.get(3)?),
                    tokens_output: u(r.get(4)?),
                    tokens_cache_read: u(r.get(5)?),
                    tokens_cache_creation: u(r.get(6)?),
                    requests: u(r.get(7)?),
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn get_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
    ) -> StoreResult<UsageLedger> {
        // Read the requests row + every model row inside ONE transaction so a concurrent
        // `put_usage`/`add_usage` (another process on the same file) can never yield a torn ledger.
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        let requests: Option<i64> = tx
            .query_row(
                "SELECT requests FROM usage_windows WHERE bucket_id=?1 AND window_start=?2",
                params![bucket_id, window_start as i64],
                |r| r.get(0),
            )
            .optional()
            .store()?;
        let mut ledger = UsageLedger {
            // DI-3: clamp a (corrupt / direct-DB) negative stored counter to 0 instead of wrapping
            // a negative i64 to a huge u64 via `as`.
            requests: requests.unwrap_or(0).max(0) as u64,
            models: Vec::new(),
        };
        {
            let mut stmt = tx
                .prepare(
                    "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                     FROM usage_ledger WHERE bucket_id=?1 AND window_start=?2 ORDER BY model",
                )
                .store()?;
            let rows = stmt
                .query_map(params![bucket_id, window_start as i64], |r| {
                    let u = |v: i64| v.max(0) as u64;
                    Ok(ModelTokens {
                        model: r.get(0)?,
                        tokens: TierTokens {
                            input: u(r.get(1)?),
                            output: u(r.get(2)?),
                            cache_read: u(r.get(3)?),
                            cache_write: u(r.get(4)?),
                        },
                    })
                })
                .store()?
                .collect::<Result<Vec<_>, _>>()
                .store()?;
            ledger.models = rows;
        }
        tx.commit().store()?;
        Ok(ledger)
    }
}

// `allowed_pools` is stored in the `allowed_pools TEXT` column. The historical format was a bare
// comma-delimited string, which CORRUPTS any pool name containing a comma: a single intended pool
// `"prod,special"` round-trips as two pools `["prod", "special"]`, so `pool_allowed` matches EITHER
// fragment (a silent privilege expansion) and never matches the real compound name (a silent deny).
// A JSON array is delimiter-safe for arbitrary string values, so we now SERIALIZE as JSON. We still
// READ legacy comma-delimited rows transparently (a value that is not valid JSON array TEXT — i.e.
// every row written before this change — falls back to the comma split), so an existing on-disk DB
// keeps working without a migration. New writes are always JSON, so a comma-bearing name survives a
// write/read round-trip exactly.
fn pools_to_storage(pools: &[String]) -> String {
    // serde_json::to_string over a `&[String]` is infallible (no map keys, no non-finite floats),
    // but we must not panic on the admin write path: on the unreachable error fall back to the empty
    // JSON array, which `pools_from_storage` reads back as "no restriction" — fail-safe, and far
    // better than aborting the request task.
    serde_json::to_string(pools).unwrap_or_else(|_| "[]".to_string())
}
fn pools_from_storage(stored: &str) -> Vec<String> {
    let trimmed = stored.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // New format: a JSON array of strings. Parse it as the source of truth.
    if let Ok(pools) = serde_json::from_str::<Vec<String>>(trimmed) {
        return pools;
    }
    // Legacy format (written before the JSON migration): bare comma-delimited string. A comma-free
    // legacy value round-trips identically; a comma-bearing one is preserved as-is by future JSON
    // writes once the key is next persisted.
    trimmed.split(',').map(String::from).collect()
}

// Shared SQL bodies for the key/credential UPSERTs, so the autocommit single-statement methods
// (`put_key`, `put_aws_credential`) and the transactional mint (`put_key_with_aws_credential`) hold
// the SQL EXACTLY ONCE and can never drift. `rusqlite::Transaction` derefs to `Connection`, so a
// `&tx` coerces to `&Connection` here — the same body runs whether `conn` is a plain connection
// guard or a transaction. The SQL is byte-for-byte the original inline statements.

fn put_key_inner(conn: &rusqlite::Connection, key: &VirtualKey) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO virtual_keys
                (id, key_hash, name, allowed_pools, max_budget_cents, budget_period, rpm_limit, tpm_limit, enabled, created_at, budget_group, labels)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(id) DO UPDATE SET
                key_hash=excluded.key_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
                max_budget_cents=excluded.max_budget_cents, budget_period=excluded.budget_period,
                rpm_limit=excluded.rpm_limit, tpm_limit=excluded.tpm_limit, enabled=excluded.enabled,
                budget_group=excluded.budget_group, labels=excluded.labels",
        params![
            key.id,
            key.key_hash,
            key.name,
            pools_to_storage(&key.allowed_pools),
            key.max_budget_cents,
            key.budget_period,
            key.rpm_limit,
            key.tpm_limit,
            key.enabled as i64,
            key.created_at as i64,
            key.budget_group,
            labels_to_storage(&key.labels),
        ],
    ).store()?;
    Ok(())
}

/// `labels` persist as a JSON object in the `labels TEXT` column (delimiter-safe for arbitrary
/// operator strings, mirroring the `allowed_pools` JSON storage). Serialization over a
/// `BTreeMap<String, String>` is infallible; fall back to `{}` rather than panic on a write path.
fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}

fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

fn put_aws_credential_inner(conn: &rusqlite::Connection, cred: &AwsCredential) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(access_key_id) DO UPDATE SET
                key_id=excluded.key_id, secret_access_key=excluded.secret_access_key",
        params![cred.access_key_id, cred.key_id, cred.secret_access_key],
    )
    .store()?;
    Ok(())
}

impl Store for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        put_key_inner(&self.lock_conn(), key)
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels
                 FROM virtual_keys WHERE id=?1",
                params![id],
                row_to_key,
            )
            .optional().store()?;
        Ok(row)
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels
             FROM virtual_keys ORDER BY created_at",
        ).store()?;
        let rows = stmt.query_map([], row_to_key).store()?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.store()?);
        }
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Both DELETEs must be atomic. Under SQLite autocommit each `execute` commits on its own, so
        // a failure of the second statement (I/O error, disk full, constraint) would leave the key
        // row gone but its usage_counters rows orphaned — accumulating forever and, worse, poisoning
        // any future key re-created with the same id with stale usage. Wrap both in one transaction
        // so they commit together or not at all. The Mutex already serializes us against other
        // writers, so the transaction cannot deadlock against a concurrent busbar caller.
        let mut conn = self.lock_conn();
        let tx = conn.transaction().store()?;
        tx.execute("DELETE FROM virtual_keys WHERE id=?1", params![id])
            .store()?;
        tx.execute("DELETE FROM usage_windows WHERE bucket_id=?1", params![id])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE bucket_id=?1", params![id])
            .store()?;
        // Remove any AWS credential rows tied to this key in the SAME transaction: a revoked key's
        // SigV4 credential must NOT outlive the key, or a Bedrock-SDK client signing with that
        // AccessKeyId could keep authenticating after revocation (an auth-bypass). The in-memory
        // AccessKeyId index is rebuilt on the post-delete `refresh`, and even before that rebuild the
        // index already skips a credential whose key row is gone (see `load_by_access_key_id`), so the
        // revocation is effective immediately and durably.
        tx.execute("DELETE FROM aws_credentials WHERE key_id=?1", params![id])
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        put_aws_credential_inner(&self.lock_conn(), cred)
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // ATOMIC mint: the bearer-key INSERT and its AWS-credential INSERT commit together or not at
        // all. Under autocommit a failure of the second statement would orphan the just-written key row
        // (inert: no resolvable AccessKeyId). Wrap both in one transaction — same pattern as
        // `delete_key`. The connection Mutex already serializes us against any other writer, so the
        // transaction cannot deadlock against a concurrent busbar caller.
        let mut conn = self.lock_conn();
        let tx = conn.transaction().store()?;
        // `&tx` coerces to `&Connection` via `Transaction`'s Deref, so both writes share the exact same
        // SQL bodies as the autocommit `put_key`/`put_aws_credential` — they can never drift.
        put_key_inner(&tx, key)?;
        put_aws_credential_inner(&tx, cred)?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare("SELECT access_key_id, key_id, secret_access_key FROM aws_credentials")
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AwsCredential {
                    access_key_id: r.get(0)?,
                    key_id: r.get(1)?,
                    secret_access_key: r.get(2)?,
                })
            })
            .store()?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.store()?);
        }
        Ok(out)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        Self::put_usage_inner(&self.conn, bucket_id, window_start, ledger)
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        Self::add_usage_inner(&self.conn, bucket_id, window_start, delta)
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        Self::add_metering_inner(&self.conn, delta)
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Self::list_metering_inner(&self.conn, bucket)
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Self::get_usage_inner(&self.conn, bucket_id, window_start)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // INSERT OR REPLACE on the `seq` PK: append-only in practice, but idempotent if the engine
        // ever re-writes a record for the same seq (e.g. a snapshot replay), never a UNIQUE error.
        self.lock_conn()
            .execute(
                "INSERT OR REPLACE INTO audit_log
                    (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    entry.seq as i64,
                    entry.ts as i64,
                    entry.action,
                    entry.resource,
                    entry.outcome,
                    entry.principal,
                    entry.prev_hash,
                    entry.hash,
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq",
            )
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AuditRecord {
                    seq: r.get::<_, i64>(0)?.max(0) as u64,
                    ts: r.get::<_, i64>(1)?.max(0) as u64,
                    action: r.get(2)?,
                    resource: r.get(3)?,
                    outcome: r.get(4)?,
                    principal: r.get(5)?,
                    prev_hash: r.get(6)?,
                    hash: r.get(7)?,
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // BOUNDED restore read (audit issue): select only the most-recent `limit` rows at the SOURCE
        // (a `LIMIT` on a descending scan), then reverse into oldest-first. This keeps the ABI
        // response and the engine ring bounded regardless of how large the never-pruned durable log
        // has grown, so restore cannot exceed the plugin response cap or OOM.
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq DESC LIMIT ?1",
            )
            .store()?;
        let mut rows = stmt
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                Ok(AuditRecord {
                    seq: r.get::<_, i64>(0)?.max(0) as u64,
                    ts: r.get::<_, i64>(1)?.max(0) as u64,
                    action: r.get(2)?,
                    resource: r.get(3)?,
                    outcome: r.get(4)?,
                    principal: r.get(5)?,
                    prev_hash: r.get(6)?,
                    hash: r.get(7)?,
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        rows.reverse(); // DESC LIMIT gave newest-first; the restore contract is oldest-first.
        Ok(rows)
    }
}

// Hash-lookup primitive retained for the governance unit tests that pin the by-hash resolution
// semantics. (The legacy direct-SQL charge/refund/add primitives died with `usage_counters` - v2
// production enforcement is the in-memory chain charge in `GovState`; the store is a pure
// write-behind ledger.)
impl SqliteStore {
    pub fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at,budget_group,labels
                 FROM virtual_keys WHERE key_hash=?1",
                params![key_hash],
                row_to_key,
            )
            .optional().store()?;
        Ok(row)
    }
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<VirtualKey> {
    Ok(VirtualKey {
        id: r.get(0)?,
        key_hash: r.get(1)?,
        name: r.get(2)?,
        allowed_pools: pools_from_storage(&r.get::<_, String>(3)?),
        max_budget_cents: r.get(4)?,
        budget_period: r.get(5)?,
        // DI-2: a direct-DB value above u32::MAX would silently wrap to a WRONG (lower) cap with
        // `as u32`. Saturate instead — the admin API already bounds these on the write path; this
        // closes the direct-DB hole.
        rpm_limit: r
            .get::<_, Option<i64>>(6)?
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
        tpm_limit: r
            .get::<_, Option<i64>>(7)?
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
        enabled: r.get::<_, i64>(8)? != 0,
        created_at: r.get::<_, i64>(9)? as u64,
        budget_group: r.get(10)?,
        labels: labels_from_storage(&r.get::<_, String>(11)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::{ModelTokensDelta, Store, TierTokensDelta, VirtualKey};
    use rusqlite::params;

    fn sample_key(id: &str, hash: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            key_hash: hash.to_string(),
            name: "test".to_string(),
            allowed_pools: vec![],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn delta(requests: i64, model: &str, input: i64, output: i64) -> UsageDelta {
        UsageDelta {
            requests,
            models: vec![ModelTokensDelta {
                model: model.to_string(),
                tokens: TierTokensDelta {
                    input,
                    output,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        }
    }

    /// The TRAIT `add_usage` (fleet-additive flush primitive) accumulates per-model signed deltas
    /// atomically and floors at 0 on an over-refund; `put_usage` stays an absolute overwrite.
    #[test]
    fn trait_add_usage_accumulates_and_floors() {
        let s = SqliteStore::open(":memory:", 5000).unwrap();
        let base = UsageLedger {
            requests: 3,
            models: vec![ModelTokens {
                model: "gpt-5".into(),
                tokens: TierTokens {
                    input: 9,
                    output: 4,
                    cache_read: 1,
                    cache_write: 0,
                },
            }],
        };
        s.put_usage("k_add", 100, &base).unwrap();
        Store::add_usage(&s, "k_add", 100, &delta(2, "gpt-5", 1, 1)).unwrap();
        let u = s.get_usage("k_add", 100).unwrap();
        assert_eq!(u.requests, 5);
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!((t.input, t.output, t.cache_read), (10, 5, 1));
        // A second model materializes its own row.
        Store::add_usage(&s, "k_add", 100, &delta(0, "haiku", 7, 3)).unwrap();
        assert_eq!(s.get_usage("k_add", 100).unwrap().models.len(), 2);
        // Negative (refund) delta lands; an over-refund floors at 0.
        Store::add_usage(&s, "k_add", 100, &delta(-10, "gpt-5", -100, -100)).unwrap();
        let u = s.get_usage("k_add", 100).unwrap();
        assert_eq!(u.requests, 0);
        assert_eq!(u.tokens_for("gpt-5").unwrap().input, 0);
        // Fresh row via add alone (INSERT arm), floored on a negative first delta.
        Store::add_usage(&s, "k_new", 100, &delta(1, "m", -5, 7)).unwrap();
        let u = s.get_usage("k_new", 100).unwrap();
        assert_eq!(u.requests, 1);
        let t = u.tokens_for("m").unwrap();
        assert_eq!((t.input, t.output), (0, 7));
    }

    /// `put_usage` is an ABSOLUTE overwrite: a model row present in the old snapshot but absent
    /// from the new one is REMOVED (the whole (bucket, window) record is replaced).
    #[test]
    fn put_usage_replaces_whole_ledger() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.put_usage(
            "k",
            0,
            &UsageLedger {
                requests: 2,
                models: vec![
                    ModelTokens {
                        model: "a".into(),
                        tokens: TierTokens {
                            input: 1,
                            output: 1,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    },
                    ModelTokens {
                        model: "b".into(),
                        tokens: TierTokens {
                            input: 2,
                            output: 2,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    },
                ],
            },
        )
        .unwrap();
        s.put_usage(
            "k",
            0,
            &UsageLedger {
                requests: 1,
                models: vec![ModelTokens {
                    model: "a".into(),
                    tokens: TierTokens {
                        input: 9,
                        output: 0,
                        cache_read: 0,
                        cache_write: 0,
                    },
                }],
            },
        )
        .unwrap();
        let u = s.get_usage("k", 0).unwrap();
        assert_eq!(u.requests, 1);
        assert_eq!(
            u.models.len(),
            1,
            "stale model rows are replaced, not merged"
        );
        assert_eq!(u.tokens_for("a").unwrap().input, 9);
    }

    /// SCHEMA BUMP (v2): opening a database that still carries the pre-cost-model `usage_counters`
    /// schema DROPS and recreates the governance tables (1.5.0 unreleased: bump, not migrate) and
    /// stamps `user_version = 2`. A v2 database re-opens untouched.
    #[test]
    fn legacy_schema_is_bumped_to_v2_on_open() {
        let dir = std::env::temp_dir().join(format!("busbar-sqlite-bump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.db");
        let path_str = path.to_str().unwrap().to_string();
        {
            // Write a legacy (v1-shaped) database by hand.
            let conn = Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE virtual_keys (
                     id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                     allowed_pools TEXT NOT NULL DEFAULT '', max_budget_cents INTEGER,
                     budget_period TEXT NOT NULL DEFAULT 'total', rpm_limit INTEGER,
                     tpm_limit INTEGER, enabled INTEGER NOT NULL DEFAULT 1,
                     created_at INTEGER NOT NULL);
                 CREATE TABLE usage_counters (
                     key_id TEXT NOT NULL, window_start INTEGER NOT NULL,
                     spend_cents INTEGER NOT NULL DEFAULT 0, tokens INTEGER NOT NULL DEFAULT 0,
                     requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key_id, window_start));
                 INSERT INTO usage_counters VALUES ('vk_old', 0, 42, 9, 3);",
            )
            .unwrap();
        }
        let s = SqliteStore::open(&path_str, 5000).unwrap();
        // The legacy table is gone; the v2 ledger is empty and functional.
        assert_eq!(s.get_usage("vk_old", 0).unwrap(), UsageLedger::default());
        Store::add_usage(&s, "vk_old", 0, &delta(1, "m", 1, 1)).unwrap();
        assert_eq!(s.get_usage("vk_old", 0).unwrap().requests, 1);
        let version: i64 = s
            .lock_conn()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // Re-open: v2 data survives (no re-drop).
        drop(s);
        let s2 = SqliteStore::open(&path_str, 5000).unwrap();
        assert_eq!(
            s2.get_usage("vk_old", 0).unwrap().requests,
            1,
            "a v2 database must re-open without being dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `budget_group` + `labels` persist through the sqlite row round-trip.
    #[test]
    fn budget_group_and_labels_roundtrip() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut k = sample_key("kg", "hashG");
        k.budget_group = Some("growth".to_string());
        k.labels = std::collections::BTreeMap::from([
            ("team".to_string(), "growth".to_string()),
            ("env".to_string(), "prod".to_string()),
        ]);
        s.put_key(&k).unwrap();
        let got = s.get_key("kg").unwrap().unwrap();
        assert_eq!(got.budget_group.as_deref(), Some("growth"));
        assert_eq!(got.labels.get("env").map(String::as_str), Some("prod"));
        assert_eq!(got, k);
    }

    /// DI-2: a direct-DB `rpm_limit`/`tpm_limit` above `u32::MAX` must SATURATE to `u32::MAX` on read,
    /// not wrap to a wrong (lower) cap via `as u32`.
    #[test]
    fn test_rpm_tpm_above_u32max_saturate_on_read() {
        let s = SqliteStore::open_in_memory().unwrap();
        let k = sample_key("kbig", "hashBIG");
        s.put_key(&k).unwrap();
        let huge: i64 = i64::from(u32::MAX) + 1_000;
        {
            let conn = s.lock_conn();
            conn.execute(
                "UPDATE virtual_keys SET rpm_limit=?1, tpm_limit=?2 WHERE id='kbig'",
                params![huge, huge],
            )
            .unwrap();
        }
        let got = s.get_key("kbig").unwrap().unwrap();
        assert_eq!(got.rpm_limit, Some(u32::MAX));
        assert_eq!(got.tpm_limit, Some(u32::MAX));
    }

    /// DI-3: direct-DB NEGATIVE stored ledger counters clamp to 0 on read, never wrap to a huge u64.
    #[test]
    fn test_negative_ledger_counters_clamp_to_zero_on_read() {
        let s = SqliteStore::open_in_memory().unwrap();
        {
            let conn = s.lock_conn();
            conn.execute(
                "INSERT INTO usage_windows (bucket_id, window_start, requests) VALUES ('kneg', 0, -3)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO usage_ledger (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES ('kneg', 0, 'm', -5, -1, -2, -4)",
                [],
            )
            .unwrap();
        }
        let u = s.get_usage("kneg", 0).unwrap();
        assert_eq!(
            u.requests, 0,
            "a negative stored request counter must clamp to 0"
        );
        let t = u.tokens_for("m").unwrap();
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (0, 0, 0, 0),
            "negative stored token counters clamp to 0"
        );
    }

    /// DI-3 parity for metering: a direct-DB negative metering counter clamps to 0 on read.
    #[test]
    fn test_negative_metering_counters_clamp_to_zero_on_read() {
        let s = SqliteStore::open_in_memory().unwrap();
        {
            let conn = s.lock_conn();
            conn.execute(
                    "INSERT INTO usage_metering (key_id, bucket, model, provider,
                         tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
                     VALUES ('kneg', 0, 'm', 'p', -5, -1, -2, -3, -4)",
                    [],
                )
                .unwrap();
        }
        let rows = s.list_metering(0).unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(
            (
                r.tokens_input,
                r.tokens_output,
                r.tokens_cache_read,
                r.tokens_cache_creation,
                r.requests
            ),
            (0, 0, 0, 0, 0)
        );
    }

    /// A pool name CONTAINING a comma must survive a persist/read round-trip as ONE pool.
    #[test]
    fn test_comma_bearing_pool_name_roundtrips_as_single_pool() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut k = sample_key("kc", "hashCOMMA");
        k.allowed_pools = vec!["prod,special".to_string(), "plain".to_string()];
        s.put_key(&k).unwrap();
        let got = s.get_key("kc").unwrap().unwrap();
        assert_eq!(
            got.allowed_pools,
            vec!["prod,special".to_string(), "plain".to_string()]
        );
    }

    /// `pools_from_storage` must still read a LEGACY bare comma-delimited row.
    #[test]
    fn test_pools_from_storage_reads_legacy_csv() {
        assert_eq!(
            pools_from_storage("[\"a\",\"b\"]"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            pools_from_storage("a,b"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(pools_from_storage("solo"), vec!["solo".to_string()]);
        assert!(pools_from_storage("").is_empty());
        assert!(pools_from_storage("[]").is_empty());
    }

    #[test]
    fn test_poisoned_conn_lock_recovers_not_panics() {
        // Regression: a panic while the SqliteStore `conn` Mutex is held poisons it. Every `Store`
        // method acquires the connection via `lock_conn`, which must RECOVER (via into_inner)
        // rather than `.unwrap()`-panic on every subsequent call.
        use std::sync::Arc;

        let s = Arc::new(SqliteStore::open_in_memory().unwrap());
        Store::add_usage(&*s, "k_poison", 100, &delta(1, "m", 50, 0)).unwrap();

        let s2 = Arc::clone(&s);
        let _ = std::thread::spawn(move || {
            let _guard = s2.conn.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(
            s.conn.is_poisoned(),
            "conn lock must be poisoned for the test"
        );

        assert_eq!(
            s.get_usage("k_poison", 100).unwrap().requests,
            1,
            "get_usage must recover the poisoned conn lock instead of panicking"
        );
        Store::add_usage(&*s, "k_poison", 100, &delta(1, "m", 25, 0)).unwrap();
        let u = s.get_usage("k_poison", 100).unwrap();
        assert_eq!(u.requests, 2);
        assert_eq!(u.tokens_for("m").unwrap().input, 75);
    }

    /// Durable audit (#17): `append_audit` persists records and `list_audit` returns them
    /// oldest-first by `seq`, verbatim; a re-append of the same seq upserts (idempotent).
    #[test]
    fn test_audit_append_and_list_roundtrip() {
        use busbar_api::AuditRecord;
        let s = SqliteStore::open_in_memory().unwrap();
        let mk = |seq: u64, prev: &str, hash: &str| AuditRecord {
            seq,
            ts: 1000 + seq,
            action: "hook.register".into(),
            resource: format!("hook:{seq}"),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: prev.into(),
            hash: hash.into(),
        };
        s.append_audit(&mk(2, "h1", "h2")).unwrap();
        s.append_audit(&mk(1, "", "h1")).unwrap();
        s.append_audit(&mk(3, "h2", "h3")).unwrap();
        let got = s.list_audit().unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].seq, got[1].seq, got[2].seq), (1, 2, 3));
        assert_eq!(got[0].prev_hash, "");
        assert_eq!(got[1].prev_hash, "h1");
        s.append_audit(&mk(2, "h1", "h2b")).unwrap();
        let got2 = s.list_audit().unwrap();
        assert_eq!(got2.len(), 3);
        assert_eq!(got2[1].hash, "h2b");
    }

    #[test]
    fn test_key_crud_roundtrip() {
        let s = SqliteStore::open_in_memory().unwrap();
        let k = sample_key("k1", "hashAAA");
        s.put_key(&k).unwrap();

        assert_eq!(s.get_key("k1").unwrap().as_ref(), Some(&k));
        assert_eq!(s.get_key_by_hash("hashAAA").unwrap().as_ref(), Some(&k));
        assert_eq!(s.get_key("missing").unwrap(), None);
        assert_eq!(s.list_keys().unwrap(), vec![k.clone()]);

        let mut k2 = k.clone();
        k2.enabled = false;
        k2.allowed_pools = vec![];
        s.put_key(&k2).unwrap();
        let got = s.get_key("k1").unwrap().unwrap();
        assert!(!got.enabled);
        assert!(got.allowed_pools.is_empty());

        s.delete_key("k1").unwrap();
        assert_eq!(s.get_key("k1").unwrap(), None);
    }

    #[test]
    fn test_delete_key_removes_key_and_ledger_atomically() {
        // After delete, both the key row AND all of its ledger rows across windows are gone.
        let s = SqliteStore::open_in_memory().unwrap();
        let key = sample_key("vk_delete_me", "hash_delete_me");
        s.put_key(&key).unwrap();
        Store::add_usage(&s, "vk_delete_me", 100, &delta(1, "m", 1000, 0)).unwrap();
        Store::add_usage(&s, "vk_delete_me", 200, &delta(1, "m", 50, 0)).unwrap();
        assert!(s.get_key("vk_delete_me").unwrap().is_some());
        assert_eq!(s.get_usage("vk_delete_me", 100).unwrap().requests, 1);

        s.delete_key("vk_delete_me").unwrap();

        assert!(s.get_key("vk_delete_me").unwrap().is_none());
        assert_eq!(
            s.get_usage("vk_delete_me", 100).unwrap(),
            UsageLedger::default()
        );
        assert_eq!(
            s.get_usage("vk_delete_me", 200).unwrap(),
            UsageLedger::default()
        );
    }

    #[test]
    fn test_delete_key_does_not_inherit_stale_ledger_on_recreate() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.put_key(&sample_key("vk_reuse", "hash_vk_reuse")).unwrap();
        Store::add_usage(&s, "vk_reuse", 100, &delta(1, "m", 9999, 0)).unwrap();
        s.delete_key("vk_reuse").unwrap();
        s.put_key(&sample_key("vk_reuse", "hash_vk_reuse")).unwrap();
        assert_eq!(
            s.get_usage("vk_reuse", 100).unwrap(),
            UsageLedger::default(),
            "re-created key must not inherit the deleted key's ledger"
        );
    }
}
