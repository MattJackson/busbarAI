// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store — the default `db` plugin.
//! Implements `busbar_api::store::Store` over an embedded, mutex-guarded rusqlite `Connection`,
//! depending only on the `busbar-api` contract (plus rusqlite), never on the engine.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage,
    VirtualKey,
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
    created_at       INTEGER NOT NULL
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
CREATE TABLE IF NOT EXISTS usage_counters (
    key_id       TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    spend_cents  INTEGER NOT NULL DEFAULT 0,
    tokens       INTEGER NOT NULL DEFAULT 0,
    requests     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, window_start)
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
        // `CREATE TABLE IF NOT EXISTS` for both `virtual_keys` and the new `aws_credentials` table is
        // idempotent and backward-compatible: an existing on-disk DB keeps its `virtual_keys` rows
        // untouched and simply gains the `aws_credentials` table (a NEW table, so no `ALTER`/column-add
        // dance and no risk to existing rows). A bearer-only DB from an older build upgrades cleanly.
        self.lock_conn().execute_batch(SCHEMA).store()?;
        Ok(())
    }

    // ── Shared SQL bodies for the accounting methods ─────────────────────────────────────────────
    // Each `*_inner` holds the EXACT SQL of its accounting method, locking the passed connection mutex
    // (poison-recovering). Takes no `&self`, so it is shared without borrowing the store.

    fn add_usage_inner(
        conn: &Mutex<Connection>,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        count_request: bool,
    ) -> StoreResult<()> {
        let req_delta = i64::from(count_request);
        let conn = Self::lock_conn_raw(conn);
        conn.execute(
            "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(key_id, window_start) DO UPDATE SET
                spend_cents = spend_cents + excluded.spend_cents,
                tokens      = tokens + excluded.tokens,
                requests    = requests + excluded.requests",
            params![
                key_id,
                window_start as i64,
                spend_cents,
                i64::try_from(tokens).unwrap_or(i64::MAX),
                req_delta
            ],
        )
        .store()?;
        Ok(())
    }

    fn put_usage_inner(
        conn: &Mutex<Connection>,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): mirrors `add_usage_inner`'s UPSERT shape but
        // the DO UPDATE SETs (not adds) each counter to the flusher's snapshot of the in-memory cell,
        // so a re-flush of the same cell is idempotent and never double-counts. Clamp the u64 counts
        // into i64 like the other inners (a value above i64::MAX pins to i64::MAX, never wraps).
        let conn = Self::lock_conn_raw(conn);
        conn.execute(
            "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(key_id, window_start) DO UPDATE SET
                spend_cents = excluded.spend_cents,
                tokens      = excluded.tokens,
                requests    = excluded.requests",
            params![
                key_id,
                window_start as i64,
                spend_cents,
                i64::try_from(tokens).unwrap_or(i64::MAX),
                i64::try_from(requests).unwrap_or(i64::MAX)
            ],
        )
        .store()?;
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

    fn charge_within_budget_inner(
        conn: &Mutex<Connection>,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        // First-request-in-window guard: if the row does not yet exist the UPSERT's INSERT branch
        // fires unconditionally (a `WHERE` clause only guards the DO UPDATE branch), so a flat fee
        // that ALONE exceeds the cap would slip in. Reject it up front — a single request costing
        // more than the whole budget can never be admitted. (cost_cents is clamped >= 0 by the
        // caller; max_cents None means uncapped.)
        if let Some(max) = max_cents {
            if cost_cents > max {
                return Ok(false);
            }
        }
        let conn = Self::lock_conn_raw(conn);
        // ONE atomic UPSERT: insert the first request in the window (always within cap given the
        // guard above), or accumulate onto an existing row ONLY IF the post-charge spend stays within
        // `max_cents`. `RETURNING` yields a row exactly when the charge landed; zero rows ⇒ the
        // conditional DO UPDATE's WHERE failed ⇒ over budget ⇒ reject. SQLite evaluates the bare
        // column names in the WHERE against the EXISTING row (pre-update), so `spend_cents + :cost`
        // is the prospective post-charge total. `:max IS NULL` (uncapped) short-circuits to always-charge.
        // OVERFLOW SAFETY: SQLite arithmetic does NOT wrap on i64 overflow — it promotes the result to
        // REAL (floating point). So if `spend_cents` were ever near i64::MAX, `spend_cents + :cost`
        // becomes a large REAL (~9.2e18) which fails `<= :max` and the charge is correctly REJECTED —
        // there is no C-style negative-wrap that could sneak a charge past the cap. (Verified empirically.)
        let charged: Option<i64> = conn
            .query_row(
                "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
                 VALUES (?1, ?2, ?3, 0, 1)
                 ON CONFLICT(key_id, window_start) DO UPDATE SET
                     spend_cents = spend_cents + ?3,
                     requests    = requests + 1
                   WHERE ?4 IS NULL OR spend_cents + ?3 <= ?4
                 RETURNING spend_cents",
                params![key_id, window_start as i64, cost_cents, max_cents],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .store()?;
        Ok(charged.is_some())
    }

    fn refund_request_inner(
        conn: &Mutex<Connection>,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
    ) -> StoreResult<()> {
        let conn = Self::lock_conn_raw(conn);
        // Reverse exactly one atomic charge: subtract the flat fee from spend and one from requests,
        // each floored at 0 (MAX(0, …)) so a refund can never push a counter negative even if windows
        // or rows were reset between charge and refund. UPDATE-only: if the row is gone there is
        // nothing to refund (a no-op, not an error).
        conn.execute(
            "UPDATE usage_counters SET
                 spend_cents = MAX(0, spend_cents - ?3),
                 requests    = MAX(0, requests - 1)
             WHERE key_id = ?1 AND window_start = ?2",
            params![key_id, window_start as i64, cost_cents],
        )
        .store()?;
        Ok(())
    }

    fn get_usage_inner(
        conn: &Mutex<Connection>,
        key_id: &str,
        window_start: u64,
    ) -> StoreResult<Usage> {
        let conn = Self::lock_conn_raw(conn);
        let row = conn
            .query_row(
                "SELECT spend_cents, tokens, requests FROM usage_counters WHERE key_id=?1 AND window_start=?2",
                params![key_id, window_start as i64],
                |r| {
                    Ok(Usage {
                        spend_cents: r.get(0)?,
                        // DI-3: clamp a (corrupt / direct-DB) negative stored counter to 0 instead
                        // of wrapping a negative i64 to a huge u64 via `as`.
                        tokens: r.get::<_, i64>(1)?.max(0) as u64,
                        requests: r.get::<_, i64>(2)?.max(0) as u64,
                    })
                },
            )
            .optional().store()?;
        Ok(row.unwrap_or_default())
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
                (id, key_hash, name, allowed_pools, max_budget_cents, budget_period, rpm_limit, tpm_limit, enabled, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET
                key_hash=excluded.key_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
                max_budget_cents=excluded.max_budget_cents, budget_period=excluded.budget_period,
                rpm_limit=excluded.rpm_limit, tpm_limit=excluded.tpm_limit, enabled=excluded.enabled",
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
        ],
    ).store()?;
    Ok(())
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
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
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
            "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
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
        tx.execute("DELETE FROM usage_counters WHERE key_id=?1", params![id])
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
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()> {
        Self::put_usage_inner(
            &self.conn,
            key_id,
            window_start,
            spend_cents,
            tokens,
            requests,
        )
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        Self::add_metering_inner(&self.conn, delta)
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Self::list_metering_inner(&self.conn, bucket)
    }

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        Self::get_usage_inner(&self.conn, key_id, window_start)
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

// Direct-store SQL primitives retained ONLY for the governance unit tests that pin their
// UPSERT/boundary and hash-lookup semantics. Production enforcement is the in-memory hard-cap in
// `GovState` (SQLite is a write-behind durability layer), so these are inherent `#[cfg(test)]`
// methods on the concrete `SqliteStore` — NOT part of the swappable `Store` plugin contract a `db`
// plugin (Postgres, …) must implement.
impl SqliteStore {
    pub fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
                 FROM virtual_keys WHERE key_hash=?1",
                params![key_hash],
                row_to_key,
            )
            .optional().store()?;
        Ok(row)
    }

    pub fn add_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        count_request: bool,
    ) -> StoreResult<()> {
        Self::add_usage_inner(
            &self.conn,
            key_id,
            window_start,
            spend_cents,
            tokens,
            count_request,
        )
    }

    pub fn charge_within_budget(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        Self::charge_within_budget_inner(&self.conn, key_id, window_start, cost_cents, max_cents)
    }

    pub fn refund_request(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
    ) -> StoreResult<()> {
        Self::refund_request_inner(&self.conn, key_id, window_start, cost_cents)
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::{Store, VirtualKey};
    use rusqlite::params;
    use std::sync::Arc;

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
        }
    }

    /// DI-2: a direct-DB `rpm_limit`/`tpm_limit` above `u32::MAX` must SATURATE to `u32::MAX` on read,
    /// not wrap to a wrong (lower) cap via `as u32`. The admin API bounds these on write; this covers
    /// the direct-DB hole.
    #[test]
    fn test_rpm_tpm_above_u32max_saturate_on_read() {
        let s = SqliteStore::open_in_memory().unwrap();
        // Seed a key the normal way to satisfy NOT NULL / schema, then poke oversized limits directly.
        let k = sample_key("kbig", "hashBIG");
        s.put_key(&k).unwrap();
        let huge: i64 = i64::from(u32::MAX) + 1_000; // > u32::MAX, fits i64
        {
            let conn = s.lock_conn();
            conn.execute(
                "UPDATE virtual_keys SET rpm_limit=?1, tpm_limit=?2 WHERE id='kbig'",
                params![huge, huge],
            )
            .unwrap();
        }
        let got = s.get_key("kbig").unwrap().unwrap();
        assert_eq!(
            got.rpm_limit,
            Some(u32::MAX),
            "an oversized rpm_limit must saturate, not wrap"
        );
        assert_eq!(
            got.tpm_limit,
            Some(u32::MAX),
            "an oversized tpm_limit must saturate, not wrap"
        );
    }

    /// DI-3: a direct-DB NEGATIVE stored token/request counter must clamp to 0 on read, not wrap to a
    /// huge u64 via `as u64`.
    #[test]
    fn test_negative_usage_counters_clamp_to_zero_on_read() {
        let s = SqliteStore::open_in_memory().unwrap();
        let window_start: i64 = 1_700_000_000;
        {
            let conn = s.lock_conn();
            conn.execute(
                "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
                     VALUES ('kneg', ?1, 0, -5, -3)",
                params![window_start],
            )
            .unwrap();
        }
        let u = s.get_usage("kneg", window_start as u64).unwrap();
        assert_eq!(
            u.tokens, 0,
            "a negative stored token counter must clamp to 0"
        );
        assert_eq!(
            u.requests, 0,
            "a negative stored request counter must clamp to 0"
        );
    }

    /// DI-3 parity with `get_usage`: a direct-DB negative metering counter clamps to 0 on read.
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
            (0, 0, 0, 0, 0),
            "negative stored metering counters clamp to 0"
        );
    }

    /// A pool name CONTAINING a comma must survive a persist/read round-trip as ONE pool, not be
    /// split into fragments. The old comma-delimited CSV storage corrupted such names (a key for
    /// `"prod,special"` round-tripped as `["prod", "special"]`, an implicit privilege expansion that
    /// also failed to match its own compound name). JSON-array storage is delimiter-safe.
    #[test]
    fn test_comma_bearing_pool_name_roundtrips_as_single_pool() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut k = sample_key("kc", "hashCOMMA");
        k.allowed_pools = vec!["prod,special".to_string(), "plain".to_string()];
        s.put_key(&k).unwrap();

        let got = s.get_key("kc").unwrap().unwrap();
        assert_eq!(
            got.allowed_pools,
            vec!["prod,special".to_string(), "plain".to_string()],
            "comma-bearing pool name must not be split on read"
        );
        // The compound name survives storage as ONE pool; splitting on the comma (the pre-JSON
        // bug) would have produced two. (ACL matching via `pool_allowed` is tested in the engine.)
    }

    /// `pools_from_storage` must still read a LEGACY bare comma-delimited row (written before the
    /// JSON migration) so an existing on-disk DB keeps working without a migration step.
    #[test]
    fn test_pools_from_storage_reads_legacy_csv() {
        // New JSON format.
        assert_eq!(
            pools_from_storage("[\"a\",\"b\"]"),
            vec!["a".to_string(), "b".to_string()]
        );
        // Legacy comma-delimited format (not valid JSON) falls back to the comma split.
        assert_eq!(
            pools_from_storage("a,b"),
            vec!["a".to_string(), "b".to_string()]
        );
        // A single legacy comma-free value.
        assert_eq!(pools_from_storage("solo"), vec!["solo".to_string()]);
        // Empty stays empty (= no restriction).
        assert!(pools_from_storage("").is_empty());
        assert!(pools_from_storage("[]").is_empty());
    }

    #[test]
    fn test_poisoned_conn_lock_recovers_not_panics() {
        // Regression: a panic while the SqliteStore `conn` Mutex is held poisons it. Every `Store`
        // method acquires the connection via `lock_conn`, which must RECOVER (via into_inner)
        // rather than `.unwrap()`-panic on every subsequent call — otherwise one transient panic
        // permanently disables governance persistence (and, via spawn_blocking join, silently fails
        // budget enforcement OPEN). We deliberately poison the lock, then assert the durable
        // read/write path still functions.
        use std::sync::Arc;

        let s = Arc::new(SqliteStore::open_in_memory().unwrap());
        s.add_usage("k_poison", 100, 10, 50, true).unwrap();

        // Poison the connection Mutex: panic while holding the guard.
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

        // Despite the poison, durable access keeps working (no panic): reads recover the guard,
        // and writes continue to accrue correctly on the recovered (still-consistent) connection.
        assert_eq!(
            s.get_usage("k_poison", 100).unwrap().requests,
            1,
            "get_usage must recover the poisoned conn lock instead of panicking"
        );
        s.add_usage("k_poison", 100, 5, 25, true).unwrap();
        let u = s.get_usage("k_poison", 100).unwrap();
        assert_eq!(
            (u.requests, u.spend_cents, u.tokens),
            (2, 15, 75),
            "writes must keep accruing on a recovered (poisoned) conn lock"
        );
    }

    /// Durable audit (#17): `append_audit` persists records and `list_audit` returns them oldest-first
    /// by `seq`, verbatim (the store never interprets the hash chain). A re-append of the same seq
    /// upserts (idempotent), never a UNIQUE error — so a snapshot replay is safe.
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
        // Insert out of order to prove the ORDER BY seq.
        s.append_audit(&mk(2, "h1", "h2")).unwrap();
        s.append_audit(&mk(1, "", "h1")).unwrap();
        s.append_audit(&mk(3, "h2", "h3")).unwrap();
        let got = s.list_audit().unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(
            (got[0].seq, got[1].seq, got[2].seq),
            (1, 2, 3),
            "oldest-first by seq"
        );
        assert_eq!(got[0].prev_hash, "");
        assert_eq!(got[1].prev_hash, "h1");
        assert_eq!(got[2].resource, "hook:3");

        // Idempotent upsert on seq (a replay overwrites, never a UNIQUE violation).
        s.append_audit(&mk(2, "h1", "h2b")).unwrap();
        let got2 = s.list_audit().unwrap();
        assert_eq!(got2.len(), 3, "re-appending seq 2 upserts, not duplicates");
        assert_eq!(got2[1].hash, "h2b", "the upsert overwrote the record");
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

        // Update via UPSERT on id.
        let mut k2 = k.clone();
        k2.enabled = false;
        k2.allowed_pools = vec![]; // empty = all
        s.put_key(&k2).unwrap();
        let got = s.get_key("k1").unwrap().unwrap();
        assert!(!got.enabled);
        assert!(got.allowed_pools.is_empty());

        s.delete_key("k1").unwrap();
        assert_eq!(s.get_key("k1").unwrap(), None);
    }

    /// fix 2a: the atomic check-and-charge is a HARD cap. A budget of 100c with a 30c flat fee admits
    /// exactly 3 requests (90c); the 4th would reach 120c > 100c and is REJECTED atomically. The first
    /// request in a window inserts; subsequent ones take the conditional UPSERT path.
    #[test]
    fn test_charge_within_budget_is_a_hard_cap() {
        let s = SqliteStore::open_in_memory().unwrap();
        let w = 0u64;
        // 3 charges fit (30, 60, 90), the 4th (would be 120) is rejected.
        assert!(
            s.charge_within_budget("k", w, 30, Some(100)).unwrap(),
            "1st 30c admitted"
        );
        assert!(
            s.charge_within_budget("k", w, 30, Some(100)).unwrap(),
            "2nd 60c admitted"
        );
        assert!(
            s.charge_within_budget("k", w, 30, Some(100)).unwrap(),
            "3rd 90c admitted"
        );
        assert!(
            !s.charge_within_budget("k", w, 30, Some(100)).unwrap(),
            "4th 120c REJECTED"
        );
        // The rejected charge did NOT mutate spend — it stays at 90.
        assert_eq!(
            s.get_usage("k", w).unwrap().spend_cents,
            90,
            "rejected charge must not bill"
        );
        assert_eq!(
            s.get_usage("k", w).unwrap().requests,
            3,
            "only admitted requests counted"
        );
    }

    /// fix 2a: a single request whose flat fee ALONE exceeds the cap is rejected even as the FIRST
    /// request in the window (the INSERT-branch guard), and an UNCAPPED key always charges.
    #[test]
    fn test_charge_within_budget_first_request_and_uncapped() {
        let s = SqliteStore::open_in_memory().unwrap();
        // First-request fee > cap → rejected, no row created.
        assert!(!s.charge_within_budget("big", 0, 200, Some(100)).unwrap());
        assert_eq!(
            s.get_usage("big", 0).unwrap().requests,
            0,
            "rejected first request creates no charge"
        );
        // Uncapped (None) always charges.
        assert!(s.charge_within_budget("free", 0, 999_999, None).unwrap());
        assert_eq!(s.get_usage("free", 0).unwrap().spend_cents, 999_999);
    }

    /// fix 2a (the headline): CONCURRENT atomic charges cannot overshoot the cap. 50 tasks each try to
    /// charge 30c against a 100c cap on ONE shared store; exactly 3 may succeed (90c), the rest are
    /// rejected, and final spend is EXACTLY 90 — never the N×30 overshoot the old non-atomic
    /// read-then-charge allowed.
    #[test]
    fn test_concurrent_charges_cannot_overshoot_cap() {
        let store: Arc<SqliteStore> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut handles = Vec::new();
        for _ in 0..50 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || {
                s.charge_within_budget("k", 0, 30, Some(100)).unwrap()
            }));
        }
        let mut admitted = 0u32;
        for h in handles {
            if h.join().unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 3,
            "exactly 3 of 50 concurrent charges fit under a 100c/30c cap"
        );
        assert_eq!(
            store.get_usage("k", 0).unwrap().spend_cents,
            90,
            "final spend must be EXACTLY 90 — no concurrency overshoot (the hard-cap guarantee)"
        );
    }

    /// M9: cap BOUNDARY semantics through `Store::charge_within_budget` (the admission primitive).
    /// (a) a FIRST request whose `cost_cents == max_cents` must ADMIT (post-charge spend equals, not
    /// exceeds, the cap). (b) a window PRE-SEEDED with `spend_cents >= max_cents` must REJECT the next
    /// charge. These pin the `>`-vs-`>=` boundary the hard cap turns on.
    #[test]
    fn test_charge_within_budget_cap_boundaries() {
        // (a) cost == cap on a fresh window → admit.
        let s = SqliteStore::open_in_memory().unwrap();
        assert!(
            s.charge_within_budget("k", 0, 100, Some(100)).unwrap(),
            "first request with cost_cents == max_cents must admit (spend lands exactly at the cap)"
        );
        assert_eq!(s.get_usage("k", 0).unwrap().spend_cents, 100);
        // A further charge now that spend == cap must reject.
        assert!(
            !s.charge_within_budget("k", 0, 1, Some(100)).unwrap(),
            "once spend == cap, any further charge is rejected"
        );

        // (b) window pre-seeded at/above the cap → reject the next charge outright.
        let s2 = SqliteStore::open_in_memory().unwrap();
        // Seed spend >= max via an uncapped accounting write, then probe with a capped charge.
        s2.add_usage("k2", 0, 250, 0, true).unwrap();
        assert!(
            !s2.charge_within_budget("k2", 0, 1, Some(200)).unwrap(),
            "a window pre-seeded with spend_cents >= max_cents must reject"
        );
        assert_eq!(
            s2.get_usage("k2", 0).unwrap().spend_cents,
            250,
            "the rejected charge must not mutate spend"
        );
    }

    /// fix 2a companion: `refund_request` reverses exactly one flat charge, floored at 0 (a refund
    /// can never drive a counter negative).
    #[test]
    fn test_refund_request_reverses_charge_floored_at_zero() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert!(s.charge_within_budget("k", 0, 30, Some(1000)).unwrap());
        assert!(s.charge_within_budget("k", 0, 30, Some(1000)).unwrap());
        assert_eq!(s.get_usage("k", 0).unwrap().spend_cents, 60);
        assert_eq!(s.get_usage("k", 0).unwrap().requests, 2);
        s.refund_request("k", 0, 30).unwrap();
        assert_eq!(
            s.get_usage("k", 0).unwrap().spend_cents,
            30,
            "one refund reverses one charge"
        );
        assert_eq!(s.get_usage("k", 0).unwrap().requests, 1);
        // Over-refunding floors at 0, never negative.
        s.refund_request("k", 0, 30).unwrap();
        s.refund_request("k", 0, 30).unwrap();
        assert_eq!(
            s.get_usage("k", 0).unwrap().spend_cents,
            0,
            "refund floors spend at 0"
        );
        assert_eq!(
            s.get_usage("k", 0).unwrap().requests,
            0,
            "refund floors requests at 0"
        );
    }

    #[test]
    fn test_usage_accumulates() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.add_usage("k1", 100, 25, 1000, true).unwrap();
        s.add_usage("k1", 100, 30, 500, true).unwrap();
        let u = s.get_usage("k1", 100).unwrap();
        assert_eq!(u.spend_cents, 55);
        assert_eq!(u.tokens, 1500);
        assert_eq!(u.requests, 2);
        // A token-accrual call (count_request = false) adds spend/tokens but NOT a request — so the
        // per-request fee + token usage for one request don't double-count it.
        s.add_usage("k1", 100, 7, 250, false).unwrap();
        let u2 = s.get_usage("k1", 100).unwrap();
        assert_eq!(u2.spend_cents, 62);
        assert_eq!(u2.tokens, 1750);
        assert_eq!(
            u2.requests, 2,
            "count_request=false must not increment requests"
        );
        // Different window is independent; unknown = zero.
        assert_eq!(s.get_usage("k1", 200).unwrap(), Usage::default());
    }

    #[test]
    fn test_delete_key_removes_key_and_usage_atomically() {
        // Regression: `delete_key` deletes from both `virtual_keys` and `usage_counters`. The two
        // DELETEs are now wrapped in one transaction so they commit together — leaving no orphaned
        // usage rows that would (a) accumulate forever and (b) poison a future key re-created with
        // the same id with stale usage. Here we assert the post-condition: after delete, both the
        // key row AND all of its usage rows across windows are gone.
        let s = SqliteStore::open_in_memory().unwrap();
        let key = VirtualKey {
            id: "vk_delete_me".into(),
            key_hash: "hash_delete_me".into(),
            name: "victim".into(),
            allowed_pools: vec!["p1".into()],
            max_budget_cents: Some(1000),
            budget_period: "total".into(),
            rpm_limit: Some(60),
            tpm_limit: Some(1000),
            enabled: true,
            created_at: 0,
        };
        s.put_key(&key).unwrap();
        s.add_usage("vk_delete_me", 100, 25, 1000, true).unwrap();
        s.add_usage("vk_delete_me", 200, 5, 50, true).unwrap();
        // Precondition: key + usage present.
        assert!(s.get_key("vk_delete_me").unwrap().is_some());
        assert_eq!(s.get_usage("vk_delete_me", 100).unwrap().requests, 1);

        s.delete_key("vk_delete_me").unwrap();

        // Key row gone.
        assert!(
            s.get_key("vk_delete_me").unwrap().is_none(),
            "key row must be deleted"
        );
        // No orphaned usage rows in ANY window.
        assert_eq!(
            s.get_usage("vk_delete_me", 100).unwrap(),
            Usage::default(),
            "usage row in window 100 must be deleted alongside the key"
        );
        assert_eq!(
            s.get_usage("vk_delete_me", 200).unwrap(),
            Usage::default(),
            "usage row in window 200 must be deleted alongside the key"
        );
    }

    #[test]
    fn test_delete_key_does_not_inherit_stale_usage_on_recreate() {
        // The orphaned-usage hazard manifests as a re-created key inheriting prior usage. With the
        // atomic delete, re-minting the same id starts from zero usage.
        let s = SqliteStore::open_in_memory().unwrap();
        let mk = |id: &str| VirtualKey {
            id: id.into(),
            key_hash: format!("hash_{id}"),
            name: "k".into(),
            allowed_pools: vec![],
            max_budget_cents: None,
            budget_period: "total".into(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
        };
        s.put_key(&mk("vk_reuse")).unwrap();
        s.add_usage("vk_reuse", 100, 99, 9999, true).unwrap();
        s.delete_key("vk_reuse").unwrap();
        // Re-create with the same id; the prior window's usage must NOT bleed through.
        s.put_key(&mk("vk_reuse")).unwrap();
        assert_eq!(
            s.get_usage("vk_reuse", 100).unwrap(),
            Usage::default(),
            "re-created key must not inherit the deleted key's usage"
        );
    }
}
