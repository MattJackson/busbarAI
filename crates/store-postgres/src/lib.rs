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

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage,
    VirtualKey,
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

// Same tables/columns as the SQLite backend, in Postgres types: INTEGER -> BIGINT, the enabled flag
// as BOOLEAN. `CREATE TABLE IF NOT EXISTS` is idempotent, so migrate() is safe to run every open.
const SCHEMA: &str = "
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
    created_at       BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS aws_credentials (
    access_key_id     TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    secret_access_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aws_credentials_key_id ON aws_credentials (key_id);
CREATE TABLE IF NOT EXISTS usage_counters (
    key_id       TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    spend_cents  BIGINT NOT NULL DEFAULT 0,
    tokens       BIGINT NOT NULL DEFAULT 0,
    requests     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, window_start)
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

impl PostgresStore {
    /// Connect to Postgres with the given libpq connection string / URL (e.g.
    /// `postgres://user:pass@host:5432/dbname`) and ensure the schema. TLS is not wired in this
    /// build (`NoTls`); front the database with a TLS-terminating proxy or a local socket.
    pub fn connect(conn_str: &str) -> StoreResult<Self> {
        let client = Client::connect(conn_str, NoTls).store()?;
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
        self.lock().batch_execute(SCHEMA).store()?;
        Ok(())
    }
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
        rpm_limit: r.get::<_, Option<i64>>(6).map(|v| v as u32),
        tpm_limit: r.get::<_, Option<i64>>(7).map(|v| v as u32),
        enabled: r.get(8),
        created_at: read_u64(r.get::<_, i64>(9)),
    }
}

const KEY_COLUMNS: &str =
    "id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at";

impl Store for PostgresStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let pools = pools_to_storage(&key.allowed_pools);
        let rpm = key.rpm_limit.map(|v| v as i64);
        let tpm = key.tpm_limit.map(|v| v as i64);
        let created = clamp(key.created_at);
        self.lock()
            .execute(
                "INSERT INTO virtual_keys
                    (id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                 ON CONFLICT (id) DO UPDATE SET
                    key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                    max_budget_cents=EXCLUDED.max_budget_cents, budget_period=EXCLUDED.budget_period,
                    rpm_limit=EXCLUDED.rpm_limit, tpm_limit=EXCLUDED.tpm_limit, enabled=EXCLUDED.enabled",
                &[
                    &key.id, &key.key_hash, &key.name, &pools, &key.max_budget_cents,
                    &key.budget_period, &rpm, &tpm, &key.enabled, &created,
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
        tx.execute("DELETE FROM usage_counters WHERE key_id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM aws_credentials WHERE key_id=$1", &[&id])
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        let ws = clamp(window_start);
        let row = self
            .lock()
            .query_opt(
                "SELECT spend_cents,tokens,requests FROM usage_counters WHERE key_id=$1 AND window_start=$2",
                &[&key_id, &ws],
            )
            .store()?;
        Ok(row
            .map(|r| Usage {
                spend_cents: r.get(0),
                tokens: read_u64(r.get::<_, i64>(1)),
                requests: read_u64(r.get::<_, i64>(2)),
            })
            .unwrap_or_default())
    }

    fn put_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): SET (not add) each counter, so a re-flush of
        // the same in-memory cell is idempotent and never double-counts.
        let (ws, tk, rq) = (clamp(window_start), clamp(tokens), clamp(requests));
        self.lock()
            .execute(
                "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (key_id, window_start) DO UPDATE SET
                    spend_cents = EXCLUDED.spend_cents,
                    tokens      = EXCLUDED.tokens,
                    requests    = EXCLUDED.requests",
                &[&key_id, &ws, &spend_cents, &tk, &rq],
            )
            .store()?;
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
        let rpm = key.rpm_limit.map(|v| v as i64);
        let tpm = key.tpm_limit.map(|v| v as i64);
        let created = clamp(key.created_at);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "INSERT INTO virtual_keys
                (id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             ON CONFLICT (id) DO UPDATE SET
                key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                max_budget_cents=EXCLUDED.max_budget_cents, budget_period=EXCLUDED.budget_period,
                rpm_limit=EXCLUDED.rpm_limit, tpm_limit=EXCLUDED.tpm_limit, enabled=EXCLUDED.enabled",
            &[
                &key.id, &key.key_hash, &key.name, &pools, &key.max_budget_cents,
                &key.budget_period, &rpm, &tpm, &key.enabled, &created,
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

    /// End-to-end against a REAL Postgres, gated on `BUSBAR_TEST_POSTGRES_URL` (a docker
    /// `postgres:16` service in CI). Skips cleanly when unset LOCALLY so the default `cargo test`
    /// needs no database — but MUST NOT silently skip in CI: CI provisions the service and sets the
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
        };
        store.put_key(&key).unwrap();
        let got = store.get_key("vk_pg").unwrap().unwrap();
        assert_eq!(got.max_budget_cents, Some(1234));
        // The comma-bearing pool name survives (JSON encoding, not a bare comma split).
        assert_eq!(got.allowed_pools, vec!["prod,special".to_string()]);
        assert_eq!(got.rpm_limit, Some(60));

        store.put_usage("vk_pg", 100, 42, 9, 3).unwrap();
        let u = store.get_usage("vk_pg", 100).unwrap();
        assert_eq!((u.spend_cents, u.tokens, u.requests), (42, 9, 3));

        // Attach an AWS credential so delete_key's CASCADE (key + usage + credentials) can be
        // verified end to end — the credential-cleanup path P1 #6 flagged as untested.
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
        // CASCADE: the key, its usage counters, AND its AWS credential are all gone.
        assert!(store.get_key("vk_pg").unwrap().is_none());
        let u = store.get_usage("vk_pg", 100).unwrap();
        assert_eq!(
            (u.spend_cents, u.tokens, u.requests),
            (0, 0, 0),
            "delete_key must cascade to the usage counters"
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
}
