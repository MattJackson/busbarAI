// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Governance persistence (sprint 0.12, ADR-0009). A durable `Store` seam — SEPARATE from the hot
//! in-memory `StateStore` (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual
//! keys + config, and per-key usage counters (spend/tokens/requests) per budget window. Historical
//! request logs are NOT stored here (they go to the observability pipeline, 0.11). The default impl
//! is `SqliteStore` (embedded, single file, statically linked — preserves the single-binary story);
//! a `PostgresStore` can implement the same trait later for multi-node.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

/// A virtual key issued by busbar (distinct from upstream provider keys). Maps a caller to the
/// pools they may use plus their budget/rate-limit policy.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VirtualKey {
    pub id: String,
    /// SHA-256 hex of the presented secret (the secret itself is never stored).
    pub key_hash: String,
    pub name: String,
    /// Pools this key may target; empty = all pools allowed.
    pub allowed_pools: Vec<String>,
    /// Spend cap in cents for the budget period; None = unlimited.
    pub max_budget_cents: Option<i64>,
    /// "total" | "daily" | "monthly".
    pub budget_period: String,
    /// Requests-per-minute cap; None = unlimited.
    pub rpm_limit: Option<u32>,
    /// Tokens-per-minute cap; None = unlimited.
    pub tpm_limit: Option<u32>,
    pub enabled: bool,
    pub created_at: u64,
}

/// Accumulated usage for a key within a budget window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Usage {
    pub spend_cents: i64,
    pub tokens: u64,
    pub requests: u64,
}

pub(crate) type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug)]
pub(crate) struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for StoreError {}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

/// The durable governance store seam (ADR-0009). Swappable: `SqliteStore` today, `PostgresStore`
/// later behind the same trait.
#[allow(dead_code)] // CRUD surface; wired by G-2..G-5
pub(crate) trait Store: Send + Sync + 'static {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()>;
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>>;
    fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>>;
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>>;
    fn delete_key(&self, id: &str) -> StoreResult<()>;
    /// Add usage to a key's counter for the given budget-window start (UPSERT/accumulate).
    fn add_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
    ) -> StoreResult<()>;
    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage>;
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
CREATE TABLE IF NOT EXISTS usage_counters (
    key_id       TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    spend_cents  INTEGER NOT NULL DEFAULT 0,
    tokens       INTEGER NOT NULL DEFAULT 0,
    requests     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, window_start)
);
";

/// Embedded SQLite store (the ADR-0009 default). The single `Connection` is mutex-guarded; the
/// governance surface is low-frequency (key CRUD) or batched (usage), so this is not on the hot path.
pub(crate) struct SqliteStore {
    conn: Mutex<Connection>,
}

#[allow(dead_code)] // open/open_in_memory used by main (G-2) + tests
impl SqliteStore {
    pub(crate) fn open(path: &str) -> StoreResult<Self> {
        let store = Self {
            conn: Mutex::new(Connection::open(path)?),
        };
        store.migrate()?;
        Ok(store)
    }

    pub(crate) fn open_in_memory() -> StoreResult<Self> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> StoreResult<()> {
        self.conn.lock().unwrap().execute_batch(SCHEMA)?;
        Ok(())
    }
}

fn pools_to_csv(pools: &[String]) -> String {
    pools.join(",")
}
fn csv_to_pools(csv: &str) -> Vec<String> {
    if csv.is_empty() {
        Vec::new()
    } else {
        csv.split(',').map(String::from).collect()
    }
}

impl Store for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
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
                pools_to_csv(&key.allowed_pools),
                key.max_budget_cents,
                key.budget_period,
                key.rpm_limit,
                key.tpm_limit,
                key.enabled as i64,
                key.created_at as i64,
            ],
        )?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
                 FROM virtual_keys WHERE id=?1",
                params![id],
                row_to_key,
            )
            .optional()?;
        Ok(row)
    }

    fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
                 FROM virtual_keys WHERE key_hash=?1",
                params![key_hash],
                row_to_key,
            )
            .optional()?;
        Ok(row)
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,key_hash,name,allowed_pools,max_budget_cents,budget_period,rpm_limit,tpm_limit,enabled,created_at
             FROM virtual_keys ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], row_to_key)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM virtual_keys WHERE id=?1", params![id])?;
        conn.execute("DELETE FROM usage_counters WHERE key_id=?1", params![id])?;
        Ok(())
    }

    fn add_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
    ) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO usage_counters (key_id, window_start, spend_cents, tokens, requests)
             VALUES (?1,?2,?3,?4,1)
             ON CONFLICT(key_id, window_start) DO UPDATE SET
                spend_cents = spend_cents + excluded.spend_cents,
                tokens      = tokens + excluded.tokens,
                requests    = requests + 1",
            params![key_id, window_start as i64, spend_cents, tokens as i64],
        )?;
        Ok(())
    }

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT spend_cents, tokens, requests FROM usage_counters WHERE key_id=?1 AND window_start=?2",
                params![key_id, window_start as i64],
                |r| {
                    Ok(Usage {
                        spend_cents: r.get(0)?,
                        tokens: r.get::<_, i64>(1)? as u64,
                        requests: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<VirtualKey> {
    Ok(VirtualKey {
        id: r.get(0)?,
        key_hash: r.get(1)?,
        name: r.get(2)?,
        allowed_pools: csv_to_pools(&r.get::<_, String>(3)?),
        max_budget_cents: r.get(4)?,
        budget_period: r.get(5)?,
        rpm_limit: r.get::<_, Option<i64>>(6)?.map(|v| v as u32),
        tpm_limit: r.get::<_, Option<i64>>(7)?.map(|v| v as u32),
        enabled: r.get::<_, i64>(8)? != 0,
        created_at: r.get::<_, i64>(9)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(id: &str, hash: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            key_hash: hash.to_string(),
            name: "test-key".to_string(),
            allowed_pools: vec!["prod".to_string(), "cheap".to_string()],
            max_budget_cents: Some(5000),
            budget_period: "monthly".to_string(),
            rpm_limit: Some(60),
            tpm_limit: None,
            enabled: true,
            created_at: 1_700_000_000,
        }
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

    #[test]
    fn test_usage_accumulates() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.add_usage("k1", 100, 25, 1000).unwrap();
        s.add_usage("k1", 100, 30, 500).unwrap();
        let u = s.get_usage("k1", 100).unwrap();
        assert_eq!(u.spend_cents, 55);
        assert_eq!(u.tokens, 1500);
        assert_eq!(u.requests, 2);
        // Different window is independent; unknown = zero.
        assert_eq!(s.get_usage("k1", 200).unwrap(), Usage::default());
    }
}
