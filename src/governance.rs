// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Governance persistence (sprint 0.12, ADR-0009). A durable `Store` seam — SEPARATE from the hot
//! in-memory `StateStore` (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual
//! keys + config, and per-key usage counters (spend/tokens/requests) per budget window. Historical
//! request logs are NOT stored here (they go to the observability pipeline, 0.11). The default impl
//! is `SqliteStore` (embedded, single file, statically linked — preserves the single-binary story);
//! a `PostgresStore` can implement the same trait later for multi-node.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// per-key rate-limit state for the current 60s window. Ephemeral (in-memory, not persisted —
/// ADR-0009: single-node rate windows; cross-node distributed limits are a future Redis concern).
#[derive(Default)]
struct RateState {
    window_start: u64,
    requests: u32,
    tokens: u64,
}

/// Per-instance governance runtime: the durable `Store` plus an in-memory key cache (hashed-secret
/// → key) so validation on the hot path is a map lookup, not a DB round-trip. Held in `App`
/// (`Option`: `None` = governance disabled) — NOT a process-global, so tests stay isolated.
pub(crate) struct GovState {
    store: Arc<dyn Store>,
    by_hash: RwLock<HashMap<String, VirtualKey>>,
    /// Flat cents charged per request (one half of the cost model; the other is per-token, below).
    /// Total budget spend = per-request fee + tokens/1000 * price_per_1k_tokens_cents.
    price_per_request_cents: i64,
    /// cents per 1000 tokens (input + output), accrued from response usage at stream end.
    price_per_1k_tokens_cents: i64,
    /// per-key RPM/TPM windows (ephemeral).
    rate: RwLock<HashMap<String, RateState>>,
    /// bearer token guarding the /admin management API (None = admin API disabled).
    admin_token: Option<String>,
}

/// parameters for minting a new virtual key (from the management API).
pub(crate) struct NewKeySpec {
    pub name: String,
    pub allowed_pools: Vec<String>,
    pub max_budget_cents: Option<i64>,
    pub budget_period: String,
    pub rpm_limit: Option<u32>,
    pub tpm_limit: Option<u32>,
}

impl GovState {
    pub(crate) fn new(
        store: Arc<dyn Store>,
        price_per_request_cents: i64,
        price_per_1k_tokens_cents: i64,
        admin_token: Option<String>,
    ) -> StoreResult<Self> {
        let by_hash = Self::load(store.as_ref())?;
        Ok(Self {
            store,
            by_hash: RwLock::new(by_hash),
            price_per_request_cents,
            price_per_1k_tokens_cents,
            rate: RwLock::new(HashMap::new()),
            admin_token,
        })
    }

    /// Accrue token-based usage from a completed response to a key's current budget window: adds
    /// `tokens/1000 * price_per_1k_tokens_cents` to spend, plus the raw tokens (for TPM). Called
    /// once per request at stream end from the response usage tap. Best-effort (store errors logged).
    pub(crate) fn record_tokens(&self, key_id: &str, budget_period: &str, now: u64, tokens: u64) {
        if tokens == 0 {
            // Still feed the (zero) rate counter to be explicit; nothing to spend.
            return;
        }
        let window = budget_window(budget_period, now);
        let spend =
            (tokens.saturating_mul(self.price_per_1k_tokens_cents.max(0) as u64) / 1000) as i64;
        if let Err(e) = self.store.add_usage(key_id, window, spend, tokens) {
            tracing::warn!(key = %key_id, error = %e, "token usage record failed");
        }
        self.add_rate_tokens(key_id, now, tokens);
    }

    /// the configured admin token (None = admin API disabled).
    pub(crate) fn admin_token(&self) -> Option<&str> {
        self.admin_token.as_deref()
    }

    /// mint a new virtual key, persist it, refresh the cache, and return (key, plaintext
    /// secret). The secret is shown to the caller ONCE here and never stored (only its hash is).
    pub(crate) fn create_key(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let secret = generate_secret();
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        let key = VirtualKey {
            id: format!("vk_{}", &hash[..16]),
            key_hash: hash,
            name: spec.name,
            allowed_pools: spec.allowed_pools,
            max_budget_cents: spec.max_budget_cents,
            budget_period: spec.budget_period,
            rpm_limit: spec.rpm_limit,
            tpm_limit: spec.tpm_limit,
            enabled: true,
            created_at: now,
        };
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok((key, secret))
    }

    /// all virtual keys (metadata; callers must strip `key_hash` before returning).
    pub(crate) fn all_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.store.list_keys()
    }

    /// delete a key by id + refresh the cache.
    pub(crate) fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.store.delete_key(id)?;
        self.refresh()
    }

    /// current-window usage for a key (None if the key doesn't exist).
    pub(crate) fn usage_for(&self, id: &str, now: u64) -> StoreResult<Option<Usage>> {
        match self.store.get_key(id)? {
            Some(key) => {
                let window = budget_window(&key.budget_period, now);
                Ok(Some(self.store.get_usage(id, window)?))
            }
            None => Ok(None),
        }
    }

    /// check + consume one request slot against the key's RPM/TPM for the current 60s window.
    /// `Ok(())` admits the request (and counts it); `Err(retry_after_secs)` rejects it (429). RPM is
    /// enforced precisely; TPM is enforced against tokens accrued so far this window (tokens are
    /// fed post-response from the response usage tap, so TPM reflects the prior window's tokens).
    pub(crate) fn check_rate(&self, key: &VirtualKey, now: u64) -> Result<(), u64> {
        if key.rpm_limit.is_none() && key.tpm_limit.is_none() {
            return Ok(());
        }
        let window = now / 60 * 60;
        let retry = (window + 60).saturating_sub(now).max(1);
        let mut map = self.rate.write().unwrap();
        let st = map.entry(key.id.clone()).or_default();
        if st.window_start != window {
            *st = RateState {
                window_start: window,
                requests: 0,
                tokens: 0,
            };
        }
        if let Some(tpm) = key.tpm_limit {
            if st.tokens >= tpm as u64 {
                return Err(retry);
            }
        }
        if let Some(rpm) = key.rpm_limit {
            if st.requests >= rpm {
                return Err(retry);
            }
        }
        st.requests += 1;
        Ok(())
    }

    /// add tokens to the key's current rate window (for TPM). Called from `record_request`.
    fn add_rate_tokens(&self, key_id: &str, now: u64, tokens: u64) {
        if tokens == 0 {
            return;
        }
        let window = now / 60 * 60;
        let mut map = self.rate.write().unwrap();
        if let Some(st) = map.get_mut(key_id) {
            if st.window_start == window {
                st.tokens += tokens;
            }
        }
    }

    /// is this key already at/over its budget for the current window? (No cap → never.)
    pub(crate) fn is_over_budget(&self, key: &VirtualKey, now: u64) -> bool {
        let Some(limit) = key.max_budget_cents else {
            return false;
        };
        let window = budget_window(&key.budget_period, now);
        self.store
            .get_usage(&key.id, window)
            .map(|u| u.spend_cents >= limit)
            .unwrap_or(false)
    }

    /// charge one request (flat per-request cost + token count) to the key's current window.
    /// Best-effort: a store error is logged-and-dropped (telemetry must not break serving).
    pub(crate) fn record_request(&self, key: &VirtualKey, now: u64, tokens: u64) {
        let window = budget_window(&key.budget_period, now);
        if let Err(e) = self
            .store
            .add_usage(&key.id, window, self.price_per_request_cents, tokens)
        {
            tracing::warn!(key = %key.id, error = %e, "usage record failed");
        }
        // also feed the rate window's TPM counter.
        self.add_rate_tokens(&key.id, now, tokens);
    }

    fn load(store: &dyn Store) -> StoreResult<HashMap<String, VirtualKey>> {
        Ok(store
            .list_keys()?
            .into_iter()
            .map(|k| (k.key_hash.clone(), k))
            .collect())
    }

    /// Resolve a presented secret to its virtual key (cache lookup; secret hashed, never compared raw).
    pub(crate) fn lookup(&self, secret: &str) -> Option<VirtualKey> {
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        self.by_hash.read().unwrap().get(&hash).cloned()
    }

    /// Direct handle to the backing store, for tests that seed/inspect persistence.
    #[cfg(test)]
    pub(crate) fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    /// Reload the cache from the store (after a management-API mutation,).
    pub(crate) fn refresh(&self) -> StoreResult<()> {
        let fresh = Self::load(self.store.as_ref())?;
        *self.by_hash.write().unwrap() = fresh;
        Ok(())
    }
}

/// Resolved governance context attached to each request by the auth middleware. `key` is `None`
/// when governance is disabled (so downstream enforcement is a no-op).
#[derive(Clone, Debug, Default)]
pub(crate) struct GovCtx {
    pub key: Option<VirtualKey>,
}

/// Generate a virtual-key secret from 16 bytes of the OS CSPRNG (portable across Unix/Windows via
/// getrandom). Fails closed: if the OS exposes no entropy source we refuse to mint a key rather
/// than fall back to a guessable (time-derived) secret. getrandom failure is near-impossible on
/// supported platforms; the panic aborts only the key-mint request (the server stays up).
fn generate_secret() -> String {
    // Portable OS CSPRNG via getrandom: /dev/urandom on Unix, BCryptGenRandom on Windows, etc.
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf)
        .expect("OS CSPRNG (getrandom) unavailable — refusing to mint a guessable virtual key");
    format!("sk-bb-{}", hex::encode(buf))
}

/// Whether `key` may target `pool` (empty allowed_pools = all pools).
pub(crate) fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.allowed_pools.is_empty() || key.allowed_pools.iter().any(|p| p == pool)
}

/// The epoch start of the budget window containing `now` for a given period. "total" = a
/// single all-time window (0); "daily" = UTC midnight; "monthly" = UTC first-of-month.
pub(crate) fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        "daily" => now / 86_400 * 86_400,
        "monthly" => {
            let days = (now / 86_400) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * 86_400
        }
        _ => 0, // "total" (and any unknown period) = one all-time window
    }
}

// Howard Hinnant's civil-date algorithms (shared shape with sigv4); self-contained here.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

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
pub(crate) trait Store: Send + Sync + 'static {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()>;
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>>;
    // Lookup by key hash — part of the Store contract and unit-tested, but the hot-path key
    // resolution uses the in-memory cache by id, so it's not called in release.
    #[cfg_attr(not(test), allow(dead_code))]
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

impl SqliteStore {
    pub(crate) fn open(path: &str) -> StoreResult<Self> {
        let store = Self {
            conn: Mutex::new(Connection::open(path)?),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory SQLite store, for unit tests.
    #[cfg(test)]
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
            params![
                key_id,
                window_start as i64,
                spend_cents,
                i64::try_from(tokens).unwrap_or(i64::MAX)
            ],
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
    fn test_govstate_lookup_pool_allowed_refresh() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-abc";
        let mut k = sample_key("k1", &crate::sigv4::sha256_hex(secret.as_bytes()));
        k.allowed_pools = vec!["prod".to_string()];
        store.put_key(&k).unwrap();

        let gov = GovState::new(store, 1, 0, None).unwrap();
        // hashed-secret lookup hits the cache.
        assert_eq!(gov.lookup(secret).unwrap().id, "k1");
        assert!(gov.lookup("wrong-secret").is_none());

        let resolved = gov.lookup(secret).unwrap();
        assert!(pool_allowed(&resolved, "prod"));
        assert!(!pool_allowed(&resolved, "other"));

        // A key added after construction isn't visible until refresh().
        let secret2 = "sk-vk-def";
        let mut k2 = sample_key("k2", &crate::sigv4::sha256_hex(secret2.as_bytes()));
        k2.allowed_pools = vec![]; // empty = all pools
        gov.store().put_key(&k2).unwrap();
        assert!(gov.lookup(secret2).is_none(), "not cached pre-refresh");
        gov.refresh().unwrap();
        let r2 = gov.lookup(secret2).unwrap();
        assert!(pool_allowed(&r2, "anything"), "empty allowed_pools = all");
    }

    #[test]
    fn test_budget_window_periods() {
        assert_eq!(budget_window("total", 1_700_000_000), 0);
        assert_eq!(budget_window("unknown", 1_700_000_000), 0);
        assert_eq!(budget_window("daily", 1_700_000_000), 1_699_920_000);
        // 1700000000 = 2023-11-14 → 2023-11-01 00:00Z = 1698796800.
        assert_eq!(budget_window("monthly", 1_700_000_000), 1_698_796_800);
    }

    #[test]
    fn test_is_over_budget_and_record() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut k = sample_key("k1", "h1");
        k.max_budget_cents = Some(100);
        k.budget_period = "total".to_string();
        store.put_key(&k).unwrap();
        let gov = GovState::new(store, 30, 0, None).unwrap(); // 30 cents/request

        assert!(!gov.is_over_budget(&k, 1_700_000_000));
        for _ in 0..3 {
            gov.record_request(&k, 1_700_000_000, 0); // 90c < 100c
        }
        assert!(!gov.is_over_budget(&k, 1_700_000_000));
        gov.record_request(&k, 1_700_000_000, 0); // 120c ≥ 100c
        assert!(gov.is_over_budget(&k, 1_700_000_000));

        let mut unlimited = k.clone();
        unlimited.max_budget_cents = None;
        assert!(!gov.is_over_budget(&unlimited, 1_700_000_000));
    }

    #[test]
    fn test_record_tokens_cost() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        // 50 cents per 1000 tokens, no per-request fee.
        let gov = GovState::new(store.clone(), 0, 50, None).unwrap();
        gov.record_tokens("k1", "total", 1_700_000_000, 2000); // 2000 * 50 / 1000 = 100 cents
        let u = store.get_usage("k1", 0).unwrap();
        assert_eq!(u.spend_cents, 100);
        assert_eq!(u.tokens, 2000);
    }

    #[test]
    fn test_check_rate_rpm_window() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 1, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(2);
        k.tpm_limit = None;
        let now = 1_700_000_040; // mid-window

        assert!(gov.check_rate(&k, now).is_ok(), "1st request");
        assert!(gov.check_rate(&k, now).is_ok(), "2nd request");
        let retry = gov.check_rate(&k, now).unwrap_err();
        assert!((1..=60).contains(&retry), "3rd → 429 with retry {retry}");
        // Next 60s window resets the counter.
        assert!(
            gov.check_rate(&k, now + 60).is_ok(),
            "new window admits again"
        );

        // A key with no RPM/TPM cap is never rate-limited.
        let mut unl = sample_key("k2", "h2");
        unl.rpm_limit = None;
        unl.tpm_limit = None;
        for _ in 0..100 {
            assert!(gov.check_rate(&unl, now).is_ok());
        }
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
