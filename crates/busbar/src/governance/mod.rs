// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Governance persistence. A durable `Store` seam — SEPARATE from the hot in-memory `StateStore`
//! (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual keys + config, and
//! per-key usage counters (spend/tokens/requests) per budget window. Historical request logs are
//! NOT stored here (they go to the observability pipeline). The default impl is `SqliteStore`
//! (embedded, single file, statically linked — preserves the single-binary story); a
//! `PostgresStore` could implement the same trait later for multi-node.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Length of the fixed rate-limit window (RPM/TPM are evaluated per this many seconds).
const RATE_WINDOW_SECS: u64 = 60;

/// Amortize the bounded eviction sweep of the rate map: a full `retain` (O(active keys)) runs at
/// most once per this many `check_rate` admissions, instead of on every single admission. Per-key
/// correctness does not depend on the sweep — `check_rate` already resets a looked-up key's entry
/// when its `window_start` is stale — so the sweep is purely to bound the map's memory by evicting
/// keys that have gone silent. Running it occasionally keeps the per-request cost off the hot path
/// while still guaranteeing the map cannot grow unboundedly across windows.
/// Operator-tunable via `governance.rate_sweep_interval` (default 256). Read in production through
/// `crate::limits::rate_sweep_interval()`; this const is retained (as the config DEFAULT) only for
/// the tests that exercise the default-configured sweep cadence.
#[cfg(test)]
const RATE_SWEEP_INTERVAL: u32 = crate::config::DEFAULT_RATE_SWEEP_INTERVAL;
/// Millicents per whole cent — the divisor that flushes the sub-cent spend carry (`record_tokens`).
/// This is the milli-prefix scale (1/1000), NOT a token-pricing unit: `price_per_1k_tokens_cents` is
/// cents-per-1000-tokens ≡ millicents-per-token, so `tokens * price` already lands in millicents and
/// `/ MILLICENTS_PER_CENT` flushes whole cents with a 0..999 millicent remainder. Named for the
/// milli→cent conversion it actually performs so a future change to the token-pricing scale (e.g.
/// per-100-tokens) cannot silently corrupt this divisor.
const MILLICENTS_PER_CENT: u64 = 1_000;
/// Seconds in a UTC day, for `budget_window`'s day/month arithmetic. `pub(crate)` so cross-module
/// TEST code can reference it as `crate::governance::SECS_PER_DAY`; production modules that need the
/// same value independently (e.g. `sigv4.rs`) keep a private copy where layering prohibits importing
/// it for a one-line constant.
pub(crate) const SECS_PER_DAY: u64 = 86_400;

// ── Budget-period sentinel tokens (matched in `budget_window`) ───────────────────────────────────
/// The "all-time" budget window sentinel: a single window from epoch 0.
pub(crate) const BUDGET_PERIOD_TOTAL: &str = "total";
/// The "daily" budget window sentinel: resets at UTC midnight.
pub(crate) const BUDGET_PERIOD_DAILY: &str = "daily";
/// The "monthly" budget window sentinel: resets at UTC first-of-month.
pub(crate) const BUDGET_PERIOD_MONTHLY: &str = "monthly";

// ── Virtual-key / bearer-secret formats ──────────────────────────────────────────────────────────
/// The `"vk_"` prefix prepended to the 16-hex-char hash prefix to form a virtual-key id.
const VK_ID_PREFIX: &str = "vk_";
/// Number of hex characters from the SHA-256 hash used as the suffix of a virtual-key id.
const VK_ID_HASH_PREFIX_LEN: usize = 16;
/// The `"sk-bb-"` prefix for bearer secrets returned by `generate_secret`.
const SK_SECRET_PREFIX: &str = "sk-bb-";

// ── AWS-key formats ───────────────────────────────────────────────────────────────────────────────
/// The literal `"AKIA"` prefix required by AWS SDK validators for long-term AccessKeyIds.
const AWS_ACCESS_KEY_PREFIX: &str = "AKIA";
/// Fixed total length (in characters) of a busbar-issued AWS AccessKeyId (`"AKIA"` + 16 random).
const AWS_ACCESS_KEY_ID_LEN: usize = 20;
/// Fixed length (in characters) of a busbar-issued AWS secret access key (base64-ish, 40 chars).
const AWS_SECRET_ACCESS_KEY_LEN: usize = 40;

// SQLite `busy_timeout` for the on-disk DB: a transient lock contention retries for this many
// milliseconds before failing, rather than erroring instantly with `SQLITE_BUSY`. Operator-tunable
// via `governance.sqlite_busy_timeout_ms` (default 5000); read through `crate::limits`.

/// Per-key rate-limit state for the current 60s window. Ephemeral (in-memory, not persisted):
/// rate windows are single-node; cross-node distributed limits would be a future concern.
#[derive(Default)]
struct RateState {
    window_start: u64,
    requests: u32,
    tokens: u64,
}

/// In-memory budget counter for a key's CURRENT window — the AUTHORITATIVE hot-path enforcement
/// state. SQLite is a write-behind durability layer flushed off the request path. One cell per key
/// (current window only; reset on rollover), so growth is key-count-bounded like the rate map.
#[derive(Clone, Copy)]
struct BudgetCell {
    window_start: u64,
    spend_cents: i64,
    tokens: u64,
    requests: u64,
    dirty: bool,
}

/// The two auth-path key caches, held together under `GovState::caches`'s single `RwLock` so
/// `refresh` can swap both in one critical section. `by_hash` is the hashed-secret → key index; it
/// backs `lookup`. `by_access_key_id` is the AWS AccessKeyId → resolved-credential index for inbound
/// SigV4 resolution on the Bedrock-ingress hot path: the AccessKeyId arrives in plaintext in the
/// SigV4 `Authorization` header's `Credential=` field, so it is keyed on the plaintext AccessKeyId
/// (NOT hashed like `by_hash`) — a lookup handle, not a secret. Each entry bundles the owning
/// `VirtualKey` with its secret access key, so the verify path resolves both in one lookup. Only keys
/// minted WITH an AWS credential appear in `by_access_key_id`. Both are rebuilt by `refresh` from the
/// SAME store snapshot, so a disabled/deleted/re-minted key is reflected in both — now also visible
/// to readers atomically (the one lock guarantees no reader sees a half-applied swap).
struct GovCaches {
    by_hash: HashMap<String, VirtualKey>,
    by_access_key_id: HashMap<String, AwsKeyEntry>,
}

/// Per-instance governance runtime: the durable `Store` plus an in-memory key cache (hashed-secret
/// → key) so validation on the hot path is a map lookup, not a DB round-trip. Held in `App`
/// (`Option`: `None` = governance disabled) — NOT a process-global, so tests stay isolated.
pub(crate) struct GovState {
    store: Arc<dyn Store>,
    /// Both auth-path caches under ONE lock so `refresh` swaps them atomically — a reader can never
    /// observe a new `by_hash` against a stale `by_access_key_id`. See `GovCaches`.
    caches: RwLock<GovCaches>,
    /// Flat cents charged per request (one half of the cost model; the other is per-token, below).
    /// Total budget spend = per-request fee + tokens/1000 * price_per_1k_tokens_cents.
    price_per_request_cents: i64,
    /// cents per 1000 tokens (input + output), accrued from response usage at stream end.
    price_per_1k_tokens_cents: i64,
    /// per-key RPM/TPM windows (ephemeral).
    rate: RwLock<HashMap<String, RateState>>,
    /// Per-key accumulator of the sub-cent (millicent) remainder of token spend. Token cost is
    /// `tokens/1000 * price_per_1k_tokens_cents`; in pure integer cents a request whose cost is < 1
    /// cent (e.g. 500 tokens at 1¢/1k = 0.5¢) used to TRUNCATE to 0 and be lost forever. We instead
    /// accrue spend in MILLICENTS (`tokens * price_per_1k_cents`), flush WHOLE cents to the durable
    /// store, and carry the 0..999 millicent remainder here until it crosses a cent on a later
    /// request. In-memory only (dropping a sub-1¢ remainder per key on restart is acceptable);
    /// bounded by the key count (the same set `caches.by_hash` already holds). The `Mutex` keeps the
    /// per-key read-modify-write atomic under concurrent requests for the same key. The value is
    /// `(window, remainder)`: the remainder is attributed to the budget WINDOW it was generated in and
    /// RESET when the window rolls over, so a sub-cent remainder never leaks across a day/month boundary
    /// into the next window's spend (the <1¢ dropped at a rollover is the same accepted trade-off as the
    /// on-restart drop). One entry per key (not per key×window), so growth stays key-count-bounded.
    token_spend_carry: std::sync::Mutex<HashMap<String, (u64, u64)>>,
    /// Admission counter that amortizes the bounded eviction sweep of `rate` (see
    /// `RATE_SWEEP_INTERVAL`): every Nth `check_rate` call performs the full stale-entry retain,
    /// so the per-request hot path does not scan all active keys on every admission.
    rate_sweep_ticker: AtomicU32,
    /// Admission counter that amortizes the bounded eviction sweep of `token_spend_carry`. The sweep is
    /// only useful for churned, ageable (windowed) keys; a deployment with many long-lived `total`-period
    /// keys (`window == 0`, never age out) keeps the map size permanently above the threshold, so gating
    /// the O(n) retain solely on `len > THRESHOLD` would run it under-lock on EVERY flush. This ticker
    /// makes the scan fire only every Nth over-threshold flush — restoring the amortized-O(1) hot path.
    carry_sweep_ticker: AtomicU32,
    /// SHA-256 hex digest of the configured /admin bearer token, computed once at construction. The
    /// plaintext token is NOT retained — only its digest, which is all the constant-time compare on
    /// the /admin path needs (less plaintext secret held in memory). `None` = admin API disabled.
    admin_token_hash: Option<String>,
    /// AUTHORITATIVE in-memory budget counters — the hard-cap admission state consulted (and charged)
    /// on the request hot path with NO await and NO store round-trip. One `BudgetCell` per key for its
    /// CURRENT window (reset on rollover), so the map is key-count-bounded exactly like `rate`. SQLite
    /// is a WRITE-BEHIND durability layer: the flusher (`flush_budgets`) periodically SETS the durable
    /// counter to a dirty cell's absolute values off the request path, and boot `hydrate_budgets`
    /// re-loads accrued spend so a restart forgets nothing. The atomic check-and-charge under this
    /// single `RwLock` gives the SAME hard-cap guarantee the SQL UPSERT gave, now in memory (single
    /// node) — and, being in-memory, it can never fail with a store error, so there is no admission
    /// fail-mode to configure.
    budget: RwLock<HashMap<String, BudgetCell>>,
    /// Admission counter that amortizes the bounded eviction sweep of `budget` (mirrors
    /// `rate_sweep_ticker`): every Nth `charge_budget_mem` call performs the full stale-cell retain,
    /// so the per-request hot path does not scan all active keys on every admission. Per-key
    /// correctness does not depend on the sweep (a looked-up cell is reset in place when its window is
    /// stale); the sweep purely bounds the map by evicting cells for keys that have gone silent.
    budget_sweep_ticker: AtomicU32,
}

/// Parameters for minting a new virtual key (from the management API).
pub(crate) struct NewKeySpec {
    pub(crate) name: String,
    pub(crate) allowed_pools: Vec<String>,
    pub(crate) max_budget_cents: Option<i64>,
    pub(crate) budget_period: String,
    pub(crate) rpm_limit: Option<u32>,
    pub(crate) tpm_limit: Option<u32>,
}

mod state;

/// THE GOVERNANCE RE-KEY (design-hooks-v2 §2.3): synthesize the governance grants for a
/// GROUP-CARRYING principal from the UNION of its `group_map:` entries — the same `VirtualKey`
/// shape every enforcement site already speaks, keyed by the PRINCIPAL id, so an SSO user and a
/// virtual key get identical enforcement (pool ACL, RPM/TPM windows, budget, usage attribution,
/// the hook `send_user` projection) through identical code.
///
/// Fail-closed: `None` unless at least one mapped group SETS `allowed_pools` (the data-plane
/// grant; an admin-only group confers no inference access). Union is most-permissive: pool lists
/// union (an explicit `[]` = every pool); a granting group without an rpm/tpm/budget cap makes the
/// principal uncapped on that axis, otherwise the max wins.
pub(crate) fn synthesize_principal_key(
    principal: &crate::auth::Principal,
    group_map: &std::collections::HashMap<String, crate::config::GroupMapEntry>,
) -> Option<VirtualKey> {
    let granting: Vec<&crate::config::GroupMapEntry> = principal
        .groups
        .iter()
        .filter_map(|g| group_map.get(g))
        .filter(|e| e.allowed_pools.is_some())
        .collect();
    if granting.is_empty() {
        return None;
    }
    // Pool union. An explicit `[]` on any granting group = unrestricted (empty Vec is the
    // VirtualKey encoding for "all pools").
    let mut pools: Vec<String> = Vec::new();
    let mut all_pools = false;
    for e in &granting {
        match e.allowed_pools.as_deref() {
            Some([]) => all_pools = true,
            Some(list) => {
                for p in list {
                    if !pools.contains(p) {
                        pools.push(p.clone());
                    }
                }
            }
            None => unreachable!("filtered on is_some"),
        }
    }
    if all_pools {
        pools.clear();
    }
    // Most-permissive cap union: any granting group WITHOUT the cap lifts it entirely.
    let cap_union = |get: fn(&crate::config::GroupMapEntry) -> Option<i64>| -> Option<i64> {
        let mut max: Option<i64> = None;
        for e in &granting {
            let v = get(e)?; // a capless granting group lifts the cap entirely
            max = Some(max.map_or(v, |m: i64| m.max(v)));
        }
        max
    };
    let rpm = cap_union(|e| e.rpm_limit.map(i64::from)).map(|v| v as u32);
    let tpm = cap_union(|e| e.tpm_limit.map(i64::from)).map(|v| v as u32);
    let budget = cap_union(|e| e.max_budget_cents);
    Some(VirtualKey {
        id: principal.id.clone(),
        // NOT a credential hash — a marker. The synthetic key never authenticates anything (the
        // auth module already did); it exists purely to carry grants through enforcement.
        key_hash: format!("principal:{}", principal.id),
        name: principal
            .name
            .clone()
            .unwrap_or_else(|| principal.id.clone()),
        allowed_pools: pools,
        max_budget_cents: budget,
        budget_period: BUDGET_PERIOD_TOTAL.to_string(),
        rpm_limit: rpm,
        tpm_limit: tpm,
        enabled: true,
        created_at: 0,
    })
}

/// Resolved governance context attached to each request by the auth middleware. `key` is `None`
/// when governance is disabled (so downstream enforcement is a no-op).
#[derive(Clone, Debug, Default)]
pub(crate) struct GovCtx {
    pub(crate) key: Option<VirtualKey>,
}

/// Generate a virtual-key secret from 32 bytes of the OS CSPRNG (portable across Unix/Windows via
/// getrandom). 256 bits — parity with the AWS secret access key beside it, raised from the old 128-bit
/// width (still brute-force-infeasible, but 128 was the one credential axis below the project's own
/// bar). Fails closed: if the OS exposes no entropy source we refuse to mint a key rather than fall
/// back to a guessable (time-derived) secret. getrandom failure is near-impossible on supported
/// platforms; on failure we return the error so the caller (`create_key`) surfaces a 500 instead of
/// panicking the process — the server stays up.
fn generate_secret() -> Result<String, getrandom::Error> {
    // Portable OS CSPRNG via getrandom: /dev/urandom on Unix, BCryptGenRandom on Windows, etc.
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)?;
    Ok(format!("{SK_SECRET_PREFIX}{}", hex::encode(buf)))
}

/// Generate an AWS-style AccessKeyId: the literal `AKIA` prefix (matching the real long-term-key
/// shape an AWS SDK expects and validates) followed by 16 chars from a 36-symbol uppercase
/// alphanumeric alphabet (A-Z + 0-9), for a fixed total length of 20 — the exact AKID shape AWS
/// SDK client-side validators accept. The AccessKeyId is NOT secret — it travels in plaintext in
/// the SigV4 `Authorization` header and is the public lookup handle — but it is minted from the OS
/// CSPRNG so it is unguessable and collision-resistant. Fails closed (returns the error so the
/// caller surfaces a 500, never panics the server) if the OS exposes no entropy.
fn generate_aws_access_key_id() -> Result<String, getrandom::Error> {
    // 36-symbol uppercase-alphanumeric alphabet (A-Z, 0-9). The AKID format is a FIXED 20 chars
    // (AKIA + 16 random), so we emit 16 symbols over 36 symbols → 16*log2(36) ≈ 82.7 bits. That is
    // the maximum entropy attainable inside the fixed 20-char AWS shape; the old code masked each
    // byte to its low 5 bits (`& 0x1f`) over a 32-symbol set for only 80 bits AND discarded 3 bits
    // per byte. Dropping the mask and widening the alphabet recovers that headroom without changing
    // the wire length AWS SDKs validate. (A full ≥100-bit handle is incompatible with the fixed
    // 20-char format; the secret access key, not the public AKID, carries the real signing entropy.)
    const ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf)?;
    let mut s = String::with_capacity(AWS_ACCESS_KEY_ID_LEN);
    s.push_str(AWS_ACCESS_KEY_PREFIX);
    for &b in &buf {
        // Map each FULL byte into the alphabet via modulo. 256 is not a multiple of 36 so the
        // lowest 4 symbols are marginally favored (a ~0.02-bit bias, negligible for an unguessable
        // public lookup handle), but no byte bits are discarded. Index is always in 0..36 (no
        // out-of-bounds, no panic on the mint path).
        s.push(ALPHABET[(b as usize) % ALPHABET.len()] as char);
    }
    Ok(s)
}

/// Generate an AWS-style secret access key: 40 chars from a base64-like alphabet (matching the shape
/// real AWS secret keys take), sourced from 30 bytes of the OS CSPRNG (240 bits, encoded). This is
/// the SYMMETRIC SigV4 signing secret — stored in plaintext (HMAC verification needs the same value
/// the client signs with) and shown to the operator exactly once at mint. Fails closed on no entropy.
fn generate_aws_secret_access_key() -> Result<String, getrandom::Error> {
    // Base64-url-safe-ish alphabet without padding: A-Z a-z 0-9 + /. 64 symbols → 6 bits each.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 40 chars * 6 bits = 240 bits = 30 bytes of entropy; draw the 30 bytes and emit 40 symbols.
    let mut buf = [0u8; 30];
    getrandom::fill(&mut buf)?;
    // Pack the 240 bits and slice them into 40 six-bit groups. A running bit accumulator avoids any
    // dependency on a base64 crate and keeps the mapping panic-free (every index is `& 0x3f`).
    let mut out = String::with_capacity(AWS_SECRET_ACCESS_KEY_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in &buf {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((acc >> bits) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    Ok(out)
}

/// Whether `key` may target `pool` (empty allowed_pools = all pools).
pub(crate) fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.allowed_pools.is_empty() || key.allowed_pools.iter().any(|p| p == pool)
}

/// The epoch start of the budget window containing `now` for a given period. "total" = a
/// single all-time window (0); "daily" = UTC midnight; "monthly" = UTC first-of-month.
pub(crate) fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        BUDGET_PERIOD_DAILY => now / SECS_PER_DAY * SECS_PER_DAY,
        BUDGET_PERIOD_MONTHLY => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * SECS_PER_DAY
        }
        BUDGET_PERIOD_TOTAL => 0, // explicit all-time window (the documented sentinel)
        // An unrecognized period (typo such as `monthlly`, or an unsupported value such as
        // `weekly`) is NOT silently accepted as `total`: it almost always means a misconfigured
        // key. We fail safe to the all-time window (0) — the tightest enforcement, never wider —
        // but emit a diagnostic so the misconfiguration is visible instead of silent. (Rejecting
        // the value at key-creation time is the admin handler's job; this is the evaluation-path
        // backstop.) Misconfiguration is rare, so the per-evaluation warn is acceptable.
        other => {
            tracing::warn!(
                budget_period = other,
                "unrecognized budget_period; enforcing as all-time ('total') window"
            );
            0
        }
    }
}

// Public-domain civil-date algorithms (same approach as sigv4); self-contained, no date crate.
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

pub(crate) use busbar_api::{
    AwsCredential, AwsKeyEntry, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage,
    VirtualKey,
};

/// Seconds in a metering day bucket. Metering is a TIME SERIES in fixed UTC-day buckets —
/// deliberately decoupled from the per-key budget windows the enforcement counters use, so
/// per-model aggregation ACROSS keys has one well-defined time base.
pub(crate) const METERING_BUCKET_SECS: u64 = 86_400;

/// Floor an epoch to its UTC-day metering bucket start.
pub(crate) fn metering_bucket(now: u64) -> u64 {
    now - (now % METERING_BUCKET_SECS)
}

// The durable-store contract (the `Store` trait, its records, and `StoreError`) now lives in the
// `busbar-api` contract crate, re-exported above so the rest of the engine names them unchanged.
// rusqlite/getrandom errors convert into the api's backend-agnostic `StoreError` HERE via a local
// extension trait: the contract crate must stay free of any storage dependency, so the `From` impls
// that used to power `?` cannot live there. Replace `<rusqlite call>?` with `<call>.store()?`.
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, rusqlite::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
    }
}
impl<T> IntoStoreResult<T> for Result<T, getrandom::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(format!("OS CSPRNG (getrandom) unavailable: {e}")))
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
";

/// Embedded SQLite store (the default `Store`). The single `Connection` is mutex-guarded; the
/// governance surface is low-frequency (key CRUD) or batched (usage), so this is not on the hot path.
pub(crate) struct SqliteStore {
    // `Arc<Mutex<…>>` (not a bare `Mutex`): the async accounting flavor offloads the synchronous SQL
    // onto the blocking pool, which needs an owned handle to the connection mutex it can move into the
    // `spawn_blocking` closure. The `Arc` lets each offload clone a cheap shared handle while
    // `lock_conn()` (and every synchronous method) still locks the SAME single connection — the Arc
    // derefs to the inner `Mutex`, so serialization across sync and async callers is preserved.
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub(crate) fn open(path: &str) -> StoreResult<Self> {
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
            conn.pragma_update(
                None,
                "busy_timeout",
                crate::limits::sqlite_busy_timeout_ms(),
            )
            .store()?;
        }
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory SQLite store, for unit tests.
    #[cfg(test)]
    pub(crate) fn open_in_memory() -> StoreResult<Self> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory().store()?)),
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
    /// but takes the mutex by reference so the shared `*_inner` SQL bodies (called from BOTH the sync
    /// trait methods, holding `&self.conn`, AND the async offloads, holding a cloned `Arc`) can lock
    /// it without needing `&self`.
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

    // ── Shared SQL bodies for the dual-flavor accounting methods ─────────────────────────────────
    // Each `*_inner` holds the EXACT SQL of its accounting method, locking the passed connection
    // mutex (poison-recovering) so it can run from EITHER the synchronous trait method (`&self.conn`)
    // OR an async offload (a cloned `Arc<Mutex<Connection>>` moved into a `spawn_blocking` closure).
    // No `&self`, so the offload closure need not borrow the store. The SQL is byte-for-byte the
    // original — sync and async share one body, so they can never drift.

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
}

// Direct-store SQL primitives retained ONLY for the governance unit tests that pin their
// UPSERT/boundary and hash-lookup semantics. Production enforcement is the in-memory hard-cap in
// `GovState` (SQLite is a write-behind durability layer), so these are inherent `#[cfg(test)]`
// methods on the concrete `SqliteStore` — NOT part of the swappable `Store` plugin contract a `db`
// plugin (Postgres, …) must implement.
#[cfg(test)]
impl SqliteStore {
    pub(crate) fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
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

    pub(crate) fn add_usage(
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

    pub(crate) fn charge_within_budget(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        Self::charge_within_budget_inner(&self.conn, key_id, window_start, cost_cents, max_cents)
    }

    pub(crate) fn refund_request(
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

/// The write-behind budget flusher: on a fixed cadence (and once more on graceful shutdown) push the
/// dirty in-memory budget cells to the durable store off the request hot path. Mirrors the D3
/// `state_persist::spawn_snapshotter` shape — a spawned loop that ticks, does the durable write, and
/// runs one FINAL flush on the shutdown signal so a graceful stop loses nothing. The in-memory cells
/// stay AUTHORITATIVE for enforcement; this only keeps SQLite eventually-consistent for restart
/// crash-recovery (`hydrate_budgets`) and the historical/telemetry reads. `flush_budgets` is
/// best-effort and re-marks a cell dirty on a store error, so a transient write failure is retried on
/// the next tick rather than lost.
pub(crate) fn spawn_budget_flusher(
    gov: std::sync::Arc<GovState>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let interval = std::time::Duration::from_millis(crate::limits::usage_flush_interval_ms());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    gov.flush_budgets();
                }
                _ = shutdown.recv() => {
                    // Graceful shutdown: one FINAL flush so no accrued spend/requests is lost, then exit.
                    gov.flush_budgets();
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
