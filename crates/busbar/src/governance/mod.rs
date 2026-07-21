// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Governance persistence. A durable `Store` seam — SEPARATE from the hot in-memory `StateStore`
//! (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual keys + config, and
//! per-key usage counters (spend/tokens/requests) per budget window. Historical request logs are
//! NOT stored here (they go to the observability pipeline). The `Store` CONTRACT lives in
//! `busbar-api`; the DEFAULT backend is the in-memory `MemoryStore` (ephemeral, zero-setup), with
//! `SqliteStore` (durable) and future backends as swappable plugin crates chosen by `governance.store`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

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

/// Number of shards for the per-key enforcement maps (`rate`, `budget`, `token_spend_carry`). A
/// power of two so `hash & (N-1)` selects the shard with a mask (no modulo). 64 keeps lock
/// contention low well past typical core counts while adding trivial fixed memory (64 small empty
/// maps + 64 atomics per `GovState`). Each key deterministically maps to ONE shard, so a key's
/// read-modify-write (rate window, budget charge, spend carry) stays atomic within that shard's lock
/// exactly as it was under the single global lock — sharding only removes CROSS-key serialization,
/// never a per-key invariant.
const GOV_SHARDS: usize = 64;

/// One shard of a [`Sharded`] map: the key→value map plus its OWN amortized-sweep ticker (the sweep
/// is per-shard, so a shard scans only its own — ~1/64th — of the keys when it fires).
struct MapShard<V> {
    map: RwLock<HashMap<String, V>>,
    sweep_ticker: AtomicU32,
}

impl<V> Default for MapShard<V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            sweep_ticker: AtomicU32::new(0),
        }
    }
}

/// A key-id-sharded `HashMap`, replacing a single `RwLock<HashMap>` that every governed request
/// contended. A key always resolves to the SAME shard (`stable_hash(key_id) & (GOV_SHARDS-1)`), so
/// per-key semantics (window straddle, atomic check-and-charge, spend carry) are byte-identical to
/// the single-lock version — only requests for DIFFERENT keys whose ids land in different shards no
/// longer serialize on one lock. Whole-map operations (flush / hydrate / usage sweep) iterate every
/// shard.
struct Sharded<V> {
    shards: Box<[MapShard<V>]>,
}

impl<V> Sharded<V> {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(GOV_SHARDS);
        shards.resize_with(GOV_SHARDS, MapShard::default);
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    /// The shard owning `key_id`. `GOV_SHARDS` is a power of two, so this masks the stable hash — a
    /// process-stable hash (NOT `DefaultHasher`) so a key maps to the same shard across restarts,
    /// which is irrelevant to correctness (the maps are ephemeral) but keeps behaviour deterministic.
    #[inline]
    fn shard_for(&self, key_id: &str) -> &MapShard<V> {
        let h = crate::store::fnv1a_u64(key_id) as usize;
        &self.shards[h & (GOV_SHARDS - 1)]
    }

    /// Acquire this key's shard for writing (poison-recovering — a panic under any holder must not
    /// cascade into a governance outage on the request path; the maps' invariants are re-established
    /// per call, so the recovered guard is safe to use).
    #[inline]
    fn write(&self, key_id: &str) -> std::sync::RwLockWriteGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id)
            .map
            .write()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire this key's shard for reading (poison-recovering, same rationale as [`Sharded::write`]).
    #[inline]
    fn read(&self, key_id: &str) -> std::sync::RwLockReadGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id)
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Every shard's write guard, in shard order — for the whole-map operations that must visit ALL
    /// keys (the write-behind flush snapshot). Each guard is acquired lazily by the iterator, so only
    /// one shard is locked at a time (no cross-shard deadlock, and a concurrent per-key op contends
    /// only for the single shard the iterator currently holds).
    fn write_all(
        &self,
    ) -> impl Iterator<Item = std::sync::RwLockWriteGuard<'_, HashMap<String, V>>> {
        self.shards
            .iter()
            .map(|s| s.map.write().unwrap_or_else(|p| p.into_inner()))
    }

    /// TEST-ONLY: the sweep ticker for the shard owning `key_id`, so a test can drive the amortized
    /// sweep cadence for a specific key exactly as it did against the old single global ticker.
    #[cfg(test)]
    fn sweep_ticker_for(&self, key_id: &str) -> &AtomicU32 {
        &self.shard_for(key_id).sweep_ticker
    }

    /// TEST-ONLY: the raw shard lock owning `key_id`, for the poison-recovery test (it panics inside
    /// the write guard to poison exactly the shard the key resolves to, then asserts the hot path
    /// recovers for that same key).
    #[cfg(test)]
    fn shard_lock_for(&self, key_id: &str) -> &RwLock<HashMap<String, V>> {
        &self.shard_for(key_id).map
    }
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
    /// Hashed-secret → key. Values are `Arc<VirtualKey>` so the per-request bearer `lookup` (on the
    /// chat hot path) resolves to a REFCOUNT BUMP rather than a deep clone of a multi-`String`
    /// `VirtualKey` under the read lock — the resolved key is immutable for the life of the request
    /// and threaded read-only through governance/routing, so sharing it via `Arc` is exact.
    by_hash: HashMap<String, Arc<VirtualKey>>,
    by_access_key_id: HashMap<String, AwsKeyEntry>,
}

/// Per-instance governance runtime: the durable `Store` plus an in-memory key cache (hashed-secret
/// → key) so validation on the hot path is a map lookup, not a DB round-trip. Held in `App`
/// (always `Some` in a running engine — governance is always constructed; `None` only in tests that
/// omit it) — NOT a process-global, so tests stay isolated.
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
    /// per-key RPM/TPM windows (ephemeral). SHARDED by key id so concurrent admissions for different
    /// keys don't serialize on one lock (each key deterministically owns one shard; per-key window
    /// semantics are unchanged — see [`Sharded`]).
    rate: Sharded<RateState>,
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
    /// SHARDED by key id (mirrors `rate`). The value is `(window, remainder)`; each shard carries its
    /// own amortized eviction ticker (see [`MapShard`]).
    token_spend_carry: Sharded<(u64, u64)>,
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
    /// SHARDED by key id (mirrors `rate`): the atomic per-key check-and-charge runs under that key's
    /// shard lock, so the hard-cap guarantee is unchanged (a key is only ever charged under one lock);
    /// different keys no longer serialize. Each shard carries its own amortized eviction ticker.
    budget: Sharded<BudgetCell>,
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
) -> Option<Arc<VirtualKey>> {
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
    Some(Arc::new(VirtualKey {
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
    }))
}

/// Resolved governance context attached to each request by the auth middleware. `key` is `None`
/// when governance is disabled (so downstream enforcement is a no-op).
#[derive(Clone, Debug, Default)]
pub(crate) struct GovCtx {
    /// The resolved virtual key (or synthesized principal key), shared via `Arc`: attaching it to the
    /// request and threading it through governance/routing is then a refcount bump, never a clone of
    /// the key's `String` fields. `None` when governance is disabled (enforcement is a no-op).
    pub(crate) key: Option<Arc<VirtualKey>>,
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
// getrandom errors convert into the api's backend-agnostic `StoreError` HERE via a local
// extension trait (the contract crate stays dependency-light). The SQLite backend lives in its own
// plugin crate (`busbar-store-sqlite`); the engine only names the `Store` contract + the re-exported type.
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, getrandom::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(format!("OS CSPRNG (getrandom) unavailable: {e}")))
    }
}

// The RAM store is the always-on DEFAULT governance backend (and the universal test double). The
// SQLite backend is no longer compiled in — it is a dynamic-library plugin loaded at boot (see
// crate::main's store selection + busbar-plugin-loader).
pub(crate) use busbar_store_memory::MemoryStore;

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
